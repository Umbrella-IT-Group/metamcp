/**
 * `gateway_events` is immutable for 30 days and prunable after, and this
 * proves it two ways.
 *
 * The operator requirement behind the table is at least 30 days of activity
 * history that cannot be rewritten or quietly trimmed. Unlike `audit_log`,
 * which is append-only forever, this table is high-volume operational history
 * and must age out — so the guarantee is a WINDOW rather than a permanent
 * block, and a window has an edge that can be got wrong in both directions.
 * Both directions are tested: a young row must survive every deletion attempt,
 * and an old row must actually be deletable or the retention sweeper is a
 * recurring exception on a timer.
 *
 * Layer 1 (always runs): the migration SQL and the drizzle journal are
 * asserted directly. A migration whose journal entry does not out-rank the
 * previous max is SILENTLY SKIPPED by drizzle — the table would simply never
 * exist in production and nothing would fail loudly — so the ordering is
 * checked as a test, not trusted to review.
 *
 * Layer 2 (opt-in via TEST_DATABASE_URL): the triggers are exercised against a
 * REAL Postgres. A trigger that exists in a .sql file and a trigger that
 * actually refuses a DELETE are different claims, and only the second one is
 * worth anything to whoever is reading this table to reconstruct what
 * happened.
 *
 *   docker run -d --name metamcp-events-test -e POSTGRES_PASSWORD=test \
 *     -e POSTGRES_USER=test -e POSTGRES_DB=metamcp_test \
 *     -p 127.0.0.1:55437:5432 postgres:16-alpine
 *   cd apps/backend
 *   DATABASE_URL=postgres://test:test@127.0.0.1:55437/metamcp_test \
 *     npx drizzle-kit migrate
 *   TEST_DATABASE_URL=postgres://test:test@127.0.0.1:55437/metamcp_test \
 *     npx vitest run src/db/repositories/gateway-events-immutability.integration.test.ts
 *
 * NOTE for whoever runs layer 2: the young rows this suite inserts CANNOT be
 * cleaned up afterwards. That is not an oversight — it is the property under
 * test. Point it at a disposable database.
 */

import { readFileSync } from "node:fs";
import path from "node:path";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

const MIGRATION_PATH = path.resolve(
  __dirname,
  "../../../drizzle/0031_gateway_events.sql",
);
const JOURNAL_PATH = path.resolve(
  __dirname,
  "../../../drizzle/meta/_journal.json",
);

describe("migration 0031 — the DDL that makes the window real", () => {
  const raw = readFileSync(MIGRATION_PATH, "utf8");
  // Assertions run against the STATEMENTS, not the file: this migration's
  // header comment discusses the neighbouring tables by name, and a naive
  // whole-file match would read that prose as schema.
  const sql = raw
    .split("\n")
    .filter((line) => !line.trimStart().startsWith("--"))
    .join("\n");

  it("blocks UPDATE and TRUNCATE unconditionally", () => {
    expect(sql).toContain(
      "CREATE OR REPLACE FUNCTION gateway_events_block_mutation",
    );
    expect(sql).toContain("RAISE EXCEPTION");
    expect(sql).toMatch(
      /CREATE TRIGGER gateway_events_no_update BEFORE UPDATE/,
    );
    // TRUNCATE does not fire row-level triggers, so without a statement-level
    // one it stays a single-statement path to an empty history regardless of
    // row age.
    expect(sql).toMatch(
      /CREATE TRIGGER gateway_events_no_truncate BEFORE TRUNCATE/,
    );
  });

  it("age-gates DELETE on a 30-day window rather than blocking it outright", () => {
    expect(sql).toContain(
      "CREATE OR REPLACE FUNCTION gateway_events_block_recent_delete",
    );
    expect(sql).toContain("interval '30 days'");
    expect(sql).toMatch(
      /CREATE TRIGGER gateway_events_no_recent_delete BEFORE DELETE/,
    );
    // The DELETE trigger must NOT be the unconditional blocker — wiring it to
    // `gateway_events_block_mutation` would compile, pass the block above, and
    // silently make retention impossible.
    expect(sql).toMatch(
      /gateway_events_no_recent_delete BEFORE DELETE ON "gateway_events"\s+FOR EACH ROW EXECUTE FUNCTION gateway_events_block_recent_delete\(\)/,
    );
  });

  it("does not double-store tool calls", () => {
    // `tool_call` rows live in `tool_call_audit` (migration 0019) with more
    // detail than this envelope carries. The category must not appear in the
    // DDL, and the writer filters it — see lib/gateway-events/sink.
    expect(sql).not.toMatch(/\btool_call\b/);
  });

  it("stores occurred_at at MILLISECOND precision, so the keyset cursor round-trips", () => {
    // A cursor is a JavaScript Date handed back by the client. At the default
    // microsecond precision the returned value is earlier than the row it came
    // from, and the next page's `<` comparison then skips every row sharing
    // that millisecond. Pinned here because the failure is silent: every query
    // still succeeds, rows just quietly vanish between pages.
    expect(sql).toMatch(/"occurred_at" timestamp \(3\) with time zone/);
  });

  it("is idempotent, per fork convention", () => {
    expect(sql).toContain('CREATE TABLE IF NOT EXISTS "gateway_events"');
    expect((sql.match(/CREATE INDEX IF NOT EXISTS/g) ?? []).length).toBe(2);
    expect((sql.match(/DROP TRIGGER IF EXISTS/g) ?? []).length).toBe(3);
  });
});

describe("drizzle journal", () => {
  const journal = JSON.parse(readFileSync(JOURNAL_PATH, "utf8")) as {
    entries: { idx: number; when: number; tag: string }[];
  };

  it("registers 0031 with a `when` STRICTLY GREATER than every earlier entry", () => {
    const [entry] = journal.entries.filter(
      (e) => e.tag === "0031_gateway_events",
    );
    expect(entry).toBeDefined();

    const earlier = journal.entries.filter((e) => e.idx < entry.idx);
    const maxEarlier = Math.max(...earlier.map((e) => e.when));

    // drizzle applies only entries whose `when` exceeds the max already
    // applied. Get this wrong and the migration is skipped in production
    // WITHOUT an error — the history table simply never exists.
    expect(entry.when).toBeGreaterThan(maxEarlier);
    expect(entry.idx).toBe(31);
  });

  it("keeps idx and when monotonically increasing across the whole journal", () => {
    const idxs = journal.entries.map((e) => e.idx);
    const whens = journal.entries.map((e) => e.when);

    expect(idxs).toEqual([...idxs].sort((a, b) => a - b));
    expect(whens).toEqual([...whens].sort((a, b) => a - b));
    expect(new Set(whens).size).toBe(whens.length);
  });
});

const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL;

// `describe.skipIf` rather than a silent early return: a skipped suite is
// visible in the vitest output, so "the trigger test didn't run" can never be
// mistaken for "the trigger test passed".
const describeIfDb = describe.skipIf(!TEST_DATABASE_URL);

type Db = Awaited<typeof import("../index")>["db"];

let db: Db;
let gatewayEventsRepository: (typeof import("./gateway-events.repo"))["gatewayEventsRepository"];

describeIfDb("gateway_events against a REAL postgres", () => {
  const youngMarker = `itest-young-${Date.now()}`;
  const oldMarker = `itest-old-${Date.now()}`;

  beforeAll(async () => {
    if (!TEST_DATABASE_URL) return;

    // db/index reads DATABASE_URL at import time, so it has to be set BEFORE
    // the first dynamic import below.
    process.env.DATABASE_URL = TEST_DATABASE_URL;

    ({ db } = await import("../index"));
    ({ gatewayEventsRepository } = await import("./gateway-events.repo"));

    await gatewayEventsRepository.record({
      category: "connection",
      level: "warn",
      server_name: youngMarker,
      message: "Transport closed unexpectedly (backend drop)",
      metadata: { error: "socket hang up" },
    });

    // Backdated past the window. INSERT is deliberately ungated — the triggers
    // guard mutation and removal, not arrival — so this is the honest way to
    // produce a prunable row without waiting 30 days.
    await db.execute(
      `INSERT INTO gateway_events (occurred_at, category, level, server_name, message)
       VALUES (now() - interval '31 days', 'system', 'info', '${oldMarker}', 'aged out')` as never,
    );
  });

  afterAll(async () => {
    if (!TEST_DATABASE_URL || !db) return;
    // Deliberately no cleanup of the young row: removing it is exactly what is
    // blocked. Use a disposable database.
    //
    // TWO pools to close. `record()` writes through its own bounded pool (see
    // ../gateway-events-db) so a chatty backend cannot starve the request path
    // or the security-audit writer; leaving it open here hangs the vitest
    // worker.
    const { pool } = await import("../index");
    const { gatewayEventsPool } = await import("../gateway-events-db");
    await Promise.all([pool.end(), gatewayEventsPool.end()]);
  });

  it("accepts the INSERT the repository makes", async () => {
    const rows = await db.execute(
      `SELECT category, level, message, metadata FROM gateway_events WHERE server_name = '${youngMarker}'` as never,
    );

    expect(rows.rows).toHaveLength(1);
    expect(rows.rows[0]).toMatchObject({
      category: "connection",
      level: "warn",
      message: "Transport closed unexpectedly (backend drop)",
      metadata: { error: "socket hang up" },
    });
  });

  /**
   * drizzle wraps a driver error in its own `Failed query: …` message and
   * keeps the postgres one on `cause`, so asserting on the outer message alone
   * would pass for ANY failed statement — including a typo'd table name, which
   * would make this suite green while proving nothing.
   */
  async function expectRefusedWith(query: Promise<unknown>, pattern: RegExp) {
    let raised: unknown;
    try {
      await query;
    } catch (error) {
      raised = error;
    }

    expect(raised).toBeDefined();
    const cause = (raised as { cause?: { message?: string } }).cause;
    expect(cause?.message).toMatch(pattern);
  }

  it("REFUSES an UPDATE, at any age", async () => {
    await expectRefusedWith(
      db.execute(
        `UPDATE gateway_events SET message = 'edited' WHERE server_name = '${youngMarker}'` as never,
      ),
      /gateway_events is append-only/,
    );
    await expectRefusedWith(
      db.execute(
        `UPDATE gateway_events SET message = 'edited' WHERE server_name = '${oldMarker}'` as never,
      ),
      /gateway_events is append-only/,
    );
  });

  it("REFUSES a TRUNCATE", async () => {
    await expectRefusedWith(
      db.execute(`TRUNCATE TABLE gateway_events` as never),
      /gateway_events is append-only/,
    );
  });

  it("REFUSES a DELETE of a row inside the 30-day window", async () => {
    await expectRefusedWith(
      db.execute(
        `DELETE FROM gateway_events WHERE server_name = '${youngMarker}'` as never,
      ),
      /immutable for 30 days/,
    );
  });

  it("PERMITS a DELETE of a row past the window", async () => {
    await db.execute(
      `DELETE FROM gateway_events WHERE server_name = '${oldMarker}'` as never,
    );

    const rows = await db.execute(
      `SELECT uuid FROM gateway_events WHERE server_name = '${oldMarker}'` as never,
    );
    expect(rows.rows).toHaveLength(0);
  });

  /**
   * The end-to-end claim the two halves make together: the sweeper's cutoff
   * and the trigger's window agree, so a real prune removes aged rows and
   * leaves recent ones WITHOUT raising. This is the assertion that would have
   * caught a JavaScript-side cutoff drifting past the boundary on a clock
   * running ahead of the database.
   */
  it("pruneOlderThan(30) removes aged rows and leaves the window intact", async () => {
    const pruneMarker = `itest-prune-${Date.now()}`;
    await db.execute(
      `INSERT INTO gateway_events (occurred_at, category, message, server_name)
       VALUES (now() - interval '45 days', 'system', 'prunable', '${pruneMarker}')` as never,
    );

    await expect(
      gatewayEventsRepository.pruneOlderThan(30),
    ).resolves.toBeUndefined();

    const pruned = await db.execute(
      `SELECT uuid FROM gateway_events WHERE server_name = '${pruneMarker}'` as never,
    );
    expect(pruned.rows).toHaveLength(0);

    const survivor = await db.execute(
      `SELECT message FROM gateway_events WHERE server_name = '${youngMarker}'` as never,
    );
    expect(survivor.rows).toHaveLength(1);
    expect(survivor.rows[0]).toMatchObject({
      message: "Transport closed unexpectedly (backend drop)",
    });
  });

  it("lists newest-first and pages with a keyset cursor that neither repeats nor skips", async () => {
    const pageMarker = `itest-page-${Date.now()}`;
    // Three rows sharing ONE timestamp — the case a timestamp-only cursor gets
    // wrong, and the reason the cursor is the full (occurred_at, uuid) tuple.
    await db.execute(
      `INSERT INTO gateway_events (occurred_at, category, message, server_name)
       SELECT now() - interval '1 hour', 'system', 'page ' || g, '${pageMarker}'
       FROM generate_series(1, 3) AS g` as never,
    );

    const first = await gatewayEventsRepository.list({
      serverName: pageMarker,
      limit: 2,
    });
    expect(first).toHaveLength(2);

    // The cursor is built from what a CLIENT would send back: the row's
    // timestamp after a round trip through a JavaScript Date. That round trip
    // is exactly where a microsecond-precision column loses information and
    // pages start skipping rows, so building it any other way here would test
    // the wrong thing.
    const cursor = {
      occurred_at: new Date(first[1].occurred_at.toISOString()),
      uuid: first[1].uuid,
    };
    const second = await gatewayEventsRepository.list({
      serverName: pageMarker,
      cursor,
      limit: 2,
    });

    expect(second).toHaveLength(1);
    const uuids = [...first, ...second].map((row) => row.uuid);
    expect(new Set(uuids).size).toBe(3);
  });

  /**
   * The one claim no unit test can make: an ordinary `metamcpLogStore.record()`
   * call, with nothing mocked, ends up as a row.
   *
   * Every layer between the two is stubbed somewhere else — the sink's
   * repository in `lib/gateway-events/sink.test.ts`, the store's sink in
   * `lib/metamcp/log-store-persistence.test.ts` — so all of those suites would
   * stay green if the lazy import in the sink resolved to nothing in a real
   * process. This is the case that would catch it.
   */
  it("persists an ordinary log-store event end to end, with nothing mocked", async () => {
    const storeMarker = `itest-store-${Date.now()}`;
    const { metamcpLogStore } = await import("../../lib/metamcp/log-store");

    metamcpLogStore.record({
      category: "client",
      serverName: storeMarker,
      level: "info",
      message: "client connected",
      clientName: "example-consumer",
      sessionId: "session-itest",
    });

    // The write is detached by design, so the assertion has to wait for it
    // rather than for the call that scheduled it.
    let rows = { rows: [] as unknown[] };
    for (let attempt = 0; attempt < 50; attempt += 1) {
      rows = (await db.execute(
        `SELECT category, level, client_name, session_id, message FROM gateway_events WHERE server_name = '${storeMarker}'` as never,
      )) as typeof rows;
      if (rows.rows.length > 0) break;
      await new Promise((resolve) => setTimeout(resolve, 20));
    }

    expect(rows.rows).toHaveLength(1);
    expect(rows.rows[0]).toMatchObject({
      category: "client",
      level: "info",
      client_name: "example-consumer",
      session_id: "session-itest",
      message: "client connected",
    });
  });

  it("does NOT persist a tool_call, even though the store rings one", async () => {
    const toolMarker = `itest-tool-${Date.now()}`;
    const { metamcpLogStore } = await import("../../lib/metamcp/log-store");

    metamcpLogStore.record({
      category: "tool_call",
      serverName: toolMarker,
      level: "info",
      message: "example_tool (12ms)",
      toolName: "example_tool",
      durationMs: 12,
    });

    // Give the detached write the same chance to land as the case above, so a
    // row that DID get written cannot pass this by being slow.
    await new Promise((resolve) => setTimeout(resolve, 250));

    const rows = await db.execute(
      `SELECT uuid FROM gateway_events WHERE server_name = '${toolMarker}'` as never,
    );
    expect(rows.rows).toHaveLength(0);
  });

  /**
   * The repository half of the pagination contract, against real rows.
   *
   * `logs.impl` asks for `pageSize + 1` and treats the extra row as evidence
   * that a next page exists. The repository used to clamp that request back
   * down to the page maximum, so at the largest page size — which is also the
   * default — the probe row could not come back, the cursor was always null,
   * and everything past the first page was unreachable. Nothing failed; rows
   * simply stopped existing. Only a run with more rows than a full page shows
   * it.
   */
  it("returns the probe row at a full-page request, so a next page is detectable", async () => {
    const bulkMarker = `itest-bulk-${Date.now()}`;
    await db.execute(
      `INSERT INTO gateway_events (category, message, server_name)
       SELECT 'system', 'bulk ' || g, '${bulkMarker}'
       FROM generate_series(1, 250) AS g` as never,
    );

    const { GATEWAY_EVENT_PAGE_MAX } = await import(
      "../../lib/gateway-events/bounds"
    );

    const probed = await gatewayEventsRepository.list({
      serverName: bulkMarker,
      limit: GATEWAY_EVENT_PAGE_MAX + 1,
    });
    expect(probed).toHaveLength(GATEWAY_EVENT_PAGE_MAX + 1);

    // The ceiling is still a ceiling: one past the probe is refused, so a
    // caller cannot ask for an unbounded page by inflating the limit.
    const overreach = await gatewayEventsRepository.list({
      serverName: bulkMarker,
      limit: GATEWAY_EVENT_PAGE_MAX + 500,
    });
    expect(overreach).toHaveLength(GATEWAY_EVENT_PAGE_MAX + 1);
  });

  /**
   * The property the break-glass note in migration 0031 and the README both
   * assert, verified rather than assumed: a deletion spanning the boundary
   * frees NOTHING.
   *
   * The trigger raises per row and a raise aborts the whole statement, so a
   * DELETE covering both aged and in-window rows rolls back completely. That is
   * what makes "reclaiming space early needs a superuser" true rather than
   * merely discouraged — there is no partial prune that creeps inward, and an
   * operator who tries one gets an error and their disk usage unchanged.
   */
  it("rolls back a deletion that spans the window, freeing nothing", async () => {
    const spanMarker = `itest-span-${Date.now()}`;
    await db.execute(
      `INSERT INTO gateway_events (occurred_at, category, message, server_name) VALUES
         (now() - interval '60 days', 'system', 'aged', '${spanMarker}'),
         (now() - interval '1 hour', 'system', 'recent', '${spanMarker}')` as never,
    );

    await expectRefusedWith(
      db.execute(
        `DELETE FROM gateway_events WHERE server_name = '${spanMarker}'` as never,
      ),
      /immutable for 30 days/,
    );

    // BOTH rows survive. The aged one was deletable on its own, and would have
    // been gone if the statement had been allowed to partially succeed.
    const rows = await db.execute(
      `SELECT message FROM gateway_events WHERE server_name = '${spanMarker}' ORDER BY occurred_at` as never,
    );
    expect(rows.rows).toHaveLength(2);
  });

  it("lists server names ordered and bounded by both ends of the window", async () => {
    const nameMarker = `itest-names-${Date.now()}`;
    await db.execute(
      `INSERT INTO gateway_events (occurred_at, category, message, server_name) VALUES
         (now() - interval '2 hours', 'system', 'in window', '${nameMarker}-b'),
         (now() - interval '2 hours', 'system', 'in window', '${nameMarker}-a'),
         (now() - interval '10 days', 'system', 'before window', '${nameMarker}-old')` as never,
    );

    const names = await gatewayEventsRepository.listServerNames(
      new Date(Date.now() - 6 * 60 * 60 * 1000),
      new Date(),
    );

    expect(names).toContain(`${nameMarker}-a`);
    expect(names).toContain(`${nameMarker}-b`);
    // Outside the window, so it must not populate a filter described as the
    // servers seen in the window the operator is looking at.
    expect(names).not.toContain(`${nameMarker}-old`);
    // Ordered in SQL, which is what makes the LIMIT deterministic rather than
    // an arbitrary subset that changes between page loads.
    expect(names).toEqual([...names].sort());
  });

  it("treats a search term as a substring, not a LIKE pattern", async () => {
    const searchMarker = `itest-search-${Date.now()}`;
    await db.execute(
      `INSERT INTO gateway_events (category, message, server_name) VALUES
         ('system', 'pool at 100% capacity', '${searchMarker}'),
         ('system', 'pool at 100 capacity', '${searchMarker}')` as never,
    );

    // Without escaping, '100%' is "starts with 100" and matches both rows.
    const matches = await gatewayEventsRepository.list({
      serverName: searchMarker,
      search: "100%",
    });

    expect(matches).toHaveLength(1);
    expect(matches[0].message).toBe("pool at 100% capacity");
  });
});
