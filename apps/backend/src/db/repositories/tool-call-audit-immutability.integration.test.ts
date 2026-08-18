/**
 * `tool_call_audit` is immutable for 30 days and prunable after, and this
 * proves it two ways.
 *
 * The requirement behind the table is at least 30 days of in-platform log
 * history that cannot be rewritten or quietly trimmed. This table was the last
 * one not honouring it: `audit_log` has been append-only since migration 0028,
 * but nothing constrained this one, so the DELETE its retention pruner needs
 * was an unrestricted DELETE and the credential serving requests could empty
 * the table rather than prune its aged tail. Migration 0032 makes the
 * difference a 30-day window, and a window has an edge that can be got wrong
 * in both directions. Both directions are tested here: a young row must
 * survive every removal attempt, and an aged row must actually be deletable or
 * retention becomes a recurring exception on a five-minute timer.
 *
 * Layer 1 (always runs): the migration SQL and the drizzle journal are
 * asserted directly. A migration whose journal entry does not out-rank the
 * previous max is SILENTLY SKIPPED by drizzle, so the triggers would simply be
 * absent in production with nothing failing loudly. The ordering is checked as
 * a test, not trusted to review.
 *
 * Layer 2 (opt-in via TEST_DATABASE_URL): the triggers are exercised against a
 * REAL Postgres. A trigger that exists in a .sql file and a trigger that
 * actually refuses a DELETE are different claims, and only the second one is
 * worth anything to whoever is reading this table after a credential was
 * misused.
 *
 *   docker run -d --name metamcp-toolaudit-test -e POSTGRES_PASSWORD=test \
 *     -e POSTGRES_USER=test -e POSTGRES_DB=metamcp_test \
 *     -p 127.0.0.1:55492:5432 postgres:16-alpine
 *   cd apps/backend
 *   DATABASE_URL=postgres://test:test@127.0.0.1:55492/metamcp_test \
 *     npx drizzle-kit migrate
 *   TEST_DATABASE_URL=postgres://test:test@127.0.0.1:55492/metamcp_test \
 *     npx vitest run src/db/repositories/tool-call-audit-immutability.integration.test.ts
 *
 * NOTE for whoever runs layer 2: the young rows this suite inserts CANNOT be
 * cleaned up afterwards. That is not an oversight, it is the property under
 * test. Point it at a disposable database.
 */

import { readFileSync } from "node:fs";
import path from "node:path";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

const MIGRATION_PATH = path.resolve(
  __dirname,
  "../../../drizzle/0032_tool_call_audit_immutability_window.sql",
);
const JOURNAL_PATH = path.resolve(
  __dirname,
  "../../../drizzle/meta/_journal.json",
);

describe("migration 0032 — the DDL that makes the window real", () => {
  const raw = readFileSync(MIGRATION_PATH, "utf8");
  // Assertions run against the STATEMENTS, not the file: this migration's
  // header comment quotes the pruner and names the neighbouring tables, and a
  // naive whole-file match would read that prose as schema.
  const sql = raw
    .split("\n")
    .filter((line) => !line.trimStart().startsWith("--"))
    .join("\n");

  it("blocks UPDATE and TRUNCATE unconditionally", () => {
    expect(sql).toContain(
      "CREATE OR REPLACE FUNCTION tool_call_audit_block_mutation",
    );
    expect(sql).toContain("RAISE EXCEPTION");
    expect(sql).toMatch(
      /CREATE TRIGGER tool_call_audit_no_update BEFORE UPDATE/,
    );
    // TRUNCATE does not fire row-level triggers, so without a statement-level
    // one it stays a single-statement path to an empty history regardless of
    // row age.
    expect(sql).toMatch(
      /CREATE TRIGGER tool_call_audit_no_truncate BEFORE TRUNCATE/,
    );
  });

  it("age-gates DELETE on a 30-day window rather than blocking it outright", () => {
    expect(sql).toContain(
      "CREATE OR REPLACE FUNCTION tool_call_audit_block_recent_delete",
    );
    expect(sql).toContain("interval '30 days'");
    expect(sql).toMatch(
      /CREATE TRIGGER tool_call_audit_no_recent_delete BEFORE DELETE/,
    );
    // The DELETE trigger must NOT be wired to the unconditional blocker. That
    // would compile, pass the block above, and silently make retention
    // impossible at every age.
    expect(sql).toMatch(
      /tool_call_audit_no_recent_delete BEFORE DELETE ON "tool_call_audit"\s+FOR EACH ROW EXECUTE FUNCTION tool_call_audit_block_recent_delete\(\)/,
    );
  });

  it("gates on called_at, the column this table actually has", () => {
    // 0028 and 0031 use `occurred_at`; this table predates that naming. A
    // copy-paste of the sibling migration would reference a column that does
    // not exist here, and the failure would land at DELETE time in production
    // rather than at migrate time.
    expect(sql).toContain("OLD.called_at");
    expect(sql).not.toContain("occurred_at");
  });

  it("is idempotent, per fork convention", () => {
    // A re-run must not crash-loop a deployer, so every statement is a
    // create-or-replace or a drop-if-exists.
    expect((sql.match(/CREATE OR REPLACE FUNCTION/g) ?? []).length).toBe(2);
    expect((sql.match(/DROP TRIGGER IF EXISTS/g) ?? []).length).toBe(3);
  });

  it("leaves the pruner room, so retention can never trip the window", () => {
    // The coupling this migration depends on, pinned in the direction that can
    // break it. `pruneOlderThan` deletes rows STRICTLY OLDER than its cutoff,
    // and the cutoff is TOOL_AUDIT_RETENTION_DAYS back from now. Let that
    // value land inside the window and every prune raises and rolls back, so
    // the floor is what keeps the two from ever meeting.
    const retention = readFileSync(
      path.resolve(__dirname, "../../lib/tool-audit-retention.ts"),
      "utf8",
    );
    expect(retention).toContain("TOOL_AUDIT_RETENTION_FLOOR_DAYS = 30");
    expect(retention).toContain("TOOL_AUDIT_RETENTION_DEFAULT_DAYS = 90");

    // The router must consume the clamped constant rather than re-reading the
    // raw variable, which is how the floor could be present and bypassed.
    const oauthRouter = readFileSync(
      path.resolve(__dirname, "../../routers/oauth/index.ts"),
      "utf8",
    );
    expect(oauthRouter).toContain(
      'import { TOOL_AUDIT_RETENTION_DAYS } from "@/lib/tool-audit-retention"',
    );
    expect(oauthRouter).not.toContain("process.env.TOOL_AUDIT_RETENTION_DAYS");

    const repo = readFileSync(
      path.resolve(__dirname, "./tool-call-audit.repo.ts"),
      "utf8",
    );
    // `lt`, not `gt`: the pruner removes rows older than the cutoff. A flipped
    // comparison would delete everything INSIDE the window, which is the exact
    // set the trigger refuses.
    expect(repo).toMatch(/lt\(toolCallAuditTable\.called_at, cutoff\)/);
  });
});

describe("drizzle journal", () => {
  const journal = JSON.parse(readFileSync(JOURNAL_PATH, "utf8")) as {
    entries: { idx: number; when: number; tag: string }[];
  };

  it("registers 0032 with a `when` STRICTLY GREATER than every earlier entry", () => {
    const [entry] = journal.entries.filter(
      (e) => e.tag === "0032_tool_call_audit_immutability_window",
    );
    expect(entry).toBeDefined();

    const earlier = journal.entries.filter((e) => e.idx < entry.idx);
    const maxEarlier = Math.max(...earlier.map((e) => e.when));

    // drizzle applies only entries whose `when` exceeds the max already
    // applied. Get this wrong and the migration is skipped in production
    // WITHOUT an error, leaving the table unprotected and nothing to read.
    expect(entry.when).toBeGreaterThan(maxEarlier);
    expect(entry.idx).toBe(32);
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
let toolCallAuditRepository: (typeof import("./tool-call-audit.repo"))["toolCallAuditRepository"];

describeIfDb("tool_call_audit against a REAL postgres", () => {
  const youngMarker = `itest-young-${Date.now()}`;
  const oldMarker = `itest-old-${Date.now()}`;

  beforeAll(async () => {
    if (!TEST_DATABASE_URL) return;

    // db/index reads DATABASE_URL at import time, so it has to be set BEFORE
    // the first dynamic import below.
    process.env.DATABASE_URL = TEST_DATABASE_URL;

    ({ db } = await import("../index"));
    ({ toolCallAuditRepository } = await import("./tool-call-audit.repo"));

    await toolCallAuditRepository.record({
      server_name: youngMarker,
      tool_name: "example_tool",
      success: true,
      client_name: "example-consumer",
      auth_method: "api_key",
      latency_ms: 12,
    });

    // Backdated past the window. INSERT is deliberately ungated, because the
    // triggers guard mutation and removal rather than arrival, so this is the
    // honest way to produce a prunable row without waiting 30 days.
    await db.execute(
      `INSERT INTO tool_call_audit (called_at, server_name, tool_name, success)
       VALUES (now() - interval '31 days', '${oldMarker}', 'aged_tool', true)` as never,
    );
  });

  afterAll(async () => {
    if (!TEST_DATABASE_URL || !db) return;
    // Deliberately no cleanup of the young row: removing it is exactly what is
    // blocked. Use a disposable database.
    //
    // One pool, unlike the audit_log and gateway_events suites: this
    // repository writes through the main `db` rather than a bounded pool of
    // its own. Leaving it open hangs the vitest worker.
    const { pool } = await import("../index");
    await pool.end();
  });

  it("accepts the INSERT the repository makes", async () => {
    const rows = await db.execute(
      `SELECT tool_name, success, client_name, auth_method FROM tool_call_audit WHERE server_name = '${youngMarker}'` as never,
    );

    expect(rows.rows).toHaveLength(1);
    expect(rows.rows[0]).toMatchObject({
      tool_name: "example_tool",
      success: true,
      client_name: "example-consumer",
      auth_method: "api_key",
    });
  });

  /**
   * drizzle wraps a driver error in its own `Failed query: …` message and
   * keeps the postgres one on `cause`, so asserting on the outer message alone
   * would pass for ANY failed statement, including a typo'd table name, which
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
        `UPDATE tool_call_audit SET success = false WHERE server_name = '${youngMarker}'` as never,
      ),
      /tool_call_audit is append-only/,
    );
    // The aged row too: the window governs DELETE only. A row past 30 days is
    // prunable, never editable.
    await expectRefusedWith(
      db.execute(
        `UPDATE tool_call_audit SET success = false WHERE server_name = '${oldMarker}'` as never,
      ),
      /tool_call_audit is append-only/,
    );
  });

  it("REFUSES a TRUNCATE", async () => {
    await expectRefusedWith(
      db.execute(`TRUNCATE TABLE tool_call_audit` as never),
      /tool_call_audit is append-only/,
    );
  });

  it("REFUSES a DELETE of a row inside the 30-day window", async () => {
    await expectRefusedWith(
      db.execute(
        `DELETE FROM tool_call_audit WHERE server_name = '${youngMarker}'` as never,
      ),
      /immutable for 30 days/,
    );
  });

  it("PERMITS a DELETE of a row past the window", async () => {
    await db.execute(
      `DELETE FROM tool_call_audit WHERE server_name = '${oldMarker}'` as never,
    );

    const rows = await db.execute(
      `SELECT uuid FROM tool_call_audit WHERE server_name = '${oldMarker}'` as never,
    );
    expect(rows.rows).toHaveLength(0);
  });

  it("still holds the young row after every removal attempt", async () => {
    const rows = await db.execute(
      `SELECT success FROM tool_call_audit WHERE server_name = '${youngMarker}'` as never,
    );

    expect(rows.rows).toHaveLength(1);
    expect(rows.rows[0]).toMatchObject({ success: true });
  });

  /**
   * The end-to-end claim the two halves make together: the pruner's cutoff and
   * the trigger's window agree at the shipped default, so a real prune removes
   * aged rows and leaves recent ones WITHOUT raising.
   *
   * 90 rather than 30 on purpose. 30 would exercise the boundary the pruner
   * never actually asks for; the default is what runs every five minutes in
   * production, and it is the one that has to stay quiet.
   */
  it("pruneOlderThan(90) removes aged rows and leaves the window intact", async () => {
    const pruneMarker = `itest-prune-${Date.now()}`;
    await db.execute(
      `INSERT INTO tool_call_audit (called_at, server_name, tool_name, success)
       VALUES (now() - interval '100 days', '${pruneMarker}', 'prunable_tool', true)` as never,
    );

    await expect(
      toolCallAuditRepository.pruneOlderThan(90),
    ).resolves.toBeUndefined();

    const pruned = await db.execute(
      `SELECT uuid FROM tool_call_audit WHERE server_name = '${pruneMarker}'` as never,
    );
    expect(pruned.rows).toHaveLength(0);

    const survivor = await db.execute(
      `SELECT tool_name FROM tool_call_audit WHERE server_name = '${youngMarker}'` as never,
    );
    expect(survivor.rows).toHaveLength(1);
    expect(survivor.rows[0]).toMatchObject({ tool_name: "example_tool" });
  });

  /**
   * The configuration the migration header calls out as the one that now
   * fails loudly. A retention shorter than the window makes the pruner ask to
   * delete rows the trigger refuses; the caller in `routers/oauth/index.ts`
   * logs that error and continues, so pruning stops and the rows survive.
   * Asserted because "fails loudly" is a claim, and the alternative (a short
   * retention silently winning over the window) is the outcome that loses the
   * record.
   */
  /**
   * The failure the floor clamp in `lib/tool-audit-retention` exists to stop,
   * demonstrated against a real database rather than argued.
   *
   * An unclamped retention between 1 and 29 does NOT merely shorten retention.
   * The pruner issues one DELETE for everything older than its cutoff, that
   * statement spans the immutability boundary, the trigger raises on the first
   * in-window row, and the raise rolls the whole statement back. So the aged
   * rows the sweep existed to reclaim survive too, and the table grows without
   * bound behind an error logged every five minutes.
   */
  it("RAISES and prunes NOTHING when retention is configured below the window", async () => {
    // Two rows, one either side of the boundary. Both are selected by
    // `pruneOlderThan(1)`; only the young one is refused. The aged one is the
    // assertion that matters, because it is the row that a "retention is just
    // shorter" reading would expect to disappear.
    const midWindowMarker = `itest-midwindow-${Date.now()}`;
    const agedMarker = `itest-aged-${Date.now()}`;
    await db.execute(
      `INSERT INTO tool_call_audit (called_at, server_name, tool_name, success) VALUES
         (now() - interval '10 days',  '${midWindowMarker}', 'in_window_tool', true),
         (now() - interval '200 days', '${agedMarker}',      'aged_tool',      true)` as never,
    );

    await expect(toolCallAuditRepository.pruneOlderThan(1)).rejects.toThrow();

    const inWindow = await db.execute(
      `SELECT tool_name FROM tool_call_audit WHERE server_name = '${midWindowMarker}'` as never,
    );
    expect(inWindow.rows).toHaveLength(1);
    expect(inWindow.rows[0]).toMatchObject({ tool_name: "in_window_tool" });

    // The whole point: the aged row is collateral damage of the rollback.
    const aged = await db.execute(
      `SELECT tool_name FROM tool_call_audit WHERE server_name = '${agedMarker}'` as never,
    );
    expect(aged.rows).toHaveLength(1);
    expect(aged.rows[0]).toMatchObject({ tool_name: "aged_tool" });
  });

  /**
   * And the clamp's payoff: at the value the resolver would have substituted,
   * the same sweep succeeds and the aged tail is reclaimed.
   *
   * This is the half that makes the clamp worth having rather than just safe.
   * Running the previous case alone would leave "does anything still get
   * pruned?" unanswered.
   */
  it("prunes the aged tail normally at the clamped floor value", async () => {
    const { TOOL_AUDIT_RETENTION_FLOOR_DAYS } = await import(
      "../../lib/tool-audit-retention"
    );
    expect(TOOL_AUDIT_RETENTION_FLOOR_DAYS).toBe(30);

    // The two rows the previous test left behind are still present: one at 10
    // days (inside the window) and one at 200 days (prunable). Pruning at the
    // floor must remove the second and leave the first.
    await expect(
      toolCallAuditRepository.pruneOlderThan(TOOL_AUDIT_RETENTION_FLOOR_DAYS),
    ).resolves.toBeUndefined();

    const aged = await db.execute(
      `SELECT uuid FROM tool_call_audit WHERE tool_name = 'aged_tool'` as never,
    );
    expect(aged.rows).toHaveLength(0);

    const inWindow = await db.execute(
      `SELECT uuid FROM tool_call_audit WHERE tool_name = 'in_window_tool'` as never,
    );
    expect(inWindow.rows).toHaveLength(1);
  });
});
