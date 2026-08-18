/**
 * The stats query is a claim about the CATALOG, and a catalog query is the
 * kind that unit tests cannot make honest.
 *
 * Three things can only be settled against a real PostgreSQL. Whether the
 * `VALUES`-plus-`to_regclass` join actually resolves all three table names
 * (a typo returns a row with nulls rather than an error, so the monitor would
 * report `unknown` forever and look like it was working); whether the bigint
 * casts arrive as something the JavaScript side can turn into numbers; and
 * whether `reltuples` behaves the way the null-handling assumes, which is the
 * -1 that PostgreSQL 14+ uses for a never-analyzed relation.
 *
 * Opt in with TEST_DATABASE_URL:
 *
 *   docker run -d --name metamcp-audit-storage-test -e POSTGRES_PASSWORD=test \
 *     -e POSTGRES_USER=test -e POSTGRES_DB=metamcp_test \
 *     -p 127.0.0.1:55521:5432 postgres:16-alpine
 *   cd apps/backend
 *   DATABASE_URL=postgres://test:test@127.0.0.1:55521/metamcp_test \
 *     npx drizzle-kit migrate
 *   TEST_DATABASE_URL=postgres://test:test@127.0.0.1:55521/metamcp_test \
 *     npx vitest run src/db/repositories/audit-storage.integration.test.ts
 *
 * The rows this suite inserts land in tables that are immutable for 30 days,
 * so they cannot be cleaned up afterwards. Point it at a disposable database.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";

const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL;

// `describe.skipIf` rather than a silent early return: a skipped suite is
// visible in the vitest output, so "the catalog test didn't run" can never be
// mistaken for "the catalog test passed".
const describeIfDb = describe.skipIf(!TEST_DATABASE_URL);

type Db = Awaited<typeof import("../index")>["db"];

let db: Db;
let auditStorageRepository: (typeof import("./audit-storage.repo"))["auditStorageRepository"];
let AUDIT_STORAGE_TABLES: (typeof import("./audit-storage.repo"))["AUDIT_STORAGE_TABLES"];

describeIfDb("audit storage stats against a REAL postgres", () => {
  beforeAll(async () => {
    if (!TEST_DATABASE_URL) return;

    // Both db modules read DATABASE_URL at import time, so it has to be set
    // BEFORE the first dynamic import below.
    process.env.DATABASE_URL = TEST_DATABASE_URL;

    ({ db } = await import("../index"));
    ({ auditStorageRepository, AUDIT_STORAGE_TABLES } = await import(
      "./audit-storage.repo"
    ));
  });

  afterAll(async () => {
    if (!TEST_DATABASE_URL || !db) return;
    // TWO pools to close: the stats query rides the bounded gateway-events pool
    // (see ../gateway-events-db), and leaving it open hangs the vitest worker.
    const { pool } = await import("../index");
    const { gatewayEventsPool } = await import("../gateway-events-db");
    await Promise.all([pool.end(), gatewayEventsPool.end()]);
  });

  it("runs on a pool that bounds how long a statement can hold a connection", async () => {
    // The pool is two connections wide, so a statement stuck on a lock takes
    // half the writer's budget for as long as the lock lives. This query
    // touches no table data, but `pg_total_relation_size` still takes ACCESS
    // SHARE, which conflicts with the ACCESS EXCLUSIVE held by a migration, a
    // VACUUM FULL, or the README's break-glass DISABLE TRIGGER. Measured
    // against a held lock: the read blocks for the full duration of the lock
    // and the pool's 1s CHECKOUT timeout never fires, because the connection
    // was already checked out. Only a server-side statement timeout bounds it.
    //
    // Asserted as the effective server setting rather than by taking a lock
    // here, so the case cannot wedge a shared test database if it fails
    // partway.
    const { gatewayEventsDb } = await import("../gateway-events-db");
    const shown = await gatewayEventsDb.execute(
      `SHOW statement_timeout` as never,
    );

    expect(String(shown.rows[0].statement_timeout)).toBe("5s");
  });

  it("returns exactly one row per watched table, in a stable order", async () => {
    const rows = await auditStorageRepository.tableStats();

    expect(rows.map((row) => row.table)).toEqual([...AUDIT_STORAGE_TABLES]);
  });

  it("resolves every table name to a real relation with a real size", async () => {
    const rows = await auditStorageRepository.tableStats();

    for (const row of rows) {
      // A null size is `to_regclass` finding nothing, which is what a typo in
      // the VALUES list looks like. The monitor would then report `unknown`
      // for that table indefinitely without ever failing.
      expect(row.total_bytes).not.toBeNull();
      // An empty table still has a page-aligned footprint plus its indexes, so
      // zero here would mean the size function was measuring nothing.
      expect(row.total_bytes).toBeGreaterThan(0);
      expect(Number.isInteger(row.total_bytes)).toBe(true);
    }
  });

  it("reports a planner estimate once the table has been analyzed", async () => {
    const marker = `itest-stats-${Date.now()}`;
    await db.execute(
      `INSERT INTO gateway_events (category, message, server_name)
       SELECT 'system', 'stats ' || g, '${marker}'
       FROM generate_series(1, 500) AS g` as never,
    );
    // `reltuples` is maintained by VACUUM/ANALYZE, not by the INSERT, so
    // without this the estimate is whatever the last analyze left behind.
    await db.execute(`ANALYZE gateway_events` as never);

    const rows = await auditStorageRepository.tableStats();
    const events = rows.find((row) => row.table === "gateway_events");

    expect(events).toBeDefined();
    expect(events?.est_rows).not.toBeNull();
    // An estimate, deliberately: this is the number the planner has, not a
    // count, which is the entire reason the query is affordable on a table
    // with tens of millions of rows.
    expect(events?.est_rows).toBeGreaterThanOrEqual(500);
  });

  it("maps a negative reltuples to no-estimate, and only a negative one", async () => {
    // The whole null-handling rests on PostgreSQL 14+ storing -1 rather than 0
    // for a relation that has never been vacuumed or analyzed, which is true
    // of `audit_log` and `tool_call_audit` on a freshly migrated database.
    // Asserting the mapping BOTH ways rather than asserting a particular
    // table is null keeps this deterministic whatever autovacuum has done by
    // the time it runs.
    const raw = await db.execute(
      `SELECT t.table_name, c.reltuples AS reltuples
         FROM (VALUES ('audit_log'), ('gateway_events'), ('tool_call_audit'))
           AS t(table_name)
         LEFT JOIN pg_catalog.pg_class c ON c.oid = to_regclass(t.table_name)
        ORDER BY t.table_name` as never,
    );

    const reported = await auditStorageRepository.tableStats();

    expect(raw.rows).toHaveLength(3);
    for (const row of raw.rows) {
      const mine = reported.find(
        (entry) => entry.table === String(row.table_name),
      );
      expect(mine?.est_rows === null).toBe(Number(row.reltuples) < 0);
    }
  });

  it("grows the reported size as rows are added", async () => {
    const before = await auditStorageRepository.tableStats();
    const beforeBytes =
      before.find((row) => row.table === "gateway_events")?.total_bytes ?? 0;

    const marker = `itest-growth-${Date.now()}`;
    await db.execute(
      `INSERT INTO gateway_events (category, message, server_name)
       SELECT 'system', repeat('x', 900) || g, '${marker}'
       FROM generate_series(1, 4000) AS g` as never,
    );

    const after = await auditStorageRepository.tableStats();
    const afterBytes =
      after.find((row) => row.table === "gateway_events")?.total_bytes ?? 0;

    // The property the tripwire is built on: `pg_total_relation_size` tracks
    // real growth. A figure that never moved would make the threshold
    // unreachable and the whole monitor decorative.
    expect(afterBytes).toBeGreaterThan(beforeBytes);
  });

  it("measures the tables the application actually writes to", async () => {
    // `to_regclass` resolves through the connection's search_path, the same
    // way every unqualified table reference in this application does. Pinning
    // the OIDs against `current_schema()` is what proves the stats describe
    // those tables rather than same-named relations somewhere else on the
    // path.
    const resolved = await db.execute(
      `SELECT t.name,
              (to_regclass(t.name))::oid AS resolved_oid,
              (SELECT c.oid FROM pg_catalog.pg_class c
                 JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
                WHERE c.relname = t.name AND n.nspname = current_schema()) AS schema_oid
         FROM (VALUES ('audit_log'), ('gateway_events'), ('tool_call_audit')) AS t(name)` as never,
    );

    expect(resolved.rows).toHaveLength(3);
    for (const row of resolved.rows) {
      expect(row.resolved_oid).not.toBeNull();
      expect(row.resolved_oid).toBe(row.schema_oid);
    }
  });
});
