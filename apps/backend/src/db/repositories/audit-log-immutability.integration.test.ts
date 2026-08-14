/**
 * `audit_log` is append-only, and this proves it two ways.
 *
 * The operator requirement out of the 2026-08-13 incident is an audit archive
 * with NO application or admin path that empties it. Two things enforce that:
 * a repository with no delete/update/prune method (audit-log.repo.ts), and the
 * database triggers migration 0028 installs. The repository half is enforced
 * by its own absence; this file covers the database half.
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
 * worth anything the morning after an incident.
 *
 *   docker run -d --name metamcp-audit-test -e POSTGRES_PASSWORD=test \
 *     -e POSTGRES_USER=test -e POSTGRES_DB=metamcp_test \
 *     -p 127.0.0.1:55433:5432 postgres:16-alpine
 *   cd apps/backend
 *   DATABASE_URL=postgres://test:test@127.0.0.1:55433/metamcp_test \
 *     npx drizzle-kit migrate
 *   TEST_DATABASE_URL=postgres://test:test@127.0.0.1:55433/metamcp_test \
 *     npx vitest run src/db/repositories/audit-log-immutability.integration.test.ts
 *
 * NOTE for whoever runs layer 2: the rows this suite inserts CANNOT be cleaned
 * up afterwards. That is not an oversight — it is the property under test.
 * Point it at a disposable database.
 */

import { readFileSync } from "node:fs";
import path from "node:path";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

const MIGRATION_PATH = path.resolve(
  __dirname,
  "../../../drizzle/0028_audit_log.sql",
);
const JOURNAL_PATH = path.resolve(
  __dirname,
  "../../../drizzle/meta/_journal.json",
);

describe("migration 0028 — the DDL that makes the table append-only", () => {
  const raw = readFileSync(MIGRATION_PATH, "utf8");
  // Assertions run against the STATEMENTS, not the file: this migration's
  // header comment names the Phase-2 columns it deliberately omits, and a
  // naive whole-file match would read that prose as schema.
  const sql = raw
    .split("\n")
    .filter((line) => !line.trimStart().startsWith("--"))
    .join("\n");

  it("blocks all three wipe verbs, not just DELETE", () => {
    expect(sql).toContain(
      "CREATE OR REPLACE FUNCTION audit_log_block_mutation",
    );
    expect(sql).toContain("RAISE EXCEPTION");
    expect(sql).toMatch(/CREATE TRIGGER audit_log_no_update BEFORE UPDATE/);
    expect(sql).toMatch(/CREATE TRIGGER audit_log_no_delete BEFORE DELETE/);
    // TRUNCATE does not fire row-level triggers, so without a statement-level
    // one it stays a single-statement path to an empty audit archive.
    expect(sql).toMatch(/CREATE TRIGGER audit_log_no_truncate BEFORE TRUNCATE/);
  });

  it("is idempotent, per fork convention", () => {
    expect(sql).toContain('CREATE TABLE IF NOT EXISTS "audit_log"');
    expect((sql.match(/CREATE INDEX IF NOT EXISTS/g) ?? []).length).toBe(4);
    expect((sql.match(/DROP TRIGGER IF EXISTS/g) ?? []).length).toBe(3);
  });

  it("does NOT ship the Phase-2 hash-chain columns as always-NULL decoration", () => {
    expect(sql).not.toMatch(/\bprev_hash\b/);
    expect(sql).not.toMatch(/\brow_hash\b/);
  });
});

describe("drizzle journal", () => {
  const journal = JSON.parse(readFileSync(JOURNAL_PATH, "utf8")) as {
    entries: { idx: number; when: number; tag: string }[];
  };

  it("registers 0028 with a `when` STRICTLY GREATER than every earlier entry", () => {
    const [entry] = journal.entries.filter((e) => e.tag === "0028_audit_log");
    expect(entry).toBeDefined();

    const others = journal.entries.filter((e) => e.tag !== "0028_audit_log");
    const maxOther = Math.max(...others.map((e) => e.when));

    // drizzle applies only entries whose `when` exceeds the max already
    // applied. Get this wrong and the migration is skipped in production
    // WITHOUT an error — the audit table simply never exists.
    expect(entry.when).toBeGreaterThan(maxOther);
    expect(entry.idx).toBe(28);
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
let auditLogRepository: (typeof import("./audit-log.repo"))["auditLogRepository"];

describeIfDb("audit_log against a REAL postgres", () => {
  const marker = `itest-${Date.now()}`;

  beforeAll(async () => {
    if (!TEST_DATABASE_URL) return;

    // db/index reads DATABASE_URL at import time, so it has to be set BEFORE
    // the first dynamic import below.
    process.env.DATABASE_URL = TEST_DATABASE_URL;

    ({ db } = await import("../index"));
    ({ auditLogRepository } = await import("./audit-log.repo"));

    await auditLogRepository.record({
      actor_type: "api_key",
      actor_id: marker,
      action: "mcp.auth.denied",
      outcome: "denied",
      http_status: 401,
      detail: { reason: "invalid_api_key", credential: { last4: "0000" } },
    });
  });

  afterAll(async () => {
    if (!TEST_DATABASE_URL || !db) return;
    // Deliberately no cleanup: every removal verb is blocked, which is the
    // whole point. Use a disposable database.
    const { pool } = await import("../index");
    await pool.end();
  });

  it("accepts the INSERT the repository makes", async () => {
    const rows = await db.execute(
      `SELECT actor_type, action, outcome, http_status FROM audit_log WHERE actor_id = '${marker}'` as never,
    );

    expect(rows.rows).toHaveLength(1);
    expect(rows.rows[0]).toMatchObject({
      actor_type: "api_key",
      action: "mcp.auth.denied",
      outcome: "denied",
      http_status: 401,
    });
  });

  /**
   * drizzle wraps a driver error in its own `Failed query: …` message and
   * keeps the postgres one on `cause`, so asserting on the outer message
   * alone would pass for ANY failed statement — including a typo'd table
   * name, which would make this suite green while proving nothing.
   */
  async function expectRefusedAsAppendOnly(query: Promise<unknown>) {
    let raised: unknown;
    try {
      await query;
    } catch (error) {
      raised = error;
    }

    expect(raised).toBeDefined();
    const cause = (raised as { cause?: { message?: string } }).cause;
    expect(cause?.message).toMatch(/audit_log is append-only/);
  }

  it("REFUSES an UPDATE", async () => {
    await expectRefusedAsAppendOnly(
      db.execute(
        `UPDATE audit_log SET outcome = 'success' WHERE actor_id = '${marker}'` as never,
      ),
    );
  });

  it("REFUSES a DELETE", async () => {
    await expectRefusedAsAppendOnly(
      db.execute(`DELETE FROM audit_log WHERE actor_id = '${marker}'` as never),
    );
  });

  it("REFUSES a TRUNCATE", async () => {
    await expectRefusedAsAppendOnly(
      db.execute(`TRUNCATE TABLE audit_log` as never),
    );
  });

  it("still holds the row after all three attempts", async () => {
    const rows = await db.execute(
      `SELECT outcome FROM audit_log WHERE actor_id = '${marker}'` as never,
    );

    expect(rows.rows).toHaveLength(1);
    expect(rows.rows[0]).toMatchObject({ outcome: "denied" });
  });
});
