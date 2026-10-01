/**
 * Migration 0039 adds `args_shape` and `error_detail` to `tool_call_audit`, and
 * this proves the two properties that matter about it, two ways.
 *
 * 1. IT IS APPLIED. A migration whose journal `when` does not exceed the max
 *    already applied is SILENTLY SKIPPED by drizzle: no error, the columns are
 *    just never created. Here that is the worst case in the schema, because
 *    every audit INSERT would then reference a missing column, fail, and be
 *    swallowed by the fire-and-forget writer: the audit trail stops recording
 *    and nothing says so. The ordering is therefore asserted as a test, not
 *    trusted to review.
 * 2. IT IS HARMLESS to the guarantees the table already carries: the columns
 *    are nullable, unconstrained and unindexed (a violation would be a
 *    swallowed INSERT failure), the statements are idempotent, and the
 *    immutability triggers from 0032 still refuse an UPDATE of the new columns.
 *
 * Layer 1 (always runs): the SQL and the journal are asserted directly, with
 * no database.
 *
 * Layer 2 (opt-in via TEST_DATABASE_URL): the same claims against a REAL
 * Postgres, after `drizzle-kit migrate` has applied every migration. The rows
 * this suite inserts inside the 30-day window CANNOT be cleaned up afterwards;
 * that is the property under test, so point it at a disposable database. See
 * tool-call-audit-immutability.integration.test.ts for the recipe.
 */

import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

const MIGRATION_TAG = "0039_tool_call_audit_args_shape_and_error_detail";
const MIGRATION_PATH = path.resolve(
  __dirname,
  `../../../drizzle/${MIGRATION_TAG}.sql`,
);
const JOURNAL_PATH = path.resolve(
  __dirname,
  "../../../drizzle/meta/_journal.json",
);
// The max `when` before this migration (0038). The new entry must exceed it and
// every other entry; asserting the literal as well means a future edit that
// lowers it fails here and not at deploy.
const PRIOR_MAX_WHEN = 1787702400000;

const raw = readFileSync(MIGRATION_PATH, "utf8");
// Assertions run against the STATEMENTS, not the file: the header comment
// names constraints and statements it forbids, and a whole-file match would
// read that prose as schema.
const sql = raw
  .split("\n")
  .filter((line) => !line.trimStart().startsWith("--"))
  .join("\n");

describe("migration 0039: the DDL", () => {
  it("is exactly two idempotent ADD COLUMN statements", () => {
    const statements = sql
      .split(";")
      .map((statement) => statement.trim())
      .filter((statement) => statement.length > 0);

    expect(statements).toEqual([
      'ALTER TABLE "tool_call_audit" ADD COLUMN IF NOT EXISTS "args_shape" jsonb',
      'ALTER TABLE "tool_call_audit" ADD COLUMN IF NOT EXISTS "error_detail" text',
    ]);
  });

  it("carries no NOT NULL, DEFAULT, CHECK, index, UPDATE or DROP", () => {
    // Every one of these either turns a failed write into a swallowed INSERT
    // failure (a silently missing audit row) or is refused by 0032 anyway.
    for (const forbidden of [
      /NOT NULL/i,
      /DEFAULT/i,
      /CHECK/i,
      /CREATE\s+(UNIQUE\s+)?INDEX/i,
      /\bUPDATE\b/i,
      /\bDROP\b/i,
      /\bDELETE\b/i,
    ]) {
      expect(sql).not.toMatch(forbidden);
    }
  });

  it("contains no email-shaped literal (migrations above 0034 are guarded)", () => {
    expect(raw).not.toMatch(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/);
  });

  it("matches the drizzle schema columns", () => {
    const schema = readFileSync(
      path.resolve(__dirname, "../schema.ts"),
      "utf8",
    );
    expect(schema).toContain('args_shape: jsonb("args_shape")');
    expect(schema).toContain('error_detail: text("error_detail")');
    // Nullable in the schema too: no .notNull() chained on either column.
    expect(schema).not.toMatch(/args_shape:[^\n]*notNull/);
    expect(schema).not.toMatch(/error_detail:[^\n]*notNull/);
  });
});

describe("drizzle journal ordering for 0039", () => {
  const journal = JSON.parse(readFileSync(JOURNAL_PATH, "utf8")) as {
    entries: { idx: number; when: number; tag: string }[];
  };

  it("registers 0039 as idx 39 with the migration's file name as its tag", () => {
    const entry = journal.entries.find((e) => e.tag === MIGRATION_TAG);
    expect(entry).toBeDefined();
    expect(entry?.idx).toBe(39);
  });

  it("has a `when` STRICTLY GREATER than every other entry", () => {
    const entry = journal.entries.find((e) => e.tag === MIGRATION_TAG);
    const when = entry?.when ?? Number.NEGATIVE_INFINITY;
    const others = journal.entries.filter((e) => e.tag !== MIGRATION_TAG);
    const maxOther = Math.max(...others.map((e) => e.when));

    // drizzle applies only entries whose `when` exceeds the max already
    // applied. Get this wrong and 0039 is skipped in production WITHOUT an
    // error and every audit INSERT starts failing silently.
    expect(when).toBeGreaterThan(maxOther);
    expect(when).toBeGreaterThan(PRIOR_MAX_WHEN);
  });

  it("keeps idx and when monotonically increasing and unique across the journal", () => {
    const idxs = journal.entries.map((e) => e.idx);
    const whens = journal.entries.map((e) => e.when);
    expect(idxs).toEqual([...idxs].sort((a, b) => a - b));
    expect(whens).toEqual([...whens].sort((a, b) => a - b));
    expect(new Set(whens).size).toBe(whens.length);
  });

  it("lists every migration file and every listed entry has a file", () => {
    // A .sql file the journal does not list is never applied (silent); a
    // journal entry with no file crashes the migrator (loud). Both are cheap to
    // catch here.
    const files = readdirSync(path.dirname(MIGRATION_PATH))
      .filter((name) => name.endsWith(".sql"))
      .map((name) => name.slice(0, -".sql".length))
      .sort();
    const tags = journal.entries.map((e) => e.tag).sort();
    expect(tags).toEqual(files);
  });
});

const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL;

// `describe.skipIf` rather than a silent early return: a skipped suite shows in
// the vitest output, so "the DB test didn't run" is never mistaken for "passed".
const describeIfDb = describe.skipIf(!TEST_DATABASE_URL);

type Db = Awaited<typeof import("../index")>["db"];

let db: Db;
let toolCallAuditRepository: (typeof import("./tool-call-audit.repo"))["toolCallAuditRepository"];

describeIfDb("migration 0039 against a REAL postgres", () => {
  const marker = `itest-shape-${Date.now()}`;

  beforeAll(async () => {
    if (!TEST_DATABASE_URL) return;
    // db/index reads DATABASE_URL at import time, so set it BEFORE the import.
    process.env.DATABASE_URL = TEST_DATABASE_URL;
    ({ db } = await import("../index"));
    ({ toolCallAuditRepository } = await import("./tool-call-audit.repo"));
  });

  afterAll(async () => {
    if (!TEST_DATABASE_URL || !db) return;
    // No cleanup of the inserted row: removing it is exactly what 0032 blocks.
    const { pool } = await import("../index");
    await pool.end();
  });

  it("has both columns, nullable, with no default", async () => {
    const result = await db.execute(
      `SELECT column_name, data_type, is_nullable, column_default
         FROM information_schema.columns
        WHERE table_name = 'tool_call_audit'
          AND column_name IN ('args_shape', 'error_detail')
        ORDER BY column_name` as never,
    );

    expect(result.rows).toEqual([
      {
        column_name: "args_shape",
        data_type: "jsonb",
        is_nullable: "YES",
        column_default: null,
      },
      {
        column_name: "error_detail",
        data_type: "text",
        is_nullable: "YES",
        column_default: null,
      },
    ]);
  });

  it("records a row with args_shape and error_detail and reads it back", async () => {
    await toolCallAuditRepository.record({
      server_name: marker,
      tool_name: "example_tool",
      success: false,
      error_code: "inband_error",
      error_detail: "invalid_input",
      args_shape: { sel: { mode: "list" }, keys: ["company", "mode"] },
    });

    const result = await db.execute(
      `SELECT error_code, error_detail,
              args_shape->'sel'->>'mode' AS mode,
              args_shape->'keys' AS keys
         FROM tool_call_audit WHERE server_name = '${marker}'` as never,
    );

    expect(result.rows).toHaveLength(1);
    expect(result.rows[0]).toMatchObject({
      error_code: "inband_error",
      error_detail: "invalid_input",
      mode: "list",
      keys: ["company", "mode"],
    });
  });

  it("still accepts a row with neither column (a pre-0039 style INSERT)", async () => {
    const bare = `${marker}-bare`;
    await toolCallAuditRepository.record({
      server_name: bare,
      tool_name: "example_tool",
      success: true,
    });
    const result = await db.execute(
      `SELECT args_shape, error_detail FROM tool_call_audit WHERE server_name = '${bare}'` as never,
    );
    expect(result.rows).toEqual([{ args_shape: null, error_detail: null }]);
  });

  it("REFUSES an UPDATE of the new columns (0032 still holds)", async () => {
    let raised: unknown;
    try {
      await db.execute(
        `UPDATE tool_call_audit SET error_detail = 'tampered' WHERE server_name = '${marker}'` as never,
      );
    } catch (error) {
      raised = error;
    }
    expect(raised).toBeDefined();
    const cause = (raised as { cause?: { message?: string } }).cause;
    expect(cause?.message).toMatch(/tool_call_audit is append-only/);
  });

  it("re-running the migration statements is a no-op (idempotent)", async () => {
    for (const statement of sql
      .split(";")
      .map((s) => s.trim())
      .filter((s) => s.length > 0)) {
      await db.execute(statement as never);
    }
    const result = await db.execute(
      `SELECT count(*)::int AS n FROM information_schema.columns
        WHERE table_name = 'tool_call_audit'
          AND column_name IN ('args_shape', 'error_detail')` as never,
    );
    expect(result.rows[0]).toMatchObject({ n: 2 });
  });
});
