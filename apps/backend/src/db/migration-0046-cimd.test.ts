/**
 * Migration 0046 (the 'cimd' registration source): its own journal entry and
 * the shape of its SQL, without a database.
 *
 * The journal rule this guards for this one migration: drizzle applies only
 * the entries whose "when" is above the maximum already applied, so an entry
 * whose "when" is not above its predecessor's is SILENTLY skipped and the
 * CHECK never widens. The whole-journal ordering test belongs to another
 * change; this pins the one entry this change adds. The statement is proven
 * against a real database in
 * repositories/oauth-cimd.integration.test.ts, which applies the file twice.
 */
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

const DRIZZLE_DIR = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../drizzle",
);

interface JournalEntry {
  idx: number;
  version: string;
  when: number;
  tag: string;
  breakpoints: boolean;
}

const journal = JSON.parse(
  readFileSync(path.join(DRIZZLE_DIR, "meta", "_journal.json"), "utf8"),
) as { entries: JournalEntry[] };

const TAG = "0046_oauth_client_metadata_documents";
const entry = journal.entries.find((e) => e.tag === TAG);

describe("migration 0046 journal entry", () => {
  it("is present with the reserved index, tag and timestamp", () => {
    expect(entry).toEqual({
      idx: 46,
      version: "7",
      when: 1788393600000,
      tag: TAG,
      breakpoints: true,
    });
  });

  it("is above every entry before it, so drizzle will not skip it", () => {
    const before = journal.entries.filter((e) => e.tag !== TAG && e.idx < 46);
    expect(before.length).toBeGreaterThan(0);
    for (const prior of before) {
      expect({
        tag: prior.tag,
        below: prior.when < (entry?.when ?? 0),
      }).toEqual({
        tag: prior.tag,
        below: true,
      });
    }
  });
});

describe("migration 0046 SQL", () => {
  const sql = readFileSync(path.join(DRIZZLE_DIR, `${TAG}.sql`), "utf8");
  const statements = sql
    .split("\n")
    .filter((line) => !line.trimStart().startsWith("--"))
    .join("\n");

  it("widens the registration source CHECK to admit cimd and keeps the older values", () => {
    expect(statements).toContain('"oauth_clients_registration_source_valid"');
    expect(statements).toMatch(/IN \('dcr', 'admin', 'cimd'\)/);
    expect(statements).toMatch(/"registration_source" IS NULL/);
  });

  it("is idempotent: replaces the constraint only when it does not yet name cimd", () => {
    expect(statements).toMatch(/IF NOT EXISTS/);
    expect(statements).toMatch(/pg_get_constraintdef\(oid\) LIKE '%''cimd''%'/);
  });

  it("is additive: no column, table, index or data change", () => {
    expect(statements).not.toMatch(/\b(CREATE|DROP)\s+(TABLE|INDEX|COLUMN)\b/i);
    expect(statements).not.toMatch(/\bADD\s+COLUMN\b/i);
    expect(statements).not.toMatch(/\b(INSERT|UPDATE|DELETE|TRUNCATE)\b/i);
  });
});
