/**
 * `oauth_access_tokens` must hold refresh token and refresh expiry
 * both-or-neither, and migration 0035 is what makes existing data honor that
 * before it adds the CHECK.
 *
 * A row with a refresh token but a NULL expiry is never-expiring (the refresh
 * grant reads a NULL expiry as "not expired") and never-reaped (no
 * cleanupExpired predicate matches it), so it is an immortal credential. The
 * mirror shape, an expiry with no refresh token, is meaningless. 0035 repairs
 * both shapes and THEN adds the constraint, inside one pg_constraint-guarded
 * block, so applying it can never fail on rows written before it.
 *
 * Layer 1 (always runs): the migration SQL and the drizzle journal are
 * asserted directly. The repair has to happen BEFORE the ALTER or the ALTER
 * still fails on legacy data, and the whole block has to stay behind the
 * pg_constraint guard or a re-run re-repairs already-good rows. A migration
 * whose journal entry does not out-rank the previous max is SILENTLY SKIPPED
 * by drizzle, so the ordering is checked as a test, not trusted to review.
 *
 * Layer 2 (opt-in via TEST_DATABASE_URL): the migration is exercised against a
 * REAL Postgres. A repair that lives in a .sql file and a repair that actually
 * turns a violating row into a legitimate one are different claims, and only
 * the second one keeps the gateway booting the morning it deploys.
 *
 *   docker run -d --name metamcp-0035-test -e POSTGRES_PASSWORD=test \
 *     -e POSTGRES_USER=test -e POSTGRES_DB=metamcp_test \
 *     -p 127.0.0.1:55435:5432 postgres:16-alpine
 *   cd apps/backend
 *   DATABASE_URL=postgres://test:test@127.0.0.1:55435/metamcp_test \
 *     npx drizzle-kit migrate
 *   TEST_DATABASE_URL=postgres://test:test@127.0.0.1:55435/metamcp_test \
 *     npx vitest run src/db/repositories/oauth-refresh-pairing.integration.test.ts
 *
 * Point it at a disposable database.
 */

import { readFileSync } from "node:fs";
import path from "node:path";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

const MIGRATION_PATH = path.resolve(
  __dirname,
  "../../../drizzle/0035_oauth_refresh_expiry_pairing_check.sql",
);
const JOURNAL_PATH = path.resolve(
  __dirname,
  "../../../drizzle/meta/_journal.json",
);

const RAW = readFileSync(MIGRATION_PATH, "utf8");

describe("migration 0035: repair then constrain", () => {
  // Assert against the STATEMENTS, not the file: the header prose names the
  // shapes and the columns, so a naive whole-file match would read comments as
  // schema.
  const sql = RAW.split("\n")
    .filter((line) => !line.trimStart().startsWith("--"))
    .join("\n");

  it("guards the whole block on pg_constraint so a re-run is a no-op", () => {
    expect(sql).toContain("FROM pg_constraint");
    expect(sql).toContain("conname = 'oauth_access_tokens_refresh_pairing'");
    expect(sql).toMatch(/IF NOT EXISTS \(\s*SELECT 1 FROM pg_constraint/);
  });

  it("repairs both mixed shapes", () => {
    // The immortal-credential shape: a refresh token with no expiry becomes an
    // already-expired refresh token.
    expect(sql).toMatch(
      /UPDATE "oauth_access_tokens"\s+SET "refresh_token_expires_at" = now\(\)\s+WHERE "refresh_token" IS NOT NULL\s+AND "refresh_token_expires_at" IS NULL/,
    );
    // The meaningless mirror shape: an orphan expiry with no refresh token is
    // cleared.
    expect(sql).toMatch(
      /UPDATE "oauth_access_tokens"\s+SET "refresh_token_expires_at" = NULL\s+WHERE "refresh_token" IS NULL\s+AND "refresh_token_expires_at" IS NOT NULL/,
    );
  });

  it("runs both repairs BEFORE the ALTER, or the ALTER still fails", () => {
    const updates = [...sql.matchAll(/UPDATE "oauth_access_tokens"/g)];
    const alterAt = sql.indexOf('ALTER TABLE "oauth_access_tokens"');

    expect(updates).toHaveLength(2);
    expect(alterAt).toBeGreaterThan(-1);
    for (const update of updates) {
      expect(update.index).toBeLessThan(alterAt);
    }
  });

  it("adds the both-or-neither CHECK under the documented name", () => {
    expect(sql).toContain(
      'ADD CONSTRAINT "oauth_access_tokens_refresh_pairing"',
    );
    expect(sql).toContain(
      'CHECK (("refresh_token" IS NULL) = ("refresh_token_expires_at" IS NULL))',
    );
  });
});

describe("drizzle journal", () => {
  const journal = JSON.parse(readFileSync(JOURNAL_PATH, "utf8")) as {
    entries: { idx: number; when: number; tag: string }[];
  };

  it("registers 0035 with a `when` STRICTLY GREATER than every earlier entry", () => {
    const [entry] = journal.entries.filter(
      (e) => e.tag === "0035_oauth_refresh_expiry_pairing_check",
    );
    expect(entry).toBeDefined();

    // drizzle applies only entries whose `when` exceeds the max already
    // applied. Get this wrong and the migration is skipped in production
    // WITHOUT an error, and the repair and the constraint never run.
    const earlier = journal.entries.filter((e) => e.idx < entry.idx);
    const maxEarlier = Math.max(...earlier.map((e) => e.when));

    expect(entry.when).toBeGreaterThan(maxEarlier);
    expect(entry.idx).toBe(35);
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
// visible in the vitest output, so "the migration test didn't run" can never
// be mistaken for "the migration test passed".
const describeIfDb = describe.skipIf(!TEST_DATABASE_URL);

type Db = Awaited<typeof import("../index")>["db"];

let db: Db;

describeIfDb("migration 0035 against a REAL postgres", () => {
  const marker = `itest0035-${Date.now()}`;
  const user = `${marker}-user`;
  const client = `${marker}-client`;

  // The four rows under test: two violating shapes to repair, and two
  // legitimate shapes that must survive the migration untouched.
  const immortal = `${marker}-immortal`; // refresh token, NULL expiry
  const orphan = `${marker}-orphan`; // NULL refresh token, non-NULL expiry
  const refreshable = `${marker}-refreshable`; // both set, legitimate
  const noRefresh = `${marker}-norefresh`; // both NULL, legitimate

  beforeAll(async () => {
    if (!TEST_DATABASE_URL) return;

    // db/index reads DATABASE_URL at import time, so it has to be set BEFORE
    // the first dynamic import below.
    process.env.DATABASE_URL = TEST_DATABASE_URL;
    ({ db } = await import("../index"));

    // Start from a clean slate: drop the constraint so violating rows can be
    // inserted, then remove any rows a prior run left. The migration re-adds
    // the constraint, which is the property under test.
    await db.execute(
      `ALTER TABLE "oauth_access_tokens" DROP CONSTRAINT IF EXISTS "oauth_access_tokens_refresh_pairing"` as never,
    );
    await db.execute(
      `DELETE FROM "oauth_access_tokens" WHERE "user_id" = '${user}'` as never,
    );
    await db.execute(`DELETE FROM "users" WHERE "id" = '${user}'` as never);
    await db.execute(
      `DELETE FROM "oauth_clients" WHERE "client_id" = '${client}'` as never,
    );

    // Parents for the token FKs.
    await db.execute(
      `INSERT INTO "users" ("id", "name", "email") VALUES ('${user}', 'itest 0035', '${user}@example.test')` as never,
    );
    await db.execute(
      `INSERT INTO "oauth_clients" ("client_id", "client_name") VALUES ('${client}', 'itest 0035')` as never,
    );

    // Two violating rows.
    await db.execute(
      `INSERT INTO "oauth_access_tokens" ("access_token", "client_id", "user_id", "expires_at", "refresh_token", "refresh_token_expires_at") VALUES ('${immortal}', '${client}', '${user}', now() + interval '1 hour', 'rt-${immortal}', NULL)` as never,
    );
    await db.execute(
      `INSERT INTO "oauth_access_tokens" ("access_token", "client_id", "user_id", "expires_at", "refresh_token", "refresh_token_expires_at") VALUES ('${orphan}', '${client}', '${user}', now() + interval '1 hour', NULL, now() + interval '30 days')` as never,
    );
    // Two legitimate rows that must not be altered. The refreshable row's
    // refresh expiry is far enough out that a spurious repair to now() would be
    // detectable.
    await db.execute(
      `INSERT INTO "oauth_access_tokens" ("access_token", "client_id", "user_id", "expires_at", "refresh_token", "refresh_token_expires_at") VALUES ('${refreshable}', '${client}', '${user}', now() + interval '1 hour', 'rt-${refreshable}', now() + interval '30 days')` as never,
    );
    await db.execute(
      `INSERT INTO "oauth_access_tokens" ("access_token", "client_id", "user_id", "expires_at", "refresh_token", "refresh_token_expires_at") VALUES ('${noRefresh}', '${client}', '${user}', now() + interval '1 hour', NULL, NULL)` as never,
    );

    // Apply the migration exactly as it ships.
    await db.execute(RAW as never);
  });

  afterAll(async () => {
    if (!TEST_DATABASE_URL || !db) return;
    const { pool } = await import("../index");
    await pool.end();
  });

  async function refreshExpiry(accessToken: string) {
    const rows = await db.execute(
      `SELECT "refresh_token", "refresh_token_expires_at" FROM "oauth_access_tokens" WHERE "access_token" = '${accessToken}'` as never,
    );
    return rows.rows[0] as {
      refresh_token: string | null;
      refresh_token_expires_at: Date | null;
    };
  }

  it("adds the constraint the migration is guarded on", async () => {
    const rows = await db.execute(
      `SELECT 1 FROM pg_constraint WHERE conname = 'oauth_access_tokens_refresh_pairing' AND conrelid = '"oauth_access_tokens"'::regclass` as never,
    );
    expect(rows.rows).toHaveLength(1);
  });

  it("repairs the immortal shape into an expired refresh token", async () => {
    const row = await refreshExpiry(immortal);
    expect(row.refresh_token).not.toBeNull();
    expect(row.refresh_token_expires_at).not.toBeNull();
  });

  it("clears the orphan expiry with no refresh token", async () => {
    const row = await refreshExpiry(orphan);
    expect(row.refresh_token).toBeNull();
    expect(row.refresh_token_expires_at).toBeNull();
  });

  it("leaves the legitimate refreshable row untouched", async () => {
    const row = await refreshExpiry(refreshable);
    expect(row.refresh_token).not.toBeNull();
    expect(row.refresh_token_expires_at).not.toBeNull();
    // A spurious repair would have overwritten this with now(); the seed put it
    // ~30 days out, so it must still be well in the future.
    const at = new Date(row.refresh_token_expires_at as Date).getTime();
    expect(at).toBeGreaterThan(Date.now() + 24 * 60 * 60 * 1000);
  });

  it("leaves the legitimate no-refresh row untouched", async () => {
    const row = await refreshExpiry(noRefresh);
    expect(row.refresh_token).toBeNull();
    expect(row.refresh_token_expires_at).toBeNull();
  });

  it("leaves zero violating rows behind", async () => {
    const rows = await db.execute(
      `SELECT count(*)::int AS n FROM "oauth_access_tokens" WHERE ("refresh_token" IS NULL) <> ("refresh_token_expires_at" IS NULL) AND "user_id" = '${user}'` as never,
    );
    expect((rows.rows[0] as { n: number }).n).toBe(0);
  });

  it("is a no-op on a second apply", async () => {
    await expect(db.execute(RAW as never)).resolves.toBeDefined();
    const rows = await db.execute(
      `SELECT count(*)::int AS n FROM pg_constraint WHERE conname = 'oauth_access_tokens_refresh_pairing' AND conrelid = '"oauth_access_tokens"'::regclass` as never,
    );
    expect((rows.rows[0] as { n: number }).n).toBe(1);
  });
});
