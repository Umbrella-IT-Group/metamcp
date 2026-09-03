/**
 * Refresh-token family reuse detection: migration 0037 and its repository.
 *
 * Refresh tokens rotate on every use, so a presented refresh token that is not
 * live but WAS rotated out of a family is reuse. Migration 0037 adds a
 * `family_id` to oauth_access_tokens (so a rotation chain is one family) and a
 * side table `oauth_rotated_refresh_tokens` (the reuse-detection surface). The
 * refresh grant revokes the whole family on reuse.
 *
 * Layer 1 (always runs): the migration SQL and the drizzle journal are asserted
 * directly. family_id is added nullable, backfilled, THEN set NOT NULL — get
 * that order wrong and SET NOT NULL fails on the rows the backfill has not yet
 * reached. Every CREATE must be IF NOT EXISTS or a re-run after a partial apply
 * crashes instead of no-opping. A migration whose journal entry does not
 * out-rank the previous max is SILENTLY SKIPPED by drizzle, so the ordering is
 * checked as a test, not trusted to review.
 *
 * Layer 2 (opt-in via TEST_DATABASE_URL): the repository is exercised against a
 * REAL Postgres. Recording a rotated token and detecting its reuse, revoking a
 * family without touching its neighbours, and reaping expired markers are all
 * claims about SQL behaviour that a mock cannot make.
 *
 *   docker run -d --name metamcp-0037-test -e POSTGRES_PASSWORD=test \
 *     -e POSTGRES_USER=test -e POSTGRES_DB=metamcp_test \
 *     -p 127.0.0.1:55437:5432 postgres:16-alpine
 *   cd apps/backend
 *   DATABASE_URL=postgres://test:test@127.0.0.1:55437/metamcp_test \
 *     npx drizzle-kit migrate
 *   TEST_DATABASE_URL=postgres://test:test@127.0.0.1:55437/metamcp_test \
 *     npx vitest run src/db/repositories/oauth-refresh-token-family.integration.test.ts
 *
 * Point it at a disposable database.
 */

import { readFileSync } from "node:fs";
import path from "node:path";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { hashApiKey } from "../../lib/api-key-hash";
import { INTEGRATION_DB_LOCK_KEY } from "./integration-db-lock";

const MIGRATION_PATH = path.resolve(
  __dirname,
  "../../../drizzle/0037_oauth_refresh_token_family.sql",
);
const JOURNAL_PATH = path.resolve(
  __dirname,
  "../../../drizzle/meta/_journal.json",
);

const RAW = readFileSync(MIGRATION_PATH, "utf8");

describe("migration 0037: family_id column and the rotated-token table", () => {
  // Assert against the STATEMENTS, not the file: the header prose names the
  // columns and the table, so a naive whole-file match would read comments as
  // schema.
  const sql = RAW.split("\n")
    .filter((line) => !line.trimStart().startsWith("--"))
    .join("\n");

  it("adds family_id nullable, then backfills, then sets NOT NULL — in that order", () => {
    const addAt = sql.indexOf('ADD COLUMN IF NOT EXISTS "family_id" uuid');
    // The column carries a DEFAULT so the image deployed before this migration
    // (which inserts without family_id) keeps issuing tokens if it is rolled
    // back after 0037 has run; each such insert becomes a family of one.
    expect(sql).toContain('"family_id" uuid DEFAULT gen_random_uuid()');
    const backfillAt = sql.search(
      /UPDATE "oauth_access_tokens"\s+SET "family_id" = gen_random_uuid\(\)\s+WHERE "family_id" IS NULL/,
    );
    const notNullAt = sql.indexOf('ALTER COLUMN "family_id" SET NOT NULL');

    expect(addAt).toBeGreaterThan(-1);
    expect(backfillAt).toBeGreaterThan(-1);
    expect(notNullAt).toBeGreaterThan(-1);
    // SET NOT NULL must come AFTER the backfill, or it fails on unbackfilled
    // rows; the backfill must come AFTER the ADD, or the column does not exist.
    expect(addAt).toBeLessThan(backfillAt);
    expect(backfillAt).toBeLessThan(notNullAt);
  });

  it("indexes family_id for the revocation delete", () => {
    expect(sql).toContain(
      'CREATE INDEX IF NOT EXISTS "oauth_access_tokens_family_id_idx"',
    );
  });

  it("creates the rotated-token table keyed on the stored hash with cascade FKs", () => {
    expect(sql).toContain(
      'CREATE TABLE IF NOT EXISTS "oauth_rotated_refresh_tokens"',
    );
    expect(sql).toContain('"refresh_token_hash" text PRIMARY KEY');
    expect(sql).toContain('"family_id" uuid NOT NULL');
    // Both owner columns cascade with their parent, so a deleted client or user
    // leaves no orphan markers.
    expect(sql).toMatch(
      /"client_id" text NOT NULL REFERENCES "oauth_clients" \("client_id"\) ON DELETE CASCADE/,
    );
    expect(sql).toMatch(
      /"user_id" text NOT NULL REFERENCES "users" \("id"\) ON DELETE CASCADE/,
    );
  });

  it("indexes the rotated table for revocation and for the reaper", () => {
    expect(sql).toContain(
      'CREATE INDEX IF NOT EXISTS "oauth_rotated_refresh_tokens_family_id_idx"',
    );
    expect(sql).toContain(
      'CREATE INDEX IF NOT EXISTS "oauth_rotated_refresh_tokens_expires_at_idx"',
    );
  });

  it("makes every CREATE idempotent, so a re-run after a partial apply is a no-op", () => {
    // A bare CREATE TABLE/INDEX (no IF NOT EXISTS) crashes the second time the
    // migration runs, which is exactly the partial-apply case idempotency is
    // for.
    const bareCreates = [...sql.matchAll(/CREATE (TABLE|INDEX)\s+"/g)];
    expect(bareCreates).toHaveLength(0);
  });
});

describe("drizzle journal", () => {
  const journal = JSON.parse(readFileSync(JOURNAL_PATH, "utf8")) as {
    entries: { idx: number; when: number; tag: string }[];
  };

  it("registers 0037 with a `when` STRICTLY GREATER than every earlier entry", () => {
    const [entry] = journal.entries.filter(
      (e) => e.tag === "0037_oauth_refresh_token_family",
    );
    expect(entry).toBeDefined();

    // drizzle applies only entries whose `when` exceeds the max already
    // applied. Get this wrong and the migration is skipped in production
    // WITHOUT an error, and neither the column nor the table is created.
    const earlier = journal.entries.filter((e) => e.idx < entry.idx);
    const maxEarlier = Math.max(...earlier.map((e) => e.when));

    expect(entry.when).toBeGreaterThan(maxEarlier);
    expect(entry.idx).toBe(37);
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
// visible in the vitest output, so "the integration test didn't run" can never
// be mistaken for "the integration test passed".
const describeIfDb = describe.skipIf(!TEST_DATABASE_URL);

type Db = Awaited<typeof import("../index")>["db"];

const HOUR = 60 * 60 * 1000;
const DAY = 24 * HOUR;

let db: Db;
let oauthRepository: (typeof import("./oauth.repo"))["oauthRepository"];

describeIfDb("family reuse detection against a REAL postgres", () => {
  const marker = `itest0037-${Date.now()}`;
  const user = `${marker}-user`;
  const client = `${marker}-client`;

  beforeAll(async () => {
    if (!TEST_DATABASE_URL) return;

    // db/index reads DATABASE_URL at import time, so it has to be set BEFORE the
    // first dynamic import below.
    process.env.DATABASE_URL = TEST_DATABASE_URL;
    ({ db } = await import("../index"));
    ({ oauthRepository } = await import("./oauth.repo"));

    // Serialize against every other TEST_DATABASE_URL suite: cleanupExpired
    // below is a GLOBAL delete, and the shared advisory lock is the only thing
    // that keeps a parallel suite's fixtures out of its blast radius.
    await db.execute(
      `SELECT pg_advisory_lock(${INTEGRATION_DB_LOCK_KEY})` as never,
    );

    // Clean slate for this run's scoped rows. Deleting the user cascades to its
    // access tokens and (migration 0037's FK) its rotated markers.
    await db.execute(`DELETE FROM "users" WHERE "id" = '${user}'` as never);
    await db.execute(
      `DELETE FROM "oauth_clients" WHERE "client_id" = '${client}'` as never,
    );
    await db.execute(
      `INSERT INTO "users" ("id", "name", "email") VALUES ('${user}', 'itest 0037', '${user}@example.test')` as never,
    );
    await db.execute(
      `INSERT INTO "oauth_clients" ("client_id", "client_name") VALUES ('${client}', 'itest 0037')` as never,
    );
  });

  afterAll(async () => {
    if (!TEST_DATABASE_URL || !db) return;
    await db.execute(`DELETE FROM "users" WHERE "id" = '${user}'` as never);
    await db.execute(
      `DELETE FROM "oauth_clients" WHERE "client_id" = '${client}'` as never,
    );
    await db.execute(
      `SELECT pg_advisory_unlock(${INTEGRATION_DB_LOCK_KEY})` as never,
    );
    const { pool } = await import("../index");
    await pool.end();
  });

  // Create a live token pair in a given family via the real write path.
  async function seedLive(family: string, suffix: string) {
    await oauthRepository.setAccessToken(`mcp_token_${suffix}`, {
      client_id: client,
      user_id: user,
      scope: "mcp",
      expires_at: Date.now() + 12 * HOUR,
      family_id: family,
      refresh: {
        token: `mcp_refresh_${suffix}`,
        expires_at: Date.now() + 30 * DAY,
      },
    });
  }

  it("records a rotated token and detects its later reuse by plaintext", async () => {
    const family = "f0000001-0000-0000-0000-000000000001";
    await oauthRepository.recordRotatedRefreshToken({
      refreshTokenHash: hashApiKey("mcp_refresh_rotated_a"),
      familyId: family,
      clientId: client,
      userId: user,
      expiresAt: new Date(Date.now() + 30 * DAY),
    });

    const hit = await oauthRepository.getRotatedRefreshToken(
      "mcp_refresh_rotated_a",
    );
    expect(hit).not.toBeNull();
    expect(hit?.family_id).toBe(family);
    expect(hit?.client_id).toBe(client);
    expect(hit?.user_id).toBe(user);

    // A token that was never rotated out is not a reuse.
    const miss = await oauthRepository.getRotatedRefreshToken(
      "mcp_refresh_never_issued",
    );
    expect(miss).toBeNull();
  });

  it("revokes ONLY the compromised family — live tokens and markers of others survive", async () => {
    const compromised = "f0000002-0000-0000-0000-000000000002";
    const bystander = "f0000003-0000-0000-0000-000000000003";

    await seedLive(compromised, "victim");
    await seedLive(bystander, "bystander");
    await oauthRepository.recordRotatedRefreshToken({
      refreshTokenHash: hashApiKey("mcp_refresh_victim_old"),
      familyId: compromised,
      clientId: client,
      userId: user,
      expiresAt: new Date(Date.now() + 30 * DAY),
    });
    await oauthRepository.recordRotatedRefreshToken({
      refreshTokenHash: hashApiKey("mcp_refresh_bystander_old"),
      familyId: bystander,
      clientId: client,
      userId: user,
      expiresAt: new Date(Date.now() + 30 * DAY),
    });

    const revoked = await oauthRepository.revokeFamily(compromised);
    // One live access-token row belonged to the compromised family.
    expect(revoked).toBe(1);

    // The compromised family's live token is dead and its marker is gone.
    expect(
      await oauthRepository.getByRefreshToken("mcp_refresh_victim"),
    ).toBeNull();
    expect(
      await oauthRepository.getRotatedRefreshToken("mcp_refresh_victim_old"),
    ).toBeNull();

    // The bystander family is entirely untouched.
    const survivor = await oauthRepository.getByRefreshToken(
      "mcp_refresh_bystander",
    );
    expect(survivor).not.toBeNull();
    expect(survivor?.family_id).toBe(bystander);
    expect(
      await oauthRepository.getRotatedRefreshToken("mcp_refresh_bystander_old"),
    ).not.toBeNull();
  });

  it("reaps rotated markers past their expiry and keeps live ones", async () => {
    const family = "f0000004-0000-0000-0000-000000000004";
    await oauthRepository.recordRotatedRefreshToken({
      refreshTokenHash: hashApiKey("mcp_refresh_expired_marker"),
      familyId: family,
      clientId: client,
      userId: user,
      // Already expired: the reaper must collect it.
      expiresAt: new Date(Date.now() - HOUR),
    });
    await oauthRepository.recordRotatedRefreshToken({
      refreshTokenHash: hashApiKey("mcp_refresh_fresh_marker"),
      familyId: family,
      clientId: client,
      userId: user,
      expiresAt: new Date(Date.now() + 30 * DAY),
    });

    await oauthRepository.cleanupExpired();

    expect(
      await oauthRepository.getRotatedRefreshToken(
        "mcp_refresh_expired_marker",
      ),
    ).toBeNull();
    expect(
      await oauthRepository.getRotatedRefreshToken("mcp_refresh_fresh_marker"),
    ).not.toBeNull();
  });

  it("rejects an access-token row with no family_id (NOT NULL holds at the column)", async () => {
    await expect(
      db.execute(
        `INSERT INTO "oauth_access_tokens" ("access_token", "access_token_last4", "client_id", "user_id", "expires_at") VALUES ('${marker}-nofamily', 'nofa', '${client}', '${user}', now() + interval '1 hour')` as never,
      ),
    ).rejects.toThrow();
  });
});
