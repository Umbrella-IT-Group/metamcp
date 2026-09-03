/**
 * Migration 0038 — the DDL that adds api_keys.admin_plane and its three
 * plane-separation CHECK constraints. Proven two ways.
 *
 * Layer 1 (always runs): the migration SQL, the drizzle journal, and the
 * schema.ts mirror are asserted directly. A migration whose journal entry does
 * not out-rank the previous max is SILENTLY SKIPPED by drizzle — the column
 * would simply never exist in production and nothing would fail loudly — so the
 * ordering is checked as a test, not trusted to review. The schema.ts mirror is
 * checked so a fresh `drizzle-kit generate` cannot try to re-add the column.
 *
 * Layer 2 (opt-in via TEST_DATABASE_URL): the column default and the three
 * CHECKs are exercised against a REAL Postgres. A CHECK that exists in a .sql
 * file and a CHECK that actually refuses a straddling row are different claims,
 * and only the second one keeps the planes apart the morning after.
 *
 *   docker run -d --name metamcp-adminplane-test -e POSTGRES_PASSWORD=test \
 *     -e POSTGRES_USER=test -e POSTGRES_DB=metamcp_test \
 *     -p 127.0.0.1:55561:5432 postgres:16-alpine
 *   cd apps/backend
 *   DATABASE_URL=postgres://test:test@127.0.0.1:55561/metamcp_test \
 *     npx drizzle-kit migrate
 *   TEST_DATABASE_URL=postgres://test:test@127.0.0.1:55561/metamcp_test \
 *     npx vitest run src/db/repositories/api-key-admin-plane.integration.test.ts
 */

import { readFileSync } from "node:fs";
import path from "node:path";

import { eq } from "drizzle-orm";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

import { INTEGRATION_DB_LOCK_KEY } from "./integration-db-lock";

const MIGRATION_PATH = path.resolve(
  __dirname,
  "../../../drizzle/0038_api_key_admin_plane.sql",
);
const JOURNAL_PATH = path.resolve(
  __dirname,
  "../../../drizzle/meta/_journal.json",
);
const SCHEMA_PATH = path.resolve(__dirname, "../schema.ts");

describe("migration 0038 — the DDL that adds the plane flag", () => {
  const raw = readFileSync(MIGRATION_PATH, "utf8");
  // Assert against the STATEMENTS, not the file: the header comment names the
  // planes and would otherwise be read as schema.
  const sql = raw
    .split("\n")
    .filter((line) => !line.trimStart().startsWith("--"))
    .join("\n");

  it("adds the column idempotently, NOT NULL default false (deploy is inert)", () => {
    expect(sql).toContain(
      'ALTER TABLE "api_keys" ADD COLUMN IF NOT EXISTS "admin_plane" boolean NOT NULL DEFAULT false',
    );
  });

  it("guards all three plane-separation CHECKs with a DO block (idempotent)", () => {
    for (const name of [
      "api_keys_admin_plane_requires_owner",
      "api_keys_admin_plane_no_endpoint_scope",
      "api_keys_admin_plane_no_acts_as",
    ]) {
      expect(sql).toContain(`conname = '${name}'`);
      expect(sql).toContain(`ADD CONSTRAINT "${name}"`);
    }
    // One DO $$ guard per constraint (postgres has no ADD CONSTRAINT IF NOT
    // EXISTS), matching the acts-as precedent in migration 0024.
    expect((sql.match(/DO \$\$/g) ?? []).length).toBe(3);
  });

  it("encodes each plane invariant in its CHECK expression", () => {
    expect(sql).toContain(
      'CHECK ("admin_plane" = false OR "user_id" IS NOT NULL)',
    );
    expect(sql).toContain(
      'CHECK ("admin_plane" = false OR "endpoint_uuid" IS NULL)',
    );
    expect(sql).toContain(
      'CHECK ("admin_plane" = false OR "acts_as_user_id" IS NULL)',
    );
  });
});

describe("drizzle journal", () => {
  const journal = JSON.parse(readFileSync(JOURNAL_PATH, "utf8")) as {
    entries: { idx: number; when: number; tag: string }[];
  };

  it("registers 0038 with a `when` strictly above every earlier entry", () => {
    const [entry] = journal.entries.filter(
      (e) => e.tag === "0038_api_key_admin_plane",
    );
    expect(entry).toBeDefined();
    const earlier = journal.entries.filter((e) => e.idx < entry.idx);
    const maxEarlier = Math.max(...earlier.map((e) => e.when));
    // drizzle applies only entries whose `when` exceeds the max already applied;
    // 0037 is 1787616000000. Get this wrong and 0038 is skipped in production
    // WITHOUT an error, and the column never exists.
    expect(entry.when).toBeGreaterThan(maxEarlier);
    expect(entry.when).toBeGreaterThan(1787616000000);
    expect(entry.idx).toBe(38);
  });

  it("keeps idx and when monotonically increasing across the whole journal", () => {
    const idxs = journal.entries.map((e) => e.idx);
    const whens = journal.entries.map((e) => e.when);
    expect(idxs).toEqual([...idxs].sort((a, b) => a - b));
    expect(whens).toEqual([...whens].sort((a, b) => a - b));
    expect(new Set(whens).size).toBe(whens.length);
  });
});

describe("schema.ts mirror — so `drizzle-kit generate` re-adds nothing", () => {
  const schema = readFileSync(SCHEMA_PATH, "utf8");

  it("declares the admin_plane column NOT NULL default false", () => {
    expect(schema).toContain(
      'admin_plane: boolean("admin_plane").notNull().default(false)',
    );
  });

  it("mirrors all three plane CHECKs by name", () => {
    expect(schema).toContain('"api_keys_admin_plane_requires_owner"');
    expect(schema).toContain('"api_keys_admin_plane_no_endpoint_scope"');
    expect(schema).toContain('"api_keys_admin_plane_no_acts_as"');
  });
});

const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL;
const describeIfDb = describe.skipIf(!TEST_DATABASE_URL);

type Db = Awaited<typeof import("../index")>["db"];
type Schema = typeof import("../schema");
type Repo = InstanceType<
  (typeof import("./api-keys.repo"))["ApiKeysRepository"]
>;

let db: Db;
let schema: Schema;
let repo: Repo;
let hashApiKey: (typeof import("../../lib/api-key-hash"))["hashApiKey"];

const USER_ID = "adminplane-owner";
const NAMESPACE_UUID = "50000000-0000-4000-8000-000000000001";
const ENDPOINT_UUID = "60000000-0000-4000-8000-00000000000a";

describeIfDb("api_keys.admin_plane against a REAL postgres", () => {
  beforeAll(async () => {
    if (!TEST_DATABASE_URL) return;
    process.env.DATABASE_URL = TEST_DATABASE_URL;
    ({ db } = await import("../index"));
    schema = await import("../schema");
    const { ApiKeysRepository } = await import("./api-keys.repo");
    repo = new ApiKeysRepository();
    ({ hashApiKey } = await import("../../lib/api-key-hash"));
    await db.execute(
      `SELECT pg_advisory_lock(${INTEGRATION_DB_LOCK_KEY})` as never,
    );
  });

  afterAll(async () => {
    if (!TEST_DATABASE_URL || !db) return;
    await truncate();
    await db.execute(
      `SELECT pg_advisory_unlock(${INTEGRATION_DB_LOCK_KEY})` as never,
    );
    const { pool } = await import("../index");
    await pool.end();
  });

  async function truncate() {
    await db.execute(
      `TRUNCATE TABLE users, endpoints, namespaces, api_keys RESTART IDENTITY CASCADE` as never,
    );
  }

  async function seed() {
    await truncate();
    await db.insert(schema.usersTable).values({
      id: USER_ID,
      name: "Admin Plane Owner",
      email: "adminplane-owner@example.invalid",
      role: "admin",
    });
    await db
      .insert(schema.namespacesTable)
      .values({ uuid: NAMESPACE_UUID, name: "adminplane-ns", user_id: null });
    await db.insert(schema.endpointsTable).values({
      uuid: ENDPOINT_UUID,
      name: "adminplane-ep",
      namespace_uuid: NAMESPACE_UUID,
      user_id: null,
    });
  }

  beforeEach(async () => {
    if (!TEST_DATABASE_URL) return;
    await seed();
  });

  it("defaults an existing-shape row to admin_plane=false", async () => {
    const [row] = await db
      .insert(schema.apiKeysTable)
      .values({
        name: "legacy-data-plane",
        key_hash: "hash-default-1",
        last4: "aaaa",
        user_id: USER_ID,
        endpoint_uuid: ENDPOINT_UUID,
      })
      .returning({ admin_plane: schema.apiKeysTable.admin_plane });
    expect(row.admin_plane).toBe(false);
  });

  it("accepts a well-formed admin-plane row (owner, no scope, no acts-as)", async () => {
    const [row] = await db
      .insert(schema.apiKeysTable)
      .values({
        name: "ci-control-plane",
        key_hash: "hash-ok-1",
        last4: "bbbb",
        user_id: USER_ID,
        endpoint_uuid: null,
        acts_as_user_id: null,
        admin_plane: true,
      })
      .returning({ admin_plane: schema.apiKeysTable.admin_plane });
    expect(row.admin_plane).toBe(true);
  });

  // The offending constraint name arrives on the pg driver error (`.constraint`
  // / its `.message`), which drizzle carries as the thrown error's `cause`; the
  // top-level message is just "Failed query: ...". Assert against the whole
  // chain so each test proves WHICH invariant fired, not merely that one did.
  async function checkViolation(promise: Promise<unknown>): Promise<string> {
    const err = (await promise.then(
      () => null,
      (e) => e,
    )) as
      | (Error & { constraint?: string; cause?: { constraint?: string } })
      | null;
    expect(err).not.toBeNull();
    const cause = err?.cause as
      | { constraint?: string; message?: string }
      | undefined;
    return [err?.message, err?.constraint, cause?.message, cause?.constraint]
      .filter(Boolean)
      .join(" | ");
  }

  it("requires-owner CHECK rejects an admin-plane row with a NULL owner", async () => {
    const chain = await checkViolation(
      db.insert(schema.apiKeysTable).values({
        name: "bad-public-control-plane",
        key_hash: "hash-bad-1",
        last4: "cccc",
        user_id: null,
        admin_plane: true,
      }),
    );
    expect(chain).toContain("api_keys_admin_plane_requires_owner");
  });

  it("no-endpoint-scope CHECK rejects an admin-plane row with an endpoint", async () => {
    const chain = await checkViolation(
      db.insert(schema.apiKeysTable).values({
        name: "bad-scoped-control-plane",
        key_hash: "hash-bad-2",
        last4: "dddd",
        user_id: USER_ID,
        endpoint_uuid: ENDPOINT_UUID,
        admin_plane: true,
      }),
    );
    expect(chain).toContain("api_keys_admin_plane_no_endpoint_scope");
  });

  it("an admin-plane row carrying an acts-as identity is refused (no_acts_as is the backstop)", async () => {
    // The explicit api_keys_admin_plane_no_acts_as CHECK exists (proven in
    // layer 1), but it is structurally SHADOWED in practice, which is exactly
    // the design's point: an admin-plane row with acts_as needs endpoint_uuid
    // to be null (no_endpoint_scope), and acts_as with a null endpoint already
    // trips the pre-existing api_keys_acts_as_requires_scope from migration
    // 0024. So an insert can only ever demonstrate one of the two firing; the
    // explicit no_acts_as CHECK is the invariant's backstop should acts_as ever
    // be changed. Either name here means "an admin-plane key cannot carry an
    // acts-as identity", which is the property under test.
    const chain = await checkViolation(
      db.insert(schema.apiKeysTable).values({
        name: "bad-identity-control-plane",
        key_hash: "hash-bad-3",
        last4: "eeee",
        user_id: USER_ID,
        endpoint_uuid: null,
        acts_as_user_id: USER_ID,
        admin_plane: true,
      }),
    );
    expect(
      chain.includes("api_keys_admin_plane_no_acts_as") ||
        chain.includes("api_keys_acts_as_requires_scope"),
    ).toBe(true);
  });

  describe("validateAdminPlaneApiKey — the control-plane resolver", () => {
    async function insertKey(over: {
      raw: string;
      name: string;
      admin_plane: boolean;
      is_active?: boolean;
      user_id?: string | null;
    }) {
      await db.insert(schema.apiKeysTable).values({
        name: over.name,
        key_hash: hashApiKey(over.raw),
        last4: over.raw.slice(-4),
        user_id: over.user_id === undefined ? USER_ID : over.user_id,
        endpoint_uuid: null,
        acts_as_user_id: null,
        admin_plane: over.admin_plane,
        is_active: over.is_active ?? true,
      });
    }

    it("resolves an active admin-plane key to its owner with the fresh role", async () => {
      await insertKey({
        raw: "sk_mt_valid_admin_plane",
        name: "ci-valid",
        admin_plane: true,
      });

      const result = await repo.validateAdminPlaneApiKey(
        "sk_mt_valid_admin_plane",
      );

      expect(result.valid).toBe(true);
      if (result.valid) {
        expect(result.user.id).toBe(USER_ID);
        expect(result.user.role).toBe("admin");
        expect(result.disabled).toBe(false);
      }
    });

    it("returns not_admin_plane for a data-plane key", async () => {
      await insertKey({
        raw: "sk_mt_data_plane_here",
        name: "dp",
        admin_plane: false,
      });

      const result = await repo.validateAdminPlaneApiKey(
        "sk_mt_data_plane_here",
      );
      expect(result).toEqual({ valid: false, reason: "not_admin_plane" });
    });

    it("returns inactive for a deactivated admin-plane key", async () => {
      await insertKey({
        raw: "sk_mt_inactive_admin",
        name: "ci-inactive",
        admin_plane: true,
        is_active: false,
      });

      const result = await repo.validateAdminPlaneApiKey(
        "sk_mt_inactive_admin",
      );
      expect(result).toEqual({ valid: false, reason: "inactive" });
    });

    it("returns unknown_key for a key that does not exist", async () => {
      const result = await repo.validateAdminPlaneApiKey("sk_mt_no_such_key");
      expect(result).toEqual({ valid: false, reason: "unknown_key" });
    });

    it("reports disabled=true (valid) when the owner is locked out — caller fails closed", async () => {
      await db
        .update(schema.usersTable)
        .set({ disabled: true })
        .where(eq(schema.usersTable.id, USER_ID));
      await insertKey({
        raw: "sk_mt_disabled_owner_key",
        name: "ci-disabled-owner",
        admin_plane: true,
      });

      const result = await repo.validateAdminPlaneApiKey(
        "sk_mt_disabled_owner_key",
      );
      expect(result.valid).toBe(true);
      if (result.valid) expect(result.disabled).toBe(true);
    });
  });
});
