/**
 * Migration 0040 and the API-key IP policy against a REAL Postgres.
 *
 * Layer 1 (always runs): the migration SQL, the drizzle journal and the
 * schema.ts mirror are asserted directly. A journal entry whose `when` does not
 * out-rank the previous max is SILENTLY skipped by drizzle (the columns would
 * never exist in production and the validators would fail on every request),
 * so ordering is a test, not a review item.
 *
 * Layer 2 (opt-in via TEST_DATABASE_URL): the column defaults that make the
 * deploy inert, the mode CHECK, and the two validators end to end (real
 * repository, real config rows, real policy module) for the precedence rules,
 * the opt-in, the any-IP exemption and the last_used_ip stamp. Run each
 * integration file on its own:
 *
 *   cd apps/backend
 *   DATABASE_URL=<throwaway db> npx drizzle-kit migrate
 *   TEST_DATABASE_URL=<throwaway db> \
 *     npx vitest run src/db/repositories/api-key-ip-allowlist.integration.test.ts
 *
 * Addresses are RFC 5737 / RFC 3849 documentation ranges only.
 */

import { readFileSync } from "node:fs";
import path from "node:path";

import { eq } from "drizzle-orm";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

import { INTEGRATION_DB_LOCK_KEY } from "./integration-db-lock";

const MIGRATION_PATH = path.resolve(
  __dirname,
  "../../../drizzle/0041_api_key_ip_allowlist.sql",
);
const JOURNAL_PATH = path.resolve(
  __dirname,
  "../../../drizzle/meta/_journal.json",
);
const SCHEMA_PATH = path.resolve(__dirname, "../schema.ts");

describe("migration 0040: the DDL", () => {
  const raw = readFileSync(MIGRATION_PATH, "utf8");
  const sql = raw
    .split("\n")
    .filter((line) => !line.trimStart().startsWith("--"))
    .join("\n");

  it("adds the three columns idempotently with inert defaults", () => {
    expect(sql).toContain(
      'ALTER TABLE "api_keys" ADD COLUMN IF NOT EXISTS "allowed_cidrs" text[];',
    );
    expect(sql).toContain(
      `ALTER TABLE "api_keys" ADD COLUMN IF NOT EXISTS "ip_policy_mode" text NOT NULL DEFAULT 'off';`,
    );
    expect(sql).toContain(
      'ALTER TABLE "api_keys" ADD COLUMN IF NOT EXISTS "last_used_ip" text;',
    );
  });

  it("guards the mode CHECK with a DO block (idempotent)", () => {
    expect(sql).toContain("conname = 'api_keys_ip_policy_mode_valid'");
    expect(sql).toContain(
      `CHECK ("ip_policy_mode" IN ('off', 'audit', 'enforce'))`,
    );
    expect((sql.match(/DO \$\$/g) ?? []).length).toBe(1);
  });
});

describe("drizzle journal for 0040", () => {
  const journal = JSON.parse(readFileSync(JOURNAL_PATH, "utf8")) as {
    entries: { idx: number; when: number; tag: string }[];
  };

  it("registers 0040 with a `when` strictly above every EARLIER entry", () => {
    const entry = journal.entries.find(
      (e) => e.tag === "0041_api_key_ip_allowlist",
    );
    expect(entry).toBeDefined();
    expect(entry?.idx).toBe(41);
    const earlier = journal.entries.filter((e) => e.idx < (entry?.idx ?? 0));
    expect(entry?.when).toBeGreaterThan(
      Math.max(...earlier.map((e) => e.when)),
    );
    // 0039's `when`; get this wrong and 0040 is skipped WITHOUT an error.
    expect(entry?.when).toBeGreaterThan(1787788800000);
  });
});

describe("schema.ts mirror: so `drizzle-kit generate` re-adds nothing", () => {
  const schema = readFileSync(SCHEMA_PATH, "utf8");

  it("declares the three columns and the CHECK", () => {
    expect(schema).toContain('allowed_cidrs: text("allowed_cidrs").array()');
    expect(schema).toContain(
      'ip_policy_mode: text("ip_policy_mode").notNull().default("off")',
    );
    expect(schema).toContain('last_used_ip: text("last_used_ip")');
    expect(schema).toContain('"api_keys_ip_policy_mode_valid"');
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
let configService: (typeof import("../../lib/config.service"))["configService"];
let resetPolicyState: () => void;

const USER_ID = "ipallow-owner";

const check = (clientIp: string | undefined, surface = "data_plane") => ({
  clientIp,
  surface: surface as "data_plane" | "admin_plane",
  audit: {
    actor_ip: clientIp ?? null,
    actor_user_agent: null,
    request_id: null,
  },
});

describeIfDb("API-key IP policy against a REAL postgres", () => {
  beforeAll(async () => {
    if (!TEST_DATABASE_URL) return;
    process.env.DATABASE_URL = TEST_DATABASE_URL;
    ({ db } = await import("../index"));
    schema = await import("../schema");
    const { ApiKeysRepository } = await import("./api-keys.repo");
    repo = new ApiKeysRepository();
    ({ hashApiKey } = await import("../../lib/api-key-hash"));
    ({ configService } = await import("../../lib/config.service"));
    const policy = await import("../../lib/api-key-ip-policy");
    resetPolicyState = policy.__resetIpPolicyStateForTesting;
    // No audit rows from this suite: the audit table is append-only and has
    // its own suites; the throttle and the rows are pinned in unit tests.
    const { setAuditSinkForTesting } = await import(
      "../../lib/audit/audit-emitter"
    );
    setAuditSinkForTesting(null);
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
      `TRUNCATE TABLE users, api_keys RESTART IDENTITY CASCADE` as never,
    );
    await db.execute(
      `DELETE FROM config WHERE id IN ('API_KEY_IP_POLICY_MODE', 'API_KEY_IP_ALLOWED_CIDRS')` as never,
    );
  }

  beforeEach(async () => {
    if (!TEST_DATABASE_URL) return;
    resetPolicyState();
    await truncate();
    await db.insert(schema.usersTable).values({
      id: USER_ID,
      name: "IP Allow Owner",
      email: "ipallow-owner@example.invalid",
      role: "admin",
    });
  });

  async function insertKey(over: {
    raw: string;
    admin_plane?: boolean;
    allowed_cidrs?: string[] | null;
    ip_policy_mode?: string;
  }) {
    const [row] = await db
      .insert(schema.apiKeysTable)
      .values({
        name: over.raw,
        key_hash: hashApiKey(over.raw),
        last4: over.raw.slice(-4),
        user_id: USER_ID,
        endpoint_uuid: null,
        admin_plane: over.admin_plane ?? false,
        ...(over.allowed_cidrs !== undefined
          ? { allowed_cidrs: over.allowed_cidrs }
          : {}),
        ...(over.ip_policy_mode !== undefined
          ? { ip_policy_mode: over.ip_policy_mode }
          : {}),
      })
      .returning({
        uuid: schema.apiKeysTable.uuid,
        allowed_cidrs: schema.apiKeysTable.allowed_cidrs,
        ip_policy_mode: schema.apiKeysTable.ip_policy_mode,
        last_used_ip: schema.apiKeysTable.last_used_ip,
      });
    return row;
  }

  const stamped = async (uuid: string) => {
    // The stamp is fire-and-forget; give it a moment to land.
    for (let i = 0; i < 50; i += 1) {
      const [row] = await db
        .select({ last_used_ip: schema.apiKeysTable.last_used_ip })
        .from(schema.apiKeysTable)
        .where(eq(schema.apiKeysTable.uuid, uuid));
      if (row?.last_used_ip) return row.last_used_ip;
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
    return null;
  };

  it("an existing-shape row is inert: no list, mode off, no last_used_ip", async () => {
    const row = await insertKey({ raw: "sk_mt_inert_defaults_0001" });
    expect(row).toMatchObject({
      allowed_cidrs: null,
      ip_policy_mode: "off",
      last_used_ip: null,
    });
  });

  it("round-trips a text[] list", async () => {
    const row = await insertKey({
      raw: "sk_mt_roundtrip_list_0002",
      allowed_cidrs: ["203.0.113.0/24", "2001:db8::/32"],
      ip_policy_mode: "audit",
    });
    expect(row.allowed_cidrs).toEqual(["203.0.113.0/24", "2001:db8::/32"]);
  });

  it("the CHECK refuses an unknown mode", async () => {
    const err = await insertKey({
      raw: "sk_mt_bad_mode_00000003",
      ip_policy_mode: "enforced",
    }).then(
      () => null,
      (e: Error & { cause?: { message?: string; constraint?: string } }) => e,
    );
    expect(err).not.toBeNull();
    const chain = [err?.message, err?.cause?.message, err?.cause?.constraint]
      .filter(Boolean)
      .join(" | ");
    expect(chain).toContain("api_keys_ip_policy_mode_valid");
  });

  it("with no policy anywhere, every key validates from any address (the deploy state)", async () => {
    await insertKey({ raw: "sk_mt_deploy_state_0004" });

    const result = await repo.validateApiKey(
      "sk_mt_deploy_state_0004",
      check("198.51.100.9"),
    );
    expect(result.valid).toBe(true);
  });

  it("a key with no list follows the GLOBAL policy read live from config", async () => {
    await insertKey({ raw: "sk_mt_follows_global_05" });
    await configService.setApiKeyIpPolicy({
      mode: "enforce",
      cidrs: ["192.0.2.0/24"],
    });

    expect(
      (await repo.validateApiKey("sk_mt_follows_global_05", check("192.0.2.7")))
        .valid,
    ).toBe(true);
    expect(
      await repo.validateApiKey(
        "sk_mt_follows_global_05",
        check("198.51.100.9"),
      ),
    ).toMatchObject({ valid: false, ip_denied: true });

    // Switching the global mode back to audit applies to the very next call.
    await configService.setApiKeyIpPolicy({
      mode: "audit",
      cidrs: ["192.0.2.0/24"],
    });
    expect(
      (
        await repo.validateApiKey(
          "sk_mt_follows_global_05",
          check("198.51.100.9"),
        )
      ).valid,
    ).toBe(true);
  });

  it("a key's OWN list and mode win over the global policy", async () => {
    await insertKey({
      raw: "sk_mt_own_list_wins_06",
      allowed_cidrs: ["203.0.113.0/24"],
      ip_policy_mode: "enforce",
    });
    await configService.setApiKeyIpPolicy({
      mode: "enforce",
      cidrs: ["192.0.2.0/24"],
    });

    expect(
      (
        await repo.validateApiKey(
          "sk_mt_own_list_wins_06",
          check("203.0.113.4"),
        )
      ).valid,
    ).toBe(true);
    expect(
      await repo.validateApiKey("sk_mt_own_list_wins_06", check("192.0.2.7")),
    ).toMatchObject({ valid: false, ip_denied: true });
  });

  it("the any-IP exemption admits any address, and no address, under enforce", async () => {
    await insertKey({
      raw: "sk_mt_ci_exempt_000007",
      allowed_cidrs: ["0.0.0.0/0", "::/0"],
      ip_policy_mode: "enforce",
    });
    await configService.setApiKeyIpPolicy({
      mode: "enforce",
      cidrs: ["192.0.2.0/24"],
    });

    for (const ip of ["198.51.100.9", "2001:db8::77", undefined]) {
      expect(
        (await repo.validateApiKey("sk_mt_ci_exempt_000007", check(ip))).valid,
      ).toBe(true);
    }
  });

  it("without the opt-in (the validate oracle) an enforce list is not evaluated", async () => {
    await insertKey({
      raw: "sk_mt_oracle_optout_08",
      allowed_cidrs: ["203.0.113.0/24"],
      ip_policy_mode: "enforce",
    });

    expect((await repo.validateApiKey("sk_mt_oracle_optout_08")).valid).toBe(
      true,
    );
  });

  it("an accepted request stamps last_used_ip", async () => {
    const row = await insertKey({ raw: "sk_mt_stamp_the_ip_09" });

    await repo.validateApiKey("sk_mt_stamp_the_ip_09", check("2001:db8::9"));

    expect(await stamped(row.uuid)).toBe("2001:db8::9");
  });

  it("the control plane refuses an admin-plane key from outside its list", async () => {
    await insertKey({
      raw: "sk_mt_admin_plane_ip_10",
      admin_plane: true,
      allowed_cidrs: ["203.0.113.0/24"],
      ip_policy_mode: "enforce",
    });

    const refused = await repo.validateAdminPlaneApiKey(
      "sk_mt_admin_plane_ip_10",
      check("198.51.100.9", "admin_plane"),
    );
    const served = await repo.validateAdminPlaneApiKey(
      "sk_mt_admin_plane_ip_10",
      check("203.0.113.9", "admin_plane"),
    );

    expect(refused).toMatchObject({ valid: false, reason: "ip_not_allowed" });
    expect(served.valid).toBe(true);
  });

  it("setIpPolicy returns the before and after rows and persists the policy", async () => {
    const row = await insertKey({ raw: "sk_mt_set_policy_00011" });

    const result = await repo.setIpPolicy(row.uuid, {
      allowed_cidrs: ["203.0.113.0/24"],
      ip_policy_mode: "audit",
    });

    expect(result?.before).toEqual({
      allowed_cidrs: null,
      ip_policy_mode: "off",
    });
    expect(result?.after).toMatchObject({
      uuid: row.uuid,
      allowed_cidrs: ["203.0.113.0/24"],
      ip_policy_mode: "audit",
    });
    expect(
      await repo.setIpPolicy("00000000-0000-4000-8000-000000000000", {
        allowed_cidrs: null,
        ip_policy_mode: "off",
      }),
    ).toBeNull();
  });

  it("findAll carries the policy columns for the admin list", async () => {
    await insertKey({
      raw: "sk_mt_list_policy_0012",
      allowed_cidrs: ["203.0.113.0/24"],
      ip_policy_mode: "enforce",
    });
    const [listed] = await repo.findAll();
    expect(listed).toMatchObject({
      allowed_cidrs: ["203.0.113.0/24"],
      ip_policy_mode: "enforce",
      last_used_ip: null,
    });
  });
});
