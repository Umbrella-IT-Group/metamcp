/**
 * Client metadata document rows (migration 0046) against a REAL Postgres:
 * the migration itself, the upsert that writes them, and the sweep that
 * reaps them.
 *
 * Migration. The file is executed inside a scratch schema whose
 * `oauth_clients` is cloned from the migrated public table and put back to
 * its pre-0046 shape (a CHECK that names only 'dcr' and 'admin'). Pinned: the
 * pre-change shape refuses a 'cimd' row, the migration admits it and still
 * refuses a value that is not in the set, and a second run changes nothing
 * (the constraint is the same object, not dropped and re-created).
 *
 * Upsert. A refresh rewrites the fields the document publishes and never an
 * approval decision, and a row of another source that owns the id is left
 * exactly as it was.
 *
 * Sweep. Only a `cimd` row, not refreshed for the window, with no token, code
 * or rotated marker, is deleted; the rows of every other source and every row
 * somebody is connected through stay, and the DCR sweep never matches a
 * `cimd` row.
 *
 * Opt-in via TEST_DATABASE_URL, pointed at a disposable, migrated database.
 */
import { readFileSync } from "node:fs";
import path from "node:path";

import { Client } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { INTEGRATION_DB_LOCK_KEY } from "./integration-db-lock";

const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL;
const describeIfDb = describe.skipIf(!TEST_DATABASE_URL);

const MIGRATION = readFileSync(
  path.join(
    __dirname,
    "..",
    "..",
    "..",
    "drizzle",
    "0046_oauth_client_metadata_documents.sql",
  ),
  "utf8",
);

const HOUR = 3_600_000;
const DAY = 24 * HOUR;
const NOW = new Date();
const past = (ms: number) => new Date(NOW.getTime() - ms);

describeIfDb("migration 0046 on the pre-change CHECK", () => {
  const SCHEMA = `mig0046_${Date.now().toString(36)}`;
  let client: Client;

  const insertWithSource = (id: string, source: string | null) =>
    client.query(
      `INSERT INTO oauth_clients (client_id, client_name, redirect_uris, registration_source, approval_status)
       VALUES ($1, 'n', '{https://claude.ai/cb}', $2, 'approved')`,
      [id, source],
    );

  const constraint = async () => {
    const res = await client.query(
      `SELECT oid::text AS oid, pg_get_constraintdef(oid) AS def
         FROM pg_constraint
        WHERE conname = 'oauth_clients_registration_source_valid'
          AND conrelid = '"oauth_clients"'::regclass`,
    );
    return res.rows as Array<{ oid: string; def: string }>;
  };

  beforeAll(async () => {
    client = new Client({ connectionString: TEST_DATABASE_URL });
    await client.connect();
    await client.query(`SELECT pg_advisory_lock(${INTEGRATION_DB_LOCK_KEY})`);
    await client.query(`CREATE SCHEMA ${SCHEMA}`);
    await client.query(`SET search_path TO ${SCHEMA}`);
    await client.query(
      `CREATE TABLE oauth_clients (LIKE public.oauth_clients INCLUDING ALL)`,
    );
    // Back to the pre-0046 shape: the same CHECK name, without 'cimd'.
    await client.query(
      `ALTER TABLE oauth_clients DROP CONSTRAINT oauth_clients_registration_source_valid`,
    );
    await client.query(
      `ALTER TABLE oauth_clients ADD CONSTRAINT oauth_clients_registration_source_valid
         CHECK (registration_source IS NULL OR registration_source IN ('dcr', 'admin'))`,
    );
  });

  afterAll(async () => {
    if (!client) return;
    await client.query(`DROP SCHEMA IF EXISTS ${SCHEMA} CASCADE`);
    await client.query(`SELECT pg_advisory_unlock(${INTEGRATION_DB_LOCK_KEY})`);
    await client.end();
  });

  it("is refused a cimd row before the migration", async () => {
    await expect(insertWithSource("c_before", "cimd")).rejects.toThrow(
      /oauth_clients_registration_source_valid/,
    );
  });

  it("admits cimd after the migration, and still refuses a value outside the set", async () => {
    await client.query(MIGRATION);

    await insertWithSource("c_cimd", "cimd");
    await insertWithSource("c_dcr", "dcr");
    await insertWithSource("c_admin", "admin");
    await insertWithSource("c_null", null);
    await expect(insertWithSource("c_other", "xyz")).rejects.toThrow(
      /oauth_clients_registration_source_valid/,
    );
    await expect(insertWithSource("c_case", "CIMD")).rejects.toThrow(
      /oauth_clients_registration_source_valid/,
    );
    const stored = await client.query(
      `SELECT client_id FROM oauth_clients ORDER BY client_id`,
    );
    expect(stored.rows.map((r: { client_id: string }) => r.client_id)).toEqual([
      "c_admin",
      "c_cimd",
      "c_dcr",
      "c_null",
    ]);
  });

  it("leaves the constraint untouched when it runs again", async () => {
    const before = await constraint();
    expect(before).toHaveLength(1);
    expect(before[0].def).toContain("'cimd'");

    await client.query(MIGRATION);

    expect(await constraint()).toEqual(before);
    // Rows written under the widened CHECK survive a re-run.
    const kept = await client.query(
      `SELECT count(*)::int AS n FROM oauth_clients WHERE registration_source = 'cimd'`,
    );
    expect(kept.rows[0].n).toBe(1);
  });
});

type Db = Awaited<typeof import("../index")>["db"];
type Pool = Awaited<typeof import("../index")>["pool"];
type Schema = typeof import("../schema");

describeIfDb("client metadata document rows against real postgres", () => {
  const PREFIX = "https://itest-cimd.example.com/";
  const id = (name: string) => `${PREFIX}${name}.json`;
  const ids = {
    fresh: id("fresh"),
    staleUnused: id("stale-unused"),
    staleToken: id("stale-token"),
    staleCode: id("stale-code"),
    staleMarker: id("stale-marker"),
    refresh: id("refresh"),
    rejected: id("rejected"),
    race: id("race"),
    dcrOld: `mcp_client_itest_cimd_dcr`,
    adminOld: `mcp_client_itest_cimd_admin`,
    legacyOld: `mcp_client_itest_cimd_legacy`,
    dcrUrlShaped: id("dcr-url-shaped"),
    adminUrlShaped: id("admin-url-shaped"),
    pendingCimd: id("pending-cimd"),
    inside: id("inside"),
    outside: id("outside"),
    counted: id("counted"),
  };
  const USER_ID = "itest-cimd-user";
  const CALLBACK = "https://claude.ai/api/mcp/auth_callback";

  let db: Db;
  let pool: Pool;
  let schema: Schema;
  let drizzle: typeof import("drizzle-orm");
  let oauthRepository: (typeof import("./oauth.repo"))["oauthRepository"];

  const draft = (
    clientId: string,
    overrides: Record<string, unknown> = {},
  ) => ({
    client_id: clientId,
    client_secret: null,
    client_name: "Itest client",
    redirect_uris: [CALLBACK],
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
    token_endpoint_auth_method: "none",
    scope: "mcp",
    client_uri: null,
    logo_uri: null,
    contacts: null,
    tos_uri: null,
    policy_uri: null,
    software_id: null,
    software_version: null,
    created_at: NOW,
    ...overrides,
  });

  const rowOf = async (clientId: string) => {
    const [row] = await db
      .select()
      .from(schema.oauthClientsTable)
      .where(drizzle.eq(schema.oauthClientsTable.client_id, clientId));
    return row ?? null;
  };

  const allIds = () => Object.values(ids);

  async function cleanup() {
    await db
      .delete(schema.oauthClientsTable)
      .where(drizzle.inArray(schema.oauthClientsTable.client_id, allIds()));
    await db
      .delete(schema.usersTable)
      .where(drizzle.eq(schema.usersTable.id, USER_ID));
  }

  beforeAll(async () => {
    process.env.DATABASE_URL = TEST_DATABASE_URL;
    ({ db, pool } = await import("../index"));
    schema = await import("../schema");
    drizzle = await import("drizzle-orm");
    ({ oauthRepository } = await import("./oauth.repo"));
    await db.execute(
      `SELECT pg_advisory_lock(${INTEGRATION_DB_LOCK_KEY})` as never,
    );
    await cleanup();
    await db.insert(schema.usersTable).values({
      id: USER_ID,
      name: "Cimd Integration User",
      email: "cimd-itest@example.invalid",
      emailVerified: true,
      role: "member",
      createdAt: past(30 * DAY),
      updatedAt: past(30 * DAY),
    });
  });

  afterAll(async () => {
    if (!db) return;
    await cleanup();
    await db.execute(
      `SELECT pg_advisory_unlock(${INTEGRATION_DB_LOCK_KEY})` as never,
    );
    await pool.end();
  });

  describe("upsertCimdClient", () => {
    it("creates an approved row with no approving person and no secret", async () => {
      const at = new Date();
      const row = await oauthRepository.upsertCimdClient(draft(ids.fresh), at);

      expect(row).toMatchObject({
        client_id: ids.fresh,
        registration_source: "cimd",
        approval_status: "approved",
        approved_by: null,
        rejected_at: null,
        client_secret: null,
        client_secret_salt: null,
        token_endpoint_auth_method: "none",
        scope: "mcp",
        redirect_uris: [CALLBACK],
      });
      expect(row?.approved_at?.getTime()).toBe(at.getTime());
      expect(row?.updated_at?.getTime()).toBe(at.getTime());
    });

    it("refreshes the document's fields and the freshness clock on a second write", async () => {
      await oauthRepository.upsertCimdClient(
        draft(ids.refresh),
        past(2 * HOUR),
      );
      const at = new Date();

      const row = await oauthRepository.upsertCimdClient(
        draft(ids.refresh, {
          client_name: "Renamed",
          redirect_uris: [CALLBACK, "https://claude.com/api/mcp/auth_callback"],
          logo_uri: "https://itest-cimd.example.com/logo.png",
        }),
        at,
      );

      expect(row).toMatchObject({
        client_name: "Renamed",
        redirect_uris: [CALLBACK, "https://claude.com/api/mcp/auth_callback"],
        logo_uri: "https://itest-cimd.example.com/logo.png",
      });
      expect(row?.updated_at?.getTime()).toBe(at.getTime());
      expect((await rowOf(ids.refresh))?.created_at.getTime()).toBeLessThan(
        at.getTime() - HOUR,
      );
    });

    it("never changes an approval decision: a row rejected by hand stays rejected", async () => {
      await oauthRepository.upsertCimdClient(
        draft(ids.rejected),
        past(2 * HOUR),
      );
      const rejectedAt = new Date();
      await db
        .update(schema.oauthClientsTable)
        .set({
          approval_status: "rejected",
          rejected_at: rejectedAt,
          approved_at: null,
        })
        .where(drizzle.eq(schema.oauthClientsTable.client_id, ids.rejected));

      const row = await oauthRepository.upsertCimdClient(
        draft(ids.rejected, { client_name: "Refreshed after rejection" }),
        new Date(),
      );

      expect(row).toMatchObject({
        approval_status: "rejected",
        client_name: "Refreshed after rejection",
      });
      expect(row?.rejected_at?.getTime()).toBe(rejectedAt.getTime());
      expect(row?.approved_at).toBeNull();
    });

    it.each([
      ["dcr", "dcrUrlShaped"],
      ["admin", "adminUrlShaped"],
    ] as const)(
      "leaves a %s row that owns the id exactly as it was, and reports that nothing was written",
      async (source, key) => {
        await db.insert(schema.oauthClientsTable).values({
          client_id: ids[key],
          client_name: "Hand made",
          redirect_uris: ["https://claude.ai/original"],
          registration_source: source,
          approval_status: "approved",
          token_endpoint_auth_method: "client_secret_post",
          client_secret: "stored-hash",
          client_secret_salt: "stored-salt",
        });
        const before = await rowOf(ids[key]);

        const result = await oauthRepository.upsertCimdClient(
          draft(ids[key], { client_name: "Takeover" }),
          new Date(),
        );

        expect(result).toBeNull();
        expect(await rowOf(ids[key])).toEqual(before);
      },
    );

    it("survives two concurrent writes of the same id", async () => {
      const results = await Promise.all([
        oauthRepository.upsertCimdClient(draft(ids.race), new Date()),
        oauthRepository.upsertCimdClient(draft(ids.race), new Date()),
      ]);

      expect(results.map((r) => r?.client_id)).toEqual([ids.race, ids.race]);
      expect(
        (
          await db
            .select()
            .from(schema.oauthClientsTable)
            .where(drizzle.eq(schema.oauthClientsTable.client_id, ids.race))
        ).length,
      ).toBe(1);
    });
  });

  describe("countCimdClients", () => {
    it("counts only rows of source cimd", async () => {
      const before = await oauthRepository.countCimdClients();
      await db.insert(schema.oauthClientsTable).values({
        client_id: ids.dcrOld,
        client_name: "dcr",
        redirect_uris: ["http://localhost:1/cb"],
        registration_source: "dcr",
        approval_status: "approved",
      });

      expect(await oauthRepository.countCimdClients()).toBe(before);

      await oauthRepository.upsertCimdClient(draft(ids.counted), new Date());
      expect(await oauthRepository.countCimdClients()).toBe(before + 1);
    });
  });

  describe("pruneUnusedCimdClients", () => {
    const WINDOW_DAYS = 30;
    let removed: number;

    async function survivors() {
      const rows = await db
        .select({ client_id: schema.oauthClientsTable.client_id })
        .from(schema.oauthClientsTable)
        .where(drizzle.inArray(schema.oauthClientsTable.client_id, allIds()));
      return rows.map((r) => r.client_id).sort();
    }

    beforeAll(async () => {
      // Wipe the rows the upsert tests left, so the sweep's cases are the
      // only cimd rows this file owns.
      await cleanup();
      await db.insert(schema.usersTable).values({
        id: USER_ID,
        name: "Cimd Integration User",
        email: "cimd-itest@example.invalid",
        emailVerified: true,
        role: "member",
        createdAt: past(30 * DAY),
        updatedAt: past(30 * DAY),
      });

      const stale = past(40 * DAY);
      await oauthRepository.upsertCimdClient(draft(ids.fresh), past(2 * DAY));
      await oauthRepository.upsertCimdClient(draft(ids.staleUnused), stale);
      await oauthRepository.upsertCimdClient(draft(ids.staleToken), stale);
      await oauthRepository.upsertCimdClient(draft(ids.staleCode), stale);
      await oauthRepository.upsertCimdClient(draft(ids.staleMarker), stale);
      // Just inside and just outside the window.
      await oauthRepository.upsertCimdClient(
        draft(ids.inside),
        past(WINDOW_DAYS * DAY - HOUR),
      );
      await oauthRepository.upsertCimdClient(
        draft(ids.outside),
        past(WINDOW_DAYS * DAY + HOUR),
      );
      // A cimd row someone set to pending by hand, created long ago but
      // refreshed yesterday: the DCR sweep counts a pending row's age from
      // created_at and would delete it if it matched cimd rows at all, and the
      // cimd sweep keeps it because it is fresh.
      await oauthRepository.upsertCimdClient(draft(ids.pendingCimd), past(DAY));
      await db
        .update(schema.oauthClientsTable)
        .set({
          approval_status: "pending",
          approved_at: null,
          created_at: stale,
        })
        .where(drizzle.eq(schema.oauthClientsTable.client_id, ids.pendingCimd));

      // Other sources, old.
      for (const [client_id, source] of [
        [ids.dcrOld, "dcr"],
        [ids.adminOld, "admin"],
        [ids.legacyOld, null],
      ] as const) {
        await db.insert(schema.oauthClientsTable).values({
          client_id,
          client_name: client_id,
          redirect_uris: [CALLBACK],
          registration_source: source,
          approval_status: "approved",
          created_at: stale,
          updated_at: stale,
        });
      }

      await db.insert(schema.oauthAccessTokensTable).values({
        access_token: "itest-cimd-access",
        access_token_last4: "cess",
        client_id: ids.staleToken,
        user_id: USER_ID,
        scope: "mcp",
        expires_at: past(2 * DAY),
        refresh_token: "itest-cimd-refresh",
        refresh_token_expires_at: new Date(NOW.getTime() + 300 * DAY),
        family_id: "bbbbbbbb-0000-4000-8000-0000000000c1",
        created_at: stale,
      });
      await db.insert(schema.oauthAuthorizationCodesTable).values({
        code: "itest-cimd-code",
        client_id: ids.staleCode,
        redirect_uri: CALLBACK,
        scope: "mcp",
        user_id: USER_ID,
        code_challenge: "chal",
        code_challenge_method: "S256",
        expires_at: new Date(NOW.getTime() + 5 * 60_000),
      });
      await db.insert(schema.oauthRotatedRefreshTokensTable).values({
        refresh_token_hash: "itest-cimd-rotated",
        family_id: "bbbbbbbb-0000-4000-8000-0000000000c2",
        client_id: ids.staleMarker,
        user_id: USER_ID,
        expires_at: new Date(NOW.getTime() + 100 * DAY),
      });

      // The DCR sweep first: it must leave every cimd row alone.
      await oauthRepository.pruneUnapprovedDcrClients(7, DAY);
      removed = await oauthRepository.pruneUnusedCimdClients(WINDOW_DAYS);
    });

    it("deletes a stale cimd row with nothing hanging off it, and one just outside the window", async () => {
      const left = await survivors();
      expect(left).not.toContain(ids.staleUnused);
      expect(left).not.toContain(ids.outside);
      expect(removed).toBeGreaterThanOrEqual(2);
    });

    it("keeps a fresh row and one just inside the window", async () => {
      const left = await survivors();
      expect(left).toContain(ids.fresh);
      expect(left).toContain(ids.inside);
    });

    it.each([
      ["an access token", "staleToken"],
      ["an authorization code", "staleCode"],
      ["a rotated refresh-token marker", "staleMarker"],
    ] as const)(
      "keeps a stale row somebody is connected through (%s)",
      async (_what, key) => {
        expect(await survivors()).toContain(ids[key]);
      },
    );

    it("never touches a row of another source, however old", async () => {
      const left = await survivors();
      for (const key of ["dcrOld", "adminOld", "legacyOld"] as const) {
        expect(left).toContain(ids[key]);
      }
    });

    it("is not matched by the DCR sweep, even as a pending row", async () => {
      expect(await survivors()).toContain(ids.pendingCimd);
    });

    it("deletes nothing for a window of zero or less", async () => {
      const before = await survivors();
      expect(await oauthRepository.pruneUnusedCimdClients(0)).toBe(0);
      expect(await oauthRepository.pruneUnusedCimdClients(-5)).toBe(0);
      expect(await survivors()).toEqual(before);
    });
  });
});
