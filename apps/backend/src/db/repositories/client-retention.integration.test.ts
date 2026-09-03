/**
 * REAL-POSTGRES integration test for the DCR client retention sweep,
 * `oauthRepository.pruneUnusedClients`.
 *
 * WHY THIS FILE EXISTS. The sweep is the only DELETE in this codebase that
 * runs unattended, on a timer, against rows a customer integration depends on.
 * Its entire correctness is in a four-predicate WHERE clause — a provenance
 * equality, a timestamp comparison, and two NOT EXISTS anti-joins — and the
 * suite that covered it (../../routers/oauth/client-retention.test.ts) replaces
 * the whole repository with `vi.fn()`. That suite pins the window resolution
 * and the never-throws contract, which is real value, but it cannot tell you
 * whether the statement deletes the right rows; a mock returns whatever the
 * test author imagined. Getting the direction of the `created_at` comparison
 * backwards, or dropping the provenance check, both leave it green.
 *
 * What is asserted here is one table of cases against one real statement:
 * which rows survive a sweep, and which do not.
 *
 * GATING: opt-in via TEST_DATABASE_URL, and deliberately NOT via DATABASE_URL,
 * for the reason spelled out at the top of ./access-queries.integration.test.ts
 * — this suite deletes rows, and pointing it at a database has to be an
 * explicit act rather than a side effect of having a connection string
 * exported. Same setup:
 *
 *   docker run -d --name metamcp-access-test -e POSTGRES_PASSWORD=test \
 *     -e POSTGRES_USER=test -e POSTGRES_DB=metamcp_test \
 *     -p 127.0.0.1:55432:5432 postgres:16-alpine
 *   cd apps/backend
 *   DATABASE_URL=postgres://test:test@127.0.0.1:55432/metamcp_test \
 *     npx drizzle-kit migrate
 *   TEST_DATABASE_URL=postgres://test:test@127.0.0.1:55432/metamcp_test \
 *     npx vitest run src/db/repositories/client-retention.integration.test.ts
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { INTEGRATION_DB_LOCK_KEY } from "./integration-db-lock";

const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL;

// `describe.skipIf` rather than a silent early return: a skipped suite is
// visible in the vitest output, so "the integration test didn't run" can never
// be mistaken for "the integration test passed".
const describeIfDb = describe.skipIf(!TEST_DATABASE_URL);

const DAY = 24 * 60 * 60 * 1000;
const NOW = new Date();
const past = (ms: number) => new Date(NOW.getTime() - ms);
const future = (ms: number) => new Date(NOW.getTime() + ms);

/** The window every case below is positioned against. */
const RETENTION_DAYS = 7;

const USER_ID = "retention-itest-user";

/**
 * One row per rule the WHERE clause enforces, named for what it proves.
 *
 * Every client here is OUT of the window and has NO children except where the
 * case name says otherwise, so each survivor survives for exactly one reason
 * and a broken predicate can only take down the case that tests it.
 */
const BARE_DCR_OLD = "mcp_client_retention_bare_old";
const DCR_WITH_TOKEN = "mcp_client_retention_with_token";
const DCR_WITH_CODE = "mcp_client_retention_with_code";
const DCR_RECENT = "mcp_client_retention_recent";
const ADMIN_OLD = "mcp_client_retention_admin_old";
const LEGACY_NULL_OLD = "mcp_client_retention_legacy_old";

const ALL_CLIENT_IDS = [
  BARE_DCR_OLD,
  DCR_WITH_TOKEN,
  DCR_WITH_CODE,
  DCR_RECENT,
  ADMIN_OLD,
  LEGACY_NULL_OLD,
];

type Db = Awaited<typeof import("../index")>["db"];
type Schema = typeof import("../schema");

let db: Db;
let schema: Schema;
let oauthRepository: (typeof import("./oauth.repo"))["oauthRepository"];
let inArray: (typeof import("drizzle-orm"))["inArray"];

beforeAll(async () => {
  if (!TEST_DATABASE_URL) return;

  // db/index reads DATABASE_URL at import time, so it has to be set BEFORE the
  // first dynamic import below — hence the lazy module graph.
  process.env.DATABASE_URL = TEST_DATABASE_URL;

  ({ db } = await import("../index"));
  schema = await import("../schema");
  ({ oauthRepository } = await import("./oauth.repo"));
  ({ inArray } = await import("drizzle-orm"));

  // See ./integration-db-lock: ./access-queries.integration.test.ts TRUNCATEs
  // the same tables from a parallel vitest worker.
  await db.execute(
    `SELECT pg_advisory_lock(${INTEGRATION_DB_LOCK_KEY})` as never,
  );

  await seed();
});

afterAll(async () => {
  if (!TEST_DATABASE_URL || !db) return;
  await cleanup();
  await db.execute(
    `SELECT pg_advisory_unlock(${INTEGRATION_DB_LOCK_KEY})` as never,
  );
  const { pool } = await import("../index");
  await pool.end();
});

async function cleanup() {
  // Scoped deletes rather than the TRUNCATE its sibling suite uses. The client
  // rows cascade to their own codes and tokens, and the user row is this
  // file's own — so nothing outside this fixture is touched, which keeps the
  // blast radius of a mistake here inside this file.
  await db
    .delete(schema.oauthClientsTable)
    .where(inArray(schema.oauthClientsTable.client_id, ALL_CLIENT_IDS));
  await db
    .delete(schema.usersTable)
    .where(inArray(schema.usersTable.id, [USER_ID]));
}

async function seed() {
  await cleanup();

  // Authorization codes and access tokens both carry a NOT NULL user_id FK.
  await db.insert(schema.usersTable).values({
    id: USER_ID,
    name: "Retention Integration User",
    email: "retention-itest@example.invalid",
    emailVerified: true,
    role: "member",
    createdAt: past(30 * DAY),
    updatedAt: past(30 * DAY),
  });

  await db.insert(schema.oauthClientsTable).values([
    {
      // The row the sweep exists for: anonymous DCR, never used, out of window.
      client_id: BARE_DCR_OLD,
      client_name: "Bare DCR, out of window",
      redirect_uris: ["https://claude.ai/api/mcp/auth_callback"],
      registration_source: "dcr",
      created_at: past(30 * DAY),
    },
    {
      // Paired: a live access token means a working connector.
      client_id: DCR_WITH_TOKEN,
      client_name: "DCR with an access token",
      redirect_uris: ["https://claude.ai/api/mcp/auth_callback"],
      registration_source: "dcr",
      created_at: past(30 * DAY),
    },
    {
      // Mid-flow: registered, authorized, has not exchanged the code yet.
      client_id: DCR_WITH_CODE,
      client_name: "DCR with an authorization code",
      redirect_uris: ["https://claude.ai/api/mcp/auth_callback"],
      registration_source: "dcr",
      created_at: past(30 * DAY),
    },
    {
      // Registered an hour ago. A connector that pairs tomorrow is normal.
      client_id: DCR_RECENT,
      client_name: "DCR inside the window",
      redirect_uris: ["https://claude.ai/api/mcp/auth_callback"],
      registration_source: "dcr",
      created_at: past(1 * 60 * 60 * 1000),
    },
    {
      // THE BLOCKER THIS FILE WAS WRITTEN FOR. Identical to BARE_DCR_OLD in
      // every respect the sweep could otherwise see — same client_id prefix,
      // no children, same age — and it must survive, because an admin
      // pre-provisioned it for a partner who has not paired yet.
      client_id: ADMIN_OLD,
      client_name: "Admin-minted, awaiting a partner",
      redirect_uris: ["https://claude.ai/api/mcp/auth_callback"],
      registration_source: "admin",
      created_at: past(30 * DAY),
    },
    {
      // Written before migration 0029. Provenance unknown, so possibly an
      // admin's: NULL must not be swept.
      client_id: LEGACY_NULL_OLD,
      client_name: "Pre-0029 row with no provenance",
      redirect_uris: ["https://claude.ai/api/mcp/auth_callback"],
      registration_source: null,
      created_at: past(30 * DAY),
    },
  ]);

  await db.insert(schema.oauthAccessTokensTable).values({
    access_token: "retention-itest-access",
    access_token_last4: "cess",
    client_id: DCR_WITH_TOKEN,
    user_id: USER_ID,
    scope: "mcp",
    // Deliberately EXPIRED, with a refresh token still live. This is the state
    // the sweep's safety argument rests on: a paired-but-dormant client keeps
    // its token row for the refresh TTL, and "has a row" is what the anti-join
    // tests — not "has a valid token".
    expires_at: past(2 * DAY),
    refresh_token: "retention-itest-refresh",
    refresh_token_expires_at: future(300 * DAY),
    created_at: past(30 * DAY),
  });

  await db.insert(schema.oauthAuthorizationCodesTable).values({
    code: "retention-itest-code",
    client_id: DCR_WITH_CODE,
    redirect_uri: "https://claude.ai/api/mcp/auth_callback",
    scope: "mcp",
    user_id: USER_ID,
    expires_at: past(29 * DAY),
    created_at: past(30 * DAY),
  });
}

async function survivingClientIds(): Promise<string[]> {
  const rows = await db
    .select({ client_id: schema.oauthClientsTable.client_id })
    .from(schema.oauthClientsTable)
    .where(inArray(schema.oauthClientsTable.client_id, ALL_CLIENT_IDS));
  return rows.map((row) => row.client_id).sort();
}

describeIfDb("pruneUnusedClients against real postgres", () => {
  // One sweep, then assertions about its result. Running it per-test would
  // make every case after the first operate on an already-swept table, which
  // is a different question than the one being asked.
  let removed: number;
  let survivors: string[];

  beforeAll(async () => {
    removed = await oauthRepository.pruneUnusedClients(RETENTION_DAYS);
    survivors = await survivingClientIds();
  });

  it("deletes the bare DCR client that is out of the window", () => {
    expect(survivors).not.toContain(BARE_DCR_OLD);
  });

  it("keeps an admin-minted client of the same age with no children", () => {
    // Flip the sweep's registration_source predicate off and this is the
    // assertion that fails. Nothing else about this row distinguishes it from
    // the deleted one — including its `mcp_client_` prefix, which both mint
    // paths produce.
    expect(survivors).toContain(ADMIN_OLD);
  });

  it("keeps a pre-0029 client whose provenance is NULL", () => {
    // `eq(registration_source, 'dcr')` excludes NULL; `ne(..., 'admin')` would
    // too, but only by accident of SQL three-valued logic. This pins the
    // outcome either way.
    expect(survivors).toContain(LEGACY_NULL_OLD);
  });

  it("keeps a DCR client that has an access token row", () => {
    expect(survivors).toContain(DCR_WITH_TOKEN);
  });

  it("keeps a DCR client that has an authorization code", () => {
    expect(survivors).toContain(DCR_WITH_CODE);
  });

  it("keeps a DCR client created inside the window", () => {
    // Reverse the created_at comparison and this fails while the deletion case
    // above still passes, which is the pair that pins the direction.
    expect(survivors).toContain(DCR_RECENT);
  });

  it("removes exactly one row and reports that count", () => {
    // The count is what the operator-facing log line prints, and a sweep that
    // deleted the right row plus something else would satisfy every assertion
    // above. Scoped to this fixture's ids, so an unrelated row left in a
    // developer's database cannot make it flap.
    expect(survivors).toEqual(
      [
        ADMIN_OLD,
        DCR_RECENT,
        DCR_WITH_CODE,
        DCR_WITH_TOKEN,
        LEGACY_NULL_OLD,
      ].sort(),
    );
    expect(removed).toBe(1);
  });

  it("is a no-op on a second run", () => {
    // Idempotence matters because this runs every five minutes forever.
    return expect(
      oauthRepository.pruneUnusedClients(RETENTION_DAYS),
    ).resolves.toBe(0);
  });

  it("deletes nothing when the window is disabled", async () => {
    // `<= 0` is the documented off switch. It must not be read as "cutoff is
    // now", which would delete every never-used client in the table.
    await expect(oauthRepository.pruneUnusedClients(0)).resolves.toBe(0);
    await expect(oauthRepository.pruneUnusedClients(-1)).resolves.toBe(0);
    expect(await survivingClientIds()).toHaveLength(5);
  });
});
