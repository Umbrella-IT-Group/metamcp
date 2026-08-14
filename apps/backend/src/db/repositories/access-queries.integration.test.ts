/**
 * REAL-POSTGRES integration test for the two Access-dashboard queries.
 *
 * Why this file exists: the first cut of this surface shipped past three
 * review layers with a bug that only a real driver could reveal. Every raw
 * `sql` fragment interpolated into a drizzle projection loses the decoder
 * drizzle would otherwise attach from the column type, so node-postgres hands
 * back its WIRE representation — bigint `count(*)` as a string, `timestamptz`
 * as a string — and the router's `.output()` schema then rejects the whole
 * response with `invalid_type: expected date, received string`. Nothing in
 * the type system catches it (the TS type already claims `Date`/`number`),
 * and no mock can catch it either, because a mock returns whatever the test
 * author imagined the driver returns.
 *
 * So this test runs the ACTUAL statements against an ACTUAL postgres and
 * parses the serialized rows through the ACTUAL zod contracts. If it passes,
 * `frontend.users.list` and `frontend.oauthTokens.list` work end to end.
 *
 * GATING: opt-in via TEST_DATABASE_URL, and deliberately NOT via DATABASE_URL.
 * This suite TRUNCATES the tables it touches. Reusing DATABASE_URL would mean
 * that anyone who happened to have their production connection string
 * exported — the normal state for someone running the backend locally — would
 * wipe real accounts by typing `vitest`. A separate variable makes pointing
 * this at a database an explicit act.
 *
 *   docker run -d --name metamcp-access-test -e POSTGRES_PASSWORD=test \
 *     -e POSTGRES_USER=test -e POSTGRES_DB=metamcp_test \
 *     -p 127.0.0.1:55432:5432 postgres:16-alpine
 *   cd apps/backend
 *   DATABASE_URL=postgres://test:test@127.0.0.1:55432/metamcp_test \
 *     npx drizzle-kit migrate
 *   TEST_DATABASE_URL=postgres://test:test@127.0.0.1:55432/metamcp_test \
 *     npx vitest run src/db/repositories/access-queries.integration.test.ts
 */

import {
  ActiveOAuthTokenItemSchema,
  UserListItemSchema,
} from "@repo/zod-types";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL;

// `describe.skipIf` rather than a silent early return: a skipped suite is
// visible in the vitest output, so "the integration test didn't run" can never
// be mistaken for "the integration test passed".
const describeIfDb = describe.skipIf(!TEST_DATABASE_URL);

const NOW = new Date();
const HOUR = 60 * 60 * 1000;
const past = (ms: number) => new Date(NOW.getTime() - ms);
const future = (ms: number) => new Date(NOW.getTime() + ms);

const ADMIN_ID = "itest-admin";
const MEMBER_ID = "itest-member";
const QUIET_ID = "itest-quiet";
const CLIENT_ID = "itest_client";

type Db = Awaited<typeof import("../index")>["db"];
type Schema = typeof import("../schema");

let db: Db;
let schema: Schema;
let buildUserListQuery: (typeof import("./users.repo"))["buildUserListQuery"];
let usersRepository: (typeof import("./users.repo"))["usersRepository"];
let oauthRepository: (typeof import("./oauth.repo"))["oauthRepository"];
let UsersSerializer: (typeof import("../serializers/users.serializer"))["UsersSerializer"];
let OAuthTokensSerializer: (typeof import("../serializers/oauth-tokens.serializer"))["OAuthTokensSerializer"];

beforeAll(async () => {
  if (!TEST_DATABASE_URL) return;

  // db/index reads DATABASE_URL at import time, so it has to be set BEFORE the
  // first dynamic import below — hence the whole module graph is imported
  // lazily rather than at the top of the file.
  process.env.DATABASE_URL = TEST_DATABASE_URL;

  ({ db } = await import("../index"));
  schema = await import("../schema");
  ({ buildUserListQuery, usersRepository } = await import("./users.repo"));
  ({ oauthRepository } = await import("./oauth.repo"));
  ({ UsersSerializer } = await import("../serializers/users.serializer"));
  ({ OAuthTokensSerializer } = await import(
    "../serializers/oauth-tokens.serializer"
  ));

  await seed();
});

afterAll(async () => {
  if (!TEST_DATABASE_URL || !db) return;
  await truncate();
  const { pool } = await import("../index");
  await pool.end();
});

async function truncate() {
  // TRUNCATE ... CASCADE in one statement: the FK graph between these tables
  // makes any per-table delete order fragile.
  await db.execute(
    `TRUNCATE TABLE users, oauth_clients, api_keys, endpoints, namespaces RESTART IDENTITY CASCADE` as never,
  );
}

async function seed() {
  await truncate();

  await db.insert(schema.usersTable).values([
    {
      id: ADMIN_ID,
      name: "Integration Admin",
      email: "itest-admin@example.invalid",
      emailVerified: true,
      role: "admin",
      createdAt: past(72 * HOUR),
      updatedAt: past(72 * HOUR),
    },
    {
      id: MEMBER_ID,
      name: "Integration Member",
      email: "itest-member@example.invalid",
      emailVerified: false,
      role: "member",
      createdAt: past(48 * HOUR),
      updatedAt: past(48 * HOUR),
    },
    {
      // Never held a session, token or key — exercises the NULL/zero branch of
      // every correlated subquery in one row.
      id: QUIET_ID,
      name: "Integration Quiet",
      email: "itest-quiet@example.invalid",
      emailVerified: false,
      role: "member",
      createdAt: past(24 * HOUR),
      updatedAt: past(24 * HOUR),
    },
  ]);

  await db.insert(schema.sessionsTable).values([
    {
      id: "itest-session-live",
      token: "itest-session-token-live",
      userId: MEMBER_ID,
      expiresAt: future(24 * HOUR),
      createdAt: past(2 * HOUR),
      updatedAt: past(HOUR),
    },
    {
      // Expired: must NOT be counted as live access, but SHOULD still be the
      // most recent refresh if it is the newest row.
      id: "itest-session-expired",
      token: "itest-session-token-expired",
      userId: MEMBER_ID,
      expiresAt: past(HOUR),
      createdAt: past(96 * HOUR),
      updatedAt: past(90 * HOUR),
    },
  ]);

  await db.insert(schema.oauthClientsTable).values({
    client_id: CLIENT_ID,
    client_secret: null,
    client_name: "Integration Client",
    redirect_uris: ["https://claude.ai/api/mcp/auth_callback"],
  });

  await db.insert(schema.oauthAccessTokensTable).values([
    {
      access_token: "itest-access-live",
      client_id: CLIENT_ID,
      user_id: MEMBER_ID,
      scope: "mcp",
      expires_at: future(12 * HOUR),
      refresh_token: "itest-refresh-live",
      refresh_token_expires_at: future(30 * 24 * HOUR),
      created_at: past(HOUR),
    },
    {
      access_token: "itest-access-norefresh",
      client_id: CLIENT_ID,
      user_id: MEMBER_ID,
      scope: "mcp",
      expires_at: future(6 * HOUR),
      refresh_token: null,
      refresh_token_expires_at: null,
      created_at: past(2 * HOUR),
    },
    {
      // Expired: excluded from the listing and from the live count.
      access_token: "itest-access-expired",
      client_id: CLIENT_ID,
      user_id: MEMBER_ID,
      scope: "mcp",
      expires_at: past(HOUR),
      refresh_token: null,
      created_at: past(48 * HOUR),
    },
  ]);

  const [namespace] = await db
    .insert(schema.namespacesTable)
    .values({ name: "itest-namespace", user_id: ADMIN_ID })
    .returning({ uuid: schema.namespacesTable.uuid });

  // Asserted rather than `!`-ed: if the seed silently failed to insert, every
  // assertion downstream would fail with a confusing message about counts
  // instead of naming the real problem here.
  if (!namespace) throw new Error("seed failed: namespace was not inserted");

  // An endpoint owned by the ADMIN but living in the admin's namespace, plus
  // one owned by the MEMBER — the cross-user cascade fixture.
  await db.insert(schema.endpointsTable).values([
    {
      name: "itest-endpoint-admin",
      namespace_uuid: namespace.uuid,
      user_id: ADMIN_ID,
    },
    {
      name: "itest-endpoint-member",
      namespace_uuid: namespace.uuid,
      user_id: MEMBER_ID,
    },
  ]);

  const [scopedEndpoint] = await db
    .select({ uuid: schema.endpointsTable.uuid })
    .from(schema.endpointsTable)
    .where(
      // drizzle's eq is imported lazily below to keep the top of this file
      // free of ORM imports that would resolve before DATABASE_URL is set.
      (await import("drizzle-orm")).eq(
        schema.endpointsTable.name,
        "itest-endpoint-admin",
      ),
    );

  if (!scopedEndpoint) {
    throw new Error("seed failed: scoped endpoint was not inserted");
  }

  await db.insert(schema.apiKeysTable).values([
    {
      name: "itest-key-member-active",
      key: "sk_mt_itest_member_active",
      user_id: MEMBER_ID,
      is_active: true,
    },
    {
      name: "itest-key-member-inactive",
      key: "sk_mt_itest_member_inactive",
      user_id: MEMBER_ID,
      is_active: false,
    },
    {
      // Owned by the ADMIN but ACTING AS the member (migration 0024). This is
      // the key the first cut of revokeAccess left live, and that
      // active_api_key_count did not count.
      name: "itest-key-actsas-member",
      key: "sk_mt_itest_actsas",
      user_id: ADMIN_ID,
      acts_as_user_id: MEMBER_ID,
      endpoint_uuid: scopedEndpoint.uuid,
      is_active: true,
    },
  ]);

  await db.insert(schema.m365UserTokensTable).values({
    user_id: MEMBER_ID,
    entra_oid: "itest-oid",
    tenant_id: "itest-tenant",
    rt_ciphertext: "itest-ciphertext",
    kek_id: "itest-kek",
    scopes_granted: "User.Read",
    status: "active",
  });
}

describeIfDb("buildUserListQuery against real postgres", () => {
  it("returns rows that satisfy UserListItemSchema after serialization", async () => {
    const rows = await buildUserListQuery(NOW);
    const serialized = UsersSerializer.serializeUserList(rows);

    expect(serialized.length).toBeGreaterThanOrEqual(3);

    // The whole point of this file: parse through the REAL contract, which is
    // what tRPC's `.output()` does on every call. A driver-decode regression
    // fails right here instead of in production.
    for (const user of serialized) {
      expect(() => UserListItemSchema.parse(user)).not.toThrow();
    }
  });

  it("decodes last_session_refresh_at as a Date, not the driver's string", async () => {
    const rows = await buildUserListQuery(NOW);
    const member = rows.find((row) => row.id === MEMBER_ID);

    expect(member).toBeDefined();
    // timestamptz arrives as a string unless the fragment carries a decoder.
    expect(member?.last_session_refresh_at).toBeInstanceOf(Date);
    // Newest session refresh wins, expired or not — this is "when did this
    // account last touch the gateway", not "is it live now".
    expect(member?.last_session_refresh_at?.getTime()).toBe(
      past(HOUR).getTime(),
    );
  });

  it("decodes every count as a number and scopes each to live access only", async () => {
    const rows = await buildUserListQuery(NOW);
    const member = rows.find((row) => row.id === MEMBER_ID);
    const quiet = rows.find((row) => row.id === QUIET_ID);

    for (const value of [
      member?.active_session_count,
      member?.active_oauth_token_count,
      member?.active_api_key_count,
    ]) {
      expect(typeof value).toBe("number");
    }

    // 2 sessions seeded, 1 unexpired.
    expect(member?.active_session_count).toBe(1);
    // 3 tokens seeded, 2 unexpired.
    expect(member?.active_oauth_token_count).toBe(2);
    // 1 active own key + 1 inactive own key + 1 active acts-as key = 2 live
    // paths. The acts-as key is a real way to act as this identity, so it
    // counts; omitting it under-reported the blast radius.
    expect(member?.active_api_key_count).toBe(2);

    // An account with no history reads zero/null rather than dropping out of
    // the listing or reporting NaN.
    expect(quiet?.active_session_count).toBe(0);
    expect(quiet?.active_oauth_token_count).toBe(0);
    expect(quiet?.active_api_key_count).toBe(0);
    expect(quiet?.last_session_refresh_at).toBeNull();
  });

  it("orders newest account first", async () => {
    const rows = await buildUserListQuery(NOW);
    const ids = rows.map((row) => row.id);

    expect(ids.indexOf(QUIET_ID)).toBeLessThan(ids.indexOf(MEMBER_ID));
    expect(ids.indexOf(MEMBER_ID)).toBeLessThan(ids.indexOf(ADMIN_ID));
  });
});

describeIfDb("listActiveAccessTokens against real postgres", () => {
  it("returns rows that satisfy ActiveOAuthTokenItemSchema after serialization", async () => {
    const rows = await oauthRepository.listActiveAccessTokens(NOW);
    const serialized = OAuthTokensSerializer.serializeActiveTokenList(rows);

    // 3 tokens seeded, 1 expired.
    expect(serialized).toHaveLength(2);

    for (const token of serialized) {
      expect(() => ActiveOAuthTokenItemSchema.parse(token)).not.toThrow();
    }
  });

  it("decodes has_refresh_token as a real boolean and never exposes a token value", async () => {
    const rows = await oauthRepository.listActiveAccessTokens(NOW);
    const serialized = OAuthTokensSerializer.serializeActiveTokenList(rows);

    for (const token of serialized) {
      expect(typeof token.has_refresh_token).toBe("boolean");
      expect(token.created_at).toBeInstanceOf(Date);
      expect(token.expires_at).toBeInstanceOf(Date);
    }

    expect(serialized.map((t) => t.has_refresh_token).sort()).toEqual([
      false,
      true,
    ]);

    const payload = JSON.stringify(serialized);
    expect(payload).not.toContain("itest-access-live");
    expect(payload).not.toContain("itest-refresh-live");
  });

  it("joins the owning user and registered client", async () => {
    const rows = await oauthRepository.listActiveAccessTokens(NOW);

    for (const row of rows) {
      expect(row.user_email).toBe("itest-member@example.invalid");
      expect(row.client_name).toBe("Integration Client");
    }
  });
});

describeIfDb("frontend.users.list end to end against real postgres", () => {
  // The bug that sent this feature back to be rebuilt lived in the seam
  // BETWEEN the query and the wire contract: the repository returned rows, the
  // serializer passed them through, and tRPC's `.output()` then rejected the
  // whole response. Testing the query alone would have missed it, and so
  // would testing the router with a mocked impl. This drives the REAL router
  // over the REAL implementation over the REAL database — the same path a
  // browser takes — so `.output()` validation is genuinely exercised.
  beforeAll(async () => {
    await seed();
  });

  it("returns real rows through the real adminProcedure, output schema and all", async () => {
    const { createUsersRouter } = await import("@repo/trpc");
    const { usersImplementations } = await import("../../trpc/users.impl");

    const router = createUsersRouter(usersImplementations);
    const result = await router
      .createCaller({
        user: { id: ADMIN_ID, role: "admin" },
        session: { id: "itest-session-live" },
      })
      .list();

    expect(result.total).toBe(3);
    expect(result.users).toHaveLength(3);

    const member = result.users.find((row) => row.id === MEMBER_ID);
    expect(member?.email).toBe("itest-member@example.invalid");
    expect(member?.active_session_count).toBe(1);
    expect(member?.active_oauth_token_count).toBe(2);
    expect(member?.active_api_key_count).toBe(2);
    expect(member?.last_session_refresh_at).toBeInstanceOf(Date);
    expect(member?.disabled).toBe(false);

    // No credential material anywhere in the real response body.
    expect(JSON.stringify(result)).not.toMatch(/sk_|\$2[aby]\$/);
  });

  it("returns real token rows through the real adminProcedure", async () => {
    const { createOAuthTokensRouter } = await import("@repo/trpc");
    const { oauthTokensImplementations } = await import(
      "../../trpc/oauth-tokens.impl"
    );

    const router = createOAuthTokensRouter(oauthTokensImplementations);
    const result = await router
      .createCaller({
        user: { id: ADMIN_ID, role: "admin" },
        session: { id: "itest-session-live" },
      })
      .list();

    expect(result.tokens).toHaveLength(2);
    for (const token of result.tokens) {
      expect(token.user_email).toBe("itest-member@example.invalid");
      expect(token.client_name).toBe("Integration Client");
    }
    // The token values are in the database this query just read. They must not
    // be in its response.
    const payload = JSON.stringify(result);
    expect(payload).not.toContain("itest-access-live");
    expect(payload).not.toContain("itest-refresh-live");
  });

  it("refuses a member caller even with a real database behind it", async () => {
    const { createUsersRouter } = await import("@repo/trpc");
    const { usersImplementations } = await import("../../trpc/users.impl");

    const router = createUsersRouter(usersImplementations);

    // The admin gate is asserted in access-admin-gate.test.ts against mocks;
    // repeating it here proves the gate survives real wiring rather than only
    // holding for a stubbed implementations object.
    await expect(
      router
        .createCaller({
          user: { id: MEMBER_ID, role: "member" },
          session: { id: "itest-session-live" },
        })
        .list(),
    ).rejects.toMatchObject({ code: "FORBIDDEN" });
  });
});

describeIfDb("previewDeleteImpact against real postgres", () => {
  // Re-seeded because the suites below MUTATE. Ordering dependence between
  // test files is a debugging tax nobody should have to pay.
  beforeAll(async () => {
    await seed();
  });

  it("counts the CROSS-USER endpoints a delete would destroy", async () => {
    // The admin owns the namespace; the member owns an endpoint inside it.
    // `namespaces.user_id` cascades and `endpoints.namespace_uuid` cascades
    // from namespaces, so deleting the admin kills the member's endpoint.
    // This was the claim the original confirmation dialog denied.
    const impact = await usersRepository.previewDeleteImpact(ADMIN_ID);

    expect(impact.own_namespaces).toBe(1);
    expect(impact.own_endpoints).toBe(1);
    expect(impact.other_users_endpoints).toBe(1);
  });

  it("counts the CROSS-USER API keys a delete would destroy", async () => {
    // The admin owns a key whose `acts_as_user_id` is the member, and
    // `api_keys.acts_as_user_id` cascades — so deleting the MEMBER (a CI /
    // sync identity, in the real case) silently revokes another
    // administrator's production key.
    const impact = await usersRepository.previewDeleteImpact(MEMBER_ID);

    expect(impact.other_users_api_keys).toBe(1);
    expect(impact.sessions).toBe(2);
    expect(impact.oauth_tokens).toBe(3);
    expect(impact.m365_tokens).toBe(1);
  });

  it("matches what the cascade actually removes", async () => {
    const { eq, ne } = await import("drizzle-orm");
    const impact = await usersRepository.previewDeleteImpact(ADMIN_ID);

    const before = await db
      .select({ uuid: schema.endpointsTable.uuid })
      .from(schema.endpointsTable)
      .where(ne(schema.endpointsTable.user_id, ADMIN_ID));
    expect(before).toHaveLength(impact.other_users_endpoints);

    await usersRepository.deleteById(ADMIN_ID);

    // The preview is only useful if it is TRUE. Verified by doing the thing.
    const after = await db
      .select({ uuid: schema.endpointsTable.uuid })
      .from(schema.endpointsTable)
      .where(ne(schema.endpointsTable.user_id, ADMIN_ID));
    expect(after).toHaveLength(0);

    // ...and the other user's account itself is untouched.
    const [survivor] = await db
      .select({ id: schema.usersTable.id })
      .from(schema.usersTable)
      .where(eq(schema.usersTable.id, MEMBER_ID));
    expect(survivor?.id).toBe(MEMBER_ID);
  });
});

describeIfDb("setDisabled against real postgres", () => {
  beforeAll(async () => {
    await seed();
  });

  it("locks the account, stamps the audit columns, and reverses cleanly", async () => {
    const { eq } = await import("drizzle-orm");

    expect(await usersRepository.isDisabled(MEMBER_ID)).toBe(false);

    const locked = await usersRepository.setDisabled(MEMBER_ID, true, ADMIN_ID);
    expect(locked).toEqual({ id: MEMBER_ID, disabled: true });
    expect(await usersRepository.isDisabled(MEMBER_ID)).toBe(true);

    const [row] = await db
      .select({
        disabled: schema.usersTable.disabled,
        disabled_at: schema.usersTable.disabled_at,
        disabled_by: schema.usersTable.disabled_by,
      })
      .from(schema.usersTable)
      .where(eq(schema.usersTable.id, MEMBER_ID));
    expect(row?.disabled).toBe(true);
    expect(row?.disabled_at).toBeInstanceOf(Date);
    expect(row?.disabled_by).toBe(ADMIN_ID);

    // Enable reverses it, and clears the stamp so the columns describe the
    // CURRENT state rather than a stale lock.
    await usersRepository.setDisabled(MEMBER_ID, false, ADMIN_ID);
    expect(await usersRepository.isDisabled(MEMBER_ID)).toBe(false);

    const [reenabled] = await db
      .select({
        disabled: schema.usersTable.disabled,
        disabled_at: schema.usersTable.disabled_at,
        disabled_by: schema.usersTable.disabled_by,
      })
      .from(schema.usersTable)
      .where(eq(schema.usersTable.id, MEMBER_ID));
    expect(reenabled?.disabled).toBe(false);
    expect(reenabled?.disabled_at).toBeNull();
    expect(reenabled?.disabled_by).toBeNull();
  });

  it("surfaces the lock in the admin listing", async () => {
    await usersRepository.setDisabled(MEMBER_ID, true, ADMIN_ID);

    const rows = await buildUserListQuery(new Date());
    const serialized = UsersSerializer.serializeUserList(rows);
    const member = serialized.find((row) => row.id === MEMBER_ID);

    expect(member?.disabled).toBe(true);
    expect(member?.disabled_by).toBe(ADMIN_ID);
    expect(member?.disabled_at).toBeInstanceOf(Date);
    // Still parses under the real contract with the columns populated.
    expect(() => UserListItemSchema.parse(member)).not.toThrow();

    await usersRepository.setDisabled(MEMBER_ID, false, ADMIN_ID);
  });

  it("fails CLOSED for an account that does not exist", async () => {
    // A session pointing at a deleted user row is not a session this gateway
    // should serve. Defaulting to "enabled" would turn a mid-cascade race
    // into an open door.
    expect(await usersRepository.isDisabled("no-such-user")).toBe(true);
  });
});

describeIfDb("revokeAccess against real postgres", () => {
  beforeAll(async () => {
    await seed();
  });

  it("severs every access path including acts-as keys and the m365 token", async () => {
    const result = await usersRepository.revokeAccess(MEMBER_ID);
    const { eq } = await import("drizzle-orm");

    expect(result.sessions_deleted).toBe(2);
    // 2 unexpired + 1 expired: revocation removes the lot, not just the live
    // ones — an expired access token can still carry a valid refresh token.
    expect(result.oauth_tokens_deleted).toBe(3);
    // 1 own active key + 1 acts-as key. The inactive one is already revoked.
    expect(result.api_keys_deactivated).toBe(2);
    expect(result.m365_tokens_revoked).toBe(1);

    const keys = await db
      .select({
        name: schema.apiKeysTable.name,
        is_active: schema.apiKeysTable.is_active,
      })
      .from(schema.apiKeysTable);

    // Nothing that can act as this identity may still authenticate.
    for (const key of keys) {
      if (key.name !== "itest-key-member-inactive") {
        expect(key.is_active).toBe(false);
      }
    }

    const [m365] = await db
      .select({ status: schema.m365UserTokensTable.status })
      .from(schema.m365UserTokensTable)
      .where(eq(schema.m365UserTokensTable.user_id, MEMBER_ID));
    expect(m365?.status).toBe("reauth_required");

    // The account itself survives — it is the incident evidence.
    const [user] = await db
      .select({ id: schema.usersTable.id })
      .from(schema.usersTable)
      .where(eq(schema.usersTable.id, MEMBER_ID));
    expect(user?.id).toBe(MEMBER_ID);
  });
});
