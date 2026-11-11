/**
 * Self-registered clients wait for an administrator (migration 0042), end to
 * end against a REAL Postgres: real registration, authorization and token
 * routers, real better-auth, real repositories, and the real tRPC procedure
 * builders with the real oauthClients implementation.
 *
 * Pinned here:
 *  - an anonymous loopback registration succeeds but is stored pending even
 *    when its body asks to be approved; authorizing it shows the waiting page
 *    with no signed request, consent cookie, code or token;
 *  - an administrator's approval issues nothing by itself, and reloading the
 *    same authorization request then reaches consent with its state and PKCE
 *    challenge unchanged, and the code and refresh grants work;
 *  - a hosted-callback registration is refused and stores no row;
 *  - for a pending or rejected client, a valid signed consent request, a
 *    stored code and a stored refresh token all buy nothing, and nothing is
 *    consumed, rotated or deleted (refresh omits client_id, both client-auth
 *    modes);
 *  - approved admin-created hosted clients and legacy rows still authorize,
 *    exchange and refresh;
 *  - who may list and decide (anonymous, member, admin, admin-plane key),
 *    pending-only transitions, a concurrent approve and reject, refusal of a
 *    pending row with a hosted callback, audit attribution, and that listing
 *    returns no stored secret, salt or raw audit detail.
 *
 * Opt-in via TEST_DATABASE_URL, pointed at a disposable, migrated database:
 *
 *   cd apps/backend
 *   DATABASE_URL=<url> npx drizzle-kit migrate
 *   TEST_DATABASE_URL=<url> npx vitest run \
 *     src/routers/oauth/dcr-approval.integration.test.ts
 */

import { createHash, randomBytes, randomUUID } from "node:crypto";
import type { AddressInfo } from "node:net";

import express from "express";
import { Client } from "pg";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

import { INTEGRATION_DB_LOCK_KEY } from "../../db/repositories/integration-db-lock";

const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL;
const describeIfDb = describe.skipIf(!TEST_DATABASE_URL);

const quiet = { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() };
vi.mock("@/utils/logger", () => ({ default: quiet }));

const RUN = Date.now().toString(36);
const EMAIL = `itest-dcr-approval-${RUN}@example.test`;
const PASSWORD = `itest-throwaway-password-${RUN}`;
const ORIGIN = "http://127.0.0.1:1";
const LOOPBACK = "http://localhost:53682/callback";
const HOSTED = "https://claude.ai/api/mcp/auth_callback";
const ADMIN_ID = `itest-admin-${RUN}`;
const REGISTER_IP = "198.51.100.77";
// Named through constants, as the other suites do, so these read as the
// settings ./dcr-mode and ./token resolve per request.
const DCR_MODE_ENV = "OAUTH_DCR_MODE";
const REFRESH_AUTH_ENV = "OAUTH_REFRESH_CLIENT_AUTH";

type Caller = Record<string, Record<string, (input?: unknown) => Promise<any>>>;

describeIfDb(
  "self-registered clients wait for an administrator (real Postgres)",
  () => {
    let base: string;
    let server: import("node:http").Server;
    let suiteLock: Client;
    let db: typeof import("../../db/index").db;
    let schema: typeof import("../../db/schema");
    let drizzle: typeof import("drizzle-orm");
    let hashApiKey: typeof import("../../lib/api-key-hash").hashApiKey;
    let consentToken: typeof import("./consent-token");
    let trpc: typeof import("@repo/trpc");
    let sessionCookie = "";
    let USER_ID = "";
    let ipCounter = 0;
    const createdClients: string[] = [];

    let admin: { frontend: Caller };
    let member: { frontend: Caller };
    let anonymous: { frontend: Caller };
    let adminPlane: { frontend: Caller };

    const nextIp = () => `203.0.113.${(++ipCounter % 250) + 1}`;
    const cookiesOf = (res: Response) =>
      (res.headers.getSetCookie?.() ?? []).map((c) => c.split(";")[0]);
    const pkce = () => {
      const verifier = randomBytes(32).toString("base64url");
      const challenge = createHash("sha256")
        .update(verifier)
        .digest("base64url");
      return { verifier, challenge };
    };

    async function register(body: Record<string, unknown>, ip = nextIp()) {
      const res = await fetch(`${base}/oauth/register`, {
        method: "POST",
        headers: { "content-type": "application/json", "cf-connecting-ip": ip },
        body: JSON.stringify(body),
      });
      const json = (await res.json()) as Record<string, unknown>;
      if (typeof json.client_id === "string")
        createdClients.push(json.client_id);
      return { status: res.status, body: json };
    }

    function authorizeUrl(
      clientId: string,
      redirectUri: string,
      challenge: string,
      state: string,
    ) {
      return (
        `${base}/oauth/authorize?response_type=code&client_id=${encodeURIComponent(clientId)}` +
        `&redirect_uri=${encodeURIComponent(redirectUri)}` +
        `&code_challenge=${challenge}&code_challenge_method=S256&state=${state}`
      );
    }

    async function authorize(url: string) {
      return fetch(url, {
        redirect: "manual",
        headers: { cookie: sessionCookie, "cf-connecting-ip": nextIp() },
      });
    }

    async function decide(authorizeRes: Response) {
      const areq = new URL(
        authorizeRes.headers.get("location") as string,
      ).searchParams.get("areq") as string;
      return fetch(`${base}/oauth/authorize/decision`, {
        method: "POST",
        redirect: "manual",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
          cookie: [sessionCookie, ...cookiesOf(authorizeRes)].join("; "),
          "cf-connecting-ip": nextIp(),
        },
        body: new URLSearchParams({ areq, decision: "approve" }).toString(),
      });
    }

    async function token(params: Record<string, string>) {
      const res = await fetch(`${base}/oauth/token`, {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
          "cf-connecting-ip": nextIp(),
        },
        body: new URLSearchParams(params).toString(),
      });
      return {
        status: res.status,
        body: (await res.json()) as Record<string, string | undefined>,
      };
    }

    async function clientRow(clientId: string) {
      const [row] = await db
        .select()
        .from(schema.oauthClientsTable)
        .where(drizzle.eq(schema.oauthClientsTable.client_id, clientId));
      return row ?? null;
    }

    async function grantCounts(clientId: string) {
      const codes = await db
        .select()
        .from(schema.oauthAuthorizationCodesTable)
        .where(
          drizzle.eq(schema.oauthAuthorizationCodesTable.client_id, clientId),
        );
      const tokens = await db
        .select()
        .from(schema.oauthAccessTokensTable)
        .where(drizzle.eq(schema.oauthAccessTokensTable.client_id, clientId));
      const rotated = await db
        .select()
        .from(schema.oauthRotatedRefreshTokensTable)
        .where(
          drizzle.eq(schema.oauthRotatedRefreshTokensTable.client_id, clientId),
        );
      return {
        codes: codes.length,
        tokens: tokens.length,
        rotated: rotated.length,
      };
    }

    /** The audit writer is detached; wait for its row. */
    async function auditRows(action: string, targetId: string, expected = 1) {
      for (let attempt = 0; attempt < 100; attempt++) {
        const rows = await db
          .select()
          .from(schema.auditLogTable)
          .where(
            drizzle.and(
              drizzle.eq(schema.auditLogTable.action, action),
              drizzle.eq(schema.auditLogTable.target_id, targetId),
            ),
          );
        if (rows.length >= expected) return rows;
        await new Promise((r) => setTimeout(r, 20));
      }
      return [];
    }

    /** A client row written straight to the table, as psql or a seed would. */
    async function seedClient(fields: {
      client_id: string;
      status: "approved" | "pending" | "rejected";
      source: "dcr" | "admin" | null;
      redirect: string;
    }) {
      await db.insert(schema.oauthClientsTable).values({
        client_id: fields.client_id,
        client_name: fields.client_id,
        redirect_uris: [fields.redirect],
        token_endpoint_auth_method: "none",
        grant_types: ["authorization_code", "refresh_token"],
        registration_source: fields.source,
        approval_status: fields.status,
        rejected_at: fields.status === "rejected" ? new Date() : null,
      });
      createdClients.push(fields.client_id);
    }

    beforeAll(async () => {
      process.env.DATABASE_URL = TEST_DATABASE_URL;
      process.env.BETTER_AUTH_SECRET = `itest-throwaway-secret-${RUN}`;
      process.env.APP_URL = ORIGIN;
      delete process.env[DCR_MODE_ENV];
      delete process.env[REFRESH_AUTH_ENV];
      suiteLock = new Client({ connectionString: TEST_DATABASE_URL });
      await suiteLock.connect();
      await suiteLock.query(
        `SELECT pg_advisory_lock(${INTEGRATION_DB_LOCK_KEY})`,
      );

      ({ db } = await import("../../db/index"));
      schema = await import("../../db/schema");
      drizzle = await import("drizzle-orm");
      ({ hashApiKey } = await import("../../lib/api-key-hash"));
      consentToken = await import("./consent-token");
      trpc = await import("@repo/trpc");
      const { auth } = await import("../../auth");
      const utils = await import("./utils");
      const { auditContextMiddleware } = await import(
        "../../middleware/audit-context.middleware"
      );
      const { default: registrationRouter } = await import("./registration");
      const { default: authorizationRouter } = await import("./authorization");
      const { default: tokenRouter } = await import("./token");
      const { oauthClientsImplementations } = await import(
        "../../trpc/oauth-clients.impl"
      );

      await db
        .delete(schema.usersTable)
        .where(drizzle.eq(schema.usersTable.email, EMAIL));
      const signup = await auth.handler(
        new Request(`${ORIGIN}/api/auth/sign-up/email`, {
          method: "POST",
          headers: { "content-type": "application/json", origin: ORIGIN },
          body: JSON.stringify({
            email: EMAIL,
            password: PASSWORD,
            name: "itest",
          }),
        }),
      );
      expect(signup.status).toBe(200);
      sessionCookie = cookiesOf(signup).join("; ");
      USER_ID = ((await signup.json()) as { user: { id: string } }).user.id;

      const app = express();
      // Same order as apps/backend/src/index.ts and routers/oauth/index.ts.
      app.use(auditContextMiddleware);
      app.use(utils.securityHeaders);
      app.use(utils.jsonParsingMiddleware);
      app.use(utils.urlencodedParsingMiddleware);
      app.use(authorizationRouter);
      app.use(tokenRouter);
      app.use(registrationRouter);
      await new Promise<void>((resolve) => {
        server = app.listen(0, "127.0.0.1", resolve);
      });
      base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

      // The real app router with the real oauthClients implementation; every
      // other router is a stub this file never calls.
      const stub = new Proxy({}, { get: () => async () => ({}) });
      const appRouter = trpc.createAppRouter({
        frontend: {
          mcpServers: stub,
          namespaces: stub,
          endpoints: stub,
          oauth: stub,
          oauthClients: oauthClientsImplementations,
          oauthTokens: stub,
          users: stub,
          tools: stub,
          apiKeys: stub,
          config: stub,
          logs: stub,
          accessGroups: stub,
        } as unknown as Parameters<typeof trpc.createAppRouter>[0]["frontend"],
      });
      const audit = {
        actor_ip: "192.0.2.10",
        actor_user_agent: "itest",
        request_id: "r",
      };
      const callerFor = (ctx: object) =>
        appRouter.createCaller(ctx as never) as unknown as { frontend: Caller };
      admin = callerFor({
        user: { id: ADMIN_ID, role: "admin", email: "admin@example.test" },
        session: { id: "admin-session" },
        audit,
      });
      member = callerFor({
        user: { id: USER_ID, role: "member", email: EMAIL },
        session: { id: "member-session" },
        audit,
      });
      anonymous = callerFor({ audit });
      adminPlane = callerFor({
        user: { id: ADMIN_ID, role: "admin", email: "admin@example.test" },
        session: { id: "synthetic" },
        authOrigin: {
          kind: "admin_plane",
          key_uuid: randomUUID(),
          owner_user_id: ADMIN_ID,
        },
        audit,
      });
    }, 60_000);

    afterAll(async () => {
      await new Promise((resolve) => server?.close(resolve));
      if (db) {
        for (const id of createdClients) {
          await db
            .delete(schema.oauthClientsTable)
            .where(drizzle.eq(schema.oauthClientsTable.client_id, id));
        }
        await db
          .delete(schema.usersTable)
          .where(drizzle.eq(schema.usersTable.email, EMAIL));
        const { pool } = await import("../../db/index");
        await pool.end();
      }
      await suiteLock?.query(
        `SELECT pg_advisory_unlock(${INTEGRATION_DB_LOCK_KEY})`,
      );
      await suiteLock?.end();
    });

    it("holds an anonymous loopback registration until an administrator approves it", async () => {
      // The registration asks to be approved and admin-created; the door decides.
      const reg = await register(
        {
          client_name: "Claude Code",
          redirect_uris: [LOOPBACK],
          approval_status: "approved",
          approved_by: "someone",
          registration_source: "admin",
        },
        REGISTER_IP,
      );
      expect(reg.status).toBe(201);
      expect(reg.body.approval_status).toBe("pending");
      const clientId = reg.body.client_id as string;

      const stored = await clientRow(clientId);
      expect(stored).toMatchObject({
        approval_status: "pending",
        registration_source: "dcr",
        approved_by: null,
        approved_at: null,
        rejected_at: null,
      });

      // Authorize: the waiting page, and nothing a consent flow would start with.
      const { verifier, challenge } = pkce();
      const url = authorizeUrl(
        clientId,
        LOOPBACK,
        challenge,
        "keep-this-state",
      );
      const waiting = await authorize(url);
      const page = await waiting.text();
      expect(waiting.status).toBe(403);
      expect(waiting.headers.get("content-type")).toContain("text/html");
      expect(waiting.headers.get("cache-control")).toBe("no-store");
      expect(waiting.headers.get("location")).toBeNull();
      expect(cookiesOf(waiting)).toEqual([]);
      expect(page).toContain("Waiting for administrator approval");
      expect(page).toContain(clientId);
      expect(page).not.toContain("areq");
      expect(await grantCounts(clientId)).toEqual({
        codes: 0,
        tokens: 0,
        rotated: 0,
      });

      const [blocked] = await auditRows(
        "oauth.authorize.client_not_approved",
        clientId,
      );
      expect(blocked).toMatchObject({
        actor_type: "user",
        actor_id: USER_ID,
        outcome: "denied",
        http_status: 403,
      });
      expect(JSON.stringify(blocked.detail)).not.toContain(challenge);
      expect(JSON.stringify(blocked.detail)).not.toContain("keep-this-state");

      // The administrator's view: status, provenance, the registering address,
      // and no secret, salt or raw audit detail.
      await auditRows("oauth.dcr.register", clientId);
      const listed = await admin.frontend.oauthClients.list();
      const item = listed.clients.find(
        (c: { client_id: string }) => c.client_id === clientId,
      );
      expect(item).toMatchObject({
        approval_status: "pending",
        registration_source: "dcr",
        registered_from_ip: REGISTER_IP,
        approved_by: null,
      });
      const wire = JSON.stringify(listed);
      expect(wire).not.toContain("client_secret_salt");
      expect(wire).not.toContain('"client_secret"');
      expect(wire).not.toContain('"detail"');

      // Approval: attributed to the session's administrator, and it mints no
      // grant of its own.
      const decided = await admin.frontend.oauthClients.approve({
        client_id: clientId,
      });
      expect(decided).toMatchObject({
        approval_status: "approved",
        approved_by: ADMIN_ID,
      });
      expect(await grantCounts(clientId)).toEqual({
        codes: 0,
        tokens: 0,
        rotated: 0,
      });
      const [approvedRow] = await auditRows("oauthclient.approve", clientId);
      expect(approvedRow).toMatchObject({
        actor_type: "user",
        actor_id: ADMIN_ID,
        outcome: "success",
      });
      expect(approvedRow.detail).toMatchObject({
        previous_status: "pending",
        new_status: "approved",
      });

      // Reload the SAME authorization request: consent, with the state and the
      // PKCE challenge the client is waiting on unchanged.
      const resumed = await authorize(url);
      expect(resumed.status).toBe(302);
      const areq = new URL(
        resumed.headers.get("location") as string,
      ).searchParams.get("areq");
      const payload = consentToken.verifyConsentRequest(areq);
      expect(payload).toMatchObject({
        client_id: clientId,
        redirect_uri: LOOPBACK,
        state: "keep-this-state",
        code_challenge: challenge,
        code_challenge_method: "S256",
        user_id: USER_ID,
      });

      const decision = await decide(resumed);
      expect(decision.status).toBe(200);
      const code = (await decision.text()).match(
        /mcp_code_[A-Za-z0-9_-]+/,
      )?.[0] as string;
      expect(code).toBeTruthy();

      const exchanged = await token({
        grant_type: "authorization_code",
        code,
        client_id: clientId,
        redirect_uri: LOOPBACK,
        code_verifier: verifier,
      });
      expect(exchanged.status).toBe(200);
      const refreshed = await token({
        grant_type: "refresh_token",
        refresh_token: exchanged.body.refresh_token as string,
      });
      expect(refreshed.status).toBe(200);
    });

    it("lists a client once with its earliest successful registration address", async () => {
      const registrationIp = "198.51.100.78";
      const reg = await register(
        { client_name: "Registration history", redirect_uris: [LOOPBACK] },
        registrationIp,
      );
      expect(reg.status).toBe(201);
      const clientId = reg.body.client_id as string;
      const [registered] = await auditRows("oauth.dcr.register", clientId);
      expect(registered).toBeDefined();

      const base = {
        actor_type: "anonymous",
        action: "oauth.dcr.register",
        target_type: "oauth_client",
        target_id: clientId,
        outcome: "success",
      };
      const earlier = new Date(registered.occurred_at.getTime() - 1_000);
      await db.insert(schema.auditLogTable).values([
        {
          ...base,
          actor_ip: "192.0.2.201",
          occurred_at: new Date(registered.occurred_at.getTime() + 1_000),
        },
        {
          ...base,
          outcome: "denied",
          actor_ip: "192.0.2.202",
          occurred_at: earlier,
        },
        {
          ...base,
          action: "oauth.authorize.client_not_approved",
          actor_ip: "192.0.2.203",
          occurred_at: earlier,
        },
      ]);

      const listed = await admin.frontend.oauthClients.list();
      const items = listed.clients.filter(
        (client: { client_id: string }) => client.client_id === clientId,
      );
      expect(items).toHaveLength(1);
      expect(items[0].registered_from_ip).toBe(registrationIp);
    });

    it("refuses a hosted-callback registration and stores nothing", async () => {
      const before = await db.select().from(schema.oauthClientsTable);
      const reg = await register({
        client_name: "Claude",
        redirect_uris: [HOSTED],
      });
      expect(reg.status).toBe(400);
      expect(reg.body).toEqual({
        error: "invalid_redirect_uri",
        error_description:
          "This gateway registers only local callback addresses automatically. Hosted clients use a client an administrator creates.",
      });
      const after = await db.select().from(schema.oauthClientsTable);
      expect(after.length).toBe(before.length);
    });

    it("escapes hostile registration data on the waiting page and links nothing", async () => {
      const hostileName = `Claude Code"><script>alert('x')</script><img src=x>`;
      const hostileCallback = `http://localhost:8765/cb?x="><script>alert(1)</script>`;
      const reg = await register({
        client_name: hostileName,
        redirect_uris: [hostileCallback],
      });
      expect(reg.status).toBe(201);
      const { challenge } = pkce();
      const res = await authorize(
        authorizeUrl(
          reg.body.client_id as string,
          hostileCallback,
          challenge,
          "s",
        ),
      );
      const page = await res.text();
      expect(res.status).toBe(403);
      expect(page).not.toContain("<script>");
      expect(page).not.toContain("<img");
      expect(page).not.toMatch(/href=/i);
      expect(page).toContain("&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;");
      expect(page).toContain("cb?x=&quot;&gt;&lt;script&gt;");
      expect(res.headers.get("content-security-policy")).toContain(
        "default-src 'none'",
      );
    });

    it("shows a rejected client its own page and keeps the decision final", async () => {
      const reg = await register({
        client_name: "Unwanted",
        redirect_uris: [LOOPBACK],
      });
      const clientId = reg.body.client_id as string;
      const rejected = await admin.frontend.oauthClients.reject({
        client_id: clientId,
      });
      expect(rejected.approval_status).toBe("rejected");
      expect(rejected.rejected_at).toBeInstanceOf(Date);

      const res = await authorize(
        authorizeUrl(clientId, LOOPBACK, pkce().challenge, "s"),
      );
      expect(res.status).toBe(403);
      expect(await res.text()).toContain("Application rejected");

      await expect(
        admin.frontend.oauthClients.approve({ client_id: clientId }),
      ).rejects.toMatchObject({ code: "CONFLICT" });
      expect((await clientRow(clientId))?.approval_status).toBe("rejected");
    });

    describe.each(["pending", "rejected"] as const)(
      "grants issued around a %s client buy nothing",
      (status) => {
        const clientId = `mcp_client_itest_seeded_${status}_${RUN}`;
        const code = `mcp_code_seeded_${status}_${RUN}`;
        const refresh = `mcp_refresh_seeded_${status}_${RUN}`;
        const access = `mcp_token_seeded_${status}_${RUN}`;
        const { verifier, challenge } = pkce();
        const cid = `cid${status}`;
        const csrf = randomBytes(32).toString("base64url");

        beforeAll(async () => {
          await seedClient({
            client_id: clientId,
            status,
            source: "dcr",
            redirect: LOOPBACK,
          });
          await db.insert(schema.oauthAuthorizationCodesTable).values({
            code: hashApiKey(code),
            client_id: clientId,
            redirect_uri: LOOPBACK,
            scope: "mcp",
            user_id: USER_ID,
            code_challenge: challenge,
            code_challenge_method: "S256",
            expires_at: new Date(Date.now() + 5 * 60 * 1000),
          });
          await db.insert(schema.oauthAccessTokensTable).values({
            access_token: hashApiKey(access),
            access_token_last4: access.slice(-4),
            client_id: clientId,
            user_id: USER_ID,
            scope: "mcp",
            expires_at: new Date(Date.now() + 60 * 60 * 1000),
            refresh_token: hashApiKey(refresh),
            refresh_token_expires_at: new Date(
              Date.now() + 24 * 60 * 60 * 1000,
            ),
            family_id: randomUUID(),
          });
        });

        const areq = () =>
          consentToken.signConsentRequest({
            client_id: clientId,
            redirect_uri: LOOPBACK,
            scope: "mcp",
            state: "s",
            code_challenge: challenge,
            code_challenge_method: "S256",
            user_id: USER_ID,
            cid,
            csrf,
            exp: Date.now() + 60_000,
          });

        it("consent info refuses a valid signed request", async () => {
          const res = await fetch(
            `${base}/oauth/consent/info?areq=${encodeURIComponent(areq())}`,
            { headers: { cookie: sessionCookie } },
          );
          expect(res.status).toBe(403);
          expect(((await res.json()) as { error: string }).error).toBe(
            "unauthorized_client",
          );
        });

        it("the consent decision mints no code and redirects nowhere", async () => {
          const res = await fetch(`${base}/oauth/authorize/decision`, {
            method: "POST",
            redirect: "manual",
            headers: {
              "content-type": "application/x-www-form-urlencoded",
              cookie: `${sessionCookie}; ${consentToken.consentCsrfCookieName(false, cid)}=${csrf}`,
              "cf-connecting-ip": nextIp(),
            },
            body: new URLSearchParams({
              areq: areq(),
              decision: "approve",
            }).toString(),
          });
          expect(res.status).toBe(403);
          expect(res.headers.get("location")).toBeNull();
          expect(await grantCounts(clientId)).toEqual({
            codes: 1,
            tokens: 1,
            rotated: 0,
          });
        });

        it("the stored code is refused and left in place", async () => {
          const res = await token({
            grant_type: "authorization_code",
            code,
            client_id: clientId,
            redirect_uri: LOOPBACK,
            code_verifier: verifier,
          });
          expect(res.status).toBe(400);
          expect(res.body.error).toBe("unauthorized_client");
          expect(await grantCounts(clientId)).toEqual({
            codes: 1,
            tokens: 1,
            rotated: 0,
          });
        });

        it.each(["log", "enforce"])(
          "the stored refresh token is refused without rotation (client auth %s, no client_id)",
          async (mode) => {
            process.env[REFRESH_AUTH_ENV] = mode;
            try {
              const res = await token({
                grant_type: "refresh_token",
                refresh_token: refresh,
              });
              expect(res.status).toBe(400);
              expect(res.body.error).toBe("unauthorized_client");
            } finally {
              delete process.env[REFRESH_AUTH_ENV];
            }
            const [row] = await db
              .select()
              .from(schema.oauthAccessTokensTable)
              .where(
                drizzle.eq(schema.oauthAccessTokensTable.client_id, clientId),
              );
            expect(row?.refresh_token).toBe(hashApiKey(refresh));
            expect(await grantCounts(clientId)).toEqual({
              codes: 1,
              tokens: 1,
              rotated: 0,
            });
          },
        );
      },
    );

    it.each([
      ["an admin-created hosted client", "admin" as const, HOSTED],
      ["a legacy row with no provenance", null, LOOPBACK],
    ])(
      "still authorizes, exchanges and refreshes %s",
      async (_label, source, redirect) => {
        const clientId = `mcp_client_itest_ok_${source ?? "legacy"}_${RUN}`;
        await seedClient({
          client_id: clientId,
          status: "approved",
          source,
          redirect,
        });
        const { verifier, challenge } = pkce();
        const consent = await authorize(
          authorizeUrl(clientId, redirect, challenge, "s"),
        );
        expect(consent.status).toBe(302);
        const decision = await decide(consent);
        const code =
          redirect === HOSTED
            ? new URL(
                decision.headers.get("location") as string,
              ).searchParams.get("code")
            : (await decision.text()).match(/mcp_code_[A-Za-z0-9_-]+/)?.[0];
        expect(code).toMatch(/^mcp_code_/);
        const exchanged = await token({
          grant_type: "authorization_code",
          code: code as string,
          client_id: clientId,
          redirect_uri: redirect,
          code_verifier: verifier,
        });
        expect(exchanged.status).toBe(200);
        const refreshed = await token({
          grant_type: "refresh_token",
          refresh_token: exchanged.body.refresh_token as string,
        });
        expect(refreshed.status).toBe(200);
      },
    );

    it("lets an administrator still create a hosted client, approved", async () => {
      const created = await admin.frontend.oauthClients.create({
        client_name: "Claude (org)",
        redirect_uris: [HOSTED],
        token_endpoint_auth_method: "client_secret_post",
        approval_status: "pending",
      });
      createdClients.push(created.client_id);
      expect(created.approval_status).toBe("approved");
      expect(await clientRow(created.client_id)).toMatchObject({
        approval_status: "approved",
        registration_source: "admin",
      });
    });

    it("keeps listing and decisions to administrators' own sessions", async () => {
      const reg = await register({
        client_name: "Scope probe",
        redirect_uris: [LOOPBACK],
      });
      const clientId = reg.body.client_id as string;

      for (const procedure of ["list", "approve", "reject"] as const) {
        const input =
          procedure === "list" ? undefined : { client_id: clientId };
        await expect(
          anonymous.frontend.oauthClients[procedure](input),
        ).rejects.toMatchObject({
          code: "UNAUTHORIZED",
        });
        await expect(
          member.frontend.oauthClients[procedure](input),
        ).rejects.toMatchObject({
          code: "FORBIDDEN",
        });
        await expect(
          adminPlane.frontend.oauthClients[procedure](input),
        ).rejects.toMatchObject({
          code: "FORBIDDEN",
          message: trpc.ADMIN_PLANE_FORBIDDEN_MESSAGE,
        });
      }
      // Nor can an admin-plane key mint an already approved client.
      await expect(
        adminPlane.frontend.oauthClients.create({
          client_name: "CI client",
          redirect_uris: [HOSTED],
        }),
      ).rejects.toMatchObject({ code: "FORBIDDEN" });
      expect((await clientRow(clientId))?.approval_status).toBe("pending");
    });

    it("gives a concurrent approve and reject exactly one winner", async () => {
      for (let round = 0; round < 5; round++) {
        const reg = await register({
          client_name: `Race ${round}`,
          redirect_uris: [LOOPBACK],
        });
        const clientId = reg.body.client_id as string;
        const [approve, reject] = await Promise.allSettled([
          admin.frontend.oauthClients.approve({ client_id: clientId }),
          admin.frontend.oauthClients.reject({ client_id: clientId }),
        ]);
        const outcomes = [approve, reject].map((r) => r.status);
        expect(outcomes.filter((s) => s === "fulfilled")).toHaveLength(1);
        const loser = [approve, reject].find(
          (r) => r.status === "rejected",
        ) as PromiseRejectedResult;
        expect(loser.reason).toMatchObject({ code: "CONFLICT" });
        const winner = approve.status === "fulfilled" ? "approved" : "rejected";
        expect((await clientRow(clientId))?.approval_status).toBe(winner);
        // One success audit row, for the winner only.
        await new Promise((r) => setTimeout(r, 150));
        const approvedRows = await auditRows(
          "oauthclient.approve",
          clientId,
          0,
        );
        const rejectedRows = await auditRows("oauthclient.reject", clientId, 0);
        expect(approvedRows.length + rejectedRows.length).toBe(1);
      }
    });

    it("refuses to approve a pending row with a hosted callback, and stale or ineligible rows", async () => {
      const hostedPending = `mcp_client_itest_hosted_pending_${RUN}`;
      await seedClient({
        client_id: hostedPending,
        status: "pending",
        source: "dcr",
        redirect: HOSTED,
      });
      await expect(
        admin.frontend.oauthClients.approve({ client_id: hostedPending }),
      ).rejects.toMatchObject({ code: "BAD_REQUEST" });
      expect((await clientRow(hostedPending))?.approval_status).toBe("pending");

      const adminRow = `mcp_client_itest_admin_row_${RUN}`;
      await seedClient({
        client_id: adminRow,
        status: "approved",
        source: "admin",
        redirect: HOSTED,
      });
      await expect(
        admin.frontend.oauthClients.reject({ client_id: adminRow }),
      ).rejects.toMatchObject({ code: "CONFLICT" });
      expect((await clientRow(adminRow))?.approval_status).toBe("approved");

      await expect(
        admin.frontend.oauthClients.approve({
          client_id: `mcp_client_gone_${RUN}`,
        }),
      ).rejects.toMatchObject({ code: "NOT_FOUND" });

      // No success audit row for any refused decision.
      await new Promise((r) => setTimeout(r, 150));
      for (const id of [hostedPending, adminRow]) {
        expect(await auditRows("oauthclient.approve", id, 0)).toEqual([]);
        expect(await auditRows("oauthclient.reject", id, 0)).toEqual([]);
      }
    });
  },
);
