/**
 * A client identified by a published metadata document (CIMD), end to end
 * against a REAL Postgres: real authorization and token routers, real
 * better-auth, real repositories, the real resolver and guard. Only DNS and
 * the socket are faked, below the guard.
 *
 * Pinned:
 *  - the whole flow: authorize reaches consent, consent info names the
 *    document's host, the decision mints a code, the code exchanges with an
 *    RFC 7636 Appendix B verifier, and the refresh token refreshes;
 *  - removing the allowlist entry makes authorize, consent info, the token
 *    exchange and the refresh refuse, consumes and rotates nothing, and the
 *    same requests work again once the entry is back;
 *  - a document that adds a redirect URI is picked up once, and a transient
 *    503 serves a fresh row and a stale row but not one past 24 hours.
 *
 * Opt-in via TEST_DATABASE_URL, pointed at a disposable, migrated database:
 *
 *   cd apps/backend
 *   DATABASE_URL=<url> npx drizzle-kit migrate
 *   TEST_DATABASE_URL=<url> npx vitest run \
 *     src/routers/oauth/cimd.integration.test.ts
 */
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
const EMAIL = `itest-cimd-${RUN}@example.test`;
const PASSWORD = `itest-throwaway-password-${RUN}`;
const ORIGIN = "http://127.0.0.1:1";
const CIMD_ID = `https://cimd-itest-${RUN}.example.com/oauth/client.json`;
const HOSTED = "https://claude.ai/api/mcp/auth_callback";
const SECOND_HOSTED = "https://claude.com/api/mcp/auth_callback";
// RFC 7636 Appendix B.
const VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const ALLOWLIST_ENV = "OAUTH_CIMD_ALLOWED_CLIENTS";
const T0 = Date.UTC(2026, 10, 12, 12, 0, 0);
const HOUR = 3_600_000;

describeIfDb("client metadata document client (real Postgres)", () => {
  let base: string;
  let server: import("node:http").Server;
  let suiteLock: Client;
  let db: typeof import("../../db/index").db;
  let schema: typeof import("../../db/schema");
  let drizzle: typeof import("drizzle-orm");
  let cimd: typeof import("./cimd");
  let cimdConfig: typeof import("./cimd-config");
  let sessionCookie = "";
  let ipCounter = 0;
  let now = T0;
  let documentRedirects: string[] = [HOSTED];
  let documentStatus = 200;
  let fetchCount = 0;

  const nextIp = () => `203.0.113.${(++ipCounter % 250) + 1}`;
  const cookiesOf = (res: Response) =>
    (res.headers.getSetCookie?.() ?? []).map((c) => c.split(";")[0]);

  const baseFetch = vi.fn(async () => {
    fetchCount += 1;
    if (documentStatus !== 200) {
      return new Response("unavailable", { status: documentStatus });
    }
    return new Response(
      JSON.stringify({
        client_id: CIMD_ID,
        client_name: "Itest Connector",
        redirect_uris: documentRedirects,
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        token_endpoint_auth_method: "none",
      }),
      { status: 200 },
    );
  });
  const lookup = vi.fn(async () => ["93.184.216.34"]);

  const allow = (value: string) => {
    process.env[ALLOWLIST_ENV] = value;
    cimdConfig.resetCimdConfigForTesting();
  };

  function authorizeUrl(redirectUri = HOSTED) {
    return (
      `${base}/oauth/authorize?response_type=code&client_id=${encodeURIComponent(CIMD_ID)}` +
      `&redirect_uri=${encodeURIComponent(redirectUri)}` +
      `&code_challenge=${CHALLENGE}&code_challenge_method=S256&state=st`
    );
  }

  async function authorize(redirectUri = HOSTED) {
    return fetch(authorizeUrl(redirectUri), {
      redirect: "manual",
      headers: { cookie: sessionCookie, "cf-connecting-ip": nextIp() },
    });
  }

  const areqOf = (res: Response) =>
    new URL(res.headers.get("location") as string).searchParams.get(
      "areq",
    ) as string;

  async function consentInfo(areq: string) {
    const res = await fetch(
      `${base}/oauth/consent/info?areq=${encodeURIComponent(areq)}`,
      { headers: { cookie: sessionCookie, "cf-connecting-ip": nextIp() } },
    );
    return {
      status: res.status,
      body: (await res.json()) as Record<string, unknown>,
    };
  }

  async function decide(authorizeRes: Response) {
    return fetch(`${base}/oauth/authorize/decision`, {
      method: "POST",
      redirect: "manual",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        cookie: [sessionCookie, ...cookiesOf(authorizeRes)].join("; "),
        "cf-connecting-ip": nextIp(),
      },
      body: new URLSearchParams({
        areq: areqOf(authorizeRes),
        decision: "approve",
      }).toString(),
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

  /** Authorize and approve; returns the code the client's callback receives. */
  async function obtainCode(): Promise<string> {
    const authorized = await authorize();
    expect(authorized.status).toBe(302);
    const decision = await decide(authorized);
    expect(decision.status).toBe(302);
    const code = new URL(
      decision.headers.get("location") as string,
    ).searchParams.get("code");
    expect(code).toBeTruthy();
    return code as string;
  }

  const exchange = (code: string) =>
    token({
      grant_type: "authorization_code",
      code,
      client_id: CIMD_ID,
      redirect_uri: HOSTED,
      code_verifier: VERIFIER,
    });

  const clientRow = async () => {
    const [row] = await db
      .select()
      .from(schema.oauthClientsTable)
      .where(drizzle.eq(schema.oauthClientsTable.client_id, CIMD_ID));
    return row ?? null;
  };

  const tokenRows = () =>
    db
      .select()
      .from(schema.oauthAccessTokensTable)
      .where(drizzle.eq(schema.oauthAccessTokensTable.client_id, CIMD_ID));

  const codeRows = () =>
    db
      .select()
      .from(schema.oauthAuthorizationCodesTable)
      .where(
        drizzle.eq(schema.oauthAuthorizationCodesTable.client_id, CIMD_ID),
      );

  /** The audit writer is detached; wait for the rows. */
  async function resolveAudit(expected: number) {
    for (let attempt = 0; attempt < 100; attempt++) {
      const rows = await db
        .select()
        .from(schema.auditLogTable)
        .where(
          drizzle.and(
            drizzle.eq(schema.auditLogTable.action, "oauth.cimd.resolve"),
            drizzle.eq(schema.auditLogTable.target_id, CIMD_ID),
          ),
        );
      if (rows.length >= expected) return rows;
      await new Promise((r) => setTimeout(r, 20));
    }
    return [];
  }

  async function resetClient() {
    await db
      .delete(schema.oauthClientsTable)
      .where(drizzle.eq(schema.oauthClientsTable.client_id, CIMD_ID));
    cimd.resetCimdStateForTesting();
    cimd.setCimdClockForTesting(() => now);
    cimd.setCimdTransportForTesting({ lookup, baseFetch });
    documentRedirects = [HOSTED];
    documentStatus = 200;
    fetchCount = 0;
  }

  beforeAll(async () => {
    process.env.DATABASE_URL = TEST_DATABASE_URL;
    process.env.BETTER_AUTH_SECRET = `itest-throwaway-secret-${RUN}`;
    process.env.APP_URL = ORIGIN;
    suiteLock = new Client({ connectionString: TEST_DATABASE_URL });
    await suiteLock.connect();
    await suiteLock.query(
      `SELECT pg_advisory_lock(${INTEGRATION_DB_LOCK_KEY})`,
    );

    ({ db } = await import("../../db/index"));
    schema = await import("../../db/schema");
    drizzle = await import("drizzle-orm");
    cimd = await import("./cimd");
    cimdConfig = await import("./cimd-config");
    const { auth } = await import("../../auth");
    const utils = await import("./utils");
    const { auditContextMiddleware } = await import(
      "../../middleware/audit-context.middleware"
    );
    const { default: authorizationRouter } = await import("./authorization");
    const { default: tokenRouter } = await import("./token");

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

    const app = express();
    app.use(auditContextMiddleware);
    app.use(utils.securityHeaders);
    app.use(utils.jsonParsingMiddleware);
    app.use(utils.urlencodedParsingMiddleware);
    app.use(authorizationRouter);
    app.use(tokenRouter);
    await new Promise<void>((resolve) => {
      server = app.listen(0, "127.0.0.1", resolve);
    });
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

    allow(CIMD_ID);
    await resetClient();
  }, 60_000);

  afterAll(async () => {
    delete process.env[ALLOWLIST_ENV];
    cimd?.resetCimdStateForTesting();
    await new Promise((resolve) => server?.close(resolve));
    if (db) {
      await db
        .delete(schema.oauthClientsTable)
        .where(drizzle.eq(schema.oauthClientsTable.client_id, CIMD_ID));
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

  it("runs the whole flow: authorize, consent, code, exchange, refresh", async () => {
    allow(CIMD_ID);
    await resetClient();

    const authorized = await authorize();
    expect(authorized.status).toBe(302);
    expect(new URL(authorized.headers.get("location") as string).pathname).toBe(
      "/consent",
    );
    expect(fetchCount).toBe(1);
    expect(await clientRow()).toMatchObject({
      registration_source: "cimd",
      approval_status: "approved",
      approved_by: null,
      token_endpoint_auth_method: "none",
      client_secret: null,
      redirect_uris: [HOSTED],
      client_name: "Itest Connector",
    });

    const info = await consentInfo(areqOf(authorized));
    expect(info).toEqual({
      status: 200,
      body: {
        client_id: CIMD_ID,
        client_name: "Itest Connector",
        redirect_uri: HOSTED,
        scope: "mcp",
        client_id_host: `cimd-itest-${RUN}.example.com`,
      },
    });

    const decision = await decide(authorized);
    expect(decision.status).toBe(302);
    const callback = new URL(decision.headers.get("location") as string);
    expect(callback.origin + callback.pathname).toBe(HOSTED);
    expect(callback.searchParams.get("state")).toBe("st");
    const code = callback.searchParams.get("code") as string;

    const exchanged = await exchange(code);
    expect(exchanged.status).toBe(200);
    expect(exchanged.body.refresh_token).toBeTruthy();

    const refreshed = await token({
      grant_type: "refresh_token",
      refresh_token: exchanged.body.refresh_token as string,
    });
    expect(refreshed.status).toBe(200);

    // One document fetch for the whole flow, and one audit success row for it.
    expect(fetchCount).toBe(1);
    const audit = await resolveAudit(1);
    expect(audit).toHaveLength(1);
    expect(audit[0]).toMatchObject({
      outcome: "success",
      actor_type: "anonymous",
      detail: { result: "created", host: `cimd-itest-${RUN}.example.com` },
    });
    expect(JSON.stringify(audit[0].detail)).not.toContain("Itest Connector");
  });

  it("refuses everything when the entry is removed, burns nothing, and works again when it is back", async () => {
    allow(CIMD_ID);
    await resetClient();

    // A code outstanding, and a token pair issued from another code.
    const outstanding = await obtainCode();
    const issued = await exchange(await obtainCode());
    expect(issued.status).toBe(200);
    const before = await tokenRows();
    expect(before).toHaveLength(1);
    expect(await codeRows()).toHaveLength(1);

    allow("https://other-itest.example.org/client.json");

    const refusedAuthorize = await authorize();
    expect(refusedAuthorize.status).toBe(400);
    expect(await refusedAuthorize.json()).toEqual(
      cimdConfig.CIMD_CLIENT_REFUSED_ERROR,
    );

    const exchangeRefused = await exchange(outstanding);
    expect(exchangeRefused.status).toBe(400);
    expect(exchangeRefused.body.error).toBe("unauthorized_client");
    // The code was not consumed.
    expect(await codeRows()).toHaveLength(1);

    const refreshRefused = await token({
      grant_type: "refresh_token",
      refresh_token: issued.body.refresh_token as string,
    });
    expect(refreshRefused.status).toBe(400);
    expect(refreshRefused.body.error).toBe("unauthorized_client");
    // The token row is exactly as it was: not rotated, not deleted.
    expect(await tokenRows()).toEqual(before);

    // Consent info for a request signed while the entry existed.
    allow(CIMD_ID);
    const signed = await authorize();
    expect(signed.status).toBe(302);
    allow("https://other-itest.example.org/client.json");
    expect((await consentInfo(areqOf(signed))).status).toBe(403);
    const decisionRefused = await decide(signed);
    expect(decisionRefused.status).toBe(403);
    expect(await codeRows()).toHaveLength(1);

    allow(CIMD_ID);
    expect((await exchange(outstanding)).status).toBe(200);
    const refreshedAgain = await token({
      grant_type: "refresh_token",
      refresh_token: issued.body.refresh_token as string,
    });
    expect(refreshedAgain.status).toBe(200);
  });

  it("picks up a redirect URI the document added, once", async () => {
    allow(CIMD_ID);
    await resetClient();
    expect((await authorize()).status).toBe(302);
    expect(fetchCount).toBe(1);

    // Not listed yet: the row is fresh, so one refresh looks for it, and the
    // request is refused for its callback.
    now += 60_000;
    const missing = await authorize(SECOND_HOSTED);
    expect(missing.status).toBe(400);
    expect(await missing.json()).toMatchObject({
      error_description: "redirect_uri is not registered for this client",
    });
    expect(fetchCount).toBe(2);

    // The document now lists it; a minute later the refresh picks it up, and
    // the request after that is served from the stored row.
    documentRedirects = [HOSTED, SECOND_HOSTED];
    now += 61_000;
    expect((await authorize(SECOND_HOSTED)).status).toBe(302);
    expect(fetchCount).toBe(3);
    expect((await authorize(SECOND_HOSTED)).status).toBe(302);
    expect(fetchCount).toBe(3);
    expect((await clientRow())?.redirect_uris).toEqual([HOSTED, SECOND_HOSTED]);
  });

  it("serves a stale row through a transient failure, but not one past 24 hours", async () => {
    allow(CIMD_ID);
    await resetClient();
    expect((await authorize()).status).toBe(302);

    documentStatus = 503;
    now += 2 * HOUR;
    expect((await authorize()).status).toBe(302);
    expect(fetchCount).toBe(2);

    now = T0 + 25 * HOUR;
    cimd.resetCimdStateForTesting();
    cimd.setCimdClockForTesting(() => now);
    cimd.setCimdTransportForTesting({ lookup, baseFetch });
    const refused = await authorize();
    expect(refused.status).toBe(400);
    expect(await refused.json()).toEqual(cimdConfig.CIMD_CLIENT_REFUSED_ERROR);
    now = T0;
  });
});
