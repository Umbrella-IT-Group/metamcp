/**
 * The headless loopback login, end to end, against a REAL Postgres: register
 * a client with a loopback callback the way `claude mcp login --no-browser`
 * does, approve on the consent screen, copy the code from the gateway's page,
 * and redeem it from the waiting login. Also pins the code page's warning and
 * escaping, the five-minute loopback code lifetime and its boundary, and that
 * a non-loopback redirect keeps the ten-minute code and the bare 302.
 *
 * Real routers (registration, authorization, token), real better-auth, real
 * repositories.
 *
 * Opt-in via TEST_DATABASE_URL, pointed at a disposable, migrated database:
 *
 *   cd apps/backend
 *   DATABASE_URL=<url> npx drizzle-kit migrate
 *   TEST_DATABASE_URL=<url> npx vitest run \
 *     src/routers/oauth/loopback-consent.integration.test.ts
 */

import { createHash, randomBytes } from "node:crypto";
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
const EMAIL = `itest-loopback-${RUN}@example.test`;
const PASSWORD = `itest-throwaway-password-${RUN}`;
const ORIGIN = "http://127.0.0.1:1";
const LOOPBACK = "http://localhost:53682/callback";
const HOSTILE_NAME = `Claude Code"><img src=x onerror=alert(1)>`;
const WEB_CLIENT_ID = `mcp_client_itest_web_${RUN}`;
const WEB_REDIRECT = "https://claude.ai/api/mcp/auth_callback";

describeIfDb("headless loopback login (real Postgres)", () => {
  let base: string;
  let server: import("node:http").Server;
  let suiteLock: Client;
  let db: typeof import("../../db/index").db;
  let schema: typeof import("../../db/schema");
  let eq: typeof import("drizzle-orm").eq;
  let sessionCookie = "";
  let ipCounter = 0;
  const createdClients: string[] = [];

  const nextIp = () => `203.0.113.${(++ipCounter % 250) + 1}`;
  const cookiesOf = (res: Response) =>
    (res.headers.getSetCookie?.() ?? []).map((c) => c.split(";")[0]);

  async function register(clientName: string) {
    const res = await fetch(`${base}/oauth/register`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "cf-connecting-ip": nextIp(),
      },
      body: JSON.stringify({
        client_name: clientName,
        redirect_uris: [LOOPBACK],
      }),
    });
    expect(res.status).toBe(201);
    const { client_id } = (await res.json()) as { client_id: string };
    createdClients.push(client_id);
    return client_id;
  }

  /** authorize -> consent -> approve, as the signed-in browser does. */
  async function approveFor(clientId: string, redirectUri: string) {
    const verifier = randomBytes(32).toString("base64url");
    const challenge = createHash("sha256").update(verifier).digest("base64url");
    const authorize = await fetch(
      `${base}/oauth/authorize?response_type=code&client_id=${clientId}` +
        `&redirect_uri=${encodeURIComponent(redirectUri)}` +
        `&code_challenge=${challenge}&code_challenge_method=S256&state=st`,
      {
        redirect: "manual",
        headers: { cookie: sessionCookie, "cf-connecting-ip": nextIp() },
      },
    );
    expect(authorize.status).toBe(302);
    const areq = new URL(
      authorize.headers.get("location") as string,
    ).searchParams.get("areq") as string;
    const before = Date.now();
    const decision = await fetch(`${base}/oauth/authorize/decision`, {
      method: "POST",
      redirect: "manual",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        cookie: [sessionCookie, ...cookiesOf(authorize)].join("; "),
        "cf-connecting-ip": nextIp(),
      },
      body: new URLSearchParams({ areq, decision: "approve" }).toString(),
    });
    const after = Date.now();
    return { decision, verifier, before, after };
  }

  async function redeem(
    clientId: string,
    redirectUri: string,
    code: string,
    verifier: string,
  ) {
    const res = await fetch(`${base}/oauth/token`, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        "cf-connecting-ip": nextIp(),
      },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        client_id: clientId,
        redirect_uri: redirectUri,
        code_verifier: verifier,
      }).toString(),
    });
    return {
      status: res.status,
      body: (await res.json()) as Record<string, string | undefined>,
    };
  }

  async function storedCodeExpiry(clientId: string): Promise<number> {
    const rows = await db
      .select({ expires_at: schema.oauthAuthorizationCodesTable.expires_at })
      .from(schema.oauthAuthorizationCodesTable)
      .where(eq(schema.oauthAuthorizationCodesTable.client_id, clientId));
    expect(rows).toHaveLength(1);
    return (rows[0]?.expires_at as Date).getTime();
  }

  beforeAll(async () => {
    process.env.DATABASE_URL = TEST_DATABASE_URL;
    process.env.BETTER_AUTH_SECRET = `itest-throwaway-secret-${RUN}`;
    process.env.APP_URL = ORIGIN;
    delete process.env.NEXT_PUBLIC_BRANDING_ORG_NAME;
    suiteLock = new Client({ connectionString: TEST_DATABASE_URL });
    await suiteLock.connect();
    await suiteLock.query(
      `SELECT pg_advisory_lock(${INTEGRATION_DB_LOCK_KEY})`,
    );

    ({ db } = await import("../../db/index"));
    schema = await import("../../db/schema");
    ({ eq } = await import("drizzle-orm"));
    const { auth } = await import("../../auth");
    const { oauthRepository } = await import("../../db/repositories");
    const utils = await import("./utils");
    const { default: registrationRouter } = await import("./registration");
    const { default: authorizationRouter } = await import("./authorization");
    const { default: tokenRouter } = await import("./token");

    await db
      .delete(schema.usersTable)
      .where(eq(schema.usersTable.email, EMAIL));
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

    await oauthRepository.upsertClient({
      client_id: WEB_CLIENT_ID,
      client_name: "itest web client",
      redirect_uris: [WEB_REDIRECT],
      token_endpoint_auth_method: "none",
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
    } as Parameters<typeof oauthRepository.upsertClient>[0]);
    createdClients.push(WEB_CLIENT_ID);

    const app = express();
    // Same middleware order as routers/oauth/index.ts.
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
  }, 60_000);

  afterAll(async () => {
    await new Promise((resolve) => server?.close(resolve));
    if (db) {
      await db
        .delete(schema.usersTable)
        .where(eq(schema.usersTable.email, EMAIL));
      for (const id of createdClients) {
        await db
          .delete(schema.oauthClientsTable)
          .where(eq(schema.oauthClientsTable.client_id, id));
      }
      const { pool } = await import("../../db/index");
      await pool.end();
    }
    await suiteLock?.query(
      `SELECT pg_advisory_unlock(${INTEGRATION_DB_LOCK_KEY})`,
    );
    await suiteLock?.end();
  });

  it("shows the warning above the code, then the copied code redeems from the waiting login", async () => {
    const clientId = await register("Claude Code");
    const { decision, verifier, before, after } = await approveFor(
      clientId,
      LOOPBACK,
    );

    expect(decision.status).toBe(200);
    expect(decision.headers.get("cache-control")).toBe("no-store");
    expect(decision.headers.get("referrer-policy")).toBe("no-referrer");
    const csp = decision.headers.get("content-security-policy") ?? "";
    expect(csp).toContain("default-src 'none'");
    expect(csp).toMatch(/script-src 'nonce-[^']+'/);

    const html = await decision.text();
    const code = /<code>(mcp_code_[A-Za-z0-9_-]+)<\/code>/.exec(html)?.[1];
    expect(code).toBeTruthy();
    const warningAt = html.indexOf('id="code-warning"');
    expect(warningAt).toBeGreaterThan(-1);
    expect(html.indexOf(`<code>${code}</code>`)).toBeGreaterThan(warningAt);
    expect(html).toContain(
      'The application name <span class="name">Claude Code</span> and the callback address below were supplied by whoever started this request.',
    );
    expect(html).toContain(
      "Umbrella IT never asks anyone to send or paste this code for them.",
    );

    // Five minutes from approval for a loopback code.
    const expiresAt = await storedCodeExpiry(clientId);
    expect(expiresAt).toBeGreaterThanOrEqual(before + 5 * 60 * 1000 - 1000);
    expect(expiresAt).toBeLessThanOrEqual(after + 5 * 60 * 1000 + 1000);

    // The headless path: the code typed into the login that is waiting for it.
    const redeemed = await redeem(clientId, LOOPBACK, code as string, verifier);
    expect(redeemed.status).toBe(200);
    expect(redeemed.body.access_token).toMatch(/^mcp_token_/);
    expect(redeemed.body.refresh_token).toMatch(/^mcp_refresh_/);
  });

  it("escapes a hostile registered name on the code page", async () => {
    const clientId = await register(HOSTILE_NAME);
    const { decision } = await approveFor(clientId, LOOPBACK);

    const html = await decision.text();
    expect(decision.status).toBe(200);
    expect(html).not.toContain("<img src=x");
    expect(html).toContain(
      "Claude Code&quot;&gt;&lt;img src=x onerror=alert(1)&gt;",
    );
  });

  it("refuses a loopback code once its five minutes have passed, and honours it just before", async () => {
    const clientId = await register("Claude Code");

    const late = await approveFor(clientId, LOOPBACK);
    const lateCode = /<code>(mcp_code_[A-Za-z0-9_-]+)<\/code>/.exec(
      await late.decision.text(),
    )?.[1] as string;
    await db
      .update(schema.oauthAuthorizationCodesTable)
      .set({ expires_at: new Date(Date.now() - 1000) })
      .where(eq(schema.oauthAuthorizationCodesTable.client_id, clientId));
    const expired = await redeem(clientId, LOOPBACK, lateCode, late.verifier);
    expect(expired.status).toBe(400);
    expect(expired.body).toEqual({
      error: "invalid_grant",
      error_description: "Authorization code has expired",
    });

    const onTime = await approveFor(clientId, LOOPBACK);
    const onTimeCode = /<code>(mcp_code_[A-Za-z0-9_-]+)<\/code>/.exec(
      await onTime.decision.text(),
    )?.[1] as string;
    await db
      .update(schema.oauthAuthorizationCodesTable)
      .set({ expires_at: new Date(Date.now() + 2000) })
      .where(eq(schema.oauthAuthorizationCodesTable.client_id, clientId));
    expect(
      (await redeem(clientId, LOOPBACK, onTimeCode, onTime.verifier)).status,
    ).toBe(200);
  });

  it("keeps the ten-minute code and the bare 302 for a non-loopback redirect", async () => {
    const { decision, verifier, before, after } = await approveFor(
      WEB_CLIENT_ID,
      WEB_REDIRECT,
    );

    expect(decision.status).toBe(302);
    const location = new URL(decision.headers.get("location") as string);
    expect(`${location.origin}${location.pathname}`).toBe(WEB_REDIRECT);
    const code = location.searchParams.get("code") as string;
    expect(code).toMatch(/^mcp_code_/);

    const expiresAt = await storedCodeExpiry(WEB_CLIENT_ID);
    expect(expiresAt).toBeGreaterThanOrEqual(before + 10 * 60 * 1000 - 1000);
    expect(expiresAt).toBeLessThanOrEqual(after + 10 * 60 * 1000 + 1000);
    expect(
      (await redeem(WEB_CLIENT_ID, WEB_REDIRECT, code, verifier)).status,
    ).toBe(200);
  });
});
