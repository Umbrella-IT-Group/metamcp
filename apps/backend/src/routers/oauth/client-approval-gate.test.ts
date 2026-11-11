/**
 * The client-approval gate (migration 0042) on the paths a unit test reaches
 * more directly than the Postgres suite (./dcr-approval.integration.test.ts):
 *
 *  - only the exact status "approved" passes: an unknown or missing status is
 *    refused at authorize and at both token grants, before any code is
 *    consumed or token claimed;
 *  - a caller who is not signed in sees the waiting page rather than the
 *    sign-in redirect, and the audit row is anonymous;
 *  - OAUTH_DCR_MODE=off changes nothing for an approved client: authorize and
 *    refresh work as before.
 *
 * Real routers over a real socket, repositories mocked.
 */

import { createHash, randomBytes } from "node:crypto";
import type { Server } from "node:http";

import express from "express";
import {
  afterAll,
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";

import { armUserLockFakes } from "./user-lock-test-fakes";

vi.mock("@/utils/logger", () => ({
  default: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

const oauthRepositoryMock = {
  getClient: vi.fn(),
  getAuthCode: vi.fn(),
  deleteAuthCode: vi.fn(),
  consumeAuthCode: vi.fn(),
  setAuthCode: vi.fn(),
  setAccessToken: vi.fn(),
  getByRefreshToken: vi.fn(),
  getRotatedRefreshToken: vi.fn(),
  claimRefreshToken: vi.fn(),
  recordRotatedRefreshToken: vi.fn(),
  deleteAccessTokenByHash: vi.fn(),
  revokeFamily: vi.fn(),
  withUserLock: vi.fn(),
};

vi.mock("../../db/repositories", () => ({
  oauthRepository: oauthRepositoryMock,
  usersRepository: { isDisabled: vi.fn().mockResolvedValue(false) },
}));

const authHandler = vi.fn();
vi.mock("../../auth", () => ({
  auth: { api: { getSession: vi.fn() }, handler: authHandler },
}));

process.env.APP_URL = "https://gateway.example.test";
process.env.BETTER_AUTH_SECRET = "test-secret-for-client-approval-gate";

const { setAuditSinkForTesting } = await import("@/lib/audit/audit-emitter");
const utils = await import("./utils");
const dcrMode = await import("./dcr-mode");
const { default: authorizationRouter } = await import("./authorization");
const { default: tokenRouter } = await import("./token");

const CLIENT_ID = "mcp_client_gate";
const LOOPBACK = "http://localhost:53682/callback";
const USER_ID = "user-gate";

type AuditRow = Record<string, unknown>;
let rows: AuditRow[] = [];
let server: Server;
let baseUrl: string;

beforeAll(async () => {
  const app = express();
  app.use(utils.jsonParsingMiddleware);
  app.use(utils.urlencodedParsingMiddleware);
  app.use(authorizationRouter);
  app.use(tokenRouter);
  server = await new Promise<Server>((resolve) => {
    const s = app.listen(0, "127.0.0.1", () => resolve(s));
  });
  const address = server.address();
  const port = typeof address === "object" && address ? address.port : 0;
  baseUrl = `http://127.0.0.1:${port}`;
});

afterAll(async () => {
  await new Promise((resolve) => server.close(resolve));
});

const signedOut = async () => new Response("null", { status: 200 });
const signedIn = async () =>
  new Response(
    JSON.stringify({ user: { id: USER_ID }, session: { id: "s1" } }),
    { status: 200, headers: { "content-type": "application/json" } },
  );

function client(status: unknown) {
  return {
    client_id: CLIENT_ID,
    client_name: "Claude Code",
    redirect_uris: [LOOPBACK],
    token_endpoint_auth_method: "none",
    client_secret: null,
    client_secret_salt: null,
    registration_source: "dcr",
    approval_status: status,
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  utils.resetConsentDecisionRateLimitForTests();
  rows = [];
  setAuditSinkForTesting(async (event) => {
    rows.push(event as unknown as AuditRow);
  });
  authHandler.mockImplementation(signedOut);
  oauthRepositoryMock.setAccessToken.mockResolvedValue(undefined);
  oauthRepositoryMock.recordRotatedRefreshToken.mockResolvedValue(undefined);
  oauthRepositoryMock.getRotatedRefreshToken.mockResolvedValue(null);
  armUserLockFakes(oauthRepositoryMock);
});

afterEach(() => {
  setAuditSinkForTesting(null);
  delete process.env[dcrMode.OAUTH_DCR_MODE_ENV];
  dcrMode.resetOAuthDcrModeForTests();
});

let ipCounter = 0;
const nextIp = () => `192.0.2.${(++ipCounter % 250) + 1}`;
const flush = () => new Promise((resolve) => setTimeout(resolve, 10));

async function authorize() {
  const challenge = createHash("sha256")
    .update(randomBytes(32).toString("base64url"))
    .digest("base64url");
  const res = await fetch(
    `${baseUrl}/oauth/authorize?response_type=code&client_id=${CLIENT_ID}` +
      `&redirect_uri=${encodeURIComponent(LOOPBACK)}` +
      `&code_challenge=${challenge}&code_challenge_method=S256&state=st`,
    {
      redirect: "manual",
      headers: { cookie: "session=1", "cf-connecting-ip": nextIp() },
    },
  );
  await flush();
  return {
    status: res.status,
    location: res.headers.get("location"),
    setCookie: res.headers.getSetCookie?.() ?? [],
    text: await res.text(),
  };
}

async function postToken(params: Record<string, string>) {
  const res = await fetch(`${baseUrl}/oauth/token`, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      "cf-connecting-ip": nextIp(),
    },
    body: new URLSearchParams(params).toString(),
  });
  return {
    status: res.status,
    body: (await res.json()) as Record<string, unknown>,
  };
}

describe("only the exact status 'approved' passes", () => {
  it.each([["weird"], ["Approved"], [null], [undefined]])(
    "refuses status %j at authorize with the rejected page",
    async (status) => {
      oauthRepositoryMock.getClient.mockResolvedValue(client(status));
      authHandler.mockImplementation(signedIn);
      const res = await authorize();
      expect(res.status).toBe(403);
      expect(res.location).toBeNull();
      expect(res.setCookie).toEqual([]);
      expect(res.text).toContain("Application rejected");
      expect(oauthRepositoryMock.setAuthCode).not.toHaveBeenCalled();
    },
  );

  it.each([["weird"], [null], [undefined]])(
    "refuses status %j at the code grant before consuming the code",
    async (status) => {
      const verifier = randomBytes(32).toString("base64url");
      oauthRepositoryMock.getClient.mockResolvedValue(client(status));
      oauthRepositoryMock.getAuthCode.mockResolvedValue({
        code: "hash",
        client_id: CLIENT_ID,
        redirect_uri: LOOPBACK,
        scope: "mcp",
        user_id: USER_ID,
        code_challenge: createHash("sha256")
          .update(verifier)
          .digest("base64url"),
        code_challenge_method: "S256",
        expires_at: new Date(Date.now() + 60_000),
        created_at: new Date(),
      });
      const res = await postToken({
        grant_type: "authorization_code",
        code: "mcp_code_x",
        client_id: CLIENT_ID,
        redirect_uri: LOOPBACK,
        code_verifier: verifier,
      });
      expect(res.status).toBe(400);
      expect(res.body.error).toBe("unauthorized_client");
      expect(oauthRepositoryMock.withUserLock).not.toHaveBeenCalled();
      expect(oauthRepositoryMock.consumeAuthCode).not.toHaveBeenCalled();
      expect(oauthRepositoryMock.setAccessToken).not.toHaveBeenCalled();
    },
  );

  it.each([["weird"], [null]])(
    "refuses status %j at the refresh grant before claiming the token",
    async (status) => {
      oauthRepositoryMock.getClient.mockResolvedValue(client(status));
      oauthRepositoryMock.getByRefreshToken.mockResolvedValue({
        access_token: "access-hash",
        access_token_last4: "abcd",
        client_id: CLIENT_ID,
        user_id: USER_ID,
        scope: "mcp",
        expires_at: new Date(Date.now() + 60_000),
        refresh_token: "refresh-hash",
        refresh_token_expires_at: new Date(Date.now() + 86_400_000),
        family_id: "ffffffff-0000-0000-0000-000000000001",
        created_at: new Date(),
      });
      const res = await postToken({
        grant_type: "refresh_token",
        refresh_token: "mcp_refresh_x",
      });
      expect(res.status).toBe(400);
      expect(res.body.error).toBe("unauthorized_client");
      expect(oauthRepositoryMock.claimRefreshToken).not.toHaveBeenCalled();
      expect(
        oauthRepositoryMock.recordRotatedRefreshToken,
      ).not.toHaveBeenCalled();
      expect(
        oauthRepositoryMock.deleteAccessTokenByHash,
      ).not.toHaveBeenCalled();
      expect(oauthRepositoryMock.setAccessToken).not.toHaveBeenCalled();
    },
  );
});

describe("a caller who is not signed in", () => {
  it("sees the waiting page, not the sign-in redirect, and is audited as anonymous", async () => {
    oauthRepositoryMock.getClient.mockResolvedValue(client("pending"));
    const res = await authorize();
    expect(res.status).toBe(403);
    expect(res.location).toBeNull();
    expect(res.text).toContain("Waiting for administrator approval");
    const blocked = rows.filter(
      (r) => r.action === "oauth.authorize.client_not_approved",
    );
    expect(blocked).toHaveLength(1);
    expect(blocked[0]).toMatchObject({
      actor_type: "anonymous",
      actor_id: null,
      target_id: CLIENT_ID,
      outcome: "denied",
      http_status: 403,
      detail: { approval_status: "pending", redirect_uri: LOOPBACK },
    });
  });

  it("is still sent to sign in for an approved client (regression)", async () => {
    oauthRepositoryMock.getClient.mockResolvedValue(client("approved"));
    const res = await authorize();
    expect(res.status).toBe(302);
    expect(res.location).toContain("/login");
  });
});

describe("OAUTH_DCR_MODE=off leaves approved clients working", () => {
  beforeEach(() => {
    process.env[dcrMode.OAUTH_DCR_MODE_ENV] = "off";
    dcrMode.resetOAuthDcrModeForTests();
  });

  it("authorize still reaches consent for a signed-in user", async () => {
    oauthRepositoryMock.getClient.mockResolvedValue(client("approved"));
    authHandler.mockImplementation(signedIn);
    const res = await authorize();
    expect(res.status).toBe(302);
    expect(res.location).toContain("/consent?areq=");
  });

  it("refresh still rotates", async () => {
    oauthRepositoryMock.getClient.mockResolvedValue(client("approved"));
    oauthRepositoryMock.getByRefreshToken.mockResolvedValue({
      access_token: "access-hash",
      access_token_last4: "abcd",
      client_id: CLIENT_ID,
      user_id: USER_ID,
      scope: "mcp",
      expires_at: new Date(Date.now() + 60_000),
      refresh_token: "refresh-hash",
      refresh_token_expires_at: new Date(Date.now() + 86_400_000),
      family_id: "ffffffff-0000-0000-0000-000000000002",
      created_at: new Date(),
    });
    const res = await postToken({
      grant_type: "refresh_token",
      refresh_token: "mcp_refresh_y",
    });
    expect(res.status).toBe(200);
    expect(oauthRepositoryMock.claimRefreshToken).toHaveBeenCalledTimes(1);
    expect(oauthRepositoryMock.setAccessToken).toHaveBeenCalledTimes(1);
  });
});
