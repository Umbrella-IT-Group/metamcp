/**
 * The token endpoint's audit rows.
 *
 * `token.test.ts` pins the grep-friendly `[oauth] token issued` LINE. That
 * line lives in a 2000-entry ring buffer that dies on restart, which is
 * precisely the gap the 2026-08-13 review ran into: the credential chain the
 * attacker held — a 24h access token backed by a 365d refresh token — had no
 * durable, queryable record at all. These are the rows that replace it.
 *
 * The load-bearing assertion in every test here is a negative: the access
 * token appears ONLY as a sha256 + last-4 fingerprint. `audit_log` is
 * append-only and deliberately has no prune path, so a token written into it
 * could never be taken back out. The fingerprint is the same shape the MCP
 * bearer detector records on refused requests, which is what lets an operator
 * follow one credential from mint to misuse across the two.
 *
 * Same harness as `token.test.ts`: the router driven as express middleware
 * against fake req/res, repositories mocked so `db/index.ts` never loads.
 */

import { createHash, randomBytes } from "crypto";
import express from "express";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const loggerMock = {
  debug: vi.fn(),
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
};

vi.mock("@/utils/logger", () => ({ default: loggerMock }));

const oauthRepositoryMock = {
  getAuthCode: vi.fn(),
  deleteAuthCode: vi.fn(),
  getClient: vi.fn(),
  getByRefreshToken: vi.fn(),
  setAccessToken: vi.fn(),
  deleteAccessToken: vi.fn(),
  getAccessToken: vi.fn(),
};

const usersRepositoryMock = { isDisabled: vi.fn() };

vi.mock("../../db/repositories", () => ({
  oauthRepository: oauthRepositoryMock,
  usersRepository: usersRepositoryMock,
}));

const { default: tokenRouter } = await import("./token");
const { setAuditSinkForTesting } = await import("@/lib/audit/audit-emitter");

const CLIENT_ID = "mcp_client_test";
const USER_ID = "user-abc123";
const SCOPE = "mcp";
const CLIENT_IP = "203.0.113.9";
const REQUEST_ID = "req-token-under-test";
const REDIRECT_URI = "https://claude.ai/api/mcp/auth_callback";

type AuditRow = {
  action: string;
  outcome: string;
  actor_type: string;
  actor_id?: string | null;
  actor_ip?: string | null;
  request_id?: string | null;
  target_type?: string | null;
  target_id?: string | null;
  detail?: Record<string, unknown>;
};

let rows: AuditRow[];

const flush = () => new Promise((resolve) => setTimeout(resolve, 0));
const serialized = () => JSON.stringify(rows);

let ipCounter = 0;

interface FakeRes {
  statusCode: number;
  body: Record<string, string> | undefined;
  settled: Promise<void>;
  status(code: number): FakeRes;
  json(payload: Record<string, string>): FakeRes;
  send(): FakeRes;
}

function makeReq(body: Record<string, unknown>, path: string): express.Request {
  ipCounter += 1;
  return {
    method: "POST",
    url: path,
    originalUrl: path,
    baseUrl: "",
    body,
    // The fields the audit-context middleware stamps in production; set
    // directly because that middleware is mounted on the app, not this router.
    auditRequestId: REQUEST_ID,
    auditClientIp: CLIENT_IP,
    headers: { "user-agent": "Claude/1.0" },
    ip: `10.3.0.${ipCounter}`,
    socket: { remoteAddress: `10.3.0.${ipCounter}` },
  } as unknown as express.Request;
}

function makeRes(): FakeRes {
  let settle: () => void;
  const settled = new Promise<void>((resolve) => {
    settle = resolve;
  });

  const res: FakeRes = {
    statusCode: 200,
    body: undefined,
    settled,
    status(code) {
      res.statusCode = code;
      return res;
    },
    json(payload) {
      res.body = payload;
      settle();
      return res;
    },
    send() {
      settle();
      return res;
    },
  };

  return res;
}

async function post(
  body: Record<string, unknown>,
  path = "/oauth/token",
): Promise<FakeRes> {
  const req = makeReq(body, path);
  const res = makeRes();

  await new Promise<void>((resolve, reject) => {
    (tokenRouter as unknown as express.RequestHandler)(
      req,
      res as unknown as express.Response,
      (err?: unknown) => (err ? reject(err) : resolve()),
    );
    res.settled.then(resolve);
  });

  return res;
}

function grantBody(res: FakeRes): Record<string, string> {
  if (!res.body) throw new Error("token endpoint settled without a JSON body");
  return res.body;
}

const sha256 = (value: string) =>
  createHash("sha256").update(value).digest("hex");

beforeEach(() => {
  vi.clearAllMocks();
  rows = [];
  setAuditSinkForTesting(async (event) => {
    rows.push(event as AuditRow);
  });
  oauthRepositoryMock.setAccessToken.mockResolvedValue(undefined);
  oauthRepositoryMock.deleteAuthCode.mockResolvedValue(undefined);
  oauthRepositoryMock.deleteAccessToken.mockResolvedValue(undefined);
  usersRepositoryMock.isDisabled.mockResolvedValue(false);
});

afterEach(() => {
  setAuditSinkForTesting(undefined);
});

describe("oauth.token.issue — the authorization_code grant", () => {
  const codeVerifier = randomBytes(32).toString("base64url");
  const codeChallenge = createHash("sha256")
    .update(codeVerifier)
    .digest("base64url");
  const authCode = "mcp_code_abcdefghijklmnop";

  beforeEach(() => {
    oauthRepositoryMock.getAuthCode.mockResolvedValue({
      code: authCode,
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      scope: SCOPE,
      user_id: USER_ID,
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
      expires_at: new Date(Date.now() + 10 * 60 * 1000),
    });
    oauthRepositoryMock.getClient.mockResolvedValue({
      client_id: CLIENT_ID,
      client_name: "Claude",
      token_endpoint_auth_method: "none",
      client_secret: null,
    });
  });

  const exchange = () =>
    post({
      grant_type: "authorization_code",
      code: authCode,
      redirect_uri: REDIRECT_URI,
      client_id: CLIENT_ID,
      code_verifier: codeVerifier,
    });

  it("writes one row fingerprinting the token, never the token itself", async () => {
    const body = grantBody(await exchange());
    await flush();

    expect(body.access_token).toMatch(/^mcp_token_/);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      action: "oauth.token.issue",
      outcome: "success",
      actor_type: "user",
      actor_id: USER_ID,
      actor_ip: CLIENT_IP,
      request_id: REQUEST_ID,
      target_type: "oauth_client",
      target_id: CLIENT_ID,
    });
    expect(rows[0].detail).toMatchObject({
      grant_type: "authorization_code",
      client_name: "Claude",
      access_token_sha256: sha256(body.access_token),
      access_token_last4: body.access_token.slice(-4),
    });

    // Every credential this request handled, absent from the table.
    expect(serialized()).not.toContain(body.access_token);
    expect(serialized()).not.toContain(body.refresh_token);
    expect(serialized()).not.toContain(authCode);
    expect(serialized()).not.toContain(codeVerifier);
  });

  it("writes NOTHING when the grant is refused", async () => {
    // A disabled account's code stays redeemable for its full TTL, so the
    // refusal is the outcome here. Lane A's detectors own denial rows; this
    // emitter must not claim a token was issued.
    usersRepositoryMock.isDisabled.mockResolvedValue(true);

    const res = await exchange();
    await flush();

    expect(res.statusCode).toBe(400);
    expect(oauthRepositoryMock.setAccessToken).not.toHaveBeenCalled();
    expect(rows).toEqual([]);
  });
});

describe("oauth.token.refresh — rotation", () => {
  const refreshToken = "mcp_refresh_zyxwvutsrqponml";

  beforeEach(() => {
    oauthRepositoryMock.getByRefreshToken.mockResolvedValue({
      access_token: "mcp_token_previous_value",
      refresh_token: refreshToken,
      client_id: CLIENT_ID,
      user_id: USER_ID,
      scope: SCOPE,
      refresh_token_expires_at: new Date(Date.now() + 86400000),
      expires_at: new Date(Date.now() + 3600000),
    });
  });

  it("writes a refresh row with the NEW token's fingerprint only", async () => {
    const body = grantBody(
      await post({
        grant_type: "refresh_token",
        refresh_token: refreshToken,
        client_id: CLIENT_ID,
      }),
    );
    await flush();

    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      action: "oauth.token.refresh",
      outcome: "success",
      actor_id: USER_ID,
      target_id: CLIENT_ID,
    });
    expect(rows[0].detail).toMatchObject({
      grant_type: "refresh_token",
      access_token_sha256: sha256(body.access_token),
    });
    expect(serialized()).not.toContain(refreshToken);
    expect(serialized()).not.toContain(body.access_token);
    expect(serialized()).not.toContain(body.refresh_token);
  });
});

describe("oauth.token.revoke / introspect — only for tokens that exist", () => {
  const liveToken = "mcp_token_still_valid_value";

  it("records a revocation of a real access token", async () => {
    oauthRepositoryMock.getAccessToken.mockResolvedValue({
      access_token: liveToken,
      client_id: CLIENT_ID,
      user_id: USER_ID,
      scope: SCOPE,
      expires_at: new Date(Date.now() + 3600000),
      created_at: new Date(),
    });

    await post({ token: liveToken }, "/oauth/revoke");
    await flush();

    expect(oauthRepositoryMock.deleteAccessToken).toHaveBeenCalledWith(
      liveToken,
    );
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      action: "oauth.token.revoke",
      outcome: "success",
      actor_id: USER_ID,
      target_id: CLIENT_ID,
    });
    expect(rows[0].detail).toMatchObject({
      token_type: "access_token",
      token_sha256: sha256(liveToken),
    });
    expect(serialized()).not.toContain(liveToken);
  });

  it("writes NOTHING for an unknown token — the unauthenticated write amplifier", async () => {
    // RFC 7009 requires a 200 for garbage, so one row per invented string
    // would be an attacker-controlled INSERT into a table nobody can prune,
    // recording only a value the caller made up. The failure-only limiter now
    // on both endpoints bounds the RATE of those requests but not the row
    // count, so this decision is unchanged. See token.ts.
    oauthRepositoryMock.getAccessToken.mockResolvedValue(null);
    oauthRepositoryMock.getByRefreshToken.mockResolvedValue(null);

    const res = await post({ token: "not_a_real_token" }, "/oauth/revoke");
    await flush();

    expect(res.statusCode).toBe(200);
    expect(rows).toEqual([]);
  });

  it("writes NOTHING for an ACTIVE introspection — the replayable branch", async () => {
    // Introspection does not consume the token, so unlike revoke it is
    // unbounded: whoever holds one stolen credential can replay it forever,
    // each replay a permanent row on an endpoint with no rate limiter. And
    // `oauth.token.issue` already recorded that this credential exists under
    // the same fingerprint, so the row adds almost nothing. Documented
    // decision, see emitTokenLifecycle in token.ts.
    oauthRepositoryMock.getAccessToken.mockResolvedValue({
      access_token: liveToken,
      client_id: CLIENT_ID,
      user_id: USER_ID,
      scope: SCOPE,
      expires_at: new Date(Date.now() + 3600000),
      created_at: new Date(),
    });

    const res = await post({ token: liveToken }, "/oauth/introspect");
    await flush();

    expect(grantBody(res).active).toBe(true);
    expect(rows).toEqual([]);
  });

  it("DOES record an introspection refused because the account is disabled", async () => {
    // Bounded by the same argument in reverse: it needs a real token that
    // belongs to a locked-out account, i.e. a credential an administrator has
    // already acted against — and a relying party still asking about it is
    // exactly what an incident responder wants to see.
    oauthRepositoryMock.getAccessToken.mockResolvedValue({
      access_token: liveToken,
      client_id: CLIENT_ID,
      user_id: USER_ID,
      scope: SCOPE,
      expires_at: new Date(Date.now() + 3600000),
      created_at: new Date(),
    });
    usersRepositoryMock.isDisabled.mockResolvedValue(true);

    await post({ token: liveToken }, "/oauth/introspect");
    await flush();

    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      action: "oauth.token.introspect",
      outcome: "failure",
      actor_id: USER_ID,
    });
    expect(rows[0].detail).toMatchObject({
      active: false,
      reason: "disabled",
      token_sha256: sha256(liveToken),
    });
    expect(serialized()).not.toContain(liveToken);
  });
});

describe("a broken audit sink cannot break a grant", () => {
  it("a REJECTING sink still issues the token pair", async () => {
    setAuditSinkForTesting(async () => {
      throw new Error("connection pool exhausted");
    });
    const refreshToken = "mcp_refresh_zyxwvutsrqponml";
    oauthRepositoryMock.getByRefreshToken.mockResolvedValue({
      access_token: "mcp_token_previous_value",
      refresh_token: refreshToken,
      client_id: CLIENT_ID,
      user_id: USER_ID,
      scope: SCOPE,
      refresh_token_expires_at: new Date(Date.now() + 86400000),
      expires_at: new Date(Date.now() + 3600000),
    });

    const body = grantBody(
      await post({
        grant_type: "refresh_token",
        refresh_token: refreshToken,
        client_id: CLIENT_ID,
      }),
    );
    await flush();

    expect(body.access_token).toMatch(/^mcp_token_/);
    expect(oauthRepositoryMock.setAccessToken).toHaveBeenCalledTimes(1);
  });
});
