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
 *
 * `GET /oauth/userinfo` is exercised here too, even though it lives in its own
 * router and has its own suite. The property under test is the one this file
 * exists for — a rejection that DESTROYS a credential must leave a row, and
 * that row must hold a fingerprint rather than the credential — and the audit
 * sink seam plus the `serialized()` negative that enforce it live here.
 * Duplicating the seam into `userinfo.test.ts` would fork the discipline
 * across two files instead of pinning it in one.
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

// The RFC 7662 credential gate on /oauth/introspect lives in its own module
// and has its own tests (./introspection-auth.test.ts). Stubbed to "authorized"
// here so the branches this file was written for stay reachable — without it
// every introspect assertion below would collapse into the same 401.
vi.mock("./introspection-auth", () => ({
  requireIntrospectionCredential: vi.fn(async () => ({
    ok: true,
    userId: null,
  })),
}));

const { default: tokenRouter } = await import("./token");
const { default: userinfoRouter } = await import("./userinfo");
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

async function getUserinfo(token: string): Promise<FakeRes> {
  ipCounter += 1;
  const req = {
    method: "GET",
    url: "/oauth/userinfo",
    originalUrl: "/oauth/userinfo",
    baseUrl: "",
    // Same hand-stamped attribution as makeReq: the audit-context middleware
    // is mounted on the app, not on this router.
    auditRequestId: REQUEST_ID,
    auditClientIp: CLIENT_IP,
    headers: { authorization: `Bearer ${token}`, "user-agent": "Claude/1.0" },
    ip: `10.3.0.${ipCounter}`,
    socket: { remoteAddress: `10.3.0.${ipCounter}` },
  } as unknown as express.Request;
  const res = makeRes();

  await new Promise<void>((resolve, reject) => {
    (userinfoRouter as unknown as express.RequestHandler)(
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

  it("claims NO issuance when a disabled account's code is refused", async () => {
    // A disabled account's code stays redeemable for its full TTL, so the
    // refusal is the outcome here. Lane A's detectors own denial rows; this
    // emitter must not claim a token was issued.
    //
    // Scoped to THIS refusal on purpose. It is not the general claim "a
    // refused grant is never audited" — the expired-code and expired-refresh
    // refusals below do emit, because they destroy the row they read and are
    // therefore self-limiting. This one leaves the code intact so that Enable
    // restores a working flow, which is exactly why it stays silent: an
    // invented code could otherwise be replayed into the table forever.
    usersRepositoryMock.isDisabled.mockResolvedValue(true);

    const res = await exchange();
    await flush();

    expect(res.statusCode).toBe(400);
    expect(oauthRepositoryMock.setAccessToken).not.toHaveBeenCalled();
    expect(rows).toEqual([]);
  });

  it("records an EXPIRED code as a failed issue, before consuming it", async () => {
    // Same defect class as the expired-refresh branch: the handler deletes a
    // real, currently-stored credential and used to answer 400 with nothing
    // written anywhere. Bounded for the same reason revoke is — it needs a
    // real code and it consumes it.
    const issuedAt = new Date(Date.now() - 11 * 60 * 1000);
    const expiredAt = new Date(Date.now() - 60 * 1000);
    oauthRepositoryMock.getAuthCode.mockResolvedValue({
      code: authCode,
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      scope: SCOPE,
      user_id: USER_ID,
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
      created_at: issuedAt,
      expires_at: expiredAt,
    });

    const res = await exchange();
    await flush();

    expect(res.statusCode).toBe(400);
    // The code is still consumed — auditing must not change the outcome.
    expect(oauthRepositoryMock.deleteAuthCode).toHaveBeenCalledWith(authCode);
    expect(oauthRepositoryMock.setAccessToken).not.toHaveBeenCalled();

    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      action: "oauth.token.issue",
      outcome: "failure",
      actor_type: "user",
      actor_id: USER_ID,
      actor_ip: CLIENT_IP,
      request_id: REQUEST_ID,
      target_type: "oauth_client",
      target_id: CLIENT_ID,
      http_status: 400,
    });
    expect(rows[0].detail).toMatchObject({
      reason: "authorization_code_expired",
      token_type: "authorization_code",
      token_sha256: sha256(authCode),
      created_at: issuedAt.toISOString(),
      expires_at: expiredAt.toISOString(),
    });
    // The code is a credential too — fingerprint only, same as every token.
    expect(serialized()).not.toContain(authCode);
    expect(serialized()).not.toContain(codeVerifier);
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

describe("oauth.token.refresh — an EXPIRED refresh token is destroyed, loudly", () => {
  // The branch this file was extended for. It reads a real token row, DELETES
  // it, and answered 400 with nothing written anywhere — not even a logger
  // line — so the credential and the record of when its chain was minted
  // disappeared in the same request.
  const refreshToken = "mcp_refresh_long_since_expired";
  const priorAccessToken = "mcp_token_previous_value";
  const issuedAt = new Date(Date.now() - 400 * 86400000);
  const accessExpiredAt = new Date(Date.now() - 399 * 86400000);
  const refreshExpiredAt = new Date(Date.now() - 86400000);

  beforeEach(() => {
    oauthRepositoryMock.getByRefreshToken.mockResolvedValue({
      access_token: priorAccessToken,
      refresh_token: refreshToken,
      client_id: CLIENT_ID,
      user_id: USER_ID,
      scope: SCOPE,
      created_at: issuedAt,
      expires_at: accessExpiredAt,
      refresh_token_expires_at: refreshExpiredAt,
    });
  });

  const redeem = () =>
    post({
      grant_type: "refresh_token",
      refresh_token: refreshToken,
      client_id: CLIENT_ID,
    });

  it("writes exactly one failure row and still destroys the row", async () => {
    const res = await redeem();
    await flush();

    expect(res.statusCode).toBe(400);
    // The delete is the behaviour the audit row exists to describe; it must
    // still happen, and it must still target the row's ACCESS token, which is
    // the primary key.
    expect(oauthRepositoryMock.deleteAccessToken).toHaveBeenCalledWith(
      priorAccessToken,
    );
    expect(oauthRepositoryMock.setAccessToken).not.toHaveBeenCalled();

    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      action: "oauth.token.refresh",
      outcome: "failure",
      actor_type: "user",
      actor_id: USER_ID,
      actor_ip: CLIENT_IP,
      request_id: REQUEST_ID,
      target_type: "oauth_client",
      target_id: CLIENT_ID,
      http_status: 400,
    });
    expect(rows[0].detail).toMatchObject({
      reason: "refresh_token_expired",
      token_type: "refresh_token",
    });
  });

  it("dates the destroyed chain and joins it to the row that minted it", async () => {
    // The forensic content. Once the row is deleted nothing else records when
    // the chain began, and `access_token_sha256` is the join key back to the
    // `oauth.token.issue` row under the key that emitter already writes.
    await redeem();
    await flush();

    expect(rows[0].detail).toMatchObject({
      token_sha256: sha256(refreshToken),
      token_last4: refreshToken.slice(-4),
      access_token_sha256: sha256(priorAccessToken),
      access_token_last4: priorAccessToken.slice(-4),
      created_at: issuedAt.toISOString(),
      expires_at: accessExpiredAt.toISOString(),
      refresh_token_expires_at: refreshExpiredAt.toISOString(),
    });
  });

  it("records both credentials as fingerprints and neither as itself", async () => {
    await redeem();
    await flush();

    expect(serialized()).not.toContain(refreshToken);
    expect(serialized()).not.toContain(priorAccessToken);
  });

  it("still refuses and still deletes when the audit sink REJECTS", async () => {
    // Mirror of "a broken audit sink cannot break a grant" for the rejection
    // path. An audit write that fails must degrade the record, never the
    // request — and it must not leave a destroyed-credential branch half
    // executed.
    setAuditSinkForTesting(async () => {
      throw new Error("connection pool exhausted");
    });

    const res = await redeem();
    await flush();

    expect(res.statusCode).toBe(400);
    expect(res.body).toMatchObject({ error: "invalid_grant" });
    expect(oauthRepositoryMock.deleteAccessToken).toHaveBeenCalledWith(
      priorAccessToken,
    );
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

  it("DOES record a revocation refused because the client does not match", async () => {
    // The highest-signal event either endpoint produces: someone presenting a
    // REAL, currently-issued token while naming a client it was not issued to.
    // Bounded like the other two emitting branches — it cannot be reached with
    // an invented string — so it is not the replay amplifier the unknown-token
    // branch would be.
    oauthRepositoryMock.getAccessToken.mockResolvedValue({
      access_token: liveToken,
      client_id: CLIENT_ID,
      user_id: USER_ID,
      scope: SCOPE,
      expires_at: new Date(Date.now() + 3600000),
      created_at: new Date(),
    });

    const res = await post(
      { token: liveToken, client_id: "mcp_client_somebody_else" },
      "/oauth/revoke",
    );
    await flush();

    expect(res.statusCode).toBe(400);
    // The token must SURVIVE a refused revocation.
    expect(oauthRepositoryMock.deleteAccessToken).not.toHaveBeenCalled();
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      action: "oauth.token.revoke",
      outcome: "failure",
      actor_id: USER_ID,
      target_id: CLIENT_ID,
      http_status: 400,
    });
    expect(rows[0].detail).toMatchObject({
      reason: "client_mismatch",
      token_type: "access_token",
      presented_client_id: "mcp_client_somebody_else",
      token_sha256: sha256(liveToken),
    });
    // Still a fingerprint only — the refusal path is not an exemption.
    expect(serialized()).not.toContain(liveToken);
  });

  it("clamps the presented client_id, which is unauthenticated request text", async () => {
    // `audit_log` has no prune path, so a row's SIZE is as permanent as its
    // contents and any un-clamped request value is a write amplifier. Same
    // rule the DCR redirect_uris follow.
    oauthRepositoryMock.getAccessToken.mockResolvedValue({
      access_token: liveToken,
      client_id: CLIENT_ID,
      user_id: USER_ID,
      scope: SCOPE,
      expires_at: new Date(Date.now() + 3600000),
      created_at: new Date(),
    });

    await post(
      { token: liveToken, client_id: "z".repeat(5000) },
      "/oauth/revoke",
    );
    await flush();

    expect(rows).toHaveLength(1);
    expect(
      (rows[0].detail as { presented_client_id: string }).presented_client_id
        .length,
    ).toBe(100);
    expect(serialized().length).toBeLessThan(8000);
  });

  it("records the mismatch on the REFRESH token branch too", async () => {
    oauthRepositoryMock.getAccessToken.mockResolvedValue(null);
    oauthRepositoryMock.getByRefreshToken.mockResolvedValue({
      access_token: liveToken,
      refresh_token: "mcp_refresh_value",
      client_id: CLIENT_ID,
      user_id: USER_ID,
      scope: SCOPE,
      expires_at: new Date(Date.now() + 3600000),
      created_at: new Date(),
    });

    await post(
      { token: "mcp_refresh_value", client_id: "mcp_client_somebody_else" },
      "/oauth/revoke",
    );
    await flush();

    expect(oauthRepositoryMock.deleteAccessToken).not.toHaveBeenCalled();
    expect(rows).toHaveLength(1);
    expect(rows[0].detail).toMatchObject({
      reason: "client_mismatch",
      token_type: "refresh_token",
    });
  });

  it("writes NOTHING when client_id is omitted — the non-blocking path", async () => {
    // Omitting client_id skips the comparison entirely, which is deliberate
    // for secretless public clients. It is an ordinary successful revocation
    // and must not produce a mismatch row.
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

    expect(rows).toHaveLength(1);
    expect(rows[0].outcome).toBe("success");
  });

  it("DOES record an introspection refused because the account is disabled", async () => {
    // Bounded by the same argument in reverse: it needs a real token that
    // belongs to a locked-out account, i.e. a credential an administrator has
    // already acted against — and a relying party still asking about it is
    // exactly what a responder wants to see.
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

  it("DOES record an introspection that finds an EXPIRED token, which it deletes", async () => {
    // The introspect twin of the expired-refresh branch: the handler destroys
    // the row it just read. Bounded by that destruction, so it emits — unlike
    // the ACTIVE branch above, which consumes nothing and is replayable.
    const expiredToken = "mcp_token_aged_out_value";
    const issuedAt = new Date(Date.now() - 2 * 86400000);
    const accessExpiredAt = new Date(Date.now() - 86400000);
    const refreshExpiresAt = new Date(Date.now() + 300 * 86400000);
    oauthRepositoryMock.getAccessToken.mockResolvedValue({
      access_token: expiredToken,
      refresh_token: "mcp_refresh_still_alive",
      client_id: CLIENT_ID,
      user_id: USER_ID,
      scope: SCOPE,
      created_at: issuedAt,
      expires_at: accessExpiredAt,
      refresh_token_expires_at: refreshExpiresAt,
    });

    const res = await post({ token: expiredToken }, "/oauth/introspect");
    await flush();

    expect(grantBody(res).active).toBe(false);
    expect(oauthRepositoryMock.deleteAccessToken).toHaveBeenCalledWith(
      expiredToken,
    );
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      action: "oauth.token.introspect",
      outcome: "failure",
      actor_id: USER_ID,
      target_id: CLIENT_ID,
      // RFC 7662 answers an inactive token with 200, so the row must say 200.
      http_status: 200,
    });
    expect(rows[0].detail).toMatchObject({
      active: false,
      reason: "access_token_expired",
      token_type: "access_token",
      token_sha256: sha256(expiredToken),
      created_at: issuedAt.toISOString(),
      expires_at: accessExpiredAt.toISOString(),
      // The delete takes the whole row, so a refresh token that had NOT
      // expired dies with it. The record has to show that.
      refresh_token_expires_at: refreshExpiresAt.toISOString(),
    });
    expect(serialized()).not.toContain(expiredToken);
    expect(serialized()).not.toContain("mcp_refresh_still_alive");
  });

  it("still answers and still deletes on introspect when the sink REJECTS", async () => {
    setAuditSinkForTesting(async () => {
      throw new Error("connection pool exhausted");
    });
    const expiredToken = "mcp_token_aged_out_value";
    oauthRepositoryMock.getAccessToken.mockResolvedValue({
      access_token: expiredToken,
      client_id: CLIENT_ID,
      user_id: USER_ID,
      scope: SCOPE,
      created_at: new Date(Date.now() - 2 * 86400000),
      expires_at: new Date(Date.now() - 86400000),
      refresh_token_expires_at: null,
    });

    const res = await post({ token: expiredToken }, "/oauth/introspect");
    await flush();

    expect(grantBody(res).active).toBe(false);
    expect(oauthRepositoryMock.deleteAccessToken).toHaveBeenCalledWith(
      expiredToken,
    );
  });
});

describe("oauth.token.userinfo — the third destroy-on-expiry branch", () => {
  const expiredToken = "mcp_token_userinfo_aged_out";
  const issuedAt = new Date(Date.now() - 2 * 86400000);
  const accessExpiredAt = new Date(Date.now() - 86400000);
  const refreshExpiresAt = new Date(Date.now() + 300 * 86400000);

  beforeEach(() => {
    oauthRepositoryMock.getAccessToken.mockResolvedValue({
      access_token: expiredToken,
      refresh_token: "mcp_refresh_still_alive",
      client_id: CLIENT_ID,
      user_id: USER_ID,
      scope: SCOPE,
      created_at: issuedAt,
      expires_at: accessExpiredAt,
      refresh_token_expires_at: refreshExpiresAt,
    });
  });

  it("records the destruction and still answers 401", async () => {
    const res = await getUserinfo(expiredToken);
    await flush();

    expect(res.statusCode).toBe(401);
    expect(oauthRepositoryMock.deleteAccessToken).toHaveBeenCalledWith(
      expiredToken,
    );
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      action: "oauth.token.userinfo",
      outcome: "failure",
      actor_type: "user",
      actor_id: USER_ID,
      actor_ip: CLIENT_IP,
      request_id: REQUEST_ID,
      target_type: "oauth_client",
      target_id: CLIENT_ID,
      http_status: 401,
    });
    expect(rows[0].detail).toMatchObject({
      reason: "access_token_expired",
      token_type: "access_token",
      token_sha256: sha256(expiredToken),
      token_last4: expiredToken.slice(-4),
      created_at: issuedAt.toISOString(),
      expires_at: accessExpiredAt.toISOString(),
      refresh_token_expires_at: refreshExpiresAt.toISOString(),
    });
    expect(serialized()).not.toContain(expiredToken);
    expect(serialized()).not.toContain("mcp_refresh_still_alive");
  });

  it("writes NOTHING when the token is simply unknown", async () => {
    // The unbounded case: an invented bearer value costs an anonymous caller
    // one request and would cost the append-only table one permanent row.
    oauthRepositoryMock.getAccessToken.mockResolvedValue(null);

    const res = await getUserinfo("mcp_token_invented_by_the_caller");
    await flush();

    expect(res.statusCode).toBe(401);
    expect(rows).toEqual([]);
  });

  it("writes NOTHING when the account is disabled — the row survives", async () => {
    // Disable is a reversible lockout, so this branch destroys nothing and is
    // therefore not self-limiting. It keeps its logger.warn and no row.
    oauthRepositoryMock.getAccessToken.mockResolvedValue({
      access_token: expiredToken,
      client_id: CLIENT_ID,
      user_id: USER_ID,
      scope: SCOPE,
      created_at: issuedAt,
      expires_at: new Date(Date.now() + 3600000),
      refresh_token_expires_at: refreshExpiresAt,
    });
    usersRepositoryMock.isDisabled.mockResolvedValue(true);

    const res = await getUserinfo(expiredToken);
    await flush();

    expect(res.statusCode).toBe(401);
    expect(oauthRepositoryMock.deleteAccessToken).not.toHaveBeenCalled();
    expect(rows).toEqual([]);
  });

  it("still answers and still deletes when the sink REJECTS", async () => {
    setAuditSinkForTesting(async () => {
      throw new Error("connection pool exhausted");
    });

    const res = await getUserinfo(expiredToken);
    await flush();

    expect(res.statusCode).toBe(401);
    expect(oauthRepositoryMock.deleteAccessToken).toHaveBeenCalledWith(
      expiredToken,
    );
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
