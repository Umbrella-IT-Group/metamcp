/**
 * /oauth/introspect and /oauth/revoke — failure-only rate limiting, and the
 * RFC 7009 client match on revocation.
 *
 * THE REGRESSION TEST IS THE POINT OF THIS FILE. Both endpoints are
 * unauthenticated, so the obvious hardening is a per-IP limiter — and on this
 * deployment that would be a self-inflicted outage rather than a control:
 * `trust proxy` is deliberately off, so every caller arriving through the
 * tunnel shares ONE `req.ip` bucket, and throttling that bucket throttles the
 * whole organisation at once. The limiter added here counts only tokens that
 * resolve to nothing, so a caller holding a real token can hammer either
 * endpoint indefinitely and must never see a 429. That is asserted first, from
 * a SINGLE ip, because sharing one bucket is exactly the condition under which
 * a naive limiter fails.
 *
 * The handlers are module-private, so the router is driven directly as express
 * middleware against fake req/res — same harness as token.test.ts, with one
 * deliberate difference: the ip is FIXED per test rather than unique per
 * request, since accumulating (or not accumulating) within one bucket is what
 * is under test.
 */

import express from "express";
import { beforeEach, describe, expect, it, vi } from "vitest";

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
  // Revoke-by-refresh-token holds the row from getByRefreshToken, so it deletes
  // by the row's stored access-token hash (migration 0036).
  deleteAccessTokenByHash: vi.fn(),
  getAccessToken: vi.fn(),
};

const usersRepositoryMock = {
  isDisabled: vi.fn(),
};

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

const CLIENT_ID = "mcp_client_test";
const OTHER_CLIENT_ID = "mcp_client_someone_else";
const USER_ID = "user-abc123";
const SCOPE = "admin";
const LIVE_TOKEN = "mcp_token_a_real_previously_issued_token";
const LIVE_REFRESH = "mcp_refresh_a_real_previously_issued_token";

/**
 * The limiter's window is a minute and its store is module-scoped, so each
 * test takes its own ip to start from an empty bucket. Every request WITHIN a
 * test then shares that one ip — the shared-bucket condition being tested.
 */
let ipCounter = 0;
let currentIp = "";
const freshIp = () => {
  ipCounter += 1;
  currentIp = `198.51.100.${ipCounter}`;
  return currentIp;
};

interface FakeRes {
  statusCode: number;
  body: Record<string, unknown> | undefined;
  settled: Promise<void>;
  status(code: number): FakeRes;
  json(payload: Record<string, unknown>): FakeRes;
  send(): FakeRes;
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
  path: string,
): Promise<FakeRes> {
  const req = {
    method: "POST",
    url: path,
    originalUrl: path,
    baseUrl: "",
    body,
    headers: {},
    ip: currentIp,
    socket: { remoteAddress: currentIp },
  } as unknown as express.Request;
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

/** A live, unexpired access-token row. */
const liveAccessTokenRow = (overrides: Record<string, unknown> = {}) => ({
  access_token: LIVE_TOKEN,
  refresh_token: LIVE_REFRESH,
  client_id: CLIENT_ID,
  user_id: USER_ID,
  scope: SCOPE,
  expires_at: new Date(Date.now() + 60 * 60 * 1000),
  refresh_token_expires_at: new Date(Date.now() + 86400 * 1000),
  created_at: new Date(Date.now() - 60 * 1000),
  ...overrides,
});

beforeEach(() => {
  vi.clearAllMocks();
  freshIp();
  usersRepositoryMock.isDisabled.mockResolvedValue(false);
  oauthRepositoryMock.getAccessToken.mockResolvedValue(null);
  oauthRepositoryMock.getByRefreshToken.mockResolvedValue(null);
});

// 20 failures per minute is the shared limiter's budget; well past it.
const OVER_THE_LIMIT = 25;

describe("POST /oauth/introspect — a real token is never throttled", () => {
  it("answers 200 active:true to the SAME token from the SAME ip 25 times", async () => {
    // The whole-organisation outage guard. Every OAuth-authenticated MCP
    // request used to introspect, all of them from one shared `req.ip`, so a
    // limiter that counted successes would have taken the gateway down.
    oauthRepositoryMock.getAccessToken.mockResolvedValue(liveAccessTokenRow());

    const statuses: number[] = [];
    for (let i = 0; i < OVER_THE_LIMIT; i += 1) {
      const res = await post({ token: LIVE_TOKEN }, "/oauth/introspect");
      statuses.push(res.statusCode);
      expect(res.body).toMatchObject({ active: true, sub: USER_ID });
    }

    expect(statuses).toEqual(Array(OVER_THE_LIMIT).fill(200));
    expect(statuses).not.toContain(429);
  });

  it("leaves the bucket empty, so a later wrong guess is not already refused", async () => {
    // The success path must not merely avoid 429 for itself — it must leave
    // NOTHING behind. A limiter whose successes accumulated silently would
    // pass the assertion above and still refuse the next caller on the shared
    // ip. Proved by spending only ONE failure afterwards and expecting it to
    // be answered normally.
    oauthRepositoryMock.getAccessToken.mockResolvedValue(liveAccessTokenRow());
    for (let i = 0; i < OVER_THE_LIMIT; i += 1) {
      await post({ token: LIVE_TOKEN }, "/oauth/introspect");
    }

    oauthRepositoryMock.getAccessToken.mockResolvedValue(null);
    const res = await post({ token: "mcp_token_wrong" }, "/oauth/introspect");

    expect(res.statusCode).toBe(200);
    expect(res.body).toEqual({ active: false });
  });

  it("ACCEPTED TRADEOFF: a real token IS refused from an ip already over budget", async () => {
    // Stated as a test rather than left implicit, because it is the one way
    // this limiter can hurt a legitimate caller: the bucket is per-ip and
    // `trust proxy` is off, so an abuser sharing the address takes the
    // endpoint down for everyone on it. It is tolerable only because the
    // gateway's own traffic no longer arrives here at all — the middleware
    // reads the token row in-process (api-key-oauth.middleware.ts) — so
    // nothing on the MCP data plane depends on this endpoint answering.
    oauthRepositoryMock.getAccessToken.mockResolvedValue(null);
    for (let i = 0; i < OVER_THE_LIMIT; i += 1) {
      await post({ token: `mcp_token_invented_${i}` }, "/oauth/introspect");
    }

    oauthRepositoryMock.getAccessToken.mockResolvedValue(liveAccessTokenRow());
    const res = await post({ token: LIVE_TOKEN }, "/oauth/introspect");

    expect(res.statusCode).toBe(429);
  });

  it("does not count a DISABLED account's token against the budget", async () => {
    // A real credential, refused for a reason that is not the caller's doing.
    // Counting it would let one locked-out account's still-running client
    // spend the shared bucket and refuse everybody else.
    oauthRepositoryMock.getAccessToken.mockResolvedValue(liveAccessTokenRow());
    usersRepositoryMock.isDisabled.mockResolvedValue(true);

    for (let i = 0; i < OVER_THE_LIMIT; i += 1) {
      const res = await post({ token: LIVE_TOKEN }, "/oauth/introspect");
      expect(res.statusCode).toBe(200);
      expect(res.body).toEqual({ active: false });
    }
  });
});

describe("POST /oauth/introspect — invented tokens are bounded", () => {
  it("answers 429 once a caller has sprayed unresolvable tokens", async () => {
    oauthRepositoryMock.getAccessToken.mockResolvedValue(null);

    const statuses: number[] = [];
    for (let i = 0; i < OVER_THE_LIMIT; i += 1) {
      const res = await post(
        { token: `mcp_token_invented_${i}` },
        "/oauth/introspect",
      );
      statuses.push(res.statusCode);
    }

    expect(statuses).toContain(429);
    // The first attempts still answer normally: the limiter bounds abuse, it
    // does not refuse a first wrong guess.
    expect(statuses[0]).toBe(200);
    expect(statuses[statuses.length - 1]).toBe(429);
  });

  it("stops touching the database once the caller is over budget", async () => {
    // The check runs before the lookup, so refusing costs nothing. A limiter
    // that still queried would leave the amplifier it was added to remove.
    oauthRepositoryMock.getAccessToken.mockResolvedValue(null);

    for (let i = 0; i < OVER_THE_LIMIT; i += 1) {
      await post({ token: `mcp_token_invented_${i}` }, "/oauth/introspect");
    }
    const callsBefore = oauthRepositoryMock.getAccessToken.mock.calls.length;

    const res = await post({ token: "mcp_token_more" }, "/oauth/introspect");

    expect(res.statusCode).toBe(429);
    expect(oauthRepositoryMock.getAccessToken.mock.calls.length).toBe(
      callsBefore,
    );
  });

  it("keeps introspect and revoke on separate budgets", async () => {
    // Spam at one endpoint must not refuse a legitimate caller at the other.
    oauthRepositoryMock.getAccessToken.mockResolvedValue(null);
    for (let i = 0; i < OVER_THE_LIMIT; i += 1) {
      await post({ token: `mcp_token_invented_${i}` }, "/oauth/introspect");
    }

    oauthRepositoryMock.getAccessToken.mockResolvedValue(liveAccessTokenRow());
    const res = await post({ token: LIVE_TOKEN }, "/oauth/revoke");

    expect(res.statusCode).toBe(200);
    expect(oauthRepositoryMock.deleteAccessToken).toHaveBeenCalledWith(
      LIVE_TOKEN,
    );
  });
});

describe("POST /oauth/revoke — a real token is never throttled", () => {
  it("answers 200 to 25 revocations of real tokens from one ip", async () => {
    oauthRepositoryMock.getAccessToken.mockResolvedValue(liveAccessTokenRow());

    const statuses: number[] = [];
    for (let i = 0; i < OVER_THE_LIMIT; i += 1) {
      statuses.push(
        (await post({ token: LIVE_TOKEN }, "/oauth/revoke")).statusCode,
      );
    }

    expect(statuses).toEqual(Array(OVER_THE_LIMIT).fill(200));
    expect(statuses).not.toContain(429);
  });

  it("answers 429 once a caller has sprayed tokens that do not exist", async () => {
    oauthRepositoryMock.getAccessToken.mockResolvedValue(null);
    oauthRepositoryMock.getByRefreshToken.mockResolvedValue(null);

    const statuses: number[] = [];
    for (let i = 0; i < OVER_THE_LIMIT; i += 1) {
      statuses.push(
        (await post({ token: `invented_${i}` }, "/oauth/revoke")).statusCode,
      );
    }

    // RFC 7009 still answers 200 to garbage — up to the point where the
    // caller has proved it is spraying.
    expect(statuses[0]).toBe(200);
    expect(statuses).toContain(429);
    expect(statuses[statuses.length - 1]).toBe(429);
  });
});

describe("POST /oauth/revoke — RFC 7009 client match", () => {
  it("revokes when the client_id matches the token", async () => {
    oauthRepositoryMock.getAccessToken.mockResolvedValue(liveAccessTokenRow());

    const res = await post(
      { token: LIVE_TOKEN, client_id: CLIENT_ID },
      "/oauth/revoke",
    );

    expect(res.statusCode).toBe(200);
    expect(oauthRepositoryMock.deleteAccessToken).toHaveBeenCalledWith(
      LIVE_TOKEN,
    );
  });

  it("revokes when client_id is omitted — public clients often omit it", async () => {
    // Non-blocking by design: these are secretless public PKCE clients, and
    // refusing the ones that omit client_id would break revocation for the
    // clients least able to protect a token.
    oauthRepositoryMock.getAccessToken.mockResolvedValue(liveAccessTokenRow());

    const res = await post({ token: LIVE_TOKEN }, "/oauth/revoke");

    expect(res.statusCode).toBe(200);
    expect(oauthRepositoryMock.deleteAccessToken).toHaveBeenCalledWith(
      LIVE_TOKEN,
    );
  });

  it("refuses and does NOT delete when the client_id is someone else's", async () => {
    oauthRepositoryMock.getAccessToken.mockResolvedValue(liveAccessTokenRow());

    const res = await post(
      { token: LIVE_TOKEN, client_id: OTHER_CLIENT_ID },
      "/oauth/revoke",
    );

    expect(res.statusCode).toBe(400);
    expect(res.body).toMatchObject({ error: "invalid_client" });
    // The load-bearing half: the token must survive the refused request.
    expect(oauthRepositoryMock.deleteAccessToken).not.toHaveBeenCalled();
  });

  it("applies the same match to a REFRESH token", async () => {
    // The refresh branch is a separate code path; a check on only the access
    // branch would leave the longer-lived credential unprotected.
    oauthRepositoryMock.getAccessToken.mockResolvedValue(null);
    oauthRepositoryMock.getByRefreshToken.mockResolvedValue(
      liveAccessTokenRow(),
    );

    const res = await post(
      { token: LIVE_REFRESH, client_id: OTHER_CLIENT_ID },
      "/oauth/revoke",
    );

    expect(res.statusCode).toBe(400);
    expect(res.body).toMatchObject({ error: "invalid_client" });
    expect(oauthRepositoryMock.deleteAccessToken).not.toHaveBeenCalled();
  });

  it("revokes a REFRESH token whose client_id matches", async () => {
    oauthRepositoryMock.getAccessToken.mockResolvedValue(null);
    oauthRepositoryMock.getByRefreshToken.mockResolvedValue(
      liveAccessTokenRow(),
    );

    const res = await post(
      { token: LIVE_REFRESH, client_id: CLIENT_ID },
      "/oauth/revoke",
    );

    expect(res.statusCode).toBe(200);
    // The row is in hand from getByRefreshToken, so the delete goes through the
    // by-hash path against the row's stored access-token digest (migration
    // 0036), not the plaintext-hashing deleteAccessToken.
    expect(oauthRepositoryMock.deleteAccessTokenByHash).toHaveBeenCalledWith(
      LIVE_TOKEN,
    );
  });
});
