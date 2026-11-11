/**
 * /oauth/introspect and /oauth/revoke — failure-only rate limiting, and the
 * RFC 7009 client match on revocation.
 *
 * THE REGRESSION TEST IS THE POINT OF THIS FILE. Revocation takes no
 * credential and introspection's credential check runs after the limiter, so
 * the limiter is what bounds unresolvable tokens. It counts only tokens that
 * resolve to nothing, so a caller holding a real token can call either
 * endpoint indefinitely and must never see a 429. That is asserted first, from
 * a SINGLE address, because many requests sharing one bucket is exactly the
 * condition under which a request-counting limiter fails.
 *
 * The budget is keyed per edge client address (CF-Connecting-IP), falling back
 * to `req.ip` when that header is absent or blank; see
 * getPublicOAuthRateLimitIdentifier in lib/auth-rate-limiter. Most blocks below
 * send no edge header, so the fallback `req.ip` is the bucket under test; the
 * keying block at the end drives the edge header itself.
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
  // /oauth/revoke resolves a rotated-out refresh token through its marker and
  // deletes under the owner's credential lock; armed in beforeEach by
  // armUserLockFakes (./user-lock-test-fakes).
  getRotatedRefreshToken: vi.fn(),
  revokeFamily: vi.fn(),
  withUserLock: vi.fn(),
  deleteByRefreshToken: vi.fn(),
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
const { armUserLockFakes, FAKE_OAUTH_TX } = await import(
  "./user-lock-test-fakes"
);
const { requireIntrospectionCredential } = await import("./introspection-auth");

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
  options: { headers?: Record<string, string>; ip?: string } = {},
): Promise<FakeRes> {
  const ip = options.ip ?? currentIp;
  const req = {
    method: "POST",
    url: path,
    originalUrl: path,
    baseUrl: "",
    body,
    headers: options.headers ?? {},
    ip,
    socket: { remoteAddress: ip },
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
  oauthRepositoryMock.getRotatedRefreshToken.mockResolvedValue(null);
  armUserLockFakes(oauthRepositoryMock);
});

// 20 failures per minute per (address, route) is the limiter's budget; well
// past it.
const OVER_THE_LIMIT = 25;

describe("POST /oauth/introspect — a real token is never throttled", () => {
  it("answers 200 active:true to the SAME token from the SAME ip 25 times", async () => {
    // The success-path guard. Every OAuth-authenticated MCP request used to
    // introspect, many of them from one address, so a limiter that counted
    // successes would have refused the gateway's own traffic.
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
    // pass the assertion above and still refuse the next caller on the same
    // address. Proved by spending only ONE failure afterwards and expecting it
    // to be answered normally.
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
    // this limiter can refuse a legitimate token: the bucket is per address,
    // so once an address has spent its budget, every request from it is
    // refused for the rest of the window. It is tolerable because the
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
    // spend the budget of everyone sharing its address.
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
      FAKE_OAUTH_TX,
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
      FAKE_OAUTH_TX,
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
      FAKE_OAUTH_TX,
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
    // The refresh branch's own delete, and the lock it would run under.
    expect(oauthRepositoryMock.deleteByRefreshToken).not.toHaveBeenCalled();
    expect(oauthRepositoryMock.withUserLock).not.toHaveBeenCalled();
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
    // Deleted by the presented refresh token's hash, under the owner's
    // credential lock, so a refresh of the same token cannot interleave.
    expect(oauthRepositoryMock.deleteByRefreshToken).toHaveBeenCalledWith(
      LIVE_REFRESH,
      FAKE_OAUTH_TX,
    );
    expect(oauthRepositoryMock.withUserLock.mock.calls[0][0]).toBe(USER_ID);
  });
});

/**
 * Keying on the edge client address.
 *
 * Behind the tunnel every request reaches this router with the same `req.ip`
 * (`trust proxy` is off), so these cases put several edge addresses on ONE
 * `req.ip` and check that each gets its own budget. The budget arithmetic is
 * pinned exactly (twenty failures answered, the twenty-first refused) because
 * re-keying is only useful if the per-client allowance stays where it was.
 */
describe("POST /oauth/introspect and /oauth/revoke: budgets keyed on the edge client address", () => {
  /** The in-container address every tunnelled request arrives from. */
  const TUNNEL_IP = "127.0.0.1";
  const BUDGET = 20;

  // Distinct per call, so no case starts on a bucket another case spent: the
  // limiter is module-scoped and its window is a minute.
  let edgeCounter = 0;
  const freshEdgeIp = () => {
    edgeCounter += 1;
    return `2001:db8::${edgeCounter.toString(16)}`;
  };
  const fromEdge = (edgeIp: string) => ({
    headers: { "cf-connecting-ip": edgeIp },
    ip: TUNNEL_IP,
  });

  /** One failed lookup on `route` from `edgeIp`; returns the status. */
  const failOnce = async (
    route: "/oauth/introspect" | "/oauth/revoke",
    options: { headers?: Record<string, string>; ip?: string },
    n: number,
  ): Promise<number> => {
    oauthRepositoryMock.getAccessToken.mockResolvedValue(null);
    oauthRepositoryMock.getByRefreshToken.mockResolvedValue(null);
    return (await post({ token: `mcp_token_unknown_${n}` }, route, options))
      .statusCode;
  };

  it("gives two edge addresses sharing one req.ip separate introspect budgets", async () => {
    const first = fromEdge(freshEdgeIp());
    const second = fromEdge(freshEdgeIp());

    for (let i = 0; i < BUDGET; i += 1) {
      expect(await failOnce("/oauth/introspect", first, i)).toBe(200);
    }
    expect(await failOnce("/oauth/introspect", first, BUDGET)).toBe(429);

    // The other client on the same req.ip is untouched: its first failure is
    // answered normally and its real token is served.
    expect(await failOnce("/oauth/introspect", second, 0)).toBe(200);
    oauthRepositoryMock.getAccessToken.mockResolvedValue(liveAccessTokenRow());
    const live = await post({ token: LIVE_TOKEN }, "/oauth/introspect", second);
    expect(live.statusCode).toBe(200);
    expect(live.body).toMatchObject({ active: true, sub: USER_ID });
  });

  it("gives two edge addresses sharing one req.ip separate revoke budgets", async () => {
    const first = fromEdge(freshEdgeIp());
    const second = fromEdge(freshEdgeIp());

    for (let i = 0; i < BUDGET; i += 1) {
      expect(await failOnce("/oauth/revoke", first, i)).toBe(200);
    }
    expect(await failOnce("/oauth/revoke", first, BUDGET)).toBe(429);

    oauthRepositoryMock.getAccessToken.mockResolvedValue(liveAccessTokenRow());
    const live = await post({ token: LIVE_TOKEN }, "/oauth/revoke", second);
    expect(live.statusCode).toBe(200);
    expect(oauthRepositoryMock.deleteAccessToken).toHaveBeenCalledWith(
      LIVE_TOKEN,
      FAKE_OAUTH_TX,
    );
  });

  it.each(["/oauth/introspect", "/oauth/revoke"] as const)(
    "%s answers the 20th failure from one edge address and refuses the 21st",
    async (route) => {
      const client = fromEdge(freshEdgeIp());

      for (let i = 0; i < BUDGET - 1; i += 1) {
        expect(await failOnce(route, client, i)).toBe(200);
      }
      // The 20th is still inside the budget; refusing it would be the
      // double-count off-by-one the limiter's read-only check exists to avoid.
      expect(await failOnce(route, client, BUDGET - 1)).toBe(200);
      expect(await failOnce(route, client, BUDGET)).toBe(429);
      // And it stays refused for the rest of the window.
      expect(await failOnce(route, client, BUDGET + 1)).toBe(429);
    },
  );

  it("does no credential or database work for a refused introspect", async () => {
    const client = fromEdge(freshEdgeIp());
    for (let i = 0; i < BUDGET; i += 1) {
      await failOnce("/oauth/introspect", client, i);
    }
    vi.mocked(requireIntrospectionCredential).mockClear();
    oauthRepositoryMock.getAccessToken.mockClear();
    usersRepositoryMock.isDisabled.mockClear();

    const refused = await post(
      { token: "mcp_token_after_budget" },
      "/oauth/introspect",
      client,
    );

    expect(refused.statusCode).toBe(429);
    expect(refused.body).toMatchObject({ error: "too_many_requests" });
    expect(requireIntrospectionCredential).not.toHaveBeenCalled();
    expect(oauthRepositoryMock.getAccessToken).not.toHaveBeenCalled();
    expect(usersRepositoryMock.isDisabled).not.toHaveBeenCalled();
  });

  it("does no database work for a refused revoke", async () => {
    const client = fromEdge(freshEdgeIp());
    for (let i = 0; i < BUDGET; i += 1) {
      await failOnce("/oauth/revoke", client, i);
    }
    oauthRepositoryMock.getAccessToken.mockClear();
    oauthRepositoryMock.getByRefreshToken.mockClear();
    oauthRepositoryMock.getRotatedRefreshToken.mockClear();

    const refused = await post(
      { token: "mcp_token_after_budget" },
      "/oauth/revoke",
      client,
    );

    expect(refused.statusCode).toBe(429);
    expect(oauthRepositoryMock.getAccessToken).not.toHaveBeenCalled();
    expect(oauthRepositoryMock.getByRefreshToken).not.toHaveBeenCalled();
    expect(oauthRepositoryMock.deleteAccessToken).not.toHaveBeenCalled();
    expect(oauthRepositoryMock.deleteAccessTokenByHash).not.toHaveBeenCalled();
    expect(oauthRepositoryMock.getRotatedRefreshToken).not.toHaveBeenCalled();
    expect(oauthRepositoryMock.withUserLock).not.toHaveBeenCalled();
  });

  it("keeps introspect and revoke on separate budgets for one edge address", async () => {
    const client = fromEdge(freshEdgeIp());
    for (let i = 0; i < BUDGET; i += 1) {
      await failOnce("/oauth/introspect", client, i);
    }
    expect(await failOnce("/oauth/introspect", client, BUDGET)).toBe(429);

    // The same client's revoke budget is untouched, in both directions.
    for (let i = 0; i < BUDGET; i += 1) {
      expect(await failOnce("/oauth/revoke", client, i)).toBe(200);
    }
    expect(await failOnce("/oauth/revoke", client, BUDGET)).toBe(429);
  });

  it("does not count successes: a client's real tokens leave its whole budget intact", async () => {
    const client = fromEdge(freshEdgeIp());
    oauthRepositoryMock.getAccessToken.mockResolvedValue(liveAccessTokenRow());
    for (let i = 0; i < OVER_THE_LIMIT; i += 1) {
      const res = await post(
        { token: LIVE_TOKEN },
        "/oauth/introspect",
        client,
      );
      expect(res.statusCode).toBe(200);
      expect(res.body).toMatchObject({ active: true });
    }

    // All twenty failures are still available after the successes.
    for (let i = 0; i < BUDGET; i += 1) {
      expect(await failOnce("/oauth/introspect", client, i)).toBe(200);
    }
    expect(await failOnce("/oauth/introspect", client, BUDGET)).toBe(429);
  });

  it("falls back to req.ip when the edge header is absent", async () => {
    // Direct-to-origin and local development carry no edge header. The key
    // is then req.ip, so two such callers on different addresses still get
    // separate budgets, and a request on the same req.ip shares the spent one.
    const spentIp = currentIp;
    for (let i = 0; i < BUDGET; i += 1) {
      await failOnce("/oauth/introspect", { ip: spentIp }, i);
    }
    expect(await failOnce("/oauth/introspect", { ip: spentIp }, BUDGET)).toBe(
      429,
    );

    expect(await failOnce("/oauth/introspect", { ip: "192.0.2.200" }, 0)).toBe(
      200,
    );
    // An edge-attributed request on the spent req.ip keys on its edge
    // address, not on req.ip, so it is not refused.
    expect(
      await failOnce(
        "/oauth/introspect",
        { headers: { "cf-connecting-ip": freshEdgeIp() }, ip: spentIp },
        0,
      ),
    ).toBe(200);
  });

  it("treats a blank edge header as absent and keys on req.ip", async () => {
    const spentIp = currentIp;
    for (let i = 0; i < BUDGET; i += 1) {
      await failOnce(
        "/oauth/revoke",
        { headers: { "cf-connecting-ip": "   " }, ip: spentIp },
        i,
      );
    }

    // The blank-header failures landed in the req.ip bucket: a header-less
    // request on the same req.ip is now refused with them.
    expect(await failOnce("/oauth/revoke", { ip: spentIp }, BUDGET)).toBe(429);
    expect(
      await failOnce(
        "/oauth/revoke",
        { headers: { "cf-connecting-ip": "" }, ip: spentIp },
        BUDGET + 1,
      ),
    ).toBe(429);
  });
});
