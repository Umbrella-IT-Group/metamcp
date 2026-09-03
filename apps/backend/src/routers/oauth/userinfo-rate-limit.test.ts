/**
 * GET /oauth/userinfo — failure-only rate limiting.
 *
 * userinfo reads a bearer token row and hands back the account's identity
 * claims, and it used to carry no limiter at all, so a burst of unresolvable
 * tokens hit the database (and the destroy-emit path for expired ones) with no
 * bound. It now carries the SAME failure-only limiter as /oauth/introspect and
 * /oauth/revoke: only tokens that resolve to nothing accumulate, so a caller
 * presenting a token this server issued is never throttled. It keys on the edge
 * client IP (CF-Connecting-IP) with req.ip as the fallback, the same keying the
 * authorize and token limiters use, so one source spraying failures fills only
 * its own bucket rather than 429ing every caller behind the tunnel; that
 * per-edge isolation is asserted directly below. `trust proxy` is off, so req.ip
 * behind the tunnel is one shared container address, which is why the fallback
 * path and the edge path are tested separately.
 *
 * Driven directly as express middleware against fake req/res, the same harness
 * as token-public-endpoint.test.ts, with a FIXED identity per test (a fixed
 * req.ip, plus a fixed CF-Connecting-IP where the edge path is under test) since
 * accumulating within one bucket is what is under test.
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
  getAccessToken: vi.fn(),
  deleteAccessToken: vi.fn(),
};

const usersRepositoryMock = {
  isDisabled: vi.fn(),
};

vi.mock("../../db/repositories", () => ({
  oauthRepository: oauthRepositoryMock,
  usersRepository: usersRepositoryMock,
}));

const { default: userinfoRouter } = await import("./userinfo");

const USER_ID = "user-abc123";
const SCOPE = "mcp";
const LIVE_TOKEN = "mcp_token_a_real_previously_issued_token";

// The limiter window is a minute and its store is module-scoped, so each test
// takes its own ip to start from an empty bucket; every request within a test
// then shares that ip — the shared-bucket condition being tested.
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
  };

  return res;
}

async function getUserinfo(
  token: string,
  cfConnectingIp?: string,
): Promise<FakeRes> {
  const headers: Record<string, string> = {
    authorization: `Bearer ${token}`,
  };
  // Cloudflare's per-caller header. When present the limiter keys on it; when
  // absent it falls back to req.ip, so omitting it exercises the fallback path.
  if (cfConnectingIp !== undefined) {
    headers["cf-connecting-ip"] = cfConnectingIp;
  }
  const req = {
    method: "GET",
    url: "/oauth/userinfo",
    originalUrl: "/oauth/userinfo",
    baseUrl: "",
    headers,
    ip: currentIp,
    socket: { remoteAddress: currentIp },
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

const liveTokenRow = () => ({
  access_token: LIVE_TOKEN,
  client_id: "mcp_client_test",
  user_id: USER_ID,
  scope: SCOPE,
  expires_at: new Date(Date.now() + 60 * 60 * 1000),
  created_at: new Date(Date.now() - 60 * 1000),
});

beforeEach(() => {
  vi.clearAllMocks();
  freshIp();
  usersRepositoryMock.isDisabled.mockResolvedValue(false);
  oauthRepositoryMock.deleteAccessToken.mockResolvedValue(undefined);
  oauthRepositoryMock.getAccessToken.mockResolvedValue(null);
});

// 20 failures per minute is the shared limiter's budget; well past it.
const OVER_THE_LIMIT = 25;

describe("GET /oauth/userinfo — a real token is never throttled", () => {
  it("answers 200 to the SAME live token from the SAME ip past the budget", async () => {
    oauthRepositoryMock.getAccessToken.mockResolvedValue(liveTokenRow());

    const statuses: number[] = [];
    for (let i = 0; i < OVER_THE_LIMIT; i += 1) {
      const res = await getUserinfo(LIVE_TOKEN);
      statuses.push(res.statusCode);
      expect(res.body).toMatchObject({ sub: USER_ID });
    }

    expect(statuses).toEqual(Array(OVER_THE_LIMIT).fill(200));
    expect(statuses).not.toContain(429);
  });

  it("leaves the bucket empty, so a later wrong token is not already refused", async () => {
    oauthRepositoryMock.getAccessToken.mockResolvedValue(liveTokenRow());
    for (let i = 0; i < OVER_THE_LIMIT; i += 1) {
      await getUserinfo(LIVE_TOKEN);
    }

    oauthRepositoryMock.getAccessToken.mockResolvedValue(null);
    const res = await getUserinfo("mcp_token_wrong");

    expect(res.statusCode).toBe(401);
  });

  it("does not count a DISABLED account's real token against the budget", async () => {
    // A real credential refused for a reason that is not the caller's doing.
    // Counting it would let one locked-out account's still-running client spend
    // that edge IP's bucket and refuse everyone sharing it.
    oauthRepositoryMock.getAccessToken.mockResolvedValue(liveTokenRow());
    usersRepositoryMock.isDisabled.mockResolvedValue(true);

    for (let i = 0; i < OVER_THE_LIMIT; i += 1) {
      const res = await getUserinfo(LIVE_TOKEN);
      expect(res.statusCode).toBe(401);
    }
  });
});

describe("GET /oauth/userinfo — unresolvable tokens are bounded", () => {
  it("answers 429 once a caller has sprayed tokens that resolve to nothing", async () => {
    oauthRepositoryMock.getAccessToken.mockResolvedValue(null);

    const statuses: number[] = [];
    for (let i = 0; i < OVER_THE_LIMIT; i += 1) {
      const res = await getUserinfo(`mcp_token_invented_${i}`);
      statuses.push(res.statusCode);
    }

    expect(statuses[0]).toBe(401);
    expect(statuses).toContain(429);
    expect(statuses[statuses.length - 1]).toBe(429);
  });

  it("stops touching the database once the caller is over budget", async () => {
    oauthRepositoryMock.getAccessToken.mockResolvedValue(null);
    for (let i = 0; i < OVER_THE_LIMIT; i += 1) {
      await getUserinfo(`mcp_token_invented_${i}`);
    }

    oauthRepositoryMock.getAccessToken.mockClear();
    const res = await getUserinfo("mcp_token_invented_final");

    expect(res.statusCode).toBe(429);
    expect(oauthRepositoryMock.getAccessToken).not.toHaveBeenCalled();
  });
});

describe("GET /oauth/userinfo: one edge IP cannot 429 another", () => {
  // Fixed edge IPs, distinct from any other test's, since the limiter store is
  // module-scoped and never reset between tests: a reused key would carry a
  // previous test's failures.
  it("keeps two edge IPs on independent buckets", async () => {
    // Same container req.ip, different CF-Connecting-IP. Under the old
    // per-req.ip keying these shared one bucket, so a noisy source's failures
    // 429ed everyone; keyed on the edge IP they do not.
    oauthRepositoryMock.getAccessToken.mockResolvedValue(null);
    const noisyEdge = "203.0.113.10";
    const quietEdge = "203.0.113.11";

    const noisy: number[] = [];
    for (let i = 0; i < OVER_THE_LIMIT; i += 1) {
      noisy.push(
        (await getUserinfo(`mcp_token_bad_${i}`, noisyEdge)).statusCode,
      );
    }
    expect(noisy).toContain(429);

    // The quiet edge IP has spent nothing, so its first unresolvable token is
    // answered 401, not pre-emptively 429ed by the noisy neighbour.
    const quiet = await getUserinfo("mcp_token_bad_quiet", quietEdge);
    expect(quiet.statusCode).toBe(401);
  });

  it("shares one bucket across requests from the same edge IP", async () => {
    oauthRepositoryMock.getAccessToken.mockResolvedValue(null);
    const edge = "203.0.113.20";

    const statuses: number[] = [];
    for (let i = 0; i < OVER_THE_LIMIT; i += 1) {
      statuses.push((await getUserinfo(`mcp_token_bad_${i}`, edge)).statusCode);
    }

    expect(statuses[0]).toBe(401);
    expect(statuses).toContain(429);
  });

  it("falls back to req.ip when no edge header is present", async () => {
    // Direct-to-origin and local development send no CF-Connecting-IP, so the
    // bucket keys on req.ip. freshIp() gave this test its own req.ip in
    // beforeEach, so it starts empty and bounds the spray just as the edge path
    // does.
    oauthRepositoryMock.getAccessToken.mockResolvedValue(null);

    const statuses: number[] = [];
    for (let i = 0; i < OVER_THE_LIMIT; i += 1) {
      statuses.push((await getUserinfo(`mcp_token_bad_${i}`)).statusCode);
    }

    expect(statuses[0]).toBe(401);
    expect(statuses).toContain(429);
  });
});
