/**
 * GET /oauth/userinfo — failure-only rate limiting.
 *
 * userinfo reads a bearer token row and hands back the account's identity
 * claims, and it used to carry no limiter at all, so a burst of unresolvable
 * tokens hit the database (and the destroy-emit path for expired ones) with no
 * bound. It now carries the SAME failure-only limiter as /oauth/introspect and
 * /oauth/revoke: only tokens that resolve to nothing accumulate, so a caller
 * presenting a token this server issued is never throttled. The whole-org
 * outage guard is the first assertion — the bucket is per-`req.ip` and `trust
 * proxy` is off, so a limiter that counted successes would throttle everyone on
 * the shared address.
 *
 * Driven directly as express middleware against fake req/res — same harness as
 * token-public-endpoint.test.ts, with a FIXED ip per test since accumulating
 * within one bucket is what is under test.
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

async function getUserinfo(token: string): Promise<FakeRes> {
  const req = {
    method: "GET",
    url: "/oauth/userinfo",
    originalUrl: "/oauth/userinfo",
    baseUrl: "",
    headers: { authorization: `Bearer ${token}` },
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
    // the shared bucket and refuse everyone on the same edge IP.
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
