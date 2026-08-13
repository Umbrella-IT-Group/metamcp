/**
 * Tests for the token endpoint's success-path grant logging.
 *
 * Two things are being pinned, and the second is the load-bearing one:
 *
 * 1. A line IS emitted on every successful grant. It is the only instrument
 *    that shows whether Claude connectors redeem a refresh token before their
 *    access token expires, so a refactor that quietly drops it takes the
 *    investigation's evidence with it.
 * 2. That line NEVER contains a whole credential. The endpoint handles access
 *    tokens, refresh tokens, authorization codes, and client secrets; the log
 *    is allowed the last four characters of the access token and nothing else.
 *    This assertion is run against EVERY logger call the request produced, not
 *    just the one under test, so a future `logger.debug(req.body)` fails here.
 *
 * The handlers are module-private, so the router is driven directly as express
 * middleware against fake req/res objects — no supertest dependency, and no DB:
 * the repository module is mocked, which also keeps `db/index.ts` (which throws
 * without DATABASE_URL) out of the import graph entirely.
 */

import { createHash, randomBytes } from "crypto";
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
  getAccessToken: vi.fn(),
};

vi.mock("../../db/repositories", () => ({
  oauthRepository: oauthRepositoryMock,
}));

const { default: tokenRouter } = await import("./token");

const CLIENT_ID = "mcp_client_test";
const USER_ID = "user-abc123";
const SCOPE = "admin";

interface FakeRes {
  statusCode: number;
  body: Record<string, string> | undefined;
  settled: Promise<void>;
  status(code: number): FakeRes;
  json(payload: Record<string, string>): FakeRes;
  send(): FakeRes;
}

// Unique per request so the token endpoint's in-memory rate limiter (20 per IP
// per minute, shared process-wide because it lives at module scope in utils.ts)
// can never make one test's traffic fail another's.
let ipCounter = 0;
function makeReq(body: Record<string, unknown>): express.Request {
  ipCounter += 1;
  return {
    method: "POST",
    url: "/oauth/token",
    originalUrl: "/oauth/token",
    baseUrl: "",
    body,
    headers: {},
    ip: `10.0.0.${ipCounter}`,
    socket: { remoteAddress: `10.0.0.${ipCounter}` },
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

async function post(body: Record<string, unknown>): Promise<FakeRes> {
  const req = makeReq(body);
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

/** The JSON body a grant returned, asserted present so callers can index it. */
function grantBody(res: FakeRes): Record<string, string> {
  if (!res.body) {
    throw new Error("token endpoint settled without a JSON body");
  }
  return res.body;
}

/** Every string any logger method was called with during the request. */
function allLoggedText(): string {
  return [
    ...loggerMock.debug.mock.calls,
    ...loggerMock.info.mock.calls,
    ...loggerMock.warn.mock.calls,
    ...loggerMock.error.mock.calls,
  ]
    .flat()
    .map((arg) => (typeof arg === "string" ? arg : JSON.stringify(arg)))
    .join("\n");
}

function issuedLine(): string {
  const lines = loggerMock.info.mock.calls
    .flat()
    .filter(
      (arg): arg is string =>
        typeof arg === "string" && arg.startsWith("[oauth] token issued"),
    );
  expect(lines).toHaveLength(1);
  return lines[0];
}

beforeEach(() => {
  vi.clearAllMocks();
  oauthRepositoryMock.setAccessToken.mockResolvedValue(undefined);
  oauthRepositoryMock.deleteAuthCode.mockResolvedValue(undefined);
  oauthRepositoryMock.deleteAccessToken.mockResolvedValue(undefined);
});

describe("POST /oauth/token — authorization_code success logging", () => {
  const codeVerifier = randomBytes(32).toString("base64url");
  const codeChallenge = createHash("sha256")
    .update(codeVerifier)
    .digest("base64url");
  const authCode = "mcp_code_abcdefghijklmnop";

  beforeEach(() => {
    oauthRepositoryMock.getAuthCode.mockResolvedValue({
      code: authCode,
      client_id: CLIENT_ID,
      redirect_uri: "https://claude.ai/api/mcp/auth_callback",
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

  async function exchange() {
    return post({
      grant_type: "authorization_code",
      code: authCode,
      redirect_uri: "https://claude.ai/api/mcp/auth_callback",
      client_id: CLIENT_ID,
      code_verifier: codeVerifier,
    });
  }

  it("logs one grep-friendly line naming the grant, client, and user", async () => {
    const body = grantBody(await exchange());
    expect(body.access_token).toMatch(/^mcp_token_/);

    expect(issuedLine()).toBe(
      "[oauth] token issued grant=authorization_code " +
        `client=${CLIENT_ID} client_name="Claude" user=${USER_ID} ` +
        `token=...${body.access_token.slice(-4)}`,
    );
  });

  it("omits rotated= on the initial grant (nothing was rotated)", async () => {
    await exchange();
    expect(issuedLine()).not.toContain("rotated");
  });

  it("logs the last 4 characters of the access token and no whole secret", async () => {
    const body = grantBody(await exchange());
    const logged = allLoggedText();

    expect(logged).toContain(`token=...${body.access_token.slice(-4)}`);
    expect(logged).not.toContain(body.access_token);
    expect(logged).not.toContain(body.refresh_token);
    expect(logged).not.toContain(authCode);
    expect(logged).not.toContain(codeVerifier);
  });

  it("neutralizes log injection via a hostile client_name from open DCR", async () => {
    // client_name is attacker-controlled: /oauth/register requires no auth.
    // Unescaped, this name would emit a second, forged "token issued" line.
    const forged =
      'Evil"\n[oauth] token issued grant=refresh_token ' +
      "client=mcp_client_forged user=user-victim token=...dead rotated=true";
    oauthRepositoryMock.getClient.mockResolvedValue({
      client_id: CLIENT_ID,
      client_name: forged,
      token_endpoint_auth_method: "none",
      client_secret: null,
    });

    await exchange();

    // issuedLine() itself asserts exactly ONE issued logger call was made.
    // The security property is single-LINE output: the forged text may survive
    // inside the quoted client_name, but with the newline escaped it can never
    // start a second line for a line-oriented consumer (grep) to count.
    const line = issuedLine();
    expect(line).not.toContain("\n");
    expect(line.split("\n")).toHaveLength(1);
    // The hostile name survives only in escaped form, clamped to 100 chars.
    expect(line).toContain(`client_name=${JSON.stringify(forged.slice(0, 100))}`);
  });
});

describe("POST /oauth/token — refresh_token success logging", () => {
  const refreshToken = "mcp_refresh_qrstuvwxyz012345";

  beforeEach(() => {
    oauthRepositoryMock.getByRefreshToken.mockResolvedValue({
      access_token: "mcp_token_previouslyissued0000",
      refresh_token: refreshToken,
      client_id: CLIENT_ID,
      user_id: USER_ID,
      scope: SCOPE,
      expires_at: new Date(Date.now() + 60 * 1000),
      refresh_token_expires_at: new Date(Date.now() + 365 * 24 * 3600 * 1000),
    });
  });

  async function refresh() {
    return post({
      grant_type: "refresh_token",
      refresh_token: refreshToken,
      client_id: CLIENT_ID,
    });
  }

  it("logs the refresh grant and marks the refresh token as rotated", async () => {
    const body = grantBody(await refresh());
    expect(body.access_token).toMatch(/^mcp_token_/);

    expect(issuedLine()).toBe(
      "[oauth] token issued grant=refresh_token " +
        `client=${CLIENT_ID} user=${USER_ID} ` +
        `token=...${body.access_token.slice(-4)} rotated=true`,
    );
  });

  it("logs no whole secret — not the old refresh token, not the new pair", async () => {
    const body = grantBody(await refresh());
    const logged = allLoggedText();

    expect(logged).not.toContain(refreshToken);
    expect(logged).not.toContain(body.access_token);
    expect(logged).not.toContain(body.refresh_token);
    expect(logged).not.toContain("mcp_token_previouslyissued0000");
  });
});

describe("POST /oauth/token — failure paths stay silent", () => {
  it("logs no issued-token line when the refresh token is unknown", async () => {
    oauthRepositoryMock.getByRefreshToken.mockResolvedValue(null);

    const res = await post({
      grant_type: "refresh_token",
      refresh_token: "mcp_refresh_notarealtoken",
    });

    expect(res.statusCode).toBe(400);
    expect(allLoggedText()).not.toContain("[oauth] token issued");
  });
});
