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

const usersRepositoryMock = {
  isDisabled: vi.fn(),
};

vi.mock("../../db/repositories", () => ({
  oauthRepository: oauthRepositoryMock,
  usersRepository: usersRepositoryMock,
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
function makeReq(
  body: Record<string, unknown>,
  path = "/oauth/token",
): express.Request {
  ipCounter += 1;
  return {
    method: "POST",
    url: path,
    originalUrl: path,
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

async function post(
  body: Record<string, unknown>,
  path?: string,
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
  // Default: the account is live. Tests that care set their own answer, so a
  // disabled-enforcement test that forgot to arm the mock fails OPEN and its
  // own assertion catches it.
  usersRepositoryMock.isDisabled.mockResolvedValue(false);
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

/**
 * `users.disabled` enforcement at the token endpoint (migration 0027).
 *
 * Wave 2 first shipped disable at the login and OAuth-authorize planes. This
 * endpoint sits behind BOTH of them and is reached by neither: a refresh token
 * minted before the lock is good for 365 days here, and an authorization code
 * minted in the seconds before the lock stays redeemable for its full 10-minute
 * TTL. Either one hands a locked-out account a fresh 24h access token, which is
 * exactly the credential chain credential-theft abuse turns on.
 *
 * Each test asserts three things together, because any one alone can pass while
 * the guard is useless: the grant is REFUSED, no token was minted
 * (`setAccessToken` never called), and — the reversibility property — the
 * existing credential was NOT destroyed on the way out. Disable is a lockout;
 * Revoke is the thing that deletes.
 */
describe("POST /oauth/token — disabled account is refused on both grants", () => {
  const codeVerifier = randomBytes(32).toString("base64url");
  const codeChallenge = createHash("sha256")
    .update(codeVerifier)
    .digest("base64url");
  const authCode = "mcp_code_disabledaccount0000";
  const refreshToken = "mcp_refresh_disabledaccount0";
  const priorAccessToken = "mcp_token_previouslyissued0000";

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
    oauthRepositoryMock.getByRefreshToken.mockResolvedValue({
      access_token: priorAccessToken,
      refresh_token: refreshToken,
      client_id: CLIENT_ID,
      user_id: USER_ID,
      scope: SCOPE,
      expires_at: new Date(Date.now() + 60 * 1000),
      refresh_token_expires_at: new Date(Date.now() + 365 * 24 * 3600 * 1000),
    });
  });

  const exchange = () =>
    post({
      grant_type: "authorization_code",
      code: authCode,
      redirect_uri: "https://claude.ai/api/mcp/auth_callback",
      client_id: CLIENT_ID,
      code_verifier: codeVerifier,
    });

  const refresh = () =>
    post({
      grant_type: "refresh_token",
      refresh_token: refreshToken,
      client_id: CLIENT_ID,
    });

  it("refuses a disabled account's refresh token with invalid_grant", async () => {
    usersRepositoryMock.isDisabled.mockResolvedValue(true);

    const res = await refresh();

    expect(res.statusCode).toBe(400);
    expect(res.body?.error).toBe("invalid_grant");
    expect(usersRepositoryMock.isDisabled).toHaveBeenCalledWith(USER_ID);
    expect(oauthRepositoryMock.setAccessToken).not.toHaveBeenCalled();
    expect(allLoggedText()).not.toContain("[oauth] token issued");
  });

  it("does not destroy the refused refresh token — disable is reversible", async () => {
    // The guard sits BEFORE the rotation delete on purpose. Rejecting after it
    // would consume the token row and leave the connector permanently broken
    // even after an admin presses Enable, which quietly turns Disable into
    // Revoke.
    usersRepositoryMock.isDisabled.mockResolvedValue(true);

    await refresh();

    expect(oauthRepositoryMock.deleteAccessToken).not.toHaveBeenCalled();
  });

  it("still answers a disabled account exactly like an unknown refresh token", async () => {
    // No oracle: a holder of a stolen refresh token must not be able to tell
    // "this account was locked" from "this token is not one of ours".
    usersRepositoryMock.isDisabled.mockResolvedValue(true);
    const disabledRes = await refresh();

    vi.clearAllMocks();
    usersRepositoryMock.isDisabled.mockResolvedValue(false);
    oauthRepositoryMock.getByRefreshToken.mockResolvedValue(null);
    const unknownRes = await refresh();

    expect(disabledRes.statusCode).toBe(unknownRes.statusCode);
    expect(disabledRes.body).toEqual(unknownRes.body);
  });

  it("refuses a disabled account's authorization code inside its 10-minute TTL", async () => {
    usersRepositoryMock.isDisabled.mockResolvedValue(true);

    const res = await exchange();

    expect(res.statusCode).toBe(400);
    expect(res.body?.error).toBe("invalid_grant");
    expect(usersRepositoryMock.isDisabled).toHaveBeenCalledWith(USER_ID);
    expect(oauthRepositoryMock.setAccessToken).not.toHaveBeenCalled();
    expect(allLoggedText()).not.toContain("[oauth] token issued");
  });

  it("does not burn the refused authorization code", async () => {
    usersRepositoryMock.isDisabled.mockResolvedValue(true);

    await exchange();

    expect(oauthRepositoryMock.deleteAuthCode).not.toHaveBeenCalled();
  });

  it("logs reason=disabled naming the grant and user, and no credential", async () => {
    usersRepositoryMock.isDisabled.mockResolvedValue(true);

    await refresh();

    const logged = allLoggedText();
    expect(logged).toContain("reason=disabled");
    expect(logged).toContain("grant=refresh_token");
    expect(logged).toContain(`user=${USER_ID}`);
    expect(logged).not.toContain(refreshToken);
    expect(logged).not.toContain(priorAccessToken);
  });

  it("still issues both grants for an ENABLED account (regression guard)", async () => {
    // The guard must refuse the disabled account and nobody else — a check
    // that rejected everyone would pass every test above.
    usersRepositoryMock.isDisabled.mockResolvedValue(false);

    expect(grantBody(await refresh()).access_token).toMatch(/^mcp_token_/);
    expect(grantBody(await exchange()).access_token).toMatch(/^mcp_token_/);
  });
});

describe("POST /oauth/introspect — a disabled account's token is not active", () => {
  const accessToken = "mcp_token_introspectme";

  const introspect = () => post({ token: accessToken }, "/oauth/introspect");

  beforeEach(() => {
    oauthRepositoryMock.getAccessToken.mockResolvedValue({
      access_token: accessToken,
      client_id: CLIENT_ID,
      user_id: USER_ID,
      scope: SCOPE,
      expires_at: new Date(Date.now() + 60 * 60 * 1000),
      created_at: new Date(Date.now() - 60 * 1000),
    });
  });

  it("answers active:false and nothing else once the account is disabled", async () => {
    // RFC 7662 §2.2: an inactive token gets `active` and no other member. The
    // members withheld here are the ones that matter — `sub` confirms the
    // account exists, `client_id` and `scope` describe the grant.
    usersRepositoryMock.isDisabled.mockResolvedValue(true);

    const res = await introspect();

    expect(res.statusCode).toBe(200);
    expect(res.body).toEqual({ active: false });
    expect(usersRepositoryMock.isDisabled).toHaveBeenCalledWith(USER_ID);
  });

  it("leaves the token row in place — disable is reversible, revoke is not", async () => {
    // The expiry branch deletes; this one must not. Deleting here would turn
    // Disable into a revocation that outlives Enable.
    usersRepositoryMock.isDisabled.mockResolvedValue(true);

    await introspect();

    expect(oauthRepositoryMock.deleteAccessToken).not.toHaveBeenCalled();
  });

  it("logs reason=disabled without echoing the token", async () => {
    usersRepositoryMock.isDisabled.mockResolvedValue(true);

    await introspect();

    const logged = allLoggedText();
    expect(logged).toContain("reason=disabled");
    expect(logged).toContain(`user=${USER_ID}`);
    expect(logged).not.toContain(accessToken);
  });

  it("still reports an ENABLED account's token as active (regression guard)", async () => {
    usersRepositoryMock.isDisabled.mockResolvedValue(false);

    const res = await introspect();

    expect(res.body).toMatchObject({
      active: true,
      sub: USER_ID,
      scope: SCOPE,
      client_id: CLIENT_ID,
    });
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
