/**
 * Which client a token request speaks for, across the three registered
 * `token_endpoint_auth_method` values the metadata document advertises
 * (`none`, `client_secret_post`, `client_secret_basic`), on both grants.
 *
 * The defect these pin (upstream metatool-ai/metamcp issue #342): the token
 * endpoint read `client_id` from the request BODY only. RFC 6749 section 2.3.1
 * puts a confidential client's id in the `Authorization: Basic` header, and a
 * client registered for `client_secret_basic` is entitled to send it nowhere
 * else. So the authorization_code grant refused every such client with 400
 * invalid_client before its Basic branch ever ran, and the refresh_token grant
 * silently SKIPPED its client check for them.
 *
 * Three groups of cases:
 *
 *  1. `none` and `client_secret_post` with no Authorization header. These are
 *     the production connectors, and they must behave exactly as before: the
 *     same statuses, error codes and descriptions, the same repository calls.
 *     Every case in this group passes against the pre-fix token.ts too, which
 *     is the evidence that those paths did not move.
 *  2. `client_secret_basic` with the client id in the header only: the grant
 *     succeeds when the header names the client the code or token was issued
 *     to and its secret verifies, and is refused otherwise.
 *  3. A Basic header naming a DIFFERENT client than the body's client_id: the
 *     request is refused 401 invalid_client before anything is read, consumed
 *     or rotated, whatever method the client registered.
 *
 * Same harness as token.test.ts: the router is driven as express middleware
 * against fake req/res, and the repositories are mocked so db/index.ts never
 * loads.
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
  consumeAuthCode: vi.fn(),
  getClient: vi.fn(),
  getByRefreshToken: vi.fn(),
  setAccessToken: vi.fn(),
  deleteAccessToken: vi.fn(),
  deleteAccessTokenByHash: vi.fn(),
  getAccessToken: vi.fn(),
  recordRotatedRefreshToken: vi.fn(),
  getRotatedRefreshToken: vi.fn(),
  revokeFamily: vi.fn(),
};

const usersRepositoryMock = {
  isDisabled: vi.fn(),
};

vi.mock("../../db/repositories", () => ({
  oauthRepository: oauthRepositoryMock,
  usersRepository: usersRepositoryMock,
}));

vi.mock("./introspection-auth", () => ({
  requireIntrospectionCredential: vi.fn(async () => ({
    ok: true,
    userId: null,
  })),
}));

const { default: tokenRouter } = await import("./token");
// Dynamic for the same reason as in token.test.ts: a static import of ./utils
// would pull the logger in before the hoisted mock's object exists.
const { hashClientSecret } = await import("./utils");

const CLIENT_ID = "mcp_client_registered0000";
const OTHER_CLIENT_ID = "mcp_client_someoneelse000";
const USER_ID = "user-clientauth";
const SCOPE = "admin";
const REDIRECT_URI = "https://claude.ai/api/mcp/auth_callback";
const RIGHT_SECRET = "mcp_secret_the_real_one_0123456789";
const WRONG_SECRET = "mcp_secret_not_the_real_one_98765";

interface FakeRes {
  statusCode: number;
  body: Record<string, string> | undefined;
  settled: Promise<void>;
  status(code: number): FakeRes;
  json(payload: Record<string, string>): FakeRes;
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

// Unique per request so the module-scope token rate limiter (keyed by IP)
// never lets one case's traffic fail another's.
let ipCounter = 0;
async function post(
  body: Record<string, unknown>,
  authorization?: string,
): Promise<FakeRes> {
  ipCounter += 1;
  const req = {
    method: "POST",
    url: "/oauth/token",
    originalUrl: "/oauth/token",
    baseUrl: "",
    body,
    headers: authorization ? { authorization } : {},
    ip: `10.0.42.${ipCounter}`,
    socket: { remoteAddress: `10.0.42.${ipCounter}` },
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

/** RFC 6749 2.3.1: each half form-urlencoded, joined by a colon, base64. */
function basic(clientId: string, secret: string): string {
  const encode = (value: string) =>
    encodeURIComponent(value).replace(/%20/g, "+");
  return `Basic ${Buffer.from(`${encode(clientId)}:${encode(secret)}`).toString("base64")}`;
}

const hashed = hashClientSecret(RIGHT_SECRET);
function clientRow(
  method: "none" | "client_secret_post" | "client_secret_basic",
) {
  return method === "none"
    ? {
        client_id: CLIENT_ID,
        client_name: "Public Client",
        token_endpoint_auth_method: "none",
        client_secret: null,
        client_secret_salt: null,
      }
    : {
        client_id: CLIENT_ID,
        client_name: "Confidential Client",
        token_endpoint_auth_method: method,
        client_secret: hashed.hash,
        client_secret_salt: hashed.salt,
      };
}

const codeVerifier = randomBytes(32).toString("base64url");
const codeChallenge = createHash("sha256")
  .update(codeVerifier)
  .digest("base64url");
const AUTH_CODE = "mcp_code_clientauthcode00000";
const REFRESH_TOKEN = "mcp_refresh_clientauthtoken000";
const PRIOR_ACCESS_TOKEN_HASH = "stored-access-token-hash";

beforeEach(() => {
  vi.clearAllMocks();
  oauthRepositoryMock.getAuthCode.mockResolvedValue({
    code: AUTH_CODE,
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    scope: SCOPE,
    user_id: USER_ID,
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
    expires_at: new Date(Date.now() + 10 * 60 * 1000),
  });
  oauthRepositoryMock.getByRefreshToken.mockResolvedValue({
    access_token: PRIOR_ACCESS_TOKEN_HASH,
    refresh_token: "stored-refresh-token-hash",
    client_id: CLIENT_ID,
    user_id: USER_ID,
    scope: SCOPE,
    expires_at: new Date(Date.now() + 60 * 1000),
    refresh_token_expires_at: new Date(Date.now() + 365 * 24 * 3600 * 1000),
    family_id: "22222222-2222-2222-2222-222222222222",
  });
  oauthRepositoryMock.consumeAuthCode.mockResolvedValue(true);
  oauthRepositoryMock.setAccessToken.mockResolvedValue(undefined);
  oauthRepositoryMock.deleteAccessTokenByHash.mockResolvedValue(undefined);
  oauthRepositoryMock.recordRotatedRefreshToken.mockResolvedValue(undefined);
  usersRepositoryMock.isDisabled.mockResolvedValue(false);
});

const codeBody = (extra: Record<string, unknown> = {}) => ({
  grant_type: "authorization_code",
  code: AUTH_CODE,
  redirect_uri: REDIRECT_URI,
  code_verifier: codeVerifier,
  ...extra,
});

const refreshBody = (extra: Record<string, unknown> = {}) => ({
  grant_type: "refresh_token",
  refresh_token: REFRESH_TOKEN,
  ...extra,
});

/** The success shape both grants return. */
function expectIssued(res: FakeRes) {
  expect(res.statusCode).toBe(200);
  expect(Object.keys(res.body ?? {}).sort()).toEqual([
    "access_token",
    "expires_in",
    "refresh_token",
    "scope",
    "token_type",
  ]);
  expect(res.body?.access_token).toMatch(/^mcp_token_/);
  expect(res.body?.token_type).toBe("Bearer");
  expect(res.body?.scope).toBe(SCOPE);
  expect(oauthRepositoryMock.setAccessToken).toHaveBeenCalledTimes(1);
  expect(oauthRepositoryMock.setAccessToken.mock.calls[0][1]).toMatchObject({
    client_id: CLIENT_ID,
    user_id: USER_ID,
  });
}

/** Refused, and nothing was minted, consumed or rotated on the way out. */
function expectRefusedUntouched(
  res: FakeRes,
  status: number,
  body: Record<string, string>,
) {
  expect(res.statusCode).toBe(status);
  expect(res.body).toEqual(body);
  expect(oauthRepositoryMock.setAccessToken).not.toHaveBeenCalled();
  expect(oauthRepositoryMock.consumeAuthCode).not.toHaveBeenCalled();
  expect(oauthRepositoryMock.deleteAuthCode).not.toHaveBeenCalled();
  expect(oauthRepositoryMock.deleteAccessTokenByHash).not.toHaveBeenCalled();
  expect(oauthRepositoryMock.recordRotatedRefreshToken).not.toHaveBeenCalled();
}

describe("authorization_code: none and client_secret_post are unchanged", () => {
  it("none: body client_id, no header, issues a pair", async () => {
    oauthRepositoryMock.getClient.mockResolvedValue(clientRow("none"));

    expectIssued(await post(codeBody({ client_id: CLIENT_ID })));
    expect(oauthRepositoryMock.getClient).toHaveBeenCalledWith(CLIENT_ID);
  });

  it("none: a body client_id the code was not issued to is refused 400", async () => {
    oauthRepositoryMock.getClient.mockResolvedValue(clientRow("none"));

    expectRefusedUntouched(
      await post(codeBody({ client_id: OTHER_CLIENT_ID })),
      400,
      {
        error: "invalid_client",
        error_description: "Client ID does not match",
      },
    );
  });

  it("none: no client_id at all is refused 400, as before", async () => {
    oauthRepositoryMock.getClient.mockResolvedValue(clientRow("none"));

    expectRefusedUntouched(await post(codeBody()), 400, {
      error: "invalid_client",
      error_description: "Client ID does not match",
    });
  });

  it("client_secret_post: right body secret issues a pair", async () => {
    oauthRepositoryMock.getClient.mockResolvedValue(
      clientRow("client_secret_post"),
    );

    expectIssued(
      await post(
        codeBody({ client_id: CLIENT_ID, client_secret: RIGHT_SECRET }),
      ),
    );
  });

  it("client_secret_post: wrong body secret is refused 401", async () => {
    oauthRepositoryMock.getClient.mockResolvedValue(
      clientRow("client_secret_post"),
    );

    expectRefusedUntouched(
      await post(
        codeBody({ client_id: CLIENT_ID, client_secret: WRONG_SECRET }),
      ),
      401,
      { error: "invalid_client", error_description: "Invalid client secret" },
    );
  });
});

describe("authorization_code: client_secret_basic", () => {
  beforeEach(() => {
    oauthRepositoryMock.getClient.mockResolvedValue(
      clientRow("client_secret_basic"),
    );
  });

  it("takes the client id from the Basic header when the body omits it (issue #342)", async () => {
    expectIssued(await post(codeBody(), basic(CLIENT_ID, RIGHT_SECRET)));
    expect(oauthRepositoryMock.getClient).toHaveBeenCalledWith(CLIENT_ID);
  });

  it("still issues when the body repeats the same client id", async () => {
    expectIssued(
      await post(
        codeBody({ client_id: CLIENT_ID }),
        basic(CLIENT_ID, RIGHT_SECRET),
      ),
    );
  });

  it("refuses a wrong secret in the header 401, code not consumed", async () => {
    expectRefusedUntouched(
      await post(codeBody(), basic(CLIENT_ID, WRONG_SECRET)),
      401,
      {
        error: "invalid_client",
        error_description: "Invalid client credentials",
      },
    );
  });

  it("refuses a header naming a client the code was not issued to", async () => {
    expectRefusedUntouched(
      await post(codeBody(), basic(OTHER_CLIENT_ID, RIGHT_SECRET)),
      400,
      {
        error: "invalid_client",
        error_description: "Client ID does not match",
      },
    );
  });

  it("refuses a basic client that sends no Authorization header", async () => {
    expectRefusedUntouched(
      await post(codeBody({ client_id: CLIENT_ID })),
      401,
      {
        error: "invalid_client",
        error_description: "Client authentication required via Basic auth",
      },
    );
  });

  it("splits an unencoded header at the first colon, so a colon in the secret survives", async () => {
    // A client that skips the RFC 6749 2.3.1 form-encoding step sends the
    // colon raw. RFC 7617 lets a password contain one and not a user-id, so
    // only the first colon separates the two.
    const colonSecret = "mcp_secret_with:a_colon_inside_it";
    const colonHashed = hashClientSecret(colonSecret);
    oauthRepositoryMock.getClient.mockResolvedValue({
      ...clientRow("client_secret_basic"),
      client_secret: colonHashed.hash,
      client_secret_salt: colonHashed.salt,
    });
    const raw = `Basic ${Buffer.from(`${CLIENT_ID}:${colonSecret}`).toString("base64")}`;

    expectIssued(await post(codeBody(), raw));
  });

  it("form-decodes the secret, so a space and a percent sign survive the header", async () => {
    // basic() encodes the way RFC 6749 2.3.1 says to: the space travels as
    // "+" and the percent sign as "%25". Read back raw, neither would verify.
    const oddSecret = "mcp secret 100% odd";
    const oddHashed = hashClientSecret(oddSecret);
    oauthRepositoryMock.getClient.mockResolvedValue({
      ...clientRow("client_secret_basic"),
      client_secret: oddHashed.hash,
      client_secret_salt: oddHashed.salt,
    });

    expectIssued(await post(codeBody(), basic(CLIENT_ID, oddSecret)));
  });

  it("refuses an unreadable header (broken percent escape) 401, code not consumed", async () => {
    const broken = `Basic ${Buffer.from(`${CLIENT_ID}:bad%ZZescape`).toString("base64")}`;

    expectRefusedUntouched(
      await post(codeBody({ client_id: CLIENT_ID }), broken),
      401,
      {
        error: "invalid_client",
        error_description: "Invalid client credentials",
      },
    );
  });
});

describe("refresh_token: none and client_secret_post are unchanged", () => {
  it("none: body client_id issues a rotated pair", async () => {
    expectIssued(await post(refreshBody({ client_id: CLIENT_ID })));
    expect(oauthRepositoryMock.deleteAccessTokenByHash).toHaveBeenCalledWith(
      PRIOR_ACCESS_TOKEN_HASH,
    );
  });

  it("none: no client_id at all still refreshes (the check is skipped, as before)", async () => {
    expectIssued(await post(refreshBody()));
  });

  it("none: a body client_id the token was not issued to is refused 400", async () => {
    expectRefusedUntouched(
      await post(refreshBody({ client_id: OTHER_CLIENT_ID })),
      400,
      {
        error: "invalid_client",
        error_description: "Client ID does not match",
      },
    );
  });

  it("client_secret_post: body client_id and secret issue a rotated pair", async () => {
    expectIssued(
      await post(
        refreshBody({ client_id: CLIENT_ID, client_secret: RIGHT_SECRET }),
      ),
    );
  });
});

describe("refresh_token: client_secret_basic", () => {
  it("takes the client id from the Basic header when the body omits it", async () => {
    expectIssued(await post(refreshBody(), basic(CLIENT_ID, RIGHT_SECRET)));
  });

  it("refuses a header naming a client the token was not issued to, without rotating", async () => {
    // Before the fix this check was skipped for a Basic client, because the
    // body carried no client_id to compare.
    expectRefusedUntouched(
      await post(refreshBody(), basic(OTHER_CLIENT_ID, RIGHT_SECRET)),
      400,
      {
        error: "invalid_client",
        error_description: "Client ID does not match",
      },
    );
  });
});

describe("conflicting client ids in the body and the Basic header", () => {
  const conflict = {
    error: "invalid_client",
    error_description:
      "client_id in the request body does not match the Authorization header",
  };

  it("authorization_code: refused 401 before the code is read", async () => {
    oauthRepositoryMock.getClient.mockResolvedValue(
      clientRow("client_secret_basic"),
    );

    expectRefusedUntouched(
      await post(
        codeBody({ client_id: CLIENT_ID }),
        basic(OTHER_CLIENT_ID, RIGHT_SECRET),
      ),
      401,
      conflict,
    );
    expect(oauthRepositoryMock.getAuthCode).not.toHaveBeenCalled();
  });

  it("authorization_code: refused for a client registered as none too", async () => {
    oauthRepositoryMock.getClient.mockResolvedValue(clientRow("none"));

    expectRefusedUntouched(
      await post(
        codeBody({ client_id: CLIENT_ID }),
        basic(OTHER_CLIENT_ID, ""),
      ),
      401,
      conflict,
    );
  });

  it("refresh_token: refused 401 before the token is read or rotated", async () => {
    expectRefusedUntouched(
      await post(
        refreshBody({ client_id: CLIENT_ID }),
        basic(OTHER_CLIENT_ID, RIGHT_SECRET),
      ),
      401,
      conflict,
    );
    expect(oauthRepositoryMock.getByRefreshToken).not.toHaveBeenCalled();
  });
});
