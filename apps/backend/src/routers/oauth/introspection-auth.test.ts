/**
 * `POST /oauth/introspect` requires a first-party credential.
 *
 * RFC 7662 §2.1 requires an introspection endpoint to authorize its callers.
 * This one authorized none: anyone who could reach the gateway could hand it a
 * token value and be told whether it was live, along with the token's `scope`,
 * `client_id` and `sub`. That is a validation oracle for a stolen or guessed
 * credential and a user-id disclosure on top.
 *
 * Gating it is only safe because the endpoint has no remaining consumer. The
 * one real caller was this gateway itself — `api-key-oauth.middleware.ts`
 * self-fetched it once per OAuth-authenticated MCP request — and that call was
 * replaced with an in-process `oauthRepository.getAccessToken` read. Nothing
 * else in the backend or frontend posts to it. `/oauth/revoke` is deliberately
 * NOT gated: revocation needs the token value to do anything, destroying a
 * credential is the safe direction to fail, and the public PKCE clients that
 * legitimately revoke hold no secret to present.
 *
 * This file drives the REAL gate against the real router, so it is what proves
 * the wiring; the other three token suites stub `./introspection-auth` out so
 * they can keep testing the branches behind it.
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

const validateApiKeyMock = vi.fn();

class ApiKeysRepositoryMock {
  validateApiKey = validateApiKeyMock;
}

const oauthRepositoryMock = {
  getAccessToken: vi.fn(),
  getByRefreshToken: vi.fn(),
  deleteAccessToken: vi.fn(),
  getClient: vi.fn(),
  getAuthCode: vi.fn(),
  deleteAuthCode: vi.fn(),
  setAccessToken: vi.fn(),
};

const usersRepositoryMock = { isDisabled: vi.fn() };

vi.mock("../../db/repositories", () => ({
  oauthRepository: oauthRepositoryMock,
  usersRepository: usersRepositoryMock,
  ApiKeysRepository: ApiKeysRepositoryMock,
}));

const { default: tokenRouter } = await import("./token");

const VALID_API_KEY = "sk_mt_a_first_party_key";
const LIVE_TOKEN = "mcp_token_a_real_previously_issued_token";
const CLIENT_ID = "mcp_client_test";
const USER_ID = "user-abc123";

/**
 * The limiter behind these endpoints is per-IP, module-scoped and counts
 * failures — and a refused-for-no-credential request IS a failure. A fresh
 * address per test keeps one test's refusals out of another's budget.
 */
let ipCounter = 0;

interface FakeRes {
  statusCode: number;
  body: Record<string, unknown> | undefined;
  headers: Record<string, string>;
  settled: Promise<void>;
  status(code: number): FakeRes;
  set(name: string, value: string): FakeRes;
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
    headers: {},
    settled,
    status(code) {
      res.statusCode = code;
      return res;
    },
    set(name, value) {
      res.headers[name.toLowerCase()] = value;
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
  path: string,
  body: Record<string, unknown>,
  headers: Record<string, string> = {},
): Promise<FakeRes> {
  ipCounter += 1;
  const ip = `192.0.2.${ipCounter}`;

  const req = {
    method: "POST",
    url: path,
    originalUrl: path,
    baseUrl: "",
    path,
    body,
    headers,
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

const liveAccessTokenRow = () => ({
  access_token: LIVE_TOKEN,
  refresh_token: "mcp_refresh_a_real_previously_issued_token",
  client_id: CLIENT_ID,
  user_id: USER_ID,
  scope: "mcp",
  expires_at: new Date(Date.now() + 60 * 60 * 1000),
  refresh_token_expires_at: new Date(Date.now() + 86400 * 1000),
  created_at: new Date(Date.now() - 60 * 1000),
});

beforeEach(() => {
  vi.clearAllMocks();
  usersRepositoryMock.isDisabled.mockResolvedValue(false);
  oauthRepositoryMock.getAccessToken.mockResolvedValue(liveAccessTokenRow());
  oauthRepositoryMock.getByRefreshToken.mockResolvedValue(null);
  validateApiKeyMock.mockImplementation(async (key: string) =>
    key === VALID_API_KEY
      ? { valid: true, user_id: USER_ID, key_uuid: "key-uuid" }
      : { valid: false },
  );
});

describe("POST /oauth/introspect — anonymous callers are refused", () => {
  it("answers 401 with a challenge when no credential is presented", async () => {
    const res = await post("/oauth/introspect", { token: LIVE_TOKEN });

    expect(res.statusCode).toBe(401);
    expect(res.body?.error).toBe("invalid_client");
    expect(res.headers["www-authenticate"]).toContain("Bearer");
  });

  it("does not answer the question it was asked", async () => {
    // The whole point: a refusal must not leak the answer. `active`, `sub`,
    // `client_id` and `scope` are exactly what an oracle would hand over.
    const res = await post("/oauth/introspect", { token: LIVE_TOKEN });

    expect(res.body).not.toHaveProperty("active");
    expect(res.body).not.toHaveProperty("sub");
    expect(res.body).not.toHaveProperty("client_id");
    expect(res.body).not.toHaveProperty("scope");
  });

  it("refuses before touching the token row", async () => {
    // An unauthenticated caller must not be able to make this endpoint do
    // database work, or the 401 is merely a different way to spend queries.
    await post("/oauth/introspect", { token: LIVE_TOKEN });
    expect(oauthRepositoryMock.getAccessToken).not.toHaveBeenCalled();
  });

  it("refuses an invalid or revoked API key", async () => {
    const res = await post(
      "/oauth/introspect",
      { token: LIVE_TOKEN },
      { "x-api-key": "sk_mt_not_a_real_key" },
    );

    expect(res.statusCode).toBe(401);
    expect(validateApiKeyMock).toHaveBeenCalledWith("sk_mt_not_a_real_key");
  });

  it("does not accept an OAuth access token as its own credential", async () => {
    // Presenting the very token under inspection must not authorize the
    // inspection: that would leave the oracle open to anyone already holding
    // one stolen credential, which is the threat the gate exists for.
    const res = await post(
      "/oauth/introspect",
      { token: LIVE_TOKEN },
      { authorization: `Bearer ${LIVE_TOKEN}` },
    );

    expect(res.statusCode).toBe(401);
  });
});

describe("POST /oauth/introspect — a first-party key still works", () => {
  it("accepts X-API-Key and answers the introspection", async () => {
    const res = await post(
      "/oauth/introspect",
      { token: LIVE_TOKEN },
      { "x-api-key": VALID_API_KEY },
    );

    expect(res.statusCode).toBe(200);
    expect(res.body?.active).toBe(true);
    expect(res.body?.client_id).toBe(CLIENT_ID);
    expect(res.body?.sub).toBe(USER_ID);
  });

  it("accepts the same key as an Authorization bearer", async () => {
    const res = await post(
      "/oauth/introspect",
      { token: LIVE_TOKEN },
      { authorization: `Bearer ${VALID_API_KEY}` },
    );

    expect(res.statusCode).toBe(200);
    expect(res.body?.active).toBe(true);
  });

  it("still reports a disabled account's token as inactive", async () => {
    // The `users.disabled` control (migration 0027) sits behind the gate and
    // must survive it: an authorized caller asking about a locked-out
    // account's token gets `active: false`, not the token's details.
    usersRepositoryMock.isDisabled.mockResolvedValue(true);

    const res = await post(
      "/oauth/introspect",
      { token: LIVE_TOKEN },
      { "x-api-key": VALID_API_KEY },
    );

    expect(res.statusCode).toBe(200);
    expect(res.body).toEqual({ active: false });
  });
});

describe("POST /oauth/revoke — deliberately left public", () => {
  it("revokes without any API key", async () => {
    // Public PKCE clients have no secret to present, and RFC 7009 revocation
    // already requires the token value. Gating this would break revocation for
    // the clients least able to protect a token in the first place.
    const res = await post("/oauth/revoke", { token: LIVE_TOKEN });

    expect(res.statusCode).toBe(200);
    expect(oauthRepositoryMock.deleteAccessToken).toHaveBeenCalledWith(
      LIVE_TOKEN,
    );
  });
});
