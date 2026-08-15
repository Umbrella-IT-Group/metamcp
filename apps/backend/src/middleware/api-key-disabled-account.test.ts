/**
 * `users.disabled` enforcement on the DATA plane — authenticateApiKey.
 *
 * This is the plane the credential-theft abuse actually ran on. Wave 2 first
 * shipped disable at the login and OAuth-authorize planes only, which locked
 * the doors an attacker holding a live bearer token or API key never uses:
 * OAuth access tokens live 24h here, refresh tokens 365d, and API keys never
 * expire. These tests pin that a disabled account is refused on its NEXT
 * request through every authenticated shape of this middleware, and — equally
 * load-bearing — that an ENABLED account is still served, so the guard can
 * never be "fixed" by making it refuse everyone.
 *
 * The effective identity of an API key is two accounts, not one: the key's
 * owner and, for an admin key carrying an acts-as binding (migration 0024),
 * the user it impersonates. Either being disabled must refuse.
 *
 * Driven as real express middleware against fake req/res. All three
 * repositories are mocked at the module seam — the middleware constructs an
 * ApiKeysRepository at module load, and users.repo / oauth.repo reach db/index,
 * which throws without DATABASE_URL.
 *
 * `globalThis.fetch` is stubbed to THROW rather than to answer. The OAuth
 * branch used to validate a bearer token by calling this server's own
 * /oauth/introspect over HTTP; it now reads the token row directly. A stub that
 * answered would let that round-trip come back unnoticed, so the stub is a
 * tripwire and one test asserts it was never touched.
 */

import { DatabaseEndpoint } from "@repo/zod-types";
import express from "express";
import { afterAll, beforeEach, describe, expect, it, vi } from "vitest";

const { validateApiKeyMock, isDisabledMock, getAccessTokenMock, loggerMock } =
  vi.hoisted(() => ({
    validateApiKeyMock: vi.fn(),
    isDisabledMock: vi.fn(),
    getAccessTokenMock: vi.fn(),
    loggerMock: {
      debug: vi.fn(),
      info: vi.fn(),
      warn: vi.fn(),
      error: vi.fn(),
    },
  }));

vi.mock("@/utils/logger", () => ({ default: loggerMock }));

vi.mock("../db/repositories/api-keys.repo", () => ({
  ApiKeysRepository: class {
    validateApiKey = validateApiKeyMock;
  },
}));

vi.mock("../db/repositories/users.repo", () => ({
  usersRepository: { isDisabled: isDisabledMock },
}));

vi.mock("../db/repositories/oauth.repo", () => ({
  oauthRepository: { getAccessToken: getAccessTokenMock },
}));

const { authenticateApiKey } = await import("./api-key-oauth.middleware");

const ENDPOINT_UUID = "11111111-1111-4111-8111-111111111111";
const KEY_UUID = "44444444-4444-4444-8444-444444444444";
const OWNER_ID = "user-owner";
const ADMIN_ID = "user-admin";
const TARGET_ID = "user-target";
const OAUTH_TOKEN = "mcp_token_liveaccesstoken000000";
const API_KEY = "sk_mt_livekey000000";

const makeEndpoint = (
  overrides: Partial<DatabaseEndpoint> = {},
): DatabaseEndpoint => ({
  uuid: ENDPOINT_UUID,
  name: "autotask",
  description: null,
  namespace_uuid: "33333333-3333-4333-8333-333333333333",
  enable_api_key_auth: true,
  require_scoped_api_key: false,
  enable_max_rate: false,
  enable_client_max_rate: false,
  max_rate_seconds: null,
  max_rate: null,
  client_max_rate: null,
  client_max_rate_seconds: null,
  client_max_rate_strategy: null,
  client_max_rate_strategy_key: null,
  enable_oauth: false,
  use_query_param_auth: false,
  created_at: new Date("2026-07-01T00:00:00Z"),
  updated_at: new Date("2026-07-01T00:00:00Z"),
  user_id: null,
  ...overrides,
});

interface FakeRes {
  statusCode: number;
  body: Record<string, unknown> | undefined;
  status(code: number): FakeRes;
  json(payload: Record<string, unknown>): FakeRes;
  set(): FakeRes;
}

function makeRes(): FakeRes {
  const res: FakeRes = {
    statusCode: 200,
    body: undefined,
    status(code) {
      res.statusCode = code;
      return res;
    },
    json(payload) {
      res.body = payload;
      return res;
    },
    set() {
      return res;
    },
  };
  return res;
}

// Unique per request so the middleware's in-memory failed-attempt rate limiter
// (module scope, shared process-wide) can never let one test's traffic fail
// another's.
let ipCounter = 0;

/**
 * Run authenticateApiKey once and report what happened: whether next() was
 * called (request would be SERVED) and the response if it was refused.
 */
async function authenticate(options: {
  endpoint: DatabaseEndpoint;
  headers: Record<string, string>;
}): Promise<{ served: boolean; res: FakeRes }> {
  ipCounter += 1;
  const req = {
    method: "POST",
    url: "/mcp",
    headers: options.headers,
    query: {},
    protocol: "https",
    get: () => "mcp.example.com",
    ip: `10.0.0.${ipCounter}`,
    socket: { remoteAddress: `10.0.0.${ipCounter}` },
    endpoint: options.endpoint,
    endpointName: options.endpoint.name,
    namespaceUuid: options.endpoint.namespace_uuid,
  } as unknown as express.Request;

  const res = makeRes();
  let served = false;

  await authenticateApiKey(req, res as unknown as express.Response, () => {
    served = true;
  });

  return { served, res };
}

const realFetch = globalThis.fetch;

// A TRIPWIRE, not a stub: nothing in this middleware may make an HTTP call any
// more. Validating a bearer token by asking our own /oauth/introspect over the
// network is the thing that was removed, and a stub that answered politely
// would hide its return.
const fetchTripwire = vi.fn(() => {
  throw new Error("authenticateApiKey must not make HTTP calls");
});
globalThis.fetch = fetchTripwire as unknown as typeof fetch;

afterAll(() => {
  globalThis.fetch = realFetch;
});

beforeEach(() => {
  vi.clearAllMocks();
  vi.stubEnv("APP_URL", "https://mcp.example.com");
  // Default: nobody is disabled. Every test that cares sets its own answer,
  // so a test that forgets fails OPEN here and its assertion catches it —
  // rather than passing because the default happened to refuse everyone.
  isDisabledMock.mockResolvedValue(false);
  // Default: the bearer token resolves to a live, unexpired row.
  getAccessTokenMock.mockResolvedValue({
    access_token: OAUTH_TOKEN,
    client_id: "mcp_client_test",
    user_id: OWNER_ID,
    scope: "admin",
    expires_at: new Date(Date.now() + 60 * 60 * 1000),
    created_at: new Date(Date.now() - 60 * 1000),
  });
  validateApiKeyMock.mockResolvedValue({
    valid: true,
    user_id: OWNER_ID,
    key_uuid: KEY_UUID,
    endpoint_uuid: null,
    acts_as_user_id: null,
  });
});

describe("authenticateApiKey — OAuth bearer token plane", () => {
  const oauthEndpoint = makeEndpoint({
    enable_api_key_auth: false,
    enable_oauth: true,
  });
  const headers = { authorization: `Bearer ${OAUTH_TOKEN}` };

  it("serves an ENABLED account's bearer token (regression guard)", async () => {
    const { served, res } = await authenticate({
      endpoint: oauthEndpoint,
      headers,
    });

    expect(served).toBe(true);
    expect(isDisabledMock).toHaveBeenCalledWith(OWNER_ID);
    expect(res.body).toBeUndefined();
  });

  it("refuses a DISABLED account's bearer token", async () => {
    isDisabledMock.mockResolvedValue(true);

    const { served, res } = await authenticate({
      endpoint: oauthEndpoint,
      headers,
    });

    expect(served).toBe(false);
    expect(res.statusCode).toBe(403);
    expect(res.body?.error).toBe("access_denied");
  });

  it("refuses on the api-key-ON + oauth-ON endpoint shape too", async () => {
    // CONDITION 3 runs the OAuth branch first for an Authorization header.
    // A guard on only one of the two OAuth call sites would leave this shape
    // open, and it is the shape the live gateway's endpoints actually use.
    isDisabledMock.mockResolvedValue(true);

    const { served, res } = await authenticate({
      endpoint: makeEndpoint({
        enable_api_key_auth: true,
        enable_oauth: true,
      }),
      headers,
    });

    expect(served).toBe(false);
    expect(res.statusCode).toBe(403);
    expect(res.body?.error).toBe("access_denied");
    // It must NOT fall through and re-try the same string as an API key.
    expect(validateApiKeyMock).not.toHaveBeenCalled();
  });

  it("validates the bearer token in-process, with no HTTP call at all", async () => {
    // The self-call this replaced ran on EVERY OAuth-authenticated MCP
    // request, which is what made /oauth/introspect impossible to bound: the
    // only real traffic on that public endpoint was ours, arriving from one
    // shared IP. With the round-trip gone, a limiter there cannot reach us.
    const { served } = await authenticate({
      endpoint: oauthEndpoint,
      headers,
    });

    expect(served).toBe(true);
    expect(fetchTripwire).not.toHaveBeenCalled();
    expect(getAccessTokenMock).toHaveBeenCalledWith(OAUTH_TOKEN);
  });

  it("refuses an EXPIRED token without serving the request", async () => {
    // The expiry check lived in the introspect handler; dropping the
    // round-trip without replicating it would have honoured dead tokens.
    getAccessTokenMock.mockResolvedValue({
      access_token: OAUTH_TOKEN,
      client_id: "mcp_client_test",
      user_id: OWNER_ID,
      scope: "admin",
      expires_at: new Date(Date.now() - 1000),
      created_at: new Date(Date.now() - 3600_000),
    });

    const { served, res } = await authenticate({
      endpoint: oauthEndpoint,
      headers,
    });

    expect(served).toBe(false);
    expect(res.statusCode).toBe(401);
    expect(fetchTripwire).not.toHaveBeenCalled();
  });

  it("refuses a bearer token with no row behind it", async () => {
    getAccessTokenMock.mockResolvedValue(null);

    const { served, res } = await authenticate({
      endpoint: oauthEndpoint,
      headers,
    });

    expect(served).toBe(false);
    expect(res.statusCode).toBe(401);
  });

  it("names the account in the log so the operator can see who was refused", async () => {
    isDisabledMock.mockResolvedValue(true);

    await authenticate({ endpoint: oauthEndpoint, headers });

    const warned = loggerMock.warn.mock.calls.flat().join("\n");
    expect(warned).toContain("reason=disabled");
    expect(warned).toContain(`user=${OWNER_ID}`);
    // The credential itself is never written to the log.
    expect(warned).not.toContain(OAUTH_TOKEN);
  });
});

describe("authenticateApiKey — API key plane", () => {
  const keyEndpoint = makeEndpoint();
  const headers = { "x-api-key": API_KEY };

  it("serves an ENABLED key owner (regression guard)", async () => {
    const { served } = await authenticate({
      endpoint: keyEndpoint,
      headers,
    });

    expect(served).toBe(true);
    expect(isDisabledMock).toHaveBeenCalledWith(OWNER_ID);
  });

  it("refuses a key whose OWNER is disabled", async () => {
    isDisabledMock.mockResolvedValue(true);

    const { served, res } = await authenticate({
      endpoint: keyEndpoint,
      headers,
    });

    expect(served).toBe(false);
    expect(res.statusCode).toBe(403);
    expect(res.body?.error).toBe("Access denied");
  });

  it("refuses an ENABLED admin key acting as a DISABLED user", async () => {
    // The exact impersonation shape: the key and its owner are fine, but the
    // identity it exercises was just locked out. Serving this would let an
    // admin key keep acting as the account an operator revoked.
    validateApiKeyMock.mockResolvedValue({
      valid: true,
      user_id: ADMIN_ID,
      key_uuid: KEY_UUID,
      endpoint_uuid: ENDPOINT_UUID,
      acts_as_user_id: TARGET_ID,
    });
    isDisabledMock.mockImplementation(async (id: string) => id === TARGET_ID);

    const { served, res } = await authenticate({
      endpoint: keyEndpoint,
      headers,
    });

    expect(served).toBe(false);
    expect(res.statusCode).toBe(403);
    expect(isDisabledMock).toHaveBeenCalledWith(ADMIN_ID);
    expect(isDisabledMock).toHaveBeenCalledWith(TARGET_ID);
  });

  it("refuses a DISABLED owner's key even when the acts-as target is fine", async () => {
    validateApiKeyMock.mockResolvedValue({
      valid: true,
      user_id: ADMIN_ID,
      key_uuid: KEY_UUID,
      endpoint_uuid: ENDPOINT_UUID,
      acts_as_user_id: TARGET_ID,
    });
    isDisabledMock.mockImplementation(async (id: string) => id === ADMIN_ID);

    const { served, res } = await authenticate({
      endpoint: keyEndpoint,
      headers,
    });

    expect(served).toBe(false);
    expect(res.statusCode).toBe(403);
  });

  it("serves an admin key acting as an ENABLED user (regression guard)", async () => {
    validateApiKeyMock.mockResolvedValue({
      valid: true,
      user_id: ADMIN_ID,
      key_uuid: KEY_UUID,
      endpoint_uuid: ENDPOINT_UUID,
      acts_as_user_id: TARGET_ID,
    });

    const { served } = await authenticate({ endpoint: keyEndpoint, headers });

    expect(served).toBe(true);
    expect(isDisabledMock).toHaveBeenCalledWith(ADMIN_ID);
    expect(isDisabledMock).toHaveBeenCalledWith(TARGET_ID);
  });

  it("still serves a PUBLIC key, which has no owner to lock out", async () => {
    // Regression guard on the fail-closed helper's one deliberate skip. A
    // public key's user_id is NULL by design; passing that to isDisabled would
    // match no row, fail closed to `true`, and take every public key on the
    // gateway offline.
    validateApiKeyMock.mockResolvedValue({
      valid: true,
      user_id: null,
      key_uuid: KEY_UUID,
      endpoint_uuid: null,
      acts_as_user_id: null,
    });

    const { served } = await authenticate({ endpoint: keyEndpoint, headers });

    expect(served).toBe(true);
    expect(isDisabledMock).not.toHaveBeenCalled();
  });

  it("refuses on the api-key-ON + oauth-ON endpoint shape too", async () => {
    // CONDITION 3's API-key branch is a second, separate call site.
    isDisabledMock.mockResolvedValue(true);

    const { served, res } = await authenticate({
      endpoint: makeEndpoint({
        enable_api_key_auth: true,
        enable_oauth: true,
      }),
      headers,
    });

    expect(served).toBe(false);
    expect(res.statusCode).toBe(403);
    expect(res.body?.error).toBe("Access denied");
  });
});
