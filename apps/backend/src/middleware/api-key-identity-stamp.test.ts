/**
 * `authenticateApiKey` must NAME every caller it admits.
 *
 * The in-memory session pool binds each session to the identity
 * `resolveSessionIdentity` derives from these request fields, and that resolver
 * answers `anonymous` when `authMethod` is absent — correct for an endpoint
 * published through `ALLOW_UNAUTHENTICATED_ENDPOINTS`, and a silent return to
 * SHARED SESSIONS if it ever happened on a credentialed one, because every
 * anonymous identity matches every other. Nothing downstream can detect the
 * difference: an unstamped request looks exactly like a legitimately anonymous
 * one.
 *
 * The safety of that design rests entirely on this middleware stamping
 * `authMethod` plus `apiKeyUuid` / `oauthUserId` on EVERY success branch, so
 * the coupling is pinned here rather than assumed. All four authenticated
 * shapes are covered — api-key-only, oauth-only, and both branches of a
 * dual-auth endpoint — because a regression in any one of them fails open on
 * its own.
 *
 * Driven as real express middleware against fake req/res, mirroring
 * `api-key-disabled-account.test.ts`; the same three repositories are mocked at
 * the module seam because the middleware constructs an ApiKeysRepository at
 * module load and users.repo / oauth.repo reach db/index.
 */

import { DatabaseEndpoint } from "@repo/zod-types";
import express from "express";
import { beforeEach, describe, expect, it, vi } from "vitest";

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

// Same module-load import-chain reason as the mocks above; every endpoint here
// has `restricted: false`, so the access-group gate returns before calling it.
vi.mock("../db/repositories/access-groups.repo", () => ({
  accessGroupsRepository: {
    hasEndpointGrant: vi.fn().mockResolvedValue(false),
  },
}));

const { authenticateApiKey } = await import("./api-key-oauth.middleware");
const { resolveSessionIdentity } = await import("../lib/metamcp/session-auth");

const ENDPOINT_UUID = "11111111-1111-4111-8111-111111111111";
const KEY_UUID = "44444444-4444-4444-8444-444444444444";
const OWNER_ID = "user-owner";
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
  restricted: false,
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

// Unique per request so the middleware's process-wide failed-attempt limiter
// can never let one test's traffic fail another's.
let ipCounter = 0;

/**
 * Run authenticateApiKey once and hand back the request OBJECT it passed
 * through — the thing under test here is what the middleware wrote onto it,
 * which the disabled-account suite's harness discards.
 */
async function authenticate(options: {
  endpoint: DatabaseEndpoint;
  headers: Record<string, string>;
}): Promise<{ served: boolean; req: express.Request; res: FakeRes }> {
  ipCounter += 1;
  const req = {
    method: "POST",
    url: "/mcp",
    headers: options.headers,
    query: {},
    protocol: "https",
    get: () => "mcp.example.com",
    ip: `10.1.0.${ipCounter}`,
    socket: { remoteAddress: `10.1.0.${ipCounter}` },
    endpoint: options.endpoint,
    endpointName: options.endpoint.name,
    namespaceUuid: options.endpoint.namespace_uuid,
  } as unknown as express.Request;

  const res = makeRes();
  let served = false;

  await authenticateApiKey(req, res as unknown as express.Response, () => {
    served = true;
  });

  return { served, req, res };
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.stubEnv("APP_URL", "https://mcp.example.com");
  isDisabledMock.mockResolvedValue(false);
  getAccessTokenMock.mockResolvedValue({
    access_token: OAUTH_TOKEN,
    client_id: "mcp_client_test",
    user_id: OWNER_ID,
    scope: "mcp",
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

/** The four shapes: every endpoint/credential combination that reaches next(). */
const authenticatedShapes = [
  {
    label: "api-key-only endpoint, API key",
    endpoint: makeEndpoint({ enable_api_key_auth: true, enable_oauth: false }),
    headers: { "x-api-key": API_KEY },
    expected: { method: "api_key", credentialId: KEY_UUID },
  },
  {
    label: "oauth-only endpoint, bearer token",
    endpoint: makeEndpoint({ enable_api_key_auth: false, enable_oauth: true }),
    headers: { authorization: `Bearer ${OAUTH_TOKEN}` },
    expected: { method: "oauth", credentialId: OWNER_ID },
  },
  {
    label: "dual-auth endpoint, API key branch",
    endpoint: makeEndpoint({ enable_api_key_auth: true, enable_oauth: true }),
    headers: { "x-api-key": API_KEY },
    expected: { method: "api_key", credentialId: KEY_UUID },
  },
  {
    label: "dual-auth endpoint, bearer-token branch",
    endpoint: makeEndpoint({ enable_api_key_auth: true, enable_oauth: true }),
    headers: { authorization: `Bearer ${OAUTH_TOKEN}` },
    expected: { method: "oauth", credentialId: OWNER_ID },
  },
] as const;

describe("authenticateApiKey — stamps a nameable identity on every success branch", () => {
  for (const shape of authenticatedShapes) {
    it(`names the caller on ${shape.label}`, async () => {
      const { served, req } = await authenticate({
        endpoint: shape.endpoint,
        headers: { ...shape.headers },
      });

      expect(served).toBe(true);
      const stamped = req as express.Request & {
        authMethod?: "api_key" | "oauth";
        apiKeyUuid?: string;
        oauthUserId?: string;
      };
      expect(stamped.authMethod).toBe(shape.expected.method);
      if (shape.expected.method === "api_key") {
        expect(stamped.apiKeyUuid).toBe(shape.expected.credentialId);
      } else {
        expect(stamped.oauthUserId).toBe(shape.expected.credentialId);
      }
    });

    it(`the session identity derived from ${shape.label} is nameable, never anonymous`, async () => {
      // The assertion that actually matters downstream: an unstamped request
      // would resolve to `anonymous`, and every anonymous identity matches
      // every other one — i.e. shared sessions on a credentialed endpoint.
      const { req } = await authenticate({
        endpoint: shape.endpoint,
        headers: { ...shape.headers },
      });

      const identity = resolveSessionIdentity(
        req as Parameters<typeof resolveSessionIdentity>[0],
      );
      expect(identity).toEqual(shape.expected);
      expect(identity.method).not.toBe("anonymous");
      expect(identity.credentialId).not.toBeNull();
    });
  }

  it("gives two different API keys two different identities on the same endpoint", async () => {
    // The binding is only worth anything if sibling credentials resolve apart.
    const endpoint = makeEndpoint();
    const { req: reqA } = await authenticate({
      endpoint,
      headers: { "x-api-key": API_KEY },
    });

    validateApiKeyMock.mockResolvedValue({
      valid: true,
      user_id: OWNER_ID,
      key_uuid: "55555555-5555-4555-8555-555555555555",
      endpoint_uuid: null,
      acts_as_user_id: null,
    });
    const { req: reqB } = await authenticate({
      endpoint,
      headers: { "x-api-key": "sk_mt_secondkey0000" },
    });

    const identityA = resolveSessionIdentity(
      reqA as Parameters<typeof resolveSessionIdentity>[0],
    );
    const identityB = resolveSessionIdentity(
      reqB as Parameters<typeof resolveSessionIdentity>[0],
    );
    // Same OWNER, two keys — two credentials, so two identities.
    expect(identityA.credentialId).not.toBe(identityB.credentialId);
  });

  it("leaves a REFUSED request unstamped, so nothing downstream can read an identity off it", async () => {
    validateApiKeyMock.mockResolvedValue({ valid: false });

    const { served, req } = await authenticate({
      endpoint: makeEndpoint(),
      headers: { "x-api-key": "sk_mt_bogus" },
    });

    expect(served).toBe(false);
    const stamped = req as express.Request & { authMethod?: string };
    expect(stamped.authMethod).toBeUndefined();
  });
});
