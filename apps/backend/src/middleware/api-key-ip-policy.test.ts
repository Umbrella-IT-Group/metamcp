/**
 * The DATA plane and the API-key IP policy (migration 0040).
 *
 * The policy itself is evaluated inside validateApiKey (its own suites pin
 * that). What only this file can pin is the call-site contract in
 * authenticateApiKey, at BOTH api-key branches and on BOTH carriers:
 *  - every key validation passes the explicit IP-policy opt-in, carrying the
 *    CF-Connecting-IP address (never req.ip), surface data_plane and the
 *    endpoint the key was trying to reach;
 *  - a refusal reported as `ip_denied` is answered 403 with the generic body,
 *    BEFORE the admin-plane branch and the invalid-credential path, so it is
 *    never counted by the failed-credential limiter, never reaches the
 *    disabled-account or endpoint-scope checks, and writes no per-request
 *    `mcp.auth.denied` row (the policy module wrote the throttled one);
 *  - an OAuth bearer is never put through the API-key policy.
 *
 * Same harness as api-key-admin-plane-refusal.test.ts.
 */

import { DatabaseEndpoint } from "@repo/zod-types";
import express from "express";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

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

vi.mock("../db/repositories/access-groups.repo", () => ({
  accessGroupsRepository: {
    hasEndpointGrant: vi.fn().mockResolvedValue(false),
  },
}));

const { authenticateApiKey } = await import("./api-key-oauth.middleware");
const { setAuditSinkForTesting } = await import("@/lib/audit/audit-emitter");
const { authRateLimiter } = await import("@/lib/auth-rate-limiter");

type AuditRow = { action: string; detail?: Record<string, unknown> };

const ENDPOINT_UUID = "11111111-1111-4111-8111-111111111111";
const OTHER_ENDPOINT_UUID = "22222222-2222-4222-8222-222222222222";
const KEY_UUID = "44444444-4444-4444-8444-444444444444";
const KEY = "sk_mt_iptestkey00000000";
const GENERIC_BODY = {
  error: "Access denied",
  message: "This credential is not currently permitted to access this gateway.",
};

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

async function authenticate(options: {
  endpoint: DatabaseEndpoint;
  headers: Record<string, string>;
  /** CF-Connecting-IP; omitted entirely when null. */
  clientIp?: string | null;
}): Promise<{ served: boolean; res: FakeRes }> {
  const clientIp =
    options.clientIp === undefined ? "198.51.100.9" : options.clientIp;
  const req = {
    method: "POST",
    url: "/mcp",
    headers: {
      "user-agent": "n8n/1.0",
      ...(clientIp === null ? {} : { "cf-connecting-ip": clientIp }),
      ...options.headers,
    },
    query: {},
    protocol: "https",
    get: () => "mcp.example.com",
    // req.ip is a constant loopback behind the rewrite; it must never be what
    // the policy sees.
    ip: "127.0.0.1",
    socket: { remoteAddress: "127.0.0.1" },
    endpoint: options.endpoint,
    endpointName: options.endpoint.name,
    namespaceUuid: "33333333-3333-4333-8333-333333333333",
  } as unknown as express.Request;

  const res = makeRes();
  let served = false;
  await authenticateApiKey(req, res as unknown as express.Response, () => {
    served = true;
  });
  return { served, res };
}

let rows: AuditRow[];
const flush = () => new Promise((resolve) => setTimeout(resolve, 0));

const ipDenied = { valid: false, ip_denied: true, key_uuid: KEY_UUID };
const validUnscoped = {
  valid: true,
  user_id: null,
  key_uuid: KEY_UUID,
  endpoint_uuid: null,
  acts_as_user_id: null,
};

beforeEach(() => {
  vi.clearAllMocks();
  isDisabledMock.mockResolvedValue(false);
  getAccessTokenMock.mockResolvedValue(null);
  rows = [];
  setAuditSinkForTesting(async (event) => {
    rows.push(event as AuditRow);
  });
});

afterEach(() => {
  setAuditSinkForTesting(undefined);
});

const apiKeyEndpoint = makeEndpoint();
const oauthEndpoint = makeEndpoint({ enable_oauth: true });

const cases: Array<{
  branch: string;
  endpoint: DatabaseEndpoint;
  headers: Record<string, string>;
}> = [
  {
    branch: "api-key-only endpoint, X-API-Key",
    endpoint: apiKeyEndpoint,
    headers: { "x-api-key": KEY },
  },
  {
    branch: "api-key-only endpoint, Bearer",
    endpoint: apiKeyEndpoint,
    headers: { authorization: `Bearer ${KEY}` },
  },
  {
    branch: "OAuth-enabled endpoint, X-API-Key",
    endpoint: oauthEndpoint,
    headers: { "x-api-key": KEY },
  },
  {
    branch: "OAuth-enabled endpoint, Bearer",
    endpoint: oauthEndpoint,
    headers: { authorization: `Bearer ${KEY}` },
  },
];

describe.each(cases)("authenticateApiKey IP policy: $branch", (c) => {
  it("passes the explicit opt-in: CF-Connecting-IP, surface, endpoint", async () => {
    validateApiKeyMock.mockResolvedValue(validUnscoped);

    const { served } = await authenticate({
      endpoint: c.endpoint,
      headers: c.headers,
      clientIp: "203.0.113.41",
    });

    expect(served).toBe(true);
    expect(validateApiKeyMock).toHaveBeenCalledTimes(1);
    const [token, ipCheck] = validateApiKeyMock.mock.calls[0];
    expect(token).toBe(KEY);
    expect(ipCheck).toMatchObject({
      clientIp: "203.0.113.41",
      surface: "data_plane",
      target: {
        type: "endpoint",
        id: c.endpoint.uuid,
        label: c.endpoint.name,
      },
    });
  });

  it("passes an UNDEFINED address when CF-Connecting-IP is absent (never req.ip)", async () => {
    validateApiKeyMock.mockResolvedValue(validUnscoped);

    await authenticate({
      endpoint: c.endpoint,
      headers: c.headers,
      clientIp: null,
    });

    const [, ipCheck] = validateApiKeyMock.mock.calls[0];
    // The opt-in is still present (so enforce fails closed); the address is
    // honestly unknown rather than the loopback req.ip.
    expect(ipCheck).toBeDefined();
    expect(ipCheck.clientIp).toBeUndefined();
  });

  it("answers an ip_denied key 403 with the generic body and serves nothing", async () => {
    validateApiKeyMock.mockResolvedValue(ipDenied);

    const { served, res } = await authenticate({
      endpoint: c.endpoint,
      headers: c.headers,
    });
    await flush();

    expect(served).toBe(false);
    expect(res.statusCode).toBe(403);
    expect(res.body).toMatchObject(GENERIC_BODY);
    // No per-request row: the policy module already wrote the throttled one.
    expect(rows.filter((r) => r.action === "mcp.auth.denied")).toHaveLength(0);
    // Nothing downstream of the refusal ran.
    expect(isDisabledMock).not.toHaveBeenCalled();
  });

  it("never counts an IP denial toward the failed-credential limiter", async () => {
    validateApiKeyMock.mockResolvedValue(ipDenied);
    const recordSpy = vi.spyOn(authRateLimiter, "recordFailedAttempt");

    // Well past the limiter's 20, from one source address.
    for (let i = 0; i < 30; i += 1) {
      const { res } = await authenticate({
        endpoint: c.endpoint,
        headers: c.headers,
        clientIp: "198.51.100.200",
      });
      expect(res.statusCode).toBe(403);
    }
    expect(recordSpy).not.toHaveBeenCalled();
    recordSpy.mockRestore();
  });
});

describe("authenticateApiKey IP policy: what the refusal hides", () => {
  it("a wrong-address holder of a key scoped ELSEWHERE gets the generic 403, not the scope message", async () => {
    // The validator refuses on IP before anything about scope is evaluated, so
    // the answer is identical to any other IP refusal.
    validateApiKeyMock.mockResolvedValue(ipDenied);

    const { res } = await authenticate({
      endpoint: apiKeyEndpoint,
      headers: { "x-api-key": KEY },
    });

    expect(res.statusCode).toBe(403);
    expect(res.body?.message).toBe(GENERIC_BODY.message);
    expect(String(res.body?.message)).not.toContain("scoped");
  });

  it("the same key from an allowed address still gets its real scope answer", async () => {
    validateApiKeyMock.mockResolvedValue({
      ...validUnscoped,
      endpoint_uuid: OTHER_ENDPOINT_UUID,
    });

    const { res } = await authenticate({
      endpoint: apiKeyEndpoint,
      headers: { "x-api-key": KEY },
    });

    expect(res.statusCode).toBe(403);
    expect(String(res.body?.message)).toContain(
      "scoped to a different endpoint",
    );
  });
});

describe("authenticateApiKey IP policy: OAuth is untouched", () => {
  it("a live OAuth bearer on an OAuth-only endpoint never reaches the key validator", async () => {
    getAccessTokenMock.mockResolvedValue({
      access_token: "mcp_token_live",
      user_id: "user-1",
      scope: "mcp",
      expires_at: new Date(Date.now() + 3_600_000),
    });

    const { served } = await authenticate({
      endpoint: makeEndpoint({
        enable_api_key_auth: false,
        enable_oauth: true,
      }),
      headers: { authorization: "Bearer mcp_token_live" },
    });

    expect(served).toBe(true);
    expect(validateApiKeyMock).not.toHaveBeenCalled();
  });

  it("a live OAuth bearer on a mixed endpoint is served without the key validator", async () => {
    getAccessTokenMock.mockResolvedValue({
      access_token: "mcp_token_live",
      user_id: "user-1",
      scope: "mcp",
      expires_at: new Date(Date.now() + 3_600_000),
    });

    const { served } = await authenticate({
      endpoint: oauthEndpoint,
      headers: { authorization: "Bearer mcp_token_live" },
    });

    expect(served).toBe(true);
    expect(validateApiKeyMock).not.toHaveBeenCalled();
  });
});
