/**
 * What an ANONYMOUS caller can learn from, and reach through, `/metamcp`.
 *
 * Two defects on the same surface, found by reading this fork's source rather
 * than by probing it, and fixed together because they compose into one
 * capability: map the estate, then walk in.
 *
 * CONDITION 1 (`api-key-oauth.middleware`) used to `next()` an endpoint whose
 * `enable_api_key_auth` and `enable_oauth` were both off, which published that
 * namespace's whole tool set with no credential, no audit actor and no rate
 * limit, off a pair of checkboxes. It now refuses unless the deployment says
 * `ALLOW_UNAUTHENTICATED_ENDPOINTS=true`.
 *
 * `lookup-endpoint-middleware` used to answer an unknown endpoint name with
 * `404 No endpoint found with name: <name>` while a real one continued to a
 * 401, and that 401 named the endpoint's auth mode. Together: a free
 * does-this-exist oracle plus a fingerprint of the door, at any rate the
 * caller liked. Every response an anonymous caller can obtain is now the same
 * response.
 *
 * Driven as real express middleware against fake req/res, the same way
 * `api-key-disabled-account.test.ts` does it, because the repositories reach
 * `db/index`, which throws without DATABASE_URL.
 */

import { DatabaseEndpoint } from "@repo/zod-types";
import express from "express";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const {
  validateApiKeyMock,
  isDisabledMock,
  getAccessTokenMock,
  findByNameMock,
  loggerMock,
} = vi.hoisted(() => ({
  validateApiKeyMock: vi.fn(),
  isDisabledMock: vi.fn(),
  getAccessTokenMock: vi.fn(),
  findByNameMock: vi.fn(),
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

// The access-group gate (migration 0033) reaches `access-groups.repo` from
// `lib/endpoint-access-control`, which puts it on this middleware's module-load
// import chain and therefore on db/index — same reason oauth.repo is mocked
// above. Every endpoint in this file has `restricted: false`, so the gate
// returns before it would ever call this.
vi.mock("../db/repositories/access-groups.repo", () => ({
  accessGroupsRepository: {
    hasEndpointGrant: vi.fn().mockResolvedValue(false),
  },
}));

vi.mock("../db/repositories/endpoints.repo", () => ({
  endpointsRepository: { findByName: findByNameMock },
}));

const { authenticateApiKey, __resetUnauthenticatedEndpointWarnings } =
  await import("./api-key-oauth.middleware");
const { createLookupEndpoint, __resetEndpointProbeReporting } = await import(
  "./lookup-endpoint-middleware"
);
const { AuthRateLimiter } = await import("../lib/auth-rate-limiter");

const ENDPOINT_UUID = "11111111-1111-4111-8111-111111111111";
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
  // Access-group gate off (migration 0033 default), so these fixtures keep
  // asserting pre-0033 behaviour exactly.
  restricted: false,
  created_at: new Date("2026-07-01T00:00:00Z"),
  updated_at: new Date("2026-07-01T00:00:00Z"),
  user_id: null,
  ...overrides,
});

interface FakeRes {
  statusCode: number;
  body: Record<string, unknown> | undefined;
  headers: Record<string, string>;
  status(code: number): FakeRes;
  json(payload: Record<string, unknown>): FakeRes;
  set(name: string, value: string): FakeRes;
}

function makeRes(): FakeRes {
  const res: FakeRes = {
    statusCode: 200,
    body: undefined,
    headers: {},
    status(code) {
      res.statusCode = code;
      return res;
    },
    json(payload) {
      res.body = payload;
      return res;
    },
    set(name, value) {
      res.headers[name] = value;
      return res;
    },
  };
  return res;
}

// Unique per request so the middleware's in-memory failed-attempt rate limiter
// (module scope, shared process-wide) can never let one test's traffic fail
// another's.
let ipCounter = 0;

function makeReq(options: {
  endpoint?: DatabaseEndpoint;
  endpointName?: string;
  headers?: Record<string, string>;
  auditClientIp?: string;
}): express.Request {
  ipCounter += 1;
  return {
    method: "POST",
    url: "/mcp",
    headers: options.headers ?? {},
    query: {},
    params: { endpoint_name: options.endpointName ?? "autotask" },
    protocol: "https",
    get: () => "mcp.example.com",
    ip: `10.0.0.${ipCounter}`,
    socket: { remoteAddress: `10.0.0.${ipCounter}` },
    auditClientIp: options.auditClientIp,
    endpoint: options.endpoint,
    endpointName: options.endpoint?.name,
    namespaceUuid: options.endpoint?.namespace_uuid,
  } as unknown as express.Request;
}

/** Run authenticateApiKey once: was the request SERVED, and what came back? */
async function authenticate(options: {
  endpoint?: DatabaseEndpoint;
  headers?: Record<string, string>;
}): Promise<{ served: boolean; res: FakeRes }> {
  const req = makeReq(options);
  const res = makeRes();
  let served = false;
  await authenticateApiKey(req, res as unknown as express.Response, () => {
    served = true;
  });
  return { served, res };
}

/** Run a lookup middleware once against a name. */
async function lookup(options: {
  endpointName: string;
  auditClientIp?: string;
  middleware?: ReturnType<typeof createLookupEndpoint>;
}): Promise<{ served: boolean; res: FakeRes }> {
  const req = makeReq(options);
  const res = makeRes();
  let served = false;
  const middleware = options.middleware ?? createLookupEndpoint();
  await middleware(req, res as unknown as express.Response, () => {
    served = true;
  });
  return { served, res };
}

/**
 * A response as an anonymous caller can compare it. `timestamp` is dropped
 * because it is a clock reading, not a signal about the endpoint; every
 * assertion that uses this also asserts a timestamp was present.
 */
function comparable(res: FakeRes) {
  const { timestamp: _timestamp, ...rest } = res.body ?? {};
  return { status: res.statusCode, headers: res.headers, body: rest };
}

beforeEach(() => {
  vi.clearAllMocks();
  __resetUnauthenticatedEndpointWarnings();
  __resetEndpointProbeReporting();
  delete process.env.ALLOW_UNAUTHENTICATED_ENDPOINTS;
  isDisabledMock.mockResolvedValue(false);
});

afterEach(() => {
  delete process.env.ALLOW_UNAUTHENTICATED_ENDPOINTS;
});

describe("CONDITION 1: an endpoint with both auth toggles off", () => {
  const bothOff = () =>
    makeEndpoint({ enable_api_key_auth: false, enable_oauth: false });

  it("is REFUSED with a 401 when ALLOW_UNAUTHENTICATED_ENDPOINTS is unset", async () => {
    const { served, res } = await authenticate({ endpoint: bothOff() });

    expect(served).toBe(false);
    expect(res.statusCode).toBe(401);
    expect(res.body).toMatchObject({ error: "authentication_required" });
  });

  it.each(["false", "1", "yes", "TRUE", "True", ""])(
    "stays refused when the flag is %o rather than the exact string true",
    async (value) => {
      process.env.ALLOW_UNAUTHENTICATED_ENDPOINTS = value;

      const { served, res } = await authenticate({ endpoint: bothOff() });

      // A gate that removes authentication must not be openable by a
      // near-miss spelling.
      expect(served).toBe(false);
      expect(res.statusCode).toBe(401);
    },
  );

  it("is served without authentication when the flag is exactly true", async () => {
    process.env.ALLOW_UNAUTHENTICATED_ENDPOINTS = "true";

    const { served, res } = await authenticate({ endpoint: bothOff() });

    expect(served).toBe(true);
    expect(res.statusCode).toBe(200);
  });

  it("names the endpoint in a warning so the misconfiguration is visible", async () => {
    await authenticate({ endpoint: bothOff() });

    const warned = loggerMock.warn.mock.calls.map(String).join("\n");
    expect(warned).toContain("autotask");
    expect(warned).toContain(ENDPOINT_UUID);
    expect(warned).toContain("NO authentication configured");
  });

  it("warns once per endpoint rather than once per request", async () => {
    // The refused endpoint is unauthenticated, so the caller sets the request
    // rate. One warning per request would hand them the log file.
    await authenticate({ endpoint: bothOff() });
    await authenticate({ endpoint: bothOff() });
    await authenticate({ endpoint: bothOff() });

    expect(loggerMock.warn).toHaveBeenCalledTimes(1);
  });

  it("does not refuse an endpoint that HAS authentication configured", async () => {
    // The guard must not be satisfiable by refusing everyone.
    validateApiKeyMock.mockResolvedValue({
      valid: true,
      user_id: null,
      key_uuid: "44444444-4444-4444-8444-444444444444",
    });

    const { served } = await authenticate({
      endpoint: makeEndpoint({ enable_api_key_auth: true }),
      headers: { "x-api-key": API_KEY },
    });

    expect(served).toBe(true);
  });
});

describe("endpoint-name enumeration: every anonymous answer is the same answer", () => {
  it("answers an unknown name exactly as it answers an unauthenticated real one", async () => {
    // The real endpoint, unauthenticated. This is what a connector sees on its
    // first request, and it is the shape everything else must match.
    findByNameMock.mockResolvedValue(makeEndpoint({ enable_oauth: true }));
    const realLookup = await lookup({ endpointName: "autotask" });
    expect(realLookup.served).toBe(true);
    const real = await authenticate({
      endpoint: makeEndpoint({ enable_oauth: true }),
    });

    // A name that does not exist.
    findByNameMock.mockResolvedValue(undefined);
    const invented = await lookup({ endpointName: "does-not-exist" });

    expect(invented.served).toBe(false);
    expect(comparable(invented.res)).toEqual(comparable(real.res));
    expect(invented.res.body?.timestamp).toEqual(expect.any(String));
    expect(real.res.body?.timestamp).toEqual(expect.any(String));
  });

  it("does not echo the name asked for, or admit the name is unknown", async () => {
    findByNameMock.mockResolvedValue(undefined);

    const { res } = await lookup({ endpointName: "secret-client-endpoint" });

    const serialized = JSON.stringify(res.body);
    expect(serialized).not.toContain("secret-client-endpoint");
    expect(serialized).not.toContain("not found");
    expect(serialized).not.toContain("No endpoint found");
  });

  it("keeps the real reason in the log, where the caller cannot read it", async () => {
    findByNameMock.mockResolvedValue(undefined);

    await lookup({
      endpointName: "secret-client-endpoint",
      auditClientIp: "203.0.113.7",
    });

    const warned = loggerMock.warn.mock.calls.map(String).join("\n");
    expect(warned).toContain("secret-client-endpoint");
    expect(warned).toContain("203.0.113.7");
  });

  it("does not disclose the endpoint's auth mode", async () => {
    // Three different door configurations, one indistinguishable answer, so a
    // probe cannot pick the weakest endpoint to attack.
    const apiKeyOnly = await authenticate({
      endpoint: makeEndpoint({
        enable_api_key_auth: true,
        enable_oauth: false,
        use_query_param_auth: true,
      }),
    });
    const oauthOnly = await authenticate({
      endpoint: makeEndpoint({
        enable_api_key_auth: false,
        enable_oauth: true,
      }),
    });
    const both = await authenticate({
      endpoint: makeEndpoint({ enable_api_key_auth: true, enable_oauth: true }),
    });

    for (const refusal of [apiKeyOnly, oauthOnly, both]) {
      expect(refusal.served).toBe(false);
      expect(refusal.res.statusCode).toBe(401);
      const serialized = JSON.stringify(refusal.res.body);
      expect(serialized).not.toContain("X-API-Key");
      expect(serialized).not.toContain("api_key");
      expect(serialized).not.toContain("Bearer");
    }

    const bodyOf = (r: { res: FakeRes }) => comparable(r.res).body;
    expect(bodyOf(apiKeyOnly)).toEqual(bodyOf(oauthOnly));
    expect(bodyOf(oauthOnly)).toEqual(bodyOf(both));
  });

  it("still serves a VALID authenticated request to a real endpoint", async () => {
    // The property that makes the rest of this safe to ship: nothing about a
    // correct connector's request changed.
    const endpoint = makeEndpoint({ enable_api_key_auth: true });
    findByNameMock.mockResolvedValue(endpoint);
    validateApiKeyMock.mockResolvedValue({
      valid: true,
      user_id: null,
      key_uuid: "44444444-4444-4444-8444-444444444444",
    });

    const looked = await lookup({ endpointName: "autotask" });
    const authed = await authenticate({
      endpoint,
      headers: { "x-api-key": API_KEY },
    });

    expect(looked.served).toBe(true);
    expect(authed.served).toBe(true);
    expect(authed.res.statusCode).toBe(200);
  });
});

describe("endpoint-name probe rate limiting", () => {
  it("throttles a run of unknown-name probes from one client IP", async () => {
    const middleware = createLookupEndpoint({
      limiter: new AuthRateLimiter(2, 60_000),
    });
    findByNameMock.mockResolvedValue(undefined);

    const first = await lookup({
      endpointName: "guess-1",
      auditClientIp: "203.0.113.7",
      middleware,
    });
    const second = await lookup({
      endpointName: "guess-2",
      auditClientIp: "203.0.113.7",
      middleware,
    });
    const third = await lookup({
      endpointName: "guess-3",
      auditClientIp: "203.0.113.7",
      middleware,
    });

    expect(first.res.statusCode).toBe(401);
    expect(second.res.statusCode).toBe(401);
    expect(third.res.statusCode).toBe(429);
    expect(third.res.headers["Retry-After"]).toBeDefined();
  });

  it("refuses NAME-INDEPENDENTLY once tripped, so 429-versus-401 is not a new oracle", async () => {
    const middleware = createLookupEndpoint({
      limiter: new AuthRateLimiter(1, 60_000),
    });
    findByNameMock.mockResolvedValue(undefined);
    await lookup({
      endpointName: "guess-1",
      auditClientIp: "203.0.113.8",
      middleware,
    });

    // A name that DOES exist, from the same exhausted caller.
    findByNameMock.mockResolvedValue(makeEndpoint());
    const real = await lookup({
      endpointName: "autotask",
      auditClientIp: "203.0.113.8",
      middleware,
    });

    expect(real.res.statusCode).toBe(429);
    // And the database was never asked, so a burned-out scanner cannot keep
    // spending a query per guess.
    expect(findByNameMock).toHaveBeenCalledTimes(1);
  });

  it("does not spend another client's budget", async () => {
    const middleware = createLookupEndpoint({
      limiter: new AuthRateLimiter(1, 60_000),
    });
    findByNameMock.mockResolvedValue(undefined);
    await lookup({
      endpointName: "guess-1",
      auditClientIp: "203.0.113.9",
      middleware,
    });

    const other = await lookup({
      endpointName: "guess-2",
      auditClientIp: "198.51.100.4",
      middleware,
    });

    expect(other.res.statusCode).toBe(401);
  });

  it("exempts callers with no CF-Connecting-IP rather than bucketing them together", async () => {
    // In-container traffic and local development carry no such header.
    // Collapsing them into one shared bucket is the outage this keying exists
    // to avoid; see trpc-rate-limit.middleware.
    const middleware = createLookupEndpoint({
      limiter: new AuthRateLimiter(1, 60_000),
    });
    findByNameMock.mockResolvedValue(undefined);

    for (let i = 0; i < 5; i += 1) {
      const { res } = await lookup({
        endpointName: `guess-${i}`,
        middleware,
      });
      expect(res.statusCode).toBe(401);
    }
  });

  it("does not throttle the behind-the-gate variant", async () => {
    // It only runs for a caller who has already proved they are an enabled
    // administrator, and it answers them honestly.
    const middleware = createLookupEndpoint({
      limiter: new AuthRateLimiter(1, 60_000),
      afterAuthentication: true,
    });
    findByNameMock.mockResolvedValue(undefined);

    const first = await lookup({
      endpointName: "typo-1",
      auditClientIp: "203.0.113.10",
      middleware,
    });
    const second = await lookup({
      endpointName: "typo-2",
      auditClientIp: "203.0.113.10",
      middleware,
    });

    expect(first.res.statusCode).toBe(404);
    expect(second.res.statusCode).toBe(404);
  });
});
