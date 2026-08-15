/**
 * The stolen-key detector: audit emission on the MCP bearer path.
 *
 * During the 2026-08-13 incident this middleware — the layer every API key and
 * every OAuth bearer token passes through — wrote NOTHING when it refused a
 * credential. Not a log line, not a counter. A stolen key being tried against
 * endpoint after endpoint looked exactly like no traffic at all. These tests
 * pin that every refusal now produces a durable row, that the row identifies
 * the credential WITHOUT storing it, and — the property that outranks all the
 * others — that a broken audit sink changes nothing about what the caller
 * gets back.
 *
 * Driven as real express middleware against fake req/res, same harness as
 * api-key-disabled-account.test.ts. The real emitter is used (only its sink is
 * swapped) so the fire-and-forget machinery is under test, not mocked away.
 */

import { DatabaseEndpoint } from "@repo/zod-types";
import express from "express";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { validateApiKeyMock, isDisabledMock, loggerMock } = vi.hoisted(() => ({
  validateApiKeyMock: vi.fn(),
  isDisabledMock: vi.fn(),
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

// The middleware validates a bearer token by reading the token row directly
// (it used to call its own /oauth/introspect over HTTP), so oauth.repo is on
// the module-load import chain and reaches db/index like the other two. No
// test in this file takes the OAuth branch — every endpoint here has
// enable_oauth false — so the lookup answering `null` is never reached.
vi.mock("../db/repositories/oauth.repo", () => ({
  oauthRepository: { getAccessToken: vi.fn().mockResolvedValue(null) },
}));

const { authenticateApiKey } = await import("./api-key-oauth.middleware");
const { setAuditSinkForTesting } = await import("@/lib/audit/audit-emitter");

type AuditRow = {
  action: string;
  outcome: string;
  actor_type: string;
  actor_id?: string | null;
  actor_ip?: string | null;
  request_id?: string | null;
  http_status?: number | null;
  target_id?: string | null;
  detail?: Record<string, unknown>;
};

const ENDPOINT_UUID = "11111111-1111-4111-8111-111111111111";
const KEY_UUID = "44444444-4444-4444-8444-444444444444";
const API_KEY = "sk_mt_livekey000000";
const CLIENT_IP = "203.0.113.7";

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

// Unique per request so the middleware's module-scoped failed-attempt limiter
// cannot let one test's traffic rate-limit another's.
let ipCounter = 0;

async function authenticate(options: {
  endpoint?: DatabaseEndpoint;
  headers?: Record<string, string>;
  rateLimitKey?: string;
}): Promise<{ served: boolean; res: FakeRes }> {
  ipCounter += 1;
  const req = {
    method: "POST",
    url: "/mcp",
    headers: {
      "user-agent": "claude-mcp/1.0",
      "cf-connecting-ip": CLIENT_IP,
      ...(options.headers ?? {}),
    },
    query: {},
    protocol: "https",
    get: () => "mcp.example.com",
    // getAuthRateLimitIdentifier keys on req.ip; a shared key is how the 429
    // test drives the limiter over its threshold.
    ip: options.rateLimitKey ?? `10.0.0.${ipCounter}`,
    socket: { remoteAddress: "127.0.0.1" },
    endpoint: options.endpoint ?? makeEndpoint(),
    endpointName: "autotask",
    namespaceUuid: "33333333-3333-4333-8333-333333333333",
    // Stamped by audit-context.middleware in production.
    auditRequestId: "req-under-test",
    auditClientIp: CLIENT_IP,
  } as unknown as express.Request;

  const res = makeRes();
  let served = false;

  await authenticateApiKey(req, res as unknown as express.Response, () => {
    served = true;
  });

  return { served, res };
}

let rows: AuditRow[];

/** Flush the detached promise chain `emit()` schedules. */
const flush = () => new Promise((resolve) => setTimeout(resolve, 0));

beforeEach(() => {
  vi.clearAllMocks();
  rows = [];
  setAuditSinkForTesting(async (event) => {
    rows.push(event as AuditRow);
  });
  isDisabledMock.mockResolvedValue(false);
});

afterEach(() => {
  setAuditSinkForTesting(undefined);
});

describe("mcp.auth.denied — refused credentials", () => {
  it("401 invalid api key: one row, fingerprinted, actor anonymous", async () => {
    validateApiKeyMock.mockResolvedValue({ valid: false });

    const { res } = await authenticate({
      headers: { "x-api-key": API_KEY },
    });
    await flush();

    expect(res.statusCode).toBe(401);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      action: "mcp.auth.denied",
      outcome: "denied",
      // Nothing resolved, so claiming an actor would be a fabrication.
      actor_type: "anonymous",
      actor_id: null,
      actor_ip: CLIENT_IP,
      request_id: "req-under-test",
      http_status: 401,
      target_id: ENDPOINT_UUID,
    });
    expect(rows[0].detail).toMatchObject({
      reason: "invalid_api_key",
      auth_method: "api_key",
    });
  });

  it("NEVER writes the presented credential — only sha256 + last 4", async () => {
    validateApiKeyMock.mockResolvedValue({ valid: false });

    await authenticate({ headers: { "x-api-key": API_KEY } });
    await flush();

    const serialized = JSON.stringify(rows);
    expect(serialized).not.toContain(API_KEY);
    expect(serialized).not.toContain("livekey");
    expect(
      (rows[0].detail as { credential: { sha256: string; last4: string } })
        .credential,
    ).toEqual({
      sha256: expect.stringMatching(/^[0-9a-f]{64}$/),
      last4: "0000",
    });
  });

  it("403 endpoint access denied: binds the row to the key uuid", async () => {
    // A key scoped to a DIFFERENT endpoint — the credential is real, so there
    // is an actor to name.
    validateApiKeyMock.mockResolvedValue({
      valid: true,
      key_uuid: KEY_UUID,
      user_id: "user-owner",
      endpoint_uuid: "99999999-9999-4999-8999-999999999999",
    });

    const { res } = await authenticate({ headers: { "x-api-key": API_KEY } });
    await flush();

    expect(res.statusCode).toBe(403);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      action: "mcp.auth.denied",
      actor_type: "api_key",
      actor_id: KEY_UUID,
      http_status: 403,
    });
    expect(rows[0].detail).toMatchObject({ reason: "endpoint_access_denied" });
  });

  it("403 disabled account: recorded as account_disabled", async () => {
    validateApiKeyMock.mockResolvedValue({
      valid: true,
      key_uuid: KEY_UUID,
      user_id: "user-owner",
      endpoint_uuid: null,
    });
    isDisabledMock.mockResolvedValue(true);

    const { res } = await authenticate({ headers: { "x-api-key": API_KEY } });
    await flush();

    expect(res.statusCode).toBe(403);
    expect(rows[0]).toMatchObject({
      action: "mcp.auth.denied",
      actor_type: "api_key",
      actor_id: KEY_UUID,
    });
    expect(rows[0].detail).toMatchObject({ reason: "account_disabled" });
  });

  it("401 with no credential at all is still recorded (endpoint scanning)", async () => {
    const { res } = await authenticate({ headers: {} });
    await flush();

    expect(res.statusCode).toBe(401);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      action: "mcp.auth.denied",
      actor_type: "anonymous",
      http_status: 401,
    });
    // Tagged so the routine MCP discovery handshake can be excluded from a
    // query in one predicate, rather than excluded at the source.
    expect(rows[0].detail).toMatchObject({ reason: "no_credential" });
  });

  it("serves a valid credential and writes NOTHING", async () => {
    validateApiKeyMock.mockResolvedValue({
      valid: true,
      key_uuid: KEY_UUID,
      user_id: null,
      endpoint_uuid: null,
    });

    const { served } = await authenticate({
      headers: { "x-api-key": API_KEY },
    });
    await flush();

    expect(served).toBe(true);
    expect(rows).toEqual([]);
  });
});

describe("mcp.auth.ratelimited — 429", () => {
  it("uses its own action so a brute force is queryable on one predicate", async () => {
    validateApiKeyMock.mockResolvedValue({ valid: false });
    const rateLimitKey = "198.51.100.99";

    // The limiter allows 20 failures per minute per (ip, endpoint).
    for (let attempt = 0; attempt < 21; attempt += 1) {
      await authenticate({ headers: { "x-api-key": API_KEY }, rateLimitKey });
    }
    await flush();

    const last = rows[rows.length - 1];
    expect(last).toMatchObject({
      action: "mcp.auth.ratelimited",
      outcome: "denied",
      http_status: 429,
    });
    expect(last.detail).toMatchObject({ reason: "too_many_failed_attempts" });
  });
});

describe("THE SAFETY PROPERTY — a broken audit sink changes nothing", () => {
  it("a sink that THROWS still returns the normal 401", async () => {
    validateApiKeyMock.mockResolvedValue({ valid: false });
    setAuditSinkForTesting(() => {
      throw new Error("audit sink exploded");
    });

    const { served, res } = await authenticate({
      headers: { "x-api-key": API_KEY },
    });
    await flush();

    expect(served).toBe(false);
    expect(res.statusCode).toBe(401);
    expect(res.body).toMatchObject({
      error: "invalid_api_key",
      error_description: "The provided API key is invalid or expired",
    });
  });

  it("a sink that REJECTS (database down) still returns the normal 403", async () => {
    validateApiKeyMock.mockResolvedValue({
      valid: true,
      key_uuid: KEY_UUID,
      user_id: "user-owner",
      endpoint_uuid: "99999999-9999-4999-8999-999999999999",
    });
    setAuditSinkForTesting(() => Promise.reject(new Error("ECONNREFUSED")));

    const { res } = await authenticate({ headers: { "x-api-key": API_KEY } });
    await flush();

    expect(res.statusCode).toBe(403);
    expect(res.body).toMatchObject({ error: "Access denied" });
  });

  it("a throwing sink does not block a VALID credential either", async () => {
    validateApiKeyMock.mockResolvedValue({
      valid: true,
      key_uuid: KEY_UUID,
      user_id: null,
      endpoint_uuid: null,
    });
    setAuditSinkForTesting(() => {
      throw new Error("audit sink exploded");
    });

    const { served, res } = await authenticate({
      headers: { "x-api-key": API_KEY },
    });
    await flush();

    expect(served).toBe(true);
    expect(res.statusCode).toBe(200);
  });
});
