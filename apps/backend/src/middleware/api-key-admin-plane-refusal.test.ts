/**
 * DATA-plane refusal of admin-plane (control-plane) keys (migration 0038).
 *
 * A control-plane key authenticates on /trpc, never on the data plane. The
 * plane rule lives inside validateApiKey (so every data-plane surface refuses),
 * and validateApiKey reports the wrong plane as { valid: false, admin_plane:
 * true, key_uuid }. These tests pin that authenticateApiKey then refuses such a
 * key at BOTH of its api-key branches (api-key-only and OAuth-enabled
 * endpoints) and on BOTH carriers (X-API-Key and Authorization: Bearer) with a
 * 403 and the distinct `admin_plane_key_on_data_plane` audit reason, and — the
 * regression that outranks the rest — that an ordinary data-plane key
 * (admin_plane false) is still served.
 *
 * Same harness as api-key-oauth-audit.test.ts: real emitter, sink swapped to
 * capture rows; every repository mocked at the module seam (the middleware
 * builds an ApiKeysRepository at load and users/oauth/access-groups reach
 * db/index).
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

vi.mock("../db/repositories/oauth.repo", () => ({
  oauthRepository: { getAccessToken: vi.fn().mockResolvedValue(null) },
}));

vi.mock("../db/repositories/access-groups.repo", () => ({
  accessGroupsRepository: {
    hasEndpointGrant: vi.fn().mockResolvedValue(false),
  },
}));

const { authenticateApiKey } = await import("./api-key-oauth.middleware");
const { setAuditSinkForTesting } = await import("@/lib/audit/audit-emitter");

type AuditRow = {
  action: string;
  outcome: string;
  actor_type: string;
  actor_id?: string | null;
  http_status?: number | null;
  detail?: Record<string, unknown>;
};

const ENDPOINT_UUID = "11111111-1111-4111-8111-111111111111";
const KEY_UUID = "44444444-4444-4444-8444-444444444444";
const ADMIN_PLANE_KEY = "sk_mt_adminplanekey0000";
const DATA_PLANE_KEY = "sk_mt_dataplanekey00000";

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

let ipCounter = 0;

async function authenticate(options: {
  endpoint?: DatabaseEndpoint;
  headers: Record<string, string>;
}): Promise<{ served: boolean; res: FakeRes }> {
  ipCounter += 1;
  const clientIp = `198.51.100.${ipCounter}`;
  const req = {
    method: "POST",
    url: "/mcp",
    headers: {
      "user-agent": "claude-mcp/1.0",
      "cf-connecting-ip": clientIp,
      ...options.headers,
    },
    query: {},
    protocol: "https",
    get: () => "mcp.example.com",
    ip: "127.0.0.1",
    socket: { remoteAddress: "127.0.0.1" },
    endpoint: options.endpoint ?? makeEndpoint(),
    endpointName: (options.endpoint ?? makeEndpoint()).name,
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

beforeEach(() => {
  vi.clearAllMocks();
  isDisabledMock.mockResolvedValue(false);
  // validateApiKey reports the wrong plane for the admin-plane key and a live
  // row for the data-plane key — exactly the two shapes the repository returns.
  validateApiKeyMock.mockImplementation(async (key: string) =>
    key === ADMIN_PLANE_KEY
      ? { valid: false, admin_plane: true, key_uuid: KEY_UUID }
      : {
          valid: true,
          user_id: null,
          key_uuid: KEY_UUID,
          endpoint_uuid: null,
          acts_as_user_id: null,
        },
  );
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

describe("authenticateApiKey — admin-plane key on the data plane is refused", () => {
  it("refuses an admin-plane key presented as X-API-Key (api-key-only endpoint)", async () => {
    const { served, res } = await authenticate({
      endpoint: apiKeyEndpoint,
      headers: { "x-api-key": ADMIN_PLANE_KEY },
    });
    await flush();

    expect(served).toBe(false);
    expect(res.statusCode).toBe(403);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      action: "mcp.auth.denied",
      outcome: "denied",
      actor_type: "api_key",
      actor_id: KEY_UUID,
      http_status: 403,
    });
    expect(rows[0].detail).toMatchObject({
      reason: "admin_plane_key_on_data_plane",
    });
  });

  it("refuses an admin-plane key presented as Authorization Bearer (api-key-only endpoint)", async () => {
    const { served, res } = await authenticate({
      endpoint: apiKeyEndpoint,
      headers: { authorization: `Bearer ${ADMIN_PLANE_KEY}` },
    });
    await flush();

    expect(served).toBe(false);
    expect(res.statusCode).toBe(403);
    expect(rows[0].detail).toMatchObject({
      reason: "admin_plane_key_on_data_plane",
    });
  });

  it("refuses an admin-plane key on an OAuth-enabled endpoint (second api-key branch)", async () => {
    const { served, res } = await authenticate({
      endpoint: oauthEndpoint,
      headers: { authorization: `Bearer ${ADMIN_PLANE_KEY}` },
    });
    await flush();

    expect(served).toBe(false);
    expect(res.statusCode).toBe(403);
    expect(rows[0].detail).toMatchObject({
      reason: "admin_plane_key_on_data_plane",
    });
  });

  it("refuses an admin-plane key sent as X-API-Key on an OAuth-enabled endpoint", async () => {
    const { served, res } = await authenticate({
      endpoint: oauthEndpoint,
      headers: { "x-api-key": ADMIN_PLANE_KEY },
    });
    await flush();

    expect(served).toBe(false);
    expect(res.statusCode).toBe(403);
    expect(rows[0].detail).toMatchObject({
      reason: "admin_plane_key_on_data_plane",
    });
  });

  it("does NOT emit the invalid_api_key reason for a wrong-plane key", async () => {
    // The refusal is a distinct, greppable event — not folded into the generic
    // invalid-credential path (which is also where the failed-auth limiter
    // counts).
    await authenticate({
      endpoint: apiKeyEndpoint,
      headers: { "x-api-key": ADMIN_PLANE_KEY },
    });
    await flush();

    const reasons = rows.map((r) => (r.detail as { reason?: string }).reason);
    expect(reasons).toContain("admin_plane_key_on_data_plane");
    expect(reasons).not.toContain("invalid_api_key");
  });

  it("still serves an ordinary data-plane key (admin_plane false) — regression", async () => {
    const { served, res } = await authenticate({
      endpoint: apiKeyEndpoint,
      headers: { "x-api-key": DATA_PLANE_KEY },
    });
    await flush();

    expect(served).toBe(true);
    expect(res.statusCode).toBe(200);
  });
});
