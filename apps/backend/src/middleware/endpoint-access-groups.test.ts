/**
 * The access-group gate on the MCP bearer path (migration 0033).
 *
 * This is a PRODUCTION SECURITY BOUNDARY on a live gateway, so every claim it
 * makes is proved in both directions: the same request that is refused when the
 * user is not a member is SERVED once the membership query answers true, and
 * the same endpoint that refuses an OAuth caller SERVES an API-key caller. A
 * suite that only asserted the denial could not tell "the gate works" from "the
 * middleware is broken and refuses everything".
 *
 * Four properties, in the order they matter:
 *
 *   1. A restricted endpoint refuses a non-member OAuth user with 403 and the
 *      configured refusal message, compared byte for byte.
 *   2. A member passes, and an administrator passes without membership.
 *   3. An endpoint that has NOT opted in behaves exactly as it did before this
 *      feature existed — no query, no cache entry, no behaviour change. This is
 *      the regression pin for the "ships wide open" requirement.
 *   4. API-key callers are untouched on a restricted endpoint, which is the
 *      deliberate scope boundary rather than a gap.
 *
 * Driven as real express middleware against fake req/res, the same harness as
 * api-key-oauth-audit.test.ts. The real cache and the real audit emitter are
 * used (only the repositories and the sink are swapped) so the caching, the
 * invalidation and the fire-and-forget machinery are under test rather than
 * mocked away.
 */

import { DatabaseEndpoint } from "@repo/zod-types";
import express from "express";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const {
  validateApiKeyMock,
  isDisabledMock,
  findRoleByIdMock,
  getAccessTokenMock,
  hasEndpointGrantMock,
  loggerMock,
} = vi.hoisted(() => ({
  validateApiKeyMock: vi.fn(),
  isDisabledMock: vi.fn(),
  findRoleByIdMock: vi.fn(),
  getAccessTokenMock: vi.fn(),
  hasEndpointGrantMock: vi.fn(),
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
  usersRepository: {
    isDisabled: isDisabledMock,
    findRoleById: findRoleByIdMock,
  },
}));

vi.mock("../db/repositories/oauth.repo", () => ({
  oauthRepository: { getAccessToken: getAccessTokenMock },
}));

vi.mock("../db/repositories/access-groups.repo", () => ({
  accessGroupsRepository: { hasEndpointGrant: hasEndpointGrantMock },
}));

const { authenticateApiKey } = await import("./api-key-oauth.middleware");
const { setAuditSinkForTesting } = await import("@/lib/audit/audit-emitter");
const {
  ENDPOINT_ACCESS_DENIED_MESSAGE,
  invalidateEndpointAccessCache,
  __resetEndpointAccessCacheForTesting,
  __resetAccessDenialThrottleForTesting,
  __endpointAccessCacheSizeForTesting,
} = await import("@/lib/endpoint-access-control");

type AuditRow = {
  action: string;
  outcome: string;
  actor_type: string;
  actor_id?: string | null;
  http_status?: number | null;
  target_id?: string | null;
  detail?: Record<string, unknown>;
};

const ENDPOINT_UUID = "11111111-1111-4111-8111-111111111111";
const OTHER_ENDPOINT_UUID = "55555555-5555-4555-8555-555555555555";
const KEY_UUID = "44444444-4444-4444-8444-444444444444";
const OAUTH_TOKEN = "mcp_token_liveoauth0000";
const API_KEY = "sk_mt_livekey000000";
const USER_ID = "user-not-a-member";
const OTHER_USER_ID = "user-someone-else";

const makeEndpoint = (
  overrides: Partial<DatabaseEndpoint> = {},
): DatabaseEndpoint => ({
  uuid: ENDPOINT_UUID,
  name: "autotask",
  description: null,
  namespace_uuid: "33333333-3333-4333-8333-333333333333",
  enable_api_key_auth: false,
  require_scoped_api_key: false,
  enable_max_rate: false,
  enable_client_max_rate: false,
  max_rate_seconds: null,
  max_rate: null,
  client_max_rate: null,
  client_max_rate_seconds: null,
  client_max_rate_strategy: null,
  client_max_rate_strategy_key: null,
  enable_oauth: true,
  use_query_param_auth: false,
  restricted: false,
  created_at: new Date("2026-07-01T00:00:00Z"),
  updated_at: new Date("2026-07-01T00:00:00Z"),
  // Public endpoint: `checkOAuthAccess` admits every authenticated user, which
  // is precisely the blanket the access-group gate exists to narrow. A private
  // endpoint would be refused on ownership first and would never reach it.
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
  headers?: Record<string, string>;
}): Promise<{ served: boolean; res: FakeRes }> {
  ipCounter += 1;
  const clientIp = `198.51.100.${ipCounter % 250}`;
  const req = {
    method: "POST",
    url: "/mcp",
    headers: {
      "user-agent": "claude-mcp/1.0",
      "cf-connecting-ip": clientIp,
      ...(options.headers ?? {}),
    },
    query: {},
    protocol: "https",
    get: () => "mcp.example.com",
    ip: "127.0.0.1",
    socket: { remoteAddress: "127.0.0.1" },
    endpoint: options.endpoint ?? makeEndpoint(),
    endpointName: "autotask",
    namespaceUuid: "33333333-3333-4333-8333-333333333333",
    auditRequestId: "req-under-test",
    auditClientIp: clientIp,
  } as unknown as express.Request;

  const res = makeRes();
  let served = false;

  await authenticateApiKey(req, res as unknown as express.Response, () => {
    served = true;
  });

  return { served, res };
}

/** An OAuth-authenticated request carrying `userId`'s live bearer token. */
const asOAuthUser = (
  userId: string,
  endpoint?: DatabaseEndpoint,
): Promise<{ served: boolean; res: FakeRes }> => {
  getAccessTokenMock.mockResolvedValue({
    user_id: userId,
    scope: "mcp",
    expires_at: new Date(Date.now() + 60 * 60 * 1000),
  });
  return authenticate({
    endpoint,
    headers: { authorization: `Bearer ${OAUTH_TOKEN}` },
  });
};

let rows: AuditRow[];

/** Flush the detached promise chain `emit()` schedules. */
const flush = () => new Promise((resolve) => setTimeout(resolve, 0));

const accessRows = () =>
  rows.filter((r) => r.action === "endpoint.access.denied");

beforeEach(() => {
  vi.clearAllMocks();
  __resetEndpointAccessCacheForTesting();
  __resetAccessDenialThrottleForTesting();
  rows = [];
  setAuditSinkForTesting(async (event) => {
    rows.push(event as AuditRow);
  });
  isDisabledMock.mockResolvedValue(false);
  findRoleByIdMock.mockResolvedValue("member");
  hasEndpointGrantMock.mockResolvedValue(false);
});

afterEach(() => {
  setAuditSinkForTesting(undefined);
});

describe("restricted endpoint refuses a non-member OAuth user", () => {
  it("403 with the exact refusal message, byte for byte", async () => {
    const { served, res } = await asOAuthUser(
      USER_ID,
      makeEndpoint({ restricted: true }),
    );

    expect(served).toBe(false);
    expect(res.statusCode).toBe(403);
    // Byte-compare against the shipped constant AND against the literal, so a
    // change to either one alone turns this red. The constant alone would let
    // a reworded message pass; the literal alone would let the middleware start
    // sending some other string that happened to match this copy.
    expect(res.body?.error_description).toBe(ENDPOINT_ACCESS_DENIED_MESSAGE);
    expect(res.body?.error_description).toBe(
      "Permission denied, this connector is not available for you. Please reach out to your administrator.",
    );
    expect(res.body?.error).toBe("access_denied");
  });

  it("names no endpoint, group or reason in the body a caller can read", async () => {
    const { res } = await asOAuthUser(
      USER_ID,
      makeEndpoint({ restricted: true, name: "autotask" }),
    );

    const body = JSON.stringify(res.body);
    expect(body).not.toContain("autotask");
    expect(body).not.toContain(ENDPOINT_UUID);
    expect(body).not.toContain(USER_ID);
  });

  it("consults membership for the endpoint actually requested", async () => {
    await asOAuthUser(
      USER_ID,
      makeEndpoint({ uuid: OTHER_ENDPOINT_UUID, restricted: true }),
    );

    expect(hasEndpointGrantMock).toHaveBeenCalledWith(
      USER_ID,
      OTHER_ENDPOINT_UUID,
    );
  });
});

describe("who gets through", () => {
  it("a member of a mapped group is SERVED on the same endpoint that refused a non-member", async () => {
    const endpoint = makeEndpoint({ restricted: true });

    const refused = await asOAuthUser(USER_ID, endpoint);
    expect(refused.served).toBe(false);
    expect(refused.res.statusCode).toBe(403);

    // Same endpoint, same request, only the grant differs — the red-green pair.
    __resetEndpointAccessCacheForTesting();
    hasEndpointGrantMock.mockResolvedValue(true);

    const served = await asOAuthUser(USER_ID, endpoint);
    expect(served.served).toBe(true);
    expect(served.res.statusCode).toBe(200);
  });

  it("an administrator passes without belonging to any group", async () => {
    findRoleByIdMock.mockResolvedValue("admin");
    hasEndpointGrantMock.mockResolvedValue(false);

    const { served } = await asOAuthUser(
      USER_ID,
      makeEndpoint({ restricted: true }),
    );

    expect(served).toBe(true);
    // The bypass is the ROLE, not a hidden grant — the membership query still
    // ran and still answered false.
    expect(hasEndpointGrantMock).toHaveBeenCalled();
  });

  it("a non-admin, non-member is refused even though the role lookup succeeded", async () => {
    findRoleByIdMock.mockResolvedValue("member");
    hasEndpointGrantMock.mockResolvedValue(false);

    const { served, res } = await asOAuthUser(
      USER_ID,
      makeEndpoint({ restricted: true }),
    );

    expect(served).toBe(false);
    expect(res.statusCode).toBe(403);
  });
});

describe("an endpoint that has not opted in is unchanged", () => {
  it("serves the OAuth caller and touches NEITHER the role nor the grant query", async () => {
    const { served, res } = await asOAuthUser(
      USER_ID,
      makeEndpoint({ restricted: false }),
    );

    expect(served).toBe(true);
    expect(res.statusCode).toBe(200);
    // The regression pin for "ships wide open": with nothing flagged, the gate
    // costs one boolean read. A future refactor that moves the `restricted`
    // check below the queries would turn this red.
    expect(findRoleByIdMock).not.toHaveBeenCalled();
    expect(hasEndpointGrantMock).not.toHaveBeenCalled();
    expect(__endpointAccessCacheSizeForTesting()).toBe(0);
  });

  it("writes no endpoint.access.denied row", async () => {
    await asOAuthUser(USER_ID, makeEndpoint({ restricted: false }));
    await flush();

    expect(accessRows()).toHaveLength(0);
  });
});

describe("API-key callers are the deliberate scope boundary", () => {
  it("an API key is SERVED on a restricted endpoint", async () => {
    validateApiKeyMock.mockResolvedValue({
      valid: true,
      user_id: OTHER_USER_ID,
      key_uuid: KEY_UUID,
      endpoint_uuid: null,
    });

    const { served, res } = await authenticate({
      endpoint: makeEndpoint({
        restricted: true,
        enable_api_key_auth: true,
        enable_oauth: false,
      }),
      headers: { "x-api-key": API_KEY },
    });

    expect(served).toBe(true);
    expect(res.statusCode).toBe(200);
    // Not "it happened to pass" — the gate was never consulted for this
    // credential class at all.
    expect(hasEndpointGrantMock).not.toHaveBeenCalled();
  });

  it("an API key is served on a restricted endpoint that ALSO has OAuth on", async () => {
    validateApiKeyMock.mockResolvedValue({
      valid: true,
      user_id: OTHER_USER_ID,
      key_uuid: KEY_UUID,
      endpoint_uuid: null,
    });

    const { served } = await authenticate({
      endpoint: makeEndpoint({
        restricted: true,
        enable_api_key_auth: true,
        enable_oauth: true,
      }),
      headers: { "x-api-key": API_KEY },
    });

    expect(served).toBe(true);
    expect(hasEndpointGrantMock).not.toHaveBeenCalled();
  });
});

describe("both OAuth endpoint shapes carry the gate", () => {
  it("refuses on CONDITION 4 (api key off, oauth on)", async () => {
    const { served, res } = await asOAuthUser(
      USER_ID,
      makeEndpoint({
        restricted: true,
        enable_api_key_auth: false,
        enable_oauth: true,
      }),
    );

    expect(served).toBe(false);
    expect(res.body?.error_description).toBe(ENDPOINT_ACCESS_DENIED_MESSAGE);
  });

  it("refuses on CONDITION 3 (api key on, oauth on)", async () => {
    // Either branch alone would leave the other endpoint shape ungated — the
    // same reason the `users.disabled` check is duplicated across both.
    const { served, res } = await asOAuthUser(
      USER_ID,
      makeEndpoint({
        restricted: true,
        enable_api_key_auth: true,
        enable_oauth: true,
      }),
    );

    expect(served).toBe(false);
    expect(res.body?.error_description).toBe(ENDPOINT_ACCESS_DENIED_MESSAGE);
  });
});

describe("membership is cached, and revocation drops it", () => {
  it("a second request inside the TTL asks the database nothing", async () => {
    hasEndpointGrantMock.mockResolvedValue(true);
    const endpoint = makeEndpoint({ restricted: true });

    await asOAuthUser(USER_ID, endpoint);
    await asOAuthUser(USER_ID, endpoint);
    await asOAuthUser(USER_ID, endpoint);

    expect(hasEndpointGrantMock).toHaveBeenCalledTimes(1);
    expect(findRoleByIdMock).toHaveBeenCalledTimes(1);
  });

  it("REVOCATION takes effect on the next request, not after the TTL", async () => {
    hasEndpointGrantMock.mockResolvedValue(true);
    const endpoint = makeEndpoint({ restricted: true });

    const before = await asOAuthUser(USER_ID, endpoint);
    expect(before.served).toBe(true);

    // What an admin mutation does. Asserted through the invalidation HOOK
    // rather than by advancing a clock: the TTL is the ceiling for a mutation
    // that happened in another process, while this is the path a revocation in
    // THIS process takes, and it is the one an operator is watching.
    hasEndpointGrantMock.mockResolvedValue(false);
    invalidateEndpointAccessCache();

    const after = await asOAuthUser(USER_ID, endpoint);
    expect(after.served).toBe(false);
    expect(after.res.statusCode).toBe(403);
    expect(after.res.body?.error_description).toBe(
      ENDPOINT_ACCESS_DENIED_MESSAGE,
    );
    expect(hasEndpointGrantMock).toHaveBeenCalledTimes(2);
  });

  it("caches per (user, endpoint) — one user's decision is not another's", async () => {
    const endpoint = makeEndpoint({ restricted: true });

    hasEndpointGrantMock.mockResolvedValue(true);
    const member = await asOAuthUser(USER_ID, endpoint);
    expect(member.served).toBe(true);

    hasEndpointGrantMock.mockResolvedValue(false);
    const stranger = await asOAuthUser(OTHER_USER_ID, endpoint);
    expect(stranger.served).toBe(false);

    // And the first user's cached admission survived the second user's miss.
    hasEndpointGrantMock.mockResolvedValue(false);
    const memberAgain = await asOAuthUser(USER_ID, endpoint);
    expect(memberAgain.served).toBe(true);
  });

  it("a decision cached for one endpoint does not admit the same user to another", async () => {
    hasEndpointGrantMock.mockResolvedValue(true);
    const granted = await asOAuthUser(
      USER_ID,
      makeEndpoint({ restricted: true }),
    );
    expect(granted.served).toBe(true);

    hasEndpointGrantMock.mockResolvedValue(false);
    const other = await asOAuthUser(
      USER_ID,
      makeEndpoint({ uuid: OTHER_ENDPOINT_UUID, restricted: true }),
    );
    expect(other.served).toBe(false);
  });
});

describe("the denial is recorded", () => {
  it("emits one endpoint.access.denied row naming the user and the endpoint", async () => {
    await asOAuthUser(USER_ID, makeEndpoint({ restricted: true }));
    await flush();

    expect(accessRows()).toHaveLength(1);
    const row = accessRows()[0];
    expect(row.outcome).toBe("denied");
    expect(row.actor_type).toBe("user");
    expect(row.actor_id).toBe(USER_ID);
    expect(row.target_id).toBe(ENDPOINT_UUID);
    expect(row.http_status).toBe(403);
    expect(row.detail?.reason).toBe("access_group_denied");
    expect(row.detail?.auth_method).toBe("oauth");
  });

  it("fingerprints the presented token instead of storing it", async () => {
    await asOAuthUser(USER_ID, makeEndpoint({ restricted: true }));
    await flush();

    const row = accessRows()[0];
    const credential = row.detail?.credential as {
      sha256: string | null;
      last4: string | null;
    };
    expect(credential.sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(credential.last4).toBe(OAUTH_TOKEN.slice(-4));
    expect(JSON.stringify(row)).not.toContain(OAUTH_TOKEN);
  });

  it("THROTTLES a hammering client: one row, with the swallowed attempts counted", async () => {
    const endpoint = makeEndpoint({ restricted: true });

    // A refused connector retries. `audit_log` has no prune path, so a
    // per-attempt row would let the refused caller size a table nobody can
    // delete from.
    for (let i = 0; i < 25; i += 1) {
      // Cache invalidation between attempts so each one really re-decides and
      // really reaches the denial path, rather than being short-circuited.
      __resetEndpointAccessCacheForTesting();
      await asOAuthUser(USER_ID, endpoint);
    }
    await flush();

    expect(accessRows()).toHaveLength(1);
    // Every attempt still refused — throttling the RECORD never softens the
    // ANSWER.
    expect(hasEndpointGrantMock).toHaveBeenCalledTimes(25);
  });

  it("does not let one pair's flood suppress another pair's first row", async () => {
    const endpoint = makeEndpoint({ restricted: true });

    for (let i = 0; i < 5; i += 1) {
      __resetEndpointAccessCacheForTesting();
      await asOAuthUser(USER_ID, endpoint);
    }
    __resetEndpointAccessCacheForTesting();
    await asOAuthUser(OTHER_USER_ID, endpoint);
    await flush();

    expect(accessRows()).toHaveLength(2);
    expect(
      accessRows()
        .map((r) => r.actor_id)
        .sort(),
    ).toEqual([OTHER_USER_ID, USER_ID].sort());
  });

  it("a broken audit sink does not change the answer", async () => {
    setAuditSinkForTesting(() => {
      throw new Error("audit sink is down");
    });

    const { served, res } = await asOAuthUser(
      USER_ID,
      makeEndpoint({ restricted: true }),
    );

    expect(served).toBe(false);
    expect(res.statusCode).toBe(403);
    expect(res.body?.error_description).toBe(ENDPOINT_ACCESS_DENIED_MESSAGE);
  });
});
