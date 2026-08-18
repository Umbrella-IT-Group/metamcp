/**
 * Targeted tests for the two highest-risk behaviors flagged in the
 * review of the pool-cap work / PR #72 (fixes round):
 *
 *   (a) the idle-TTL sweep reap variant (`reapIdleSession`) preserves the
 *       `mcp_sessions` row — unlike the client-DELETE variant
 *       (`cleanupSession`) — and `recoverPersistedSession` succeeds
 *       against a row left in exactly that preserved state. This is the
 *       fix for the MAJOR finding: reaping via the row-deleting variant
 *       made a reaped session's next request 404 instead of lazily
 *       recovering, which the Anthropic/claude.ai connector turns into a
 *       persistent -32600 until a manual `/mcp reconnect`.
 *
 *   (b) `dispatchTracked` correctly holds a session in-flight for the
 *       full duration of a long-lived dispatch (the shape of a
 *       standalone GET stream, which never resolves until the client
 *       closes it), and releases it once the dispatch settles — the
 *       wiring the idle-TTL sweeper's "never reap in-flight" guard
 *       depends on (guard behavior itself is unit-tested exhaustively in
 *       `public-session-sweeper.test.ts`; this proves the router wires
 *       it correctly).
 *
 * Heavy DB-backed dependencies (`mcp-sessions.repo`, `consumer-identity-
 * resolver`, `metamcp-server-pool`, and `@/db` itself — pulled in
 * transitively via `session-lifetime-manager` -> `config.service` ->
 * `config.repo`) are mocked so this file runs with no postgres. Pure,
 * side-effect-free modules (`gateway-boot-id`, `session-auth`,
 * `log-store`, `m365/request-context`) run for real — mirrors the
 * `mcp-server-pool.test.ts` convention of mocking only the DB-touching
 * boundary, not the pure logic.
 */
import { readFileSync } from "node:fs";
import type { Server } from "node:http";
import { join } from "node:path";

import type { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import type { DatabaseEndpoint } from "@repo/zod-types";
// Value import, not `import type`: the /health/sessions gate tests below mount
// the REAL router on a real socket, which needs express itself. The default
// import still carries the `express.Request` / `express.Response` types the
// dispatch tests cast to.
import express from "express";
import {
  afterAll,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";

const h = vi.hoisted(() => ({
  isAdminHealthRequest: vi.fn<() => Promise<boolean>>(),
}));

// The gate's own fail-closed behavior (no cookie, bad session, unknown user,
// db error — all resolve false, never throw) is exhaustively tested in
// `lib/health-upstream.test.ts`. What is under test here is that
// /health/sessions CONSULTS it and withholds when it says no.
vi.mock("../../lib/health-upstream", () => ({
  isAdminHealthRequest: h.isAdminHealthRequest,
}));

vi.mock("@/utils/logger", () => ({
  default: {
    error: vi.fn(),
    warn: vi.fn(),
    info: vi.fn(),
    debug: vi.fn(),
  },
}));

// Covers every transitive `@/db` import (config.repo via config.service
// via session-lifetime-manager) that this file doesn't otherwise mock
// directly. Resolves by absolute path, so it applies regardless of
// whether an importer specifies `@/db` or a relative `../index`.
vi.mock("@/db", () => ({
  db: {},
  pool: { on: vi.fn() },
}));

vi.mock("@/middleware/api-key-oauth.middleware", () => ({
  authenticateApiKey: vi.fn(),
}));
vi.mock("@/middleware/lookup-endpoint-middleware", () => ({
  lookupEndpoint: vi.fn(),
}));
vi.mock("@/middleware/rate-limit.middleware", () => ({
  rateLimitMiddleware: vi.fn(),
}));

vi.mock("@/db/repositories/mcp-sessions.repo", () => ({
  mcpSessionsRepository: {
    persist: vi.fn().mockResolvedValue(undefined),
    findById: vi.fn(),
    touch: vi.fn().mockResolvedValue(undefined),
    delete: vi.fn().mockResolvedValue(undefined),
    pruneOlderThan: vi.fn().mockResolvedValue(0),
  },
}));

vi.mock("../../lib/metamcp/consumer-identity-resolver", () => ({
  resolveClientIdentity: vi.fn().mockResolvedValue({ name: "test-consumer" }),
}));

vi.mock("../../lib/metamcp/metamcp-server-pool", () => ({
  metaMcpServerPool: {
    getServer: vi.fn(),
    getServerInstance: vi.fn(),
    cleanupSession: vi.fn().mockResolvedValue(undefined),
    getMcpServerPoolStatus: vi.fn().mockReturnValue({ idle: 0, active: 0 }),
    getPoolStatus: vi.fn().mockReturnValue({ idle: 0, active: 0 }),
  },
}));

// hydrateRecoveredTransport's OWN correctness (SDK-internal state patch)
// is already covered by `transport-recovery-hydration.test.ts` against a
// REAL transport. This file's job is `recoverPersistedSession`'s
// orchestration (row lookup, namespace/auth checks, calls getServer, on
// success adds to sessionManager) — mocking this out lets that be tested
// without a full MCP `initialize` handshake.
vi.mock("../../lib/metamcp/transport-recovery-hydration", () => ({
  assertRecoveryHydrationContract: vi.fn(),
  hydrateRecoveredTransport: vi.fn().mockReturnValue(true),
}));

// Imported AFTER the vi.mock calls above (vitest hoists vi.mock, so these
// resolve to the mocked modules regardless of textual order, but keeping
// them below is the established convention in this repo's test files).
import { mcpSessionsRepository } from "@/db/repositories/mcp-sessions.repo";
import type { ApiKeyAuthenticatedRequest } from "@/middleware/api-key-oauth.middleware";
import { authenticateApiKey } from "@/middleware/api-key-oauth.middleware";
import { lookupEndpoint } from "@/middleware/lookup-endpoint-middleware";
import { rateLimitMiddleware } from "@/middleware/rate-limit.middleware";

import type { AuditEvent } from "../../lib/audit/audit-emitter";
import { setAuditSinkForTesting } from "../../lib/audit/audit-emitter";
import type { M365UserContext } from "../../lib/m365/request-context";
import { getM365UserContext } from "../../lib/m365/request-context";
import type { CallerContext } from "../../lib/metamcp/caller-context-store";
import { getCallerContext } from "../../lib/metamcp/caller-context-store";
import {
  GATEWAY_BOOT_ID,
  GATEWAY_CAPABILITY_HASH,
} from "../../lib/metamcp/gateway-boot-id";
import { metaMcpServerPool } from "../../lib/metamcp/metamcp-server-pool";
import { hashAuthPrincipal } from "../../lib/metamcp/session-auth";
import { __resetSessionDenialThrottleForTesting } from "../../lib/metamcp/session-binding-denial";
import streamableHttpRouter, {
  buildSessionsHealthPayload,
  cleanupSession,
  dispatchTracked,
  publicSessionSweeper,
  reapIdleSession,
  recoverPersistedSession,
  resolveBoundSession,
  resolveDeletableSession,
} from "./streamable-http";

function fakeAuthReq(
  overrides: Partial<ApiKeyAuthenticatedRequest> = {},
): ApiKeyAuthenticatedRequest {
  return {
    headers: {},
    query: {},
    ...overrides,
  } as unknown as ApiKeyAuthenticatedRequest;
}

beforeEach(() => {
  vi.clearAllMocks();
  // The refusal throttle is module state shared by every test in this file.
  // Without a reset, whether a given test sees its audit row depends on which
  // (credential, endpoint) pairs earlier tests happened to refuse — the audit
  // assertions below must pin the emitter, not the test ordering.
  __resetSessionDenialThrottleForTesting();
  (mcpSessionsRepository.delete as ReturnType<typeof vi.fn>).mockResolvedValue(
    undefined,
  );
  (mcpSessionsRepository.touch as ReturnType<typeof vi.fn>).mockResolvedValue(
    undefined,
  );
  (
    metaMcpServerPool.cleanupSession as ReturnType<typeof vi.fn>
  ).mockResolvedValue(undefined);
});

describe("reapIdleSession vs cleanupSession — row-preservation contract (item 1 / pool-cap review)", () => {
  it("reapIdleSession (the sweep reap variant) does NOT delete the mcp_sessions row", async () => {
    await reapIdleSession("sess-reap-1");

    expect(mcpSessionsRepository.delete).not.toHaveBeenCalled();
    // Still tears down the backend pool connections — only the row survives.
    expect(metaMcpServerPool.cleanupSession).toHaveBeenCalledWith(
      "sess-reap-1",
    );
  });

  it("cleanupSession (the client-DELETE variant) DOES delete the row — contrast case", async () => {
    await cleanupSession("sess-delete-1");

    expect(mcpSessionsRepository.delete).toHaveBeenCalledWith("sess-delete-1");
    expect(metaMcpServerPool.cleanupSession).toHaveBeenCalledWith(
      "sess-delete-1",
    );
  });

  it("reapIdleSession still drops in-memory sweeper tracking (forget runs regardless of deleteRow)", async () => {
    publicSessionSweeper.beginTracking("sess-reap-2");
    expect(publicSessionSweeper.getLastActivity("sess-reap-2")).toBeDefined();

    await reapIdleSession("sess-reap-2");

    expect(publicSessionSweeper.getLastActivity("sess-reap-2")).toBeUndefined();
    expect(mcpSessionsRepository.delete).not.toHaveBeenCalled();
  });
});

describe("recoverPersistedSession — succeeds against a row reapIdleSession leaves behind (item 1 / pool-cap review)", () => {
  it("recovers when the mcp_sessions row is present and matches (the exact state a sweep reap leaves)", async () => {
    const sessionId = "sess-recover-1";
    const rawToken = "test-api-key-value";
    const principal = hashAuthPrincipal(rawToken, "api_key");

    (
      mcpSessionsRepository.findById as ReturnType<typeof vi.fn>
    ).mockResolvedValueOnce({
      session_id: sessionId,
      namespace_uuid: "ns-1",
      endpoint_name: "ep-1",
      auth_principal: principal,
      auth_method: "api_key",
      init_params: {},
      created_at: new Date(),
      last_seen_at: new Date(),
      // Same process -> shouldRefuseRecovery allows regardless of
      // capability_hash; stamping both real values is the realistic case.
      gateway_boot_id: GATEWAY_BOOT_ID,
      capability_hash: GATEWAY_CAPABILITY_HASH,
    });

    const fakeServerInstance = {
      server: { connect: vi.fn().mockResolvedValue(undefined) },
      cleanup: vi.fn().mockResolvedValue(undefined),
      handlerContext: {} as Record<string, unknown>,
    };
    (
      metaMcpServerPool.getServer as ReturnType<typeof vi.fn>
    ).mockResolvedValueOnce(fakeServerInstance);

    const authReq = fakeAuthReq({
      namespaceUuid: "ns-1",
      endpointName: "ep-1",
      authMethod: "api_key",
      headers: { "x-api-key": rawToken },
    });

    const result = await recoverPersistedSession(sessionId, authReq);

    expect(result.status).toBe("recovered");
    if (result.status === "recovered") {
      expect(result.transport).toBeDefined();
    }
    // Recovery never touches the row-delete path — only reads + touches it.
    expect(mcpSessionsRepository.delete).not.toHaveBeenCalled();
    expect(fakeServerInstance.server.connect).toHaveBeenCalledTimes(1);
    // Recovery resumes idle-TTL tracking (item 3's beginTracking wiring) —
    // without this a session reaped once could never be TTL-swept again.
    expect(publicSessionSweeper.getLastActivity(sessionId)).toBeDefined();
  });

  it("refuses recovery when no row exists (e.g. an explicit client DELETE already removed it)", async () => {
    (
      mcpSessionsRepository.findById as ReturnType<typeof vi.fn>
    ).mockResolvedValueOnce(null);

    const result = await recoverPersistedSession(
      "sess-gone",
      fakeAuthReq({ namespaceUuid: "ns-1", endpointName: "ep-1" }),
    );

    expect(result.status).toBe("not_found");
    expect(metaMcpServerPool.getServer).not.toHaveBeenCalled();
  });

  it("refuses recovery when the incoming credential doesn't match the stored principal", async () => {
    const sessionId = "sess-recover-badauth";
    (
      mcpSessionsRepository.findById as ReturnType<typeof vi.fn>
    ).mockResolvedValueOnce({
      session_id: sessionId,
      namespace_uuid: "ns-1",
      endpoint_name: "ep-1",
      auth_principal: hashAuthPrincipal("the-real-token", "api_key"),
      auth_method: "api_key",
      init_params: {},
      created_at: new Date(),
      last_seen_at: new Date(),
      gateway_boot_id: GATEWAY_BOOT_ID,
      capability_hash: GATEWAY_CAPABILITY_HASH,
    });

    const authReq = fakeAuthReq({
      namespaceUuid: "ns-1",
      endpointName: "ep-1",
      authMethod: "api_key",
      headers: { "x-api-key": "a-different-token" },
    });

    const result = await recoverPersistedSession(sessionId, authReq);
    expect(result.status).toBe("auth_failed");
  });
});

describe("dispatchTracked — in-flight guard around a long-lived dispatch (item 7b / pool-cap review)", () => {
  it("holds the session in-flight for the full duration of an open standalone GET stream, then releases it", async () => {
    const sessionId = "sess-stream-1";
    publicSessionSweeper.beginTracking(sessionId);
    expect(publicSessionSweeper.getInFlight(sessionId)).toBe(0);

    let releaseStream!: () => void;
    const streamGate = new Promise<void>((resolve) => {
      releaseStream = resolve;
    });
    // A standalone GET stream's `handleRequest` doesn't resolve until the
    // client closes the stream — simulated here as a gated promise that
    // stays pending until the test explicitly releases it.
    const fakeTransport = {
      handleRequest: vi.fn().mockImplementation(async () => {
        await streamGate;
      }),
    } as unknown as StreamableHTTPServerTransport;

    const authReq = fakeAuthReq();
    const fakeReq = {} as express.Request;
    const fakeRes = {} as express.Response;

    const dispatchPromise = dispatchTracked(
      authReq,
      fakeTransport,
      fakeReq,
      fakeRes,
      sessionId,
    );

    // Let the microtask queue advance so markInFlight (called before the
    // first await inside the dispatch) has definitely run.
    await Promise.resolve();
    expect(publicSessionSweeper.getInFlight(sessionId)).toBe(1);
    // Still tracked and NOT idle-reapable while in-flight — this is the
    // exact state the sweeper's candidate scan skips (see
    // `public-session-sweeper.test.ts`'s in-flight guard tests).
    expect(publicSessionSweeper.getLastActivity(sessionId)).toBeDefined();

    releaseStream();
    await dispatchPromise;

    expect(publicSessionSweeper.getInFlight(sessionId)).toBe(0);
    // Settling re-stamps activity rather than clearing it — the session
    // becomes reapable only after a further idle stretch, not instantly.
    expect(publicSessionSweeper.getLastActivity(sessionId)).toBeDefined();
  });

  it("releases in-flight even when the dispatch throws", async () => {
    const sessionId = "sess-stream-error";
    publicSessionSweeper.beginTracking(sessionId);

    const fakeTransport = {
      handleRequest: vi.fn().mockRejectedValue(new Error("boom")),
    } as unknown as StreamableHTTPServerTransport;

    await expect(
      dispatchTracked(
        fakeAuthReq(),
        fakeTransport,
        {} as express.Request,
        {} as express.Response,
        sessionId,
      ),
    ).rejects.toThrow("boom");

    expect(publicSessionSweeper.getInFlight(sessionId)).toBe(0);
  });
});

/**
 * Seed a session into the module's real `sessionManager` by driving the
 * recovery path — the same path production uses to repopulate the in-memory
 * map, and therefore the path that records the session's endpoint + identity
 * binding. `creator` describes the credential the session is created UNDER;
 * the persisted row is derived from it so recovery genuinely succeeds rather
 * than being forced.
 */
async function seedBoundSession(
  sessionId: string,
  namespaceUuid: string,
  endpointName: string,
  creator: Partial<ApiKeyAuthenticatedRequest> = {},
): Promise<void> {
  const authMethod = creator.authMethod ?? "api_key";
  const headers =
    creator.headers ??
    (authMethod === "oauth"
      ? { authorization: "Bearer bound-token-value" }
      : { "x-api-key": "bound-key-value" });
  const apiKeyHeader = headers["x-api-key"];
  const rawToken =
    typeof apiKeyHeader === "string"
      ? apiKeyHeader
      : (headers.authorization as string).substring(7);
  (
    mcpSessionsRepository.findById as ReturnType<typeof vi.fn>
  ).mockResolvedValueOnce({
    session_id: sessionId,
    namespace_uuid: namespaceUuid,
    endpoint_name: endpointName,
    auth_principal: hashAuthPrincipal(rawToken, authMethod),
    auth_method: authMethod,
    init_params: {},
    created_at: new Date(),
    last_seen_at: new Date(),
    gateway_boot_id: GATEWAY_BOOT_ID,
    capability_hash: GATEWAY_CAPABILITY_HASH,
  });
  (
    metaMcpServerPool.getServer as ReturnType<typeof vi.fn>
  ).mockResolvedValueOnce({
    server: { connect: vi.fn().mockResolvedValue(undefined) },
    cleanup: vi.fn().mockResolvedValue(undefined),
    handlerContext: {} as Record<string, unknown>,
  });
  const result = await recoverPersistedSession(
    sessionId,
    fakeAuthReq({
      namespaceUuid,
      endpointName,
      ...creator,
      authMethod,
      headers,
    }),
  );
  expect(result.status).toBe("recovered");
}

describe("resolveBoundSession — ownership guard on the in-memory lookup (cross-endpoint AND cross-credential session replay)", () => {
  it("serves the transport when the request targets the SAME endpoint under the SAME credential", async () => {
    const sessionId = "sess-bound-match";
    await seedBoundSession(sessionId, "ns-A", "ep-A", {
      apiKeyUuid: "key-A-uuid",
    });

    const resolved = resolveBoundSession(
      sessionId,
      fakeAuthReq({
        namespaceUuid: "ns-A",
        endpointName: "ep-A",
        authMethod: "api_key",
        apiKeyUuid: "key-A-uuid",
      }),
    );
    expect(resolved.outcome).toBe("ok");
    if (resolved.outcome === "ok") {
      expect(resolved.transport).toBeDefined();
    }
  });

  it("refuses when a key for a DIFFERENT endpoint presents this session id (the cross-endpoint replay attempt)", async () => {
    const sessionId = "sess-bound-mismatch";
    await seedBoundSession(sessionId, "ns-A", "ep-A", {
      apiKeyUuid: "key-A-uuid",
    });

    // Same live session id, but the caller is authenticated for endpoint B.
    // The lookup must NOT hand them endpoint A's transport.
    const wrongEndpoint = resolveBoundSession(
      sessionId,
      fakeAuthReq({
        namespaceUuid: "ns-B",
        endpointName: "ep-B",
        authMethod: "api_key",
        apiKeyUuid: "key-A-uuid",
      }),
    );
    expect(wrongEndpoint.outcome).toBe("refused");

    // A partial match (right namespace, wrong endpoint name) is still a miss.
    const wrongName = resolveBoundSession(
      sessionId,
      fakeAuthReq({
        namespaceUuid: "ns-A",
        endpointName: "ep-B",
        authMethod: "api_key",
        apiKeyUuid: "key-A-uuid",
      }),
    );
    expect(wrongName.outcome).toBe("refused");
  });

  it("reports `absent` for a session id that isn't resident in memory, so lazy recovery still runs", () => {
    const resolved = resolveBoundSession(
      "sess-never-seen",
      fakeAuthReq({
        namespaceUuid: "ns-A",
        endpointName: "ep-A",
        authMethod: "api_key",
        apiKeyUuid: "key-A-uuid",
      }),
    );
    expect(resolved.outcome).toBe("absent");
  });

  it("refuses a session created under api key A when key B presents its id on the SAME endpoint", async () => {
    // The defect this guard closes: both keys authenticate for ep-A, so the
    // endpoint half of the binding matched and the pooled transport was
    // handed straight to B.
    const sessionId = "sess-cred-replay";
    await seedBoundSession(sessionId, "ns-A", "ep-A", {
      apiKeyUuid: "key-A-uuid",
    });

    const foreign = resolveBoundSession(
      sessionId,
      fakeAuthReq({
        namespaceUuid: "ns-A",
        endpointName: "ep-A",
        authMethod: "api_key",
        apiKeyUuid: "key-B-uuid",
      }),
    );
    expect(foreign.outcome).toBe("refused");
  });

  it("refuses when an OAuth caller presents an api key's session id on the same endpoint", async () => {
    const sessionId = "sess-cred-crossmethod";
    await seedBoundSession(sessionId, "ns-A", "ep-A", {
      apiKeyUuid: "key-A-uuid",
    });

    const foreign = resolveBoundSession(
      sessionId,
      fakeAuthReq({
        namespaceUuid: "ns-A",
        endpointName: "ep-A",
        authMethod: "oauth",
        oauthUserId: "key-A-uuid",
      }),
    );
    expect(foreign.outcome).toBe("refused");
  });

  it("keeps serving an OAuth caller whose access token was refreshed (identity is the user, not the token)", async () => {
    // A connector refreshes its 24h access token while holding the same
    // Mcp-Session-Id. Binding to the token would force a re-initialize on
    // every refresh; binding to the user id does not.
    const sessionId = "sess-oauth-refresh";
    await seedBoundSession(sessionId, "ns-A", "ep-A", {
      authMethod: "oauth",
      oauthUserId: "user-1",
      headers: { authorization: "Bearer first-token" },
    });

    const afterRefresh = resolveBoundSession(
      sessionId,
      fakeAuthReq({
        namespaceUuid: "ns-A",
        endpointName: "ep-A",
        authMethod: "oauth",
        oauthUserId: "user-1",
        headers: { authorization: "Bearer second-token" },
      }),
    );
    expect(afterRefresh.outcome).toBe("ok");
  });

  it("refuses when a DIFFERENT OAuth user presents the session id", async () => {
    const sessionId = "sess-oauth-foreign-user";
    await seedBoundSession(sessionId, "ns-A", "ep-A", {
      authMethod: "oauth",
      oauthUserId: "user-1",
      headers: { authorization: "Bearer first-token" },
    });

    const foreign = resolveBoundSession(
      sessionId,
      fakeAuthReq({
        namespaceUuid: "ns-A",
        endpointName: "ep-A",
        authMethod: "oauth",
        oauthUserId: "user-2",
        headers: { authorization: "Bearer other-users-token" },
      }),
    );
    expect(foreign.outcome).toBe("refused");
  });

  it("writes an mcp.auth.denied audit row naming the presenting credential and the targeted session", async () => {
    const sessionId = "sess-cred-audited";
    await seedBoundSession(sessionId, "ns-A", "ep-A", {
      apiKeyUuid: "key-A-uuid",
    });

    const events: AuditEvent[] = [];
    setAuditSinkForTesting(async (event) => {
      events.push(event);
    });
    try {
      resolveBoundSession(
        sessionId,
        fakeAuthReq({
          namespaceUuid: "ns-A",
          endpointName: "ep-A",
          endpoint: { uuid: "ep-A-uuid" } as DatabaseEndpoint,
          authMethod: "api_key",
          apiKeyUuid: "key-B-uuid",
          headers: { "x-api-key": "the-other-key-value" },
        }),
      );
      // emit() resolves its sink asynchronously; let the microtask queue drain.
      await Promise.resolve();
      await Promise.resolve();
    } finally {
      setAuditSinkForTesting(undefined);
    }

    expect(events).toHaveLength(1);
    const [event] = events;
    expect(event.action).toBe("mcp.auth.denied");
    expect(event.outcome).toBe("denied");
    expect(event.http_status).toBe(404);
    // The refusal names the caller who tried, not the session's owner.
    expect(event.actor_type).toBe("api_key");
    expect(event.actor_id).toBe("key-B-uuid");
    expect(event.target_id).toBe("ep-A-uuid");
    expect(event.detail?.reason).toBe("session_credential_mismatch");
    expect(event.detail?.session_id).toBe(sessionId);
    // The credential is fingerprinted, never stored.
    const credential = event.detail?.credential as {
      sha256: string | null;
      last4: string | null;
    };
    expect(credential.last4).toBe("alue");
    expect(JSON.stringify(event)).not.toContain("the-other-key-value");
  });

  it("audits a cross-endpoint replay as an ENDPOINT mismatch, not as a credential one", async () => {
    // Sibling of the case above and the one the hardcoded reason got wrong:
    // the SAME credential presenting the id on the WRONG endpoint. The
    // response is byte-identical either way, so `detail.reason` is the only
    // place these two classes are ever separable — and it is written to a
    // table migration 0028 makes append-only.
    const sessionId = "sess-endpoint-audited";
    await seedBoundSession(sessionId, "ns-A", "ep-A", {
      apiKeyUuid: "key-A-uuid",
    });

    const events: AuditEvent[] = [];
    setAuditSinkForTesting(async (event) => {
      events.push(event);
    });
    try {
      resolveBoundSession(
        sessionId,
        fakeAuthReq({
          namespaceUuid: "ns-B",
          endpointName: "ep-B",
          endpoint: { uuid: "ep-B-uuid" } as DatabaseEndpoint,
          authMethod: "api_key",
          apiKeyUuid: "key-A-uuid",
          headers: { "x-api-key": "bound-key-value" },
        }),
      );
      await Promise.resolve();
      await Promise.resolve();
    } finally {
      setAuditSinkForTesting(undefined);
    }

    expect(events).toHaveLength(1);
    expect(events[0].detail?.reason).toBe("session_endpoint_mismatch");
    expect(events[0].detail?.session_id).toBe(sessionId);
  });

  it("collapses a burst of refusals from one credential into ONE row carrying the swallowed count", async () => {
    // `audit_log` has no prune path (migration 0028), so an un-throttled row
    // per attempt is permanent storage a REFUSED caller paces. Walking session
    // ids is exactly the shape that would exploit it.
    const events: AuditEvent[] = [];
    setAuditSinkForTesting(async (event) => {
      events.push(event);
    });
    try {
      for (let i = 0; i < 30; i += 1) {
        const sessionId = `sess-burst-${i}`;
        await seedBoundSession(sessionId, "ns-A", "ep-A", {
          apiKeyUuid: "key-A-uuid",
        });
        resolveBoundSession(
          sessionId,
          fakeAuthReq({
            namespaceUuid: "ns-A",
            endpointName: "ep-A",
            endpoint: { uuid: "ep-A-uuid" } as DatabaseEndpoint,
            authMethod: "api_key",
            apiKeyUuid: "key-attacker-uuid",
            headers: { "x-api-key": "attacker-key-value" },
          }),
        );
      }
      await Promise.resolve();
      await Promise.resolve();
    } finally {
      setAuditSinkForTesting(undefined);
    }

    expect(events).toHaveLength(1);
    expect(events[0].detail?.suppressed_since_last).toBe(0);
  });
});

describe("resolveDeletableSession — ownership guard on the DELETE leg (round 2: guard was untested)", () => {
  /** The credential the sessions below are created under. */
  const OWNER_TOKEN = "owner-key-value";
  const ownerReq = (namespaceUuid: string, endpointName: string) =>
    fakeAuthReq({
      namespaceUuid,
      endpointName,
      authMethod: "api_key",
      apiKeyUuid: "key-owner-uuid",
      headers: { "x-api-key": OWNER_TOKEN },
    });
  /** A second credential that authenticates fine — for a different consumer. */
  const siblingReq = (namespaceUuid: string, endpointName: string) =>
    fakeAuthReq({
      namespaceUuid,
      endpointName,
      authMethod: "api_key",
      apiKeyUuid: "key-sibling-uuid",
      headers: { "x-api-key": "sibling-key-value" },
    });

  /** A persisted mcp_sessions row shaped like findById returns it. */
  function storedRow(
    namespaceUuid: string,
    endpointName: string,
    rawToken = OWNER_TOKEN,
  ) {
    return {
      session_id: "irrelevant",
      namespace_uuid: namespaceUuid,
      endpoint_name: endpointName,
      auth_principal: hashAuthPrincipal(rawToken, "api_key"),
      auth_method: "api_key",
      init_params: {},
      created_at: new Date(),
      last_seen_at: new Date(),
      gateway_boot_id: GATEWAY_BOOT_ID,
      capability_hash: GATEWAY_CAPABILITY_HASH,
    };
  }

  const owner: Partial<ApiKeyAuthenticatedRequest> = {
    apiKeyUuid: "key-owner-uuid",
    headers: { "x-api-key": OWNER_TOKEN },
  };

  it("allows the delete when the IN-MEMORY session belongs to the requesting endpoint AND credential", async () => {
    const sessionId = "sess-del-mem-match";
    await seedBoundSession(sessionId, "ns-A", "ep-A", owner);
    // Seeding itself goes through recoverPersistedSession -> findById;
    // reset call history so the assertion below sees ONLY the resolver.
    (mcpSessionsRepository.findById as ReturnType<typeof vi.fn>).mockClear();

    const resolution = await resolveDeletableSession(
      sessionId,
      ownerReq("ns-A", "ep-A"),
    );
    expect(resolution).toEqual({ outcome: "deletable" });
    // The in-memory branch never needs the DB.
    expect(mcpSessionsRepository.findById).not.toHaveBeenCalled();
  });

  it("refuses (not_found) when the in-memory session is bound to a DIFFERENT endpoint — cross-endpoint teardown DoS", async () => {
    const sessionId = "sess-del-mem-cross";
    await seedBoundSession(sessionId, "ns-A", "ep-A", owner);

    const resolution = await resolveDeletableSession(
      sessionId,
      ownerReq("ns-B", "ep-B"),
    );
    expect(resolution).toEqual({ outcome: "not_found" });
  });

  it("refuses (not_found) when a SIBLING credential on the same endpoint tries to tear the session down", async () => {
    // `cleanupSession` also drops the mcp_sessions row, so an unguarded
    // DELETE lets any second key on the endpoint end another consumer's
    // session AND its recovery path with nothing but the session id.
    const sessionId = "sess-del-mem-sibling";
    await seedBoundSession(sessionId, "ns-A", "ep-A", owner);

    const resolution = await resolveDeletableSession(
      sessionId,
      siblingReq("ns-A", "ep-A"),
    );
    expect(resolution).toEqual({ outcome: "not_found" });
  });

  it("allows the delete when the session is NOT resident but the persisted row matches endpoint AND credential (findById branch)", async () => {
    (
      mcpSessionsRepository.findById as ReturnType<typeof vi.fn>
    ).mockResolvedValueOnce(storedRow("ns-A", "ep-A"));

    const resolution = await resolveDeletableSession(
      "sess-del-row-match",
      ownerReq("ns-A", "ep-A"),
    );
    expect(resolution).toEqual({ outcome: "deletable" });
  });

  it("refuses (not_found) when the persisted row belongs to another endpoint — recovery-row deletion stays owner-only", async () => {
    (
      mcpSessionsRepository.findById as ReturnType<typeof vi.fn>
    ).mockResolvedValueOnce(storedRow("ns-A", "ep-A"));

    const resolution = await resolveDeletableSession(
      "sess-del-row-cross",
      ownerReq("ns-B", "ep-B"),
    );
    expect(resolution).toEqual({ outcome: "not_found" });
  });

  it("refuses (not_found) when the persisted row belongs to another CREDENTIAL on the same endpoint", async () => {
    // The sweeper preserves rows for reaped sessions by design, so the
    // not-resident branch is a normal state rather than an edge case — and
    // an endpoint check alone would leave exactly those sessions deletable
    // by any sibling key.
    (
      mcpSessionsRepository.findById as ReturnType<typeof vi.fn>
    ).mockResolvedValueOnce(storedRow("ns-A", "ep-A"));

    const resolution = await resolveDeletableSession(
      "sess-del-row-sibling",
      siblingReq("ns-A", "ep-A"),
    );
    expect(resolution).toEqual({ outcome: "not_found" });
  });

  it("refuses (not_found) when the persisted row was created under a different auth METHOD", async () => {
    (
      mcpSessionsRepository.findById as ReturnType<typeof vi.fn>
    ).mockResolvedValueOnce(storedRow("ns-A", "ep-A"));

    const resolution = await resolveDeletableSession(
      "sess-del-row-method",
      fakeAuthReq({
        namespaceUuid: "ns-A",
        endpointName: "ep-A",
        authMethod: "oauth",
        oauthUserId: "user-1",
        headers: { authorization: `Bearer ${OWNER_TOKEN}` },
      }),
    );
    expect(resolution).toEqual({ outcome: "not_found" });
  });

  it("refuses (not_found) when the request carries no recognizable credential at all", async () => {
    (
      mcpSessionsRepository.findById as ReturnType<typeof vi.fn>
    ).mockResolvedValueOnce(storedRow("ns-A", "ep-A"));

    const resolution = await resolveDeletableSession(
      "sess-del-row-nocred",
      fakeAuthReq({
        namespaceUuid: "ns-A",
        endpointName: "ep-A",
        authMethod: "api_key",
        apiKeyUuid: "key-owner-uuid",
      }),
    );
    expect(resolution).toEqual({ outcome: "not_found" });
  });

  it("refuses (not_found) when no session exists anywhere", async () => {
    (
      mcpSessionsRepository.findById as ReturnType<typeof vi.fn>
    ).mockResolvedValueOnce(null);

    const resolution = await resolveDeletableSession(
      "sess-del-absent",
      ownerReq("ns-A", "ep-A"),
    );
    expect(resolution).toEqual({ outcome: "not_found" });
  });

  it("treats a DB lookup FAILURE as absent (fail-closed: never delete on unknown state)", async () => {
    (
      mcpSessionsRepository.findById as ReturnType<typeof vi.fn>
    ).mockRejectedValueOnce(new Error("connection refused"));

    const resolution = await resolveDeletableSession(
      "sess-del-db-error",
      ownerReq("ns-A", "ep-A"),
    );
    expect(resolution).toEqual({ outcome: "not_found" });
  });

  it("404-shaping: absent, cross-endpoint, foreign-credential and lookup-failure produce IDENTICAL resolutions — the response cannot distinguish them", async () => {
    const crossTarget = ownerReq("ns-B", "ep-B");

    (
      mcpSessionsRepository.findById as ReturnType<typeof vi.fn>
    ).mockResolvedValueOnce(null);
    const absent = await resolveDeletableSession(
      "sess-shape-absent",
      crossTarget,
    );

    (
      mcpSessionsRepository.findById as ReturnType<typeof vi.fn>
    ).mockResolvedValueOnce(storedRow("ns-A", "ep-A"));
    const cross = await resolveDeletableSession(
      "sess-shape-cross",
      crossTarget,
    );

    (
      mcpSessionsRepository.findById as ReturnType<typeof vi.fn>
    ).mockResolvedValueOnce(storedRow("ns-A", "ep-A"));
    const foreign = await resolveDeletableSession(
      "sess-shape-foreign",
      siblingReq("ns-A", "ep-A"),
    );

    (
      mcpSessionsRepository.findById as ReturnType<typeof vi.fn>
    ).mockRejectedValueOnce(new Error("boom"));
    const dbError = await resolveDeletableSession("sess-shape-db", crossTarget);

    // One outcome, zero variants — the route's single 404 site sees the
    // same object shape for all four, so the id being live and owned by
    // someone else is unobservable from the response.
    expect(absent).toEqual({ outcome: "not_found" });
    expect(cross).toEqual(absent);
    expect(foreign).toEqual(absent);
    expect(dbError).toEqual(absent);
  });

  it("audits the RESIDENT refusal — a sibling credential's teardown attempt leaves a queryable row", async () => {
    const sessionId = "sess-del-audit-mem";
    await seedBoundSession(sessionId, "ns-A", "ep-A", owner);

    const events: AuditEvent[] = [];
    setAuditSinkForTesting(async (event) => {
      events.push(event);
    });
    try {
      const resolution = await resolveDeletableSession(sessionId, {
        ...siblingReq("ns-A", "ep-A"),
        endpoint: { uuid: "ep-A-uuid" } as DatabaseEndpoint,
      } as ApiKeyAuthenticatedRequest);
      expect(resolution).toEqual({ outcome: "not_found" });
      await Promise.resolve();
      await Promise.resolve();
    } finally {
      setAuditSinkForTesting(undefined);
    }

    expect(events).toHaveLength(1);
    expect(events[0].action).toBe("mcp.auth.denied");
    expect(events[0].http_status).toBe(404);
    expect(events[0].detail?.reason).toBe("session_credential_mismatch");
    expect(events[0].detail?.session_id).toBe(sessionId);
    expect(events[0].actor_id).toBe("key-sibling-uuid");
  });

  it("audits the NOT-RESIDENT refusal — the reaped-session teardown attempt is not silent either", async () => {
    // The sweeper preserves rows for reaped sessions by design, so this is a
    // normal steady state, and `cleanupSession` would drop the row along with
    // the session. A refusal here must be as visible as the resident one.
    (
      mcpSessionsRepository.findById as ReturnType<typeof vi.fn>
    ).mockResolvedValueOnce(storedRow("ns-A", "ep-A"));

    const events: AuditEvent[] = [];
    setAuditSinkForTesting(async (event) => {
      events.push(event);
    });
    try {
      const resolution = await resolveDeletableSession("sess-del-audit-row", {
        ...siblingReq("ns-A", "ep-A"),
        endpoint: { uuid: "ep-A-uuid" } as DatabaseEndpoint,
      } as ApiKeyAuthenticatedRequest);
      expect(resolution).toEqual({ outcome: "not_found" });
      await Promise.resolve();
      await Promise.resolve();
    } finally {
      setAuditSinkForTesting(undefined);
    }

    expect(events).toHaveLength(1);
    // Distinct from the in-memory reasons: there is no binding to classify
    // here, only the persisted principal hash.
    expect(events[0].detail?.reason).toBe(
      "session_persisted_credential_mismatch",
    );
    expect(events[0].detail?.session_id).toBe("sess-del-audit-row");
  });

  it("does NOT audit a genuine miss — only a refusal is worth a permanent row", async () => {
    (
      mcpSessionsRepository.findById as ReturnType<typeof vi.fn>
    ).mockResolvedValueOnce(null);

    const events: AuditEvent[] = [];
    setAuditSinkForTesting(async (event) => {
      events.push(event);
    });
    try {
      const resolution = await resolveDeletableSession("sess-del-audit-miss", {
        ...ownerReq("ns-A", "ep-A"),
        endpoint: { uuid: "ep-A-uuid" } as DatabaseEndpoint,
      } as ApiKeyAuthenticatedRequest);
      expect(resolution).toEqual({ outcome: "not_found" });
      await Promise.resolve();
      await Promise.resolve();
    } finally {
      setAuditSinkForTesting(undefined);
    }

    expect(events).toHaveLength(0);
  });
});

describe("buildSessionsHealthPayload — no session ids leaked (HIGH: /health/sessions id disclosure)", () => {
  it("publishes aggregate counts + sweeper stats but never the session id list", () => {
    const payload = buildSessionsHealthPayload(true);
    const sessions = payload.streamableHttpSessions as Record<string, unknown>;

    // The old payload carried `streamableHttpSessions.sessionIds: [...]` —
    // every live consumer's Mcp-Session-Id, unauthenticated. It must be gone.
    expect(sessions).toHaveProperty("count");
    expect(sessions).not.toHaveProperty("sessionIds");
    expect(JSON.stringify(payload)).not.toContain("sessionIds");
    // Monitoring still gets what it consumes.
    expect(typeof sessions.count).toBe("number");
    expect(payload.publicSessionSweeper).toBeDefined();
  });

  it("projects metaMcpPoolStatus to counts, dropping the pool's id lists", () => {
    // The removal above took `sessionIds` off the TOP level, but
    // `metaMcpPoolStatus` spread `getPoolStatus()` whole — and that returns
    // `activeSessionIds` (the same replay material, one level down) plus
    // `idleNamespaceUuids`. The default mock returns only counts, so the
    // leak was invisible until the real shape is returned here.
    vi.mocked(metaMcpServerPool.getPoolStatus).mockReturnValueOnce({
      idle: 2,
      active: 3,
      activeSessionIds: ["sess-live-1", "sess-live-2", "sess-live-3"],
      idleNamespaceUuids: ["ns-uuid-A", "ns-uuid-B"],
    });

    const payload = buildSessionsHealthPayload(true);
    const sessions = payload.streamableHttpSessions as { count: number };

    expect(
      Object.keys(payload.metaMcpPoolStatus as Record<string, unknown>).sort(),
    ).toEqual(["active", "idle"]);
    const serialised = JSON.stringify(payload);
    for (const secret of [
      "activeSessionIds",
      "idleNamespaceUuids",
      "sess-live-1",
      "ns-uuid-A",
    ]) {
      expect(serialised).not.toContain(secret);
    }
    // The counts a monitor alarms on survive, including the rollup that
    // reads `active` off the same status object.
    expect(payload.metaMcpPoolStatus).toEqual({ idle: 2, active: 3 });
    expect(payload.totalActiveSessions).toBe(sessions.count + 3);
  });
});

/**
 * The /health/sessions admin gate.
 *
 * The counts above are not secrets about a consumer — they are live intel
 * about the GATEWAY: its current scale and load, plus the sweeper's TTL,
 * sweep interval and reap counters, i.e. how long an abandoned session
 * survives and how many are in flight. That is enough to size a
 * resource-exhaustion attempt against the backend pool cap and time it
 * between sweeps, and it was served to anyone who could reach the host. Same
 * shape of fix as `/health/upstream` (`servers[]` + `pool`) and `GET
 * /metamcp/` (the estate listing): withhold the detail, keep the 200.
 */
describe("buildSessionsHealthPayload — detail is admin-only", () => {
  it("gives a non-admin caller status only — no counts, no pool, no sweeper", () => {
    expect(buildSessionsHealthPayload(false)).toEqual({ status: "ok" });
  });

  it("does not even read the session manager, pool or sweeper for a non-admin", () => {
    // Additive by construction: the detail is never BUILT, not built-then-
    // redacted, so a field added to it later cannot leak by someone
    // forgetting a delete-list. Mirrors the estate gate's "does not even
    // query the database for an anonymous caller".
    const getStats = vi.spyOn(publicSessionSweeper, "getStats");

    buildSessionsHealthPayload(false);

    expect(metaMcpServerPool.getPoolStatus).not.toHaveBeenCalled();
    expect(getStats).not.toHaveBeenCalled();
    getStats.mockRestore();
  });

  it("keeps the admin body on the same status base, detail on top", () => {
    const payload = buildSessionsHealthPayload(true);

    expect(payload.status).toBe("ok");
    expect(Object.keys(payload).sort()).toEqual([
      "metaMcpPoolStatus",
      "publicSessionSweeper",
      "status",
      "streamableHttpSessions",
      "timestamp",
      "totalActiveSessions",
    ]);
  });
});

/**
 * Route-level proof over a REAL socket, mirroring
 * `public-metamcp.estate-gate.test.ts`. The unit tests above pin the builder;
 * these pin the WIRING — that the handler consults the gate at all and passes
 * its answer through. Reverting the handler to call the builder with a
 * hard-coded `true` leaves every unit test above green and only these red.
 */
describe("GET /health/sessions — route consults the admin gate", () => {
  /** `Response.json()` is typed `unknown`; every body here is an object. */
  const readJson = async (
    response: Response,
  ): Promise<Record<string, unknown>> =>
    (await response.json()) as Record<string, unknown>;

  let server: Server;
  let baseUrl = "";

  beforeAll(async () => {
    const app = express();
    app.use("/metamcp", streamableHttpRouter);
    await new Promise<void>((resolve) => {
      server = app.listen(0, "127.0.0.1", resolve);
    });
    const address = server.address();
    if (typeof address === "object" && address) {
      baseUrl = `http://127.0.0.1:${address.port}`;
    }
  });

  afterAll(async () => {
    // Restore the file-wide default: `clearAllMocks` does not reset
    // implementations, so the stub below would otherwise follow this block
    // into any describe added after it.
    vi.mocked(metaMcpServerPool.getPoolStatus).mockReturnValue({
      idle: 0,
      active: 0,
      activeSessionIds: [],
      idleNamespaceUuids: [],
    });
    await new Promise((resolve) => server.close(resolve));
  });

  beforeEach(() => {
    // Runs after the file-level beforeEach's clearAllMocks.
    h.isAdminHealthRequest.mockResolvedValue(false);
    // Full pool shape, ids included: the anonymous body must contain neither
    // the counts nor the ids, and the ADMIN body must carry the counts while
    // still projecting the ids out.
    vi.mocked(metaMcpServerPool.getPoolStatus).mockReturnValue({
      idle: 7,
      active: 11,
      activeSessionIds: ["sess-route-live-1"],
      idleNamespaceUuids: ["ns-uuid-route-A"],
    });
  });

  it("gives an anonymous caller a bare 200 liveness body and nothing else", async () => {
    const response = await fetch(`${baseUrl}/metamcp/health/sessions`);
    const body = await readJson(response);

    // 200, not 401: an external monitor on this path must keep working.
    expect(response.status).toBe(200);
    expect(body).toEqual({ status: "ok" });
    for (const withheld of [
      "streamableHttpSessions",
      "metaMcpPoolStatus",
      "totalActiveSessions",
      "publicSessionSweeper",
      "timestamp",
    ]) {
      expect(body).not.toHaveProperty(withheld);
    }
  });

  it("leaks no count, TTL or sweep interval to an anonymous caller", async () => {
    const response = await fetch(`${baseUrl}/metamcp/health/sessions`);
    const serialised = JSON.stringify(await readJson(response));

    // The pool numbers stubbed above, and the sweeper's own knobs — the
    // material that sizes and times a pool-exhaustion attempt — plus the
    // session ids a prior fix took off this endpoint.
    for (const secret of [
      "11",
      "ttlSeconds",
      "intervalSeconds",
      "inFlightSessions",
      "trackedSessions",
      "totalSweeps",
      "sess-route-live-1",
      "ns-uuid-route-A",
    ]) {
      expect(serialised).not.toContain(secret);
    }
  });

  it("consults the gate on every request", async () => {
    await fetch(`${baseUrl}/metamcp/health/sessions`);

    expect(h.isAdminHealthRequest).toHaveBeenCalledTimes(1);
  });

  it("gives an admin the full operational detail", async () => {
    h.isAdminHealthRequest.mockResolvedValue(true);

    const response = await fetch(`${baseUrl}/metamcp/health/sessions`);
    const body = await readJson(response);

    const sessions = body.streamableHttpSessions as { count: number };

    expect(response.status).toBe(200);
    expect(body.status).toBe("ok");
    expect(body.metaMcpPoolStatus).toEqual({ idle: 7, active: 11 });
    // Count comes from the REAL session manager, which earlier describes in
    // this file seed — assert the rollup relation, not a fixed number.
    expect(typeof sessions.count).toBe("number");
    expect(body.totalActiveSessions).toBe(sessions.count + 11);
    expect(body.publicSessionSweeper).toHaveProperty("ttlSeconds");
    expect(typeof body.timestamp).toBe("string");
    // Admin-only is not a licence to re-publish the session ids the prior
    // fix removed — they stay projected out of the detail half too.
    const serialised = JSON.stringify(body);
    for (const secret of ["sess-route-live-1", "ns-uuid-route-A"]) {
      expect(serialised).not.toContain(secret);
    }
  });

  it("still answers 200 with the withheld body if the gate itself throws", async () => {
    // `isAdminHealthRequest` is contractually non-throwing, but express 4 does
    // not catch an async handler's rejection — a regression there would hang
    // the request and take the liveness probe down. Fail closed, keep the 200.
    h.isAdminHealthRequest.mockRejectedValue(new Error("auth backend down"));

    const response = await fetch(`${baseUrl}/metamcp/health/sessions`);
    const body = await readJson(response);

    expect(response.status).toBe(200);
    expect(body).toEqual({ status: "ok" });
  });
});

/**
 * The m365 delegated-identity context gate (PR: api-key-bound identity).
 * `handleRequestWithUserContext` is module-private; `dispatchTracked` is its
 * only production caller, so the gate is exercised through it with the REAL
 * `m365/request-context` (unmocked — the fake transport reads the
 * AsyncLocalStorage from inside the dispatch, exactly where the injected
 * fetch would).
 */
describe("m365 identity gate (via dispatchTracked) — oauth + acts-as api keys inject, everything else fail-closes", () => {
  /** Transport that captures the m365 context visible inside the dispatch. */
  function contextCapturingTransport(captured: {
    context: M365UserContext | undefined;
  }): StreamableHTTPServerTransport {
    return {
      handleRequest: vi.fn().mockImplementation(async () => {
        captured.context = getM365UserContext();
      }),
    } as unknown as StreamableHTTPServerTransport;
  }

  async function dispatchAndCaptureContext(
    authReq: ApiKeyAuthenticatedRequest,
    sessionId: string,
  ): Promise<M365UserContext | undefined> {
    publicSessionSweeper.beginTracking(sessionId);
    const captured: { context: M365UserContext | undefined } = {
      context: undefined,
    };
    await dispatchTracked(
      authReq,
      contextCapturingTransport(captured),
      {} as express.Request,
      {} as express.Response,
      sessionId,
    );
    return captured.context;
  }

  it("OAuth consumer: injects the OAuth user's id (unchanged behavior)", async () => {
    const context = await dispatchAndCaptureContext(
      fakeAuthReq({ authMethod: "oauth", oauthUserId: "oauth-user-1" }),
      "sess-gate-oauth",
    );
    expect(context).toEqual({ userId: "oauth-user-1" });
  });

  it("api-key consumer WITH an acts-as binding: injects the bound user's id", async () => {
    const context = await dispatchAndCaptureContext(
      fakeAuthReq({
        authMethod: "api_key",
        apiKeyUserId: "key-owner-1",
        apiKeyActsAsUserId: "acted-as-user-1",
      }),
      "sess-gate-acts-as",
    );
    expect(context).toEqual({ userId: "acted-as-user-1" });
  });

  it("api-key consumer WITHOUT a binding: NO context — the injected fetch fail-closes", async () => {
    const context = await dispatchAndCaptureContext(
      fakeAuthReq({
        authMethod: "api_key",
        apiKeyUserId: "key-owner-1",
        // apiKeyActsAsUserId deliberately absent (NULL binding).
      }),
      "sess-gate-unbound",
    );
    expect(context).toBeUndefined();
    // Explicitly: the key owner's id is NEVER used as an identity — an
    // api key acting as its creator is the exact hazard this gate refuses.
    expect(context?.userId).not.toBe("key-owner-1");
  });

  it("OAuth branch takes precedence: with both oauthUserId and an acts-as id stamped, the OAuth id wins", async () => {
    // Shouldn't be reachable (the middleware sets exactly one authMethod and
    // its matching fields), but the precedence must hold even if a future
    // middleware change stamps both.
    const context = await dispatchAndCaptureContext(
      fakeAuthReq({
        authMethod: "oauth",
        oauthUserId: "oauth-user-1",
        apiKeyActsAsUserId: "acted-as-user-1",
      }),
      "sess-gate-precedence",
    );
    expect(context).toEqual({ userId: "oauth-user-1" });
  });

  it("an acts-as id never fires outside authMethod === 'api_key'", async () => {
    const context = await dispatchAndCaptureContext(
      fakeAuthReq({
        // No authMethod at all (e.g. an unauthenticated endpoint) — a stray
        // acts-as stamp must not inject.
        apiKeyActsAsUserId: "acted-as-user-1",
      }),
      "sess-gate-no-method",
    );
    expect(context).toBeUndefined();
  });

  it("SSE and the OpenAPI bridge stay fail-closed BY DESIGN — no m365 context wiring exists there", () => {
    // Source-level pin (there is no express harness in this repo's test
    // setup): the identity gate must exist ONLY in streamable-http.ts.
    // If this fails, someone wired delegated identity into another
    // transport — that needs its own security review, not a silent pass.
    const files = [
      "sse.ts",
      join("openapi", "routes.ts"),
      join("openapi", "handlers.ts"),
      join("openapi", "tool-execution.ts"),
    ];
    for (const file of files) {
      const source = readFileSync(join(__dirname, file), "utf8");
      expect(source).not.toContain("runWithM365UserContext");
      expect(source).not.toContain("apiKeyActsAsUserId");
    }
    const streamableSource = readFileSync(
      join(__dirname, "streamable-http.ts"),
      "utf8",
    );
    expect(streamableSource).toContain("runWithM365UserContext");
  });
});

/**
 * Caller binding for `tool_call_audit` (migration 0030).
 *
 * Two carriers, tested separately because they fail differently:
 *
 *  - the REQUEST-SCOPED store (`lib/metamcp/caller-context-store`), entered by
 *    `dispatchTracked`, is what the auditing middleware actually reads. Delete
 *    that wiring and every proxied tool call is audited from a pooled object
 *    that belongs to whichever request stamped it last.
 *  - the per-instance handler context is the fallback, stamped at session
 *    creation, at lazy recovery, and again on each subsequent POST. Delete any
 *    of those and the fallback goes stale or empty.
 *
 * Every stamp site below was deletable with the suite green before these
 * tests existed.
 */
describe("caller binding — request-scoped store (the audited source)", () => {
  function callerCapturingTransport(captured: {
    caller: CallerContext | undefined;
  }): StreamableHTTPServerTransport {
    return {
      handleRequest: vi.fn().mockImplementation(async () => {
        captured.caller = getCallerContext();
      }),
    } as unknown as StreamableHTTPServerTransport;
  }

  async function dispatchAndCaptureCaller(
    authReq: ApiKeyAuthenticatedRequest,
    sessionId: string,
    clientName?: string,
  ): Promise<CallerContext | undefined> {
    publicSessionSweeper.beginTracking(sessionId);
    const captured: { caller: CallerContext | undefined } = {
      caller: undefined,
    };
    await dispatchTracked(
      authReq,
      callerCapturingTransport(captured),
      {} as express.Request,
      {} as express.Response,
      sessionId,
      clientName,
    );
    return captured.caller;
  }

  it("carries THIS request's credential, account, address and request id into the dispatch", async () => {
    const caller = await dispatchAndCaptureCaller(
      fakeAuthReq({
        authMethod: "api_key",
        apiKeyUuid: "3f7f8a1e-0000-4000-8000-000000000001",
        apiKeyUserId: "key-owner-1",
        headers: { "cf-connecting-ip": "203.0.113.7" },
        auditRequestId: "req-aaaa",
      }),
      "sess-binding-1",
      "example connector",
    );

    expect(caller).toEqual({
      clientName: "example connector",
      apiKeyUuid: "3f7f8a1e-0000-4000-8000-000000000001",
      authMethod: "api_key",
      userId: "key-owner-1",
      actsAsUserId: undefined,
      callerIp: "203.0.113.7",
      requestId: "req-aaaa",
    });
  });

  it("records an admin key's acts-as target separately from the key owner", async () => {
    const caller = await dispatchAndCaptureCaller(
      fakeAuthReq({
        authMethod: "api_key",
        apiKeyUuid: "3f7f8a1e-0000-4000-8000-000000000002",
        apiKeyUserId: "key-owner-1",
        apiKeyActsAsUserId: "acted-as-user-1",
        auditRequestId: "req-bbbb",
      }),
      "sess-binding-acts-as",
    );

    // Folding these into one column would make a delegated call read exactly
    // like a direct one by the acted-as account.
    expect(caller?.userId).toBe("key-owner-1");
    expect(caller?.actsAsUserId).toBe("acted-as-user-1");
  });

  it("does not leak one request's binding into the next dispatch on the same session", async () => {
    // The failure this guards is the whole reason the store exists: parallel
    // or successive calls on one session share a pooled handler context.
    const first = await dispatchAndCaptureCaller(
      fakeAuthReq({
        authMethod: "api_key",
        apiKeyUuid: "3f7f8a1e-0000-4000-8000-000000000001",
        apiKeyUserId: "key-owner-1",
        headers: { "cf-connecting-ip": "203.0.113.7" },
        auditRequestId: "req-first",
      }),
      "sess-binding-shared",
      "example connector",
    );
    const second = await dispatchAndCaptureCaller(
      fakeAuthReq({
        authMethod: "oauth",
        oauthUserId: "oauth-user-9",
        headers: { "cf-connecting-ip": "198.51.100.4" },
        auditRequestId: "req-second",
      }),
      "sess-binding-shared",
      "other consumer",
    );

    expect(first?.requestId).toBe("req-first");
    expect(second?.requestId).toBe("req-second");
    expect(second?.apiKeyUuid).toBeUndefined();
    expect(second?.userId).toBe("oauth-user-9");
    expect(second?.callerIp).toBe("198.51.100.4");
  });

  it("leaves the store empty outside a dispatch", async () => {
    // "No store" must stay distinguishable from "a store that resolved
    // nothing" — the auditing middleware falls back to the handler context on
    // the first and not on the second.
    await dispatchAndCaptureCaller(
      fakeAuthReq({ authMethod: "api_key", apiKeyUuid: "u-1" }),
      "sess-binding-scope",
    );
    expect(getCallerContext()).toBeUndefined();
  });
});

describe("caller binding — per-instance fallback stamps", () => {
  const fakeInstance = () => ({
    server: { connect: vi.fn().mockResolvedValue(undefined) },
    cleanup: vi.fn().mockResolvedValue(undefined),
    handlerContext: {} as Record<string, unknown>,
  });

  it("lazy recovery re-stamps the rebuilt instance with the re-validated caller", async () => {
    const sessionId = "sess-stamp-recovery";
    const rawToken = "test-api-key-value";
    (
      mcpSessionsRepository.findById as ReturnType<typeof vi.fn>
    ).mockResolvedValueOnce({
      session_id: sessionId,
      namespace_uuid: "ns-1",
      endpoint_name: "ep-1",
      auth_principal: hashAuthPrincipal(rawToken, "api_key"),
      auth_method: "api_key",
      init_params: {},
      created_at: new Date(),
      last_seen_at: new Date(),
      gateway_boot_id: GATEWAY_BOOT_ID,
      capability_hash: GATEWAY_CAPABILITY_HASH,
    });
    const instance = fakeInstance();
    (
      metaMcpServerPool.getServer as ReturnType<typeof vi.fn>
    ).mockResolvedValueOnce(instance);

    const result = await recoverPersistedSession(
      sessionId,
      fakeAuthReq({
        namespaceUuid: "ns-1",
        endpointName: "ep-1",
        authMethod: "api_key",
        apiKeyUuid: "3f7f8a1e-0000-4000-8000-000000000003",
        apiKeyUserId: "key-owner-1",
        headers: { "x-api-key": rawToken, "cf-connecting-ip": "203.0.113.7" },
        auditRequestId: "req-recovery",
      }),
    );

    expect(result.status).toBe("recovered");
    expect(instance.handlerContext).toMatchObject({
      clientName: "test-consumer",
      apiKeyUuid: "3f7f8a1e-0000-4000-8000-000000000003",
      authMethod: "api_key",
      userId: "key-owner-1",
      callerIp: "203.0.113.7",
      requestId: "req-recovery",
    });
  });
});

describe("caller binding — the POST route stamps the instance it serves", () => {
  let server: Server;
  let baseUrl = "";
  let instance: ReturnType<typeof makeInstance>;

  const makeInstance = () => ({
    server: { connect: vi.fn().mockResolvedValue(undefined) },
    cleanup: vi.fn().mockResolvedValue(undefined),
    handlerContext: {} as Record<string, unknown>,
  });

  beforeAll(async () => {
    // The file-wide mocks for these three are bare `vi.fn()`s that never call
    // next(), which is right for the unit tests above and would hang a real
    // request. Give them the shape the production chain has: resolve the
    // endpoint, stamp the identity the auth middleware would stamp, pass on.
    vi.mocked(lookupEndpoint).mockImplementation(((
      req: express.Request,
      _res: express.Response,
      next: () => void,
    ) => {
      Object.assign(req, {
        namespaceUuid: "ns-1",
        endpointName: "ep-1",
        endpoint: { uuid: "ep-uuid-1", name: "ep-1" },
        authMethod: "api_key",
        apiKeyUuid: "3f7f8a1e-0000-4000-8000-000000000004",
        apiKeyUserId: "key-owner-1",
        // Stamped app-wide by auditContextMiddleware in production.
        auditRequestId: "req-route",
        auditClientIp: "203.0.113.7",
      });
      next();
    }) as never);
    vi.mocked(authenticateApiKey).mockImplementation(((
      _req: express.Request,
      _res: express.Response,
      next: () => void,
    ) => next()) as never);
    vi.mocked(rateLimitMiddleware).mockImplementation(((
      _req: express.Request,
      _res: express.Response,
      next: () => void,
    ) => next()) as never);

    const app = express();
    app.use("/metamcp", streamableHttpRouter);
    await new Promise<void>((resolve) => {
      server = app.listen(0, "127.0.0.1", resolve);
    });
    const address = server.address();
    if (typeof address === "object" && address) {
      baseUrl = `http://127.0.0.1:${address.port}`;
    }
  });

  afterAll(async () => {
    // Restore the file-wide defaults — clearAllMocks does not reset
    // implementations, so these would otherwise follow into any later block.
    vi.mocked(lookupEndpoint).mockImplementation((() => undefined) as never);
    vi.mocked(authenticateApiKey).mockImplementation(
      (() => undefined) as never,
    );
    vi.mocked(rateLimitMiddleware).mockImplementation(
      (() => undefined) as never,
    );
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  beforeEach(() => {
    instance = makeInstance();
  });

  /**
   * Drive one POST through the real router. The transport's own answer is
   * irrelevant here (no MCP handshake is performed, so it refuses the body) —
   * what is under test is the stamp the route applies before dispatching.
   */
  const post = (headers: Record<string, string> = {}) =>
    fetch(`${baseUrl}/metamcp/ep-1/mcp`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
        ...headers,
      },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
    });

  it("stamps the instance it acquires for a NEW session", async () => {
    (
      metaMcpServerPool.getServer as ReturnType<typeof vi.fn>
    ).mockResolvedValueOnce(instance);

    await post();

    expect(instance.handlerContext).toMatchObject({
      clientName: "test-consumer",
      apiKeyUuid: "3f7f8a1e-0000-4000-8000-000000000004",
      authMethod: "api_key",
      userId: "key-owner-1",
      callerIp: "203.0.113.7",
      requestId: "req-route",
    });
  });

  it("re-stamps the pooled instance on a subsequent POST rather than leaving the initialize request's values", async () => {
    // Seed a live in-memory session so the request takes the existing-session
    // branch rather than falling into lazy recovery (which has its own stamp).
    // Seeded under the SAME api key the mocked auth chain stamps, or the
    // ownership guard would answer 404 before any stamping happened.
    const sessionId = "sess-route-existing";
    await seedBoundSession(sessionId, "ns-1", "ep-1", {
      apiKeyUuid: "3f7f8a1e-0000-4000-8000-000000000004",
    });

    // The state the bug produces: values frozen at session creation.
    instance.handlerContext = {
      clientName: "stale consumer",
      requestId: "req-from-initialize",
      callerIp: "198.51.100.99",
      apiKeyUuid: "stale-uuid",
    } as Record<string, unknown>;
    (
      metaMcpServerPool.getServerInstance as ReturnType<typeof vi.fn>
    ).mockReturnValueOnce(instance);

    await post({ "mcp-session-id": sessionId });

    expect(instance.handlerContext).toMatchObject({
      clientName: "test-consumer",
      apiKeyUuid: "3f7f8a1e-0000-4000-8000-000000000004",
      callerIp: "203.0.113.7",
      requestId: "req-route",
    });
    await cleanupSession(sessionId);
  });
});

/**
 * Route-level proof over a REAL socket that the ownership guard's ANSWER is
 * the one the MCP Streamable HTTP session model calls for.
 *
 * The resolver unit tests above pin `refused`; these pin what the routes do
 * with it, and that is the half a reader is most likely to get wrong. Letting
 * a refused reuse fall through to lazy recovery — the shape the code had when
 * the guard was endpoint-only — produces a 401 from the stored-principal
 * check instead of a 404: it tells the caller their credential is wrong rather
 * than that the session is gone, so a spec-conformant client never
 * re-initializes, and it confirms to anyone probing session ids that the one
 * they guessed is live and belongs to someone else.
 */
describe("POST/GET /:endpoint/mcp — a refused session reuse answers 404, not 401", () => {
  let server: Server;
  let baseUrl = "";

  /** The credential the mocked auth chain stamps; mutated per test. */
  let currentKeyUuid = "key-owner-uuid";

  beforeAll(async () => {
    vi.mocked(lookupEndpoint).mockImplementation(((
      req: express.Request,
      _res: express.Response,
      next: () => void,
    ) => {
      Object.assign(req, {
        namespaceUuid: "ns-guard",
        endpointName: "ep-guard",
        endpoint: { uuid: "ep-guard-uuid", name: "ep-guard" },
        authMethod: "api_key",
        apiKeyUuid: currentKeyUuid,
        auditRequestId: "req-guard",
        auditClientIp: "203.0.113.9",
      });
      next();
    }) as never);
    vi.mocked(authenticateApiKey).mockImplementation(((
      _req: express.Request,
      _res: express.Response,
      next: () => void,
    ) => next()) as never);
    vi.mocked(rateLimitMiddleware).mockImplementation(((
      _req: express.Request,
      _res: express.Response,
      next: () => void,
    ) => next()) as never);

    const app = express();
    app.use("/metamcp", streamableHttpRouter);
    await new Promise<void>((resolve) => {
      server = app.listen(0, "127.0.0.1", resolve);
    });
    const address = server.address();
    if (typeof address === "object" && address) {
      baseUrl = `http://127.0.0.1:${address.port}`;
    }
  });

  afterAll(async () => {
    vi.mocked(lookupEndpoint).mockImplementation((() => undefined) as never);
    vi.mocked(authenticateApiKey).mockImplementation(
      (() => undefined) as never,
    );
    vi.mocked(rateLimitMiddleware).mockImplementation(
      (() => undefined) as never,
    );
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  beforeEach(() => {
    currentKeyUuid = "key-owner-uuid";
  });

  const post = (sessionId: string) =>
    fetch(`${baseUrl}/metamcp/ep-guard/mcp`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
        "mcp-session-id": sessionId,
      },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
    });

  it("answers 404 + the reinitialize header when a sibling key presents another consumer's session id", async () => {
    const sessionId = "sess-route-foreign";
    await seedBoundSession(sessionId, "ns-guard", "ep-guard", {
      apiKeyUuid: "key-owner-uuid",
    });
    (mcpSessionsRepository.findById as ReturnType<typeof vi.fn>).mockClear();
    // Arm the persisted row the session really has. This is the production
    // state — every credentialed session persists one — and it is what makes
    // the assertions below bite: reaching recovery with this row present
    // fails the stored-principal check and answers 401.
    (
      mcpSessionsRepository.findById as ReturnType<typeof vi.fn>
    ).mockResolvedValue({
      session_id: sessionId,
      namespace_uuid: "ns-guard",
      endpoint_name: "ep-guard",
      auth_principal: hashAuthPrincipal("bound-key-value", "api_key"),
      auth_method: "api_key",
      init_params: {},
      created_at: new Date(),
      last_seen_at: new Date(),
      gateway_boot_id: GATEWAY_BOOT_ID,
      capability_hash: GATEWAY_CAPABILITY_HASH,
    });

    currentKeyUuid = "key-sibling-uuid";
    const response = await post(sessionId);

    expect(response.status).toBe(404);
    expect(response.headers.get("Mcp-Session-Reinitialize-Required")).toBe(
      "true",
    );
    // Recovery is never attempted for a refused reuse — that is what would
    // have turned this into a 401.
    expect(mcpSessionsRepository.findById).not.toHaveBeenCalled();
    // The refused caller never reaches the pooled instance either.
    expect(metaMcpServerPool.getServerInstance).not.toHaveBeenCalled();

    (mcpSessionsRepository.findById as ReturnType<typeof vi.fn>).mockReset();
    await cleanupSession(sessionId);
  });

  it("byte-identical to a genuine miss: the refused body carries no hint the id is live", async () => {
    const sessionId = "sess-route-shape";
    await seedBoundSession(sessionId, "ns-guard", "ep-guard", {
      apiKeyUuid: "key-owner-uuid",
    });

    currentKeyUuid = "key-sibling-uuid";
    const refused = await post(sessionId);
    const refusedBody = await refused.text();

    // A session id that never existed, same caller, same route.
    (
      mcpSessionsRepository.findById as ReturnType<typeof vi.fn>
    ).mockResolvedValueOnce(null);
    const missing = await post("sess-route-never-existed");
    const missingBody = await missing.text();

    expect(refused.status).toBe(missing.status);
    // Only the timestamp differs between the two envelopes.
    const strip = (body: string) =>
      body.replace(/"timestamp":"[^"]*"/, '"timestamp":"<ts>"');
    expect(strip(refusedBody)).toBe(strip(missingBody));
    expect(refusedBody).not.toContain(sessionId);

    await cleanupSession(sessionId);
  });

  it("still serves the OWNER of the session on the same route", async () => {
    const sessionId = "sess-route-owner";
    await seedBoundSession(sessionId, "ns-guard", "ep-guard", {
      apiKeyUuid: "key-owner-uuid",
    });
    (mcpSessionsRepository.findById as ReturnType<typeof vi.fn>).mockClear();
    (
      metaMcpServerPool.getServerInstance as ReturnType<typeof vi.fn>
    ).mockReturnValueOnce({
      server: { connect: vi.fn() },
      cleanup: vi.fn(),
      handlerContext: {} as Record<string, unknown>,
    });

    const response = await post(sessionId);

    // The transport itself refuses the body (no MCP handshake was performed
    // in this harness), so the status is the transport's business. What is
    // under test is that the guard let the request THROUGH: the route only
    // reaches the pooled instance after the guard passes, and it never
    // answered the reinitialize 404.
    expect(response.status).not.toBe(404);
    expect(metaMcpServerPool.getServerInstance).toHaveBeenCalledWith(sessionId);
    expect(mcpSessionsRepository.findById).not.toHaveBeenCalled();

    await cleanupSession(sessionId);
  });

  it("GET (the standalone notification stream) refuses a foreign credential the same way", async () => {
    const sessionId = "sess-route-get-foreign";
    await seedBoundSession(sessionId, "ns-guard", "ep-guard", {
      apiKeyUuid: "key-owner-uuid",
    });
    (mcpSessionsRepository.findById as ReturnType<typeof vi.fn>).mockClear();

    currentKeyUuid = "key-sibling-uuid";
    const response = await fetch(`${baseUrl}/metamcp/ep-guard/mcp`, {
      method: "GET",
      headers: {
        accept: "text/event-stream",
        "mcp-session-id": sessionId,
      },
    });

    expect(response.status).toBe(404);
    expect(response.headers.get("Mcp-Session-Reinitialize-Required")).toBe(
      "true",
    );
    expect(mcpSessionsRepository.findById).not.toHaveBeenCalled();

    await cleanupSession(sessionId);
  });
});
