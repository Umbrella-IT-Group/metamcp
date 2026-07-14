/**
 * Targeted tests for the two highest-risk behaviors flagged in the
 * foreman review of METAMCP-POOL-1 / PR #72 (fixes round):
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
import type { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import type express from "express";
import { beforeEach, describe, expect, it, vi } from "vitest";

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
    cleanupSession: vi.fn().mockResolvedValue(undefined),
    getMcpServerPoolStatus: vi.fn().mockReturnValue({ idle: 0, active: 0 }),
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

import {
  GATEWAY_BOOT_ID,
  GATEWAY_CAPABILITY_HASH,
} from "../../lib/metamcp/gateway-boot-id";
import { metaMcpServerPool } from "../../lib/metamcp/metamcp-server-pool";
import { hashAuthPrincipal } from "../../lib/metamcp/session-auth";
import {
  cleanupSession,
  dispatchTracked,
  publicSessionSweeper,
  reapIdleSession,
  recoverPersistedSession,
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

describe("reapIdleSession vs cleanupSession — row-preservation contract (item 1 / METAMCP-POOL-1)", () => {
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

describe("recoverPersistedSession — succeeds against a row reapIdleSession leaves behind (item 1 / METAMCP-POOL-1)", () => {
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

describe("dispatchTracked — in-flight guard around a long-lived dispatch (item 7b / METAMCP-POOL-1)", () => {
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
