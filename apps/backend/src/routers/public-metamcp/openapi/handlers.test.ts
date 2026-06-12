/**
 * Unit tests for the OpenAPI bridge recovery cascade.
 *
 * Pre-2026-05-14 the OpenAPI bridge (`handlers.ts`) had its own fork
 * of the tools/call + tools/list handlers from `metamcp-proxy.ts`,
 * and never got PR #13 / #15 / #16's recovery wiring. Tara + any
 * OpenAPI consumer hit a backend MCP container restart and got a
 * bare `Error POSTing ... HTTP 404 ... Session not found` pass-through.
 *
 * These tests verify the parallel recovery cascade we just bolted on
 * to the OpenAPI handlers:
 *
 *   1. tools/call recovers from the session-lost envelope (invalidate
 *      → re-init → retry once → return success).
 *   2. tools/call does NOT retry on a non-recoverable error.
 *   3. tools/list recovers from the session-lost envelope.
 *   4. The retried-and-still-failed case propagates the retry error.
 */

import { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { beforeEach, describe, expect, it, vi } from "vitest";

// db/index.ts throws at import if DATABASE_URL is unset — stub the
// whole module so transitive imports don't blow up the test.
vi.mock("../../../db", () => ({
  db: {},
}));
vi.mock("../../../db/schema", () => ({}));

// Heavy-import stubs — `handlers.ts` pulls in the full mcpServerPool
// + config service + fetch-metamcp chain. Stub them so the test runs
// in <1s without a postgres or live backend.
vi.mock("../../../lib/config.service", () => ({
  configService: {
    getMcpResetTimeoutOnProgress: vi.fn().mockResolvedValue(true),
    getMcpTimeout: vi.fn().mockResolvedValue(60000),
    getMcpMaxTotalTimeout: vi.fn().mockResolvedValue(60000),
  },
}));

const fakeServerParams: Record<string, { name?: string }> = {
  "server-autotask": { name: "autotask" },
};

vi.mock("../../../lib/metamcp/fetch-metamcp", () => ({
  getMcpServers: vi.fn().mockImplementation(async () => fakeServerParams),
}));

const { invalidateServerConnectionMock, getSessionMock, loggerErrorMock } =
  vi.hoisted(() => ({
    invalidateServerConnectionMock: vi.fn(),
    getSessionMock: vi.fn(),
    loggerErrorMock: vi.fn(),
  }));

// Real logger writes to console; mock it so the DEGRADED-tripwire
// tests can assert on the emitted lines.
vi.mock("@/utils/logger", () => ({
  default: {
    error: loggerErrorMock,
    warn: vi.fn(),
    info: vi.fn(),
    debug: vi.fn(),
  },
}));

vi.mock("../../../lib/metamcp/mcp-server-pool", () => ({
  mcpServerPool: {
    invalidateServerConnection: invalidateServerConnectionMock,
    getSession: getSessionMock,
  },
}));

// `metamcp-middleware/filter-tools.functional` pulls the DB at import
// time. Stub the whole module so the handler under test loads without
// DATABASE_URL set in the unit-test env.
vi.mock(
  "../../../lib/metamcp/metamcp-middleware/filter-tools.functional",
  () => ({
    createFilterCallToolMiddleware: () => (next: unknown) => next,
    createFilterListToolsMiddleware: () => (next: unknown) => next,
  }),
);
vi.mock(
  "../../../lib/metamcp/metamcp-middleware/tool-overrides.functional",
  () => ({
    createToolOverridesCallToolMiddleware: () => (next: unknown) => next,
    createToolOverridesListToolsMiddleware: () => (next: unknown) => next,
  }),
);

// The middleware functional layer is a no-op pass-through for our
// purposes — we test originalCallToolHandler / createOriginalListToolsHandler
// directly, so the middleware composition isn't exercised here.

import {
  createOriginalCallToolHandler,
  createOriginalListToolsHandler,
} from "./handlers";

type FakeClient = {
  request: ReturnType<typeof vi.fn>;
  getServerCapabilities: () => { tools: Record<string, never> };
  getServerVersion: () => { name: string };
};

function makeFakeSession(request: ReturnType<typeof vi.fn> = vi.fn()): {
  client: FakeClient;
} {
  return {
    client: {
      request,
      getServerCapabilities: () => ({ tools: {} as Record<string, never> }),
      getServerVersion: () => ({ name: "autotask" }),
    },
  };
}

const sessionLostEnvelope =
  'Error POSTing to endpoint (HTTP 404): {"jsonrpc":"2.0","id":"server-error","error":{"code":-32600,"message":"Session not found"}}';

describe("OpenAPI bridge — tools/call recovery cascade", () => {
  beforeEach(() => {
    invalidateServerConnectionMock.mockReset();
    getSessionMock.mockReset();
  });

  it("invalidates + retries once on session-lost envelope, returns success", async () => {
    const successResult: CallToolResult = {
      content: [{ type: "text", text: "ok" }],
    };
    const staleClient = makeFakeSession(
      vi.fn().mockRejectedValueOnce(new Error(sessionLostEnvelope)),
    );
    const freshClient = makeFakeSession(
      vi.fn().mockResolvedValueOnce(successResult),
    );

    // First call to getSession is in the namespace-walk that finds
    // targetSession; second call is the recovery's re-acquire.
    getSessionMock
      .mockResolvedValueOnce(staleClient)
      .mockResolvedValueOnce(freshClient);

    const handler = createOriginalCallToolHandler();
    const result = await handler(
      {
        method: "tools/call",
        params: { name: "autotask__autotask_resolve_id", arguments: {} },
      },
      { namespaceUuid: "ns-1", sessionId: "openapi_ns-1" },
    );

    expect(result).toEqual(successResult);
    expect(invalidateServerConnectionMock).toHaveBeenCalledWith(
      "openapi_ns-1",
      "server-autotask",
    );
    expect(staleClient.client.request).toHaveBeenCalledTimes(1);
    expect(freshClient.client.request).toHaveBeenCalledTimes(1);
    // getSession called twice: once for namespace-walk, once for re-acquire.
    expect(getSessionMock).toHaveBeenCalledTimes(2);
  });

  it("propagates non-recoverable errors without invalidating", async () => {
    const stale = makeFakeSession(
      vi.fn().mockRejectedValueOnce(new Error("Tool call failed: bad input")),
    );
    getSessionMock.mockResolvedValueOnce(stale);

    const handler = createOriginalCallToolHandler();
    await expect(
      handler(
        {
          method: "tools/call",
          params: { name: "autotask__autotask_resolve_id", arguments: {} },
        },
        { namespaceUuid: "ns-1", sessionId: "openapi_ns-1" },
      ),
    ).rejects.toThrow(/Tool call failed/);

    expect(invalidateServerConnectionMock).not.toHaveBeenCalled();
    expect(stale.client.request).toHaveBeenCalledTimes(1);
  });

  it("propagates retry error when the fresh session also fails", async () => {
    const stale = makeFakeSession(
      vi.fn().mockRejectedValueOnce(new Error(sessionLostEnvelope)),
    );
    const fresh = makeFakeSession(
      vi.fn().mockRejectedValueOnce(new Error("upstream still broken")),
    );
    getSessionMock.mockResolvedValueOnce(stale).mockResolvedValueOnce(fresh);

    const handler = createOriginalCallToolHandler();
    await expect(
      handler(
        {
          method: "tools/call",
          params: { name: "autotask__autotask_resolve_id", arguments: {} },
        },
        { namespaceUuid: "ns-1", sessionId: "openapi_ns-1" },
      ),
    ).rejects.toThrow(/upstream still broken/);

    expect(invalidateServerConnectionMock).toHaveBeenCalledTimes(1);
    expect(stale.client.request).toHaveBeenCalledTimes(1);
    expect(fresh.client.request).toHaveBeenCalledTimes(1);
  });

  it("throws when re-acquire returns null (server vanished mid-recovery)", async () => {
    const stale = makeFakeSession(
      vi.fn().mockRejectedValueOnce(new Error(sessionLostEnvelope)),
    );
    getSessionMock.mockResolvedValueOnce(stale).mockResolvedValueOnce(null);

    const handler = createOriginalCallToolHandler();
    await expect(
      handler(
        {
          method: "tools/call",
          params: { name: "autotask__autotask_resolve_id", arguments: {} },
        },
        { namespaceUuid: "ns-1", sessionId: "openapi_ns-1" },
      ),
    ).rejects.toThrow(/failed to re-initialize/);

    expect(invalidateServerConnectionMock).toHaveBeenCalledTimes(1);
  });
});

describe("OpenAPI bridge — tools/list DEGRADED tripwire", () => {
  // Parity with metamcp-proxy.ts's PR #28 tripwire. The Grafana alert
  // greps `DEGRADED for namespace`; before this, OpenAPI-path
  // degradation (Tara, n8n, registry-sync) never produced the line.

  beforeEach(() => {
    vi.clearAllMocks();
    loggerErrorMock.mockClear();
  });

  it("logs No-session + DEGRADED when getSession returns null", async () => {
    getSessionMock.mockResolvedValue(null);

    const handler = createOriginalListToolsHandler();
    const result = await handler(
      { method: "tools/list", params: {} },
      { namespaceUuid: "ns-1", sessionId: "openapi_ns-1" },
    );

    expect(result.tools).toEqual([]);
    const messages = loggerErrorMock.mock.calls.map((c) => String(c[0]));
    expect(
      messages.some((m) => m.includes("No session for server autotask")),
    ).toBe(true);
    expect(
      messages.some((m) =>
        m.includes(
          "tools/list DEGRADED for namespace ns-1 (OpenAPI bridge): 1/1 backend server(s) failed (autotask); returning 0 tools",
        ),
      ),
    ).toBe(true);
  });

  it("counts a non-recoverable per-server failure in the DEGRADED line", async () => {
    const broken = makeFakeSession(
      vi.fn().mockRejectedValue(new Error("boom: schema validation failed")),
    );
    getSessionMock.mockResolvedValue(broken);

    const handler = createOriginalListToolsHandler();
    const result = await handler(
      { method: "tools/list", params: {} },
      { namespaceUuid: "ns-1", sessionId: "openapi_ns-1" },
    );

    expect(result.tools).toEqual([]);
    const messages = loggerErrorMock.mock.calls.map((c) => String(c[0]));
    expect(
      messages.some((m) =>
        m.includes("tools/list DEGRADED for namespace ns-1 (OpenAPI bridge)"),
      ),
    ).toBe(true);
  });

  it("stays silent when every backend answers", async () => {
    const healthy = makeFakeSession(
      vi.fn().mockResolvedValue({
        tools: [{ name: "resolve_id", description: "d", inputSchema: {} }],
      }),
    );
    getSessionMock.mockResolvedValue(healthy);

    const handler = createOriginalListToolsHandler();
    const result = await handler(
      { method: "tools/list", params: {} },
      { namespaceUuid: "ns-1", sessionId: "openapi_ns-1" },
    );

    expect(result.tools).toHaveLength(1);
    expect(result.tools[0].name).toBe("autotask__resolve_id");
    const messages = loggerErrorMock.mock.calls.map((c) => String(c[0]));
    expect(messages.some((m) => m.includes("DEGRADED"))).toBe(false);
  });
});
