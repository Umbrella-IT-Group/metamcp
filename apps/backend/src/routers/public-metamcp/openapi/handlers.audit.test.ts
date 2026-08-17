/**
 * The OpenAPI bridge composes its OWN call-tool chain rather than reusing the
 * Streamable-HTTP one in `metamcp-proxy`, and the auditing middleware sat
 * commented out of it. Every tool call made through the OpenAPI endpoints
 * therefore executed with no `tool_call_audit` row — a gap that was invisible
 * from the table, because a missing row and a quiet consumer look identical.
 *
 * These tests pin the wiring: the chain invokes the auditing middleware, and
 * the caller binding that arrives per call reaches the row. Removing
 * `createAuditingMiddleware()` from the compose in `handlers.ts` fails them.
 *
 * Only the DB-touching boundary is mocked (the convention `streamable-http.
 * test.ts` and `mcp-server-pool.test.ts` follow). The auditing middleware and
 * `compose` run for real — they are what is under test. The two other
 * middlewares in the chain are stubbed to pass-through so their own DB-backed
 * tool-status lookups cannot decide the outcome of an audit test.
 */
import { CallToolRequest } from "@modelcontextprotocol/sdk/types.js";
import { afterEach, describe, expect, it, vi } from "vitest";

// `db/index.ts` throws without DATABASE_URL and is reached transitively from
// `lib/metamcp/utils` (sanitizeName -> oauth-sessions.repo). Same stub the
// other DB-free unit tests use.
vi.mock("../../../db/index", () => ({ db: {}, pool: {} }));

// Inlined rather than shared through a top-level helper: `vi.mock` factories
// are hoisted above every const in the file.
vi.mock(
  "../../../lib/metamcp/metamcp-middleware/filter-tools.functional",
  () => ({
    createFilterCallToolMiddleware: () => (h: unknown) => h,
    createFilterListToolsMiddleware: () => (h: unknown) => h,
  }),
);

vi.mock(
  "../../../lib/metamcp/metamcp-middleware/tool-overrides.functional",
  () => ({
    createToolOverridesCallToolMiddleware: () => (h: unknown) => h,
    createToolOverridesListToolsMiddleware: () => (h: unknown) => h,
  }),
);

// `getMcpServers` returning nothing makes the original handler reach its
// "Unknown tool" throw without any backend session — the shortest real path
// through the chain that still produces an audited outcome.
vi.mock("../../../lib/metamcp/fetch-metamcp", () => ({
  getMcpServers: vi.fn().mockResolvedValue({}),
}));

vi.mock("../../../db/repositories/namespaces.repo", () => ({
  namespacesRepository: {
    // No last-known-good owner for the tool, so the reconnect-window fallback
    // is skipped and the handler reaches its genuine "Unknown tool" throw.
    findServersForNamespaceToolName: vi.fn().mockResolvedValue([]),
  },
}));

vi.mock("../../../lib/config.service", () => ({
  configService: {
    getMcpResetTimeoutOnProgress: vi.fn().mockResolvedValue(false),
    getMcpTimeout: vi.fn().mockResolvedValue(60000),
    getMcpMaxTotalTimeout: vi.fn().mockResolvedValue(60000),
    getMcpToolCallReconnectWarmupTimeout: vi.fn().mockResolvedValue(1000),
  },
}));

vi.mock("../../../lib/metamcp/mcp-server-pool", () => ({
  mcpServerPool: {
    getSession: vi.fn().mockResolvedValue(undefined),
    ensureSession: vi.fn().mockResolvedValue(undefined),
  },
}));

vi.mock("../../../lib/metamcp/tool-call-warmup", () => ({
  acquireSessionWithBoundedWarmup: vi.fn().mockResolvedValue(undefined),
}));

import { setAuditRecorderForTesting } from "../../../lib/metamcp/metamcp-middleware/auditing.functional";
import { createMiddlewareEnabledHandlers } from "./handlers";

const caller = {
  apiKeyUuid: "3f7f8a1e-0000-4000-8000-000000000001",
  authMethod: "api_key",
  userId: "user-owner-1",
  callerIp: "203.0.113.7",
  requestId: "req-openapi-1",
};

const callRequest = (): CallToolRequest =>
  ({
    method: "tools/call",
    params: { name: "autotask__search", arguments: { q: "printer" } },
  }) as CallToolRequest;

// Flush the fire-and-forget persist() chain the middleware detaches.
const flush = () => new Promise((r) => setTimeout(r, 0));

afterEach(() => {
  setAuditRecorderForTesting(null);
  vi.clearAllMocks();
});

describe("OpenAPI call-tool chain writes tool_call_audit rows", () => {
  it("invokes the auditing middleware for a call made through the bridge", async () => {
    const recorder = vi.fn().mockResolvedValue(undefined);
    setAuditRecorderForTesting(recorder);

    const { callToolWithMiddleware, handlerContext } =
      createMiddlewareEnabledHandlers(
        "openapi_ns-123",
        "ns-123",
        "example connector",
        caller,
      );

    await expect(
      callToolWithMiddleware(callRequest(), handlerContext),
    ).rejects.toThrow(/Unknown tool/);
    await flush();

    expect(recorder).toHaveBeenCalledTimes(1);
    const entry = recorder.mock.calls[0][0];
    expect(entry.server_name).toBe("autotask");
    expect(entry.tool_name).toBe("search");
    expect(entry.success).toBe(false);
  });

  it("carries the per-call caller binding onto the row", async () => {
    const recorder = vi.fn().mockResolvedValue(undefined);
    setAuditRecorderForTesting(recorder);

    const { callToolWithMiddleware, handlerContext } =
      createMiddlewareEnabledHandlers(
        "openapi_ns-123",
        "ns-123",
        "example connector",
        caller,
      );

    await expect(
      callToolWithMiddleware(callRequest(), handlerContext),
    ).rejects.toThrow();
    await flush();

    const entry = recorder.mock.calls[0][0];
    expect(entry.client_name).toBe("example connector");
    expect(entry.api_key_uuid).toBe(caller.apiKeyUuid);
    expect(entry.auth_method).toBe("api_key");
    expect(entry.user_id).toBe("user-owner-1");
    expect(entry.caller_ip).toBe("203.0.113.7");
    expect(entry.request_id).toBe("req-openapi-1");
  });

  it("keeps two consumers apart on the SHARED openapi session id", async () => {
    // Every consumer of a namespace shares `openapi_<namespace>`, so the
    // session id identifies nobody. Attribution has to come from the per-call
    // context, and this is the test that it does.
    const recorder = vi.fn().mockResolvedValue(undefined);
    setAuditRecorderForTesting(recorder);

    const first = createMiddlewareEnabledHandlers(
      "openapi_ns-123",
      "ns-123",
      "example connector",
      caller,
    );
    const second = createMiddlewareEnabledHandlers(
      "openapi_ns-123",
      "ns-123",
      "other consumer",
      {
        apiKeyUuid: "3f7f8a1e-0000-4000-8000-000000000002",
        authMethod: "oauth",
        userId: "user-oauth-9",
        callerIp: "198.51.100.4",
        requestId: "req-openapi-2",
      },
    );

    await expect(
      first.callToolWithMiddleware(callRequest(), first.handlerContext),
    ).rejects.toThrow();
    await expect(
      second.callToolWithMiddleware(callRequest(), second.handlerContext),
    ).rejects.toThrow();
    await flush();

    expect(recorder).toHaveBeenCalledTimes(2);
    const [rowA] = recorder.mock.calls[0];
    const [rowB] = recorder.mock.calls[1];
    expect(rowA.session_id).toBe(rowB.session_id);
    expect(rowA.api_key_uuid).not.toBe(rowB.api_key_uuid);
    expect(rowA.request_id).toBe("req-openapi-1");
    expect(rowB.request_id).toBe("req-openapi-2");
    expect(rowB.auth_method).toBe("oauth");
  });

  it("records the call un-attributed rather than not at all when no identity was resolved", async () => {
    const recorder = vi.fn().mockResolvedValue(undefined);
    setAuditRecorderForTesting(recorder);

    const { callToolWithMiddleware, handlerContext } =
      createMiddlewareEnabledHandlers("openapi_ns-123", "ns-123");

    await expect(
      callToolWithMiddleware(callRequest(), handlerContext),
    ).rejects.toThrow();
    await flush();

    expect(recorder).toHaveBeenCalledTimes(1);
    const entry = recorder.mock.calls[0][0];
    expect(entry.api_key_uuid).toBeNull();
    expect(entry.request_id).toBeNull();
    expect(entry.tool_name).toBe("search");
  });
});
