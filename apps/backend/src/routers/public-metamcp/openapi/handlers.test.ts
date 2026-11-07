/**
 * Unit tests for the OpenAPI bridge recovery cascade.
 *
 * Before this fix the OpenAPI bridge (`handlers.ts`) had its own fork
 * of the tools/call + tools/list handlers from `metamcp-proxy.ts`,
 * and never got PR #13 / #15 / #16's recovery wiring. Any
 * OpenAPI consumer hit a backend MCP container restart and got a
 * bare `Error POSTing ... HTTP 404 ... Session not found` pass-through.
 *
 * These tests verify the parallel recovery cascade we just bolted on
 * to the OpenAPI handlers:
 *
 *   1. tools/call recovers from the session-lost envelope (invalidate
 *      → re-init → retry once → return success).
 *   2. tools/call does NOT retry on a non-recoverable error, nor on any
 *      failure after which the backend may have run the call (timeout,
 *      mid-call drop, 5xx, a backend-answered McpError).
 *   3. tools/list recovers from the session-lost envelope.
 *   4. The retried-and-still-failed case propagates the retry error.
 */

import { StreamableHTTPError } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import {
  CallToolResult,
  ErrorCode,
  McpError,
} from "@modelcontextprotocol/sdk/types.js";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// db/index.ts throws at import if DATABASE_URL is unset — stub the
// whole module so transitive imports don't blow up the test.
vi.mock("../../../db", () => ({
  db: {},
}));
vi.mock("../../../db/schema", () => ({}));

// Heavy-import stubs — `handlers.ts` pulls in the full mcpServerPool
// + config service + fetch-metamcp chain. Stub them so the test runs
// in <1s without a postgres or live backend.
// A pass-through spy: the tests read whether an audit cause was built at all.
vi.mock("../../../lib/metamcp/audit-listing-log", async (importOriginal) => {
  const actual =
    await importOriginal<
      typeof import("../../../lib/metamcp/audit-listing-log")
    >();
  return {
    ...actual,
    describeListingFailure: vi.fn(actual.describeListingFailure),
  };
});

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

const {
  invalidateServerConnectionMock,
  getSessionMock,
  loggerErrorMock,
  loggerWarnMock,
  loggerInfoMock,
} = vi.hoisted(() => ({
  invalidateServerConnectionMock: vi.fn(),
  getSessionMock: vi.fn(),
  loggerErrorMock: vi.fn(),
  loggerWarnMock: vi.fn(),
  loggerInfoMock: vi.fn(),
}));

// Real logger writes to console; mock it so the DEGRADED-tripwire
// tests can assert on the emitted lines.
vi.mock("@/utils/logger", () => ({
  default: {
    error: loggerErrorMock,
    warn: loggerWarnMock,
    info: loggerInfoMock,
    debug: vi.fn(),
  },
}));

vi.mock("../../../lib/metamcp/mcp-server-pool", () => ({
  mcpServerPool: {
    invalidateServerConnection: invalidateServerConnectionMock,
    getSession: getSessionMock,
    // Every failed client here still holds its pool slot, so a recovery
    // invalidates exactly as before (session-recovery.ts).
    isPooledClient: () => true,
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

import { configService } from "../../../lib/config.service";
import { describeListingFailure } from "../../../lib/metamcp/audit-listing-log";
import { setAuditRecorderForTesting } from "../../../lib/metamcp/metamcp-middleware/auditing.functional";
import {
  createMiddlewareEnabledHandlers,
  createOriginalCallToolHandler,
  createOriginalListToolsHandler,
  resetBridgeAuditSchemasForTesting,
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

// A tools/call is not idempotent, so the bridge replays one only when the
// failure proves the backend never ran it. The 2026-09-30 audit found that a
// timeout (-32001) was read as session-lost and re-sent.
describe("OpenAPI bridge: tools/call replay guard", () => {
  const callRequest = {
    method: "tools/call" as const,
    params: { name: "autotask__autotask_resolve_id", arguments: {} },
  };
  const context = { namespaceUuid: "ns-1", sessionId: "openapi_ns-1" };

  beforeEach(() => {
    invalidateServerConnectionMock.mockReset();
    getSessionMock.mockReset();
  });

  // A failing replay case leaves its unconsumed mockResolvedValueOnce queued,
  // and the next block only clears mocks, so reset here to keep a failure
  // reported against the test that caused it.
  afterEach(() => {
    invalidateServerConnectionMock.mockReset();
    getSessionMock.mockReset();
  });

  it.each([
    [
      "a request timeout (-32001)",
      new McpError(ErrorCode.RequestTimeout, "Request timed out", {
        timeout: 60000,
      }),
    ],
    [
      "a connection dropped mid-call (-32000)",
      new McpError(ErrorCode.ConnectionClosed, "Connection closed"),
    ],
    [
      "a backend-answered -32603 'Not connected'",
      new McpError(ErrorCode.InternalError, "Not connected"),
    ],
    [
      "a 5xx answer to the POST",
      new StreamableHTTPError(502, "Error POSTing to endpoint: Bad Gateway"),
    ],
    [
      "a Streamable HTTP 502 body quoting a downstream session error",
      new StreamableHTTPError(
        502,
        "Error POSTing to endpoint: downstream (HTTP 404): Session not found",
      ),
    ],
    [
      "an SSE HTTP 500 body quoting a downstream session error",
      new Error(
        "Error POSTing to endpoint (HTTP 500): downstream (HTTP 404): Session not found",
      ),
    ],
  ])("surfaces %s with no replay", async (_label, failure) => {
    const stale = makeFakeSession(vi.fn().mockRejectedValueOnce(failure));
    getSessionMock.mockResolvedValueOnce(stale);

    const handler = createOriginalCallToolHandler();
    await expect(handler(callRequest, context)).rejects.toBe(failure);

    expect(stale.client.request).toHaveBeenCalledTimes(1);
    expect(invalidateServerConnectionMock).not.toHaveBeenCalled();
    expect(getSessionMock).toHaveBeenCalledTimes(1);
  });

  it.each([
    [
      "an HTTP 404 'Session not found' StreamableHTTPError",
      new StreamableHTTPError(
        404,
        'Error POSTing to endpoint: {"jsonrpc":"2.0","error":{"code":-32001,"message":"Session not found"},"id":null}',
      ),
    ],
    ["the SDK's pre-send 'Not connected'", new Error("Not connected")],
  ])("replays once after %s", async (_label, failure) => {
    const successResult: CallToolResult = {
      content: [{ type: "text", text: "ok" }],
    };
    const stale = makeFakeSession(vi.fn().mockRejectedValueOnce(failure));
    const fresh = makeFakeSession(vi.fn().mockResolvedValueOnce(successResult));
    getSessionMock.mockResolvedValueOnce(stale).mockResolvedValueOnce(fresh);

    const handler = createOriginalCallToolHandler();
    await expect(handler(callRequest, context)).resolves.toEqual(successResult);

    expect(stale.client.request).toHaveBeenCalledTimes(1);
    expect(fresh.client.request).toHaveBeenCalledTimes(1);
    expect(invalidateServerConnectionMock).toHaveBeenCalledTimes(1);
  });
});

describe("OpenAPI bridge — tools/list DEGRADED tripwire", () => {
  // Parity with metamcp-proxy.ts's PR #28 tripwire. The Grafana alert
  // greps `DEGRADED for namespace`; before this, OpenAPI-path
  // degradation (n8n, registry-sync, other clients) never produced the line.

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

  describe("a server whose listing step rejects before the per-server catch", () => {
    // getSession and the configService reads run before the `try` in the
    // per-server callback, so a throw there rejects the callback instead of
    // reaching the catch that counts the server. Before this the client-facing
    // listing dropped the server with no DEGRADED line and no cause.
    const healthy = () =>
      makeFakeSession(
        vi.fn().mockResolvedValue({
          tools: [{ name: "resolve_id", description: "d", inputSchema: {} }],
        }),
      );
    const listWithTwoServers = async () => {
      fakeServerParams["server-other"] = { name: "other" };
      try {
        return await createOriginalListToolsHandler()(
          { method: "tools/list", params: {} },
          { namespaceUuid: "ns-1", sessionId: "openapi_ns-1" },
        );
      } finally {
        delete fakeServerParams["server-other"];
      }
    };
    const errorCallsFor = (server: string) =>
      loggerErrorMock.mock.calls.filter(
        (c) => String(c[0]) === `Error preparing tools listing for: ${server}`,
      );

    it("counts a rejecting getSession without logging its raw reason, and still returns the other servers' tools", async () => {
      const refusal = new Error("pool refused: password=SECRET");
      getSessionMock.mockImplementation(async (_sid: string, uuid: string) => {
        if (uuid === "server-autotask") throw refusal;
        return healthy();
      });

      const result = await listWithTwoServers();

      expect(result.tools.map((t) => t.name)).toEqual(["other__resolve_id"]);
      const logged = errorCallsFor("autotask");
      expect(logged).toHaveLength(1);
      expect(logged[0]).toEqual([
        "Error preparing tools listing for: autotask",
      ]);
      expect(JSON.stringify(loggerErrorMock.mock.calls)).not.toContain(
        "SECRET",
      );
      expect(errorCallsFor("other")).toHaveLength(0);
      const messages = loggerErrorMock.mock.calls.map((c) => String(c[0]));
      expect(messages).toContain(
        "tools/list DEGRADED for namespace ns-1 (OpenAPI bridge): 1/2 backend server(s) failed (autotask); returning 1 tools",
      );
    });

    it("counts a rejecting configService read without logging its raw reason, and still returns the other servers' tools", async () => {
      const unreachable = new Error("config store unreachable");
      getSessionMock.mockImplementation(async () => healthy());
      // One rejection: whichever server reads the timeout first fails, the
      // other reads it normally.
      vi.mocked(configService.getMcpTimeout).mockRejectedValueOnce(unreachable);

      const result = await listWithTwoServers();

      expect(result.tools).toHaveLength(1);
      const logged = [...errorCallsFor("autotask"), ...errorCallsFor("other")];
      expect(logged).toHaveLength(1);
      expect(logged[0]).toHaveLength(1);
      const degraded = loggerErrorMock.mock.calls
        .map((c) => String(c[0]))
        .filter((m) => m.includes("DEGRADED"));
      expect(degraded).toHaveLength(1);
      expect(degraded[0]).toMatch(
        /\(OpenAPI bridge\): 1\/2 backend server\(s\) failed \((autotask|other)\); returning 1 tools$/,
      );
    });

    it("names a lone rejected server in the DEGRADED line, and the response is unchanged", async () => {
      getSessionMock.mockRejectedValue(new Error("pool refused"));

      const result = await createOriginalListToolsHandler()(
        { method: "tools/list", params: {} },
        { namespaceUuid: "ns-1", sessionId: "openapi_ns-1" },
      );

      expect(result).toEqual({ tools: [] });
      const messages = loggerErrorMock.mock.calls.map((c) => String(c[0]));
      expect(messages).toContain(
        "tools/list DEGRADED for namespace ns-1 (OpenAPI bridge): 1/1 backend server(s) failed (autotask); returning 0 tools",
      );
      expect(loggerInfoMock).not.toHaveBeenCalled();
      expect(loggerWarnMock).not.toHaveBeenCalled();
    });
  });

  it("never builds an audit cause for a client-facing listing", async () => {
    // Four failures on the client-facing path: the pool answers null, the
    // acquisition rejects, a config read rejects, and the backend request
    // throws. Each site's cause is lazy, so none reaches the formatter an
    // audit listing pays for (it is the one that scrubs and bounds a message).
    const spy = vi.mocked(describeListingFailure);
    spy.mockClear();
    const handler = createOriginalListToolsHandler();
    const list = () =>
      handler(
        { method: "tools/list", params: {} },
        { namespaceUuid: "ns-1", sessionId: "openapi_ns-1" },
      );

    getSessionMock.mockResolvedValue(null);
    await list();
    getSessionMock.mockRejectedValue(new Error("pool refused"));
    await list();
    getSessionMock.mockResolvedValue(
      makeFakeSession(vi.fn().mockResolvedValue({ tools: [] })),
    );
    vi.mocked(configService.getMcpTimeout).mockRejectedValueOnce(
      new Error("config store unreachable"),
    );
    await list();
    getSessionMock.mockResolvedValue(
      makeFakeSession(vi.fn().mockRejectedValue(new Error("boom"))),
    );
    await list();

    const degraded = loggerErrorMock.mock.calls.filter((c) =>
      String(c[0]).includes("DEGRADED"),
    );
    expect(degraded).toHaveLength(4);
    expect(spy).not.toHaveBeenCalled();
    expect(loggerInfoMock).not.toHaveBeenCalled();
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

describe("OpenAPI bridge: argument shape for callers that never list (n8n)", () => {
  // n8n posts to <namespace>/api/<tool> and never reads openapi.json in the
  // same breath, so before this the bridge recorded counts only for every
  // call. The bridge now lists for its own audit after the call.
  const backendTools = (properties: Record<string, object>) => ({
    tools: [{ name: "search", inputSchema: { type: "object", properties } }],
  });
  const answer: CallToolResult = { content: [{ type: "text", text: "found" }] };

  function backend(
    listing: () => Promise<unknown>,
  ): ReturnType<typeof makeFakeSession> {
    return makeFakeSession(
      vi.fn(async (req: { method: string }) =>
        req.method === "tools/list" ? listing() : answer,
      ),
    );
  }

  const callThroughBridge = (namespace: string, args: unknown) => {
    const { callToolWithMiddleware, handlerContext } =
      createMiddlewareEnabledHandlers(`openapi_${namespace}`, namespace, "n8n");
    return callToolWithMiddleware(
      {
        method: "tools/call",
        params: {
          name: "autotask__search",
          arguments: args as Record<string, unknown>,
        },
      },
      handlerContext,
    );
  };

  // The cause lines an audit listing logs, one per server it could not list.
  const auditCauses = () =>
    loggerInfoMock.mock.calls
      .map((c) => String(c[0]))
      .filter((line) => line.includes("audit listing for namespace"));
  // What the log panels count as failures; these lines must stay out of it.
  const PANEL_WORDS = /\b(error|fatal|panic|exception)\b/i;

  let recorder: ReturnType<typeof vi.fn<(entry: any) => Promise<void>>>;
  beforeEach(() => {
    resetBridgeAuditSchemasForTesting();
    invalidateServerConnectionMock.mockReset();
    getSessionMock.mockReset();
    loggerErrorMock.mockReset();
    loggerWarnMock.mockReset();
    loggerInfoMock.mockReset();
    vi.mocked(describeListingFailure).mockClear();
    recorder = vi.fn().mockResolvedValue(undefined);
    setAuditRecorderForTesting(recorder);
  });
  afterEach(() => {
    setAuditRecorderForTesting(null);
  });

  it("stores the declared keys and the enum selector value, never a caller-chosen key", async () => {
    getSessionMock.mockResolvedValue(
      backend(async () =>
        backendTools({ mode: { enum: ["list"] }, q: {}, limit: {} }),
      ),
    );

    const result = await callThroughBridge("ns-a", {
      mode: "list",
      q: "printer",
      Alice_Smith: 1,
    });

    expect(result).toBe(answer);
    await vi.waitFor(() => expect(recorder).toHaveBeenCalledTimes(1));
    expect(recorder.mock.calls[0][0]).toMatchObject({
      session_id: "openapi_ns-a",
      client_name: "n8n",
      success: true,
      args_shape: {
        keys: ["mode", "q"],
        sel: { mode: "list" },
        unknown_keys: 1,
      },
    });
    expect(JSON.stringify(recorder.mock.calls[0][0].args_shape)).not.toContain(
      "Alice_Smith",
    );
  });

  it("a failed bridge listing keeps the count-only shape, the call succeeds, and no DEGRADED line is logged", async () => {
    getSessionMock.mockResolvedValue(
      backend(async () => {
        throw new Error("listing unavailable");
      }),
    );

    const result = await callThroughBridge("ns-a", { mode: "list", q: "x" });

    expect(result).toBe(answer);
    await vi.waitFor(() => expect(recorder).toHaveBeenCalledTimes(1));
    expect(recorder.mock.calls[0][0].args_shape).toEqual({
      keys: [],
      unverified_keys: 2,
    });
    expect(loggerErrorMock).not.toHaveBeenCalled();
    // The listing's cause is in the log: the server and the class and message
    // of what the backend request threw, no tool arguments.
    expect(auditCauses()).toEqual([
      "OpenAPI bridge: audit listing for namespace ns-a did not list server autotask: Err*: listing unavailable",
    ]);
    expect(describeListingFailure).toHaveBeenCalledTimes(1);
    expect(auditCauses()[0]).not.toMatch(PANEL_WORDS);
  });

  it("an audit listing's lost session cannot invalidate concurrent calls' connections", async () => {
    getSessionMock.mockResolvedValue(
      backend(async () => {
        throw new Error(sessionLostEnvelope);
      }),
    );

    expect(await callThroughBridge("ns-a", { mode: "list" })).toBe(answer);
    await vi.waitFor(() => expect(recorder).toHaveBeenCalledTimes(1));
    expect(invalidateServerConnectionMock).not.toHaveBeenCalled();
    expect(recorder.mock.calls[0][0].args_shape).toEqual({
      keys: [],
      unverified_keys: 1,
    });
  });

  it("a failed audit session acquisition emits one warning and preserves the call", async () => {
    getSessionMock
      .mockResolvedValueOnce(backend(async () => backendTools({ q: {} })))
      .mockRejectedValueOnce(new Error("session acquisition unavailable"));

    expect(await callThroughBridge("ns-a", { q: "x" })).toBe(answer);
    await vi.waitFor(() => expect(recorder).toHaveBeenCalledTimes(1));
    expect(recorder.mock.calls[0][0].args_shape).toEqual({
      keys: [],
      unverified_keys: 1,
    });
    expect(loggerErrorMock).not.toHaveBeenCalled();
    expect(loggerWarnMock).toHaveBeenCalledExactlyOnceWith(
      expect.stringContaining("could not list 1 server(s) (autotask)"),
    );
    // Rejected before the per-server catch: counted, and now says why.
    expect(auditCauses()).toEqual([
      "OpenAPI bridge: audit listing for namespace ns-a did not list server autotask: Err*: session acquisition unavailable",
    ]);
    expect(auditCauses()[0]).not.toMatch(PANEL_WORDS);
  });

  it("an audit listing the pool cannot serve names the reason, and the call is unchanged", async () => {
    getSessionMock
      .mockResolvedValueOnce(backend(async () => backendTools({ q: {} })))
      .mockResolvedValueOnce(null);

    expect(await callThroughBridge("ns-a", { q: "x" })).toBe(answer);
    await vi.waitFor(() => expect(recorder).toHaveBeenCalledTimes(1));
    expect(recorder.mock.calls[0][0].args_shape).toEqual({
      keys: [],
      unverified_keys: 1,
    });
    expect(loggerErrorMock).not.toHaveBeenCalled();
    expect(auditCauses()).toEqual([
      "OpenAPI bridge: audit listing for namespace ns-a did not list server autotask: the pool returned no session (server gated, at the connection cap, or backend unreachable)",
    ]);
    expect(auditCauses()[0]).not.toMatch(PANEL_WORDS);
  });

  it("an audit listing names a server whose name holds the tool-name separator", async () => {
    fakeServerParams["server-separator"] = { name: "a__b\npassword=SECRET" };
    getSessionMock.mockResolvedValue(
      backend(async () => backendTools({ q: {} })),
    );

    try {
      expect(await callThroughBridge("ns-a", { q: "x" })).toBe(answer);
      await vi.waitFor(() => expect(recorder).toHaveBeenCalledTimes(1));
      expect(auditCauses()).toContain(
        "OpenAPI bridge: audit listing for namespace ns-a did not list server a__bpassword=[redacted]: the server name contains the tool-name separator",
      );
      expect(loggerWarnMock).toHaveBeenCalledWith(
        "OpenAPI bridge: audit listing for namespace ns-a could not list 1 server(s) (a__bpassword=[redacted]); calls to their tools keep the count-only args_shape",
      );
      expect(loggerErrorMock).not.toHaveBeenCalled();
    } finally {
      delete fakeServerParams["server-separator"];
    }
  });

  it("a served listing writes no audit cause line", async () => {
    getSessionMock.mockRejectedValue(new Error("pool refused"));

    await createOriginalListToolsHandler()(
      { method: "tools/list", params: {} },
      { namespaceUuid: "ns-a", sessionId: "openapi_ns-a" },
    );

    expect(auditCauses()).toEqual([]);
  });

  it("a failed listing of the routing winner cannot verify keys from a colliding server", async () => {
    const first = backend(async () => {
      throw new Error("listing unavailable");
    });
    const second = backend(async () => backendTools({ Alice_Smith: {} }));
    fakeServerParams["server-autotask-2"] = { name: "autotask!" };
    getSessionMock.mockImplementation(
      async (_sessionId: string, serverUuid: string) =>
        serverUuid === "server-autotask-2" ? second : first,
    );

    try {
      expect(await callThroughBridge("ns-a", { Alice_Smith: 1 })).toBe(answer);
      await vi.waitFor(() => expect(recorder).toHaveBeenCalledTimes(1));
      expect(recorder.mock.calls[0][0].args_shape).toEqual({
        keys: [],
        unverified_keys: 1,
      });
    } finally {
      delete fakeServerParams["server-autotask-2"];
    }
  });

  it("each namespace's bridge session keeps its own snapshot, and a namespace lists once per interval", async () => {
    const first = backend(async () =>
      backendTools({ mode: { enum: ["list"] }, q: {} }),
    );
    const second = backend(async () =>
      backendTools({ mode: { enum: ["Alice_Smith"] }, Alice_Smith: {} }),
    );
    getSessionMock.mockImplementation(async (sessionId: string) =>
      sessionId === "openapi_ns-a" ? first : second,
    );
    const args = { mode: "Alice_Smith", Alice_Smith: 1, q: "x" };

    await callThroughBridge("ns-a", args);
    await vi.waitFor(() => expect(recorder).toHaveBeenCalledTimes(1));
    await callThroughBridge("ns-b", args);
    await vi.waitFor(() => expect(recorder).toHaveBeenCalledTimes(2));
    await callThroughBridge("ns-a", { mode: "list" });
    await vi.waitFor(() => expect(recorder).toHaveBeenCalledTimes(3));

    const shapes = recorder.mock.calls.map((c) => c[0].args_shape);
    expect(shapes[0]).toEqual({
      keys: ["mode", "q"],
      sel: { mode: "?" },
      unknown_keys: 1,
    });
    expect(shapes[1]).toEqual({
      keys: ["Alice_Smith", "mode"],
      sel: { mode: "Alice_Smith" },
      unknown_keys: 1,
    });
    expect(shapes[2]).toEqual({ keys: ["mode"], sel: { mode: "list" } });
    const listingsOn = (session: ReturnType<typeof backend>) =>
      session.client.request.mock.calls.filter(
        ([req]) => (req as { method: string }).method === "tools/list",
      ).length;
    expect(listingsOn(first)).toBe(1);
    expect(listingsOn(second)).toBe(1);
  });
});
