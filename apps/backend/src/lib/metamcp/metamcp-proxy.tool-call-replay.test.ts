/**
 * tools/call replay guard in `metamcp-proxy.ts`, driven end to end.
 *
 * On 2026-09-30 a delete on a client machine ran twice: the gateway's
 * backend tools/call hit the 60 s MCP_TIMEOUT, the SDK rejected with
 * McpError -32001 "Request timed out", the session-lost detector read -32001
 * as a lost session, and the proxy invalidated the pool and re-sent the
 * call. A tool call is not idempotent, so the gateway now replays one only
 * when the failure proves the backend never ran it (HTTP 404 "Session not
 * found", or a transport already closed before the send).
 *
 * Everything here is the real MCP SDK: a consumer `Client` talks to the
 * gateway's own `Server` from `createServer`, and the pooled backend
 * sessions are SDK `Client`s connected to SDK backend `Server`s over
 * `InMemoryTransport`. The one exception is the HTTP 404 case, where the
 * stale session rejects with the SDK's own `StreamableHTTPError` because an
 * in-memory transport has no HTTP status (`session-error.test.ts` captures
 * that error from a real HTTP round trip). Each backend counts how many
 * times its tool actually executed, which is the property under test.
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPError } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  CallToolRequestSchema,
  CallToolResult,
  CallToolResultSchema,
  ErrorCode,
  ListToolsRequestSchema,
  McpError,
} from "@modelcontextprotocol/sdk/types.js";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { ConnectedClient } from "./client";

const { getSessionMock, invalidateServerConnectionMock, config } = vi.hoisted(
  () => ({
    getSessionMock: vi.fn(),
    invalidateServerConnectionMock: vi.fn(),
    // The gateway's backend request timeout (MCP_TIMEOUT, 60 s in prod).
    config: { mcpTimeoutMs: 5_000 },
  }),
);

vi.mock("@/utils/logger", () => ({
  default: { error: vi.fn(), warn: vi.fn(), info: vi.fn(), debug: vi.fn() },
}));

// db/index.ts throws at import without DATABASE_URL; the proxy reaches it
// through the repositories and utils.ts.
vi.mock("../../db", () => ({ db: {} }));
vi.mock("../../db/schema", () => ({}));
vi.mock("../../db/repositories/namespaces.repo", () => ({
  namespacesRepository: {
    findServersForNamespaceToolName: vi.fn().mockResolvedValue([]),
  },
}));
vi.mock("../../db/repositories/oauth-sessions.repo", () => ({
  oauthSessionsRepository: {},
}));
vi.mock("../../trpc/tools.impl", () => ({ toolsImplementations: {} }));

vi.mock("../config.service", () => ({
  configService: {
    getMcpResetTimeoutOnProgress: async () => false,
    getMcpTimeout: async () => config.mcpTimeoutMs,
    getMcpMaxTotalTimeout: async () => 60_000,
    getMcpToolCallReconnectWarmupTimeout: async () => 0,
  },
}));

vi.mock("./fetch-metamcp", () => ({
  getMcpServers: vi.fn(async () => ({ "server-ninja": { name: "ninja" } })),
}));

vi.mock("./mcp-server-pool", () => ({
  mcpServerPool: {
    getSession: getSessionMock,
    invalidateServerConnection: invalidateServerConnectionMock,
    cleanupSession: vi.fn(),
  },
}));

// The middleware stack is pass-through here; the handler under test is the
// proxy's own tools/call routing and recovery.
vi.mock("./metamcp-middleware/auditing.functional", () => ({
  createAuditingMiddleware: () => (next: unknown) => next,
}));
vi.mock("./metamcp-middleware/filter-tools.functional", () => ({
  createFilterCallToolMiddleware: () => (next: unknown) => next,
  createFilterListToolsMiddleware: () => (next: unknown) => next,
}));
vi.mock("./metamcp-middleware/tool-overrides.functional", () => ({
  createToolOverridesCallToolMiddleware: () => (next: unknown) => next,
  createToolOverridesListToolsMiddleware: () => (next: unknown) => next,
  mapOverrideNameToOriginal: vi.fn(async (name: string) => name),
}));
vi.mock("./cold-connect-broker-fallback", () => ({
  resolveColdConnectBrokerFallback: () => undefined,
}));
vi.mock("./tool-call-warmup", () => ({
  acquireSessionWithBoundedWarmup: vi.fn(async () => undefined),
}));

import { createServer } from "./metamcp-proxy";

const TOOL = "ninja__delete_file";
const deleted: CallToolResult = {
  content: [{ type: "text", text: "deleted" }],
};

type OnCall = (backend: Server) => Promise<CallToolResult>;

interface Backend {
  session: ConnectedClient;
  backend: Server;
  executions: () => number;
}

const cleanups: Array<() => Promise<unknown>> = [];

async function realBackend(onCall: OnCall): Promise<Backend> {
  const backend = new Server(
    { name: "ninja", version: "1.0.0" },
    { capabilities: { tools: {} } },
  );
  let executions = 0;
  backend.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [{ name: "delete_file", inputSchema: { type: "object" } }],
  }));
  backend.setRequestHandler(CallToolRequestSchema, async () => {
    executions += 1;
    return onCall(backend);
  });
  const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
  await backend.connect(serverSide);
  const client = new Client({ name: "metamcp", version: "1.0.0" });
  await client.connect(clientSide);
  cleanups.push(() => client.close());
  return {
    session: {
      client,
      cleanup: () => client.close(),
      listChangedSubscribers: new Set(),
    },
    backend,
    executions: () => executions,
  };
}

/**
 * A pooled session that answers the proxy's dynamic-find tools/list and then
 * fails the tools/call with `callError`, without reaching any backend.
 */
function staleSession(callError: Error): {
  session: ConnectedClient;
  toolCalls: () => number;
} {
  let toolCalls = 0;
  const request = vi.fn(async (req: { method: string }) => {
    if (req.method === "tools/list") {
      return {
        tools: [{ name: "delete_file", inputSchema: { type: "object" } }],
      };
    }
    toolCalls += 1;
    throw callError;
  });
  const client = {
    request,
    getServerCapabilities: () => ({ tools: {} }),
    getServerVersion: () => ({ name: "ninja", version: "1.0.0" }),
  } as unknown as Client;
  return {
    session: {
      client,
      cleanup: async () => undefined,
      listChangedSubscribers: new Set(),
    },
    toolCalls: () => toolCalls,
  };
}

async function connectConsumer(): Promise<Client> {
  const { server } = await createServer("ns-1", "sess-1");
  const [consumerSide, gatewaySide] = InMemoryTransport.createLinkedPair();
  await server.connect(gatewaySide);
  const consumer = new Client({ name: "consumer", version: "1.0.0" });
  await consumer.connect(consumerSide);
  cleanups.push(() => consumer.close());
  return consumer;
}

const callTool = (consumer: Client) =>
  consumer.request(
    { method: "tools/call", params: { name: TOOL, arguments: {} } },
    CallToolResultSchema,
    { timeout: 10_000 },
  );

async function rejectionOf(promise: Promise<unknown>): Promise<McpError> {
  try {
    await promise;
  } catch (error) {
    return error as McpError;
  }
  throw new Error("expected the tools/call to reject");
}

beforeEach(() => {
  getSessionMock.mockReset();
  invalidateServerConnectionMock.mockReset();
  invalidateServerConnectionMock.mockResolvedValue(undefined);
  config.mcpTimeoutMs = 5_000;
});

afterEach(async () => {
  while (cleanups.length > 0) {
    await cleanups
      .pop()?.()
      .catch(() => undefined);
  }
});

describe("metamcp-proxy tools/call: no replay once the call may have run", () => {
  it("surfaces a gateway timeout to the consumer and executes the tool once", async () => {
    config.mcpTimeoutMs = 50;
    let release: () => void = () => undefined;
    const target = await realBackend(
      () =>
        new Promise((resolve) => {
          release = () => resolve(deleted);
        }),
    );
    cleanups.push(async () => release());
    getSessionMock.mockResolvedValue(target.session);

    const error = await rejectionOf(callTool(await connectConsumer()));

    expect(error.code).toBe(ErrorCode.RequestTimeout);
    expect(error.message).toContain("Request timed out");
    expect(target.executions()).toBe(1);
    expect(invalidateServerConnectionMock).not.toHaveBeenCalled();
    // Only the routing lookup; no re-acquire for a second send.
    expect(getSessionMock).toHaveBeenCalledTimes(1);
  });

  it("surfaces a connection dropped mid-call and executes the tool once", async () => {
    const target = await realBackend((backend) => {
      // The backend received and started the call, then went away.
      void backend.close();
      return new Promise(() => undefined);
    });
    getSessionMock.mockResolvedValue(target.session);

    const error = await rejectionOf(callTool(await connectConsumer()));

    expect(error.code).toBe(ErrorCode.ConnectionClosed);
    expect(target.executions()).toBe(1);
    expect(invalidateServerConnectionMock).not.toHaveBeenCalled();
    expect(getSessionMock).toHaveBeenCalledTimes(1);
  });

  it("does not replay a backend-answered -32603 'Not connected' (the old detector did)", async () => {
    // A backend that is itself a gateway relays its own transport loss as a
    // JSON-RPC error. It reached a backend, so it proves nothing about
    // whether the tool ran.
    const target = await realBackend(async () => {
      throw new McpError(ErrorCode.InternalError, "Not connected");
    });
    getSessionMock.mockResolvedValue(target.session);

    const error = await rejectionOf(callTool(await connectConsumer()));

    expect(error.code).toBe(ErrorCode.InternalError);
    expect(error.message).toContain("Not connected");
    expect(target.executions()).toBe(1);
    expect(invalidateServerConnectionMock).not.toHaveBeenCalled();
  });

  it("does not replay a 5xx answer to the POST", async () => {
    const stale = staleSession(
      new StreamableHTTPError(502, "Error POSTing to endpoint: Bad Gateway"),
    );
    getSessionMock.mockResolvedValue(stale.session);

    const error = await rejectionOf(callTool(await connectConsumer()));

    expect(error.message).toContain("Bad Gateway");
    expect(stale.toolCalls()).toBe(1);
    expect(invalidateServerConnectionMock).not.toHaveBeenCalled();
  });
});

describe("metamcp-proxy tools/call: one replay when the call provably never ran", () => {
  it("replays once after an HTTP 404 'Session not found' answer", async () => {
    const stale = staleSession(
      new StreamableHTTPError(
        404,
        'Error POSTing to endpoint: {"jsonrpc":"2.0","error":{"code":-32001,"message":"Session not found"},"id":null}',
      ),
    );
    const fresh = await realBackend(async () => deleted);
    getSessionMock
      .mockResolvedValueOnce(stale.session)
      .mockResolvedValueOnce(fresh.session);

    const result = await callTool(await connectConsumer());

    expect(result.content).toEqual(deleted.content);
    expect(stale.toolCalls()).toBe(1);
    expect(fresh.executions()).toBe(1);
    expect(invalidateServerConnectionMock).toHaveBeenCalledTimes(1);
    expect(invalidateServerConnectionMock).toHaveBeenCalledWith(
      "sess-1",
      "server-ninja",
    );
  });

  it("replays once when the pooled transport closed before the send", async () => {
    // The stale session answers routing, then its transport closes, so the
    // SDK refuses the tools/call with its pre-send "Not connected".
    const stale = await realBackend(async () => deleted);
    const realRequest = stale.session.client.request.bind(stale.session.client);
    stale.session.client.request = (async (
      ...args: Parameters<typeof realRequest>
    ) => {
      const result = await realRequest(...args);
      if (args[0].method === "tools/list") {
        await stale.session.client.close();
      }
      return result;
    }) as typeof realRequest;
    const fresh = await realBackend(async () => deleted);
    getSessionMock
      .mockResolvedValueOnce(stale.session)
      .mockResolvedValueOnce(fresh.session);

    const result = await callTool(await connectConsumer());

    expect(result.content).toEqual(deleted.content);
    expect(stale.executions()).toBe(0);
    expect(fresh.executions()).toBe(1);
    expect(invalidateServerConnectionMock).toHaveBeenCalledTimes(1);
  });
});

describe("metamcp-proxy dynamic-find tools/list keeps its recovery", () => {
  it("still invalidates and retries the list on a dead pooled transport", async () => {
    // tools/list is idempotent, so it keeps the broad detector: a closed
    // transport on the routing lookup is recovered, and the tool call then
    // runs once on the fresh session.
    const stale = await realBackend(async () => deleted);
    await stale.session.client.close();
    const fresh = await realBackend(async () => deleted);
    getSessionMock
      .mockResolvedValueOnce(stale.session)
      .mockResolvedValueOnce(fresh.session);

    const result = await callTool(await connectConsumer());

    expect(result.content).toEqual(deleted.content);
    expect(stale.executions()).toBe(0);
    expect(fresh.executions()).toBe(1);
    expect(invalidateServerConnectionMock).toHaveBeenCalledTimes(1);
  });
});
