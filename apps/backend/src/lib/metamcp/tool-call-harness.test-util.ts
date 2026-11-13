/**
 * Shared harness for the proxy-level tools/call tests (progress, cancel,
 * audit, pagination): a real SDK consumer `Client` talks to the gateway's own
 * `Server` over `InMemoryTransport`, and each backend is a real SDK `Server`
 * behind a real SDK `Client`. Only the gateway's pool is faked, at its
 * `getSession` seam, so the SDK's own progress, cancel and timeout logic
 * runs for real on both hops. The caller's test file owns the `vi.mock`
 * calls (they are hoisted per file) and passes `createServer` in.
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import type { RequestHandlerExtra } from "@modelcontextprotocol/sdk/shared/protocol.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import {
  CallToolRequestSchema,
  type CallToolResult,
  type JSONRPCMessage,
  ListToolsRequestSchema,
  type ServerNotification,
  type ServerRequest,
} from "@modelcontextprotocol/sdk/types.js";

import type { ConnectedClient } from "./client";

export type BackendExtra = RequestHandlerExtra<
  ServerRequest,
  ServerNotification
>;

export interface BackendCall {
  name: string;
  args: Record<string, unknown>;
  /** The progress token the backend was given (the SDK's own, never ours). */
  token: string | number | undefined;
  signal: AbortSignal;
}

export interface TestBackend {
  session: ConnectedClient;
  server: Server;
  calls: BackendCall[];
  close: () => Promise<void>;
}

export const OK: CallToolResult = { content: [{ type: "text", text: "done" }] };

/** Yields enough microtask turns for in-memory request chains to settle. */
export async function flush(turns = 100): Promise<void> {
  for (let i = 0; i < turns; i += 1) await Promise.resolve();
}

/** A timer that also ends when `signal` aborts, so a test never dangles. */
export function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    if (signal?.aborted) return resolve();
    const timer = setTimeout(resolve, ms);
    signal?.addEventListener(
      "abort",
      () => {
        clearTimeout(timer);
        resolve();
      },
      { once: true },
    );
  });
}

/** Sends one progress notification under the token the backend was given. */
export function sendProgress(
  extra: BackendExtra,
  progress: number,
  total?: number,
): Promise<void> {
  const token = extra._meta?.progressToken;
  if (token === undefined) return Promise.resolve();
  return extra.sendNotification({
    method: "notifications/progress",
    params: { progressToken: token, progress, ...(total ? { total } : {}) },
  });
}

/**
 * A real backend `Server` with one tool, `tool` (default "long_job"),
 * connected to a real `Client` that is wrapped as the gateway's pooled
 * session. `onCall` runs once per tools/call.
 */
export async function makeBackend(
  onCall: (extra: BackendExtra, call: BackendCall) => Promise<CallToolResult>,
  options: { toolName?: string; serverName?: string } = {},
): Promise<TestBackend> {
  const toolName = options.toolName ?? "long_job";
  const server = new Server(
    { name: options.serverName ?? "ninja", version: "1.0.0" },
    { capabilities: { tools: {} } },
  );
  const calls: BackendCall[] = [];
  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [{ name: toolName, inputSchema: { type: "object" } }],
  }));
  server.setRequestHandler(CallToolRequestSchema, async (request, extra) => {
    const token = extra._meta?.progressToken;
    const call: BackendCall = {
      name: request.params.name,
      args: (request.params.arguments ?? {}) as Record<string, unknown>,
      token: typeof token === "object" ? undefined : token,
      signal: extra.signal,
    };
    calls.push(call);
    return onCall(extra, call);
  });
  const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
  await server.connect(serverSide);
  const client = new Client({ name: "metamcp", version: "1.0.0" });
  await client.connect(clientSide);
  return {
    session: {
      client,
      cleanup: () => client.close(),
      listChangedSubscribers: new Set(),
    },
    server,
    calls,
    close: () => client.close(),
  };
}

export interface Gateway {
  consumer: Client;
  server: Server;
  /** The gateway side of the consumer link; wrap `send` to gate messages. */
  gatewayTransport: InMemoryTransport;
  close: () => Promise<void>;
}

/** The method of an outbound JSON-RPC message, when it has one. */
export const methodOf = (message: JSONRPCMessage): string | undefined =>
  "method" in message ? message.method : undefined;

/** A real consumer `Client` connected to a fresh `createServer` instance. */
export async function connectGateway(
  createServer: (
    namespaceUuid: string,
    sessionId: string,
  ) => Promise<{ server: Server }>,
  options: {
    sessionId?: string;
    /** Runs before the gateway connects, to wrap the gateway-side transport. */
    wrapTransport?: (transport: InMemoryTransport) => void;
  } = {},
): Promise<Gateway> {
  const { server } = await createServer("ns-1", options.sessionId ?? "sess-1");
  const [consumerSide, gatewaySide] = InMemoryTransport.createLinkedPair();
  options.wrapTransport?.(gatewaySide);
  await server.connect(gatewaySide);
  const consumer = new Client({ name: "consumer", version: "1.0.0" });
  await consumer.connect(consumerSide);
  return {
    consumer,
    server,
    gatewayTransport: gatewaySide,
    close: () => consumer.close(),
  };
}

/** Gate an outbound message class on a promise the test controls. */
export function gateSends(
  transport: InMemoryTransport,
  shouldGate: (message: JSONRPCMessage) => boolean,
  gate: () => Promise<void>,
): void {
  const original = transport.send.bind(transport);
  transport.send = async (message, options) => {
    if (shouldGate(message)) await gate();
    return original(message, options);
  };
}

/** A transport whose stream can "drop" without close() ever being called. */
export class DroppableTransport implements Transport {
  onclose?: () => void;
  onerror?: (error: Error) => void;
  onmessage?: (message: JSONRPCMessage) => void;
  sent: JSONRPCMessage[] = [];
  async start(): Promise<void> {}
  async send(message: JSONRPCMessage): Promise<void> {
    this.sent.push(message);
  }
  async close(): Promise<void> {
    throw new Error("the legacy stream transport is never closed by the SDK");
  }
  /** What SSEServerTransport does when the response stream ends. */
  drop(): void {
    this.onclose?.();
  }
}

/** Real HTTP transport refusal shapes, without opening a network connection. */
export async function makeHttpRefusingBackend(
  statuses: number[],
  options: { serverName?: string; body?: string } = {},
): Promise<{
  session: ConnectedClient;
  requests: string[];
  close: () => Promise<void>;
}> {
  const requests: string[] = [];
  const transport = new StreamableHTTPClientTransport(
    new URL("https://backend.test/mcp"),
    {
      fetch: (async (_url: unknown, init?: RequestInit) => {
        if ((init?.method ?? "GET") === "GET") {
          return new Response(null, { status: 405 });
        }
        const request = JSON.parse(String(init?.body)) as {
          id?: number;
          method: string;
        };
        if (request.method === "initialize") {
          return Response.json({
            jsonrpc: "2.0",
            id: request.id,
            result: {
              protocolVersion: "2025-06-18",
              capabilities: { tools: {} },
              serverInfo: { name: options.serverName ?? "ninja", version: "1" },
            },
          });
        }
        if (request.id === undefined) {
          return new Response(null, { status: 202 });
        }
        const status = statuses[Math.min(requests.length, statuses.length - 1)];
        requests.push(request.method);
        return new Response(
          status === 404 ? "Session not found" : (options.body ?? "denied"),
          { status },
        );
      }) as typeof fetch,
    },
  );
  const client = new Client({ name: "metamcp", version: "1" });
  await client.connect(transport);
  return {
    session: {
      client,
      cleanup: () => client.close(),
      listChangedSubscribers: new Set(),
    },
    requests,
    close: () => client.close(),
  };
}
