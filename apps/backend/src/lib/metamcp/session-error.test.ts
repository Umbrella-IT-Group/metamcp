import { randomUUID } from "node:crypto";
import http from "node:http";
import { AddressInfo } from "node:net";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";
import {
  StreamableHTTPClientTransport,
  StreamableHTTPError,
} from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import {
  CallToolRequestSchema,
  CallToolResultSchema,
  ErrorCode,
  McpError,
} from "@modelcontextprotocol/sdk/types.js";
import { afterEach, describe, expect, it } from "vitest";

import {
  isBackendSessionLostError,
  isBackendTransportLostError,
  isRecoverableBackendError,
  isToolCallReplaySafeError,
} from "./session-error";

describe("isBackendSessionLostError", () => {
  it("matches the HTTP 404 + JSON-RPC -32600 envelope the SDK produces", () => {
    const error = new Error(
      'Error POSTing to endpoint (HTTP 404): {"jsonrpc":"2.0","id":"server-error","error":{"code":-32600,"message":"Session not found"}}',
    );
    expect(isBackendSessionLostError(error)).toBe(true);
  });

  it("matches the HTTP 404 + JSON-RPC -32001 variant some servers return", () => {
    const error = new Error(
      'Error POSTing to endpoint (HTTP 404): {"error":{"code":-32001,"message":"Session not found"},"id":"","jsonrpc":"2.0"}',
    );
    expect(isBackendSessionLostError(error)).toBe(true);
  });

  it("does not match unrelated 404s", () => {
    const error = new Error("Error POSTing to endpoint (HTTP 404): Not Found");
    expect(isBackendSessionLostError(error)).toBe(false);
  });

  it("does not match transport disconnects (transport-lost detector handles those)", () => {
    const error = new Error("Not connected");
    expect(isBackendSessionLostError(error)).toBe(false);
  });

  it("returns false for null / undefined", () => {
    expect(isBackendSessionLostError(undefined)).toBe(false);
    expect(isBackendSessionLostError(null)).toBe(false);
  });

  it("returns false for unrelated strings", () => {
    expect(isBackendSessionLostError("Session not found")).toBe(false);
    expect(isBackendSessionLostError("HTTP 404")).toBe(false);
    expect(isBackendSessionLostError("random text")).toBe(false);
  });

  it("matches a string throwable carrying the full envelope", () => {
    const message =
      'Error POSTing to endpoint (HTTP 404): {"jsonrpc":"2.0","error":{"code":-32600,"message":"Session not found"}}';
    expect(isBackendSessionLostError(message)).toBe(true);
  });

  it("matches when the session-lost error is wrapped via .cause", () => {
    const inner = new Error(
      'Error POSTing to endpoint (HTTP 404): {"jsonrpc":"2.0","error":{"code":-32600,"message":"Session not found"}}',
    );
    const outer = new Error("Failed to dispatch tool call", { cause: inner });
    expect(isBackendSessionLostError(outer)).toBe(true);
  });

  it("matches when wrapped two layers deep via .cause", () => {
    const innermost = new Error(
      'Error POSTing to endpoint (HTTP 404): {"jsonrpc":"2.0","error":{"code":-32001,"message":"Session not found"}}',
    );
    const mid = new Error("Transport rejection", { cause: innermost });
    const outer = new Error("Outer wrap", { cause: mid });
    expect(isBackendSessionLostError(outer)).toBe(true);
  });

  it("matches a JSON-RPC error envelope passed as a plain object", () => {
    // Some rejection paths surface the parsed RPC error envelope directly
    // rather than the SDK's wrapped Error. The detector inspects the
    // structured payload as well as the rendered message.
    const envelope = {
      jsonrpc: "2.0",
      id: "server-error",
      error: { code: -32600, message: "Session not found" },
    };
    expect(isBackendSessionLostError(envelope)).toBe(true);
  });

  it("matches an Error whose .code carries -32001 even when the message is sparse", () => {
    const error = Object.assign(new Error("Session not found"), {
      code: -32001,
    });
    expect(isBackendSessionLostError(error)).toBe(true);
  });

  it("falls back to String(error) for objects with only toString()", () => {
    class CustomThrowable {
      toString() {
        return 'Error POSTing to endpoint (HTTP 404): {"error":{"code":-32600,"message":"Session not found"}}';
      }
    }
    expect(isBackendSessionLostError(new CustomThrowable())).toBe(true);
  });

  it("does not match objects with unrelated -32600 contexts", () => {
    // -32600 alone (without 'Session not found') is the JSON-RPC "Invalid
    // Request" code and means many things. Don't false-positive on it.
    const error = new Error("MCP error -32600: Invalid Request");
    expect(isBackendSessionLostError(error)).toBe(false);
  });

  it("handles circular cause chains without infinite-looping", () => {
    const a = new Error("Wrapper a") as Error & { cause?: unknown };
    const b = new Error("Wrapper b") as Error & { cause?: unknown };
    a.cause = b;
    b.cause = a;
    expect(isBackendSessionLostError(a)).toBe(false);
  });

  // -32001 is also the SDK's ErrorCode.RequestTimeout. Classing a timeout
  // as session-lost made tools/call re-send a call the backend may already
  // have run (the 2026-09-30 double delete). The code alone is never enough.
  it("does not match the SDK's request-timeout McpError (-32001 'Request timed out')", () => {
    const timeout = new McpError(
      ErrorCode.RequestTimeout,
      "Request timed out",
      {
        timeout: 60000,
      },
    );
    expect(timeout.code).toBe(-32001);
    expect(isBackendSessionLostError(timeout)).toBe(false);
    expect(isRecoverableBackendError(timeout)).toBe(false);
  });

  it("does not match the SDK's other -32001 timeout shapes (max total, abort reason)", () => {
    expect(
      isBackendSessionLostError(
        new McpError(
          ErrorCode.RequestTimeout,
          "Maximum total timeout exceeded",
          {
            maxTotalTimeout: 60000,
            totalElapsed: 60001,
          },
        ),
      ),
    ).toBe(false);
    // Protocol.request's cancel() wraps an abort reason as -32001 too.
    expect(
      isBackendSessionLostError(
        new McpError(ErrorCode.RequestTimeout, "AbortError: aborted"),
      ),
    ).toBe(false);
  });

  it("does not match a bare -32001 code on a plain object or a string code", () => {
    expect(
      isBackendSessionLostError({ code: -32001, message: "Request timed out" }),
    ).toBe(false);
    expect(
      isBackendSessionLostError({
        code: "-32001",
        message: "MCP error -32001: Request timed out",
      }),
    ).toBe(false);
    expect(
      isBackendSessionLostError(
        Object.assign(new Error("boom"), { code: -32001 }),
      ),
    ).toBe(false);
  });

  it("does not match a timeout wrapped via .cause", () => {
    const timeout = new McpError(ErrorCode.RequestTimeout, "Request timed out");
    const outer = new Error("Failed to dispatch tool call", { cause: timeout });
    expect(isBackendSessionLostError(outer)).toBe(false);
  });

  it("still matches a -32001 code when the same object names 'Session not found'", () => {
    const envelope = { code: -32001, message: "Session not found" };
    expect(isBackendSessionLostError(envelope)).toBe(true);
    expect(
      isBackendSessionLostError(
        Object.assign(new Error("Session not found"), { code: "-32600" }),
      ),
    ).toBe(true);
  });
});

describe("isToolCallReplaySafeError", () => {
  const httpSessionLost =
    'Error POSTing to endpoint (HTTP 404): {"jsonrpc":"2.0","id":"server-error","error":{"code":-32600,"message":"Session not found"}}';

  it("accepts an HTTP 404 'Session not found' answer from the SSE transport", () => {
    expect(isToolCallReplaySafeError(new Error(httpSessionLost))).toBe(true);
    expect(
      isToolCallReplaySafeError(
        new Error("Error POSTing to endpoint (HTTP 404): Session not found"),
      ),
    ).toBe(true);
  });

  it("accepts a StreamableHTTPError whose HTTP status is 404 with 'Session not found'", () => {
    const error = new StreamableHTTPError(
      404,
      'Error POSTing to endpoint: {"jsonrpc":"2.0","error":{"code":-32001,"message":"Session not found"},"id":null}',
    );
    expect(isToolCallReplaySafeError(error)).toBe(true);
  });

  it("accepts the SDK's pre-send 'Not connected' rejection", () => {
    expect(isToolCallReplaySafeError(new Error("Not connected"))).toBe(true);
  });

  it("refuses every timeout shape: the backend may have executed the call", () => {
    expect(
      isToolCallReplaySafeError(
        new McpError(ErrorCode.RequestTimeout, "Request timed out", {
          timeout: 60000,
        }),
      ),
    ).toBe(false);
    expect(
      isToolCallReplaySafeError(
        new McpError(
          ErrorCode.RequestTimeout,
          "Maximum total timeout exceeded",
        ),
      ),
    ).toBe(false);
  });

  it("refuses a connection dropped mid-call (-32000 'Connection closed')", () => {
    expect(
      isToolCallReplaySafeError(
        new McpError(ErrorCode.ConnectionClosed, "Connection closed"),
      ),
    ).toBe(false);
  });

  it("refuses 5xx answers and network failures", () => {
    expect(
      isToolCallReplaySafeError(
        new StreamableHTTPError(502, "Error POSTing to endpoint: Bad Gateway"),
      ),
    ).toBe(false);
    expect(
      isToolCallReplaySafeError(
        new Error(
          "Error POSTing to endpoint (HTTP 500): Internal Server Error",
        ),
      ),
    ).toBe(false);
    expect(
      isToolCallReplaySafeError(
        new TypeError("fetch failed", {
          cause: Object.assign(new Error("read ECONNRESET"), {
            code: "ECONNRESET",
          }),
        }),
      ),
    ).toBe(false);
  });

  it("refuses an HTTP 404 that does not name the session", () => {
    expect(
      isToolCallReplaySafeError(
        new Error("Error POSTing to endpoint (HTTP 404): Not Found"),
      ),
    ).toBe(false);
    expect(
      isToolCallReplaySafeError(
        new StreamableHTTPError(404, "Error POSTing to endpoint: Not Found"),
      ),
    ).toBe(false);
  });

  it("refuses any McpError, since that is a JSON-RPC answer from the backend", () => {
    // A nested gateway relaying its own transport loss, and a backend that
    // answers "Session not found" at the JSON-RPC layer: both reached a
    // backend, so neither proves the call did not run. The old union
    // detector replayed both.
    const relayedNotConnected = new McpError(
      ErrorCode.InternalError,
      "Not connected",
    );
    expect(isRecoverableBackendError(relayedNotConnected)).toBe(true);
    expect(isToolCallReplaySafeError(relayedNotConnected)).toBe(false);
    expect(
      isToolCallReplaySafeError(new McpError(-32001, "Session not found")),
    ).toBe(false);
    // Name-based match too, so a second SDK copy's McpError is still refused.
    const foreign = Object.assign(new Error("Not connected"), {
      name: "McpError",
    });
    expect(isToolCallReplaySafeError(foreign)).toBe(false);
  });

  it("refuses 'Not connected' unless it is the exact SDK message", () => {
    expect(
      isToolCallReplaySafeError(new Error("Not connected to the database")),
    ).toBe(false);
    expect(isToolCallReplaySafeError("Not connected")).toBe(false);
    expect(
      isToolCallReplaySafeError({
        jsonrpc: "2.0",
        id: "server-error",
        error: { code: -32603, message: "Not connected" },
      }),
    ).toBe(false);
  });

  it("does not dig a proof out of a .cause chain or a rendered envelope", () => {
    const wrapped = new Error("Failed to dispatch tool call", {
      cause: new Error(httpSessionLost),
    });
    expect(isBackendSessionLostError(wrapped)).toBe(true);
    expect(isToolCallReplaySafeError(wrapped)).toBe(false);
    expect(isToolCallReplaySafeError(httpSessionLost)).toBe(false);
    expect(
      isToolCallReplaySafeError({
        jsonrpc: "2.0",
        error: { code: -32600, message: "Session not found" },
      }),
    ).toBe(false);
  });

  it("returns false for null / undefined", () => {
    expect(isToolCallReplaySafeError(undefined)).toBe(false);
    expect(isToolCallReplaySafeError(null)).toBe(false);
  });
});

// The same classification against errors the real MCP SDK produces, not
// hand-built lookalikes, so an SDK change to any of these shapes fails here
// instead of silently turning a no-replay case into a replay.
describe("classification of real MCP SDK failures", () => {
  const cleanups: Array<() => Promise<void>> = [];

  afterEach(async () => {
    while (cleanups.length > 0) {
      await cleanups
        .pop()?.()
        .catch(() => undefined);
    }
  });

  type OnCall = (backend: Server) => Promise<{ content: [] }>;

  function newBackend(onCall: OnCall): Server {
    const backend = new Server(
      { name: "backend", version: "1.0.0" },
      { capabilities: { tools: {} } },
    );
    backend.setRequestHandler(CallToolRequestSchema, () => onCall(backend));
    return backend;
  }

  async function connectInMemory(
    onCall: OnCall,
  ): Promise<{ backend: Server; client: Client }> {
    const backend = newBackend(onCall);
    const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
    await backend.connect(serverSide);
    const client = new Client({ name: "gateway", version: "1.0.0" });
    await client.connect(clientSide);
    cleanups.push(() => client.close());
    return { backend, client };
  }

  async function listen(handler: http.RequestListener): Promise<URL> {
    const httpServer = http.createServer(handler);
    await new Promise<void>((resolve) =>
      httpServer.listen(0, "127.0.0.1", resolve),
    );
    cleanups.push(
      () =>
        new Promise<void>((resolve) => {
          httpServer.closeAllConnections();
          httpServer.close(() => resolve());
        }),
    );
    const { port } = httpServer.address() as AddressInfo;
    return new URL(`http://127.0.0.1:${port}`);
  }

  const callTool = (client: Client, timeout?: number) =>
    client.request(
      { method: "tools/call", params: { name: "delete_file", arguments: {} } },
      CallToolResultSchema,
      timeout === undefined ? undefined : { timeout },
    );

  async function rejectionOf(promise: Promise<unknown>): Promise<unknown> {
    try {
      await promise;
    } catch (error) {
      return error;
    }
    throw new Error("expected the request to reject");
  }

  it("a real request timeout is neither session-lost nor replay-safe", async () => {
    let release: () => void = () => undefined;
    const { client } = await connectInMemory(
      () =>
        new Promise((resolve) => {
          release = () => resolve({ content: [] });
        }),
    );
    cleanups.push(async () => release());

    const error = await rejectionOf(callTool(client, 20));

    expect(error).toBeInstanceOf(McpError);
    expect((error as McpError).code).toBe(ErrorCode.RequestTimeout);
    expect(isBackendSessionLostError(error)).toBe(false);
    expect(isRecoverableBackendError(error)).toBe(false);
    expect(isToolCallReplaySafeError(error)).toBe(false);
  });

  it("a real mid-call connection drop is not replay-safe", async () => {
    const { client } = await connectInMemory((backend) => {
      // The backend received the call, then its connection went away.
      void backend.close();
      return new Promise(() => undefined);
    });

    const error = await rejectionOf(callTool(client));

    expect((error as McpError).code).toBe(ErrorCode.ConnectionClosed);
    expect(isToolCallReplaySafeError(error)).toBe(false);
  });

  it("a real pre-send 'Not connected' is replay-safe", async () => {
    let executions = 0;
    const { client } = await connectInMemory(async () => {
      executions += 1;
      return { content: [] };
    });
    await client.close();

    const error = await rejectionOf(callTool(client));

    expect(executions).toBe(0);
    expect(isToolCallReplaySafeError(error)).toBe(true);
    expect(isRecoverableBackendError(error)).toBe(true);
  });

  it("a real streamable-http 404 'Session not found' is session-lost and replay-safe", async () => {
    let executions = 0;
    const serverTransport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => randomUUID(),
    });
    await newBackend(async () => {
      executions += 1;
      return { content: [] };
    }).connect(serverTransport);
    const base = await listen((req, res) => {
      void serverTransport.handleRequest(req, res);
    });
    const client = new Client({ name: "gateway", version: "1.0.0" });
    await client.connect(
      new StreamableHTTPClientTransport(new URL("/mcp", base)),
    );
    cleanups.push(() => client.close());

    // The backend drops its session (a restart or an idle reap). The SDK
    // server then answers every POST for it with 404 -32001 "Session not
    // found" before any handler runs.
    await serverTransport.close();
    const error = await rejectionOf(callTool(client));

    expect(error).toBeInstanceOf(StreamableHTTPError);
    expect((error as StreamableHTTPError).code).toBe(404);
    expect(executions).toBe(0);
    expect(isBackendSessionLostError(error)).toBe(true);
    expect(isToolCallReplaySafeError(error)).toBe(true);
  });

  it("a real SSE 404 'Session not found' is session-lost and replay-safe", async () => {
    // SSE session routing belongs to the app, and the gateway's own SSE
    // routers answer an unknown session with a plain-text 404. Mirror that.
    let sessionKnown = true;
    let serverTransport: SSEServerTransport | undefined;
    const base = await listen((req, res) => {
      if (req.method === "GET") {
        serverTransport = new SSEServerTransport("/messages", res);
        void newBackend(async () => ({ content: [] })).connect(serverTransport);
        return;
      }
      if (!sessionKnown || !serverTransport) {
        res.writeHead(404).end("Session not found");
        return;
      }
      void serverTransport.handlePostMessage(req, res);
    });
    const client = new Client({ name: "gateway", version: "1.0.0" });
    await client.connect(new SSEClientTransport(new URL("/sse", base)));
    cleanups.push(() => client.close());

    sessionKnown = false;
    const error = await rejectionOf(callTool(client));

    expect((error as Error).message).toContain("HTTP 404");
    expect(isBackendSessionLostError(error)).toBe(true);
    expect(isToolCallReplaySafeError(error)).toBe(true);
  });
});

describe("isBackendTransportLostError", () => {
  it("matches the bare SDK 'Not connected' Error", () => {
    // Protocol.request() in the MCP TS SDK rejects with exactly this
    // message when the underlying transport has been torn down.
    const error = new Error("Not connected");
    expect(isBackendTransportLostError(error)).toBe(true);
  });

  it("matches a 'Not connected' string throwable", () => {
    expect(isBackendTransportLostError("Not connected")).toBe(true);
  });

  it("matches the consumer-side -32603 envelope MetaMCP returns to Claude.ai / n8n", () => {
    // Production observation: consumer-side connectors see
    // the tRPC bridge's wrapped envelope rather than the raw SDK Error.
    const envelope = {
      jsonrpc: "2.0",
      id: "server-error",
      error: { code: -32603, message: "Not connected" },
    };
    expect(isBackendTransportLostError(envelope)).toBe(true);
  });

  it("matches when the transport-lost error is wrapped via .cause", () => {
    const inner = new Error("Not connected");
    const outer = new Error("Tool dispatch rejected", { cause: inner });
    expect(isBackendTransportLostError(outer)).toBe(true);
  });

  it("matches when wrapped two layers deep via .cause", () => {
    const innermost = new Error("Not connected");
    const mid = new Error("Transport adapter rejection", { cause: innermost });
    const outer = new Error("Outer wrap", { cause: mid });
    expect(isBackendTransportLostError(outer)).toBe(true);
  });

  it("matches Error with .code -32603 + 'Not connected' message", () => {
    const error = Object.assign(new Error("Not connected"), { code: -32603 });
    expect(isBackendTransportLostError(error)).toBe(true);
  });

  it("does not false-positive on unrelated -32603 'Internal error' envelopes", () => {
    // Bare -32603 is JSON-RPC "Internal error" and covers many flows.
    // Detector only fires when paired with the 'Not connected' marker.
    const envelope = {
      jsonrpc: "2.0",
      id: "x",
      error: { code: -32603, message: "Internal error" },
    };
    expect(isBackendTransportLostError(envelope)).toBe(false);
  });

  it("does not match session-not-found envelopes (those go to the session-lost detector)", () => {
    const error = new Error(
      'Error POSTing to endpoint (HTTP 404): {"jsonrpc":"2.0","error":{"code":-32600,"message":"Session not found"}}',
    );
    expect(isBackendTransportLostError(error)).toBe(false);
  });

  it("returns false for null / undefined / unrelated strings", () => {
    expect(isBackendTransportLostError(undefined)).toBe(false);
    expect(isBackendTransportLostError(null)).toBe(false);
    expect(isBackendTransportLostError("just some text")).toBe(false);
    expect(isBackendTransportLostError(new Error("Timeout"))).toBe(false);
  });

  it("handles circular .cause chains without infinite-looping", () => {
    const a = new Error("Wrapper a") as Error & { cause?: unknown };
    const b = new Error("Wrapper b") as Error & { cause?: unknown };
    a.cause = b;
    b.cause = a;
    expect(isBackendTransportLostError(a)).toBe(false);
  });

  it("falls back to String(error) for custom throwables", () => {
    class CustomTransportError {
      toString() {
        return "Not connected";
      }
    }
    expect(isBackendTransportLostError(new CustomTransportError())).toBe(true);
  });
});

describe("isRecoverableBackendError", () => {
  it("fires on session-not-found envelopes", () => {
    const error = new Error(
      'Error POSTing to endpoint (HTTP 404): {"jsonrpc":"2.0","error":{"code":-32600,"message":"Session not found"}}',
    );
    expect(isRecoverableBackendError(error)).toBe(true);
  });

  it("fires on transport-disconnect envelopes", () => {
    expect(isRecoverableBackendError(new Error("Not connected"))).toBe(true);
  });

  it("fires on the consumer-side -32603 envelope (production case)", () => {
    const envelope = {
      jsonrpc: "2.0",
      id: "server-error",
      error: { code: -32603, message: "Not connected" },
    };
    expect(isRecoverableBackendError(envelope)).toBe(true);
  });

  it("does not false-positive on unrelated errors", () => {
    expect(isRecoverableBackendError(new Error("Timeout"))).toBe(false);
    expect(isRecoverableBackendError(undefined)).toBe(false);
    expect(
      isRecoverableBackendError({
        jsonrpc: "2.0",
        error: { code: -32603, message: "Internal error" },
      }),
    ).toBe(false);
  });
});
