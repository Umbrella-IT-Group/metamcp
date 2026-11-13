/**
 * The transport tap, against the real SDK.
 *
 * The tap only works because of how `Protocol.connect` treats a transport
 * (SDK `shared/protocol.js`: it reads the handlers already on the transport,
 * installs handlers that call them first, then starts it) and because of what
 * the transports do on failure (`client/streamableHttp.js` calls `onerror` and
 * throws the same error; `client/sse.js` rejects `start()` and calls `onerror`
 * with the same error). Each test below states which of those it relies on, so
 * an SDK upgrade that changes one fails here rather than in a browser.
 *
 * Oracles: the MCP lifecycle specification (initialize, then the initialized
 * notification, then requests), SDK `client/index.js` `connect` (it sends
 * both inside `connect()`), and `shared/protocol.js` (`cancel` sends
 * `notifications/cancelled` with `{ relatedRequestId, resumptionToken,
 * onresumptiontoken }`). A real SDK `Client` and `Server` talk over
 * `InMemoryTransport`; a second pair of tests uses the real Streamable HTTP
 * transport with an injected `fetch`. Timers are fake and time is injected.
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import type {
  FetchLike,
  Transport,
  TransportSendOptions,
} from "@modelcontextprotocol/sdk/shared/transport.js";
import {
  EmptyResultSchema,
  type JSONRPCMessage,
  LATEST_PROTOCOL_VERSION,
  ListToolsRequestSchema,
  McpError,
} from "@modelcontextprotocol/sdk/types.js";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { buildRpcTrafficPairs } from "./correlation";
import { RpcTrafficStore } from "./store";
import { connectWithTraffic, tapTransport } from "./transport-tap";
import type { RpcTrafficEntry, TrafficSink } from "./types";

const T0 = Date.parse("2026-11-12T12:00:00.000Z");

beforeEach(() => {
  vi.useFakeTimers();
});
afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

/** A store on a clock that advances 5 ms every time a row is recorded. */
function newStore() {
  let ticks = 0;
  return new RpcTrafficStore({ now: () => T0 + 5 * ticks++ });
}

function newClient() {
  return new Client(
    { name: "inspector-test", version: "1.0.0" },
    { capabilities: {} },
  );
}

const describeRow = (row: RpcTrafficEntry) => {
  const message = row.message as { method?: string; transportEvent?: string };
  return `${row.direction}:${
    message.transportEvent
      ? `transport-${message.transportEvent}`
      : (message.method ?? "response")
  }`;
};

const INITIALIZE_RESULT = {
  protocolVersion: LATEST_PROTOCOL_VERSION,
  capabilities: {},
  serverInfo: { name: "scripted-server", version: "1.0.0" },
};

/**
 * A transport the test controls. `answerInitialize` replies to the initialize
 * request from inside `send`, before `send` returns (what a fast transport
 * does).
 */
class ScriptedTransport implements Transport {
  onmessage?: Transport["onmessage"];
  onerror?: Transport["onerror"];
  onclose?: Transport["onclose"];
  sessionId?: string;
  readonly sendCalls: {
    message: JSONRPCMessage;
    options?: TransportSendOptions;
  }[] = [];

  constructor(
    private readonly script: {
      answerInitialize?: boolean;
      startError?: Error;
      sendError?: Error;
    } = {},
  ) {}

  async start(): Promise<void> {
    if (this.script.startError) {
      // The shape of sse.js: report the error, then reject with the same one.
      this.onerror?.(this.script.startError);
      throw this.script.startError;
    }
  }

  async send(
    message: JSONRPCMessage,
    options?: TransportSendOptions,
  ): Promise<void> {
    this.sendCalls.push({ message, options });
    if (this.script.sendError) {
      // The shape of streamableHttp.js send(): onerror, then throw the same.
      this.onerror?.(this.script.sendError);
      throw this.script.sendError;
    }
    if (
      this.script.answerInitialize &&
      "method" in message &&
      message.method === "initialize" &&
      "id" in message
    ) {
      const reply = {
        jsonrpc: "2.0",
        id: message.id,
        result: INITIALIZE_RESULT,
      } as JSONRPCMessage;
      this.onmessage?.(reply);
    }
    // Resolves a tick later than the reply above was delivered.
    await Promise.resolve();
  }

  async close(): Promise<void> {
    this.onclose?.();
  }
}

describe("a real client and server over an in-memory transport", () => {
  async function connectedPair(store: RpcTrafficStore) {
    const [clientTransport, serverTransport] =
      InMemoryTransport.createLinkedPair();
    const server = new Server(
      { name: "fixture-server", version: "9.9.9" },
      { capabilities: { tools: {} } },
    );
    server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: [],
    }));
    await server.connect(serverTransport);
    const client = newClient();
    await connectWithTraffic(client, clientTransport, store.sink);
    return { client };
  }

  it("logs every message once, in the order of the lifecycle", async () => {
    const store = newStore();
    const { client } = await connectedPair(store);
    await client.listTools();

    expect(store.exportEntries().map(describeRow)).toEqual([
      "send:initialize",
      "receive:response",
      "send:notifications/initialized",
      "send:tools/list",
      "receive:response",
    ]);
  });

  it("measures latency from the injected clock", async () => {
    const store = newStore();
    const { client } = await connectedPair(store);
    await client.listTools();

    const { responseLabels } = buildRpcTrafficPairs(store.exportEntries());
    const labels = [...responseLabels.values()];
    expect(labels.map((label) => [label.method, label.latencyMs])).toEqual([
      ["initialize", 5],
      ["tools/list", 5],
    ]);
  });

  it("captures what the server announced, from the initialize exchange", async () => {
    const store = newStore();
    await connectedPair(store);

    // Right after connect, before anything has been rendered.
    const result = store.initializeResult();
    expect(result?.protocolVersion).toBe(LATEST_PROTOCOL_VERSION);
    expect(result?.serverInfo).toMatchObject({
      name: "fixture-server",
      version: "9.9.9",
    });
  });

  it("logs the close when the page closes the connection", async () => {
    const store = newStore();
    const { client } = await connectedPair(store);
    await client.close();
    expect(
      store
        .exportEntries()
        .some((row) => describeRow(row) === "receive:transport-closed"),
    ).toBe(true);
  });

  it("does not break the exchange when the log itself fails", async () => {
    const errors = vi.spyOn(console, "error").mockImplementation(() => {});
    const brokenSink: TrafficSink = {
      message() {
        throw new Error("a defect in the log");
      },
      transport() {
        throw new Error("a defect in the log");
      },
    };
    const [clientTransport, serverTransport] =
      InMemoryTransport.createLinkedPair();
    const server = new Server(
      { name: "fixture-server", version: "1.0.0" },
      { capabilities: { tools: {} } },
    );
    server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: [{ name: "search_items", inputSchema: { type: "object" } }],
    }));
    await server.connect(serverTransport);
    const client = newClient();
    await connectWithTraffic(client, clientTransport, brokenSink);

    const listed = await client.listTools();
    expect(listed.tools.map((tool) => tool.name)).toEqual(["search_items"]);
    // Reported, not swallowed.
    expect(errors).toHaveBeenCalled();
    expect(String(errors.mock.calls[0]?.[0])).toContain(
      "Inspector traffic log",
    );
  });
});

describe("tapTransport", () => {
  it("logs a message before the transport sees it, even when the reply arrives inside send", async () => {
    const store = newStore();
    const transport = new ScriptedTransport({ answerInitialize: true });
    tapTransport(transport, store.sink);

    await transport.send({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: LATEST_PROTOCOL_VERSION,
        capabilities: {},
        clientInfo: { name: "t", version: "1" },
      },
    });

    // The reply was delivered while send was still running. A log written
    // after send returned would show it first.
    expect(store.exportEntries().map(describeRow)).toEqual([
      "send:initialize",
      "receive:response",
    ]);
  });

  it("forwards every argument to the real send", async () => {
    const store = newStore();
    const transport = new ScriptedTransport();
    tapTransport(transport, store.sink);
    const onToken = () => {};
    const message = {
      jsonrpc: "2.0",
      method: "notifications/cancelled",
    } as const;

    await transport.send(message, {
      relatedRequestId: "rel-1",
      resumptionToken: "resume-1",
      onresumptiontoken: onToken,
    });

    expect(transport.sendCalls).toHaveLength(1);
    expect(transport.sendCalls[0]?.message).toBe(message);
    expect(transport.sendCalls[0]?.options).toEqual({
      relatedRequestId: "rel-1",
      resumptionToken: "resume-1",
      onresumptiontoken: onToken,
    });
  });

  it("logs each message of a batch", async () => {
    const store = newStore();
    const transport = new ScriptedTransport();
    tapTransport(transport, store.sink);
    const batch = [
      { jsonrpc: "2.0", id: 1, method: "tools/list" },
      { jsonrpc: "2.0", id: 2, method: "ping" },
    ] as unknown as JSONRPCMessage;
    await transport.send(batch);
    expect(store.exportEntries().map(describeRow)).toEqual([
      "send:tools/list",
      "send:ping",
    ]);
  });

  it("calls handlers that were on the transport first, once each, after recording", async () => {
    const store = newStore();
    const transport = new ScriptedTransport();
    const seen: string[] = [];
    transport.onmessage = () => {
      seen.push(`message after ${store.size()} rows`);
    };
    transport.onerror = () => {
      seen.push("error");
    };
    transport.onclose = () => {
      seen.push("close");
    };
    tapTransport(transport, store.sink);

    transport.onmessage?.({ jsonrpc: "2.0", id: 1, result: {} });
    transport.onerror?.(new Error("x"));
    transport.onclose?.();

    expect(seen).toEqual(["message after 1 rows", "error", "close"]);
    expect(store.exportEntries().map(describeRow)).toEqual([
      "receive:response",
      "receive:transport-error",
      "receive:transport-closed",
    ]);
  });

  it("reports a send that fails once, and throws the same error", async () => {
    const store = newStore();
    const failure = new Error("Error POSTing to endpoint: 502");
    const transport = new ScriptedTransport({ sendError: failure });
    tapTransport(transport, store.sink);

    await expect(
      transport.send({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
    ).rejects.toBe(failure);

    // The transport reported the error through onerror AND rejected with it:
    // one failure, one row.
    expect(store.exportEntries().map(describeRow)).toEqual([
      "send:tools/list",
      "receive:transport-error",
    ]);
  });
});

describe("connectWithTraffic", () => {
  it("taps before the client connects, so the initialize request is in the log", async () => {
    const store = newStore();
    const transport = new ScriptedTransport({ answerInitialize: true });
    await connectWithTraffic(newClient(), transport, store.sink);

    expect(store.exportEntries().map(describeRow)).toEqual([
      "send:initialize",
      "receive:response",
      "send:notifications/initialized",
    ]);
  });

  it("with no sink is client.connect and nothing else", async () => {
    const transport = new ScriptedTransport({ answerInitialize: true });
    const sendBefore = transport.send;
    const connect = vi.fn(async () => {});
    await connectWithTraffic({ connect }, transport, null);

    expect(connect).toHaveBeenCalledWith(transport);
    expect(transport.send).toBe(sendBefore);

    // Through a real client too: the transport is not decorated.
    const other = new ScriptedTransport({ answerInitialize: true });
    const otherSend = other.send;
    await connectWithTraffic(newClient(), other, null);
    expect(other.send).toBe(otherSend);
  });

  it("records a handshake that fails to start once, whichever route reports it", async () => {
    const store = newStore();
    const failure = new Error("SSE error: Non-200 status code (403)");
    const transport = new ScriptedTransport({ startError: failure });

    await expect(
      connectWithTraffic(newClient(), transport, store.sink),
    ).rejects.toBe(failure);
    // What the connection hook does in its catch.
    store.publishTransportError(failure);

    const rows = store.exportEntries();
    expect(rows.map(describeRow)).toEqual(["receive:transport-error"]);
    expect(rows[0]?.message).toMatchObject({
      error: "SSE error: Non-200 status code (403)",
    });
  });
});

describe("cancelling a request", () => {
  it("sends notifications/cancelled with the options the SDK passes, and logs it", async () => {
    const store = newStore();
    const transport = new ScriptedTransport({ answerInitialize: true });
    const client = newClient();
    await connectWithTraffic(client, transport, store.sink);

    const controller = new AbortController();
    const pending = client.request({ method: "ping" }, EmptyResultSchema, {
      signal: controller.signal,
      relatedRequestId: "rel-1",
    });
    controller.abort("stop");
    const error = await pending.catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(McpError);
    const cancel = transport.sendCalls.find(
      (call) =>
        "method" in call.message &&
        call.message.method === "notifications/cancelled",
    );
    expect(cancel?.options).toMatchObject({ relatedRequestId: "rel-1" });
    expect(cancel?.message).toMatchObject({
      params: { reason: "stop" },
    });
    expect(
      store
        .exportEntries()
        .map(describeRow)
        .filter((row) => row.includes("cancelled")),
    ).toEqual(["send:notifications/cancelled"]);
  });
});

describe("the real Streamable HTTP transport", () => {
  const fakeFetch: FetchLike = async (_url, init) => {
    const method = init?.method ?? "GET";
    if (method === "POST") {
      const body = JSON.parse(String(init?.body)) as {
        id?: number;
        method?: string;
      };
      if (body.method === "initialize") {
        return new Response(
          JSON.stringify({
            jsonrpc: "2.0",
            id: body.id,
            result: {
              ...INITIALIZE_RESULT,
              serverInfo: { name: "http-fixture", version: "2.0.0" },
            },
          }),
          {
            status: 200,
            headers: {
              "content-type": "application/json",
              "mcp-session-id": "session-1",
            },
          },
        );
      }
      return new Response(null, { status: 202 });
    }
    // The standalone stream and the session delete: not supported.
    return new Response(null, { status: 405 });
  };

  it("is tapped in place: same object, its own members intact, one row per message", async () => {
    const store = newStore();
    const transport = new StreamableHTTPClientTransport(
      new URL("https://gateway.example.test/mcp"),
      { fetch: fakeFetch },
    );
    const tapped = tapTransport(transport, store.sink);
    expect(tapped).toBe(transport);

    const client = newClient();
    await client.connect(transport);

    expect(store.exportEntries().map(describeRow)).toEqual([
      "send:initialize",
      "receive:response",
      "send:notifications/initialized",
    ]);
    // Members the page reaches through the real transport.
    expect(typeof transport.terminateSession).toBe("function");
    expect(transport.sessionId).toBe("session-1");
    expect(store.initializeResult()?.serverInfo).toMatchObject({
      name: "http-fixture",
    });
  });
});
