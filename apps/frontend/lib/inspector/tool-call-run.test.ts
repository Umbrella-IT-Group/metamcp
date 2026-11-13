import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  CallToolRequestSchema,
  type CallToolResult,
  CompatibilityCallToolResultSchema,
  ErrorCode,
  type JSONRPCMessage,
  McpError,
} from "@modelcontextprotocol/sdk/types.js";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { classifyCallFailure } from "./tool-result";
import { STOP_REASON, startToolCall } from "./tool-call-run";

// What these tests pin: the Inspector's explicit button asks the server to
// cancel (MCP cancellation utility: a notifications/cancelled naming the
// request id), and nothing else the page does may. Leaving the page, closing
// the connection or switching target must not turn into a cancelled write.
// The wire is observed at the client transport's send, which is exactly what
// the SDK's abort path writes to (shared/protocol.js, request(): cancel()).

const flush = async () => {
  for (let i = 0; i < 20; i += 1) await Promise.resolve();
};

interface Pending {
  resolve: (result: CallToolResult) => void;
  signal: AbortSignal;
}

const clients: Client[] = [];

async function connectPair() {
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  const sent: JSONRPCMessage[] = [];
  const send = clientTransport.send.bind(clientTransport);
  clientTransport.send = (message, options) => {
    sent.push(message);
    return send(message, options);
  };
  const pending = new Map<string, Pending>();
  const server = new Server(
    { name: "test-server", version: "1.0.0" },
    { capabilities: { tools: {} } },
  );
  server.setRequestHandler(
    CallToolRequestSchema,
    (request, extra) =>
      new Promise<CallToolResult>((resolve) => {
        pending.set(request.params.name, { resolve, signal: extra.signal });
      }),
  );
  const client = new Client({ name: "test-client", version: "1.0.0" });
  clients.push(client);
  await Promise.all([
    server.connect(serverTransport),
    client.connect(clientTransport),
  ]);
  const cancelled = () =>
    sent.filter(
      (message) =>
        "method" in message && message.method === "notifications/cancelled",
    );
  const callId = () =>
    (
      sent.find(
        (message) => "method" in message && message.method === "tools/call",
      ) as { id: number } | undefined
    )?.id;
  const call = (signal: AbortSignal) =>
    client.request(
      { method: "tools/call", params: { name: "slow", arguments: {} } },
      CompatibilityCallToolResultSchema,
      { signal, timeout: 60_000 },
    );
  return { client, pending, cancelled, callId, call };
}

beforeEach(() => {
  vi.useFakeTimers();
});

afterEach(async () => {
  await Promise.all(clients.splice(0).map((client) => client.close()));
  vi.useRealTimers();
});

describe("the explicit button", () => {
  it("sends notifications/cancelled for the call and reports it as stopped", async () => {
    const { pending, cancelled, callId, call } = await connectPair();
    const run = startToolCall(call);
    const outcome = run.result.then(
      () => null,
      (error: unknown) => error,
    );
    await flush();
    expect(pending.get("slow")?.signal.aborted).toBe(false);

    run.stop();
    await flush();

    expect(run.stoppedByUser).toBe(true);
    expect(cancelled()).toHaveLength(1);
    expect(cancelled()[0]).toMatchObject({
      params: { requestId: callId(), reason: STOP_REASON },
    });
    // The server's handler sees its request signal abort: the cancel reached it.
    expect(pending.get("slow")?.signal.aborted).toBe(true);

    const error = await outcome;
    expect(error).toBeInstanceOf(McpError);
    expect(
      classifyCallFailure(error, { stoppedByUser: run.stoppedByUser }),
    ).toMatchObject({ status: "stopped", outcomeUnknown: true });
  });

  it("sends one cancellation however often it is pressed", async () => {
    const { cancelled, call } = await connectPair();
    const run = startToolCall(call);
    run.result.catch(() => undefined);
    await flush();
    run.stop();
    run.stop();
    await flush();
    expect(cancelled()).toHaveLength(1);
  });

  it("does nothing once the call has finished", async () => {
    const { pending, cancelled, call } = await connectPair();
    const run = startToolCall(call);
    await flush();
    pending.get("slow")?.resolve({ content: [{ type: "text", text: "done" }] });
    await expect(run.result).resolves.toMatchObject({
      content: [{ type: "text", text: "done" }],
    });
    run.stop();
    await flush();
    expect(cancelled()).toEqual([]);
    expect(run.stoppedByUser).toBe(false);
  });
});

describe("leaving the page, closing the connection, changing target", () => {
  it("detaching the page and then closing the connection sends no cancellation", async () => {
    const { client, cancelled, call } = await connectPair();
    const run = startToolCall(call);
    const outcome = run.result.then(
      () => null,
      (error: unknown) => error,
    );
    await flush();

    run.detach();
    await client.close();
    await flush();

    expect(cancelled()).toEqual([]);
    expect(run.detached).toBe(true);
    expect(run.stoppedByUser).toBe(false);
    const error = await outcome;
    expect((error as McpError).code).toBe(ErrorCode.ConnectionClosed);
  });

  it("detaching the page leaves the call running to its real answer", async () => {
    const { pending, cancelled, call } = await connectPair();
    const run = startToolCall(call);
    // Keeps a rejection from being reported as unhandled; the assertions
    // below read the same promise.
    run.result.catch(() => undefined);
    await flush();

    run.detach();
    await flush();
    expect(cancelled()).toEqual([]);
    expect(pending.get("slow")?.signal.aborted).toBe(false);

    pending.get("slow")?.resolve({ content: [{ type: "text", text: "done" }] });
    await expect(run.result).resolves.toMatchObject({
      content: [{ type: "text", text: "done" }],
    });
    expect(cancelled()).toEqual([]);
  });
});
