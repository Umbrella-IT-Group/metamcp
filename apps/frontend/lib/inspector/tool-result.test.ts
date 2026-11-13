import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  CallToolRequestSchema,
  CompatibilityCallToolResultSchema,
  ErrorCode,
  type JSONRPCMessage,
  McpError,
} from "@modelcontextprotocol/sdk/types.js";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  classifyCallFailure,
  classifyCallResult,
  imageDataUrl,
  JSON_BLOCK_LIMIT,
  stringifyForDisplay,
} from "./tool-result";

// MCP specification, server/tools, "Error Handling": a tool-level failure is
// reported inside the result with isError true, not as a protocol error. The
// SDK result type carries the field (types.js, CallToolResultSchema).
describe("classifyCallResult: isError", () => {
  it("reads isError true as a tool error and joins the text blocks", () => {
    const classified = classifyCallResult({
      isError: true,
      content: [
        { type: "text", text: "first line" },
        { type: "image", mimeType: "image/png", data: "AAAA" },
        { type: "text", text: "second line" },
      ],
    });
    expect(classified.status).toBe("tool_error");
    expect(classified.errorText).toBe("first line\nsecond line");
  });

  it("gives a plain sentence when an error result has no text", () => {
    expect(classifyCallResult({ isError: true, content: [] })).toMatchObject({
      status: "tool_error",
      errorText: "An error occurred",
    });
    expect(classifyCallResult({ isError: true })).toMatchObject({
      status: "tool_error",
      errorText: "An error occurred",
    });
  });

  it("reads the gateway's retired-tool answer as a tool error", () => {
    // The literal the gateway builds for a retired tool name: isError true, one
    // JSON text block, no structuredContent.
    const retired = {
      isError: true,
      content: [
        {
          type: "text",
          text: JSON.stringify({ error: "tool_retired", replacement: "x" }),
        },
      ],
    };
    const classified = classifyCallResult(retired);
    expect(classified.status).toBe("tool_error");
    expect(classified.structured).toBeNull();
    expect(classified.errorText).toContain("tool_retired");
  });

  it("reads everything else as success", () => {
    for (const result of [
      { content: [{ type: "text", text: "ok" }] },
      { isError: false, content: [] },
      { toolResult: 1 },
      { isError: "true", content: [] },
      {},
      null,
      "text",
    ]) {
      const classified = classifyCallResult(result);
      expect(classified.status).toBe("success");
      expect(classified.errorText).toBeNull();
    }
  });
});

describe("classifyCallResult: content", () => {
  it("extracts structuredContent only when it is an object", () => {
    expect(
      classifyCallResult({ content: [], structuredContent: { a: 1 } })
        .structured,
    ).toEqual({ a: 1 });
    expect(
      classifyCallResult({ content: [], structuredContent: [1] }).structured,
    ).toBeNull();
    expect(classifyCallResult({ content: [] }).structured).toBeNull();
  });

  it("keeps structuredContent of an error result", () => {
    expect(
      classifyCallResult({
        isError: true,
        content: [],
        structuredContent: { code: 7 },
      }).structured,
    ).toEqual({ code: 7 });
  });

  it("finds JSON inside a text block and leaves other text alone", () => {
    const blocks = classifyCallResult({
      content: [
        { type: "text", text: '{"a":1}' },
        { type: "text", text: "[1,2]" },
        { type: "text", text: "just words" },
        { type: "text", text: "{not json" },
      ],
    }).blocks;
    expect(blocks).toHaveLength(4);
    const [object, array, plain, broken] = blocks;
    expect(object).toMatchObject({
      kind: "text",
      prettyJson: '{\n  "a": 1\n}',
    });
    expect(array).toMatchObject({
      kind: "text",
      prettyJson: "[\n  1,\n  2\n]",
    });
    expect(plain).toEqual({ kind: "text", text: "just words" });
    expect(broken).toEqual({ kind: "text", text: "{not json" });
  });

  it("parses JSON text up to the size limit and not beyond it", () => {
    const atLimit = `["${"a".repeat(JSON_BLOCK_LIMIT - 4)}"]`;
    expect(atLimit).toHaveLength(JSON_BLOCK_LIMIT);
    const overLimit = `["${"a".repeat(JSON_BLOCK_LIMIT - 3)}"]`;
    const blocks = classifyCallResult({
      content: [
        { type: "text", text: atLimit },
        { type: "text", text: overLimit },
      ],
    }).blocks;
    expect(blocks).toHaveLength(2);
    expect(blocks[0]).toHaveProperty("prettyJson");
    expect(blocks[1]).not.toHaveProperty("prettyJson");
  });

  it.each([
    '{"id":9007199254740993}',
    '{"nested":[-9007199254740993]}',
    '{"value":1e309}',
  ])("keeps %s as text instead of offering a lossy formatter", (text) => {
    const [block] = classifyCallResult({
      content: [{ type: "text", text }],
    }).blocks;
    expect(block).toEqual({ kind: "text", text });
  });

  it("describes image and audio blocks without playing or fetching them", () => {
    const blocks = classifyCallResult({
      content: [
        { type: "image", mimeType: "image/png", data: "AAAA" },
        { type: "image", mimeType: "image/svg+xml", data: "AAAA" },
        { type: "audio", mimeType: "audio/wav", data: "AA==" },
      ],
    }).blocks;
    expect(blocks[0]).toEqual({
      kind: "image",
      mimeType: "image/png",
      bytes: 3,
      dataUrl: "data:image/png;base64,AAAA",
    });
    expect(blocks[1]).toEqual({
      kind: "image",
      mimeType: "image/svg+xml",
      bytes: 3,
      dataUrl: null,
    });
    expect(blocks[2]).toEqual({
      kind: "audio",
      mimeType: "audio/wav",
      bytes: 1,
    });
  });

  it("keeps a resource link and an embedded resource as plain fields", () => {
    const blocks = classifyCallResult({
      content: [
        {
          type: "resource_link",
          uri: "javascript:alert(1)",
          name: "link",
          mimeType: "text/html",
          description: "d",
        },
        {
          type: "resource",
          resource: { uri: "file:///x", mimeType: "text/plain", text: "hi" },
        },
        { type: "resource", resource: { uri: "file:///y", blob: "AAAA" } },
      ],
    }).blocks;
    expect(blocks[0]).toEqual({
      kind: "resource_link",
      uri: "javascript:alert(1)",
      name: "link",
      mimeType: "text/html",
      description: "d",
    });
    expect(blocks[1]).toEqual({
      kind: "resource",
      uri: "file:///x",
      mimeType: "text/plain",
      text: "hi",
    });
    expect(blocks[2]).toEqual({ kind: "resource", uri: "file:///y", bytes: 3 });
  });

  it("keeps an unrecognised block as its type and raw JSON", () => {
    const [block] = classifyCallResult({
      content: [{ type: "hologram", frames: 3 }],
    }).blocks;
    expect(block).toEqual({
      kind: "unknown",
      type: "hologram",
      raw: '{"type":"hologram","frames":3}',
    });
  });

  it("gives no blocks when content is missing or not a list", () => {
    expect(classifyCallResult({}).blocks).toEqual([]);
    expect(classifyCallResult({ content: "text" }).blocks).toEqual([]);
    expect(classifyCallResult({ content: [null, 5] }).blocks).toEqual([
      { kind: "unknown", type: "unknown", raw: "null" },
      { kind: "unknown", type: "unknown", raw: "5" },
    ]);
  });
});

describe("classifyCallFailure", () => {
  it("keeps the code and data of a protocol error", () => {
    const failure = classifyCallFailure(
      new McpError(ErrorCode.MethodNotFound, "Method not found", { x: 1 }),
      { stoppedByUser: false },
    );
    expect(failure).toEqual({
      status: "protocol_error",
      message: "MCP error -32601: Method not found",
      code: ErrorCode.MethodNotFound,
      data: { x: 1 },
      outcomeUnknown: false,
    });
  });

  it("reports a stop the user asked for as stopped, whatever the code", () => {
    // The SDK reports an abort as RequestTimeout, the same code a real timeout
    // has, so the code cannot say who ended the wait.
    const aborted = new McpError(ErrorCode.RequestTimeout, "Stopped");
    expect(classifyCallFailure(aborted, { stoppedByUser: true })).toMatchObject(
      { status: "stopped", outcomeUnknown: true },
    );
    expect(
      classifyCallFailure(new Error("anything"), { stoppedByUser: true }),
    ).toMatchObject({ status: "stopped", outcomeUnknown: true });
  });

  it("reports the same error as a timeout when the user did not stop it", () => {
    const failure = classifyCallFailure(
      new McpError(ErrorCode.RequestTimeout, "Request timed out"),
      { stoppedByUser: false },
    );
    expect(failure).toMatchObject({
      status: "protocol_error",
      code: ErrorCode.RequestTimeout,
      outcomeUnknown: true,
    });
  });

  it("marks a closed connection as an unknown outcome", () => {
    expect(
      classifyCallFailure(
        new McpError(ErrorCode.ConnectionClosed, "Connection closed"),
        { stoppedByUser: false },
      ),
    ).toMatchObject({ code: ErrorCode.ConnectionClosed, outcomeUnknown: true });
  });

  it("does not claim an unknown outcome for an error the server answered", () => {
    expect(
      classifyCallFailure(new McpError(ErrorCode.InvalidParams, "Bad"), {
        stoppedByUser: false,
      }).outcomeUnknown,
    ).toBe(false);
  });

  it("handles errors that are not McpError", () => {
    expect(
      classifyCallFailure(new Error("plain"), { stoppedByUser: false }),
    ).toEqual({
      status: "protocol_error",
      message: "plain",
      outcomeUnknown: true,
    });
    expect(
      classifyCallFailure("thrown text", { stoppedByUser: false }).message,
    ).toBe("thrown text");
  });

  it("marks a failed HTTP response after dispatch as an unknown outcome", async () => {
    let writes = 0;
    const client = new Client({ name: "test-client", version: "1.0.0" });
    const transport = new StreamableHTTPClientTransport(
      new URL("https://example.invalid/mcp"),
      {
        fetch: async (_url, init) => {
          if (init?.method === "GET") {
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
                protocolVersion: "2025-03-26",
                capabilities: { tools: {} },
                serverInfo: { name: "test-server", version: "1.0.0" },
              },
            });
          }
          if (request.method === "notifications/initialized") {
            return new Response(null, { status: 202 });
          }
          // The write happened, but fetch rejects before its answer arrives.
          writes += 1;
          throw new TypeError("Failed to fetch");
        },
      },
    );
    try {
      await client.connect(transport);
      const error = await client
        .request(
          { method: "tools/call", params: { name: "write", arguments: {} } },
          CompatibilityCallToolResultSchema,
        )
        .then(
          () => null,
          (failure: unknown) => failure,
        );
      expect(writes).toBe(1);
      expect(error).toBeInstanceOf(TypeError);
      expect(
        classifyCallFailure(error, { stoppedByUser: false }),
      ).toMatchObject({ status: "protocol_error", outcomeUnknown: true });
    } finally {
      await client.close();
    }
  });
});

describe("imageDataUrl", () => {
  it.each(["image/png", "image/jpeg", "image/gif", "image/webp"])(
    "allows %s",
    (mimeType) => {
      expect(imageDataUrl(mimeType, "iVBORw0KGgo=")).toBe(
        `data:${mimeType};base64,iVBORw0KGgo=`,
      );
    },
  );

  it.each([
    "image/svg+xml",
    "text/html",
    "image/png; charset=utf-8",
    "IMAGE/PNG",
    "image/png,text/html",
    "",
  ])("refuses the type %j", (mimeType) => {
    expect(imageDataUrl(mimeType, "AAAA")).toBeNull();
  });

  it("refuses data that is not base64 text", () => {
    expect(imageDataUrl("image/png", 'AAAA"onerror="x')).toBeNull();
    expect(imageDataUrl("image/png", "AAAA<")).toBeNull();
    expect(imageDataUrl("image/png", "AAAA)")).toBeNull();
    expect(imageDataUrl("image/png", "")).toBeNull();
  });

  it("refuses input that is not text", () => {
    expect(imageDataUrl(undefined, "AAAA")).toBeNull();
    expect(imageDataUrl("image/png", undefined)).toBeNull();
    expect(imageDataUrl("image/png", 42)).toBeNull();
    expect(imageDataUrl({}, "AAAA")).toBeNull();
  });

  it("drops line breaks inside base64 text", () => {
    expect(imageDataUrl("image/png", "AA\nAA")).toBe(
      "data:image/png;base64,AAAA",
    );
  });
});

describe("stringifyForDisplay", () => {
  it("pretty prints JSON and never throws", () => {
    expect(stringifyForDisplay({ a: 1 })).toBe('{\n  "a": 1\n}');
    const circular: Record<string, unknown> = {};
    circular.self = circular;
    expect(() => stringifyForDisplay(circular)).not.toThrow();
    expect(typeof stringifyForDisplay(circular)).toBe("string");
    expect(stringifyForDisplay(undefined)).toBe("undefined");
  });
});

// SDK shared/protocol.js, request(): aborting the request's signal sends
// notifications/cancelled and rejects the caller with McpError(RequestTimeout,
// String(reason)). The MCP cancellation utility defines the notification.
describe("an aborted request over a real SDK client and server", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it("sends notifications/cancelled and rejects with RequestTimeout", async () => {
    const [clientTransport, serverTransport] =
      InMemoryTransport.createLinkedPair();
    const sent: JSONRPCMessage[] = [];
    const send = clientTransport.send.bind(clientTransport);
    clientTransport.send = (message, options) => {
      sent.push(message);
      return send(message, options);
    };
    const server = new Server(
      { name: "test-server", version: "1.0.0" },
      { capabilities: { tools: {} } },
    );
    // A handler that never answers: the call stays in flight until aborted.
    server.setRequestHandler(
      CallToolRequestSchema,
      () => new Promise(() => {}),
    );
    const client = new Client({ name: "test-client", version: "1.0.0" });
    await Promise.all([
      server.connect(serverTransport),
      client.connect(clientTransport),
    ]);

    const controller = new AbortController();
    const call = client.request(
      { method: "tools/call", params: { name: "slow", arguments: {} } },
      CompatibilityCallToolResultSchema,
      { signal: controller.signal, timeout: 60_000 },
    );
    const outcome = call.then(
      () => null,
      (error: unknown) => error,
    );
    controller.abort("Cancelled from the inspector");
    const error = await outcome;

    expect(error).toBeInstanceOf(McpError);
    expect((error as McpError).code).toBe(ErrorCode.RequestTimeout);
    const callMessage = sent.find(
      (message) => "method" in message && message.method === "tools/call",
    );
    const cancelled = sent.find(
      (message) =>
        "method" in message && message.method === "notifications/cancelled",
    );
    expect(callMessage).toBeDefined();
    expect(cancelled).toMatchObject({
      params: {
        requestId: (callMessage as { id: number }).id,
        reason: "Cancelled from the inspector",
      },
    });
    expect(classifyCallFailure(error, { stoppedByUser: true }).status).toBe(
      "stopped",
    );
    expect(classifyCallFailure(error, { stoppedByUser: false }).status).toBe(
      "protocol_error",
    );

    await client.close();
  });
});
