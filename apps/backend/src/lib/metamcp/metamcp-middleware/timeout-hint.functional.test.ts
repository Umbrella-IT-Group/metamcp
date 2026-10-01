import {
  CallToolRequest,
  CallToolResult,
  ErrorCode,
  McpError,
} from "@modelcontextprotocol/sdk/types.js";
import { describe, expect, it, vi } from "vitest";

import { MetaMCPHandlerContext } from "./functional-middleware";
import {
  annotateGatewayTimeout,
  createTimeoutHintMiddleware,
  gatewayTimeoutHint,
} from "./timeout-hint.functional";

const context: MetaMCPHandlerContext = {
  namespaceUuid: "ns-1",
  sessionId: "sess-1",
};
const request = {
  method: "tools/call",
  params: { name: "ninja__run_script", arguments: {} },
} as CallToolRequest;

/** Exactly what the SDK raises locally when the request timeout fires. */
const sdkTimeout = (timeoutMs = 60_000) =>
  McpError.fromError(ErrorCode.RequestTimeout, "Request timed out", {
    timeout: timeoutMs,
  });

const run = async (error: unknown): Promise<unknown> => {
  const wrapped = createTimeoutHintMiddleware()(async () => {
    throw error;
  });
  try {
    await wrapped(request, context);
  } catch (caught) {
    return caught;
  }
  throw new Error("expected a rejection");
};

describe("timeout hint: the gateway's own timeout", () => {
  it("keeps the code and the data and adds the adjudication sentence", async () => {
    const original = sdkTimeout(60_000);
    const rewritten = (await run(original)) as McpError;

    expect(rewritten).toBeInstanceOf(McpError);
    expect(rewritten.code).toBe(ErrorCode.RequestTimeout);
    expect(rewritten.data).toEqual({ timeout: 60_000 });
    // The original message stays the first sentence, so a client that matches
    // "Request timed out" or branches on -32001 behaves as before.
    expect(rewritten.message).toMatch(
      /^MCP error -32001: Request timed out\. The gateway stopped waiting after 60 s/,
    );
    expect(rewritten.message).toContain("the backend may still be running it");
    expect(rewritten.message).toContain(
      "read the target's current state before retrying",
    );
    expect(rewritten.message).toContain("A read-only call is safe to retry.");
  });

  it("also covers the maximum-total-timeout form", async () => {
    const original = McpError.fromError(
      ErrorCode.RequestTimeout,
      "Maximum total timeout exceeded",
      { maxTotalTimeout: 120_000, totalElapsed: 120_001 },
    );
    const rewritten = (await run(original)) as McpError;

    expect(rewritten.code).toBe(ErrorCode.RequestTimeout);
    expect(rewritten.message).toMatch(
      /^MCP error -32001: Maximum total timeout exceeded\. The gateway stopped waiting after 120 s/,
    );
    expect(rewritten.data).toEqual({
      maxTotalTimeout: 120_000,
      totalElapsed: 120_001,
    });
  });

  it("omits the seconds when the data carries none usable", () => {
    expect(gatewayTimeoutHint(null)).toMatch(/^The gateway stopped waiting;/);
    expect(gatewayTimeoutHint(0)).toMatch(/^The gateway stopped waiting;/);
    expect(gatewayTimeoutHint(5)).toMatch(
      /^The gateway stopped waiting after 5 s;/,
    );
  });
});

describe("timeout hint: everything else is untouched", () => {
  it("a backend's own -32001 'Session not found' is not described as a timeout", async () => {
    // -32001 is overloaded: a backend answering an unknown session id uses it,
    // with no timeout data.
    const sessionLost = McpError.fromError(
      ErrorCode.RequestTimeout,
      "Session not found",
    );
    expect(await run(sessionLost)).toBe(sessionLost);
  });

  it("a -32001 that says 'Request timed out' but carries no timeout data is left alone", async () => {
    // Only the SDK's local timeout carries data.timeout; a relayed one does not.
    const relayed = new McpError(ErrorCode.RequestTimeout, "Request timed out");
    expect(await run(relayed)).toBe(relayed);
  });

  it("an abort carrying the timeout code is left alone", async () => {
    const aborted = new McpError(
      ErrorCode.RequestTimeout,
      "AbortError: aborted",
    );
    expect(await run(aborted)).toBe(aborted);
  });

  it.each([
    [
      "a connection-closed error",
      new McpError(ErrorCode.ConnectionClosed, "Connection closed"),
    ],
    ["a plain Error", new Error("Request timed out")],
    ["a transport-not-connected error", new Error("Not connected")],
    [
      "an invalid-params error",
      new McpError(ErrorCode.InvalidParams, "bad", { timeout: 1 }),
    ],
    ["a string", "Request timed out"],
    ["null", null],
    [
      "an object",
      { code: -32001, message: "Request timed out", data: { timeout: 1 } },
    ],
  ])("%s is rethrown as the same value", async (_label, failure) => {
    expect(await run(failure)).toBe(failure);
  });

  it("returns a successful result untouched", async () => {
    const result: CallToolResult = { content: [{ type: "text", text: "ok" }] };
    const wrapped = createTimeoutHintMiddleware()(async () => result);
    await expect(wrapped(request, context)).resolves.toBe(result);
  });

  it("returns an isError result untouched", async () => {
    const result: CallToolResult = {
      isError: true,
      content: [{ type: "text", text: "Request timed out" }],
    };
    const wrapped = createTimeoutHintMiddleware()(async () => result);
    await expect(wrapped(request, context)).resolves.toBe(result);
  });

  it("does not call the handler more than once", async () => {
    const handler = vi.fn().mockRejectedValue(sdkTimeout());
    const wrapped = createTimeoutHintMiddleware()(handler);
    await expect(wrapped(request, context)).rejects.toBeInstanceOf(McpError);
    expect(handler).toHaveBeenCalledTimes(1);
  });
});

describe("annotateGatewayTimeout", () => {
  it("is idempotent in effect: a rewritten error is not rewritten again", () => {
    const once = annotateGatewayTimeout(sdkTimeout()) as McpError;
    // The rewritten message no longer matches the bare SDK form, so a second
    // pass (a nested chain) leaves it alone and the hint never doubles.
    expect(annotateGatewayTimeout(once)).toBe(once);
  });
});
