import { describe, expect, it } from "vitest";

import { isBackendSessionLostError } from "./session-error";

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

  it("does not match transport disconnects", () => {
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
});
