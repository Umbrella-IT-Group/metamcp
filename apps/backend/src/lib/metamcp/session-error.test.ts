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

  it("returns false for non-Error inputs", () => {
    expect(isBackendSessionLostError(undefined)).toBe(false);
    expect(isBackendSessionLostError(null)).toBe(false);
    expect(isBackendSessionLostError("Session not found")).toBe(false);
  });
});
