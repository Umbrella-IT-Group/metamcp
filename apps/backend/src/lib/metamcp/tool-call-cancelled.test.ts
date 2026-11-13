/**
 * The typed cancel error. Oracle: the SDK's own `cancel()` and the gateway's
 * replay rule (session-error.ts): an McpError shape is never replayed, and the
 * typed error is recognised by class only, so a backend's JSON-RPC answer with
 * the same code cannot pass for a consumer cancel.
 */
import { McpError } from "@modelcontextprotocol/sdk/types.js";
import { describe, expect, it } from "vitest";

import { isToolCallReplaySafeError } from "./session-error";
import {
  isToolCallCancelledError,
  TOOL_CALL_CANCELLED_CODE,
  TOOL_CALL_CANCELLED_RPC_CODE,
  TOOL_CALL_OUTCOME_UNKNOWN_DETAIL,
  ToolCallCancelledError,
} from "./tool-call-cancelled";

describe("ToolCallCancelledError", () => {
  it("is an McpError carrying the in-process cancel code", () => {
    const error = new ToolCallCancelledError();
    expect(error).toBeInstanceOf(McpError);
    expect(error.code).toBe(TOOL_CALL_CANCELLED_RPC_CODE);
    expect(error.message).toContain("Tool call cancelled by the caller");
  });

  it("is recognised by class only: a backend's McpError with the same code is not", () => {
    expect(isToolCallCancelledError(new ToolCallCancelledError())).toBe(true);
    expect(
      isToolCallCancelledError(
        new McpError(
          TOOL_CALL_CANCELLED_RPC_CODE,
          "Tool call cancelled by the caller",
        ),
      ),
    ).toBe(false);
    expect(
      isToolCallCancelledError({ code: TOOL_CALL_CANCELLED_RPC_CODE }),
    ).toBe(false);
    expect(isToolCallCancelledError(undefined)).toBe(false);
  });

  it("is never replay-safe", () => {
    expect(isToolCallReplaySafeError(new ToolCallCancelledError())).toBe(false);
  });

  it("exposes audit tokens that match the classifier's token shape", () => {
    expect(TOOL_CALL_CANCELLED_CODE).toBe("cancelled");
    expect(TOOL_CALL_OUTCOME_UNKNOWN_DETAIL).toMatch(/^[a-z][a-z0-9_]{0,47}$/);
  });
});
