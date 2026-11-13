/**
 * Only an unsupported client method is an expected sampling/elicitation gap.
 * Hiding timeouts, disconnects or fixture defects behind the same fixed text
 * would also hide a changed failure reason from the conformance snapshot.
 */
import { ErrorCode, McpError } from "@modelcontextprotocol/sdk/types.js";
import { describe, expect, it } from "vitest";

import { createFixtureHandlers, type ToolExtra } from "./fixture-tools";

const TOOLS = [
  ["test_sampling", "Sampling"],
  ["test_elicitation", "Elicitation"],
  ["test_elicitation_sep1034_defaults", "Elicitation (defaults schema)"],
  ["test_elicitation_sep1330_enums", "Elicitation (enum schema)"],
] as const;

function rejecting(error: Error): ToolExtra {
  return {
    sendNotification: async () => undefined,
    sendRequest: async () => {
      throw error;
    },
  };
}

describe.each(TOOLS)("%s request failures", (name, label) => {
  const handlers = createFixtureHandlers({});

  it("keeps the stable unavailable result for MethodNotFound", async () => {
    await expect(
      handlers.callTool(
        name,
        {},
        rejecting(new McpError(ErrorCode.MethodNotFound, "Method not found")),
      ),
    ).resolves.toEqual({
      isError: true,
      content: [
        {
          type: "text",
          text: `${label} is not available through this gateway.`,
        },
      ],
    });
  });

  it.each([
    new McpError(ErrorCode.RequestTimeout, "Request timed out"),
    new McpError(ErrorCode.ConnectionClosed, "Connection closed"),
    new McpError(ErrorCode.InvalidParams, "Invalid response"),
    new Error("unexpected fixture defect"),
  ])("propagates $message instead of masking a new failure", async (error) => {
    await expect(handlers.callTool(name, {}, rejecting(error))).rejects.toBe(
      error,
    );
  });
});
