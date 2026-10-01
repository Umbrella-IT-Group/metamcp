import { describe, expect, it } from "vitest";

import {
  isUnknownToolError,
  looksLikeUnknownTool,
  UNKNOWN_TOOL_TEXT_WINDOW,
} from "./unknown-tool";

describe("looksLikeUnknownTool", () => {
  it.each([
    ["the gateway throw", "Unknown tool: autotask__add_note"],
    [
      "the OpenAPI bridge throw (JSON quoted)",
      'Unknown tool: "autotask__add_note"',
    ],
    ["a FastMCP backend answer (repr quoted)", "Unknown tool: 'add_note'"],
    [
      "the SDK-wrapped form",
      "MCP error -32602: Unknown tool: autotask__add_note",
    ],
    ["a TypeScript-SDK backend", "Tool add_note not found"],
    [
      "a TypeScript-SDK backend, wrapped",
      "MCP error -32602: Tool add_note not found",
    ],
    [
      "the filter's unresolved-server denial",
      'Access denied to tool "retired__lookup": server could not be resolved',
    ],
    ["leading whitespace", "  Unknown tool: x"],
  ])("matches %s", (_label, text) => {
    expect(looksLikeUnknownTool(text)).toBe(true);
  });

  it.each([
    ["a mid-sentence mention", "Error calling tool 'x': Unknown tool: y"],
    ["lowercase prose", "an unknown tool was requested"],
    [
      "a different denial reason",
      'Access denied to tool "x": Tool has been marked as inactive',
    ],
    ["a timeout", "MCP error -32001: Request timed out"],
    ["an empty string", ""],
    ["a tool name only", "autotask__search"],
    ["a not-found that starts elsewhere", "Ticket 123 not found"],
    ["Tool ... not found split over lines", "Tool x\nnot found"],
  ])("does not match %s", (_label, text) => {
    expect(looksLikeUnknownTool(text)).toBe(false);
  });

  it("rejects non-strings without throwing", () => {
    for (const value of [undefined, null, 5, {}, [], true]) {
      expect(looksLikeUnknownTool(value)).toBe(false);
    }
  });

  it("inspects only the first window of characters", () => {
    const padded = `${" ".repeat(UNKNOWN_TOOL_TEXT_WINDOW)}Unknown tool: x`;
    // Whitespace padding past the window pushes the phrase out of view.
    expect(looksLikeUnknownTool(padded)).toBe(false);
  });

  it("names beyond the 120 character allowance do not satisfy the not-found form", () => {
    const longName = "n".repeat(130);
    expect(looksLikeUnknownTool(`Tool ${longName} not found`)).toBe(false);
  });
});

describe("isUnknownToolError", () => {
  it("is true for the gateway's own thrown error", () => {
    expect(isUnknownToolError(new Error("Unknown tool: a__b"))).toBe(true);
    expect(isUnknownToolError(new Error('Unknown tool: "a__b"'))).toBe(true);
  });

  it("is true for an SDK-wrapped error carrying the text in message", () => {
    const wrapped = Object.assign(
      new Error("MCP error -32602: Unknown tool: a__b"),
      {
        code: -32602,
      },
    );
    expect(isUnknownToolError(wrapped)).toBe(true);
  });

  it.each([
    [
      "a timeout",
      Object.assign(new Error("Request timed out"), { code: -32001 }),
    ],
    ["not connected", new Error("Not connected")],
    ["an invalid name format", new Error("Invalid tool name format: x")],
    ["a string", "Unknown tool: x"],
    ["null", null],
    ["an object without a message", { code: 1 }],
  ])("is false for %s", (_label, value) => {
    expect(isUnknownToolError(value)).toBe(false);
  });
});
