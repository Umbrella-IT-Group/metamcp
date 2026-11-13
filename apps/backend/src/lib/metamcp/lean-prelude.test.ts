/**
 * What the lean prelude hands the call chain for a call meta tool, with the
 * catalog stubbed (the proxy suite runs the real chain).
 *
 * The rule under test: `call_tool` gives a read-only verdict only for a tool the
 * snapshot can NAME, and hands that tool's identity on with the request, so the
 * chain can refuse the call if the name has since come to lead somewhere else.
 * `call_write_tool` relied on no verdict and carries no identity, and a call
 * that is not a clean request never reaches the catalog at all.
 */
import type { CallToolRequest, Tool } from "@modelcontextprotocol/sdk/types.js";
import { McpError } from "@modelcontextprotocol/sdk/types.js";
import { describe, expect, it, vi } from "vitest";

import {
  CALL_TOOL_ROUTING_ANSWER,
  type LeanCatalog,
  type LeanListing,
} from "./lean-listing";
import { createLeanPrelude } from "./lean-prelude";

const READ: Tool = {
  name: "desk__modern",
  description: "A read-only tool listed under an alias",
  inputSchema: { type: "object" },
  annotations: { readOnlyHint: true },
};
const WRITE: Tool = {
  name: "desk__write",
  description: "A tool that changes data",
  inputSchema: { type: "object" },
  annotations: { readOnlyHint: false },
};

const call = (via: string, name: string): CallToolRequest => ({
  method: "tools/call",
  params: { name: via, arguments: { name, arguments: { id: "1" } } },
});

function prelude(listing: LeanListing | Error) {
  const log = vi.fn();
  const get = vi.fn(async () => {
    if (listing instanceof Error) throw listing;
    return listing;
  });
  const run = createLeanPrelude({
    catalog: { get } as unknown as LeanCatalog,
    log,
    elapsedMs: () => 0,
  });
  return { run, log, get };
}

const withOrigins = (
  origins: Array<[string, string[]]> | undefined,
): LeanListing => ({
  tools: [READ, WRITE],
  unavailable: 0,
  serverUuids: new Map([
    ["desk__legacy", "desk-id"],
    ["desk__write", "desk-id"],
  ]),
  isCurrent: () => true,
  ...(origins ? { origins: new Map(origins) } : {}),
});

describe("call_tool", () => {
  it("hands the request on with the original full name of the tool the verdict was given for, not the name it was asked by", async () => {
    const { run } = prelude(withOrigins([["desk__modern", ["desk__legacy"]]]));
    const result = await run(call("call_tool", "desk__modern"));
    expect(result.answer).toBeUndefined();
    expect(result.classifiedTarget).toBe("desk__legacy");
    expect(result.classifiedServerUuid).toBe("desk-id");
    expect(result.classifiedTargetIsCurrent?.()).toBe(true);
    expect(result.request?.params.name).toBe("desk__modern");
  });

  it("gives no verdict, and runs nothing, when the snapshot cannot name the tool: no origins, or two entries under the name", async () => {
    for (const origins of [
      undefined,
      [["desk__modern", ["desk__a", "desk__b"]]] as Array<[string, string[]]>,
      [] as Array<[string, string[]]>,
    ]) {
      const { run, log } = prelude(withOrigins(origins));
      const result = await run(call("call_tool", "desk__modern"));
      expect(result.request).toBeUndefined();
      expect(result.classifiedTarget).toBeUndefined();
      expect(result.answer).toEqual({
        isError: true,
        content: [{ type: "text", text: CALL_TOOL_ROUTING_ANSWER }],
      });
      expect(log).toHaveBeenCalledWith("warn", expect.any(String));
      // A count-only line: no name, no failure words.
      const line = String(log.mock.calls[0]?.[1]);
      expect(line).not.toContain("desk__");
      expect(line).not.toMatch(/error|fail/i);
    }
  });

  it("gives no verdict without the backend UUID or a snapshot validity check", async () => {
    const listing = withOrigins([["desk__modern", ["desk__legacy"]]]);
    for (const incomplete of [
      { ...listing, serverUuids: undefined },
      { ...listing, isCurrent: undefined },
    ]) {
      const { run } = prelude(incomplete);
      const result = await run(call("call_tool", "desk__modern"));
      expect(result.request).toBeUndefined();
      expect(result.answer?.isError).toBe(true);
    }
  });

  it("still sends a tool that is not read-only to the routing answer, with no identity recorded", async () => {
    const { run } = prelude(withOrigins([["desk__write", ["desk__write"]]]));
    const result = await run(call("call_tool", "desk__write"));
    expect(result.request).toBeUndefined();
    expect(result.classifiedTarget).toBeUndefined();
    expect(result.answer?.isError).toBe(true);
  });
});

describe("call_write_tool", () => {
  it("carries no identity and does not read the catalog: it may run any tool the session may run", async () => {
    const { run, get } = prelude(
      withOrigins([["desk__modern", ["desk__legacy"]]]),
    );
    const result = await run(call("call_write_tool", "desk__modern"));
    expect(result.answer).toBeUndefined();
    expect(result.classifiedTarget).toBeUndefined();
    expect(result.request?.params.name).toBe("desk__modern");
    expect(get).not.toHaveBeenCalled();
  });
});

describe("a call that is not a call_tool", () => {
  it("sends a direct real-name call on unchanged, with no identity", async () => {
    const { run, get } = prelude(
      withOrigins([["desk__modern", ["desk__legacy"]]]),
    );
    const result = await run({
      method: "tools/call",
      params: { name: "desk__modern" },
    });
    expect(result).toEqual({});
    expect(get).not.toHaveBeenCalled();
  });

  it("answers a catalog that cannot be read with the retryable answer and no identity", async () => {
    const { run } = prelude(new McpError(-32603, "backend unavailable"));
    const result = await run(call("call_tool", "desk__modern"));
    expect(result.request).toBeUndefined();
    expect(result.classifiedTarget).toBeUndefined();
    expect(result.answer?.isError).toBe(true);
  });

  it("refuses a nested meta call before it reaches the catalog", async () => {
    const { run, get } = prelude(
      withOrigins([["desk__modern", ["desk__legacy"]]]),
    );
    const result = await run(call("call_tool", "call_write_tool"));
    expect(result.answer?.isError).toBe(true);
    expect(result.classifiedTarget).toBeUndefined();
    expect(get).not.toHaveBeenCalled();
  });
});
