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
  LeanCatalog,
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

// ---------------------------------------------------------------------------
// The callback a call_tool verdict carries to be given again by a fresh listing.
//
// These run the REAL callback `createLeanPrelude` returns, against a controlled
// old listing (the verdict) and a controlled fresh one (what the reconnected
// backend lists now). The first `get` is the snapshot the verdict came from;
// every later one is the fresh listing. A stub callback result would prove
// nothing about the predicates in here.
// ---------------------------------------------------------------------------

const ASKED = "desk__modern";
const TARGET = "desk__legacy";
const SELECTED = "desk-id";

/** What a listing is when nothing changed: the alias still names the tool. */
const listing = (overrides: Partial<LeanListing> = {}): LeanListing => ({
  tools: [READ, WRITE],
  unavailable: 0,
  origins: new Map([[ASKED, [TARGET]]]),
  serverUuids: new Map([[TARGET, SELECTED]]),
  isCurrent: () => true,
  ...overrides,
});

async function verdict(fresh: () => Promise<LeanListing>) {
  const log = vi.fn();
  const first = listing();
  const get = vi
    .fn<() => Promise<LeanListing>>()
    .mockResolvedValueOnce(first)
    .mockImplementation(fresh);
  const run = createLeanPrelude({
    catalog: { get } as unknown as LeanCatalog,
    log,
    elapsedMs: () => 0,
  });
  const result = await run(call("call_tool", ASKED));
  // Asserted before it is called, so a build that has no callback fails here
  // on an assertion and not on a TypeError.
  expect(result.reverifyClassifiedTarget).toBeTypeOf("function");
  return { result, get, log, first };
}

const reverify = async (fresh: LeanListing) => {
  const { result } = await verdict(async () => fresh);
  return result.reverifyClassifiedTarget?.();
};

describe("the re-verification callback of call_tool", () => {
  it("answers current, with the fresh listing's own validity check, when the same name still stands for the same tool, backend and read-only hint", async () => {
    const fresh = listing({ isCurrent: () => true });
    const { result, get } = await verdict(async () => fresh);
    expect(await result.reverifyClassifiedTarget?.()).toEqual({
      kind: "current",
      isCurrent: fresh.isCurrent,
    });
    // One read for the verdict, one for the re-verification.
    expect(get).toHaveBeenCalledTimes(2);
    // The verdict handed to the chain is untouched by it.
    expect(result.classifiedTarget).toBe(TARGET);
    expect(result.classifiedServerUuid).toBe(SELECTED);
  });

  it("is attached to call_tool only: no call_write_tool, direct call, nested meta call or refused call carries one", async () => {
    const { run } = prelude(withOrigins([["desk__modern", ["desk__legacy"]]]));
    for (const incoming of [
      call("call_write_tool", ASKED),
      { method: "tools/call", params: { name: ASKED } } as CallToolRequest,
      call("call_tool", "call_write_tool"),
      call("call_tool", "desk__unlisted"),
    ]) {
      const result = await run(incoming);
      expect(result.reverifyClassifiedTarget).toBeUndefined();
    }
    const write = prelude(withOrigins([["desk__write", ["desk__write"]]]));
    expect(
      (await write.run(call("call_tool", "desk__write")))
        .reverifyClassifiedTarget,
    ).toBeUndefined();
  });

  it.each([
    [
      "its read-only hint flipped under the same name and backend",
      { tools: [{ ...READ, annotations: { readOnlyHint: false } }, WRITE] },
    ],
    [
      "its hints disappeared",
      { tools: [{ ...READ, annotations: undefined }, WRITE] },
    ],
    [
      "a second entry under the name is not read-only",
      { tools: [READ, { ...READ, annotations: { readOnlyHint: false } }] },
    ],
    ["the name is no longer listed", { tools: [WRITE] }],
  ])("answers changed when %s", async (_label, fresh: Partial<LeanListing>) => {
    expect(await reverify(listing(fresh))).toEqual({ kind: "changed" });
  });

  it.each([
    [
      "the requested name now lists a different full tool",
      { origins: new Map([[ASKED, ["desk__other"]]]) },
    ],
    ["the fresh origins are missing", { origins: undefined }],
    [
      "the requested name has two origins",
      { origins: new Map([[ASKED, [TARGET, "desk__other"]]]) },
    ],
    ["the requested name has no origin", { origins: new Map() }],
  ])("answers changed when %s", async (_label, fresh: Partial<LeanListing>) => {
    expect(await reverify(listing(fresh))).toEqual({ kind: "changed" });
  });

  it.each([
    [
      "a different backend now serves the same full name",
      { serverUuids: new Map([[TARGET, "replacement-id"]]) },
    ],
    ["the fresh listing has no UUID for it", { serverUuids: new Map() }],
    ["the fresh listing has no UUIDs at all", { serverUuids: undefined }],
  ])(
    "answers changed when %s, with the originally recorded UUID left as it was",
    async (_label, fresh: Partial<LeanListing>) => {
      const { result } = await verdict(async () => listing(fresh));
      expect(result.classifiedServerUuid).toBe(SELECTED);
      expect(await result.reverifyClassifiedTarget?.()).toEqual({
        kind: "changed",
      });
    },
  );

  it.each([
    ["has no validity check", { isCurrent: undefined }],
    ["is already revoked", { isCurrent: () => false }],
  ])(
    "answers changed when the fresh listing %s",
    async (_label, fresh: Partial<LeanListing>) => {
      expect(await reverify(listing(fresh))).toEqual({ kind: "changed" });
    },
  );

  it("looks the alias up under the name the client asked by, not the full name it was recorded as", async () => {
    // The recorded tool is still listed read-only under its own name, but the
    // alias the client used no longer exists: nothing may be inferred from the
    // real name.
    const fresh = listing({
      tools: [{ ...READ, name: TARGET }, WRITE],
      origins: new Map([[TARGET, [TARGET]]]),
    });
    expect(await reverify(fresh)).toEqual({ kind: "changed" });
  });

  it("answers unavailable when the catalog cannot be read (the listing's own retryable error)", async () => {
    const { result } = await verdict(async () => {
      throw new McpError(-32603, "backend unavailable");
    });
    expect(await result.reverifyClassifiedTarget?.()).toEqual({
      kind: "unavailable",
    });
  });

  it("lets an unexpected failure propagate, as the first read does, instead of calling it an unavailable catalog", async () => {
    const boom = new Error("Not connected");
    const { result } = await verdict(async () => {
      throw boom;
    });
    await expect(result.reverifyClassifiedTarget?.()).rejects.toBe(boom);
  });

  it("returns the validity check of the load it waited for, never one captured after it, so a load invalidated while it ran is refused", async () => {
    // A real catalog, whose loader captures validity before it loads, as the
    // proxy's loader does.
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    let loads = 0;
    const catalog: LeanCatalog = new LeanCatalog({
      load: async () => {
        loads += 1;
        const isCurrent = catalog.captureValidity();
        if (loads === 2) await gate;
        return listing({ isCurrent });
      },
      now: () => 0,
      ttlMs: 1_000,
    });
    const run = createLeanPrelude({
      catalog,
      log: vi.fn(),
      elapsedMs: () => 0,
    });
    const result = await run(call("call_tool", ASKED));
    expect(result.reverifyClassifiedTarget).toBeTypeOf("function");
    // The reconnect: the verdict is revoked and the fresh load starts...
    catalog.invalidate();
    const pending = result.reverifyClassifiedTarget?.();
    await Promise.resolve();
    // ...and is itself invalidated while it runs.
    catalog.invalidate();
    release();
    expect(await pending).toEqual({ kind: "changed" });
    expect(loads).toBe(2);
  });

  it("answers current for a fresh load nothing invalidated, and shares a snapshot a concurrent search already built instead of loading again", async () => {
    let loads = 0;
    const catalog: LeanCatalog = new LeanCatalog({
      load: async () => {
        loads += 1;
        return listing({ isCurrent: catalog.captureValidity() });
      },
      now: () => 0,
      ttlMs: 1_000,
    });
    const run = createLeanPrelude({
      catalog,
      log: vi.fn(),
      elapsedMs: () => 0,
    });
    const result = await run(call("call_tool", ASKED));
    catalog.invalidate();
    // A concurrent search rebuilds the snapshot after the invalidation.
    await catalog.get();
    expect(loads).toBe(2);
    const answer = await result.reverifyClassifiedTarget?.();
    expect(answer?.kind).toBe("current");
    expect(loads).toBe(2);
  });
});
