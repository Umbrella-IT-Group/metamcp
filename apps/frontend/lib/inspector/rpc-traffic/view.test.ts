/**
 * What the traffic panel searches and what its Download writes.
 *
 * The download is the one place a log leaves the browser tab, so the tests
 * pin what stays in it when bodies are left out: the structure that debugging
 * needs (methods, ids, timing, error codes) and none of the text a tool was
 * given or returned. Oracle for the structure: JSON-RPC 2.0 sections 4 and 5.
 */
import { describe, expect, it } from "vitest";

import { buildRpcTrafficPairs } from "./correlation";
import type { RpcTrafficDirection, RpcTrafficEntry } from "./types";
import {
  buildTrafficExport,
  DEFAULT_OMIT_BODIES,
  entrySearchText,
  extractInitializeResult,
  filterEntries,
  trafficExportFilename,
} from "./view";

const T0 = Date.parse("2026-11-12T12:00:00.000Z");

let counter = 0;
function entry(
  direction: RpcTrafficDirection,
  message: unknown,
  atMs = 0,
  extra: Partial<RpcTrafficEntry> = {},
): RpcTrafficEntry {
  counter += 1;
  return {
    id: `rpc-${counter}`,
    direction,
    timestamp: new Date(T0 + atMs).toISOString(),
    message,
    bytes: JSON.stringify(message).length,
    ...extra,
  };
}

const META = {
  target: { kind: "namespace", name: "ns-helpdesk" },
  exportedAtMs: T0 + 60_000,
};

describe("DEFAULT_OMIT_BODIES", () => {
  it("leaves params and results out of a download unless the user says otherwise", () => {
    expect(DEFAULT_OMIT_BODIES).toBe(true);
  });
});

describe("search", () => {
  const rows = [
    entry("send", {
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: { name: "Search_Items", arguments: { q: "Printer" } },
    }),
    entry("receive", { jsonrpc: "2.0", id: 1, result: { content: [] } }),
    entry("receive", { transportEvent: "error", error: "Network Down" }),
  ];

  it("matches the method and the body without regard to case", () => {
    expect(filterEntries(rows, "TOOLS/CALL")).toEqual([rows[0]]);
    expect(filterEntries(rows, "printer")).toEqual([rows[0]]);
    expect(filterEntries(rows, "network down")).toEqual([rows[2]]);
  });

  it("returns every row for an empty or blank query, and none for no match", () => {
    expect(filterEntries(rows, "")).toBe(rows);
    expect(filterEntries(rows, "   ")).toBe(rows);
    expect(filterEntries(rows, "no such text")).toEqual([]);
  });

  it("reads only the start of a very large body", () => {
    const big = entry("receive", {
      jsonrpc: "2.0",
      id: 2,
      result: { text: `${"a".repeat(70_000)}needle-at-the-end` },
    });
    const early = entry("receive", {
      jsonrpc: "2.0",
      id: 3,
      result: { text: `needle-at-the-start${"a".repeat(70_000)}` },
    });
    expect(filterEntries([big], "needle-at-the-end")).toEqual([]);
    expect(filterEntries([early], "needle-at-the-start")).toEqual([early]);
    expect(entrySearchText(big)).toBe(entrySearchText(big));
  });
});

describe("buildTrafficExport", () => {
  const request = entry(
    "send",
    {
      jsonrpc: "2.0",
      id: 4,
      method: "tools/call",
      params: { name: "read_secret", arguments: { key: "ARG-SECRET-VALUE" } },
    },
    0,
  );
  const answer = entry(
    "receive",
    {
      jsonrpc: "2.0",
      id: 4,
      result: { content: [{ type: "text", text: "RESULT-SECRET-VALUE" }] },
    },
    37,
  );
  const failed = entry("receive", {
    jsonrpc: "2.0",
    id: 5,
    error: { code: -32602, message: "ERRMSG-SECRET", data: "ERRDATA-SECRET" },
  });
  const burst = entry(
    "receive",
    {
      jsonrpc: "2.0",
      method: "notifications/progress",
      params: { progressToken: "t", progress: 3 },
    },
    50,
    { repeatCount: 3 },
  );
  const transport = entry("receive", {
    transportEvent: "error",
    error: "SSE error: Non-200 status code (403)",
  });
  const rows = [request, answer, failed, burst, transport];
  const labels = buildRpcTrafficPairs(rows).responseLabels;

  it("writes the whole messages when asked to", () => {
    const out = buildTrafficExport(rows, labels, META, { omitBodies: false });
    expect(out).toMatchObject({
      format: "metamcp-inspector-rpc-log",
      version: 1,
      exportedAt: "2026-11-12T12:01:00.000Z",
      target: { kind: "namespace", name: "ns-helpdesk" },
      bodiesOmitted: false,
    });
    expect(out.entries).toHaveLength(5);
    expect(out.entries[0]).toEqual({
      id: request.id,
      direction: "send",
      timestamp: request.timestamp,
      message: request.message,
    });
    expect(out.entries[1]).toMatchObject({
      message: answer.message,
      latencyMs: 37,
    });
    expect(out.entries[3]).toMatchObject({ repeatCount: 3 });
    expect(JSON.stringify(out)).toContain("ARG-SECRET-VALUE");
    expect(JSON.stringify(out)).toContain("RESULT-SECRET-VALUE");
  });

  it("leaves params, results and error text out, and nothing a tool was given or returned remains", () => {
    const out = buildTrafficExport(rows, labels, META, { omitBodies: true });
    expect(out.bodiesOmitted).toBe(true);
    const text = JSON.stringify(out);
    for (const secret of [
      "ARG-SECRET-VALUE",
      "read_secret",
      "RESULT-SECRET-VALUE",
      "ERRMSG-SECRET",
      "ERRDATA-SECRET",
    ]) {
      expect(text, secret).not.toContain(secret);
    }
    expect(out.entries[0]?.message).toEqual({
      jsonrpc: "2.0",
      id: 4,
      method: "tools/call",
    });
    expect(out.entries[1]?.message).toEqual({ jsonrpc: "2.0", id: 4 });
    expect(out.entries[2]?.message).toEqual({
      jsonrpc: "2.0",
      id: 5,
      error: { code: -32602 },
    });
    // Timing and the merge count are structure, so they stay.
    expect(out.entries[1]?.latencyMs).toBe(37);
    expect(out.entries[3]).toMatchObject({ repeatCount: 3 });
    expect(out.entries[3]?.message).toEqual({
      jsonrpc: "2.0",
      method: "notifications/progress",
    });
  });

  it("keeps the diagnosis of a failed connection when bodies are left out, bounded", () => {
    const out = buildTrafficExport(rows, labels, META, { omitBodies: true });
    expect(out.entries[4]?.message).toEqual({
      transportEvent: "error",
      error: "SSE error: Non-200 status code (403)",
    });

    const long = entry("receive", {
      transportEvent: "error",
      error: `Error POSTing: ${"s".repeat(5000)}`,
    });
    const trimmed = buildTrafficExport([long], new Map(), META, {
      omitBodies: true,
    });
    const kept = (trimmed.entries[0]?.message as { error: string }).error;
    expect(kept.length).toBeLessThan(520);
  });

  it("does not put an id that is not a string, a number or null in the structure", () => {
    const odd = entry("receive", {
      jsonrpc: "2.0",
      id: { nested: "BODY" },
      method: "x/y",
    });
    const out = buildTrafficExport([odd], new Map(), META, {
      omitBodies: true,
    });
    expect(JSON.stringify(out)).not.toContain("BODY");
  });
});

describe("trafficExportFilename", () => {
  it("is named for the target and the UTC time", () => {
    expect(trafficExportFilename("ns-helpdesk", T0)).toBe(
      "metamcp-inspector-traffic-ns-helpdesk-20261112T120000Z.json",
    );
  });

  it("reduces a hostile name to letters, digits, underscore and hyphen", () => {
    const name = trafficExportFilename('../../etc/pass wd\\"; rm -rf', T0);
    expect(name).toMatch(
      /^metamcp-inspector-traffic-[A-Za-z0-9_-]+-\d{8}T\d{6}Z\.json$/,
    );
    expect(name).not.toContain("/");
    expect(name).not.toContain("\\");
    expect(name).not.toContain("..");
  });

  it("falls back to a fixed name for an empty target and bounds a long one", () => {
    expect(trafficExportFilename("", T0)).toContain("-target-");
    expect(trafficExportFilename("n".repeat(500), T0).length).toBeLessThan(100);
  });
});

describe("extractInitializeResult", () => {
  const initialize = (id: unknown) =>
    entry("send", { jsonrpc: "2.0", id, method: "initialize", params: {} });
  const answer = (id: unknown, result: unknown) =>
    entry("receive", { jsonrpc: "2.0", id, result });

  it("returns the result of the response with the matching id", () => {
    const rows = [
      initialize(0),
      answer(9, { protocolVersion: "wrong" }),
      answer(0, { protocolVersion: "2025-11-25" }),
    ];
    expect(extractInitializeResult(rows)).toEqual({
      protocolVersion: "2025-11-25",
    });
  });

  it('does not treat id "0" as id 0', () => {
    expect(
      extractInitializeResult([initialize(0), answer("0", { a: 1 })]),
    ).toBeNull();
    expect(
      extractInitializeResult([initialize("0"), answer(0, { a: 1 })]),
    ).toBeNull();
  });

  it("is null without a request, without a response, or for an error response", () => {
    expect(extractInitializeResult([])).toBeNull();
    expect(extractInitializeResult([answer(0, { a: 1 })])).toBeNull();
    expect(extractInitializeResult([initialize(0)])).toBeNull();
    expect(
      extractInitializeResult([
        initialize(0),
        entry("receive", { jsonrpc: "2.0", id: 0, error: { code: 1 } }),
      ]),
    ).toBeNull();
  });
});
