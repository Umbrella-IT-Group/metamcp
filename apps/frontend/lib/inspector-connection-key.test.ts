/**
 * The Inspector reconnects when this key changes and at no other time, so the
 * tests pin both halves: every setting the connection uses moves the key, and
 * nothing the list refresh changes on its own (labels, the crash tracker's
 * status, bookkeeping) does.
 */
import { type McpServer, McpServerSchema } from "@repo/zod-types";
import { describe, expect, it } from "vitest";

import type { ConnectionStatus } from "./constants";
import {
  buildInspectorConnectionKey,
  inspectorConnectAction,
} from "./inspector-connection-key";

function server(overrides: Partial<McpServer> = {}): McpServer {
  return {
    uuid: "11111111-1111-4111-8111-111111111111",
    name: "alpha",
    description: "first server",
    type: "STDIO",
    command: "npx",
    args: ["-y", "@scope/pkg"],
    env: { TOKEN: "t0", REGION: "us" },
    url: null,
    created_at: "2026-10-01T00:00:00.000Z",
    bearerToken: null,
    headers: { "X-Org": "umbrella" },
    user_id: "user-1",
    error_status: "NONE",
    ...overrides,
  };
}

// The fields that decide what a connection talks to. Each must move the key.
const KEYED: { field: keyof McpServer; changed: Partial<McpServer> }[] = [
  { field: "uuid", changed: { uuid: "22222222-2222-4222-8222-222222222222" } },
  { field: "type", changed: { type: "SSE" } },
  { field: "command", changed: { command: "uvx" } },
  { field: "args", changed: { args: ["-y", "@scope/other"] } },
  { field: "env", changed: { env: { TOKEN: "t1", REGION: "us" } } },
  { field: "url", changed: { url: "https://mcp.example.test/mcp" } },
  { field: "bearerToken", changed: { bearerToken: "secret-token" } },
  { field: "headers", changed: { headers: { "X-Org": "other" } } },
];

// The fields a list refresh can change without touching the connection.
const IGNORED: { field: keyof McpServer; changed: Partial<McpServer> }[] = [
  { field: "name", changed: { name: "alpha (renamed)" } },
  { field: "description", changed: { description: "edited" } },
  { field: "error_status", changed: { error_status: "ERROR" } },
  { field: "created_at", changed: { created_at: "2026-10-02T00:00:00.000Z" } },
  { field: "user_id", changed: { user_id: "user-2" } },
];

describe("buildInspectorConnectionKey", () => {
  it("is the empty string when no server is selected", () => {
    expect(buildInspectorConnectionKey(undefined)).toBe("");
    expect(buildInspectorConnectionKey(null)).toBe("");
  });

  it("is not the empty string for a selected server", () => {
    expect(buildInspectorConnectionKey(server())).not.toBe("");
  });

  it("gives the same key for the same content in a fresh object", () => {
    const first = server();
    // What a refetch with a changed sibling looks like: a new object graph
    // with equal contents.
    const second = JSON.parse(JSON.stringify(first)) as McpServer;
    expect(second).not.toBe(first);
    expect(buildInspectorConnectionKey(second)).toBe(
      buildInspectorConnectionKey(first),
    );
  });

  it("does not depend on the key order of env or headers", () => {
    const a = server({ env: { A: "1", B: "2" }, headers: { X: "1", Y: "2" } });
    const b = server({ env: { B: "2", A: "1" }, headers: { Y: "2", X: "1" } });
    expect(buildInspectorConnectionKey(b)).toBe(buildInspectorConnectionKey(a));
  });

  it("treats null and the empty string as the same command, url and token", () => {
    const withNull = server({ command: null, url: null, bearerToken: null });
    const withEmpty = server({ command: "", url: "", bearerToken: "" });
    expect(buildInspectorConnectionKey(withEmpty)).toBe(
      buildInspectorConnectionKey(withNull),
    );
  });

  describe.each(KEYED)("a change to $field", ({ changed }) => {
    it("gives a different key", () => {
      expect(buildInspectorConnectionKey(server(changed))).not.toBe(
        buildInspectorConnectionKey(server()),
      );
    });
  });

  describe.each(IGNORED)("a change to $field", ({ changed }) => {
    it("gives the same key", () => {
      expect(buildInspectorConnectionKey(server(changed))).toBe(
        buildInspectorConnectionKey(server()),
      );
    });
  });

  it("keeps args as an array: one argument with a space is not two arguments", () => {
    const joined = server({ args: ["--flag value"] });
    const split = server({ args: ["--flag", "value"] });
    expect(buildInspectorConnectionKey(joined)).not.toBe(
      buildInspectorConnectionKey(split),
    );
  });

  it("keeps args as an array: one argument with a comma is not two arguments", () => {
    // Guards against joining args into a string with "," (or any separator
    // an argument can contain), which would merge these two servers.
    const joined = server({ args: ["a,b"] });
    const split = server({ args: ["a", "b"] });
    expect(buildInspectorConnectionKey(joined)).not.toBe(
      buildInspectorConnectionKey(split),
    );
  });

  it("keeps argument order", () => {
    const forward = server({ args: ["a", "b"] });
    const reversed = server({ args: ["b", "a"] });
    expect(buildInspectorConnectionKey(forward)).not.toBe(
      buildInspectorConnectionKey(reversed),
    );
  });

  it("cannot confuse a value that moves from one field to a neighbour", () => {
    const inUrl = server({ type: "SSE", command: null, url: "x" });
    const inCommand = server({ type: "SSE", command: "x", url: null });
    expect(buildInspectorConnectionKey(inUrl)).not.toBe(
      buildInspectorConnectionKey(inCommand),
    );
  });

  it("notices an env entry being added or removed", () => {
    const base = server({ env: { A: "1" } });
    const added = server({ env: { A: "1", B: "2" } });
    const removed = server({ env: {} });
    expect(buildInspectorConnectionKey(added)).not.toBe(
      buildInspectorConnectionKey(base),
    );
    expect(buildInspectorConnectionKey(removed)).not.toBe(
      buildInspectorConnectionKey(base),
    );
  });

  it("classifies every field of the server schema as keyed or ignored", () => {
    // A new column on McpServerSchema has to be decided here: if the
    // connection reads it, add it to KEYED and to the key builder; if not, add
    // it to IGNORED. Without this, the key would silently miss it and an edit
    // to it would leave the Inspector on the old configuration.
    const classified = [...KEYED, ...IGNORED].map(({ field }) => field).sort();
    expect(Object.keys(McpServerSchema.shape).sort()).toEqual(classified);
  });
});

describe("inspectorConnectAction", () => {
  // The page runs this when the connection key changes or the list finishes
  // loading. The error rows are the behavior change: after a failed connect the
  // hook holds no client, so a changed key connects again instead of leaving
  // the previous server's error showing under the new selection.
  const CASES: [ConnectionStatus, "reconnect" | "connect" | "none"][] = [
    ["connected", "reconnect"],
    ["disconnected", "connect"],
    ["error", "connect"],
    ["error-connecting-to-proxy", "connect"],
    ["connecting", "none"],
  ];

  it.each(CASES)("%s -> %s", (status, action) => {
    expect(inspectorConnectAction(status)).toBe(action);
  });

  it("covers every status the hook can report", () => {
    // ConnectionStatus is a type, so list the members through a Record: adding
    // a status to the union makes this object fail to compile until the case
    // table above is revisited.
    const all: Record<ConnectionStatus, true> = {
      connecting: true,
      disconnected: true,
      connected: true,
      error: true,
      "error-connecting-to-proxy": true,
    };
    expect(CASES.map(([status]) => status).sort()).toEqual(
      Object.keys(all).sort(),
    );
  });
});
