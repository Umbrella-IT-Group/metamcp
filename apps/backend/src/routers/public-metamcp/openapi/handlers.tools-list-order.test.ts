/**
 * The OpenAPI bridge's aggregated tool list is byte-stable (issue #278), against
 * real SDK peers (a real `Client` and `Server` over `InMemoryTransport`) and
 * several backends whose listings finish in a different order on every run.
 *
 * openapi.json is built from this list, and a client that re-reads it and
 * compares it (Open WebUI, the reporter's case) treated every reordering as a
 * changed tool set.
 *
 * Oracle: the same mounted backends serving the same tools give the same
 * bytes, in byte-wise (UTF-16 code unit) order of the tool name, whichever
 * backend answers first. The expected order comes from the language's default
 * `sort()` and from a literal, never from the code under test. Both return
 * sites are read: the client-facing listing and the bridge's own audit one.
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  ListToolsRequestSchema,
  Tool,
} from "@modelcontextprotocol/sdk/types.js";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { ConnectedClient } from "../../../lib/metamcp/client";

const { getSessionMock, mounted } = vi.hoisted(() => ({
  getSessionMock: vi.fn(),
  mounted: { current: {} as Record<string, { name: string }> },
}));

vi.mock("../../../db", () => ({ db: {} }));
vi.mock("../../../db/schema", () => ({}));
vi.mock("@/utils/logger", () => ({
  default: { error: vi.fn(), warn: vi.fn(), info: vi.fn(), debug: vi.fn() },
}));
vi.mock("../../../lib/config.service", () => ({
  configService: {
    getMcpResetTimeoutOnProgress: async () => true,
    getMcpTimeout: async () => 5_000,
    getMcpMaxTotalTimeout: async () => 600_000,
  },
}));
vi.mock("../../../lib/metamcp/fetch-metamcp", () => ({
  getMcpServers: vi.fn(async () => mounted.current),
  // An audit listing reads the routable and error-gated servers through this one
  // (#239, fork PR #282); none of these fixtures is error-gated.
  getNamespaceListingServers: vi.fn(async () => ({
    routable: mounted.current,
    errorGated: {},
  })),
}));
vi.mock("../../../lib/metamcp/mcp-server-pool", () => ({
  mcpServerPool: {
    getSession: getSessionMock,
    invalidateServerConnection: vi.fn(),
    isPooledClient: () => true,
  },
}));
vi.mock(
  "../../../lib/metamcp/metamcp-middleware/filter-tools.functional",
  () => ({
    createFilterCallToolMiddleware: () => (next: unknown) => next,
    createFilterListToolsMiddleware: () => (next: unknown) => next,
  }),
);
vi.mock(
  "../../../lib/metamcp/metamcp-middleware/tool-overrides.functional",
  () => ({
    createToolOverridesCallToolMiddleware: () => (next: unknown) => next,
    createToolOverridesListToolsMiddleware: () => (next: unknown) => next,
  }),
);

import {
  createOriginalListToolsHandler,
  resetBridgeAuditSchemasForTesting,
} from "./handlers";

const context = { namespaceUuid: "ns-1", sessionId: "openapi_ns-1" };
const cleanups: Array<() => Promise<unknown>> = [];

// Mount order is not sorted and neither is each backend's own order. Names mix
// case, an underscore and a non-ASCII letter, so a locale-aware comparison
// orders them differently from code units: "B" (66) < "_" (95) < "a" (97) <
// "é" (233).
const BACKENDS: Array<{ uuid: string; name: string; tools: string[] }> = [
  { uuid: "u-zeta", name: "zeta", tools: ["run", "Build", "alpha"] },
  { uuid: "u-alpha", name: "alpha", tools: ["é", "a", "B", "_x"] },
  { uuid: "u-mu", name: "mu", tools: ["list"] },
  { uuid: "u-beta", name: "beta", tools: ["z", "y", "x"] },
  { uuid: "u-omega", name: "omega", tools: ["b", "a"] },
  { uuid: "u-delta", name: "delta", tools: ["get", "Get"] },
];

const EXPECTED_FIRST = [
  "alpha__B",
  "alpha___x",
  "alpha__a",
  "alpha__é",
  "beta__x",
  "beta__y",
  "beta__z",
];

type Delays = Record<string, number>;
const STEP = 25;
const delayRuns = (): Delays[] => {
  const n = BACKENDS.length;
  const by = (f: (i: number) => number): Delays =>
    Object.fromEntries(BACKENDS.map((b, i) => [b.uuid, f(i) * STEP]));
  return [
    by((i) => i),
    by((i) => n - 1 - i),
    by((i) => (i + 2) % n),
    by((i) => (i + 4) % n),
    by((i) => (i * 5) % n),
  ];
};
let delays: Delays = {};

const toolOf = (name: string): Tool => ({
  name,
  description: `${name} description`,
  inputSchema: { type: "object", properties: {} },
});

async function mountBackends() {
  mounted.current = Object.fromEntries(
    BACKENDS.map((b) => [b.uuid, { name: b.name }]),
  );
  const sessions = new Map<string, ConnectedClient>();
  for (const backend of BACKENDS) {
    const server = new Server(
      { name: backend.name, version: "1.0.0" },
      { capabilities: { tools: {} } },
    );
    server.setRequestHandler(ListToolsRequestSchema, async () => {
      await new Promise((resolve) => setTimeout(resolve, delays[backend.uuid]));
      return { tools: backend.tools.map(toolOf) };
    });
    const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
    await server.connect(serverSide);
    const client = new Client({ name: "metamcp", version: "1.0.0" });
    await client.connect(clientSide);
    cleanups.push(() => client.close());
    sessions.set(backend.uuid, {
      client,
      cleanup: () => client.close(),
      listChangedSubscribers: new Set(),
    } as unknown as ConnectedClient);
  }
  getSessionMock.mockImplementation(async (_sessionId: string, uuid: string) =>
    sessions.get(uuid),
  );
}

const allNames = BACKENDS.flatMap((b) => b.tools.map((t) => `${b.name}__${t}`));
// The language's own default sort: UTF-16 code units, no comparator.
const oracleOrder = [...allNames].sort();

beforeEach(() => {
  getSessionMock.mockReset();
  resetBridgeAuditSchemasForTesting();
});

afterEach(async () => {
  vi.restoreAllMocks();
  while (cleanups.length > 0) {
    await cleanups
      .pop()?.()
      .catch(() => undefined);
  }
});

describe.each([
  ["the client-facing listing", false],
  ["the bridge's audit listing", true],
] as const)("OpenAPI bridge %s", (_label, audit) => {
  it("lists every tool in byte-wise name order, whichever backend answers first", async () => {
    await mountBackends();

    const bodies: string[] = [];
    for (const run of delayRuns()) {
      delays = run;
      const { tools } = await createOriginalListToolsHandler(false, { audit })(
        { method: "tools/list", params: {} },
        context,
      );
      expect(tools.map((t) => t.name)).toEqual(oracleOrder);
      bodies.push(JSON.stringify(tools));
    }

    // One set of bytes across all five completion orders.
    expect(new Set(bodies).size).toBe(1);
    // Pinned by literal, so the oracle itself cannot drift: a locale-aware
    // comparison would put "alpha__a" before "alpha__B".
    expect(oracleOrder.slice(0, EXPECTED_FIRST.length)).toEqual(EXPECTED_FIRST);
  });
});

describe("OpenAPI bridge listing of two servers that expose one name", () => {
  // The bridge has no collision guard, so both are listed. Equal names must
  // keep MOUNT order, never completion order, or the bytes still change.
  it("keeps equal names in mount order, whichever backend answers first", async () => {
    mounted.current = {
      "u-first": { name: "dup" },
      "u-second": { name: "dup" },
    };
    const sessions = new Map<string, ConnectedClient>();
    for (const uuid of ["u-first", "u-second"]) {
      const server = new Server(
        { name: "dup", version: "1.0.0" },
        { capabilities: { tools: {} } },
      );
      server.setRequestHandler(ListToolsRequestSchema, async () => {
        await new Promise((resolve) => setTimeout(resolve, delays[uuid]));
        return { tools: [{ ...toolOf("same"), description: uuid }] };
      });
      const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
      await server.connect(serverSide);
      const client = new Client({ name: "metamcp", version: "1.0.0" });
      await client.connect(clientSide);
      cleanups.push(() => client.close());
      sessions.set(uuid, {
        client,
        cleanup: () => client.close(),
        listChangedSubscribers: new Set(),
      } as unknown as ConnectedClient);
    }
    getSessionMock.mockImplementation(
      async (_sessionId: string, uuid: string) => sessions.get(uuid),
    );

    for (const run of [
      { "u-first": 0, "u-second": 60 },
      { "u-first": 60, "u-second": 0 },
    ]) {
      delays = run;
      const { tools } = await createOriginalListToolsHandler()(
        { method: "tools/list", params: {} },
        context,
      );
      expect(tools.map((t) => t.description)).toEqual(["u-first", "u-second"]);
    }
  });
});
