/**
 * The aggregated tools/list is byte-stable (issue #278), driven end to end
 * through `createServer` with real SDK peers and several backends whose
 * listings finish in a different order on every run.
 *
 * Oracle: the contract a client relies on when it hashes the list or builds a
 * cached prompt prefix from it. The same mounted backends serving the same
 * tools must produce the same bytes, in byte-wise (UTF-16 code unit) order of
 * the tool name, however the backends happen to answer. The expected order is
 * taken from the language's own default `sort()` (code units) and from a
 * literal list, never from the module under test.
 *
 * Both sites of the proxy are covered: the client-facing `tools/list`, and
 * the audit listing the gateway runs for its own schema snapshot (it never
 * reaches a client, so its input to `unambiguousAuditTools` is what is read).
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  CallToolRequestSchema,
  CallToolResultSchema,
  ListToolsRequestSchema,
  ListToolsResultSchema,
  Tool,
} from "@modelcontextprotocol/sdk/types.js";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { ConnectedClient } from "./client";

const { getSessionMock, mounted, auditInputs } = vi.hoisted(() => ({
  getSessionMock: vi.fn(),
  mounted: { current: {} as Record<string, { name: string }> },
  auditInputs: { current: [] as string[][] },
}));

vi.mock("@/utils/logger", () => ({
  default: { error: vi.fn(), warn: vi.fn(), info: vi.fn(), debug: vi.fn() },
}));
vi.mock("../../db", () => ({ db: {} }));
vi.mock("../../db/schema", () => ({}));
vi.mock("../../db/repositories/namespaces.repo", () => ({
  namespacesRepository: {
    findServersForNamespaceToolName: vi.fn().mockResolvedValue([]),
  },
}));
vi.mock("../../db/repositories/oauth-sessions.repo", () => ({
  oauthSessionsRepository: {},
}));
vi.mock("../../db/repositories", () => ({
  toolsRepository: {
    syncTools: vi.fn().mockResolvedValue({ upserted: [], deleted: [] }),
  },
  mcpServersRepository: {},
}));
vi.mock("../audit/admin-event", () => ({ emitAdminEvent: vi.fn() }));
vi.mock("../config.service", () => ({
  configService: {
    getMcpResetTimeoutOnProgress: async () => true,
    getMcpTimeout: async () => 5_000,
    getMcpMaxTotalTimeout: async () => 600_000,
    getMcpToolCallReconnectWarmupTimeout: async () => 0,
  },
}));
vi.mock("./fetch-metamcp", () => {
  const getMcpServers = vi.fn(async () => mounted.current);
  return {
    getMcpServers,
    getNamespaceListingServers: vi.fn(async () => ({
      routable: await getMcpServers(),
      errorGated: {},
    })),
    getNamespaceServerStates: vi.fn(async () => []),
  };
});
vi.mock("./mcp-server-pool", () => ({
  mcpServerPool: {
    getSession: getSessionMock,
    invalidateServerConnection: vi.fn(),
    cleanupSession: vi.fn(),
    isPooledClient: () => true,
    getPoolStatus: () => ({ idle: 1, active: 1 }),
  },
}));
vi.mock("./metamcp-middleware/filter-tools.functional", () => ({
  createFilterCallToolMiddleware: () => (next: unknown) => next,
  createFilterListToolsMiddleware: () => (next: unknown) => next,
}));
vi.mock("./metamcp-middleware/tool-overrides.functional", () => ({
  createToolOverridesCallToolMiddleware: () => (next: unknown) => next,
  createToolOverridesListToolsMiddleware: () => (next: unknown) => next,
  mapOverrideNameToOriginal: vi.fn(async (name: string) => name),
}));
vi.mock("./cold-connect-broker-fallback", () => ({
  resolveColdConnectBrokerFallback: () => undefined,
}));
vi.mock("./tool-call-warmup", () => ({
  acquireSessionWithBoundedWarmup: vi.fn(async () => undefined),
}));
// Read-only wrapper: the real function runs, the test only records the order
// of the listing the audit variant hands it.
vi.mock("./tool-arg-keys", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./tool-arg-keys")>();
  return {
    ...actual,
    unambiguousAuditTools: <T extends { name: string }>(
      tools: ReadonlyArray<T>,
      prefixes: Iterable<string | undefined>,
    ) => {
      auditInputs.current.push(tools.map((t) => t.name));
      return actual.unambiguousAuditTools(tools, prefixes);
    },
  };
});

import { metamcpLogStore } from "./log-store";
import { createServer } from "./metamcp-proxy";
import { toolsSyncCache } from "./tools-sync-cache";

const cleanups: Array<() => Promise<unknown>> = [];

// Mount order is deliberately NOT sorted, and each backend's own order is not
// sorted either. Tool names mix case, an underscore and a non-ASCII letter so
// a locale-aware comparison (localeCompare) orders them differently from code
// units: "B" (66) < "_" (95) < "a" (97) < "é" (233).
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

/** Delay in ms before each backend answers tools/list, per run. */
type Delays = Record<string, number>;
const STEP = 25;
const delayRuns = (): Delays[] => {
  const n = BACKENDS.length;
  return [
    // Mount order, reverse mount order, and three rotations, so the order
    // backends finish in is different on every run.
    Object.fromEntries(BACKENDS.map((b, i) => [b.uuid, i * STEP])),
    Object.fromEntries(BACKENDS.map((b, i) => [b.uuid, (n - 1 - i) * STEP])),
    Object.fromEntries(BACKENDS.map((b, i) => [b.uuid, ((i + 2) % n) * STEP])),
    Object.fromEntries(BACKENDS.map((b, i) => [b.uuid, ((i + 4) % n) * STEP])),
    Object.fromEntries(BACKENDS.map((b, i) => [b.uuid, ((i * 5) % n) * STEP])),
  ];
};

const toolOf = (name: string): Tool => ({
  name,
  description: `${name} description`,
  inputSchema: { type: "object", properties: {} },
});

let delays: Delays = {};

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
    server.setRequestHandler(CallToolRequestSchema, async (request) => ({
      content: [{ type: "text", text: `ran ${request.params.name}` }],
    }));
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

async function consumer(): Promise<Client> {
  const { server } = await createServer("ns-1", "sess-1");
  const [consumerSide, gatewaySide] = InMemoryTransport.createLinkedPair();
  await server.connect(gatewaySide);
  const made = new Client({ name: "consumer", version: "1.0.0" });
  await made.connect(consumerSide);
  cleanups.push(() => made.close());
  return made;
}

const rawList = async (c: Client) =>
  (await c.request({ method: "tools/list", params: {} }, ListToolsResultSchema))
    .tools;

const allNames = BACKENDS.flatMap((b) => b.tools.map((t) => `${b.name}__${t}`));
// The language's own default sort: UTF-16 code units, no comparator.
const oracleOrder = [...allNames].sort();

beforeEach(() => {
  toolsSyncCache.clear();
  getSessionMock.mockReset();
  auditInputs.current = [];
  vi.spyOn(metamcpLogStore, "record").mockImplementation(() => {});
});

afterEach(async () => {
  vi.restoreAllMocks();
  while (cleanups.length > 0) {
    await cleanups
      .pop()?.()
      .catch(() => undefined);
  }
});

describe("the client-facing tools/list", () => {
  it("lists every tool in byte-wise name order, whichever backend answers first", async () => {
    await mountBackends();
    const c = await consumer();

    const bodies: string[] = [];
    for (const run of delayRuns()) {
      delays = run;
      const tools = await rawList(c);
      expect(tools.map((t) => t.name)).toEqual(oracleOrder);
      bodies.push(JSON.stringify(tools));
    }

    // One set of bytes across all five completion orders.
    expect(new Set(bodies).size).toBe(1);
    // Pinned by literal, so the oracle itself cannot drift: a locale-aware
    // comparison would put "alpha__a" before "alpha__B".
    expect(oracleOrder.slice(0, EXPECTED_FIRST.length)).toEqual(EXPECTED_FIRST);
  });

  it("lists nothing twice and nothing fewer than the backends serve", async () => {
    await mountBackends();
    delays = delayRuns()[1];

    const names = (await rawList(await consumer())).map((t) => t.name);

    expect(names).toHaveLength(allNames.length);
    expect(new Set(names)).toEqual(new Set(allNames));
  });
});

describe("the audit listing", () => {
  it("hands unambiguousAuditTools the listing in byte-wise name order", async () => {
    await mountBackends();
    const runs = delayRuns().slice(0, 2);

    for (const run of runs) {
      delays = run;
      // A fresh proxy per run: an audit listing starts at most once a minute
      // per routing instance. A call with arguments that was never preceded
      // by a listing has no recorded schema to shape them by, so the gateway
      // lists for its own audit (auditing.functional.ts, deferShape).
      const c = await consumer();
      auditInputs.current = [];
      await c.request(
        {
          method: "tools/call",
          params: { name: "mu__list", arguments: { query: "x" } },
        },
        CallToolResultSchema,
      );
      await vi.waitFor(() =>
        expect(auditInputs.current.length).toBeGreaterThan(0),
      );
      expect(auditInputs.current.at(-1)).toEqual(oracleOrder);
    }
  });
});
