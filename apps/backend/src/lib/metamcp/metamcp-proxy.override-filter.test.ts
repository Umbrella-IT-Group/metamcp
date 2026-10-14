/**
 * The tool-status filter judges the tool a call will actually run, including a
 * call made by the tool's override name, driven end to end through
 * `createServer`.
 *
 * A real SDK consumer `Client` talks to the gateway's own `Server`; the
 * backend is an SDK `Server` over `InMemoryTransport` that counts what it ran.
 * The filter and the override middleware are the REAL ones, composed in the
 * order `createServer` composes them, and both read one in-memory stand-in for
 * their tables (see metamcp-middleware/tool-mapping-db.fixtures).
 *
 * The defect this pins: the call filter used to run OUTSIDE the override
 * middleware, so a call by an alias reached the filter as the alias, found no
 * mapping row for it, was allowed, and was then routed to the original tool.
 * A tool curated INACTIVE in a namespace stayed callable by its alias.
 *
 * What it pins:
 *   - an INACTIVE tool called by its alias is refused exactly as by its real
 *     name, and the backend runs nothing;
 *   - an ACTIVE tool runs by its alias and by its real name;
 *   - a name that is not an override gets the same answer as before, and the
 *     filter judges the very name the caller sent;
 *   - tools/list is unchanged.
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  CallToolRequestSchema,
  CallToolResultSchema,
  ListToolsRequestSchema,
  ListToolsResultSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { ConnectedClient } from "./client";
import type {
  FakeQuery,
  FakeToolMappingState,
} from "./metamcp-middleware/tool-mapping-db.fixtures";

const { state, queries, getSessionMock } = vi.hoisted(() => ({
  state: { servers: [], mappings: [] } as FakeToolMappingState,
  queries: [] as FakeQuery[],
  getSessionMock: vi.fn(),
}));

vi.mock("@/utils/logger", () => ({
  default: { error: vi.fn(), warn: vi.fn(), info: vi.fn(), debug: vi.fn() },
}));

vi.mock("drizzle-orm", async (importOriginal) => ({
  ...(await importOriginal<typeof import("drizzle-orm")>()),
  ...(await import("./metamcp-middleware/tool-mapping-db.fixtures"))
    .drizzleConditionStubs,
}));
vi.mock(
  "../../db/schema",
  async () =>
    (await import("./metamcp-middleware/tool-mapping-db.fixtures"))
      .toolMappingSchemaStub,
);
vi.mock("../../db", async () => ({
  db: (
    await import("./metamcp-middleware/tool-mapping-db.fixtures")
  ).createToolMappingDb(state, queries),
}));
vi.mock("../../db/repositories/namespaces.repo", () => ({
  namespacesRepository: { findServersForNamespaceToolName: async () => [] },
}));
vi.mock("../../db/repositories/oauth-sessions.repo", () => ({
  oauthSessionsRepository: {},
}));
vi.mock("../../trpc/tools.impl", () => ({
  toolsImplementations: { sync: vi.fn().mockResolvedValue(undefined) },
}));

vi.mock("../config.service", () => ({
  configService: {
    getMcpResetTimeoutOnProgress: async () => false,
    getMcpTimeout: async () => 5_000,
    getMcpMaxTotalTimeout: async () => 60_000,
    getMcpToolCallReconnectWarmupTimeout: async () => 0,
  },
}));

vi.mock("./fetch-metamcp", () => ({
  getMcpServers: vi.fn(async () => ({ "server-ninja": { name: "ninja" } })),
}));

vi.mock("./mcp-server-pool", () => ({
  mcpServerPool: {
    getSession: getSessionMock,
    invalidateServerConnection: vi.fn(),
    cleanupSession: vi.fn(),
    // tools/list only: a warm pool, so it does not try to warm one up.
    getPoolStatus: () => ({ idle: 1, active: 1 }),
  },
}));
vi.mock("./cold-connect-broker-fallback", () => ({
  resolveColdConnectBrokerFallback: () => undefined,
}));
vi.mock("./tool-call-warmup", () => ({
  acquireSessionWithBoundedWarmup: vi.fn(async () => undefined),
}));

import { setAuditRecorderForTesting } from "./metamcp-middleware/auditing.functional";
import { clearFilterCache } from "./metamcp-middleware/filter-tools.functional";
import { clearOverrideCache } from "./metamcp-middleware/tool-overrides.functional";
import { createServer } from "./metamcp-proxy";

const NS = "ns-1";
const SERVER = { uuid: "server-ninja", name: "ninja" };

/**
 * The namespace's curation. Two tools carry an override name (one ACTIVE, one
 * INACTIVE), two do not (one ACTIVE, one INACTIVE), and one has no mapping row
 * at all (active by default).
 */
const CURATION: FakeToolMappingState = {
  servers: [SERVER],
  mappings: [
    {
      namespaceUuid: NS,
      serverUuid: SERVER.uuid,
      toolName: "list_things",
      status: "ACTIVE",
      overrideName: "things",
    },
    {
      namespaceUuid: NS,
      serverUuid: SERVER.uuid,
      toolName: "delete_things",
      status: "INACTIVE",
      overrideName: "purge",
    },
    {
      namespaceUuid: NS,
      serverUuid: SERVER.uuid,
      toolName: "plain_read",
      status: "ACTIVE",
    },
    {
      namespaceUuid: NS,
      serverUuid: SERVER.uuid,
      toolName: "plain_write",
      status: "INACTIVE",
    },
  ],
};

const BACKEND_TOOLS = [
  "list_things",
  "delete_things",
  "plain_read",
  "plain_write",
  "unmapped",
];

const INACTIVE = "Tool has been marked as inactive in this namespace";

const cleanups: Array<() => Promise<unknown>> = [];

/** The backend's tools/call log: every name it was asked to run. */
let ran: string[];

async function backend(): Promise<ConnectedClient> {
  const server = new Server(
    { name: "ninja", version: "1.0.0" },
    { capabilities: { tools: {} } },
  );
  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: BACKEND_TOOLS.map((name) => ({
      name,
      inputSchema: { type: "object" as const },
    })),
  }));
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    ran.push(request.params.name);
    return { content: [{ type: "text", text: `ran ${request.params.name}` }] };
  });
  const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
  await server.connect(serverSide);
  const client = new Client({ name: "metamcp", version: "1.0.0" });
  await client.connect(clientSide);
  cleanups.push(() => client.close());
  return {
    client,
    cleanup: () => client.close(),
    listChangedSubscribers: new Set(),
  } as unknown as ConnectedClient;
}

async function connectConsumer(): Promise<Client> {
  const { server } = await createServer(NS, "sess-1");
  const [consumerSide, gatewaySide] = InMemoryTransport.createLinkedPair();
  await server.connect(gatewaySide);
  const consumer = new Client({ name: "consumer", version: "1.0.0" });
  await consumer.connect(consumerSide);
  cleanups.push(() => consumer.close());
  return consumer;
}

const call = (consumer: Client, name: string) =>
  consumer.request(
    { method: "tools/call", params: { name, arguments: {} } },
    CallToolResultSchema,
    { timeout: 10_000 },
  );

const textOf = (result: { content: Array<{ type: string; text?: string }> }) =>
  result.content[0]?.text;

/** The tool names the filter asked the status of, in order. */
const statusLookups = () =>
  queries
    .filter((q) => q.table === "mappings" && "ntm.namespace_uuid" in q.where)
    .filter((q) => "tools.name" in q.where)
    .map((q) => q.where["tools.name"]);

beforeEach(async () => {
  clearFilterCache();
  clearOverrideCache();
  state.servers = CURATION.servers;
  state.mappings = CURATION.mappings;
  queries.length = 0;
  ran = [];
  setAuditRecorderForTesting(null);
  getSessionMock.mockReset();
  getSessionMock.mockResolvedValue(await backend());
});

afterEach(async () => {
  setAuditRecorderForTesting(undefined);
  clearFilterCache();
  clearOverrideCache();
  while (cleanups.length > 0) {
    await cleanups
      .pop()?.()
      .catch(() => undefined);
  }
});

describe("tools/call by override name: judged as the tool it runs", () => {
  it("refuses an INACTIVE tool called by its alias, exactly as by its real name", async () => {
    const consumer = await connectConsumer();

    const byAlias = await call(consumer, "ninja__purge");
    const byName = await call(consumer, "ninja__delete_things");

    expect(byAlias.isError).toBe(true);
    expect(textOf(byAlias)).toBe(
      `Access denied to tool "ninja__delete_things": ${INACTIVE}`,
    );
    expect(byAlias.content).toEqual(byName.content);
    // Neither call reached the backend.
    expect(ran).toEqual([]);
  });

  it("asks the status of the ORIGINAL tool, never of the alias", async () => {
    await call(await connectConsumer(), "ninja__purge");

    expect(statusLookups()).toEqual(["delete_things"]);
  });

  it("runs an ACTIVE tool called by its alias", async () => {
    const result = await call(await connectConsumer(), "ninja__things");

    expect(result.isError).toBeFalsy();
    expect(textOf(result)).toBe("ran list_things");
    expect(ran).toEqual(["list_things"]);
  });

  it("runs an ACTIVE overridden tool called by its real name", async () => {
    const result = await call(await connectConsumer(), "ninja__list_things");

    expect(result.isError).toBeFalsy();
    expect(textOf(result)).toBe("ran list_things");
    expect(ran).toEqual(["list_things"]);
  });
});

describe("tools/call by a name that is not an override: unchanged", () => {
  it("runs an ACTIVE tool, and the filter judged the name as sent", async () => {
    const result = await call(await connectConsumer(), "ninja__plain_read");

    expect(textOf(result)).toBe("ran plain_read");
    expect(ran).toEqual(["plain_read"]);
    expect(statusLookups()).toEqual(["plain_read"]);
  });

  it("refuses an INACTIVE tool with the same text as before", async () => {
    const result = await call(await connectConsumer(), "ninja__plain_write");

    expect(result.isError).toBe(true);
    expect(textOf(result)).toBe(
      `Access denied to tool "ninja__plain_write": ${INACTIVE}`,
    );
    expect(ran).toEqual([]);
  });

  it("runs a tool with no mapping row (active by default)", async () => {
    const result = await call(await connectConsumer(), "ninja__unmapped");

    expect(textOf(result)).toBe("ran unmapped");
    expect(ran).toEqual(["unmapped"]);
  });

  it("refuses a server prefix that does not resolve (fail closed)", async () => {
    const result = await call(await connectConsumer(), "gone__lookup");

    expect(result.isError).toBe(true);
    expect(textOf(result)).toBe(
      'Access denied to tool "gone__lookup": server could not be resolved',
    );
    expect(ran).toEqual([]);
  });
});

describe("tools/list: unchanged", () => {
  it("lists ACTIVE tools under their override names and omits INACTIVE ones", async () => {
    const consumer = await connectConsumer();

    const { tools } = await consumer.request(
      { method: "tools/list", params: {} },
      ListToolsResultSchema,
    );

    expect(tools.map((tool) => tool.name).sort()).toEqual([
      "ninja__plain_read",
      "ninja__things",
      "ninja__unmapped",
    ]);
  });
});
