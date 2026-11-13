/**
 * The request-path tools/list pagination guard, driven end to end through
 * `createServer` with the REAL `tools.impl` and `toolsSyncCache` (only the
 * repository write is mocked) and real SDK peers.
 *
 * Oracle: the MCP spec's server/utilities/pagination page (opaque cursors, a
 * missing nextCursor ends the listing) plus three gateway contracts the guard
 * must not break:
 *   - a listing that is only a SUBSET of what the backend serves never writes
 *     the catalog (the sync deletes every unmapped row absent from its input,
 *     tools.repo.ts syncTools);
 *   - a tool lookup that cannot see the whole list answers "backend
 *     unavailable", never "Unknown tool" (tool-call-routing.ts: only an
 *     authoritative miss on a mounted server may say the tool is unknown);
 *   - a normal multi-page listing is unchanged.
 * Each backend carries a tripwire: its listing ends after 200 requests, so a
 * regression fails by assertion instead of hanging a worker.
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  CallToolRequestSchema,
  CallToolResultSchema,
  ListToolsRequestSchema,
  ListToolsResultSchema,
  McpError,
  Tool,
} from "@modelcontextprotocol/sdk/types.js";
import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  type MockInstance,
  vi,
} from "vitest";

import type { ConnectedClient } from "./client";

const { getSessionMock, syncToolsMock } = vi.hoisted(() => ({
  getSessionMock: vi.fn(),
  syncToolsMock: vi.fn(),
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
  toolsRepository: { syncTools: syncToolsMock },
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
  const getMcpServers = vi.fn(async () => ({
    "server-ninja": { name: "ninja" },
  }));
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

import { metamcpLogStore } from "./log-store";
import { createServer } from "./metamcp-proxy";
import { resetToolsListTruncationReportsForTesting } from "./paginate-tools-list";
import { toolsSyncCache } from "./tools-sync-cache";

type Pages = Record<string, { tools: string[]; next?: string }>;

const cleanups: Array<() => Promise<unknown>> = [];
let record: MockInstance<typeof metamcpLogStore.record>;

const tool = (name: string): Tool => ({
  name,
  description: `${name} description`,
  inputSchema: { type: "object", properties: {} },
});

/** A backend that pages `tools/list` by `pages[cursor ?? ""]`. */
async function pagedBackend(pages: Pages) {
  let requests = 0;
  const server = new Server(
    { name: "ninja", version: "1.0.0" },
    { capabilities: { tools: {} } },
  );
  server.setRequestHandler(ListToolsRequestSchema, async (request) => {
    requests += 1;
    // Tripwire: after 200 requests the listing simply ends, so an unguarded
    // loop finishes and fails the assertions instead of hanging the worker.
    if (requests > 200) return { tools: [] };
    const page = pages[request.params?.cursor ?? ""];
    return { tools: page.tools.map(tool), nextCursor: page.next };
  });
  server.setRequestHandler(CallToolRequestSchema, async (request) => ({
    content: [{ type: "text", text: `ran ${request.params.name}` }],
  }));
  const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
  await server.connect(serverSide);
  const client = new Client({ name: "metamcp", version: "1.0.0" });
  await client.connect(clientSide);
  cleanups.push(() => client.close());
  getSessionMock.mockResolvedValue({
    client,
    cleanup: () => client.close(),
    listChangedSubscribers: new Set(),
  } as unknown as ConnectedClient);
  return { requests: () => requests };
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

const listNames = async (c: Client) =>
  (
    await c.request({ method: "tools/list", params: {} }, ListToolsResultSchema)
  ).tools
    .map((t) => t.name)
    .sort();

const callError = async (c: Client, name: string): Promise<McpError> => {
  try {
    await c.request(
      { method: "tools/call", params: { name, arguments: {} } },
      CallToolResultSchema,
    );
  } catch (error) {
    return error as McpError;
  }
  throw new Error("expected the call to reject");
};

const truncationEvents = () =>
  record.mock.calls
    .map(([entry]) => entry as { category: string; message: string })
    .filter((entry) => entry.message.startsWith("Tool listing for server"));

const CYCLE: Pages = {
  "": { tools: ["a"], next: "A" },
  A: { tools: ["b"], next: "B" },
  B: { tools: ["c"], next: "A" },
};

beforeEach(() => {
  toolsSyncCache.clear();
  getSessionMock.mockReset();
  syncToolsMock.mockReset();
  syncToolsMock.mockResolvedValue({ upserted: [], deleted: [] });
  resetToolsListTruncationReportsForTesting();
  record = vi.spyOn(metamcpLogStore, "record").mockImplementation(() => {});
});

afterEach(async () => {
  record.mockRestore();
  vi.restoreAllMocks();
  while (cleanups.length > 0) {
    await cleanups
      .pop()?.()
      .catch(() => undefined);
  }
});

describe("a backend whose cursors cycle", () => {
  it("lists the tools gathered, stops asking, and records a server event", async () => {
    const target = await pagedBackend(CYCLE);

    const names = await listNames(await consumer());

    expect(names).toEqual(["ninja__a", "ninja__b", "ninja__c"]);
    expect(target.requests()).toBeLessThanOrEqual(4);
    const events = truncationEvents();
    expect(events).toHaveLength(1);
    expect(events[0].category).toBe("server");
    expect(events[0].message).toContain("cursor it had already been asked for");
  });

  it("serves no duplicate names when the backend ignores the cursor", async () => {
    await pagedBackend({
      "": { tools: ["a", "b"], next: "same" },
      same: { tools: ["a", "b"], next: "same" },
    });

    expect(await listNames(await consumer())).toEqual(["ninja__a", "ninja__b"]);
  });

  it("never writes the truncated listing to the catalog", async () => {
    await pagedBackend(CYCLE);
    const update = vi.spyOn(toolsSyncCache, "update");

    await listNames(await consumer());

    // The sync deletes every unmapped row the list leaves out; a subset must
    // not reach it, and the sync cache stays untouched.
    expect(syncToolsMock).not.toHaveBeenCalled();
    expect(update).not.toHaveBeenCalled();
  });

  it("still writes a complete multi-page listing (control)", async () => {
    await pagedBackend({
      "": { tools: ["a"], next: "p2" },
      p2: { tools: ["b"] },
    });

    expect(await listNames(await consumer())).toEqual(["ninja__a", "ninja__b"]);

    expect(syncToolsMock).toHaveBeenCalledTimes(1);
    const written = (
      syncToolsMock.mock.calls[0][0] as { tools: Array<{ name: string }> }
    ).tools
      .map((t) => t.name)
      .sort();
    expect(written).toEqual(["a", "b"]);
    expect(truncationEvents()).toHaveLength(0);
  });
});

describe("a tool lookup on a listing it cannot finish", () => {
  it("answers backend unavailable, not Unknown tool, for a name past the cut", async () => {
    const target = await pagedBackend(CYCLE);

    const error = await callError(await consumer(), "ninja__z");

    // The guard stopped the lookup after the cycle, and said so.
    expect(target.requests()).toBeLessThanOrEqual(4);
    expect(truncationEvents()).toHaveLength(1);
    expect(truncationEvents()[0].message).toContain("(tool lookup)");
    expect(error.message).not.toContain("Unknown tool");
    expect(error.message).toContain("tool_lookup_failed");
    expect((error.data as { reason?: string }).reason).toBe(
      "tool_lookup_failed",
    );
  });

  it("routes a name inside the gathered pages normally", async () => {
    await pagedBackend(CYCLE);

    const result = await (
      await consumer()
    ).request(
      { method: "tools/call", params: { name: "ninja__b", arguments: {} } },
      CallToolResultSchema,
    );

    expect(result.content).toEqual([{ type: "text", text: "ran b" }]);
  });

  it("still says Unknown tool when a complete listing lacks the name (control)", async () => {
    await pagedBackend({ "": { tools: ["a"] } });

    const error = await callError(await consumer(), "ninja__z");

    expect(error.message).toContain("Unknown tool");
  });
});
