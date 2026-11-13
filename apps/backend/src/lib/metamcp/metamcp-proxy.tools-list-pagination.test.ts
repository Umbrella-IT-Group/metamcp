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
import { inspect } from "node:util";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPError } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
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

import logger from "@/utils/logger";

import type { ConnectedClient } from "./client";
import { makeHttpRefusingBackend } from "./tool-call-harness.test-util";

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
import { mcpServerPool } from "./mcp-server-pool";
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
async function pagedBackend(pages: Pages, firstPageKey = "") {
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
    const page = pages[request.params?.cursor ?? firstPageKey];
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
  vi.mocked(mcpServerPool.invalidateServerConnection).mockClear();
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

  it("does not sync a subset when the next page uses an empty cursor", async () => {
    const target = await pagedBackend(
      {
        start: { tools: ["a"], next: "" },
        "": { tools: ["b"] },
      },
      "start",
    );

    expect(await listNames(await consumer())).toEqual(["ninja__a", "ninja__b"]);
    expect(target.requests()).toBe(2);
    expect(syncToolsMock).toHaveBeenCalledTimes(1);
    expect(
      syncToolsMock.mock.calls[0][0].tools.map((t: Tool) => t.name),
    ).toEqual(["a", "b"]);
    expect(truncationEvents()).toHaveLength(0);
  });

  it("serves each tool once, writes no catalog rows and reports once when every page carries an empty cursor", async () => {
    // An opaque cursor can be "", so the loop follows it. A backend that
    // answers every request with the same page and nextCursor "" is asked for
    // that page twice before the repeat guard stops, and the gathered pages
    // hold its tools twice.
    const target = await pagedBackend({
      "": { tools: ["a", "b"], next: "" },
    });
    const warn = vi.mocked(logger.warn);
    warn.mockClear();
    const update = vi.spyOn(toolsSyncCache, "update");

    const names = await listNames(await consumer());

    expect(names).toEqual(["ninja__a", "ninja__b"]);
    expect(target.requests()).toBe(2);
    expect(syncToolsMock).not.toHaveBeenCalled();
    expect(update).not.toHaveBeenCalled();
    expect(truncationEvents()).toHaveLength(1);
    // The repeats were dropped as one listing's duplicates, not through the
    // cross-server collision path (which warns about two servers).
    expect(inspect(warn.mock.calls)).not.toContain("collision");
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
    expect(truncationEvents()).toHaveLength(1);
    expect(truncationEvents()[0].message).toContain("(tool lookup)");
  });

  it("stops after two requests when every page carries an empty cursor, routes a listed name and reports once", async () => {
    const target = await pagedBackend({ "": { tools: ["a", "b"], next: "" } });

    const result = await (
      await consumer()
    ).request(
      { method: "tools/call", params: { name: "ninja__b", arguments: {} } },
      CallToolResultSchema,
    );

    expect(result.content).toEqual([{ type: "text", text: "ran b" }]);
    expect(target.requests()).toBe(2);
    expect(truncationEvents()).toHaveLength(1);
    expect(truncationEvents()[0].message).toContain("(tool lookup)");
  });

  it("answers backend unavailable for a name missing from a listing that repeats an empty cursor", async () => {
    await pagedBackend({ "": { tools: ["a", "b"], next: "" } });

    const error = await callError(await consumer(), "ninja__z");

    expect(error.message).not.toContain("Unknown tool");
    expect(error.message).toContain("tool_lookup_failed");
    expect(truncationEvents()).toHaveLength(1);
  });

  it("still says Unknown tool when a complete listing lacks the name (control)", async () => {
    await pagedBackend({ "": { tools: ["a"] } });

    const error = await callError(await consumer(), "ninja__z");

    expect(error.message).toContain("Unknown tool");
  });
});

describe("refused backend listing logs", () => {
  it.each([
    [401, "list"],
    [403, "list"],
    [401, "lookup"],
    [403, "lookup"],
  ] as const)("keeps the HTTP %s body out of %s logs", async (status, mode) => {
    const body = "private-backend-listing-response";
    const target = await makeHttpRefusingBackend([status], { body });
    cleanups.push(() => target.close());
    getSessionMock.mockResolvedValue(target.session);
    const logs = [logger.error, logger.warn, logger.info, logger.debug].map(
      (fn) => vi.mocked(fn),
    );
    logs.forEach((fn) => fn.mockClear());
    const c = await consumer();

    if (mode === "list") {
      await expect(listNames(c)).rejects.toMatchObject({
        data: { code: "backend_unavailable" },
      });
    } else {
      expect((await callError(c, "ninja__z")).message).toContain(
        "tool_lookup_failed",
      );
    }

    expect(target.requests).toContain("tools/list");
    const messages = inspect(
      logs.flatMap((fn) => fn.mock.calls),
      { depth: null },
    );
    expect(messages).toContain(`HTTP ${status}`);
    expect(messages).not.toContain(body);
    expect(inspect(record.mock.calls, { depth: null })).not.toContain(body);
  });
});

describe("a refusal met while recovering or acquiring a session", () => {
  const body = "private-backend-listing-response";
  const refusal = (status: number) =>
    new StreamableHTTPError(status, `Error POSTing to endpoint: ${body}`);
  const allLogs = () =>
    [logger.error, logger.warn, logger.info, logger.debug].map((fn) =>
      vi.mocked(fn),
    );
  const logged = () =>
    inspect(
      allLogs().flatMap((fn) => fn.mock.calls),
      { depth: null },
    );

  it.each([401, 403] as const)(
    "does not recover a lookup's HTTP %s refusal when its body reads as a lost connection",
    async (status) => {
      const target = await makeHttpRefusingBackend([status], {
        body: `Not connected ${body}`,
      });
      cleanups.push(() => target.close());
      getSessionMock.mockResolvedValue(target.session);
      allLogs().forEach((fn) => fn.mockClear());

      const error = await callError(await consumer(), "ninja__z");

      expect(error.message).toContain("tool_lookup_failed");
      expect(target.requests).toEqual(["tools/list"]);
      expect(getSessionMock).toHaveBeenCalledTimes(1);
      expect(mcpServerPool.invalidateServerConnection).not.toHaveBeenCalled();
      expect(logged()).toContain(`HTTP ${status}`);
      expect(logged()).not.toContain(body);
      expect(logged().toLowerCase()).not.toContain("connection lost");
    },
  );

  it.each([401, 403] as const)(
    "does not recover a listing's HTTP %s refusal when its body quotes session-loss markers",
    async (status) => {
      const target = await makeHttpRefusingBackend([status], {
        body: `HTTP 404 Session not found ${body}`,
      });
      cleanups.push(() => target.close());
      getSessionMock.mockResolvedValue(target.session);
      allLogs().forEach((fn) => fn.mockClear());

      await expect(listNames(await consumer())).rejects.toThrow(
        "tools/list could not reach",
      );

      expect(target.requests).toEqual(["tools/list"]);
      expect(getSessionMock).toHaveBeenCalledTimes(1);
      expect(mcpServerPool.invalidateServerConnection).not.toHaveBeenCalled();
      expect(logged()).toContain(`HTTP ${status}`);
      expect(logged()).not.toContain(body);
      expect(logged().toLowerCase()).not.toContain("connection lost");
    },
  );

  it.each([401, 403] as const)(
    "keeps the HTTP %s body out of the log when re-acquiring the session rejects with it",
    async (status) => {
      // Recover a genuine session loss, then refuse the new handshake.
      const target = await makeHttpRefusingBackend([404]);
      cleanups.push(() => target.close());
      getSessionMock
        .mockResolvedValueOnce(target.session)
        .mockRejectedValue(refusal(status));
      allLogs().forEach((fn) => fn.mockClear());

      const error = await callError(await consumer(), "ninja__z");

      expect(error.message).toContain("no_session");
      expect(target.requests).toEqual(["tools/list"]);
      expect(getSessionMock).toHaveBeenCalledTimes(2);
      expect(mcpServerPool.invalidateServerConnection).toHaveBeenCalledTimes(1);
      expect(logged()).toContain(`HTTP ${status}`);
      expect(logged()).not.toContain(body);
    },
  );

  it.each([401, 403] as const)(
    "keeps the HTTP %s body out of the listing log when acquiring the session rejects with it",
    async (status) => {
      getSessionMock.mockRejectedValue(refusal(status));
      allLogs().forEach((fn) => fn.mockClear());

      await listNames(await consumer()).catch(() => undefined);

      expect(logged()).toContain(`HTTP ${status}`);
      expect(logged()).not.toContain(body);
    },
  );

  it("keeps the diagnostic when acquiring the session rejects with a 502 (negative control)", async () => {
    getSessionMock.mockRejectedValue(refusal(502));
    allLogs().forEach((fn) => fn.mockClear());

    await listNames(await consumer()).catch(() => undefined);

    expect(logged()).toContain(body);
  });
});
