/**
 * The live-session half of a mount status change (namespace-mount-events.ts):
 * the admin write tells every live session of the namespace to drop its
 * routes to the server and re-list, and retires no pooled backend client.
 * Enforcement itself is pinned in metamcp-proxy.mount-status.test.ts.
 *
 * Background, shared with that file: a namespace mount switched to INACTIVE
 * stops serving at once, in every session, including one that already listed
 * the server's tools and holds a cached route to it.
 *
 * The call path reuses a session's cached route (`toolToClient`) and only
 * reads the routable servers (`getMcpServers`, ACTIVE mounts) when it has no
 * route, so the mount status has to be part of the filter verdict every call
 * passes (namespace-server-lookup.ts). The admin write also tells live
 * sessions to drop their routes and re-list (namespace-mount-events.ts),
 * without retiring the pooled backend client, which another namespace may
 * still use.
 *
 * Harness: the real `createServer`, the real filter and override middleware
 * over the evaluating in-memory table stand-in, a real SDK consumer and
 * in-memory SDK backends that record what they ran. The namespace server
 * reads (`getMcpServers`, `getNamespaceListingServers`,
 * `getNamespaceServerStates`) answer from the same mount rows, the way their
 * real queries do (ACTIVE unless inactive mounts are included).
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  CallToolRequestSchema,
  CallToolResultSchema,
  ListToolsRequestSchema,
  ListToolsResultSchema,
  ToolListChangedNotificationSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { ConnectedClient } from "./client";
import type {
  FakeQuery,
  FakeToolMappingState,
} from "./metamcp-middleware/tool-mapping-db.fixtures";

const { state, queries, getSessionMock, findServersMock, warmupMock, pool } =
  vi.hoisted(() => ({
    state: {
      servers: [],
      mappings: [],
      mounts: [],
      namespaces: [],
    } as FakeToolMappingState,
    queries: [] as FakeQuery[],
    getSessionMock: vi.fn(),
    findServersMock: vi.fn(),
    warmupMock: vi.fn(),
    pool: {
      invalidateServerConnection: vi.fn(),
      cleanupSession: vi.fn(),
      isPooledClient: vi.fn(),
    },
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
  namespacesRepository: { findServersForNamespaceToolName: findServersMock },
}));
vi.mock("../../db/repositories/oauth-sessions.repo", () => ({
  oauthSessionsRepository: {},
}));
vi.mock("../../trpc/tools.impl", () => ({
  toolsImplementations: {
    sync: vi.fn().mockResolvedValue(undefined),
    syncFromListing: vi.fn().mockResolvedValue(undefined),
  },
}));

vi.mock("../config.service", () => ({
  configService: {
    getMcpResetTimeoutOnProgress: async () => false,
    getMcpTimeout: async () => 5_000,
    getMcpMaxTotalTimeout: async () => 60_000,
    getMcpToolCallReconnectWarmupTimeout: async () => 0,
  },
}));

vi.mock("./fetch-metamcp", () => {
  const mountedHere = (namespaceUuid: string, includeInactive: boolean) =>
    state.mounts.filter(
      (mount) =>
        mount.namespaceUuid === namespaceUuid &&
        (includeInactive || (mount.status ?? "ACTIVE") === "ACTIVE"),
    );
  const paramsFor = (serverUuid: string) => {
    const server = state.servers.find((s) => s.uuid === serverUuid);
    return { uuid: serverUuid, name: server?.name ?? "", type: "STDIO" };
  };
  const getMcpServers = vi.fn(
    async (namespaceUuid: string, includeInactive = false) =>
      Object.fromEntries(
        mountedHere(namespaceUuid, includeInactive).map((mount) => [
          mount.serverUuid,
          paramsFor(mount.serverUuid),
        ]),
      ),
  );
  return {
    getMcpServers,
    getNamespaceListingServers: vi.fn(
      async (namespaceUuid: string, includeInactive = false) => ({
        routable: await getMcpServers(namespaceUuid, includeInactive),
        errorGated: {},
      }),
    ),
    getNamespaceServerStates: vi.fn(async (namespaceUuid: string) =>
      state.mounts
        .filter((mount) => mount.namespaceUuid === namespaceUuid)
        .map((mount) => ({
          uuid: mount.serverUuid,
          name: paramsFor(mount.serverUuid).name,
          mountStatus: mount.status ?? "ACTIVE",
          errorStatus: "NONE",
        })),
    ),
  };
});

vi.mock("./mcp-server-pool", () => ({
  mcpServerPool: {
    getSession: getSessionMock,
    invalidateServerConnection: pool.invalidateServerConnection,
    cleanupSession: pool.cleanupSession,
    isPooledClient: pool.isPooledClient,
    // tools/list only: a warm pool, so it does not try to warm one up.
    getPoolStatus: () => ({ idle: 1, active: 1 }),
  },
}));
vi.mock("./cold-connect-broker-fallback", () => ({
  resolveColdConnectBrokerFallback: () => undefined,
}));
vi.mock("./tool-call-warmup", () => ({
  acquireSessionWithBoundedWarmup: warmupMock,
}));

import { setAuditRecorderForTesting } from "./metamcp-middleware/auditing.functional";
import { clearFilterCache } from "./metamcp-middleware/filter-tools.functional";
import { clearOverrideCache } from "./metamcp-middleware/tool-overrides.functional";
import { createServer } from "./metamcp-proxy";
import {
  namespaceMountListenerCount,
  notifyNamespaceMountChange,
} from "./namespace-mount-events";

const NS = "ns-mount";
const OTHER_NS = "ns-other";
const WRITER = { uuid: "server-writer", name: "writer" };

const cleanups: Array<() => Promise<unknown>> = [];
/** What each backend ran, as `<backend label>:<tool>`. */
let ran: string[];
/** One backend client per server uuid, shared by every session (pooled). */
let backends: Record<string, ConnectedClient>;

async function backend(label: string): Promise<ConnectedClient> {
  const server = new Server(
    { name: label, version: "1.0.0" },
    { capabilities: { tools: {} } },
  );
  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [{ name: "write", inputSchema: { type: "object" as const } }],
  }));
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    ran.push(`${label}:${request.params.name}`);
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

interface Consumer {
  client: Client;
  listChanged: () => number;
}

async function connectConsumer(
  sessionId: string,
  namespaceUuid: string = NS,
): Promise<Consumer> {
  const { server, cleanup } = await createServer(namespaceUuid, sessionId);
  const [consumerSide, gatewaySide] = InMemoryTransport.createLinkedPair();
  await server.connect(gatewaySide);
  const consumer = new Client({ name: "consumer", version: "1.0.0" });
  let notifications = 0;
  consumer.setNotificationHandler(ToolListChangedNotificationSchema, () => {
    notifications += 1;
  });
  await consumer.connect(consumerSide);
  cleanups.push(async () => {
    await consumer.close();
    await cleanup();
  });
  return { client: consumer, listChanged: () => notifications };
}

const list = async (consumer: Consumer) =>
  (
    await consumer.client.request(
      { method: "tools/list", params: {} },
      ListToolsResultSchema,
    )
  ).tools.map((tool) => tool.name);

const call = (consumer: Consumer, name: string) =>
  consumer.client.request(
    { method: "tools/call", params: { name, arguments: {} } },
    CallToolResultSchema,
    { timeout: 10_000 },
  );

/**
 * Whether the gateway served the call or refused it. A refusal is either an
 * isError result (the filter's denial) or a rejected request (the routing
 * handler's unknown-tool error); both leave the backend untouched, which each
 * test checks separately through `ran`.
 */
const outcome = (consumer: Consumer, name: string) =>
  call(consumer, name).then(
    (result) => (result.isError ? "refused" : "served"),
    () => "refused",
  );

/** Set the mount status of `serverUuid` in `namespaceUuid`, as the admin write does. */
const setMount = (
  namespaceUuid: string,
  serverUuid: string,
  status: "ACTIVE" | "INACTIVE",
) => {
  for (const mount of state.mounts) {
    if (
      mount.namespaceUuid === namespaceUuid &&
      mount.serverUuid === serverUuid
    )
      mount.status = status;
  }
};

/** Let queued notifications reach the consumer. */
const settle = () => new Promise((resolve) => setTimeout(resolve, 20));

beforeEach(async () => {
  clearFilterCache();
  clearOverrideCache();
  state.servers = [WRITER];
  state.mounts = [
    { namespaceUuid: NS, serverUuid: WRITER.uuid, status: "ACTIVE" },
  ];
  state.namespaces = [
    { uuid: NS, toolPolicy: "allow_all" },
    { uuid: OTHER_NS, toolPolicy: "allow_all" },
  ];
  state.mappings = [];
  state.failOn = undefined;
  queries.length = 0;
  ran = [];
  setAuditRecorderForTesting(null);
  backends = { [WRITER.uuid]: await backend("writer-a") };
  getSessionMock.mockReset();
  getSessionMock.mockImplementation(
    async (_sessionId: string, serverUuid: string) => backends[serverUuid],
  );
  pool.invalidateServerConnection.mockReset();
  pool.invalidateServerConnection.mockResolvedValue(undefined);
  pool.cleanupSession.mockReset();
  pool.cleanupSession.mockResolvedValue(undefined);
  pool.isPooledClient.mockReset();
  pool.isPooledClient.mockReturnValue(true);
  findServersMock.mockReset();
  findServersMock.mockResolvedValue([]);
  warmupMock.mockReset();
  warmupMock.mockResolvedValue(undefined);
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

describe("the admin write tells live sessions to drop their routes and re-list", () => {
  it("each live session of the namespace gets one list_changed and keeps no route to the server", async () => {
    const first = await connectConsumer("session-1");
    const second = await connectConsumer("session-2");
    await list(first);
    await list(second);
    expect(namespaceMountListenerCount(NS)).toBe(2);

    setMount(NS, WRITER.uuid, "INACTIVE");
    expect(notifyNamespaceMountChange(NS, WRITER.uuid)).toBe(2);
    await settle();

    expect(first.listChanged()).toBe(1);
    expect(second.listChanged()).toBe(1);
    expect(await list(first)).toEqual([]);
    expect(await outcome(first, "writer__write")).toBe("refused");
    expect(ran).toEqual([]);
  });

  it("the pooled backend client is not retired", async () => {
    const live = await connectConsumer("live-session");
    await list(live);
    setMount(NS, WRITER.uuid, "INACTIVE");
    notifyNamespaceMountChange(NS, WRITER.uuid);
    await settle();

    expect(pool.invalidateServerConnection).not.toHaveBeenCalled();
    expect(pool.cleanupSession).not.toHaveBeenCalled();
    // The same backend client still answers.
    const listed = await backends[WRITER.uuid].client.request(
      { method: "tools/list", params: {} },
      ListToolsResultSchema,
    );
    expect(listed.tools.map((tool) => tool.name)).toEqual(["write"]);
  });

  it("switched back to ACTIVE, the session is told to re-list and gets the tool back", async () => {
    setMount(NS, WRITER.uuid, "INACTIVE");
    const live = await connectConsumer("live-session");
    expect(await list(live)).toEqual([]);

    setMount(NS, WRITER.uuid, "ACTIVE");
    notifyNamespaceMountChange(NS, WRITER.uuid);
    await settle();

    expect(live.listChanged()).toBe(1);
    expect(await list(live)).toEqual(["writer__write"]);
  });

  it("a session in another namespace is not told", async () => {
    state.mounts.push({
      namespaceUuid: OTHER_NS,
      serverUuid: WRITER.uuid,
      status: "ACTIVE",
    });
    const there = await connectConsumer("session-there", OTHER_NS);
    await list(there);
    notifyNamespaceMountChange(NS, WRITER.uuid);
    await settle();
    expect(there.listChanged()).toBe(0);
  });

  it("a closed session stops listening", async () => {
    const live = await connectConsumer("live-session");
    await list(live);
    expect(namespaceMountListenerCount(NS)).toBe(1);
    await live.client.close();
    await settle();
    expect(namespaceMountListenerCount(NS)).toBe(0);
  });

  it("disposing a proxy without a transport stops listening", async () => {
    const { server, cleanup } = await createServer(NS, "idle-session");
    cleanups.push(cleanup);
    expect(server.transport).toBeUndefined();
    expect(namespaceMountListenerCount(NS)).toBe(1);

    // Idle and OpenAPI proxies never connect a transport, so closing one
    // cannot fire onclose. Pool disposal calls cleanup directly instead.
    await server.close();
    await cleanup();
    expect(namespaceMountListenerCount(NS)).toBe(0);
    expect(notifyNamespaceMountChange(NS, WRITER.uuid)).toBe(0);
  });

  it("disposal stops listening even if backend cleanup fails", async () => {
    const { cleanup } = await createServer(NS, "failed-cleanup-session");
    cleanups.push(cleanup);
    pool.cleanupSession.mockRejectedValueOnce(new Error("cleanup failed"));

    await expect(cleanup()).rejects.toThrow("cleanup failed");
    expect(namespaceMountListenerCount(NS)).toBe(0);
  });
});
