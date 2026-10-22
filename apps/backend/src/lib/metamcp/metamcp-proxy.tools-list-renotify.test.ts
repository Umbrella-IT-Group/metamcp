/**
 * A backend restart must not leave a long-lived session without that
 * backend's tools. Driven end to end through `createServer` with a real
 * consumer `Client` on an in-memory transport; the pool is mocked.
 *
 * The defect: the pool's drop detectors send `notifications/tools/list_changed`
 * while the restarting backend is still down; a client that re-lists at once
 * got a SUCCESSFUL listing without that server (for a one-server namespace,
 * `{tools: []}`), replaced its tool set with it, and was never told again once
 * the backend came back: no subscriber was attached for a server the listing
 * could not reach. A one-server namespace stayed empty for that session until
 * it reconnected.
 *
 * What it pins:
 *   - no tools at all while a server failed is an error carrying
 *     `data.code: "backend_unavailable"`, never an empty list;
 *   - a session whose listing left a server out gets `list_changed` once that
 *     server answers the probe, and its next listing has the tools back;
 *   - a partial listing (another server answered) is still returned, and is
 *     owed the same re-notify;
 *   - a listing that reaches the server first cancels the owed re-notify;
 *   - closing the session stops it; the kill switch disables it;
 *   - a server re-notified and then failing again waits longer next time;
 *   - a server excluded for a misconfigured name is neither an error nor
 *     probed: no retry fixes it.
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  ListToolsRequestSchema,
  ListToolsResultSchema,
  McpError,
  Tool,
  ToolListChangedNotificationSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { ConnectedClient } from "./client";

const { getSessionMock, probeMock, getMcpServersMock } = vi.hoisted(() => ({
  getSessionMock: vi.fn(),
  probeMock: vi.fn(),
  getMcpServersMock: vi.fn(),
}));

vi.mock("@/utils/logger", () => ({
  default: { error: vi.fn(), warn: vi.fn(), info: vi.fn(), debug: vi.fn() },
}));

vi.mock("../../db", () => ({ db: {} }));
vi.mock("../../db/schema", () => ({}));
vi.mock("../../db/repositories/namespaces.repo", () => ({
  namespacesRepository: { findServersForNamespaceToolName: vi.fn() },
}));
vi.mock("../../db/repositories/oauth-sessions.repo", () => ({
  oauthSessionsRepository: {},
}));
vi.mock("../../db/repositories", () => ({
  toolsRepository: {
    syncTools: vi.fn(async () => ({ upserted: [], deleted: [] })),
  },
  mcpServersRepository: {},
}));
vi.mock("../audit/admin-event", () => ({ emitAdminEvent: vi.fn() }));

vi.mock("../config.service", () => ({
  configService: {
    getMcpResetTimeoutOnProgress: async () => false,
    getMcpTimeout: async () => 5_000,
    getMcpMaxTotalTimeout: async () => 60_000,
    getMcpToolCallReconnectWarmupTimeout: async () => 0,
  },
}));

vi.mock("./fetch-metamcp", () => ({ getMcpServers: getMcpServersMock }));

vi.mock("./mcp-server-pool", () => ({
  mcpServerPool: {
    getSession: getSessionMock,
    probeServerTools: probeMock,
    invalidateServerConnection: vi.fn(),
    cleanupSession: vi.fn(),
    // A warm pool, so tools/list does not try to warm one up.
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
  mapOverrideNameToOriginal: async (name: string) => name,
}));
vi.mock("./cold-connect-broker-fallback", () => ({
  resolveColdConnectBrokerFallback: () => undefined,
}));
vi.mock("./tool-call-warmup", () => ({
  acquireSessionWithBoundedWarmup: vi.fn(async () => undefined),
}));

// The real watch, with short delays so the cases run on real timers (the
// SDK's own request timers stay real too).
vi.mock("./tools-list-renotify", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./tools-list-renotify")>();
  return {
    ...actual,
    toolsListRenotifyWatch: new actual.ToolsListRenotifyWatch({
      delaysMs: [30, 60, 120],
    }),
  };
});

import { createServer } from "./metamcp-proxy";
import { toolsListRenotifyWatch } from "./tools-list-renotify";
import { toolsSyncCache } from "./tools-sync-cache";

const NINJA = "server-ninja";
const ITGLUE = "server-itglue";

const cleanups: Array<() => Promise<unknown>> = [];

const tool = (name: string): Tool => ({
  name,
  description: `${name} description`,
  inputSchema: { type: "object", properties: {} },
});

async function backend(name: string, tools: Tool[]): Promise<ConnectedClient> {
  const server = new Server(
    { name, version: "1.0.0" },
    { capabilities: { tools: {} } },
  );
  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools }));
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
  listChanged: ReturnType<typeof vi.fn>;
  closeSession: () => Promise<void>;
}

async function connectConsumer(sessionId = "sess-1"): Promise<Consumer> {
  const { server, cleanup } = await createServer("ns-1", sessionId);
  const [consumerSide, gatewaySide] = InMemoryTransport.createLinkedPair();
  await server.connect(gatewaySide);
  const client = new Client({ name: "consumer", version: "1.0.0" });
  const listChanged = vi.fn();
  client.setNotificationHandler(ToolListChangedNotificationSchema, () => {
    listChanged();
  });
  await client.connect(consumerSide);
  cleanups.push(() => client.close());
  cleanups.push(cleanup);
  return { client, listChanged, closeSession: cleanup };
}

const list = (consumer: Consumer) =>
  consumer.client.request(
    { method: "tools/list", params: {} },
    ListToolsResultSchema,
  );

const names = (result: { tools: Tool[] }) =>
  result.tools.map((t) => t.name).sort();

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** getSession answers per server: a session when up, undefined when down. */
function serve(sessions: Record<string, ConnectedClient | undefined>) {
  getSessionMock.mockImplementation(
    async (_sessionId: string, serverUuid: string) => sessions[serverUuid],
  );
}

beforeEach(() => {
  toolsSyncCache.clear();
  getSessionMock.mockReset();
  probeMock.mockReset();
  getMcpServersMock.mockReset();
  getMcpServersMock.mockResolvedValue({
    [NINJA]: { uuid: NINJA, name: "ninja" },
  });
  delete process.env.MCP_TOOLS_LIST_RENOTIFY;
});

afterEach(async () => {
  while (cleanups.length > 0) {
    await cleanups
      .pop()?.()
      .catch(() => undefined);
  }
  delete process.env.MCP_TOOLS_LIST_RENOTIFY;
  vi.restoreAllMocks();
});

describe("tools/list across a backend restart", () => {
  it("answers an error, not an empty list, when the only server is down, then re-notifies once it answers", async () => {
    const consumer = await connectConsumer();
    serve({ [NINJA]: undefined });
    probeMock.mockResolvedValue(false);

    const failure = await list(consumer).then(
      () => undefined,
      (error: unknown) => error,
    );
    expect(failure).toBeInstanceOf(McpError);
    expect((failure as McpError).code).toBe(-32603);
    expect((failure as McpError).data).toEqual({
      code: "backend_unavailable",
      servers: ["ninja"],
      retryable: true,
    });
    expect((failure as McpError).message).toContain(
      "not the same as an empty tool list",
    );
    expect((failure as McpError).message).toContain(
      "notifications/tools/list_changed when the server answers again",
    );

    // Still down: probed, nobody told.
    await vi.waitFor(() => expect(probeMock).toHaveBeenCalled());
    expect(consumer.listChanged).not.toHaveBeenCalled();
    expect(probeMock.mock.calls[0][0]).toMatchObject({ uuid: NINJA });
    expect(probeMock.mock.calls[0][1]).toBe("ns-1");

    // The backend is back.
    serve({ [NINJA]: await backend("ninja", [tool("device_search")]) });
    probeMock.mockResolvedValue(true);
    await vi.waitFor(() => expect(consumer.listChanged).toHaveBeenCalled());
    expect(consumer.listChanged).toHaveBeenCalledTimes(1);
    expect(names(await list(consumer))).toEqual(["ninja__device_search"]);

    // Told exactly once: nothing is owed after a good listing.
    await sleep(200);
    expect(consumer.listChanged).toHaveBeenCalledTimes(1);
    expect(toolsListRenotifyWatch.watchedServerCount()).toBe(0);
  });

  it("returns a partial listing when another server answered, and still re-notifies", async () => {
    getMcpServersMock.mockResolvedValue({
      [NINJA]: { uuid: NINJA, name: "ninja" },
      [ITGLUE]: { uuid: ITGLUE, name: "itglue" },
    });
    const itglue = await backend("itglue", [tool("search")]);
    serve({ [NINJA]: undefined, [ITGLUE]: itglue });
    probeMock.mockResolvedValue(false);
    const consumer = await connectConsumer();

    expect(names(await list(consumer))).toEqual(["itglue__search"]);

    serve({
      [NINJA]: await backend("ninja", [tool("device_search")]),
      [ITGLUE]: itglue,
    });
    probeMock.mockResolvedValue(true);
    await vi.waitFor(() => expect(consumer.listChanged).toHaveBeenCalled());
    expect(names(await list(consumer))).toEqual([
      "itglue__search",
      "ninja__device_search",
    ]);
    // Only the server that was left out was probed.
    expect(
      probeMock.mock.calls.every(([params]) => params.uuid === NINJA),
    ).toBe(true);
  });

  it("cancels the owed re-notify when a later listing reaches the server first", async () => {
    probeMock.mockResolvedValue(true);
    const consumer = await connectConsumer();
    serve({ [NINJA]: undefined });
    await expect(list(consumer)).rejects.toBeInstanceOf(McpError);

    // The consumer lists again before the first probe (30 ms) and the
    // server answers this time.
    serve({ [NINJA]: await backend("ninja", [tool("device_search")]) });
    expect(names(await list(consumer))).toEqual(["ninja__device_search"]);

    await sleep(200);
    expect(probeMock).not.toHaveBeenCalled();
    expect(consumer.listChanged).not.toHaveBeenCalled();
    expect(toolsListRenotifyWatch.watchedServerCount()).toBe(0);
  });

  it("stops watching when the session closes", async () => {
    probeMock.mockResolvedValue(false);
    const consumer = await connectConsumer();
    serve({ [NINJA]: undefined });
    await expect(list(consumer)).rejects.toBeInstanceOf(McpError);
    expect(toolsListRenotifyWatch.watchedServerCount()).toBe(1);

    await consumer.closeSession();
    expect(toolsListRenotifyWatch.watchedServerCount()).toBe(0);
    await sleep(200);
    expect(probeMock).not.toHaveBeenCalled();
  });

  it("arms nothing when MCP_TOOLS_LIST_RENOTIFY=false, and does not promise a notification", async () => {
    process.env.MCP_TOOLS_LIST_RENOTIFY = "false";
    probeMock.mockResolvedValue(true);
    const consumer = await connectConsumer();
    serve({ [NINJA]: undefined });

    const failure = (await list(consumer).catch((e: unknown) => e)) as McpError;
    expect(failure).toBeInstanceOf(McpError);
    expect(failure.data).toMatchObject({ retryable: true });
    expect(failure.message).not.toContain("list_changed");
    expect(toolsListRenotifyWatch.watchedServerCount()).toBe(0);
    await sleep(200);
    expect(probeMock).not.toHaveBeenCalled();
    expect(consumer.listChanged).not.toHaveBeenCalled();
  });

  it("waits longer for a server that was re-notified and failed the re-list again", async () => {
    const watchSpy = vi.spyOn(toolsListRenotifyWatch, "watch");
    const consumer = await connectConsumer();
    serve({ [NINJA]: undefined });
    probeMock.mockResolvedValue(true);

    await expect(list(consumer)).rejects.toBeInstanceOf(McpError);
    await vi.waitFor(() => expect(consumer.listChanged).toHaveBeenCalled());
    // The re-list fails again (the backend flapped).
    await expect(list(consumer)).rejects.toBeInstanceOf(McpError);

    expect(watchSpy).toHaveBeenCalledTimes(2);
    expect(watchSpy.mock.calls[0][3]).toBe(0);
    expect(watchSpy.mock.calls[1][3]).toBe(1);
  });

  it("lists the rest when a server is excluded for a misconfigured name, and never probes it", async () => {
    // No retry fixes a stored name containing the tool-name separator, so it
    // is neither an error nor owed a re-notify; it stays in the DEGRADED log.
    getMcpServersMock.mockResolvedValue({
      [NINJA]: { uuid: NINJA, name: "bad__name" },
      [ITGLUE]: { uuid: ITGLUE, name: "itglue" },
    });
    serve({
      [NINJA]: await backend("bad", [tool("device_search")]),
      [ITGLUE]: await backend("itglue", []),
    });
    probeMock.mockResolvedValue(true);
    const consumer = await connectConsumer();

    expect((await list(consumer)).tools).toEqual([]);
    await sleep(100);
    expect(probeMock).not.toHaveBeenCalled();
    expect(toolsListRenotifyWatch.watchedServerCount()).toBe(0);
  });

  it("answers an error naming only the unreachable server when another is misconfigured", async () => {
    getMcpServersMock.mockResolvedValue({
      [NINJA]: { uuid: NINJA, name: "ninja" },
      [ITGLUE]: { uuid: ITGLUE, name: "bad__name" },
    });
    serve({
      [NINJA]: undefined,
      [ITGLUE]: await backend("bad", [tool("search")]),
    });
    probeMock.mockResolvedValue(false);
    const consumer = await connectConsumer();

    const failure = (await list(consumer).catch((e: unknown) => e)) as McpError;
    expect(failure).toBeInstanceOf(McpError);
    expect(failure.data).toEqual({
      code: "backend_unavailable",
      servers: ["ninja"],
      retryable: true,
    });
  });

  it("still answers an empty list for a namespace with no servers", async () => {
    getMcpServersMock.mockResolvedValue({});
    const consumer = await connectConsumer();
    expect((await list(consumer)).tools).toEqual([]);
  });
});
