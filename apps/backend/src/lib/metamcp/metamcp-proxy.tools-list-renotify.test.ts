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
 *     probed: no retry fixes it;
 *   - an error-gated mounted server is unreachable, not absent: never
 *     connected to, part of the error, owed a re-notify that waits for its
 *     gate to be reset, and its watch kept across listings;
 *   - a failed read of the namespace's servers is a retryable error, never an
 *     empty list, and cancels nothing the session is owed.
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

const { getSessionMock, probeMock, listingMock, serverStateMock } = vi.hoisted(
  () => ({
    getSessionMock: vi.fn(),
    probeMock: vi.fn(),
    listingMock: vi.fn(),
    serverStateMock: vi.fn(),
  }),
);

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
vi.mock("../../db/repositories/mcp-servers.repo", () => ({
  mcpServersRepository: { findByUuid: serverStateMock },
}));
vi.mock("../../db/repositories", () => ({
  toolsRepository: {
    syncTools: vi.fn(async () => ({ upserted: [], deleted: [] })),
  },
  mcpServersRepository: { findByUuid: serverStateMock },
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

// One source of truth for what the namespace mounts, related the way
// fetch-metamcp.ts relates them: getMcpServers is the listing's routable set
// (the error gate filtered out), and answers {} when the read fails.
vi.mock("./fetch-metamcp", () => ({
  getNamespaceListingServers: listingMock,
  getMcpServers: async (namespaceUuid: string, includeInactive?: boolean) => {
    try {
      return (await listingMock(namespaceUuid, includeInactive)).routable;
    } catch {
      return {};
    }
  },
}));

vi.mock("./mcp-server-pool", async () => {
  const { serverErrorTracker } = await import("./server-error-tracker");
  return {
    mcpServerPool: {
      getSession: getSessionMock,
      probeServerTools: probeMock,
      // Use the real tracker: its boolean API returns false on database errors,
      // which must not permit the re-notify probe to use an existing client.
      isServerInErrorState: (uuid: string) =>
        serverErrorTracker.isServerInErrorState(uuid),
      invalidateServerConnection: vi.fn(),
      cleanupSession: vi.fn(),
      // A warm pool, so tools/list does not try to warm one up.
      getPoolStatus: () => ({ idle: 1, active: 1 }),
    },
  };
});

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

/** What the namespace mounts: routable servers, and error-gated ones. */
function mount(
  routable: Record<string, { uuid: string; name: string }>,
  errorGated: Record<string, { uuid: string; name: string }> = {},
) {
  listingMock.mockResolvedValue({ routable, errorGated });
}

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
  listingMock.mockReset();
  mount({ [NINJA]: { uuid: NINJA, name: "ninja" } });
  serverStateMock.mockReset();
  serverStateMock.mockResolvedValue({ error_status: "NONE" });
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

  it("treats a rejected session acquisition as unavailable and re-notifies", async () => {
    const consumer = await connectConsumer();
    getSessionMock.mockRejectedValue(new Error("connect failed"));
    probeMock.mockResolvedValue(false);

    const failure = (await list(consumer).catch((e: unknown) => e)) as McpError;
    expect(failure).toBeInstanceOf(McpError);
    expect(failure.data).toEqual({
      code: "backend_unavailable",
      servers: ["ninja"],
      retryable: true,
    });
    expect(toolsListRenotifyWatch.watchedServerCount()).toBe(1);

    serve({ [NINJA]: await backend("ninja", [tool("device_search")]) });
    probeMock.mockResolvedValue(true);
    await vi.waitFor(() =>
      expect(consumer.listChanged).toHaveBeenCalledTimes(1),
    );
    expect(names(await list(consumer))).toEqual(["ninja__device_search"]);
  });

  it("re-notifies when tools/list fails over an acquired backend session", async () => {
    const session = await backend("ninja", [tool("device_search")]);
    const request = vi
      .spyOn(session.client, "request")
      .mockRejectedValue(new McpError(-32603, "backend not ready"));
    serve({ [NINJA]: session });
    probeMock.mockResolvedValue(false);
    const consumer = await connectConsumer();

    const failure = (await list(consumer).catch((e: unknown) => e)) as McpError;
    expect(failure).toBeInstanceOf(McpError);
    expect(failure.data).toMatchObject({ code: "backend_unavailable" });
    expect(toolsListRenotifyWatch.watchedServerCount()).toBe(1);

    request.mockRestore();
    probeMock.mockResolvedValue(true);
    await vi.waitFor(() =>
      expect(consumer.listChanged).toHaveBeenCalledTimes(1),
    );
    expect(names(await list(consumer))).toEqual(["ninja__device_search"]);
  });

  it("returns a partial listing when another server answered, and still re-notifies", async () => {
    mount({
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

  it("stops watching when the consumer transport closes", async () => {
    probeMock.mockResolvedValue(false);
    const consumer = await connectConsumer();
    serve({ [NINJA]: undefined });
    await expect(list(consumer)).rejects.toBeInstanceOf(McpError);
    expect(toolsListRenotifyWatch.watchedServerCount()).toBe(1);

    await consumer.client.close();
    expect(toolsListRenotifyWatch.watchedServerCount()).toBe(0);
    await sleep(100);
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

  it.each([true, false])(
    "excludes a misconfigured name without probing it (reachable: %s)",
    async (reachable) => {
      // No retry fixes a stored name containing the tool-name separator, so it
      // is neither an error nor owed a re-notify; it stays in the DEGRADED log.
      mount({
        [NINJA]: { uuid: NINJA, name: "bad__name" },
        [ITGLUE]: { uuid: ITGLUE, name: "itglue" },
      });
      serve({
        [NINJA]: reachable
          ? await backend("bad", [tool("device_search")])
          : undefined,
        [ITGLUE]: await backend("itglue", []),
      });
      probeMock.mockResolvedValue(true);
      const consumer = await connectConsumer();

      expect((await list(consumer)).tools).toEqual([]);
      await sleep(100);
      expect(probeMock).not.toHaveBeenCalled();
      expect(toolsListRenotifyWatch.watchedServerCount()).toBe(0);
    },
  );

  it("answers an error naming only the unreachable server when another is misconfigured", async () => {
    mount({
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
    mount({});
    const consumer = await connectConsumer();
    expect((await list(consumer)).tools).toEqual([]);
  });
});

// The read of what the namespace mounts used to come from getMcpServers,
// which leaves error-gated servers out and answers {} on a database error.
// Either way the listing saw "nothing mounted": a successful empty answer,
// and every owed re-notify cancelled as if its server had left the namespace.
describe("tools/list with an error-gated server or a failed namespace read", () => {
  it("answers an error, not an empty list, when the only mounted server is error-gated, without connecting to it", async () => {
    mount({}, { [NINJA]: { uuid: NINJA, name: "ninja" } });
    serve({ [NINJA]: await backend("ninja", [tool("device_search")]) });
    serverStateMock.mockResolvedValue({ error_status: "ERROR" });
    probeMock.mockResolvedValue(true);
    const consumer = await connectConsumer();

    const failure = (await list(consumer).catch((e: unknown) => e)) as McpError;
    expect(failure).toBeInstanceOf(McpError);
    expect(failure.code).toBe(-32603);
    expect(failure.data).toEqual({
      code: "backend_unavailable",
      servers: ["ninja"],
      retryable: true,
    });
    expect(failure.message).toContain("error-gated");
    // The gate keeps the listing from connecting to it, as before.
    expect(getSessionMock).not.toHaveBeenCalled();
    expect(toolsListRenotifyWatch.watchedServerCount()).toBe(1);

    // Still gated: the watch checks the gate and does not probe or tell.
    await vi.waitFor(() => expect(serverStateMock).toHaveBeenCalledWith(NINJA));
    await sleep(100);
    expect(probeMock).not.toHaveBeenCalled();
    expect(consumer.listChanged).not.toHaveBeenCalled();

    // The gate is reset and the server answers: told once, tools back.
    mount({ [NINJA]: { uuid: NINJA, name: "ninja" } });
    serverStateMock.mockResolvedValue({ error_status: "NONE" });
    await vi.waitFor(() =>
      expect(consumer.listChanged).toHaveBeenCalledTimes(1),
    );
    expect(probeMock.mock.calls[0][0]).toMatchObject({ uuid: NINJA });
    expect(names(await list(consumer))).toEqual(["ninja__device_search"]);
    expect(toolsListRenotifyWatch.watchedServerCount()).toBe(0);
  });

  it.each(["failed read", "deleted server"])(
    "keeps an owed watch without probing when its gate cannot be cleared (%s)",
    async (condition) => {
      mount({}, { [NINJA]: { uuid: NINJA, name: "ninja" } });
      if (condition === "failed read") {
        serverStateMock.mockRejectedValue(new Error("connection terminated"));
      } else {
        serverStateMock.mockResolvedValue(undefined);
      }
      probeMock.mockResolvedValue(true);
      serve({ [NINJA]: await backend("ninja", [tool("device_search")]) });
      const consumer = await connectConsumer();

      await expect(list(consumer)).rejects.toBeInstanceOf(McpError);
      await vi.waitFor(() =>
        expect(serverStateMock).toHaveBeenCalledWith(NINJA),
      );
      await sleep(140);
      expect(probeMock).not.toHaveBeenCalled();
      expect(consumer.listChanged).not.toHaveBeenCalled();
      expect(toolsListRenotifyWatch.watchedServerCount()).toBe(1);

      serverStateMock.mockResolvedValue({ error_status: "NONE" });
      mount({ [NINJA]: { uuid: NINJA, name: "ninja" } });
      await vi.waitFor(() =>
        expect(consumer.listChanged).toHaveBeenCalledTimes(1),
      );
      expect(names(await list(consumer))).toEqual(["ninja__device_search"]);
      expect(toolsListRenotifyWatch.watchedServerCount()).toBe(0);
    },
  );

  it("keeps the owed re-notify when an unreachable server becomes error-gated", async () => {
    const watchSpy = vi.spyOn(toolsListRenotifyWatch, "watch");
    probeMock.mockResolvedValue(false);
    const consumer = await connectConsumer();
    serve({ [NINJA]: undefined });
    await expect(list(consumer)).rejects.toBeInstanceOf(McpError);
    expect(toolsListRenotifyWatch.watchedServerCount()).toBe(1);

    // The crash counter trips the gate; the session lists again meanwhile.
    mount({}, { [NINJA]: { uuid: NINJA, name: "ninja" } });
    serverStateMock.mockResolvedValue({ error_status: "ERROR" });
    const failure = (await list(consumer).catch((e: unknown) => e)) as McpError;
    expect(failure).toBeInstanceOf(McpError);
    expect(failure.data).toMatchObject({
      code: "backend_unavailable",
      servers: ["ninja"],
    });
    // The same watch, kept: not cancelled as if the server had left and
    // re-armed, which would restart its backoff on every listing.
    expect(watchSpy).toHaveBeenCalledTimes(1);
    expect(toolsListRenotifyWatch.watchedServerCount()).toBe(1);

    mount({ [NINJA]: { uuid: NINJA, name: "ninja" } });
    serverStateMock.mockResolvedValue({ error_status: "NONE" });
    serve({ [NINJA]: await backend("ninja", [tool("device_search")]) });
    probeMock.mockResolvedValue(true);
    await vi.waitFor(() =>
      expect(consumer.listChanged).toHaveBeenCalledTimes(1),
    );
    expect(names(await list(consumer))).toEqual(["ninja__device_search"]);
  });

  it("returns a partial listing when another server answered, and owes the error-gated one a re-notify", async () => {
    mount(
      { [ITGLUE]: { uuid: ITGLUE, name: "itglue" } },
      { [NINJA]: { uuid: NINJA, name: "ninja" } },
    );
    serverStateMock.mockImplementation(async (uuid: string) => ({
      error_status: uuid === NINJA ? "ERROR" : "NONE",
    }));
    serve({ [ITGLUE]: await backend("itglue", [tool("search")]) });
    const consumer = await connectConsumer();

    expect(names(await list(consumer))).toEqual(["itglue__search"]);
    expect(toolsListRenotifyWatch.watchedServerCount()).toBe(1);
    expect(getSessionMock).not.toHaveBeenCalledWith(
      expect.anything(),
      NINJA,
      expect.anything(),
      expect.anything(),
    );
  });

  it.each([
    ["alone", {}],
    ["beside a server with no tools", { [ITGLUE]: "itglue" }],
  ])(
    "still answers an empty list for an error-gated misconfigured name (%s)",
    async (_label, others) => {
      const routable = Object.fromEntries(
        Object.entries(others).map(([uuid, name]) => [uuid, { uuid, name }]),
      );
      mount(routable, { [NINJA]: { uuid: NINJA, name: "bad__name" } });
      serve({ [ITGLUE]: await backend("itglue", []) });
      probeMock.mockResolvedValue(true);
      const consumer = await connectConsumer();

      expect((await list(consumer)).tools).toEqual([]);
      await sleep(100);
      expect(probeMock).not.toHaveBeenCalled();
      expect(toolsListRenotifyWatch.watchedServerCount()).toBe(0);
    },
  );

  it("answers a retryable error, not an empty list, when the namespace read fails", async () => {
    listingMock.mockRejectedValue(new Error("connection terminated"));
    const consumer = await connectConsumer();

    const failure = (await list(consumer).catch((e: unknown) => e)) as McpError;
    expect(failure).toBeInstanceOf(McpError);
    expect(failure.code).toBe(-32603);
    expect(failure.data).toEqual({
      code: "backend_unavailable",
      reason: "namespace_lookup_failed",
      servers: [],
      retryable: true,
    });
    expect(failure.message).toContain("not the same as an empty tool list");
    expect(getSessionMock).not.toHaveBeenCalled();
  });

  it("keeps an owed re-notify when a later listing cannot read the namespace", async () => {
    const watchSpy = vi.spyOn(toolsListRenotifyWatch, "watch");
    probeMock.mockResolvedValue(false);
    const consumer = await connectConsumer();
    serve({ [NINJA]: undefined });
    await expect(list(consumer)).rejects.toBeInstanceOf(McpError);
    expect(toolsListRenotifyWatch.watchedServerCount()).toBe(1);

    listingMock.mockRejectedValueOnce(new Error("connection terminated"));
    const failure = (await list(consumer).catch((e: unknown) => e)) as McpError;
    expect(failure.data).toMatchObject({ reason: "namespace_lookup_failed" });
    expect(watchSpy).toHaveBeenCalledTimes(1);
    expect(toolsListRenotifyWatch.watchedServerCount()).toBe(1);

    serve({ [NINJA]: await backend("ninja", [tool("device_search")]) });
    probeMock.mockResolvedValue(true);
    await vi.waitFor(() =>
      expect(consumer.listChanged).toHaveBeenCalledTimes(1),
    );
    expect(names(await list(consumer))).toEqual(["ninja__device_search"]);
  });
});
