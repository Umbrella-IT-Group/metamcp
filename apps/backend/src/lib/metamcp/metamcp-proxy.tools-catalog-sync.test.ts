/**
 * The tool catalog write on a proxied tools/list, driven end to end through
 * `createServer` with the REAL `tools.impl` and the REAL `toolsSyncCache`.
 *
 * The defect this pins: the tools/list handler checked the shared hash cache,
 * claimed the new hash, then called `toolsImplementations.sync`, which checked
 * the same cache again, found the hash it had just been handed and returned
 * "Tools unchanged, skipped sync". With no overrides the two lists are
 * identical, so the `tools` table was never written from this path, and in
 * production the catalog went months stale. Only the repository is mocked
 * here, which is what lets these cases see that interplay: with `tools.impl`
 * mocked, the handler's call would look like a write.
 *
 * What it pins:
 *   - the first tools/list of a server writes the catalog, once;
 *   - listing the same set again does not touch the database;
 *   - a changed set writes again, with the new tool in it;
 *   - a failed write is retried by the next tools/list, and the listing itself
 *     is still served while the database is failing;
 *   - a failed write from the UI's `tools.sync` cannot leave a claim behind
 *     that makes the next tools/list skip its write.
 *   - namespace presentation aliases cannot suppress native backend names;
 *   - an older listing or UI write that commits last cannot leave the newer
 *     listing cached as current against a stale catalog.
 *
 * Which rows the write may delete is a property of the SQL, pinned against a
 * real Postgres in `db/repositories/tools.repo.sync.integration.test.ts`.
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  ListToolsRequestSchema,
  ListToolsResultSchema,
  Tool,
} from "@modelcontextprotocol/sdk/types.js";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { ConnectedClient } from "./client";

const {
  getSessionMock,
  syncToolsMock,
  emitAdminEventMock,
  mapOverrideNameMock,
} = vi.hoisted(() => ({
  getSessionMock: vi.fn(),
  syncToolsMock: vi.fn(),
  emitAdminEventMock: vi.fn(),
  mapOverrideNameMock: vi.fn(),
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
// The one seam: the real tools.impl writes through this repository.
vi.mock("../../db/repositories", () => ({
  toolsRepository: { syncTools: syncToolsMock },
  mcpServersRepository: {},
}));
vi.mock("../audit/admin-event", () => ({
  emitAdminEvent: emitAdminEventMock,
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
  const getMcpServers = vi.fn(async () => ({
    "server-ninja": { name: "ninja" },
  }));
  return {
    getMcpServers,
    // tools/list reads the routable set (and the error-gated servers, none
    // here) through getNamespaceListingServers. Derived from getMcpServers so
    // a case that sets the routable set drives the listing too.
    getNamespaceListingServers: vi.fn(async () => ({
      routable: await getMcpServers(),
      errorGated: {},
    })),
  };
});

vi.mock("./mcp-server-pool", () => ({
  mcpServerPool: {
    getSession: getSessionMock,
    invalidateServerConnection: vi.fn(),
    cleanupSession: vi.fn(),
    // A warm pool, so tools/list does not try to warm one up.
    getPoolStatus: () => ({ idle: 1, active: 1 }),
  },
}));

// The filter needs the database; nothing here is curated out.
vi.mock("./metamcp-middleware/filter-tools.functional", () => ({
  createFilterCallToolMiddleware: () => (next: unknown) => next,
  createFilterListToolsMiddleware: () => (next: unknown) => next,
}));
// Namespace presentation is inert here; the reverse-name seam lets a test
// prove that presentation aliases cannot change the shared raw catalog.
vi.mock("./metamcp-middleware/tool-overrides.functional", () => ({
  createToolOverridesCallToolMiddleware: () => (next: unknown) => next,
  createToolOverridesListToolsMiddleware: () => (next: unknown) => next,
  mapOverrideNameToOriginal: mapOverrideNameMock,
}));
vi.mock("./cold-connect-broker-fallback", () => ({
  resolveColdConnectBrokerFallback: () => undefined,
}));
vi.mock("./tool-call-warmup", () => ({
  acquireSessionWithBoundedWarmup: vi.fn(async () => undefined),
}));

import { toolsImplementations } from "../../trpc/tools.impl";
import { createServer } from "./metamcp-proxy";
import { toolsSyncCache } from "./tools-sync-cache";

const SERVER_UUID = "server-ninja";

const cleanups: Array<() => Promise<unknown>> = [];

const tool = (name: string): Tool => ({
  name,
  description: `${name} description`,
  inputSchema: { type: "object", properties: {} },
});

async function backend(initial: Tool[]) {
  let tools = initial;
  const server = new Server(
    { name: "ninja", version: "1.0.0" },
    { capabilities: { tools: {} } },
  );
  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools }));
  const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
  await server.connect(serverSide);
  const client = new Client({ name: "metamcp", version: "1.0.0" });
  await client.connect(clientSide);
  cleanups.push(() => client.close());
  const session: ConnectedClient = {
    client,
    cleanup: () => client.close(),
    listChangedSubscribers: new Set(),
  } as unknown as ConnectedClient;
  return {
    session,
    setTools: (next: Tool[]) => {
      tools = next;
    },
  };
}

async function connectConsumer(): Promise<Client> {
  const { server } = await createServer("ns-1", "sess-1");
  const [consumerSide, gatewaySide] = InMemoryTransport.createLinkedPair();
  await server.connect(gatewaySide);
  const consumer = new Client({ name: "consumer", version: "1.0.0" });
  await consumer.connect(consumerSide);
  cleanups.push(() => consumer.close());
  return consumer;
}

const list = (consumer: Client) =>
  consumer.request({ method: "tools/list", params: {} }, ListToolsResultSchema);

/** The tool names each repository write received, in call order. */
const writtenNames = () =>
  syncToolsMock.mock.calls.map((call) =>
    (call[0] as { tools: Array<{ name: string }> }).tools
      .map((t) => t.name)
      .sort(),
  );

beforeEach(() => {
  // The cache is a process-wide singleton; every case starts cold, as a
  // freshly started gateway does.
  toolsSyncCache.clear();
  getSessionMock.mockReset();
  syncToolsMock.mockReset();
  syncToolsMock.mockImplementation(
    async (input: { tools: Array<{ name: string }> }) => ({
      upserted: input.tools,
      deleted: [],
    }),
  );
  emitAdminEventMock.mockReset();
  mapOverrideNameMock.mockReset();
  mapOverrideNameMock.mockImplementation(async (name: string) => name);
});

afterEach(async () => {
  while (cleanups.length > 0) {
    await cleanups
      .pop()?.()
      .catch(() => undefined);
  }
});

describe("tools/list writes the server's tool catalog", () => {
  it("writes the catalog on the first tools/list of a server", async () => {
    const target = await backend([tool("list_things"), tool("add_thing")]);
    getSessionMock.mockResolvedValue(target.session);

    await list(await connectConsumer());

    expect(syncToolsMock).toHaveBeenCalledTimes(1);
    expect(syncToolsMock.mock.calls[0][0]).toMatchObject({
      mcpServerUuid: SERVER_UUID,
    });
    expect(writtenNames()).toEqual([["add_thing", "list_things"]]);
    // Recorded as the system's write: no operator stands behind a proxied
    // tools/list.
    expect(emitAdminEventMock).toHaveBeenCalledWith(undefined, {
      action: "tools.sync",
      target_type: "mcp_server",
      target_id: SERVER_UUID,
      detail: { upserted: 2, deleted: 0 },
    });
  });

  it("does not touch the database when the same set is listed again", async () => {
    const target = await backend([tool("list_things")]);
    getSessionMock.mockResolvedValue(target.session);
    const consumer = await connectConsumer();

    await list(consumer);
    await list(consumer);
    await list(await connectConsumer());

    expect(syncToolsMock).toHaveBeenCalledTimes(1);
  });

  it("saves a genuine backend tool even when a namespace uses its name as an alias", async () => {
    const target = await backend([tool("list_things"), tool("meeting_notes")]);
    getSessionMock.mockResolvedValue(target.session);
    mapOverrideNameMock.mockImplementation(async (name: string) =>
      name === "ninja__meeting_notes" ? "ninja__list_things" : name,
    );

    await list(await connectConsumer());

    // This is a raw backend listing, before gateway presentation overrides.
    // Dropping a native name because one namespace aliases to it would hide
    // that tool from curation in every namespace sharing the server/cache.
    expect(writtenNames()).toEqual([["list_things", "meeting_notes"]]);
  });

  it("writes again, with the new tool, when the set changes", async () => {
    const target = await backend([tool("list_things")]);
    getSessionMock.mockResolvedValue(target.session);
    const consumer = await connectConsumer();

    await list(consumer);
    target.setTools([tool("list_things"), tool("meeting_notes")]);
    await list(consumer);

    expect(writtenNames()).toEqual([
      ["list_things"],
      ["list_things", "meeting_notes"],
    ]);
  });

  it("retries a failed write on the next tools/list, and still serves the list meanwhile", async () => {
    const target = await backend([tool("list_things")]);
    getSessionMock.mockResolvedValue(target.session);
    syncToolsMock.mockRejectedValueOnce(new Error("db down"));
    const consumer = await connectConsumer();

    const served = await list(consumer);
    expect(served.tools.map((t) => t.name)).toEqual(["ninja__list_things"]);
    expect(syncToolsMock).toHaveBeenCalledTimes(1);

    await list(consumer);

    // The failed claim was released, so the same set is written this time.
    expect(syncToolsMock).toHaveBeenCalledTimes(2);
    expect(writtenNames()).toEqual([["list_things"], ["list_things"]]);
  });

  it("a failed UI sync leaves no claim that would make tools/list skip its write", async () => {
    const target = await backend([tool("list_things")]);
    getSessionMock.mockResolvedValue(target.session);
    syncToolsMock.mockRejectedValueOnce(new Error("db down"));

    // The server detail page's Refresh lists the same set and fails to write.
    const uiResult = await toolsImplementations.sync({
      mcpServerUuid: SERVER_UUID,
      tools: [tool("list_things")],
    });
    expect(uiResult.success).toBe(false);

    await list(await connectConsumer());

    expect(syncToolsMock).toHaveBeenCalledTimes(2);
  });

  it("retries the current listing when an older listing commits last", async () => {
    const target = await backend([tool("list_things")]);
    getSessionMock.mockResolvedValue(target.session);
    const olderConsumer = await connectConsumer();
    const currentConsumer = await connectConsumer();
    let finishOlder!: () => void;
    let signalStarted!: () => void;
    const started = new Promise<void>((resolve) => {
      signalStarted = resolve;
    });
    syncToolsMock.mockImplementationOnce(async (input) => {
      signalStarted();
      await new Promise<void>((resolve) => {
        finishOlder = resolve;
      });
      return { upserted: input.tools, deleted: [] };
    });

    const olderListing = list(olderConsumer);
    await started;
    target.setTools([tool("list_things"), tool("meeting_notes")]);
    try {
      await list(currentConsumer);
    } finally {
      finishOlder();
      await olderListing;
    }

    // The database now holds the older set. Its completed write must replace
    // the newer claim, or every future listing of the current set skips forever.
    await list(currentConsumer);
    expect(writtenNames()).toEqual([
      ["list_things"],
      ["list_things", "meeting_notes"],
      ["list_things", "meeting_notes"],
    ]);
  });

  it("retries the current listing when an older UI sync commits last", async () => {
    const target = await backend([tool("list_things"), tool("meeting_notes")]);
    getSessionMock.mockResolvedValue(target.session);
    let finishOlder!: () => void;
    let signalStarted!: () => void;
    const started = new Promise<void>((resolve) => {
      signalStarted = resolve;
    });
    syncToolsMock.mockImplementationOnce(async (input) => {
      signalStarted();
      await new Promise<void>((resolve) => {
        finishOlder = resolve;
      });
      return { upserted: input.tools, deleted: [] };
    });

    const olderSync = toolsImplementations.sync({
      mcpServerUuid: SERVER_UUID,
      tools: [tool("list_things")],
    });
    await started;
    const consumer = await connectConsumer();
    try {
      await list(consumer);
    } finally {
      finishOlder();
      await olderSync;
    }

    await list(consumer);
    expect(writtenNames()).toEqual([
      ["list_things"],
      ["list_things", "meeting_notes"],
      ["list_things", "meeting_notes"],
    ]);
  });
});
