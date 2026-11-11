/**
 * The gateway serves no prompts or resources. It advertises only `tools`
 * (gateway-capabilities.ts) and registers no prompts or resources handler, so
 * prompts/list, prompts/get, resources/list, resources/read and
 * resources/templates/list are answered Method not found even when a client
 * sends them without the capability, and nothing reaches a backend that does
 * register them. Those surfaces bypassed the namespace's mount and tool
 * curation; no backend behind the gateway registers either.
 *
 * Removing them changes the capability hash, so a session persisted by the
 * prior build is refused lazy recovery and the client re-initializes; a
 * restart of the same build still recovers. Both are pinned below.
 *
 * Harness as in metamcp-proxy.mount-status.test.ts: the real `createServer`
 * and middleware over the in-memory table stand-in, a real SDK consumer, and
 * an in-memory SDK backend that registers tools, prompts and resources and
 * records every request it receives.
 */
import { createHash } from "node:crypto";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  CallToolRequestSchema,
  ErrorCode,
  GetPromptRequestSchema,
  ListPromptsRequestSchema,
  ListResourcesRequestSchema,
  ListResourceTemplatesRequestSchema,
  ListToolsRequestSchema,
  McpError,
  ReadResourceRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { z } from "zod";

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

import {
  GATEWAY_BOOT_ID,
  GATEWAY_CAPABILITY_HASH,
  shouldRefuseRecovery,
} from "./gateway-boot-id";
import { GATEWAY_CAPABILITIES } from "./gateway-capabilities";
import { setAuditRecorderForTesting } from "./metamcp-middleware/auditing.functional";
import { clearFilterCache } from "./metamcp-middleware/filter-tools.functional";
import { clearOverrideCache } from "./metamcp-middleware/tool-overrides.functional";
import { createServer } from "./metamcp-proxy";

const NS = "ns-surfaces";
const RICH = { uuid: "server-rich", name: "rich" };

const cleanups: Array<() => Promise<unknown>> = [];
/** Every request method the backend received. */
let received: string[];

async function richBackend(): Promise<ConnectedClient> {
  const server = new Server(
    { name: "rich", version: "1.0.0" },
    { capabilities: { tools: {}, prompts: {}, resources: {} } },
  );
  server.setRequestHandler(ListToolsRequestSchema, async () => {
    received.push("tools/list");
    return {
      tools: [{ name: "write", inputSchema: { type: "object" as const } }],
    };
  });
  server.setRequestHandler(CallToolRequestSchema, async () => {
    received.push("tools/call");
    return { content: [{ type: "text", text: "ran" }] };
  });
  server.setRequestHandler(ListPromptsRequestSchema, async () => {
    received.push("prompts/list");
    return { prompts: [{ name: "brief" }] };
  });
  server.setRequestHandler(GetPromptRequestSchema, async () => {
    received.push("prompts/get");
    return { messages: [] };
  });
  server.setRequestHandler(ListResourcesRequestSchema, async () => {
    received.push("resources/list");
    return { resources: [{ uri: "mem://doc", name: "doc" }] };
  });
  server.setRequestHandler(ReadResourceRequestSchema, async () => {
    received.push("resources/read");
    return { contents: [{ uri: "mem://doc", text: "body" }] };
  });
  server.setRequestHandler(ListResourceTemplatesRequestSchema, async () => {
    received.push("resources/templates/list");
    return { resourceTemplates: [] };
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

async function connectConsumer(sessionId: string): Promise<Client> {
  const { server, cleanup } = await createServer(NS, sessionId);
  const [consumerSide, gatewaySide] = InMemoryTransport.createLinkedPair();
  await server.connect(gatewaySide);
  const consumer = new Client({ name: "consumer", version: "1.0.0" });
  await consumer.connect(consumerSide);
  cleanups.push(async () => {
    await consumer.close();
    await cleanup();
  });
  return consumer;
}

/** The JSON-RPC error code a request is answered with, or "answered". */
const answer = (
  consumer: Client,
  method: string,
  params: Record<string, unknown>,
) =>
  consumer
    .request({ method, params } as never, z.object({}).passthrough())
    .then(
      () => "answered" as const,
      (error: unknown) =>
        error instanceof McpError ? error.code : `not an McpError: ${error}`,
    );

/** sha256 of the capability set the gateway advertised before this change. */
const PRIOR_CAPABILITIES = {
  prompts: {},
  resources: {},
  tools: { listChanged: true },
};

beforeEach(async () => {
  clearFilterCache();
  clearOverrideCache();
  state.servers = [RICH];
  state.mounts = [
    { namespaceUuid: NS, serverUuid: RICH.uuid, status: "ACTIVE" },
  ];
  state.namespaces = [{ uuid: NS, toolPolicy: "allow_all" }];
  state.mappings = [];
  state.failOn = undefined;
  queries.length = 0;
  received = [];
  setAuditRecorderForTesting(null);
  const rich = await richBackend();
  getSessionMock.mockReset();
  getSessionMock.mockResolvedValue(rich);
  pool.invalidateServerConnection.mockReset();
  pool.cleanupSession.mockReset();
  pool.cleanupSession.mockResolvedValue(undefined);
  pool.isPooledClient.mockReset();
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

describe("the gateway serves no prompts or resources", () => {
  it("initialize advertises tools only", async () => {
    const consumer = await connectConsumer("session-caps");
    const capabilities = consumer.getServerCapabilities();
    expect(capabilities?.tools).toEqual({ listChanged: true });
    expect(capabilities?.prompts).toBeUndefined();
    expect(capabilities?.resources).toBeUndefined();
  });

  it.each([
    ["prompts/list", {}],
    ["prompts/get", { name: "rich__brief", arguments: {} }],
    ["resources/list", {}],
    ["resources/read", { uri: "mem://doc" }],
    ["resources/templates/list", {}],
  ])(
    "%s sent anyway is answered Method not found and reaches no backend",
    async (method, params) => {
      const consumer = await connectConsumer(`session-${method}`);
      expect(await answer(consumer, method, params)).toBe(
        ErrorCode.MethodNotFound,
      );
      expect(received).toEqual([]);
    },
  );

  it("a resource read after the listings were tried still reaches no backend", async () => {
    const consumer = await connectConsumer("session-sequence");
    await answer(consumer, "resources/list", {});
    await answer(consumer, "prompts/list", {});
    expect(await answer(consumer, "resources/read", { uri: "mem://doc" })).toBe(
      ErrorCode.MethodNotFound,
    );
    expect(await answer(consumer, "prompts/get", { name: "rich__brief" })).toBe(
      ErrorCode.MethodNotFound,
    );
    expect(received).toEqual([]);
  });

  it("tools on the same backend are still listed and called", async () => {
    const consumer = await connectConsumer("session-tools");
    expect(await answer(consumer, "tools/list", {})).toBe("answered");
    expect(
      await answer(consumer, "tools/call", {
        name: "rich__write",
        arguments: {},
      }),
    ).toBe("answered");
    expect(received).toContain("tools/list");
    expect(received).toContain("tools/call");
    expect(
      received.some((method) => /^(prompts|resources)\//.test(method)),
    ).toBe(false);
  });
});

describe("the capability change and persisted sessions", () => {
  const OTHER_BOOT = "bbbbbbbb-bbbb-4bbb-bbbb-bbbbbbbbbbbb";
  const priorHash = createHash("sha256")
    .update(JSON.stringify(PRIOR_CAPABILITIES))
    .digest("hex");

  it("the advertised set is exactly tools, and hashes differently from the prior set", () => {
    expect(GATEWAY_CAPABILITIES).toEqual({ tools: { listChanged: true } });
    expect(GATEWAY_CAPABILITY_HASH).not.toBe(priorHash);
  });

  it("a session persisted by the prior build is refused recovery, so its client re-initializes", () => {
    expect(
      shouldRefuseRecovery(
        { gateway_boot_id: OTHER_BOOT, capability_hash: priorHash },
        { bootId: GATEWAY_BOOT_ID, capabilityHash: GATEWAY_CAPABILITY_HASH },
      ),
    ).toBe(true);
  });

  it("a restart of this build still recovers its sessions", () => {
    expect(
      shouldRefuseRecovery(
        {
          gateway_boot_id: OTHER_BOOT,
          capability_hash: GATEWAY_CAPABILITY_HASH,
        },
        { bootId: GATEWAY_BOOT_ID, capabilityHash: GATEWAY_CAPABILITY_HASH },
      ),
    ).toBe(false);
  });
});
