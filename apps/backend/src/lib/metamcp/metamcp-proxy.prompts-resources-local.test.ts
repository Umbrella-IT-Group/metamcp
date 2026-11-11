/**
 * The gateway answers prompts and resources itself and relays only tools.
 * prompts/list, resources/list and resources/templates/list answer an empty
 * list; prompts/get and resources/read answer Method not found with one
 * constant message. None of the five reads the namespace's servers, acquires
 * a backend session or reaches a backend, even one that registers prompts and
 * resources and after tools/list has cached a route to it. Those surfaces
 * bypassed the namespace's mount and tool curation; no backend behind the
 * gateway registers either.
 *
 * The advertised capabilities stay exactly as they were on 8815f6b (prompts,
 * resources and tools with listChanged), so GATEWAY_CAPABILITY_HASH does not
 * change and a session persisted by a build advertising that set still
 * recovers lazily after a restart onto this one: no client is forced to
 * re-initialize. Both are pinned below (base-build-capabilities.test-util.ts
 * holds the base values; streamable-http.test.ts drives the same row through
 * recoverPersistedSession).
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
  BASE_BUILD_CAPABILITIES,
  BASE_BUILD_CAPABILITY_DIGEST,
  BASE_BUILD_CAPABILITY_HASH,
} from "./base-build-capabilities.test-util";
import {
  getMcpServers,
  getNamespaceListingServers,
  getNamespaceServerStates,
} from "./fetch-metamcp";
import {
  GATEWAY_BOOT_ID,
  GATEWAY_CAPABILITY_HASH,
  shouldRefuseRecovery,
} from "./gateway-boot-id";
import { GATEWAY_CAPABILITIES } from "./gateway-capabilities";
import { setAuditRecorderForTesting } from "./metamcp-middleware/auditing.functional";
import { clearFilterCache } from "./metamcp-middleware/filter-tools.functional";
import { clearOverrideCache } from "./metamcp-middleware/tool-overrides.functional";
import { createServer, GATEWAY_SERVES_TOOLS_ONLY } from "./metamcp-proxy";

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
    return {
      resourceTemplates: [{ uriTemplate: "mem://{name}", name: "docs" }],
    };
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

/** Send a raw request; the result, or the McpError it was refused with. */
const send = (
  consumer: Client,
  method: string,
  params: Record<string, unknown>,
) =>
  consumer
    .request({ method, params } as never, z.object({}).passthrough())
    .then(
      (result) => ({ result }),
      (error: unknown) => {
        if (error instanceof McpError) return { error };
        throw error;
      },
    );

/** Every seam through which one of the five could reach a backend. */
const backendSeams = () => ({
  backendRequests: [...received],
  sessionAcquisitions: getSessionMock.mock.calls.length,
  warmups: warmupMock.mock.calls.length,
  serverReads:
    vi.mocked(getMcpServers).mock.calls.length +
    vi.mocked(getNamespaceListingServers).mock.calls.length +
    vi.mocked(getNamespaceServerStates).mock.calls.length,
  toolLookups: findServersMock.mock.calls.length,
});

const LISTINGS = [
  ["prompts/list", { prompts: [] }],
  ["resources/list", { resources: [] }],
  ["resources/templates/list", { resourceTemplates: [] }],
] as const;

const READS = [
  ["prompts/get", { name: "rich__brief", arguments: {} }],
  ["resources/read", { uri: "mem://doc" }],
] as const;

const ALL_FIVE = [
  ...LISTINGS.map(([method]) => [method, {}] as const),
  ...READS,
];

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
  vi.mocked(getMcpServers).mockClear();
  vi.mocked(getNamespaceListingServers).mockClear();
  vi.mocked(getNamespaceServerStates).mockClear();
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

describe("the advertised capabilities are unchanged", () => {
  it("GATEWAY_CAPABILITIES is the 8815f6b set, in its key order", () => {
    expect(GATEWAY_CAPABILITIES).toEqual(BASE_BUILD_CAPABILITIES);
    expect(JSON.stringify(GATEWAY_CAPABILITIES)).toBe(
      JSON.stringify(BASE_BUILD_CAPABILITIES),
    );
  });

  it("GATEWAY_CAPABILITY_HASH equals the hash the 8815f6b build stamped on its sessions", () => {
    // Computed from the base object; the digest that build printed pins the
    // hashing too. Changing either makes every persisted session re-initialize.
    expect(GATEWAY_CAPABILITY_HASH).toBe(BASE_BUILD_CAPABILITY_HASH);
    expect(GATEWAY_CAPABILITY_HASH).toBe(BASE_BUILD_CAPABILITY_DIGEST);
  });

  it("initialize advertises prompts, resources and tools exactly as before", async () => {
    const consumer = await connectConsumer("session-caps");
    expect(consumer.getServerCapabilities()).toEqual(BASE_BUILD_CAPABILITIES);
  });
});

describe("prompts and resources are answered by the gateway, never a backend", () => {
  it.each(LISTINGS)("%s answers an empty list", async (method, empty) => {
    const consumer = await connectConsumer(`session-${method}`);
    expect(await send(consumer, method, {})).toEqual({ result: empty });
  });

  it("the SDK's typed listing calls accept the empty answers", async () => {
    const consumer = await connectConsumer("session-typed");
    expect(await consumer.listPrompts()).toEqual({ prompts: [] });
    expect(await consumer.listResources()).toEqual({ resources: [] });
    expect(await consumer.listResourceTemplates()).toEqual({
      resourceTemplates: [],
    });
  });

  it.each(READS)(
    "%s is refused Method not found with the constant message",
    async (method, params) => {
      const consumer = await connectConsumer(`session-${method}`);
      const answer = await send(consumer, method, params);
      expect(answer).not.toHaveProperty("result");
      const { error } = answer as { error: McpError };
      expect(error.code).toBe(ErrorCode.MethodNotFound);
      expect(error.message).toContain(GATEWAY_SERVES_TOOLS_ONLY);
    },
  );

  it("the refusal echoes nothing from the request", async () => {
    const consumer = await connectConsumer("session-echo");
    const messages = await Promise.all(
      [
        ["prompts/get", { name: "rich__brief" }],
        ["prompts/get", { name: "rich__<other-name>" }],
        ["resources/read", { uri: "mem://doc" }],
        ["resources/read", { uri: "file:///etc/<other-uri>" }],
      ].map(async ([method, params]) => {
        const answer = await send(
          consumer,
          method as string,
          params as Record<string, unknown>,
        );
        return (answer as { error: McpError }).error.message;
      }),
    );
    expect(new Set(messages).size).toBe(1);
    for (const fragment of ["brief", "other-name", "mem://", "other-uri"]) {
      expect(messages[0]).not.toContain(fragment);
    }
  });

  it.each(ALL_FIVE)(
    "%s reads no namespace server, acquires no session and reaches no backend",
    async (method, params) => {
      const consumer = await connectConsumer(`session-seams-${method}`);
      const before = backendSeams();
      await send(consumer, method, params);
      expect(backendSeams()).toEqual(before);
      expect(received).toEqual([]);
    },
  );

  it("none of the five reaches the backend after tools/list cached a route to it", async () => {
    const consumer = await connectConsumer("session-after-tools");
    expect(await send(consumer, "tools/list", {})).toHaveProperty("result");
    expect(received).toEqual(["tools/list"]);
    const before = backendSeams();
    for (const [method, params] of ALL_FIVE) {
      await send(consumer, method, params);
    }
    expect(backendSeams()).toEqual(before);
    expect(received).toEqual(["tools/list"]);
  });
});

describe("tools are still served", () => {
  it("tools/list and tools/call reach the backend that registers them", async () => {
    const consumer = await connectConsumer("session-tools");
    const listed = await consumer.listTools();
    expect(listed.tools.map((tool) => tool.name)).toEqual(["rich__write"]);
    const called = await consumer.callTool({
      name: "rich__write",
      arguments: {},
    });
    expect(called.content).toEqual([{ type: "text", text: "ran" }]);
    expect(received).toEqual(["tools/list", "tools/call"]);
  });
});

describe("sessions persisted by the base build recover lazily", () => {
  const OTHER_BOOT = "bbbbbbbb-bbbb-4bbb-bbbb-bbbbbbbbbbbb";

  it("a row another process of the base build stamped is recovered (the capability-hash path)", () => {
    // Different boot id, so only the capability hash can allow it: this is
    // the branch of shouldRefuseRecovery that a restart onto this build takes.
    expect(
      shouldRefuseRecovery(
        {
          gateway_boot_id: OTHER_BOOT,
          capability_hash: BASE_BUILD_CAPABILITY_HASH,
        },
        { bootId: GATEWAY_BOOT_ID, capabilityHash: GATEWAY_CAPABILITY_HASH },
      ),
    ).toBe(false);
  });

  it("contrast: a row stamped with a different capability set would be refused", () => {
    const toolsOnlyHash = createHash("sha256")
      .update(JSON.stringify({ tools: { listChanged: true } }))
      .digest("hex");
    expect(
      shouldRefuseRecovery(
        { gateway_boot_id: OTHER_BOOT, capability_hash: toolsOnlyHash },
        { bootId: GATEWAY_BOOT_ID, capabilityHash: GATEWAY_CAPABILITY_HASH },
      ),
    ).toBe(true);
  });
});
