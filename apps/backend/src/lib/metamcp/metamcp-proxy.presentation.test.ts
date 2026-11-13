/**
 * Per-endpoint presentation through the real proxy: the title and instructions
 * a client receives at `initialize`, the output-schema trim in `tools/list`,
 * and the kill switch, each driven through a real `createServer`, the real
 * middleware chain over the in-memory table stand-in, a real SDK consumer and
 * an in-memory SDK backend (the harness of
 * metamcp-proxy.prompts-resources-local.test.ts).
 *
 * Oracles. The MCP lifecycle specification: the `initialize` result carries
 * `serverInfo` (with an optional `title`) and `instructions`; SDK 1.32.0
 * `server/index.js` lines 259-270 return exactly those two. The SDK client
 * validates `structuredContent` only for a tool whose `outputSchema` it cached
 * from a listing (`client/index.js` lines 485-509, cache filled at 528-538), so
 * a tool listed without an `outputSchema` has no validator. The capability set
 * is pinned to an outside constant (base-build-capabilities.test-util.ts), not
 * to a value computed here.
 *
 * Cases marked "pin" pass on the parent by design: they hold the behaviour of a
 * session with no presentation exactly where it was.
 */
import { createHash } from "node:crypto";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  CallToolRequestSchema,
  ErrorCode,
  ListToolsRequestSchema,
  McpError,
  ToolListChangedNotificationSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { ConnectedClient } from "./client";
import type { SessionPresentation } from "./endpoint-presentation";
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
} from "./base-build-capabilities.test-util";
import { GATEWAY_CAPABILITY_HASH } from "./gateway-boot-id";
import { GATEWAY_CAPABILITIES } from "./gateway-capabilities";
import { setAuditRecorderForTesting } from "./metamcp-middleware/auditing.functional";
import { clearFilterCache } from "./metamcp-middleware/filter-tools.functional";
import { clearOverrideCache } from "./metamcp-middleware/tool-overrides.functional";
import { createServer } from "./metamcp-proxy";
import {
  namespaceMountListenerCount,
  notifyNamespaceMountChange,
} from "./namespace-mount-events";

/** The audit row the recorder receives (the recorder type is not exported). */
type AuditEntry = Parameters<
  NonNullable<Parameters<typeof setAuditRecorderForTesting>[0]>
>[0];

const NS = "ns-presentation";
const DESK = { uuid: "server-desk", name: "desk" };
const OUTPUT_SCHEMA = {
  type: "object" as const,
  properties: { count: { type: "number" as const } },
  required: ["count"],
};
/** A tool with everything a listing can carry, an output schema included. */
const READ_TOOL = {
  name: "read",
  title: "Read things",
  description: "Read things from the desk",
  inputSchema: {
    type: "object" as const,
    properties: { query: { type: "string" as const } },
  },
  outputSchema: OUTPUT_SCHEMA,
  annotations: { readOnlyHint: true },
};

const cleanups: Array<() => Promise<unknown>> = [];
const SAVED_SWITCH = process.env.MCP_ENDPOINT_PRESENTATION;

async function deskBackend(
  reportedName = "desk",
  structuredContent: Record<string, unknown> = { count: "many" },
): Promise<ConnectedClient> {
  const server = new Server(
    { name: reportedName, version: "1.0.0" },
    { capabilities: { tools: {} } },
  );
  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [READ_TOOL],
  }));
  // The result's structuredContent does NOT match the tool's output schema
  // (count is a string): only a client holding a validator can notice.
  server.setRequestHandler(CallToolRequestSchema, async () => ({
    content: [{ type: "text", text: "read" }],
    structuredContent,
  }));
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
  presentation?: SessionPresentation,
): Promise<Consumer> {
  const { server, cleanup } =
    presentation === undefined
      ? await createServer(NS, sessionId)
      : await createServer(NS, sessionId, false, presentation);
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

/**
 * Audit rows as the recorder receives them, with a promise that settles once
 * `count` rows have arrived (the audit write runs after the response).
 */
function auditRows() {
  const rows: AuditEntry[] = [];
  const waiters: Array<{ count: number; resolve: () => void }> = [];
  setAuditRecorderForTesting(async (entry: AuditEntry) => {
    rows.push(entry);
    for (const waiter of waiters) {
      if (rows.length >= waiter.count) waiter.resolve();
    }
  });
  return {
    rows,
    arrived: (count: number) =>
      rows.length >= count
        ? Promise.resolve()
        : new Promise<void>((resolve) => waiters.push({ count, resolve })),
  };
}

const FULL: SessionPresentation = {
  title: "Helpdesk desk",
  instructions: "Prefer read-only tools. Ask before changing a ticket.",
  toolListing: "full",
  omitOutputSchemas: true,
};

beforeEach(async () => {
  clearFilterCache();
  clearOverrideCache();
  delete process.env.MCP_ENDPOINT_PRESENTATION;
  state.servers = [DESK];
  state.mounts = [
    { namespaceUuid: NS, serverUuid: DESK.uuid, status: "ACTIVE" },
  ];
  state.namespaces = [{ uuid: NS, toolPolicy: "allow_all" }];
  state.mappings = [];
  state.failOn = undefined;
  queries.length = 0;
  setAuditRecorderForTesting(null);
  getSessionMock.mockReset();
  getSessionMock.mockResolvedValue(await deskBackend());
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
  if (SAVED_SWITCH === undefined) delete process.env.MCP_ENDPOINT_PRESENTATION;
  else process.env.MCP_ENDPOINT_PRESENTATION = SAVED_SWITCH;
  while (cleanups.length > 0) {
    await cleanups
      .pop()?.()
      .catch(() => undefined);
  }
});

describe("initialize", () => {
  it("pin: a session with no presentation gets today's serverInfo and no instructions", async () => {
    const consumer = await connectConsumer("session-default");
    expect(consumer.client.getServerVersion()).toEqual({
      name: `metamcp-unified-${NS}`,
      version: "1.0.0",
    });
    expect(consumer.client.getInstructions()).toBeUndefined();
  });

  it("a session with a presentation receives its title and its instructions", async () => {
    const consumer = await connectConsumer("session-presented", FULL);
    expect(consumer.client.getServerVersion()).toEqual({
      name: `metamcp-unified-${NS}`,
      version: "1.0.0",
      title: "Helpdesk desk",
    });
    expect(consumer.client.getInstructions()).toBe(FULL.instructions);
  });

  it("a title alone adds no instructions, and instructions alone add no title", async () => {
    const titled = await connectConsumer("session-title", {
      title: "Only a title",
      toolListing: "full",
      omitOutputSchemas: false,
    });
    expect(titled.client.getServerVersion()?.title).toBe("Only a title");
    expect(titled.client.getInstructions()).toBeUndefined();

    const instructed = await connectConsumer("session-instructions", {
      instructions: "Only instructions.",
      toolListing: "full",
      omitOutputSchemas: false,
    });
    expect(instructed.client.getInstructions()).toBe("Only instructions.");
    expect(instructed.client.getServerVersion()).toEqual({
      name: `metamcp-unified-${NS}`,
      version: "1.0.0",
    });
  });

  it("the title is display only: the server name is never the title", async () => {
    const consumer = await connectConsumer("session-name", {
      title: `metamcp-unified-another-namespace`,
      toolListing: "full",
      omitOutputSchemas: false,
    });
    expect(consumer.client.getServerVersion()?.name).toBe(
      `metamcp-unified-${NS}`,
    );
  });

  it("pin: a backend that reports the proxy's own name is still skipped as a self-reference in a titled session", async () => {
    getSessionMock.mockResolvedValue(
      await deskBackend(`metamcp-unified-${NS}`),
    );
    const consumer = await connectConsumer("session-self", FULL);
    const listed = await consumer.client.listTools();
    expect(listed.tools).toEqual([]);
  });

  it("the advertised capabilities, and so the capability hash, are unchanged by a presentation", async () => {
    const consumer = await connectConsumer("session-caps", FULL);
    expect(consumer.client.getServerCapabilities()).toEqual(
      GATEWAY_CAPABILITIES,
    );
    expect(consumer.client.getServerCapabilities()).toEqual(
      BASE_BUILD_CAPABILITIES,
    );
    // The digest is an outside constant: what the build stamped on every
    // persisted session before presentation existed. Changing it would make
    // every persisted session re-initialize.
    expect(GATEWAY_CAPABILITY_HASH).toBe(BASE_BUILD_CAPABILITY_DIGEST);
    expect(
      createHash("sha256")
        .update(JSON.stringify(consumer.client.getServerCapabilities()))
        .digest("hex"),
    ).toBe(BASE_BUILD_CAPABILITY_DIGEST);
  });
});

describe("the output-schema trim", () => {
  it("pin: an untrimmed session lists the output schema", async () => {
    const consumer = await connectConsumer("session-untrimmed");
    const listed = await consumer.client.listTools();
    expect(listed.tools).toHaveLength(1);
    expect(listed.tools[0].outputSchema).toEqual(OUTPUT_SCHEMA);
  });

  it("a trimmed session lists no output schema and every other field unchanged", async () => {
    const untrimmed = await connectConsumer("session-compare");
    const trimmed = await connectConsumer("session-trimmed", FULL);

    const before = (await untrimmed.client.listTools()).tools[0];
    const after = (await trimmed.client.listTools()).tools[0];

    expect("outputSchema" in after).toBe(false);
    const { outputSchema: _removed, ...withoutOutput } = before;
    expect(after).toEqual(withoutOutput);
    expect(after).toEqual({
      name: "desk__read",
      title: "Read things",
      description: "Read things from the desk",
      inputSchema: READ_TOOL.inputSchema,
      annotations: READ_TOOL.annotations,
    });
  });

  it("two sessions on one namespace can differ, and trimming one never trims the other", async () => {
    const trimmed = await connectConsumer("session-a", FULL);
    const untrimmed = await connectConsumer("session-b");

    // Listed in both orders: the middleware caches are shared by the namespace,
    // so a trim that edited a shared object in place would show up here.
    expect("outputSchema" in (await trimmed.client.listTools()).tools[0]).toBe(
      false,
    );
    expect((await untrimmed.client.listTools()).tools[0].outputSchema).toEqual(
      OUTPUT_SCHEMA,
    );
    expect("outputSchema" in (await trimmed.client.listTools()).tools[0]).toBe(
      false,
    );
  });

  it("a trimmed session still gets a tool result's structuredContent unchanged, and the SDK client does not reject it", async () => {
    const trimmed = await connectConsumer("session-result", FULL);
    await trimmed.client.listTools();
    // The backend's structuredContent violates the schema the backend listed.
    // The SDK client validates only against an outputSchema it cached from the
    // listing (client/index.js:485-509), and a trimmed listing cached none.
    const result = await trimmed.client.callTool({ name: "desk__read" });
    expect(result.structuredContent).toEqual({ count: "many" });
    expect(result.isError).toBeFalsy();
  });

  it("contrast: the same call from an untrimmed session IS rejected by the SDK client, which shows the trim is what removed the validator", async () => {
    const untrimmed = await connectConsumer("session-contrast");
    await untrimmed.client.listTools();
    const rejection = await untrimmed.client
      .callTool({ name: "desk__read" })
      .then(
        () => undefined,
        (error: unknown) => error,
      );
    expect(rejection).toBeInstanceOf(McpError);
    expect((rejection as McpError).code).toBe(ErrorCode.InvalidParams);
  });

  it("a trimmed session still gets list_changed (only the lean listing would suppress it)", async () => {
    const trimmed = await connectConsumer("session-notify", FULL);
    await trimmed.client.listTools();
    expect(namespaceMountListenerCount(NS)).toBeGreaterThan(0);

    notifyNamespaceMountChange(NS, DESK.uuid);
    // The in-memory transport delivers in order, so once a ping has answered
    // every earlier notification has arrived.
    await trimmed.client.ping();

    expect(trimmed.listChanged()).toBe(1);
  });

  it("pin: the audit shape of a call is the same in a trimmed session as in an untrimmed one", async () => {
    const audit = auditRows();
    const untrimmed = await connectConsumer("session-shape-a");
    const trimmed = await connectConsumer("session-shape-b", FULL);
    await untrimmed.client.listTools();
    await trimmed.client.listTools();

    // outputSchema never reaches the audit registry (ToolArgSchema reads only
    // inputSchema), so the trim cannot change what a row records.
    await untrimmed.client
      .callTool({ name: "desk__read", arguments: { query: "x" } })
      .catch(() => undefined);
    await trimmed.client
      .callTool({ name: "desk__read", arguments: { query: "x" } })
      .catch(() => undefined);
    await audit.arrived(2);

    expect(audit.rows).toHaveLength(2);
    expect(audit.rows[0].args_shape).toEqual({ keys: ["query"] });
    expect(audit.rows[1].args_shape).toEqual(audit.rows[0].args_shape);
  });
});

describe("the kill switch, through a real createServer", () => {
  it.each(["off", "false", "0", "OFF"])(
    "MCP_ENDPOINT_PRESENTATION=%s ignores the title, the instructions and the trim",
    async (value) => {
      process.env.MCP_ENDPOINT_PRESENTATION = value;
      const consumer = await connectConsumer(`session-off-${value}`, FULL);

      expect(consumer.client.getServerVersion()).toEqual({
        name: `metamcp-unified-${NS}`,
        version: "1.0.0",
      });
      expect(consumer.client.getInstructions()).toBeUndefined();
      expect((await consumer.client.listTools()).tools[0].outputSchema).toEqual(
        OUTPUT_SCHEMA,
      );
    },
  );

  it("with the switch on, the same call presents", async () => {
    process.env.MCP_ENDPOINT_PRESENTATION = "on";
    const consumer = await connectConsumer("session-on", FULL);
    expect(consumer.client.getInstructions()).toBe(FULL.instructions);
  });
});
