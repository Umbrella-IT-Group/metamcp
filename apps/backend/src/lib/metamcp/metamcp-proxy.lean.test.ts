/**
 * The lean tool listing through the real proxy: a real `createServer`, the
 * real audit, retired-tool, override, filter and timeout-hint middleware over
 * the in-memory table stand-in, real SDK consumers, and in-memory SDK backends
 * at the transport (the harness of metamcp-proxy.presentation.test.ts).
 *
 * What a lean session is: `tools/list` returns four meta tools
 * (`search_tools`, `describe_tool`, `call_tool`, `call_write_tool`); search and
 * describe read the post-policy listing; both call tools are rewritten into an
 * ordinary `tools/call` for the real tool and enter the middleware chain at its
 * top, so every call is audited, redirected, overridden, filtered and timed on
 * the REAL name. `call_tool` runs only tools whose effective (post-override)
 * `readOnlyHint` is true and says so; `call_write_tool` runs any tool.
 *
 * ORACLES. Differential: a direct real-name call through a non-lean session of
 * the same namespace is the oracle for what a lean call must return and what
 * audit row it must write, and a non-lean `tools/list` is the oracle for the
 * search universe (the filter and override semantics are migration 0040 and the
 * existing middleware, not the new code). Hash: `params_hash` is the sha256 of
 * the JSON of the arguments as sent and null when there are none
 * (auditing.functional.ts `hashParams`), computed here with `node:crypto`.
 * Capability set: the pinned build digest (base-build-capabilities.test-util.ts).
 * Hints: MCP ToolAnnotations defaults (SDK 1.32.0 types.js 1178-1210).
 *
 * Cases marked "pin" pass on the parent by design: they hold a session that is
 * not lean exactly where it was.
 */
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPError } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  CallToolRequestSchema,
  type CallToolResult,
  ListToolsRequestSchema,
  McpError,
  type Tool,
  ToolListChangedNotificationSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import logger from "@/utils/logger";

import type { ConnectedClient } from "./client";
import type { SessionPresentation } from "./endpoint-presentation";
import type {
  FakeQuery,
  FakeToolMappingState,
} from "./metamcp-middleware/tool-mapping-db.fixtures";

const {
  state,
  queries,
  getSessionMock,
  findServersMock,
  warmupMock,
  probeMock,
  serverStateMock,
  pool,
} = vi.hoisted(() => ({
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
  probeMock: vi.fn(),
  serverStateMock: vi.fn(),
  pool: {
    invalidateServerConnection: vi.fn(),
    cleanupSession: vi.fn(),
    isPooledClient: vi.fn(),
    getPoolStatus: vi.fn(),
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
vi.mock("../../db/repositories/mcp-servers.repo", () => ({
  mcpServersRepository: { findByUuid: serverStateMock },
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
    probeServerTools: probeMock,
    // tools/list only: a warm pool, so it does not try to warm one up. A mock
    // so a test can make the one read of it outside the listing's per-server
    // handling throw, which no backend failure can (see `beforeEach`).
    getPoolStatus: pool.getPoolStatus,
  },
}));
vi.mock("./cold-connect-broker-fallback", () => ({
  resolveColdConnectBrokerFallback: () => undefined,
}));
vi.mock("./tool-call-warmup", () => ({
  acquireSessionWithBoundedWarmup: warmupMock,
}));

import { setGatewayEventSinkForTesting } from "../gateway-events/sink";
import {
  BASE_BUILD_CAPABILITIES,
  BASE_BUILD_CAPABILITY_DIGEST,
} from "./base-build-capabilities.test-util";
import { LEAN_INSTRUCTIONS } from "./endpoint-presentation";
import { GATEWAY_CAPABILITY_HASH } from "./gateway-boot-id";
import { GATEWAY_CAPABILITIES } from "./gateway-capabilities";
import { type MetaMcpLogEntry, metamcpLogStore } from "./log-store";
import { setAuditRecorderForTesting } from "./metamcp-middleware/auditing.functional";
import { clearFilterCache } from "./metamcp-middleware/filter-tools.functional";
import {
  clearOverrideCache,
  overrideChangeListenerCount,
} from "./metamcp-middleware/tool-overrides.functional";
import { createServer } from "./metamcp-proxy";
import {
  namespaceMountListenerCount,
  notifyNamespaceMountChange,
} from "./namespace-mount-events";
import {
  RetiredToolsRegistry,
  setRetiredToolsRegistryForTesting,
} from "./retired-tools";
import { toolsListRenotifyWatch } from "./tools-list-renotify";
import { toolsSyncCache } from "./tools-sync-cache";

type AuditEntry = Parameters<
  NonNullable<Parameters<typeof setAuditRecorderForTesting>[0]>
>[0];

const NS = "ns-lean";
const DESK = { uuid: "server-desk", name: "desk" };
const GHOST = { uuid: "server-ghost", name: "ghost" };
const T0 = Date.parse("2026-11-12T12:00:00.000Z");

const READ: Tool = {
  name: "read",
  description: "Read tickets from the desk",
  inputSchema: {
    type: "object",
    properties: {
      query: { type: "string" },
      mode: { type: "string", enum: ["list", "get"] },
    },
  },
  annotations: { readOnlyHint: true },
};
const WRITE: Tool = {
  name: "write",
  description: "Update a ticket on the desk",
  inputSchema: {
    type: "object",
    properties: {
      ticket_id: { type: "string" },
      mode: { type: "string", enum: ["update", "close"] },
    },
  },
  annotations: { readOnlyHint: false, destructiveHint: false },
  outputSchema: {
    type: "object",
    properties: { ran: { type: "string" } },
  },
};
const BARE: Tool = {
  name: "bare",
  description: "A tool with no annotations at all",
  inputSchema: { type: "object", properties: { note: { type: "string" } } },
};
const SECRET: Tool = {
  name: "secret",
  description: "A tool the namespace switches off",
  inputSchema: { type: "object", properties: {} },
  annotations: { readOnlyHint: true },
};
const LEGACY: Tool = {
  name: "legacy",
  description: "A read-only tool that shows up under another name",
  inputSchema: { type: "object", properties: { id: { type: "string" } } },
  annotations: { readOnlyHint: true },
};

interface FakeBackend {
  connected: ConnectedClient;
  tools: Tool[];
  calls: Array<{ name: string; args: unknown; meta: unknown }>;
  listings: () => number;
}

const cleanups: Array<() => Promise<unknown>> = [];

async function makeBackend(
  reportedName: string,
  tools: Tool[],
): Promise<FakeBackend> {
  const handle = {
    tools,
    calls: [] as FakeBackend["calls"],
    listingCount: 0,
  };
  const server = new Server(
    { name: reportedName, version: "1.0.0" },
    { capabilities: { tools: {} } },
  );
  server.setRequestHandler(ListToolsRequestSchema, async () => {
    handle.listingCount += 1;
    return { tools: handle.tools };
  });
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    handle.calls.push({
      name: request.params.name,
      args: request.params.arguments,
      meta: request.params._meta,
    });
    return {
      content: [{ type: "text", text: `ran ${request.params.name}` }],
      structuredContent: {
        ran: request.params.name,
        args: request.params.arguments ?? null,
      },
      _meta: { source: request.params.name },
    };
  });
  const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
  await server.connect(serverSide);
  const client = new Client({ name: "metamcp", version: "1.0.0" });
  await client.connect(clientSide);
  cleanups.push(() => client.close());
  return {
    connected: {
      client,
      cleanup: () => client.close(),
      listChangedSubscribers: new Set(),
    } as unknown as ConnectedClient,
    get tools() {
      return handle.tools;
    },
    set tools(next: Tool[]) {
      handle.tools = next;
    },
    calls: handle.calls,
    listings: () => handle.listingCount,
  };
}

let desk: FakeBackend;
const sessionsByServer = new Map<string, ConnectedClient | undefined>();

interface Consumer {
  client: Client;
  /** The session's shared, per-instance handler context (never a call's own). */
  handlerContext: object;
  listChanged: () => number;
  close: () => Promise<void>;
}

const LEAN: SessionPresentation = {
  toolListing: "lean",
  omitOutputSchemas: false,
};

async function connectConsumer(
  sessionId: string,
  presentation?: SessionPresentation,
): Promise<Consumer> {
  const { server, cleanup, handlerContext } =
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
  let closed = false;
  const close = async () => {
    if (closed) return;
    closed = true;
    await consumer.close();
    await cleanup();
  };
  cleanups.push(close);
  return {
    client: consumer,
    handlerContext,
    listChanged: () => notifications,
    close,
  };
}

/** The audit rows the recorder receives, and a promise for the Nth. */
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

/** Live Logs entries, and the rows the durable sink would persist. */
function eventSinks() {
  const live: MetaMcpLogEntry[] = [];
  const persisted: Array<{
    category: string;
    server_name?: string | null;
    message: string;
    level?: string | null;
  }> = [];
  const off = metamcpLogStore.addListener((entry) => live.push(entry));
  cleanups.push(async () => {
    off();
  });
  setGatewayEventSinkForTesting(async (entry) => {
    persisted.push(entry);
  });
  return { live, persisted };
}

const textOf = (result: unknown): string =>
  ((result as CallToolResult).content[0] as { text: string }).text;
/** The JSON a meta tool answered with; a tool error here is a failed test. */
const json = (result: unknown) => {
  expect((result as CallToolResult).isError, textOf(result)).toBeFalsy();
  return JSON.parse(textOf(result)) as Record<string, any>;
};

async function meta(
  consumer: Consumer,
  name: string,
  args?: Record<string, unknown>,
  extra: Record<string, unknown> = {},
): Promise<CallToolResult> {
  return (await consumer.client.callTool({
    name,
    ...(args !== undefined ? { arguments: args } : {}),
    ...extra,
  })) as CallToolResult;
}

/** What a call came to: a result, or the protocol error's message. */
async function outcome(run: () => Promise<unknown>) {
  try {
    return { result: await run() };
  } catch (error) {
    return { error: (error as Error).message };
  }
}

const direct = (
  consumer: Consumer,
  name: string,
  args?: Record<string, unknown>,
) =>
  outcome(() =>
    consumer.client.callTool({
      name,
      ...(args !== undefined ? { arguments: args } : {}),
    }),
  );

const sha256 = (value: unknown) =>
  createHash("sha256").update(JSON.stringify(value)).digest("hex");

/** Move the fake clock; the filter caches and the catalog both read it. */
const setNow = (ms: number) => vi.setSystemTime(new Date(T0 + ms));

const flush = () => new Promise((resolve) => setImmediate(resolve));

let retiredDir: string | undefined;

const SAVED_ENV = {
  lean: process.env.MCP_LEAN_LISTING,
  presentation: process.env.MCP_ENDPOINT_PRESENTATION,
};

beforeEach(async () => {
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(new Date(T0));
  clearFilterCache();
  clearOverrideCache();
  toolsSyncCache.clear();
  delete process.env.MCP_LEAN_LISTING;
  delete process.env.MCP_ENDPOINT_PRESENTATION;
  state.servers = [DESK];
  state.mounts = [
    { namespaceUuid: NS, serverUuid: DESK.uuid, status: "ACTIVE" },
  ];
  state.namespaces = [{ uuid: NS, toolPolicy: "allow_all" }];
  state.mappings = [
    // `secret` is curated off and `legacy` is shown under another name.
    {
      namespaceUuid: NS,
      serverUuid: DESK.uuid,
      toolName: "secret",
      status: "INACTIVE",
    },
    {
      namespaceUuid: NS,
      serverUuid: DESK.uuid,
      toolName: "legacy",
      status: "ACTIVE",
      overrideName: "modern",
    },
  ];
  state.failOn = undefined;
  state.beforeQueryResult = undefined;
  queries.length = 0;
  setAuditRecorderForTesting(null);
  setGatewayEventSinkForTesting(null);
  desk = await makeBackend("desk", [READ, WRITE, BARE, SECRET, LEGACY]);
  sessionsByServer.clear();
  sessionsByServer.set(DESK.uuid, desk.connected);
  getSessionMock.mockReset();
  getSessionMock.mockImplementation(
    async (_sessionId: string, serverUuid: string) =>
      sessionsByServer.get(serverUuid),
  );
  pool.invalidateServerConnection.mockReset();
  pool.cleanupSession.mockReset();
  pool.cleanupSession.mockResolvedValue(undefined);
  pool.isPooledClient.mockReset();
  pool.getPoolStatus.mockReset();
  pool.getPoolStatus.mockReturnValue({ idle: 1, active: 1 });
  findServersMock.mockReset();
  findServersMock.mockResolvedValue([]);
  warmupMock.mockReset();
  warmupMock.mockResolvedValue(undefined);
  probeMock.mockReset();
  probeMock.mockResolvedValue(false);
  serverStateMock.mockReset();
  serverStateMock.mockResolvedValue({ error_status: "NONE" });
});

afterEach(async () => {
  setAuditRecorderForTesting(undefined);
  setGatewayEventSinkForTesting(undefined);
  setRetiredToolsRegistryForTesting(undefined);
  if (retiredDir) rmSync(retiredDir, { recursive: true, force: true });
  retiredDir = undefined;
  clearFilterCache();
  clearOverrideCache();
  for (const [name, saved] of [
    ["MCP_LEAN_LISTING", SAVED_ENV.lean],
    ["MCP_ENDPOINT_PRESENTATION", SAVED_ENV.presentation],
  ] as const) {
    if (saved === undefined) delete process.env[name];
    else process.env[name] = saved;
  }
  while (cleanups.length > 0) {
    await cleanups
      .pop()?.()
      .catch(() => undefined);
  }
  vi.useRealTimers();
});

const NAMES_OF_LEAN = [
  "search_tools",
  "describe_tool",
  "call_tool",
  "call_write_tool",
];

// ---------------------------------------------------------------------------

describe("tools/list", () => {
  it("lists exactly the four meta tools in order, contacts no backend and no table, and stays under 8 KiB", async () => {
    const lean = await connectConsumer("s-list", LEAN);
    getSessionMock.mockClear();
    queries.length = 0;
    const listed = await lean.client.listTools();
    expect(listed.tools.map((t) => t.name)).toEqual(NAMES_OF_LEAN);
    expect(getSessionMock).not.toHaveBeenCalled();
    expect(desk.listings()).toBe(0);
    expect(queries).toEqual([]);
    expect(Buffer.byteLength(JSON.stringify(listed))).toBeLessThan(8 * 1024);
    expect(listed.tools.every((t) => t.outputSchema === undefined)).toBe(true);
  });

  it("annotates call_tool read-only and call_write_tool with the MCP defaults, as listed to the client", async () => {
    const lean = await connectConsumer("s-annotations", LEAN);
    const byName = Object.fromEntries(
      (await lean.client.listTools()).tools.map((t) => [t.name, t]),
    );
    expect(byName["call_tool"]?.annotations?.readOnlyHint).toBe(true);
    expect(byName["call_write_tool"]?.annotations).toEqual({
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: false,
      openWorldHint: true,
    });
  });

  it("pin: a session that is not lean answers the meta names exactly as before, with Invalid tool name format", async () => {
    const plain = await connectConsumer("s-plain");
    for (const name of NAMES_OF_LEAN) {
      const answer = await direct(plain, name, { name: "desk__read" });
      expect(answer.error).toContain(`Invalid tool name format: ${name}`);
    }
    // And its listing is the real one.
    expect(
      (await plain.client.listTools()).tools.map((t) => t.name).sort(),
    ).toEqual(["desk__bare", "desk__modern", "desk__read", "desk__write"]);
  });
});

describe("the search universe is the post-policy listing", () => {
  async function universe(lean: Consumer) {
    const found = json(
      await meta(lean, "search_tools", { limit: 25, detail: "names" }),
    );
    return {
      names: (found.results as Array<{ name: string }>)
        .map((r) => r.name)
        .sort(),
      total: found.meta.total_tools as number,
    };
  }

  it("equals what a non-lean tools/list returns, with a curated-off tool hidden and an alias shown under its alias", async () => {
    const plain = await connectConsumer("s-plain-u");
    const lean = await connectConsumer("s-lean-u", LEAN);
    const expected = (await plain.client.listTools()).tools
      .map((t) => t.name)
      .sort();
    expect(expected).toEqual([
      "desk__bare",
      "desk__modern",
      "desk__read",
      "desk__write",
    ]);
    const seen = await universe(lean);
    expect(seen.names).toEqual(expected);
    expect(seen.total).toBe(expected.length);
  });

  it("equals it under an allowlist namespace too, where a tool with no row is not served", async () => {
    state.namespaces = [{ uuid: NS, toolPolicy: "allowlist" }];
    state.mappings = [
      {
        namespaceUuid: NS,
        serverUuid: DESK.uuid,
        toolName: "read",
        status: "ACTIVE",
      },
    ];
    clearFilterCache();
    const plain = await connectConsumer("s-plain-a");
    const lean = await connectConsumer("s-lean-a", LEAN);
    const expected = (await plain.client.listTools()).tools.map((t) => t.name);
    expect(expected).toEqual(["desk__read"]);
    expect((await universe(lean)).names).toEqual(expected);
  });

  it("describes a curated-off tool and a real name that is only listed under its alias as not found, suggesting nothing hidden", async () => {
    const lean = await connectConsumer("s-lean-d", LEAN);
    const answer = json(
      await meta(lean, "describe_tool", {
        names: ["desk__secret", "desk__legacy"],
      }),
    );
    expect(answer.tools).toEqual([]);
    expect(answer.not_found.map((n: { name: string }) => n.name)).toEqual([
      "desk__secret",
      "desk__legacy",
    ]);
    for (const entry of answer.not_found) {
      expect(JSON.stringify(entry.did_you_mean)).not.toMatch(/secret|legacy/);
    }
    // The alias is the name it can be described under.
    const aliased = json(
      await meta(lean, "describe_tool", { names: ["desk__modern"] }),
    );
    expect(aliased.tools[0]).toMatchObject({
      name: "desk__modern",
      runs_with: "call_tool",
    });
  });

  it("reports an unreachable server by count only and names it nowhere", async () => {
    state.servers = [DESK, GHOST];
    state.mounts = [
      ...state.mounts,
      { namespaceUuid: NS, serverUuid: GHOST.uuid, status: "ACTIVE" },
    ];
    sessionsByServer.set(GHOST.uuid, undefined);
    const lean = await connectConsumer("s-lean-g", LEAN);
    const searched = await meta(lean, "search_tools", { limit: 25 });
    const answer = json(searched);
    expect(answer.meta.unavailable_server_count).toBe(1);
    expect(answer.results.length).toBeGreaterThan(0);
    expect(textOf(searched)).not.toMatch(/ghost/i);
    const described = await meta(lean, "describe_tool", {
      names: ["desk__read", "desk__nope"],
    });
    expect(textOf(described)).not.toMatch(/ghost/i);
  });
});

describe("call_tool and call_write_tool run the real tool through the real chain", () => {
  it("runs a read-only tool through call_tool and a write tool through call_write_tool, with the original name and arguments, returning what a direct call returns", async () => {
    const plain = await connectConsumer("s-plain-c");
    const lean = await connectConsumer("s-lean-c", LEAN);
    const readDirect = await direct(plain, "desk__read", { query: "open" });
    const readLean = await outcome(() =>
      meta(lean, "call_tool", {
        name: "desk__read",
        arguments: { query: "open" },
      }),
    );
    expect(readLean).toEqual(readDirect);
    const writeDirect = await direct(plain, "desk__write", {
      ticket_id: "T-1",
      mode: "close",
    });
    const writeLean = await outcome(() =>
      meta(lean, "call_write_tool", {
        name: "desk__write",
        arguments: { ticket_id: "T-1", mode: "close" },
      }),
    );
    expect(writeLean).toEqual(writeDirect);
    expect(desk.calls.map((c) => [c.name, c.args])).toEqual([
      ["read", { query: "open" }],
      ["read", { query: "open" }],
      ["write", { ticket_id: "T-1", mode: "close" }],
      ["write", { ticket_id: "T-1", mode: "close" }],
    ]);
    // The result is the tool's own: isError, structuredContent and _meta.
    const result = (readLean.result ?? {}) as CallToolResult;
    expect(result.structuredContent).toEqual({
      ran: "read",
      args: { query: "open" },
    });
    expect(result._meta).toEqual({ source: "read" });
  });

  it("writes one audit row for the REAL tool, equal to the direct call's row except session and time, with the hash of the arguments as sent", async () => {
    const audit = auditRows();
    const plain = await connectConsumer("s-plain-a1");
    const lean = await connectConsumer("s-lean-a1", LEAN);
    const args = { query: "open", mode: "list" };
    await direct(plain, "desk__read", args);
    await audit.arrived(1);
    await meta(lean, "call_tool", { name: "desk__read", arguments: args });
    await audit.arrived(2);
    await meta(lean, "call_write_tool", {
      name: "desk__read",
      arguments: args,
    });
    await audit.arrived(3);
    expect(audit.rows).toHaveLength(3);
    const strip = ({
      session_id: _s,
      latency_ms: _l,
      called_at: _t,
      ...rest
    }: AuditEntry) => rest;
    expect(strip(audit.rows[1] as AuditEntry)).toEqual(
      strip(audit.rows[0] as AuditEntry),
    );
    expect(strip(audit.rows[2] as AuditEntry)).toEqual(
      strip(audit.rows[0] as AuditEntry),
    );
    for (const row of audit.rows) {
      expect(row).toMatchObject({
        server_name: "desk",
        tool_name: "read",
        params_hash: sha256(args),
        success: true,
      });
    }
    expect(audit.rows[1]?.session_id).toBe("s-lean-a1");
  });

  it.each(["call_tool", "call_write_tool"])(
    "%s with no arguments records a null params_hash, exactly as the direct call does",
    async (via) => {
      const audit = auditRows();
      const plain = await connectConsumer("s-plain-n");
      const lean = await connectConsumer("s-lean-n", LEAN);
      await direct(plain, "desk__read");
      await audit.arrived(1);
      await meta(lean, via, { name: "desk__read" });
      await audit.arrived(2);
      expect(audit.rows[0]?.params_hash).toBeNull();
      expect(audit.rows[1]?.params_hash).toBeNull();
      // The backend saw the same (empty) arguments both times.
      expect(desk.calls.map((c) => c.args)).toEqual([{}, {}]);
    },
  );

  it("passes the request's _meta to the backend call, under the gateway's own progress token", async () => {
    // With progress relayed (MCP_TOOL_CALL_PROGRESS, on by default) the SDK
    // registers the gateway's handler and sends its own token, the request id;
    // the relay answers the consumer under the consumer's token. Every other
    // _meta field reaches the backend as sent.
    const lean = await connectConsumer("s-lean-m", LEAN);
    await meta(
      lean,
      "call_write_tool",
      { name: "desk__write", arguments: { ticket_id: "T-2" } },
      { _meta: { progressToken: "token-7", "example.test/trace": "t-1" } },
    );
    const sent = desk.calls.at(-1)?.meta as Record<string, unknown> | undefined;
    expect(sent).toMatchObject({ "example.test/trace": "t-1" });
    expect(sent?.progressToken).toBeDefined();
    expect(sent?.progressToken).not.toBe("token-7");
  });

  it("passes the consumer's progress token verbatim when progress relay is off", async () => {
    const saved = process.env.MCP_TOOL_CALL_PROGRESS;
    process.env.MCP_TOOL_CALL_PROGRESS = "off";
    try {
      const lean = await connectConsumer("s-lean-m-off", LEAN);
      await meta(
        lean,
        "call_write_tool",
        { name: "desk__write", arguments: { ticket_id: "T-2" } },
        { _meta: { progressToken: "token-7" } },
      );
      expect(desk.calls.at(-1)?.meta).toMatchObject({
        progressToken: "token-7",
      });
    } finally {
      if (saved === undefined) delete process.env.MCP_TOOL_CALL_PROGRESS;
      else process.env.MCP_TOOL_CALL_PROGRESS = saved;
    }
  });

  it("logs a search as one persisted system event from the gateway, with counts only and never a tool call or a name", async () => {
    const sinks = eventSinks();
    const lean = await connectConsumer("s-lean-l", LEAN);
    await meta(lean, "search_tools", { query: "reset the secret passphrase" });
    await meta(lean, "describe_tool", { names: ["desk__read"] });
    await meta(lean, "call_tool", { name: "desk__read" });
    const lines = sinks.live.filter((e) => e.serverName === "gateway");
    expect(lines.map((e) => e.category)).toEqual(["system", "system"]);
    expect(lines.every((e) => e.level === "info")).toBe(true);
    expect(lines.map((e) => e.message).join("\n")).toMatch(/search_tools/);
    for (const line of lines) {
      expect(line.message).not.toMatch(/passphrase|desk__read|read/);
      expect(line.message).not.toMatch(/error|fail|denied|degraded/i);
      expect(line.toolName).toBeUndefined();
      expect(line.sessionId).toBe("s-lean-l");
    }
    // The real call logs under its own server, as a tool call.
    expect(
      sinks.live.filter(
        (e) => e.category === "tool_call" && e.serverName === "gateway",
      ),
    ).toEqual([]);
    expect(
      sinks.live.some(
        (e) =>
          e.category === "tool_call" &&
          e.serverName === "desk" &&
          e.toolName === "read",
      ),
    ).toBe(true);
    // What the durable sink was handed: system events only, no query text.
    const persisted = sinks.persisted.filter(
      (e) => e.server_name === "gateway",
    );
    expect(persisted).toHaveLength(2);
    expect(persisted.every((e) => e.category === "system")).toBe(true);
    expect(JSON.stringify(persisted)).not.toMatch(/passphrase/);
  });
});

describe("policy through the meta tools is the direct call's policy", () => {
  it("refuses a curated-off tool exactly as a direct call does, runs nothing, and audits the refusal under the real name", async () => {
    const audit = auditRows();
    const plain = await connectConsumer("s-plain-p1");
    const lean = await connectConsumer("s-lean-p1", LEAN);
    const viaDirect = await direct(plain, "desk__secret");
    await audit.arrived(1);
    const viaWrite = await outcome(() =>
      meta(lean, "call_write_tool", { name: "desk__secret" }),
    );
    await audit.arrived(2);
    expect(viaWrite).toEqual(viaDirect);
    expect(textOf((viaWrite as { result: unknown }).result)).toBe(
      'Access denied to tool "desk__secret": Tool has been marked as inactive in this namespace',
    );
    expect(desk.calls).toEqual([]);
    expect(audit.rows.map((r) => [r.tool_name, r.success])).toEqual([
      ["secret", false],
      ["secret", false],
    ]);
  });

  it("answers a curated-off tool sent to call_tool with the routing message, since it is not in the listing, and runs nothing", async () => {
    const audit = auditRows();
    const lean = await connectConsumer("s-lean-p1b", LEAN);
    const answer = await meta(lean, "call_tool", { name: "desk__secret" });
    expect(answer.isError).toBe(true);
    expect(textOf(answer)).toContain("call_write_tool");
    expect(desk.calls).toEqual([]);
    // No row from the routing answer: prove it with a real call after it.
    await meta(lean, "call_write_tool", { name: "desk__read" });
    await audit.arrived(1);
    await flush();
    expect(audit.rows).toHaveLength(1);
    expect(audit.rows[0]?.tool_name).toBe("read");
  });

  it("resolves an override alias to the original tool, as the direct call does", async () => {
    const plain = await connectConsumer("s-plain-p2");
    const lean = await connectConsumer("s-lean-p2", LEAN);
    const viaDirect = await direct(plain, "desk__modern", { id: "7" });
    const viaMeta = await outcome(() =>
      meta(lean, "call_tool", { name: "desk__modern", arguments: { id: "7" } }),
    );
    expect(viaMeta).toEqual(viaDirect);
    expect(desk.calls.map((c) => c.name)).toEqual(["legacy", "legacy"]);
  });

  it("answers a retired name with the retired envelope, as the direct call does, and runs nothing", async () => {
    retiredDir = mkdtempSync(path.join(tmpdir(), "lean-retired-"));
    const file = path.join(retiredDir, "retired-tools.json");
    writeFileSync(
      file,
      JSON.stringify({
        version: 1,
        retired: {
          desk__old_tool: {
            since: "2026-09-02",
            replacement: "desk__read",
            hint: "use read",
          },
        },
      }),
    );
    setRetiredToolsRegistryForTesting(
      new RetiredToolsRegistry({ path: file, reloadSeconds: 30 }),
    );
    const audit = auditRows();
    const plain = await connectConsumer("s-plain-p3");
    const lean = await connectConsumer("s-lean-p3", LEAN);
    const viaDirect = await direct(plain, "desk__old_tool");
    await audit.arrived(1);
    const viaWrite = await outcome(() =>
      meta(lean, "call_write_tool", { name: "desk__old_tool" }),
    );
    await audit.arrived(2);
    expect(viaWrite).toEqual(viaDirect);
    expect(textOf((viaWrite as { result: unknown }).result)).toContain(
      "desk__read",
    );
    expect(desk.calls).toEqual([]);
    expect(audit.rows[1]?.error_code).toBe(audit.rows[0]?.error_code);
    expect(audit.rows[1]?.tool_name).toBe("old_tool");
  });

  it("refuses an unlisted tool under an allowlist, a tool on an INACTIVE mount, and an unknown name, each as the direct call does", async () => {
    const plain = await connectConsumer("s-plain-p4");
    const lean = await connectConsumer("s-lean-p4", LEAN);

    state.namespaces = [{ uuid: NS, toolPolicy: "allowlist" }];
    clearFilterCache();
    const bareDirect = await direct(plain, "desk__bare");
    const bareLean = await outcome(() =>
      meta(lean, "call_write_tool", { name: "desk__bare" }),
    );
    expect(bareLean).toEqual(bareDirect);
    expect(textOf((bareLean as { result: unknown }).result)).toContain(
      "allowlist",
    );

    state.namespaces = [{ uuid: NS, toolPolicy: "allow_all" }];
    clearFilterCache();
    const unknownDirect = await direct(plain, "desk__nope");
    const unknownLean = await outcome(() =>
      meta(lean, "call_write_tool", { name: "desk__nope" }),
    );
    expect(unknownLean).toEqual(unknownDirect);

    const mount = state.mounts[0];
    if (mount) mount.status = "INACTIVE";
    const inactiveDirect = await direct(plain, "desk__read");
    const inactiveLean = await outcome(() =>
      meta(lean, "call_write_tool", { name: "desk__read" }),
    );
    expect(inactiveLean).toEqual(inactiveDirect);
    expect(desk.calls).toEqual([]);
  });

  it("refuses at call time a tool switched off after a search, when the setter cleared the filter cache, though the search snapshot is still warm", async () => {
    const lean = await connectConsumer("s-lean-warm1", LEAN);
    const before = json(await meta(lean, "search_tools", { limit: 25 }));
    expect(before.results.map((r: { name: string }) => r.name)).toContain(
      "desk__read",
    );
    // What `namespaces.updateToolStatus` does: write the row, clear the cache.
    state.mappings.push({
      namespaceUuid: NS,
      serverUuid: DESK.uuid,
      toolName: "read",
      status: "INACTIVE",
    });
    clearFilterCache(NS);
    // call_tool classifies from the warm snapshot (read-only) and then the
    // chain's live filter decides: refused, and nothing ran.
    const refused = await meta(lean, "call_tool", { name: "desk__read" });
    expect(refused.isError).toBe(true);
    expect(textOf(refused)).toContain(
      "Tool has been marked as inactive in this namespace",
    );
    expect(desk.calls).toEqual([]);
    // Search may lag the change, never grant: still listed inside the snapshot.
    const lagging = json(await meta(lean, "search_tools", { limit: 25 }));
    expect(lagging.results.map((r: { name: string }) => r.name)).toContain(
      "desk__read",
    );
    // And it catches up once the snapshot expires.
    setNow(1000);
    const caughtUp = json(await meta(lean, "search_tools", { limit: 25 }));
    expect(caughtUp.results.map((r: { name: string }) => r.name)).not.toContain(
      "desk__read",
    );
  });

  it("gives a call the same cached verdict a direct call gets until the filter's own cache expires, with the search snapshot warm throughout", async () => {
    // A mapping row, so the filter caches the tool's ACTIVE status.
    state.mappings.push({
      namespaceUuid: NS,
      serverUuid: DESK.uuid,
      toolName: "read",
      status: "ACTIVE",
    });
    const plain = await connectConsumer("s-plain-warm2");
    const lean = await connectConsumer("s-lean-warm2", LEAN);
    // t=0: a direct call caches the status; it expires at t=1000.
    await direct(plain, "desk__read");
    // t=600: the snapshot is loaded; it stays warm until t=1600.
    setNow(600);
    await meta(lean, "search_tools");
    // t=700: the row is switched off in the database, no cache cleared.
    setNow(700);
    const row = state.mappings.find((m) => m.toolName === "read");
    if (row) row.status = "INACTIVE";
    // t=900: both calls still see the cached ACTIVE verdict (up to 1 s of lag
    // is the filter's own contract), so both run.
    setNow(900);
    const runsDirect = await direct(plain, "desk__read");
    const runsLean = await outcome(() =>
      meta(lean, "call_tool", { name: "desk__read" }),
    );
    expect(runsLean).toEqual(runsDirect);
    expect(textOf((runsLean as { result: unknown }).result)).toBe("ran read");
    // t=1001: the filter's cache has expired and the snapshot has not: both
    // calls are refused by the live read.
    setNow(1001);
    const refusedDirect = await direct(plain, "desk__read");
    const refusedLean = await outcome(() =>
      meta(lean, "call_tool", { name: "desk__read" }),
    );
    expect(refusedLean).toEqual(refusedDirect);
    expect(textOf((refusedLean as { result: unknown }).result)).toContain(
      "marked as inactive",
    );
    const lagging = json(await meta(lean, "search_tools", { limit: 25 }));
    expect(lagging.results.map((r: { name: string }) => r.name)).toContain(
      "desk__read",
    );
    expect(desk.calls.map((c) => c.name)).toEqual(["read", "read", "read"]);
  });
});

describe("a call tool that is not a clean request", () => {
  it.each(["call_tool", "call_write_tool"])(
    "%s refuses a nested meta call, a missing or non-string name and non-object arguments, runs nothing and writes no audit row",
    async (via) => {
      const audit = auditRows();
      const lean = await connectConsumer("s-lean-bad", LEAN);
      getSessionMock.mockClear();
      const bad: Array<Record<string, unknown>> = [
        ...NAMES_OF_LEAN.map((name) => ({ name })),
        {},
        { name: 7 },
        { name: ["desk__read"] },
        { name: "desk__read", arguments: "{}" },
        { name: "desk__read", arguments: ["x"] },
        { name: `desk__${"x".repeat(300)}` },
      ];
      for (const args of bad) {
        const answer = await meta(lean, via, args);
        expect(answer.isError).toBe(true);
      }
      expect(desk.calls).toEqual([]);
      expect(getSessionMock).not.toHaveBeenCalled();
      // No row came from any of them: the one real call after is the first.
      await meta(lean, "call_write_tool", { name: "desk__read" });
      await audit.arrived(1);
      await flush();
      expect(audit.rows).toHaveLength(1);
      expect(audit.rows[0]?.tool_name).toBe("read");
    },
  );
});

describe("which call tool runs a tool", () => {
  it("runs a read-only tool through call_tool and sends a write tool to call_write_tool with a routing answer that is not a refusal", async () => {
    const audit = auditRows();
    const lean = await connectConsumer("s-lean-f4a", LEAN);
    const routed = await meta(lean, "call_tool", {
      name: "desk__write",
      arguments: { ticket_id: "T-9" },
    });
    expect(routed.isError).toBe(true);
    expect(textOf(routed)).toContain("call_write_tool");
    expect(textOf(routed)).not.toMatch(/denied|inactive|allowlist/i);
    expect(desk.calls).toEqual([]);
    // The same session reaches it through call_write_tool.
    const ran = await meta(lean, "call_write_tool", {
      name: "desk__write",
      arguments: { ticket_id: "T-9" },
    });
    expect(ran.isError).toBeFalsy();
    expect(desk.calls.map((c) => c.name)).toEqual(["write"]);
    // One audit row, from the call that ran. The routing answer wrote none.
    await audit.arrived(1);
    await flush();
    expect(audit.rows).toHaveLength(1);
    expect(audit.rows[0]).toMatchObject({ tool_name: "write", success: true });
  });

  it("sends a tool with no annotations, and one with annotations that do not say read-only, to call_write_tool", async () => {
    // (A non-boolean readOnlyHint cannot get this far: the gateway's own SDK
    // client refuses such a backend listing. That case is in lean-listing.test.)
    desk.tools = [
      READ,
      BARE,
      { ...WRITE, name: "hinted", annotations: { title: "Hinted" } },
      { ...WRITE, name: "empty", annotations: {} },
    ];
    const lean = await connectConsumer("s-lean-f4b", LEAN);
    for (const name of ["desk__bare", "desk__hinted", "desk__empty"]) {
      const routed = await meta(lean, "call_tool", { name });
      expect(routed.isError).toBe(true);
      expect(textOf(routed)).toContain("call_write_tool");
    }
    expect(desk.calls).toEqual([]);
    const ran = await meta(lean, "call_tool", { name: "desk__read" });
    expect(textOf(ran)).toBe("ran read");
  });

  it("reports in describe_tool and search_tools which meta tool runs each tool", async () => {
    const lean = await connectConsumer("s-lean-f4c", LEAN);
    const described = json(
      await meta(lean, "describe_tool", {
        names: ["desk__read", "desk__write", "desk__bare"],
      }),
    );
    const by = Object.fromEntries(
      described.tools.map((t: { name: string }) => [t.name, t]),
    );
    expect(by["desk__read"].runs_with).toBe("call_tool");
    expect(by["desk__write"].runs_with).toBe("call_write_tool");
    expect(by["desk__bare"].runs_with).toBe("call_write_tool");
    const searched = json(
      await meta(lean, "search_tools", { limit: 25, detail: "names" }),
    );
    const found = Object.fromEntries(
      searched.results.map((r: { name: string; runs_with: string }) => [
        r.name,
        r.runs_with,
      ]),
    );
    expect(found).toMatchObject({
      desk__read: "call_tool",
      desk__write: "call_write_tool",
      desk__bare: "call_write_tool",
      desk__modern: "call_tool",
    });
  });

  it("follows an annotation override in both directions", async () => {
    const lean = await connectConsumer("s-lean-f4d", LEAN);
    // The backend says read is read-only and write is not.
    expect(textOf(await meta(lean, "call_tool", { name: "desk__read" }))).toBe(
      "ran read",
    );
    expect(
      (await meta(lean, "call_tool", { name: "desk__write" })).isError,
    ).toBe(true);
    desk.calls.length = 0;

    // The namespace overrides: read is NOT read-only here, write IS.
    state.mappings.push(
      {
        namespaceUuid: NS,
        serverUuid: DESK.uuid,
        toolName: "read",
        status: "ACTIVE",
        overrideAnnotations: { readOnlyHint: false },
      },
      {
        namespaceUuid: NS,
        serverUuid: DESK.uuid,
        toolName: "write",
        status: "ACTIVE",
        overrideAnnotations: { readOnlyHint: true },
      },
    );
    // What `namespaces.updateToolOverrides` does, then the snapshot expires.
    clearOverrideCache(NS);
    clearFilterCache(NS);
    setNow(1000);

    const readNow = await meta(lean, "call_tool", { name: "desk__read" });
    expect(readNow.isError).toBe(true);
    expect(textOf(readNow)).toContain("call_write_tool");
    const writeNow = await meta(lean, "call_tool", { name: "desk__write" });
    expect(writeNow.isError).toBeFalsy();
    expect(textOf(writeNow)).toBe("ran write");
    // call_write_tool runs either one.
    expect(
      (await meta(lean, "call_write_tool", { name: "desk__read" })).isError,
    ).toBeFalsy();
    expect(desk.calls.map((c) => c.name)).toEqual(["write", "read"]);
    const described = json(
      await meta(lean, "describe_tool", {
        names: ["desk__read", "desk__write"],
      }),
    );
    expect(
      described.tools.map((t: { name: string; runs_with: string }) => [
        t.name,
        t.runs_with,
      ]),
    ).toEqual([
      ["desk__read", "call_write_tool"],
      ["desk__write", "call_tool"],
    ]);
  });

  it("does not run a writer through an alias cached as read-only after the alias is rebound", async () => {
    const lean = await connectConsumer("s-lean-rebound", LEAN);
    const described = json(
      await meta(lean, "describe_tool", { names: ["desk__modern"] }),
    );
    expect(described.tools[0].runs_with).toBe("call_tool");

    const legacy = state.mappings.find((row) => row.toolName === "legacy");
    if (!legacy) throw new Error("missing legacy mapping");
    legacy.overrideName = "former";
    state.mappings.push({
      namespaceUuid: NS,
      serverUuid: DESK.uuid,
      toolName: "write",
      status: "ACTIVE",
      overrideName: "modern",
    });
    // The real setter clears live alias resolution immediately. A cached
    // read-only hint must not authorize a different, writable target: the
    // namespace policy permits that target and does not enforce its hints.
    clearOverrideCache(NS);

    const result = await meta(lean, "call_tool", {
      name: "desk__modern",
      arguments: { ticket_id: "example-ticket", mode: "close" },
    });

    expect(desk.calls.map((call) => call.name)).not.toContain("write");
    expect(result.isError).toBe(true);
  });

  it("does not let the name's case or an unknown name through call_tool, and answers an unknown name through call_write_tool as a direct call does", async () => {
    const plain = await connectConsumer("s-plain-f4e");
    const lean = await connectConsumer("s-lean-f4e", LEAN);
    for (const name of ["DESK__READ", "desk__nope", "read", "nonsense"]) {
      const routed = await meta(lean, "call_tool", { name });
      expect(routed.isError).toBe(true);
      expect(textOf(routed)).toContain("call_write_tool");
    }
    expect(desk.calls).toEqual([]);
    for (const name of ["desk__nope", "nonsense"]) {
      expect(
        await outcome(() => meta(lean, "call_write_tool", { name })),
      ).toEqual(await direct(plain, name));
    }
  });

  it("answers a retryable error from call_tool when the catalog cannot be read, and still runs the tool through call_write_tool", async () => {
    const lean = await connectConsumer("s-lean-f4f", LEAN);
    sessionsByServer.set(DESK.uuid, undefined);
    const blocked = await meta(lean, "call_tool", { name: "desk__read" });
    expect(blocked.isError).toBe(true);
    expect(textOf(blocked)).toMatch(/Retry shortly/);
    expect(textOf(blocked)).toContain("call_write_tool");
    sessionsByServer.set(DESK.uuid, desk.connected);
    const ran = await meta(lean, "call_write_tool", { name: "desk__read" });
    expect(ran.isError).toBeFalsy();
  });
});

describe("call_tool runs the tool it classified, and only that tool", () => {
  /**
   * The writer answers to `alias` from now on, with no cache clear and no
   * event: a write to the table by a path that never told this process (another
   * writer on the database), so nothing here invalidated the search snapshot.
   * Alias resolution reads the table on a cache miss, so the very next call
   * sees it. When `alias` is the name of a real read-only tool, a snapshot that
   * says "read-only" is now describing a different tool than the call reaches.
   */
  const giveWriterTheAlias = (alias: string) =>
    state.mappings.push({
      namespaceUuid: NS,
      serverUuid: DESK.uuid,
      toolName: "write",
      status: "ACTIVE",
      overrideName: alias,
    });

  /** What `namespaces.updateToolOverrides` does after it writes the rows. */
  const rebindModernToWriter = () => {
    const legacy = state.mappings.find((row) => row.toolName === "legacy");
    if (!legacy) throw new Error("missing legacy mapping");
    legacy.overrideName = "former";
    giveWriterTheAlias("modern");
    clearOverrideCache(NS);
  };

  it("refuses a name that now leads to another tool, though the snapshot still says read-only and nothing told this process, and the backend never sees a call", async () => {
    const audit = auditRows();
    const lean = await connectConsumer("s-lean-id1", LEAN);
    const described = json(
      await meta(lean, "describe_tool", { names: ["desk__read"] }),
    );
    expect(described.tools[0].runs_with).toBe("call_tool");

    giveWriterTheAlias("read");

    for (const attempt of [1, 2]) {
      const refused = await meta(lean, "call_tool", {
        name: "desk__read",
        arguments: { ticket_id: "T-1", mode: "close" },
      });
      expect(refused.isError, `attempt ${attempt}`).toBe(true);
      // The agent is told the tool changed and to look again. Not a routing
      // answer to call_write_tool: it has not seen what the name means now.
      expect(textOf(refused)).toContain("changed");
      expect(textOf(refused)).toContain("search_tools");
      expect(textOf(refused)).toContain("describe_tool");
      expect(textOf(refused)).not.toContain("call_write_tool");
      expect(textOf(refused)).not.toContain("desk__");
    }
    await flush();
    // Nothing ran, and nothing was replayed.
    expect(desk.calls).toEqual([]);
    // Each refusal is an audit row, like any other refused call.
    await audit.arrived(2);
    expect(audit.rows).toHaveLength(2);
    for (const row of audit.rows) {
      expect(row).toMatchObject({
        tool_name: "read",
        success: false,
        error_code: "tool_error",
      });
    }
  });

  it("runs the new target through call_write_tool, which may run any tool the session may run", async () => {
    const lean = await connectConsumer("s-lean-id2", LEAN);
    await meta(lean, "describe_tool", { names: ["desk__read"] });
    giveWriterTheAlias("read");

    const refused = await meta(lean, "call_tool", { name: "desk__read" });
    expect(refused.isError).toBe(true);
    expect(desk.calls).toEqual([]);

    const ran = await meta(lean, "call_write_tool", { name: "desk__read" });
    expect(ran.isError).toBeFalsy();
    expect(textOf(ran)).toBe("ran write");
    expect(desk.calls.map((c) => c.name)).toEqual(["write"]);
  });

  it("runs an alias's new writer through call_write_tool after the setter ran, and sends the same name to the routing answer through call_tool", async () => {
    const lean = await connectConsumer("s-lean-id3", LEAN);
    const described = json(
      await meta(lean, "describe_tool", { names: ["desk__modern"] }),
    );
    expect(described.tools[0].runs_with).toBe("call_tool");
    rebindModernToWriter();

    const viaRead = await meta(lean, "call_tool", { name: "desk__modern" });
    expect(viaRead.isError).toBe(true);
    expect(desk.calls).toEqual([]);

    const viaWrite = await meta(lean, "call_write_tool", {
      name: "desk__modern",
      arguments: { ticket_id: "T-2" },
    });
    expect(viaWrite.isError).toBeFalsy();
    expect(desk.calls.map((c) => [c.name, c.args])).toEqual([
      ["write", { ticket_id: "T-2" }],
    ]);
  });

  it("still runs a read-only tool, by its real name and by an alias, when nothing changed since the snapshot", async () => {
    const lean = await connectConsumer("s-lean-id4", LEAN);
    await meta(lean, "search_tools", { limit: 25 });
    expect(textOf(await meta(lean, "call_tool", { name: "desk__read" }))).toBe(
      "ran read",
    );
    expect(
      textOf(await meta(lean, "call_tool", { name: "desk__modern" })),
    ).toBe("ran legacy");
    expect(desk.listings()).toBe(1);
    expect(desk.calls.map((c) => c.name)).toEqual(["read", "legacy"]);
  });

  it("makes an annotation override that turns the same target read-only into not read-only visible to call_tool as soon as the setter ran", async () => {
    const lean = await connectConsumer("s-lean-id5", LEAN);
    const before = json(
      await meta(lean, "describe_tool", { names: ["desk__read"] }),
    );
    expect(before.tools[0].runs_with).toBe("call_tool");
    const listingsBefore = desk.listings();

    // Same target, same name: only the hint changes, so no identity check can
    // see it. The snapshot is what must not outlive the setter.
    state.mappings.push({
      namespaceUuid: NS,
      serverUuid: DESK.uuid,
      toolName: "read",
      status: "ACTIVE",
      overrideAnnotations: { readOnlyHint: false },
    });
    clearOverrideCache(NS);

    // No time has passed: the snapshot is inside its one-second lifetime.
    const routed = await meta(lean, "call_tool", { name: "desk__read" });
    expect(routed.isError).toBe(true);
    expect(textOf(routed)).toContain("call_write_tool");
    expect(desk.calls).toEqual([]);
    expect(desk.listings()).toBeGreaterThan(listingsBefore);
    const after = json(
      await meta(lean, "describe_tool", { names: ["desk__read"] }),
    );
    expect(after.tools[0].runs_with).toBe("call_write_tool");
  });

  it("refuses a same-target annotation change while its catalog load is in flight, and does not cache the pre-change override", async () => {
    state.mappings.push({
      namespaceUuid: NS,
      serverUuid: DESK.uuid,
      toolName: "read",
      status: "ACTIVE",
      overrideAnnotations: { readOnlyHint: true },
    });
    const lean = await connectConsumer("s-lean-inflight-hint", LEAN);
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    let reached!: () => void;
    const held = new Promise<void>((resolve) => {
      reached = resolve;
    });
    let readLookups = 0;
    state.beforeQueryResult = async (query) => {
      if (
        query.table === "mappings" &&
        query.where["tools.name"] === "read" &&
        ++readLookups === 2
      ) {
        reached();
        await gate;
      }
    };
    const pending = meta(lean, "call_tool", { name: "desk__read" });
    await held;
    try {
      const row = state.mappings.find((mapping) => mapping.toolName === "read");
      if (!row) throw new Error("missing read mapping");
      row.overrideAnnotations = { readOnlyHint: false };
      clearOverrideCache(NS);
    } finally {
      release();
    }
    const result = await pending;
    expect.soft(result.isError).toBe(true);
    expect.soft(desk.calls).toEqual([]);
    // The late read must not refill the persistent override cache either:
    // the next call starts after the setter and has no stale catalog to use.
    const next = await meta(lean, "call_tool", { name: "desk__read" });
    expect(next.isError).toBe(true);
    expect(desk.calls).toEqual([]);
  });

  it.each(["alias resolution", "policy filter"])(
    "refuses a same-target annotation change after classification while %s waits",
    async (stage) => {
      const lean = await connectConsumer("s-lean-midcall-hint", LEAN);
      await meta(lean, "search_tools");
      let release!: () => void;
      const gate = new Promise<void>((resolve) => {
        release = resolve;
      });
      let reached!: () => void;
      const held = new Promise<void>((resolve) => {
        reached = resolve;
      });
      let armed = true;
      state.beforeQueryResult = async (query) => {
        if (
          armed &&
          query.table === "mappings" &&
          (stage === "alias resolution"
            ? query.where["ntm.override_name"] === "read"
            : query.where["tools.name"] === "read")
        ) {
          armed = false;
          reached();
          await gate;
        }
      };
      const pending = meta(lean, "call_tool", { name: "desk__read" });
      await held;
      try {
        state.mappings.push({
          namespaceUuid: NS,
          serverUuid: DESK.uuid,
          toolName: "read",
          status: "ACTIVE",
          overrideAnnotations: { readOnlyHint: false },
        });
        clearOverrideCache(NS);
      } finally {
        release();
      }
      expect((await pending).isError).toBe(true);
      expect(desk.calls).toEqual([]);
    },
  );

  it("refuses a replacement backend behind the same prefix and original tool name even without an invalidation event", async () => {
    const lean = await connectConsumer("s-lean-replaced-server", LEAN);
    await meta(lean, "describe_tool", { names: ["desk__read"] });
    const replacementUuid = "replacement-server";
    const replacement = await makeBackend("desk", [
      { ...READ, annotations: { readOnlyHint: false } },
    ]);
    state.servers.push({ uuid: replacementUuid, name: "desk" });
    state.mounts = [
      { namespaceUuid: NS, serverUuid: replacementUuid, status: "ACTIVE" },
    ];
    sessionsByServer.set(replacementUuid, replacement.connected);
    // A database write that did not signal this process. The live mount filter
    // drops the old route and the dynamic router finds the replacement.
    const result = await meta(lean, "call_tool", { name: "desk__read" });
    expect(result.isError).toBe(true);
    expect(replacement.calls).toEqual([]);
    expect(desk.calls).toEqual([]);
    const allowed = await meta(lean, "call_write_tool", { name: "desk__read" });
    expect(allowed.isError).toBeFalsy();
    expect(replacement.calls.map((call) => call.name)).toEqual(["read"]);
  });

  it.each([false, true])(
    "rechecks the read-only verdict before recovery retries (invalidated: %s)",
    async (invalidated) => {
      const audit = auditRows();
      const lean = await connectConsumer("s-lean-retry-proof", LEAN);
      await meta(lean, "search_tools");
      const fresh = await makeBackend("desk", [
        { ...READ, annotations: { readOnlyHint: !invalidated } },
      ]);
      const send = vi
        .spyOn(desk.connected.client, "request")
        .mockRejectedValueOnce(new Error("Not connected"));
      getSessionMock.mockImplementation(
        async (_sessionId: string, serverUuid: string) => {
          if (serverUuid !== DESK.uuid) return sessionsByServer.get(serverUuid);
          if (invalidated) {
            state.mappings.push({
              namespaceUuid: NS,
              serverUuid: DESK.uuid,
              toolName: "read",
              status: "ACTIVE",
              overrideAnnotations: { readOnlyHint: false },
            });
            clearOverrideCache(NS);
          }
          return fresh.connected;
        },
      );
      try {
        const result = await meta(lean, "call_tool", { name: "desk__read" });
        expect(desk.calls).toEqual([]);
        if (invalidated) {
          expect(result.isError).toBe(true);
          expect(textOf(result)).toContain("changed");
          expect(fresh.calls).toEqual([]);
        } else {
          expect(result.isError).toBeFalsy();
          expect(fresh.calls.map((call) => call.name)).toEqual(["read"]);
        }
        await audit.arrived(1);
        expect(audit.rows).toHaveLength(1);
        expect(audit.rows[0]?.success).toBe(!invalidated);
      } finally {
        send.mockRestore();
      }
    },
  );

  it("does not infer read-only hints from a failed annotation-override lookup", async () => {
    desk.tools = [READ];
    state.mappings.push({
      namespaceUuid: NS,
      serverUuid: DESK.uuid,
      toolName: "read",
      status: "ACTIVE",
      overrideAnnotations: { readOnlyHint: false },
    });
    const lean = await connectConsumer("s-lean-override-unavailable", LEAN);
    // Warm the policy filter, then lose only the annotation-override read.
    await meta(lean, "describe_tool", { names: ["desk__read"] });
    clearOverrideCache(NS);
    state.failOn = { mappings: true };
    const result = await meta(lean, "call_tool", { name: "desk__read" });
    expect(result.isError).toBe(true);
    expect(desk.calls).toEqual([]);
  });

  it("shows search and describe an alias rebinding as soon as the setter ran, inside the snapshot's lifetime", async () => {
    const lean = await connectConsumer("s-lean-id6", LEAN);
    const before = json(await meta(lean, "search_tools", { limit: 25 }));
    const names = (found: Record<string, any>): string[] =>
      found.results.map((r: { name: string }) => r.name);
    expect(names(before)).toContain("desk__modern");
    expect(names(before)).not.toContain("desk__former");

    rebindModernToWriter();

    const after = json(await meta(lean, "search_tools", { limit: 25 }));
    expect(names(after)).toContain("desk__former");
    const described = json(
      await meta(lean, "describe_tool", { names: ["desk__modern"] }),
    );
    expect(described.tools[0].runs_with).toBe("call_write_tool");
  });

  it("drops the snapshot for the namespace whose overrides were cleared, and for a clear of every namespace, and for no other", async () => {
    const lean = await connectConsumer("s-lean-id7", LEAN);
    await meta(lean, "search_tools");
    expect(desk.listings()).toBe(1);

    clearOverrideCache("another-namespace");
    await meta(lean, "search_tools");
    expect(desk.listings()).toBe(1);

    clearOverrideCache(NS);
    await meta(lean, "search_tools");
    expect(desk.listings()).toBe(2);

    clearOverrideCache();
    await meta(lean, "search_tools");
    expect(desk.listings()).toBe(3);
  });

  it("listens for override changes only while a lean session is open: a session that is not lean never does", async () => {
    expect(overrideChangeListenerCount(NS)).toBe(0);
    const plain = await connectConsumer("s-plain-id9");
    expect(overrideChangeListenerCount(NS)).toBe(0);
    const one = await connectConsumer("s-lean-id9a", LEAN);
    const two = await connectConsumer("s-lean-id9b", LEAN);
    expect(overrideChangeListenerCount(NS)).toBe(2);
    await one.close();
    expect(overrideChangeListenerCount(NS)).toBe(1);
    await two.close();
    await plain.close();
    expect(overrideChangeListenerCount(NS)).toBe(0);
  });

  it.each([
    ["one session", false],
    ["two sessions of the namespace", true],
  ])(
    "pin: keeps each concurrent call's recorded target to itself across %s",
    async (_label, separateSessions) => {
      const first = await connectConsumer("s-lean-id8a", LEAN);
      const second = separateSessions
        ? await connectConsumer("s-lean-id8b", LEAN)
        : first;
      // Hold the first call between its read-only verdict and its alias
      // resolution. That resolution is the one lookup by alias name `read` the
      // chain makes, so the hold sits exactly there.
      let release!: () => void;
      const gate = new Promise<void>((resolve) => {
        release = resolve;
      });
      let reached!: () => void;
      const held = new Promise<void>((resolve) => {
        reached = resolve;
      });
      let armed = true;
      state.beforeQueryResult = async (query) => {
        if (
          armed &&
          query.table === "mappings" &&
          query.where["ntm.override_name"] === "read"
        ) {
          armed = false;
          reached();
          await gate;
        }
      };

      const slow = meta(first, "call_tool", { name: "desk__read" });
      await held;
      // While it waits, another call records a different target and finishes.
      const fast = await meta(second, "call_tool", { name: "desk__modern" });
      expect(textOf(fast)).toBe("ran legacy");
      release();

      // Had the recorded target been shared, this one would be compared with
      // the other call's and refused.
      expect(textOf(await slow)).toBe("ran read");
      expect(desk.calls.map((c) => c.name)).toEqual(["legacy", "read"]);
    },
  );
});

/**
 * The lost-session defect, driven through the real proxy. A warm lean session has
 * a snapshot; the backend's MCP session is then lost. The first send of a
 * `call_tool` gets the replay-safe HTTP 404 answer (the backend ran nothing),
 * the session recovery retires the pooled connection, and the real pool fires
 * the backend client's list-changed subscribers, which drops the snapshot and
 * so revokes the verdict. Nothing about the tool changed, and the replay used
 * to refuse it as changed. It must now look at a fresh listing first.
 *
 * "guard" cases pass on the parent by design.
 */
describe("a read-only verdict revoked by a backend reconnect is re-verified once against a fresh listing", () => {
  const SESSION_NOT_FOUND = () =>
    new StreamableHTTPError(
      404,
      'Error POSTing to endpoint: {"jsonrpc":"2.0","error":{"code":-32001,"message":"Session not found"},"id":null}',
    );
  const ALL = [READ, WRITE, BARE, SECRET, LEGACY];

  /**
   * The lost session: `tools/call` on the old client answers the 404 envelope
   * (and is counted), the pool's invalidation does what the real one does
   * (fires the doomed client's subscribers without awaiting them, then drops
   * it), and the next acquisition is a replacement backend that lists
   * `recovered`. The mock pool alone makes invalidation a no-op, which does not
   * reproduce the defect.
   */
  async function loseBackendSession(recovered: Tool[] = ALL) {
    const replacement = await makeBackend("desk", recovered);
    const stale = desk.connected;
    const real = stale.client.request.bind(stale.client);
    const staleToolCalls = { count: 0 };
    vi.spyOn(stale.client, "request").mockImplementation(((
      message: { method: string },
      schema: never,
      options: never,
    ) => {
      if (message.method === "tools/call") {
        staleToolCalls.count += 1;
        return Promise.reject(SESSION_NOT_FOUND());
      }
      return real(message as never, schema, options);
    }) as never);
    pool.isPooledClient.mockImplementation(
      (_serverUuid: string, client: unknown) => client === stale,
    );
    pool.invalidateServerConnection.mockImplementation(
      async (_sessionId: string, serverUuid: string) => {
        const subscribers = [...stale.listChangedSubscribers];
        stale.listChangedSubscribers.clear();
        for (const subscriber of subscribers) void subscriber();
        sessionsByServer.set(serverUuid, replacement.connected);
      },
    );
    const sent = vi.spyOn(replacement.connected.client, "request");
    return {
      replacement,
      staleToolCalls,
      /** Requests of one method the replacement backend's client was asked to send. */
      sentTo: (method: string) =>
        sent.mock.calls.filter(([message]) => message.method === method).length,
    };
  }

  /**
   * The next listing throws a plain error that is not the listing's own
   * retryable one (those a listing turns into an unavailable catalog). Its text
   * is one a tool-call replay recognises, which is the point: it comes from the
   * re-verification, not from a backend request, and must not be read as one.
   * The listing's one unguarded read of the pool is the seam; no backend
   * failure reaches the caller as a plain error.
   */
  const failNextListing = () =>
    pool.getPoolStatus.mockImplementationOnce(() => {
      throw new Error("Not connected");
    });

  /**
   * Holds the next call at the policy filter's mount-status lookup: after the
   * early check, before the router. With the caches warm by a search, that is
   * the only table read a call makes. `held()` answers whether it got there.
   */
  function holdAtPolicyFilter() {
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    let reachedFlag = false;
    let armed = true;
    state.beforeQueryResult = async (query) => {
      if (
        armed &&
        query.table === "servers" &&
        query.where["nsm.status"] === "ACTIVE"
      ) {
        armed = false;
        reachedFlag = true;
        await gate;
      }
    };
    return {
      held: async () => {
        for (let turn = 0; turn < 200 && !reachedFlag; turn += 1) await flush();
        return reachedFlag;
      },
      release,
    };
  }

  it("runs the read-only tool once on the recovered backend, from a fresh listing, after the first send was answered 404", async () => {
    const audit = auditRows();
    const lean = await connectConsumer("s-lean-reverify", LEAN);
    await meta(lean, "search_tools");
    const { replacement, staleToolCalls, sentTo } = await loseBackendSession();

    const result = await meta(lean, "call_tool", {
      name: "desk__read",
      arguments: { query: "x" },
    });

    expect(result.isError).toBeFalsy();
    expect(textOf(result)).toBe("ran read");
    // The first send went to the dead session and the backend ran nothing.
    expect(staleToolCalls.count).toBe(1);
    expect(desk.calls).toEqual([]);
    expect(pool.invalidateServerConnection).toHaveBeenCalledTimes(1);
    // The replay ran it exactly once, after one listing of the recovered backend.
    expect(replacement.calls.map((call) => call.name)).toEqual(["read"]);
    expect(sentTo("tools/call")).toBe(1);
    expect(replacement.listings()).toBe(1);
    await audit.arrived(1);
    await flush();
    expect(audit.rows).toHaveLength(1);
    expect(audit.rows[0]).toMatchObject({
      tool_name: "read",
      success: true,
    });
    // The verdict, its fresh closure and its callback lived on this call's own
    // context only.
    expect(
      Object.keys(lean.handlerContext).filter((key) =>
        /^(classified|reverify)/.test(key),
      ),
    ).toEqual([]);
  });

  it("refuses the call as changed when the recovered backend lists the same tool as not read-only, runs nothing, and sends no second tool call", async () => {
    const audit = auditRows();
    const lean = await connectConsumer("s-lean-reverify-writer", LEAN);
    await meta(lean, "search_tools");
    const { replacement, staleToolCalls, sentTo } = await loseBackendSession([
      { ...READ, annotations: { readOnlyHint: false } },
      WRITE,
    ]);

    const result = await meta(lean, "call_tool", { name: "desk__read" });

    expect(result.isError).toBe(true);
    expect(textOf(result)).toContain("changed");
    expect(textOf(result)).not.toContain("call_write_tool");
    expect(staleToolCalls.count).toBe(1);
    expect(replacement.calls).toEqual([]);
    expect(sentTo("tools/call")).toBe(0);
    // It looked, once, instead of refusing blind.
    expect(replacement.listings()).toBe(1);
    await audit.arrived(1);
    await flush();
    expect(audit.rows).toHaveLength(1);
    expect(audit.rows[0]).toMatchObject({
      tool_name: "read",
      success: false,
      error_code: "tool_error",
    });
  });

  it("runs an alias's read-only tool again after the reconnect, under the alias the client used", async () => {
    const lean = await connectConsumer("s-lean-reverify-alias", LEAN);
    await meta(lean, "search_tools");
    const { replacement } = await loseBackendSession();

    const result = await meta(lean, "call_tool", { name: "desk__modern" });

    expect(textOf(result)).toBe("ran legacy");
    expect(replacement.calls.map((call) => call.name)).toEqual(["legacy"]);
    expect(replacement.listings()).toBe(1);
  });

  it("refuses a fresh listing from a replacement UUID even when recovery selected the original UUID and the full name is unchanged", async () => {
    const audit = auditRows();
    const lean = await connectConsumer("s-lean-reverify-new-backend", LEAN);
    await meta(lean, "search_tools");
    const { replacement, staleToolCalls, sentTo } = await loseBackendSession();
    const replacementServer = { uuid: "server-desk-replacement", name: "desk" };
    getSessionMock.mockClear();
    getSessionMock.mockImplementation(
      async (_sessionId: string, serverUuid: string) => {
        if (serverUuid === DESK.uuid) {
          // Recovery already selected the original UUID. Replace the mount
          // only now, so the fresh listing sees another backend while the
          // router's selected UUID still matches the recorded verdict. Only
          // the callback's fresh-listing UUID comparison can reject it.
          state.servers = [replacementServer];
          state.mounts = [
            {
              namespaceUuid: NS,
              serverUuid: replacementServer.uuid,
              status: "ACTIVE",
            },
          ];
          sessionsByServer.set(replacementServer.uuid, replacement.connected);
          clearFilterCache();
          clearOverrideCache(NS);
        }
        return sessionsByServer.get(serverUuid);
      },
    );

    const result = await meta(lean, "call_tool", { name: "desk__read" });

    expect(result.isError).toBe(true);
    expect(textOf(result)).toContain("changed");
    expect(staleToolCalls.count).toBe(1);
    expect(pool.invalidateServerConnection).toHaveBeenCalledTimes(1);
    expect(getSessionMock.mock.calls.map(([, uuid]) => uuid)).toEqual([
      DESK.uuid,
      replacementServer.uuid,
    ]);
    expect(replacement.listings()).toBe(1);
    expect(replacement.calls).toEqual([]);
    expect(sentTo("tools/call")).toBe(0);
    await audit.arrived(1);
    expect(audit.rows).toHaveLength(1);
    expect(audit.rows[0]).toMatchObject({ tool_name: "read", success: false });
  });

  it("refuses an alias that was rebound to a writer while the call waited, though the target it was classified as is still listed read-only", async () => {
    const lean = await connectConsumer("s-lean-reverify-rebound", LEAN);
    await meta(lean, "search_tools");
    const { held, release } = holdAtPolicyFilter();
    const listingsBefore = desk.listings();
    const pending = meta(lean, "call_tool", { name: "desk__modern" });
    expect(await held(), "the call reached the mount check").toBe(true);
    // The setter: `modern` now names the writer. The call already resolved the
    // alias to the old target, so only the revocation is left to notice it.
    const legacy = state.mappings.find((row) => row.toolName === "legacy");
    if (!legacy) throw new Error("missing legacy mapping");
    legacy.overrideName = "former";
    state.mappings.push({
      namespaceUuid: NS,
      serverUuid: DESK.uuid,
      toolName: "write",
      status: "ACTIVE",
      overrideName: "modern",
    });
    clearOverrideCache(NS);
    release();

    const result = await pending;
    expect(result.isError).toBe(true);
    expect(textOf(result)).toContain("changed");
    expect(desk.calls).toEqual([]);
    expect(desk.listings()).toBe(listingsBefore + 1);
  });

  it("refuses an alias that was rebound to ANOTHER read-only tool while the call waited: a fresh read-only hint is not enough, the alias must still stand for the tool it was classified as", async () => {
    const lean = await connectConsumer(
      "s-lean-reverify-readonly-rebound",
      LEAN,
    );
    await meta(lean, "search_tools");
    const { held, release } = holdAtPolicyFilter();
    const listingsBefore = desk.listings();
    const pending = meta(lean, "call_tool", { name: "desk__modern" });
    expect(await held(), "the call reached the mount check").toBe(true);
    // `modern` now names `read`, which is read-only too, so every hint the
    // fresh listing shows for the name is as good as before.
    const legacy = state.mappings.find((row) => row.toolName === "legacy");
    if (!legacy) throw new Error("missing legacy mapping");
    legacy.overrideName = "former";
    state.mappings.push({
      namespaceUuid: NS,
      serverUuid: DESK.uuid,
      toolName: "read",
      status: "ACTIVE",
      overrideName: "modern",
    });
    clearOverrideCache(NS);
    release();

    const result = await pending;
    expect(result.isError).toBe(true);
    expect(textOf(result)).toContain("changed");
    expect(desk.calls).toEqual([]);
    expect(desk.listings()).toBe(listingsBefore + 1);
  });

  it("answers the unavailable answer, not the changed one, when the fresh listing cannot reach any backend, and sends nothing", async () => {
    const lean = await connectConsumer("s-lean-reverify-down", LEAN);
    await meta(lean, "search_tools");
    const { replacement } = await loseBackendSession();
    // The recovered session cannot be acquired for the listing (the listing's
    // own retryable error), though the replay's own acquisition succeeded.
    let acquisitions = 0;
    getSessionMock.mockImplementation(
      async (_sessionId: string, serverUuid: string) => {
        acquisitions += 1;
        // 1: the recovery's reacquire. 2: the listing, which finds no session.
        return acquisitions === 2
          ? undefined
          : sessionsByServer.get(serverUuid);
      },
    );

    const result = await meta(lean, "call_tool", { name: "desk__read" });

    expect(result.isError).toBe(true);
    expect(textOf(result)).toContain("catalog could not be read");
    expect(textOf(result)).not.toContain("changed");
    expect(replacement.calls).toEqual([]);
  });

  it.each([
    {
      label: "its first send",
      replay: false,
      drive: async (lean: Consumer) => {
        await meta(lean, "search_tools");
        const { held, release } = holdAtPolicyFilter();
        const pending = outcome(() =>
          meta(lean, "call_tool", { name: "desk__read" }),
        );
        expect(await held(), "the call reached the mount check").toBe(true);
        // The reconnect's invalidation, with nothing else changed.
        clearOverrideCache(NS);
        failNextListing();
        release();
        return { failed: await pending, replacementCalls: undefined };
      },
    },
    {
      label: "its replay after a lost session",
      replay: true,
      drive: async (lean: Consumer) => {
        await meta(lean, "search_tools");
        const lost = await loseBackendSession();
        failNextListing();
        const failed = await outcome(() =>
          meta(lean, "call_tool", { name: "desk__read" }),
        );
        return { failed, replacementCalls: lost.sentTo("tools/call") };
      },
    },
  ])(
    "lets an unexpected failure of the re-verification out as it is, with nothing sent and no further recovery, though its text is one a replay recognises: $label",
    async ({ replay, drive }) => {
      const audit = auditRows();
      const lean = await connectConsumer("s-lean-reverify-fail", LEAN);
      const toolCallsOnDesk = vi.spyOn(desk.connected.client, "request");
      vi.mocked(logger.error).mockClear();

      const { failed, replacementCalls } = await drive(lean);

      expect(failed.result).toBeUndefined();
      expect(failed.error).toContain("Not connected");
      expect(desk.calls).toEqual([]);
      if (replacementCalls !== undefined) expect(replacementCalls).toBe(0);
      // A replay-safe reading of that text would have retired the pooled
      // connection (again) and sent the call once more.
      expect(pool.invalidateServerConnection).toHaveBeenCalledTimes(
        replay ? 1 : 0,
      );
      // The replay has no further recovery, but its backend-error catch would
      // misreport a failed listing as a failed tools/call. Keep the decision
      // outside that catch as well as the first send's recovery detector.
      expect(logger.error).not.toHaveBeenCalledWith(
        expect.stringContaining("after session re-initialize:"),
        expect.anything(),
      );
      if (!replay) {
        expect(
          toolCallsOnDesk.mock.calls.filter(
            ([message]) => message.method === "tools/call",
          ),
        ).toHaveLength(0);
      }
      await audit.arrived(1);
      await flush();
      expect(audit.rows).toHaveLength(1);
      expect(audit.rows[0]).toMatchObject({
        tool_name: "read",
        success: false,
      });
    },
  );

  it.each([
    [
      "call_write_tool through a lean session",
      true,
      (lean: Consumer) => meta(lean, "call_write_tool", { name: "desk__read" }),
    ],
    [
      "a direct call through a lean session",
      true,
      (lean: Consumer) => meta(lean, "desk__read"),
    ],
    [
      "a direct call through a session that is not lean",
      false,
      (plain: Consumer) => meta(plain, "desk__read"),
    ],
  ])(
    "guard: %s replays once after the lost session and never re-verifies: no listing for it and no log line about it",
    async (_label, isLean, call) => {
      const sinks = eventSinks();
      const consumer = await connectConsumer(
        isLean ? "s-lean-unchanged" : "s-plain-unchanged",
        isLean ? LEAN : undefined,
      );
      if (isLean) await meta(consumer, "search_tools");
      else await consumer.client.listTools();
      const { replacement, staleToolCalls, sentTo } =
        await loseBackendSession();

      const result = await call(consumer);

      expect(textOf(result)).toBe("ran read");
      expect(staleToolCalls.count).toBe(1);
      expect(replacement.calls.map((entry) => entry.name)).toEqual(["read"]);
      expect(sentTo("tools/call")).toBe(1);
      expect(pool.invalidateServerConnection).toHaveBeenCalledTimes(1);
      // The only listing the recovered backend answers is the audit's own
      // shaping of the call, the same one a plain call costs.
      expect(replacement.listings()).toBeLessThanOrEqual(1);
      expect(
        sinks.live.filter((entry) => /re-verif/.test(entry.message)),
      ).toEqual([]);
    },
  );

  it.each([
    ["a request timeout", () => new McpError(-32001, "Request timed out")],
    [
      "a 5xx answer",
      () =>
        new StreamableHTTPError(502, "Error POSTing to endpoint: Bad Gateway"),
    ],
  ])(
    "guard: %s on the first send of call_tool still surfaces with no replay, no recovery and no re-verification",
    async (_label, failure) => {
      const lean = await connectConsumer("s-lean-no-replay", LEAN);
      await meta(lean, "search_tools");
      const real = desk.connected.client.request.bind(desk.connected.client);
      let toolCalls = 0;
      vi.spyOn(desk.connected.client, "request").mockImplementation(((
        message: { method: string },
        schema: never,
        options: never,
      ) => {
        if (message.method === "tools/call") {
          toolCalls += 1;
          return Promise.reject(failure());
        }
        return real(message as never, schema, options);
      }) as never);
      const listingsBefore = desk.listings();
      const result = await outcome(() =>
        meta(lean, "call_tool", { name: "desk__read" }),
      );
      expect(result.error).toBeDefined();
      expect(toolCalls).toBe(1);
      expect(pool.invalidateServerConnection).not.toHaveBeenCalled();
      expect(desk.listings()).toBe(listingsBefore);
    },
  );
});

describe("a direct real-name call in a lean session", () => {
  it("still works with no prior search and after one, and a curated-off tool is refused as before", async () => {
    const plain = await connectConsumer("s-plain-dr");
    const lean = await connectConsumer("s-lean-dr", LEAN);
    const cold = await direct(lean, "desk__read", { query: "x" });
    expect(cold).toEqual(await direct(plain, "desk__read", { query: "x" }));
    await meta(lean, "search_tools");
    const warm = await direct(lean, "desk__write", { ticket_id: "T-3" });
    expect(warm).toEqual(
      await direct(plain, "desk__write", { ticket_id: "T-3" }),
    );
    const refused = await direct(lean, "desk__secret");
    expect(refused).toEqual(await direct(plain, "desk__secret"));
    expect(textOf((refused as { result: unknown }).result)).toContain(
      "marked as inactive",
    );
  });
});

describe("audit argument shapes", () => {
  it("learns the real tool's parameters from the search listing and does not list again for the call", async () => {
    const audit = auditRows();
    const lean = await connectConsumer("s-lean-sh1", LEAN);
    await meta(lean, "search_tools");
    expect(desk.listings()).toBe(1);
    await lean.client.listTools();
    expect(desk.listings()).toBe(1);
    await meta(lean, "call_tool", {
      name: "desk__read",
      arguments: { query: "x", mode: "get" },
    });
    await audit.arrived(1);
    expect(audit.rows[0]?.args_shape).toMatchObject({
      keys: ["mode", "query"],
      sel: { mode: "get" },
    });
    // The registry held the real tools, so no audit listing refilled it.
    expect(desk.listings()).toBe(1);
    expect(JSON.stringify(audit.rows[0]?.args_shape)).not.toMatch(
      /"name"|"arguments"/,
    );
  });

  it("shapes a call_write_tool with no prior search the way the direct call is shaped, at the same listing cost", async () => {
    const audit = auditRows();
    const plain = await connectConsumer("s-plain-sh2");
    await direct(plain, "desk__write", { ticket_id: "T-4", mode: "close" });
    await audit.arrived(1);
    const directListings = desk.listings();
    desk.calls.length = 0;
    const before = desk.listings();
    const lean = await connectConsumer("s-lean-sh2", LEAN);
    await meta(lean, "call_write_tool", {
      name: "desk__write",
      arguments: { ticket_id: "T-4", mode: "close" },
    });
    await audit.arrived(2);
    expect(audit.rows[1]?.args_shape).toEqual(audit.rows[0]?.args_shape);
    expect(audit.rows[1]?.args_shape).toMatchObject({
      keys: ["mode", "ticket_id"],
    });
    expect(desk.listings() - before).toBe(directListings);
  });
});

describe("list_changed", () => {
  it("sends a lean session no notification, but clears the sync cache entry and the search snapshot, so the next search sees the change", async () => {
    const lean = await connectConsumer("s-lean-lc", LEAN);
    const plain = await connectConsumer("s-plain-lc");
    await plain.client.listTools();
    const first = json(await meta(lean, "search_tools", { limit: 25 }));
    expect(first.meta.total_tools).toBe(4);
    expect(toolsSyncCache.hasChanged(DESK.uuid, desk.tools)).toBe(false);
    const listingsBefore = desk.listings();
    const added: Tool = {
      name: "extra",
      description: "Added later",
      inputSchema: { type: "object", properties: {} },
    };
    desk.tools = [...desk.tools, added];
    // A backend list_changed reaches every subscriber attached to its client.
    await Promise.all(
      [...desk.connected.listChangedSubscribers].map((s) => s()),
    );
    await lean.client.ping();
    await plain.client.ping();
    expect(lean.listChanged()).toBe(0);
    expect(plain.listChanged()).toBe(1);
    expect(toolsSyncCache.hasChanged(DESK.uuid, desk.tools)).toBe(true);
    // Inside the snapshot's lifetime, yet it re-lists and sees the new tool.
    const second = json(await meta(lean, "search_tools", { limit: 25 }));
    expect(second.meta.total_tools).toBe(5);
    expect(desk.listings()).toBeGreaterThan(listingsBefore);
  });

  it("answers a mount change with no notification, drops the snapshot, and refuses a later call to that server", async () => {
    const lean = await connectConsumer("s-lean-mc", LEAN);
    const plain = await connectConsumer("s-plain-mc");
    await plain.client.listTools();
    await meta(lean, "search_tools");
    const mount = state.mounts[0];
    if (mount) mount.status = "INACTIVE";
    notifyNamespaceMountChange(NS, DESK.uuid);
    await lean.client.ping();
    await plain.client.ping();
    expect(lean.listChanged()).toBe(0);
    expect(plain.listChanged()).toBe(1);
    const refused = await meta(lean, "call_write_tool", {
      name: "desk__read",
    });
    expect(refused.isError).toBe(true);
    expect(desk.calls).toEqual([]);
  });

  it("arms no owed re-notify watch and probes no backend for a degraded lean listing, where a session that is not lean arms one", async () => {
    state.servers = [DESK, GHOST];
    state.mounts = [
      ...state.mounts,
      { namespaceUuid: NS, serverUuid: GHOST.uuid, status: "ACTIVE" },
    ];
    sessionsByServer.set(GHOST.uuid, undefined);
    const lean = await connectConsumer("s-lean-ow", LEAN);
    const searched = json(await meta(lean, "search_tools", { limit: 25 }));
    expect(searched.meta.unavailable_server_count).toBe(1);
    expect(toolsListRenotifyWatch.watchedServerCount()).toBe(0);
    expect(probeMock).not.toHaveBeenCalled();
    const plain = await connectConsumer("s-plain-ow");
    await plain.client.listTools();
    expect(toolsListRenotifyWatch.watchedServerCount()).toBe(1);
    await plain.close();
    expect(toolsListRenotifyWatch.watchedServerCount()).toBe(0);
    expect(namespaceMountListenerCount(NS)).toBeGreaterThanOrEqual(1);
  });
});

describe("failures", () => {
  it("answers a retryable tool error from search and describe when no backend can be reached, while tools/list still lists the four tools", async () => {
    sessionsByServer.set(DESK.uuid, undefined);
    const lean = await connectConsumer("s-lean-fx", LEAN);
    const searched = await meta(lean, "search_tools", { query: "ticket" });
    expect(searched.isError).toBe(true);
    expect(textOf(searched)).toMatch(/Retry shortly/);
    const described = await meta(lean, "describe_tool", {
      names: ["desk__read"],
    });
    expect(described.isError).toBe(true);
    expect((await lean.client.listTools()).tools.map((t) => t.name)).toEqual(
      NAMES_OF_LEAN,
    );
    // Back up: the next search works without a reconnect.
    sessionsByServer.set(DESK.uuid, desk.connected);
    expect(
      (await meta(lean, "search_tools", { query: "ticket" })).isError,
    ).toBeFalsy();
  });

  it("refuses malformed search and describe arguments with a constant message that echoes nothing", async () => {
    const lean = await connectConsumer("s-lean-bad2", LEAN);
    const probe = "echo-me-if-you-dare";
    for (const [tool, args] of [
      ["search_tools", { query: { probe } }],
      ["search_tools", { limit: probe }],
      ["describe_tool", { names: probe }],
      ["describe_tool", {}],
    ] as const) {
      const answer = await meta(lean, tool, args as Record<string, unknown>);
      expect(answer.isError).toBe(true);
      expect(textOf(answer)).not.toContain(probe);
    }
    expect(getSessionMock).not.toHaveBeenCalled();
  });
});

describe("describe_tool", () => {
  it("returns the annotations after the namespace override, and the output schema only when asked", async () => {
    state.mappings.push({
      namespaceUuid: NS,
      serverUuid: DESK.uuid,
      toolName: "write",
      status: "ACTIVE",
      overrideAnnotations: { destructiveHint: true, idempotentHint: true },
    });
    const lean = await connectConsumer("s-lean-ds", LEAN);
    const plainAnswer = json(
      await meta(lean, "describe_tool", { names: ["desk__write"] }),
    );
    expect(plainAnswer.tools[0].annotations).toEqual({
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: true,
    });
    expect(plainAnswer.tools[0].destructive).toBe(true);
    expect(plainAnswer.tools[0].output_schema).toBeUndefined();
    const withOutput = json(
      await meta(lean, "describe_tool", {
        names: ["desk__write"],
        include_output_schema: true,
      }),
    );
    expect(withOutput.tools[0].output_schema).toEqual(WRITE.outputSchema);
  });

  it("behaves as lean when the trim is set as well", async () => {
    const lean = await connectConsumer("s-lean-trim", {
      toolListing: "lean",
      omitOutputSchemas: true,
    });
    expect((await lean.client.listTools()).tools.map((t) => t.name)).toEqual(
      NAMES_OF_LEAN,
    );
    const withOutput = json(
      await meta(lean, "describe_tool", {
        names: ["desk__write"],
        include_output_schema: true,
      }),
    );
    expect(withOutput.tools[0].output_schema).toEqual(WRITE.outputSchema);
  });
});

describe("the catalog snapshot", () => {
  it("costs one backend listing for parallel searches, none inside a second, and one more after it, with describe on the same snapshot", async () => {
    const lean = await connectConsumer("s-lean-sf", LEAN);
    const [a, b] = await Promise.all([
      meta(lean, "search_tools", { query: "ticket" }),
      meta(lean, "search_tools", { query: "update" }),
    ]);
    expect(a.isError).toBeFalsy();
    expect(b.isError).toBeFalsy();
    expect(desk.listings()).toBe(1);
    setNow(999);
    await meta(lean, "search_tools", { query: "read" });
    await meta(lean, "describe_tool", { names: ["desk__read"] });
    expect(desk.listings()).toBe(1);
    setNow(1000);
    await meta(lean, "search_tools", { query: "read" });
    expect(desk.listings()).toBe(2);
    await meta(lean, "describe_tool", { names: ["desk__read"] });
    expect(desk.listings()).toBe(2);
  });

  it("keeps two sessions' snapshots apart: each lean session lists for itself", async () => {
    const one = await connectConsumer("s-lean-two-1", LEAN);
    const two = await connectConsumer("s-lean-two-2", LEAN);
    await meta(one, "search_tools");
    await meta(two, "search_tools");
    expect(desk.listings()).toBe(2);
  });
});

describe("how a lean session presents itself", () => {
  const sha = (value: unknown) =>
    createHash("sha256").update(JSON.stringify(value)).digest("hex");

  it("starts the instructions with the workflow paragraph and puts the administrator's text after a blank line", async () => {
    const lean = await connectConsumer("s-lean-i1", {
      ...LEAN,
      title: "Desk (lean)",
      instructions: "Prefer read-only tools.",
    });
    expect(lean.client.getInstructions()).toBe(
      `${LEAN_INSTRUCTIONS}\n\nPrefer read-only tools.`,
    );
    expect(lean.client.getServerVersion()).toEqual({
      name: `metamcp-unified-${NS}`,
      version: "1.0.0",
      title: "Desk (lean)",
    });
    const bare = await connectConsumer("s-lean-i2", LEAN);
    expect(bare.client.getInstructions()).toBe(LEAN_INSTRUCTIONS);
  });

  it("advertises the capability set the build always advertised, so the hash that gates recovery does not move", async () => {
    const lean = await connectConsumer("s-lean-cap", LEAN);
    expect(lean.client.getServerCapabilities()).toEqual(GATEWAY_CAPABILITIES);
    expect(sha(GATEWAY_CAPABILITIES)).toBe(BASE_BUILD_CAPABILITY_DIGEST);
    expect(sha(BASE_BUILD_CAPABILITIES)).toBe(BASE_BUILD_CAPABILITY_DIGEST);
    expect(GATEWAY_CAPABILITY_HASH).toBe(BASE_BUILD_CAPABILITY_DIGEST);
    expect(GATEWAY_CAPABILITIES.tools?.listChanged).toBe(true);
  });

  it("serves the full listing when only the lean switch is off, keeping the title, the instructions and the trim", async () => {
    process.env.MCP_LEAN_LISTING = "off";
    const session = await connectConsumer("s-lean-off", {
      title: "Desk",
      instructions: "Prefer read-only tools.",
      toolListing: "lean",
      omitOutputSchemas: true,
    });
    const listed = (await session.client.listTools()).tools;
    expect(listed.map((t) => t.name).sort()).toEqual([
      "desk__bare",
      "desk__modern",
      "desk__read",
      "desk__write",
    ]);
    expect(listed.every((t) => t.outputSchema === undefined)).toBe(true);
    expect(session.client.getInstructions()).toBe("Prefer read-only tools.");
    expect(session.client.getServerVersion()?.title).toBe("Desk");
    // And the meta names are the unknown names they are on any full listing.
    expect((await direct(session, "search_tools", {})).error).toContain(
      "Invalid tool name format: search_tools",
    );
  });

  it("serves the full listing and no text when the master switch is off, whatever the session asked for", async () => {
    process.env.MCP_ENDPOINT_PRESENTATION = "off";
    const session = await connectConsumer("s-master-off", {
      title: "Desk",
      instructions: "Prefer read-only tools.",
      toolListing: "lean",
      omitOutputSchemas: true,
    });
    expect(session.client.getInstructions()).toBeUndefined();
    expect(session.client.getServerVersion()).toEqual({
      name: `metamcp-unified-${NS}`,
      version: "1.0.0",
    });
    expect((await session.client.listTools()).tools).toHaveLength(4);
    expect(
      (await session.client.listTools()).tools.map((t) => t.name),
    ).not.toContain("search_tools");
  });
});
