/**
 * Retired-tool redirect, timeout hint and audit classification, driven end to
 * end through `createServer`.
 *
 * A real SDK consumer `Client` talks to the gateway's own `Server`. Backend
 * sessions are SDK `Client`/`Server` pairs over `InMemoryTransport`, and the
 * backend counts how many times its one real tool actually executed. The audit
 * middleware and the retired-tool and timeout-hint middleware are the REAL
 * ones; only the filter (which needs the database) is replaced by a small fake
 * that reproduces its fail-closed denial for an unresolvable server prefix, and
 * the override middleware is pass-through.
 *
 * What it pins:
 *   - a retired name gets the redirect and the backend executes nothing;
 *   - a name that is in the map but IS served still executes exactly once;
 *   - the three ways a retired call fails today all end in the redirect;
 *   - a timeout on a listed name is neither rewritten as a redirect nor
 *     replayed, and carries the adjudication hint;
 *   - tools/list is unchanged;
 *   - the audit rows say tool_retired, unknown_tool and inband_error.
 */
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  CallToolRequestSchema,
  CallToolResult,
  CallToolResultSchema,
  ErrorCode,
  ListToolsRequestSchema,
  ListToolsResultSchema,
  McpError,
  Tool,
  ToolListChangedNotificationSchema,
} from "@modelcontextprotocol/sdk/types.js";
import {
  afterAll,
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";

import type { ConnectedClient } from "./client";
import type {
  CallToolHandler,
  ListToolsHandler,
} from "./metamcp-middleware/functional-middleware";

const {
  getSessionMock,
  invalidateServerConnectionMock,
  findServersMock,
  auditRepoImports,
  config,
} = vi.hoisted(() => ({
  getSessionMock: vi.fn(),
  invalidateServerConnectionMock: vi.fn(),
  findServersMock: vi.fn(),
  auditRepoImports: { count: 0 },
  config: { mcpTimeoutMs: 5_000, listedAlias: undefined as string | undefined },
}));

vi.mock("@/utils/logger", () => ({
  default: { error: vi.fn(), warn: vi.fn(), info: vi.fn(), debug: vi.fn() },
}));

// A pass-through spy: the tests read whether an audit cause was built at all.
vi.mock("./audit-listing-log", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./audit-listing-log")>();
  return {
    ...actual,
    describeListingFailure: vi.fn(actual.describeListingFailure),
  };
});

vi.mock("../../db", () => ({ db: {} }));
vi.mock("../../db/schema", () => ({}));
vi.mock("../../db/repositories/namespaces.repo", () => ({
  namespacesRepository: { findServersForNamespaceToolName: findServersMock },
}));
vi.mock("../../db/repositories/oauth-sessions.repo", () => ({
  oauthSessionsRepository: {},
}));
// Nothing in this file should import the real audit repository: it needs the
// database mocked away above. The audit sink is pinned in beforeEach so the
// lazy import never starts, and the afterAll below fails the file if anything
// started it anyway.
vi.mock("../../db/repositories/tool-call-audit.repo", () => {
  auditRepoImports.count += 1;
  return { toolCallAuditRepository: { record: vi.fn() } };
});
vi.mock("../../trpc/tools.impl", () => ({
  toolsImplementations: { sync: vi.fn().mockResolvedValue(undefined) },
}));

vi.mock("../config.service", () => ({
  configService: {
    getMcpResetTimeoutOnProgress: async () => false,
    getMcpTimeout: async () => config.mcpTimeoutMs,
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
    // No additional mounted owner was omitted from the routable set.
    getNamespaceServerStates: vi.fn(async () => []),
  };
});

vi.mock("./mcp-server-pool", () => ({
  mcpServerPool: {
    getSession: getSessionMock,
    invalidateServerConnection: invalidateServerConnectionMock,
    cleanupSession: vi.fn(),
    // tools/list only: a warm pool, so it does not try to warm one up.
    getPoolStatus: () => ({ idle: 1, active: 1 }),
  },
}));

// The filter needs the database. This fake reproduces only what matters here:
// the fail-closed denial for a server prefix that no longer resolves.
vi.mock("./metamcp-middleware/filter-tools.functional", () => ({
  createFilterCallToolMiddleware:
    () =>
    (
      next: (
        request: { params: { name: string } },
        context: unknown,
      ) => Promise<CallToolResult>,
    ) =>
    async (request: { params: { name: string } }, context: unknown) => {
      if (request.params.name.startsWith("gone__")) {
        return {
          isError: true,
          content: [
            {
              type: "text",
              text: `Access denied to tool "${request.params.name}": server could not be resolved`,
            },
          ],
        } satisfies CallToolResult;
      }
      return next(request, context);
    },
  createFilterListToolsMiddleware: () => (next: unknown) => next,
}));
vi.mock("./metamcp-middleware/tool-overrides.functional", () => ({
  createToolOverridesCallToolMiddleware:
    () =>
    (next: CallToolHandler) =>
    async (
      request: Parameters<CallToolHandler>[0],
      context: Parameters<CallToolHandler>[1],
    ) =>
      next(
        config.listedAlias && request.params.name === config.listedAlias
          ? {
              ...request,
              params: { ...request.params, name: "ninja__list_things" },
            }
          : request,
        context,
      ),
  createToolOverridesListToolsMiddleware:
    () =>
    (next: ListToolsHandler) =>
    async (
      request: Parameters<ListToolsHandler>[0],
      context: Parameters<ListToolsHandler>[1],
    ) => {
      const result = await next(request, context);
      return {
        ...result,
        tools: result.tools.map((tool) =>
          config.listedAlias ? { ...tool, name: config.listedAlias } : tool,
        ),
      };
    },
  mapOverrideNameToOriginal: vi.fn(async (name: string) => name),
}));
vi.mock("./cold-connect-broker-fallback", () => ({
  resolveColdConnectBrokerFallback: () => undefined,
}));
vi.mock("./tool-call-warmup", () => ({
  acquireSessionWithBoundedWarmup: vi.fn(async (args: { serverUuid: string }) =>
    warmSessions.get(args.serverUuid),
  ),
}));

import logger from "@/utils/logger";

import { describeListingFailure } from "./audit-listing-log";
import { getMcpServers, getNamespaceListingServers } from "./fetch-metamcp";
import { setAuditRecorderForTesting } from "./metamcp-middleware/auditing.functional";
import { createServer } from "./metamcp-proxy";
import {
  RetiredToolsRegistry,
  setRetiredToolsRegistryForTesting,
} from "./retired-tools";

const warmSessions = new Map<string, ConnectedClient>();

const REAL_TOOL = "ninja__list_things";
const real: CallToolResult = {
  content: [{ type: "text", text: "a real answer" }],
};

interface Backend {
  session: ConnectedClient;
  setTools: (tools: Tool[]) => void;
  pauseNextListing: () => { started: Promise<void>; release: () => void };
  /** How many times the one real tool executed. */
  executions: () => number;
  /** How many tools/call requests reached the backend, of any name. */
  requests: () => number;
  /** How many in-flight tools/call requests the backend was told to cancel. */
  cancelled: () => number;
}

const cleanups: Array<() => Promise<unknown>> = [];

async function backend(
  onReal: () => Promise<CallToolResult> = async () => real,
): Promise<Backend> {
  const server = new Server(
    { name: "ninja", version: "1.0.0" },
    { capabilities: { tools: {} } },
  );
  let executions = 0;
  let requests = 0;
  let cancelled = 0;
  let listingPause: { started: () => void; wait: Promise<void> } | undefined;
  let tools: Tool[] = [
    {
      name: "list_things",
      inputSchema: {
        type: "object",
        // Selector values are stored only from a closed set, so the test
        // backend declares its modes as an enum.
        properties: { mode: { type: "string", enum: ["list", "x1"] } },
      },
    },
  ];
  server.setRequestHandler(ListToolsRequestSchema, async () => {
    const snapshot = tools;
    const pause = listingPause;
    listingPause = undefined;
    if (pause) {
      pause.started();
      await pause.wait;
    }
    return { tools: snapshot };
  });
  server.setRequestHandler(CallToolRequestSchema, async (request, extra) => {
    requests += 1;
    // The SDK client sends notifications/cancelled when its request times out;
    // the backend's SDK turns that into an abort of this handler's signal.
    extra.signal.addEventListener("abort", () => {
      cancelled += 1;
    });
    if (request.params.name === "list_things") {
      executions += 1;
      return onReal();
    }
    // What a FastMCP backend answers for a name it does not serve.
    return {
      isError: true,
      content: [
        { type: "text", text: `Unknown tool: '${request.params.name}'` },
      ],
    };
  });
  const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
  await server.connect(serverSide);
  const client = new Client({ name: "metamcp", version: "1.0.0" });
  await client.connect(clientSide);
  cleanups.push(() => client.close());
  return {
    setTools: (next) => {
      tools = next;
    },
    pauseNextListing: () => {
      let started!: () => void;
      let release!: () => void;
      const began = new Promise<void>((resolve) => {
        started = resolve;
      });
      const wait = new Promise<void>((resolve) => {
        release = resolve;
      });
      listingPause = { started, wait };
      return { started: began, release };
    },
    session: {
      client,
      cleanup: () => client.close(),
      listChangedSubscribers: new Set(),
    },
    executions: () => executions,
    requests: () => requests,
    cancelled: () => cancelled,
  };
}

async function connectConsumer(
  namespace = "ns-1",
  session = "sess-1",
): Promise<Client> {
  const { server } = await createServer(namespace, session);
  const [consumerSide, gatewaySide] = InMemoryTransport.createLinkedPair();
  await server.connect(gatewaySide);
  const consumer = new Client({ name: "consumer", version: "1.0.0" });
  await consumer.connect(consumerSide);
  cleanups.push(() => consumer.close());
  return consumer;
}

const call = (
  consumer: Client,
  name: string,
  args: Record<string, unknown> = {},
) =>
  consumer.request(
    { method: "tools/call", params: { name, arguments: args } },
    CallToolResultSchema,
    { timeout: 10_000 },
  );

const envelopeOf = (result: {
  content: Array<{ type: string; text?: string }>;
}) => JSON.parse(result.content[0].text ?? "{}");

const list = (consumer: Client) =>
  consumer.request({ method: "tools/list", params: {} }, ListToolsResultSchema);

let dir: string;

function installMap() {
  dir = mkdtempSync(path.join(tmpdir(), "retired-e2e-"));
  const file = path.join(dir, "retired-tools.json");
  writeFileSync(
    file,
    JSON.stringify({
      version: 1,
      retired: {
        ninja__add_note: {
          since: "2026-09-02",
          replacement: "ninja__list_things",
          args: { mode: "note_add" },
          hint: "pass ticket and note",
        },
        gone__lookup: {
          since: "2026-09-28",
          replacement: "ninja__list_things",
          also: ["ninja__other"],
        },
        // Listed, and also actually served: it must keep working.
        [REAL_TOOL]: {
          since: "2026-09-02",
          replacement: "ninja__other",
          hint: "wrongly listed",
        },
      },
    }),
  );
  setRetiredToolsRegistryForTesting(
    new RetiredToolsRegistry({ path: file, reloadSeconds: 30 }),
  );
}

beforeEach(() => {
  // Pin the audit sink before the FIRST test, not only after each one. The
  // module starts with no sink chosen (undefined), and the first audited call
  // then starts a lazy import of the real repository; when that import
  // finishes it REPLACES whatever sink is installed at that moment. Under
  // full-suite load it finished (225 to 272 ms in the traces) inside a later
  // test, swapped that test's recorder for the real one, and the row the test
  // was waiting on went to a database this file mocks away, where persist's
  // catch-all swallowed the failure. The wait then expired as "called 2 times,
  // but got 1" (#237). With a sink pinned from the first test on, the import
  // never starts. A test that wants rows installs its own recorder after this.
  setAuditRecorderForTesting(null);
  getSessionMock.mockReset();
  invalidateServerConnectionMock.mockReset();
  invalidateServerConnectionMock.mockResolvedValue(undefined);
  findServersMock.mockReset();
  findServersMock.mockResolvedValue([]);
  warmSessions.clear();
  config.mcpTimeoutMs = 5_000;
  config.listedAlias = undefined;
  installMap();
});

afterEach(async () => {
  setRetiredToolsRegistryForTesting(undefined);
  setAuditRecorderForTesting(null);
  rmSync(dir, { recursive: true, force: true });
  while (cleanups.length > 0) {
    await cleanups
      .pop()?.()
      .catch(() => undefined);
  }
});

afterAll(() => {
  expect(
    auditRepoImports.count,
    "the real audit repository was imported: a test ran with no audit sink pinned, and that lazy import can replace a later test's recorder mid-test (#237)",
  ).toBe(0);
});

describe("retired names through the gateway", () => {
  it("(a) a retired name the backend does not serve gets the redirect and executes nothing", async () => {
    const target = await backend();
    getSessionMock.mockResolvedValue(target.session);

    const result = await call(await connectConsumer(), "ninja__add_note", {
      ticket: 1,
    });

    expect(result.isError).toBe(true);
    const envelope = envelopeOf(result);
    expect(envelope).toMatchObject({
      error: true,
      code: "tool_retired",
      context: {
        retired: "ninja__add_note",
        replacement: "ninja__list_things",
        replacement_call: 'ninja__list_things(mode="note_add")',
      },
    });
    expect(target.executions()).toBe(0);
    // Routing found no such tool, so nothing was even sent to the backend.
    expect(target.requests()).toBe(0);
  });

  it("(b) a name that is in the map but IS served still executes exactly once", async () => {
    const target = await backend();
    getSessionMock.mockResolvedValue(target.session);

    const result = await call(await connectConsumer(), REAL_TOOL);

    expect(result.content).toEqual(real.content);
    expect(result.isError).toBeFalsy();
    expect(target.executions()).toBe(1);
  });

  it("(c) a retired name with a stale routing row is forwarded, the backend says unknown, the client gets the redirect", async () => {
    const target = await backend();
    getSessionMock.mockResolvedValue(target.session);
    // A stale tools + mapping row: the reconnect-window fallback finds a server
    // for the retired name and the call is forwarded.
    findServersMock.mockResolvedValue([
      { serverUuid: "server-ninja", serverName: "ninja" },
    ]);
    warmSessions.set("server-ninja", target.session);

    const result = await call(await connectConsumer(), "ninja__add_note");

    expect(envelopeOf(result).code).toBe("tool_retired");
    // The backend was asked and answered "Unknown tool"; it ran nothing.
    expect(target.requests()).toBe(1);
    expect(target.executions()).toBe(0);
  });

  it("(d) an unresolvable server prefix (the filter's denial) gets the redirect", async () => {
    const target = await backend();
    getSessionMock.mockResolvedValue(target.session);

    const result = await call(await connectConsumer(), "gone__lookup");

    const envelope = envelopeOf(result);
    expect(envelope.code).toBe("tool_retired");
    expect(envelope.context.also).toEqual(["ninja__other"]);
    expect(target.requests()).toBe(0);
  });

  it("an unmapped unknown name keeps the bare gateway answer", async () => {
    const target = await backend();
    getSessionMock.mockResolvedValue(target.session);
    const consumer = await connectConsumer();

    await expect(call(consumer, "ninja__never_existed")).rejects.toThrow(
      "Unknown tool",
    );
  });

  it("(e) a timeout on a listed name is not rewritten, not replayed, and carries the hint", async () => {
    config.mcpTimeoutMs = 50;
    let release: () => void = () => undefined;
    const target = await backend(
      () =>
        new Promise((resolve) => {
          release = () => resolve(real);
        }),
    );
    cleanups.push(async () => release());
    getSessionMock.mockResolvedValue(target.session);

    let error: McpError | undefined;
    try {
      await call(await connectConsumer(), REAL_TOOL);
    } catch (caught) {
      error = caught as McpError;
    }

    expect(error).toBeInstanceOf(McpError);
    expect(error?.code).toBe(ErrorCode.RequestTimeout);
    // Not a redirect: the name is listed, but the failure is a timeout.
    expect(error?.message).not.toContain("tool_retired");
    expect(error?.message).toContain("Request timed out");
    expect(error?.message).toContain("The outcome is unknown");
    expect(error?.message).not.toContain("did not cancel");
    expect(error?.message).toContain(
      "read the target's current state before retrying",
    );
    expect(target.executions()).toBe(1);
    // The premise the hint states: the SDK really does send the backend a
    // cancellation on a timeout. If an SDK upgrade stops doing that, this fails
    // and the wording must be revisited.
    await vi.waitFor(() => expect(target.cancelled()).toBe(1));
    expect(invalidateServerConnectionMock).not.toHaveBeenCalled();
    expect(getSessionMock).toHaveBeenCalledTimes(1);
  });

  it("(f) tools/list is unchanged", async () => {
    const target = await backend();
    getSessionMock.mockResolvedValue(target.session);
    const consumer = await connectConsumer();

    const listed = await consumer.request(
      { method: "tools/list", params: {} },
      ListToolsResultSchema,
    );

    expect(listed.tools.map((tool) => tool.name)).toEqual([REAL_TOOL]);
  });
});

describe("argument schemas through real SDK transports", () => {
  // The audit row for call n, once exactly n rows exist. Reading `.at(-1)` after
  // a timer tick let a late or missing row pass as another call's row; CI saw
  // one such failure (2026-10-02, not reproduced locally), so a count mismatch
  // now fails as a count and a missing schema fails as a shape.
  const shapeOfRow = async (recorder: ReturnType<typeof vi.fn>, n: number) => {
    await vi.waitFor(() => expect(recorder).toHaveBeenCalledTimes(n));
    return recorder.mock.calls[n - 1][0].args_shape;
  };

  it("an override uses the final exposed name's schema and preserves call arguments", async () => {
    config.listedAlias = "ninja__alias";
    const recorder = vi.fn().mockResolvedValue(undefined);
    setAuditRecorderForTesting(recorder);
    const target = await backend();
    getSessionMock.mockResolvedValue(target.session);
    const consumer = await connectConsumer();
    expect((await list(consumer)).tools[0].name).toBe("ninja__alias");
    await call(consumer, "ninja__alias", { mode: "list", Alice_Smith: 1 });
    expect(await shapeOfRow(recorder, 1)).toEqual({
      keys: ["mode"],
      sel: { mode: "list" },
      unknown_keys: 1,
    });
    expect(target.executions()).toBe(1);
  });

  it.each(["ns-1", "ns-2"])(
    "another proxy in %s cannot change the first proxy's schema",
    async (otherNamespace) => {
      const recorder = vi.fn().mockResolvedValue(undefined);
      setAuditRecorderForTesting(recorder);
      const first = await backend();
      first.setTools([
        {
          name: "list_things",
          inputSchema: {
            type: "object",
            properties: { mode: { enum: ["list"] }, ticket: {} },
          },
        },
      ]);
      getSessionMock.mockResolvedValue(first.session);
      const firstConsumer = await connectConsumer();
      await list(firstConsumer);

      const second = await backend();
      second.setTools([
        {
          name: "list_things",
          inputSchema: {
            type: "object",
            properties: { mode: { enum: ["Alice_Smith"] }, Alice_Smith: {} },
          },
        },
      ]);
      getSessionMock.mockResolvedValue(second.session);
      await list(await connectConsumer(otherNamespace, "sess-2"));

      await call(firstConsumer, REAL_TOOL, {
        mode: "Alice_Smith",
        Alice_Smith: 1,
      });
      expect(await shapeOfRow(recorder, 1)).toEqual({
        keys: ["mode"],
        sel: { mode: "?" },
        unknown_keys: 1,
      });
      expect(first.executions()).toBe(1);
      expect(second.executions()).toBe(0);
    },
  );

  it("a call before any listing is shaped from the proxy's own listing, and a rename discards the old schema", async () => {
    const recorder = vi.fn().mockResolvedValue(undefined);
    setAuditRecorderForTesting(recorder);
    const target = await backend();
    getSessionMock.mockResolvedValue(target.session);
    const consumer = await connectConsumer();
    // The client never listed: the proxy listed for its own audit. The name is
    // declared; the value is not one of the enum's members.
    await call(consumer, REAL_TOOL, { mode: "Alice_Smith" });
    expect(await shapeOfRow(recorder, 1)).toEqual({
      keys: ["mode"],
      sel: { mode: "?" },
    });

    await list(consumer);
    await call(consumer, REAL_TOOL, { mode: "list" });
    expect(await shapeOfRow(recorder, 2)).toEqual({
      keys: ["mode"],
      sel: { mode: "list" },
    });

    target.setTools([
      {
        name: "renamed",
        inputSchema: { type: "object", properties: { query: {} } },
      },
    ]);
    await list(consumer);
    await call(consumer, REAL_TOOL, { mode: "Alice_Smith" });
    expect(await shapeOfRow(recorder, 3)).toEqual({
      keys: [],
      unverified_keys: 1,
    });
  });

  it("a list-changed notification invalidates the previous audit schema", async () => {
    const recorder = vi.fn().mockResolvedValue(undefined);
    setAuditRecorderForTesting(recorder);
    const target = await backend();
    getSessionMock.mockResolvedValue(target.session);
    const consumer = await connectConsumer();
    await list(consumer);
    // The backend drops `mode`, then says so. The listed schema declared it.
    target.setTools([
      {
        name: "list_things",
        inputSchema: { type: "object", properties: { query: {} } },
      },
    ]);
    await Promise.all(
      [...target.session.listChangedSubscribers].map((notify) => notify()),
    );
    await call(consumer, REAL_TOOL, { mode: "list" });
    // Shaped from a fresh listing: the old schema would store `mode`.
    expect(await shapeOfRow(recorder, 1)).toEqual({
      keys: [],
      unknown_keys: 1,
    });
  });

  it("a notification during a listing prevents an old response from restoring the schema", async () => {
    const recorder = vi.fn().mockResolvedValue(undefined);
    setAuditRecorderForTesting(recorder);
    const target = await backend();
    getSessionMock.mockResolvedValue(target.session);
    const consumer = await connectConsumer();
    await list(consumer);
    const pause = target.pauseNextListing();
    const pending = list(consumer);
    await pause.started;
    // The paused response already holds the schema that declares `mode`.
    target.setTools([
      {
        name: "list_things",
        inputSchema: { type: "object", properties: { query: {} } },
      },
    ]);
    await Promise.all(
      [...target.session.listChangedSubscribers].map((notify) => notify()),
    );
    pause.release();
    await pending;
    await call(consumer, REAL_TOOL, { mode: "list" });
    // Restored, the old response would store `mode` and its value.
    expect(await shapeOfRow(recorder, 1)).toEqual({
      keys: [],
      unknown_keys: 1,
    });
  });

  it("an older concurrent listing cannot restore an obsolete schema", async () => {
    const recorder = vi.fn().mockResolvedValue(undefined);
    setAuditRecorderForTesting(recorder);
    const target = await backend();
    getSessionMock.mockResolvedValue(target.session);
    const consumer = await connectConsumer();
    await list(consumer);
    const pause = target.pauseNextListing();
    const older = list(consumer);
    await pause.started;
    target.setTools([
      {
        name: "list_things",
        inputSchema: { type: "object", properties: { query: {} } },
      },
    ]);
    await list(consumer);
    pause.release();
    await older;
    await call(consumer, REAL_TOOL, { mode: "Alice_Smith" });
    // Restored, the obsolete schema would store `mode` (as "?"); the current
    // one does not declare it.
    expect(await shapeOfRow(recorder, 1)).toEqual({
      keys: [],
      unknown_keys: 1,
    });
  });
});

describe("argument schemas for a caller that never lists on its proxy", () => {
  // n8n-style sessions, lazily recovered sessions and long sessions whose
  // snapshot a list_changed cleared all call without a listing on that proxy.
  // The proxy lists for its own audit after the call; only the row waits.
  const listings = vi.mocked(getNamespaceListingServers);
  const servers = vi.mocked(getMcpServers);

  const rowsAfter = async (recorder: ReturnType<typeof vi.fn>, n: number) => {
    await vi.waitFor(() => expect(recorder).toHaveBeenCalledTimes(n));
    return recorder.mock.calls.map((callArgs) => callArgs[0]);
  };

  // The per-server cause lines an audit listing logs at INFO.
  const causesOf = (lines: string[]) =>
    lines.filter((line) => line.startsWith("Audit listing for session"));
  // What the log panels count as failures; those lines must stay out of it.
  const PANEL_WORDS = /\b(error|fatal|panic|exception)\b/i;

  const declaring = (properties: Record<string, object>): Tool[] => [
    { name: "list_things", inputSchema: { type: "object", properties } },
  ];

  async function connectWithCleanup(namespace = "ns-1", session = "sess-1") {
    const { server, cleanup } = await createServer(namespace, session);
    const [consumerSide, gatewaySide] = InMemoryTransport.createLinkedPair();
    await server.connect(gatewaySide);
    const consumer = new Client({ name: "consumer", version: "1.0.0" });
    await consumer.connect(consumerSide);
    cleanups.push(() => consumer.close());
    return { consumer, cleanup };
  }

  /** The next namespace read hangs until released (the audit listing's first step). */
  function holdNextListing() {
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    listings.mockImplementationOnce(async () => {
      await gate;
      return {
        routable: await getMcpServers("ns-1", false),
        errorGated: {},
      };
    });
    return release;
  }

  beforeEach(() => {
    listings.mockClear();
    servers.mockClear();
  });

  afterEach(() => {
    delete process.env.TOOL_AUDIT_ARGS_SHAPE;
  });

  it("(1) a call on a proxy that never listed stores the declared keys and the enum selector value", async () => {
    const recorder = vi.fn().mockResolvedValue(undefined);
    setAuditRecorderForTesting(recorder);
    const target = await backend();
    target.setTools(
      declaring({ mode: { type: "string", enum: ["list", "x1"] }, ticket: {} }),
    );
    getSessionMock.mockResolvedValue(target.session);
    const consumer = await connectConsumer();

    const result = await call(consumer, REAL_TOOL, { mode: "list", ticket: 5 });

    expect(result.content).toEqual(real.content);
    const [row] = await rowsAfter(recorder, 1);
    expect(row.args_shape).toEqual({
      keys: ["mode", "ticket"],
      sel: { mode: "list" },
    });
    // A deferred row keeps the time the call settled.
    expect(row.called_at).toBeInstanceOf(Date);
    expect(listings).toHaveBeenCalledTimes(1);
    expect(target.executions()).toBe(1);
  });

  it("(2) a caller-chosen key or selector value never reaches the row", async () => {
    const recorder = vi.fn().mockResolvedValue(undefined);
    setAuditRecorderForTesting(recorder);
    const target = await backend();
    target.setTools(declaring({ mode: { enum: ["list"] }, ticket: {} }));
    getSessionMock.mockResolvedValue(target.session);

    await call(await connectConsumer(), REAL_TOOL, {
      mode: "Alice_Smith",
      Alice_Smith: 1,
      client_secret_x: 2,
      "bad key": 3,
    });

    const [row] = await rowsAfter(recorder, 1);
    expect(row.args_shape).toEqual({
      keys: ["mode"],
      sel: { mode: "?" },
      unknown_keys: 2,
      invalid_keys: 1,
    });
    const stored = JSON.stringify(row.args_shape);
    expect(stored).not.toContain("Alice_Smith");
    expect(stored).not.toContain("client_secret_x");
  });

  it("(3) a listing that fails leaves the count-only shape and the call still succeeds", async () => {
    const recorder = vi.fn().mockResolvedValue(undefined);
    setAuditRecorderForTesting(recorder);
    const target = await backend();
    getSessionMock.mockResolvedValue(target.session);
    listings.mockRejectedValueOnce(new Error("namespace read failed"));
    vi.mocked(logger.error).mockClear();
    vi.mocked(logger.warn).mockClear();

    const result = await call(await connectConsumer(), REAL_TOOL, {
      mode: "list",
      ticket: 1,
    });

    expect(result.content).toEqual(real.content);
    expect(result.isError).toBeFalsy();
    const [row] = await rowsAfter(recorder, 1);
    expect(row).toMatchObject({
      success: true,
      args_shape: { keys: [], unverified_keys: 2 },
    });
    expect(listings).toHaveBeenCalledTimes(1);
    expect(target.executions()).toBe(1);
    expect(logger.error).not.toHaveBeenCalled();
    expect(logger.warn).toHaveBeenCalledExactlyOnceWith(
      expect.stringContaining("Audit listing for session sess-1"),
    );
  });

  it("(4) concurrent misses on one proxy share one listing, and the calls do not wait for it", async () => {
    const recorder = vi.fn().mockResolvedValue(undefined);
    setAuditRecorderForTesting(recorder);
    const target = await backend();
    getSessionMock.mockResolvedValue(target.session);
    const release = holdNextListing();
    const consumer = await connectConsumer();

    const results = await Promise.all(
      ["list", "x1", "list", "x1", "list"].map((mode) =>
        call(consumer, REAL_TOOL, { mode }),
      ),
    );

    // Every call answered while the listing is still held: only rows wait.
    expect(
      results.every(
        (r) =>
          r.content[0].type === "text" && r.content[0].text === "a real answer",
      ),
    ).toBe(true);
    await vi.waitFor(() => expect(listings).toHaveBeenCalledTimes(1));
    expect(recorder).not.toHaveBeenCalled();
    release();
    const rows = await rowsAfter(recorder, 5);
    expect(rows.map((row) => row.args_shape.sel.mode).sort()).toEqual([
      "list",
      "list",
      "list",
      "x1",
      "x1",
    ]);
    expect(listings).toHaveBeenCalledTimes(1);
  });

  it("(5) two proxies in one namespace with different routing winners each use their own schema", async () => {
    const recorder = vi.fn().mockResolvedValue(undefined);
    setAuditRecorderForTesting(recorder);
    const first = await backend();
    first.setTools(declaring({ mode: { enum: ["list"] }, ticket: {} }));
    const second = await backend();
    second.setTools(
      declaring({ mode: { enum: ["Alice_Smith"] }, Alice_Smith: {} }),
    );
    // Same namespace, same exposed name; each session's pool routes it to a
    // different backend.
    getSessionMock.mockImplementation(async (sessionId: string) =>
      sessionId === "sess-1" ? first.session : second.session,
    );
    const firstConsumer = await connectConsumer("ns-1", "sess-1");
    const secondConsumer = await connectConsumer("ns-1", "sess-2");
    const args = { mode: "Alice_Smith", Alice_Smith: 1, ticket: 1 };

    await call(firstConsumer, REAL_TOOL, args);
    const [firstRow] = await rowsAfter(recorder, 1);
    await call(secondConsumer, REAL_TOOL, args);
    const secondRow = (await rowsAfter(recorder, 2))[1];

    expect(firstRow).toMatchObject({ session_id: "sess-1" });
    expect(firstRow.args_shape).toEqual({
      keys: ["mode", "ticket"],
      sel: { mode: "?" },
      unknown_keys: 1,
    });
    expect(secondRow).toMatchObject({ session_id: "sess-2" });
    expect(secondRow.args_shape).toEqual({
      keys: ["Alice_Smith", "mode"],
      sel: { mode: "Alice_Smith" },
      unknown_keys: 1,
    });
    expect(first.executions()).toBe(1);
    expect(second.executions()).toBe(1);
  });

  it("a name two servers expose stays count-only instead of guessing which one routes", async () => {
    const recorder = vi.fn().mockResolvedValue(undefined);
    setAuditRecorderForTesting(recorder);
    const first = await backend();
    first.setTools(declaring({ mode: { enum: ["list"] }, ticket: {} }));
    const second = await backend();
    second.setTools(declaring({ mode: { enum: ["list"] }, Alice_Smith: {} }));
    // Both names sanitize to the prefix `ninja`, so both expose
    // `ninja__list_things`; the client-facing listing would keep one.
    servers.mockResolvedValue({
      "server-ninja": { name: "ninja" },
      "server-ninja-2": { name: "ninja!" },
    } as never);
    getSessionMock.mockImplementation(
      async (_sessionId: string, serverUuid: string) =>
        serverUuid === "server-ninja-2" ? second.session : first.session,
    );

    try {
      await call(await connectConsumer(), REAL_TOOL, { mode: "list" });
      const [row] = await rowsAfter(recorder, 1);
      expect(row.args_shape).toEqual({ keys: [], unverified_keys: 1 });
      expect(listings).toHaveBeenCalledTimes(1);
    } finally {
      servers.mockResolvedValue({ "server-ninja": { name: "ninja" } } as never);
    }
  });

  it("a failed listing of the routing winner cannot verify keys from a colliding server", async () => {
    const recorder = vi.fn().mockResolvedValue(undefined);
    setAuditRecorderForTesting(recorder);
    const first = await backend(async () => {
      // Dynamic routing reached this backend and the call succeeded, but
      // its subsequent audit listing fails. Only its competitor lists.
      vi.spyOn(first.session.client, "request").mockRejectedValueOnce(
        new Error("listing unavailable"),
      );
      return real;
    });
    const second = await backend();
    second.setTools(declaring({ Alice_Smith: {} }));
    servers.mockResolvedValue({
      "server-ninja": { name: "ninja" },
      "server-ninja-2": { name: "ninja!" },
    } as never);
    getSessionMock.mockImplementation(
      async (_sessionId: string, serverUuid: string) =>
        serverUuid === "server-ninja-2" ? second.session : first.session,
    );

    try {
      await call(await connectConsumer(), REAL_TOOL, { Alice_Smith: 1 });
      const [row] = await rowsAfter(recorder, 1);
      expect(first.executions()).toBe(1);
      expect(second.executions()).toBe(0);
      expect(row.args_shape).toEqual({ keys: [], unverified_keys: 1 });
    } finally {
      servers.mockResolvedValue({ "server-ninja": { name: "ninja" } } as never);
    }
  });

  it("a second miss inside the interval does not list again", async () => {
    const recorder = vi.fn().mockResolvedValue(undefined);
    setAuditRecorderForTesting(recorder);
    const target = await backend();
    getSessionMock.mockResolvedValue(target.session);
    const consumer = await connectConsumer();

    await call(consumer, REAL_TOOL, { mode: "list" });
    await rowsAfter(recorder, 1);
    // A name the listing does not hold misses again; the interval holds.
    await call(consumer, "ninja__add_note", { mode: "x1" });
    const rows = await rowsAfter(recorder, 2);

    expect(rows[1].args_shape).toEqual({ keys: [], unverified_keys: 1 });
    expect(listings).toHaveBeenCalledTimes(1);
  });

  it.each([false, true])(
    "an audit listing cannot invalidate backend connections (proxy closed: %s)",
    async (closeProxy) => {
      const recorder = vi.fn().mockResolvedValue(undefined);
      setAuditRecorderForTesting(recorder);
      let failListing!: (error: Error) => void;
      const pendingListing = new Promise<never>((_resolve, reject) => {
        failListing = reject;
      });
      const target = await backend(async () => {
        // The call's routing probe has finished. Hold only the subsequent
        // audit listing, which can outlive this proxy and its backend client.
        vi.spyOn(target.session.client, "request").mockReturnValueOnce(
          pendingListing,
        );
        return real;
      });
      getSessionMock.mockResolvedValue(target.session);
      const { consumer, cleanup } = await connectWithCleanup();

      expect(
        (await call(consumer, REAL_TOOL, { mode: "list" })).content,
      ).toEqual(real.content);
      await vi.waitFor(() => expect(listings).toHaveBeenCalledTimes(1));
      if (closeProxy) await cleanup();
      failListing(new Error("Not connected"));

      const [row] = await rowsAfter(recorder, 1);
      expect(invalidateServerConnectionMock).not.toHaveBeenCalled();
      expect(row.args_shape).toEqual({ keys: [], unverified_keys: 1 });
    },
  );

  it("the audit listing attaches no list_changed subscriber and sends the client nothing", async () => {
    const recorder = vi.fn().mockResolvedValue(undefined);
    setAuditRecorderForTesting(recorder);
    const ninja = await backend();
    const other = await backend();
    other.setTools([
      { name: "other_thing", inputSchema: { type: "object", properties: {} } },
    ]);
    servers.mockResolvedValue({
      "server-ninja": { name: "ninja" },
      "server-other": { name: "other" },
    } as never);
    getSessionMock.mockImplementation(
      async (_sessionId: string, serverUuid: string) =>
        serverUuid === "server-other" ? other.session : ninja.session,
    );
    const consumer = await connectConsumer();
    const notified = vi.fn();
    consumer.setNotificationHandler(
      ToolListChangedNotificationSchema,
      notified,
    );
    try {
      await call(consumer, REAL_TOOL, { mode: "list" });
      const [row] = await rowsAfter(recorder, 1);
      expect(row.args_shape).toEqual({ keys: ["mode"], sel: { mode: "list" } });
      // The audit listing reached the other server but did not subscribe the
      // client to it.
      expect(getSessionMock).toHaveBeenCalledWith(
        "sess-1",
        "server-other",
        expect.anything(),
        "ns-1",
      );
      expect(other.session.listChangedSubscribers.size).toBe(0);
      expect(notified).not.toHaveBeenCalled();
      // Control: the route the call itself took does notify, so the silence
      // above is the audit listing's, not a deaf handler.
      await Promise.all(
        [...ninja.session.listChangedSubscribers].map((notify) => notify()),
      );
      await vi.waitFor(() => expect(notified).toHaveBeenCalledTimes(1));
    } finally {
      servers.mockResolvedValue({ "server-ninja": { name: "ninja" } } as never);
    }
  });

  it("an audit listing that cannot reach a server logs one warning, no DEGRADED line, and owes the client nothing", async () => {
    const recorder = vi.fn().mockResolvedValue(undefined);
    setAuditRecorderForTesting(recorder);
    const ninja = await backend();
    servers.mockResolvedValue({
      "server-ninja": { name: "ninja" },
      "server-down": { name: "down" },
    } as never);
    getSessionMock.mockImplementation(
      async (_sessionId: string, serverUuid: string) =>
        serverUuid === "server-down" ? undefined : ninja.session,
    );
    vi.mocked(logger.error).mockClear();
    vi.mocked(logger.warn).mockClear();
    vi.mocked(logger.info).mockClear();

    try {
      await call(await connectConsumer(), REAL_TOOL, { mode: "list" });
      const [row] = await rowsAfter(recorder, 1);
      expect(row.args_shape).toEqual({ keys: ["mode"], sel: { mode: "list" } });
      // The harness's tools.impl mock has no syncFromListing, so every
      // listing in this file (client ones too) logs the catalog-sync line.
      // What must be absent is the listing's own failure reporting.
      const errors = vi
        .mocked(logger.error)
        .mock.calls.map(([line]) => String(line))
        .filter((line) => !line.startsWith("Error syncing tools to database"));
      expect(errors).toEqual([]);
      const warned = vi
        .mocked(logger.warn)
        .mock.calls.map(([line]) => String(line));
      expect(warned).toEqual([
        expect.stringContaining("Audit listing for session sess-1"),
      ]);
      expect(warned[0]).not.toMatch(/\b(error|fatal|panic|exception)\b/i);
      const info = vi
        .mocked(logger.info)
        .mock.calls.map(([line]) => String(line));
      expect(info.some((line) => line.includes("is owed"))).toBe(false);
      // The cause the warning leaves out: one line for the unlistable server,
      // saying the pool had no session for it. Nothing for the one that listed.
      expect(causesOf(info)).toEqual([
        "Audit listing for session sess-1 in namespace ns-1 did not list server down: the pool returned no session (server gated, at the connection cap, or backend unreachable)",
      ]);
      expect(causesOf(info)[0]).not.toMatch(PANEL_WORDS);
    } finally {
      servers.mockResolvedValue({ "server-ninja": { name: "ninja" } } as never);
    }
  });

  it("an audit listing whose backend request throws names the server, the class and the message", async () => {
    const recorder = vi.fn().mockResolvedValue(undefined);
    setAuditRecorderForTesting(recorder);
    // The call's own routing lists too, so the listing is made to throw only
    // after the call has executed: the next request on this client is then
    // the audit listing's.
    const target = await backend(async () => {
      vi.spyOn(target.session.client, "request").mockRejectedValueOnce(
        new McpError(ErrorCode.RequestTimeout, "Request timed out"),
      );
      return real;
    });
    getSessionMock.mockResolvedValue(target.session);
    vi.mocked(logger.warn).mockClear();
    vi.mocked(logger.info).mockClear();

    const result = await call(await connectConsumer(), REAL_TOOL, {
      mode: "list",
      ticket: 7,
    });

    // The call is untouched and the row stays count-only, as before.
    expect(result.content).toEqual(real.content);
    const [row] = await rowsAfter(recorder, 1);
    expect(row.args_shape).toEqual({ keys: [], unverified_keys: 2 });
    const causes = causesOf(
      vi.mocked(logger.info).mock.calls.map(([line]) => String(line)),
    );
    // The SDK's own "MCP error" prefix is cut to keep the line off the
    // error panels; the class and the rest of the message survive.
    expect(causes).toEqual([
      "Audit listing for session sess-1 in namespace ns-1 did not list server ninja: McpError: MCP err* -32001: Request timed out",
    ]);
    expect(causes[0]).not.toMatch(PANEL_WORDS);
    // No tool argument value reaches the line.
    expect(causes[0]).not.toContain("ticket");
    // Still exactly the one warning, worded as before.
    expect(logger.warn).toHaveBeenCalledExactlyOnceWith(
      expect.stringContaining("could not list 1 server(s) (ninja)"),
    );
  });

  it("an audit listing whose session acquisition rejects names the class and the message", async () => {
    const recorder = vi.fn().mockResolvedValue(undefined);
    setAuditRecorderForTesting(recorder);
    const ninja = await backend();
    class PoolRefused extends Error {
      constructor(message: string) {
        super(message);
        this.name = "PoolRefused";
      }
    }
    servers.mockResolvedValue({
      "server-ninja": { name: "ninja" },
      "server-down": { name: "down" },
    } as never);
    getSessionMock.mockImplementation(
      async (_sessionId: string, serverUuid: string) => {
        if (serverUuid === "server-down") {
          throw new PoolRefused("connection cap reached");
        }
        return ninja.session;
      },
    );
    vi.mocked(logger.info).mockClear();

    try {
      await call(await connectConsumer(), REAL_TOOL, { mode: "list" });
      const [row] = await rowsAfter(recorder, 1);
      // The server that listed still verifies its keys.
      expect(row.args_shape).toEqual({ keys: ["mode"], sel: { mode: "list" } });
      expect(
        causesOf(vi.mocked(logger.info).mock.calls.map(([l]) => String(l))),
      ).toEqual([
        "Audit listing for session sess-1 in namespace ns-1 did not list server down: PoolRefused: connection cap reached",
      ]);
    } finally {
      servers.mockResolvedValue({ "server-ninja": { name: "ninja" } } as never);
    }
  });

  it("an audit listing names a server whose name holds the tool-name separator", async () => {
    const recorder = vi.fn().mockResolvedValue(undefined);
    setAuditRecorderForTesting(recorder);
    const ninja = await backend();
    servers.mockResolvedValue({
      "server-ninja": { name: "ninja" },
      "server-separator": { name: "bad__name" },
    } as never);
    getSessionMock.mockResolvedValue(ninja.session);
    vi.mocked(logger.info).mockClear();

    try {
      await call(await connectConsumer(), REAL_TOOL, { mode: "list" });
      await rowsAfter(recorder, 1);
      expect(
        causesOf(vi.mocked(logger.info).mock.calls.map(([l]) => String(l))),
      ).toEqual([
        "Audit listing for session sess-1 in namespace ns-1 did not list server bad__name: the server name contains the tool-name separator",
      ]);
    } finally {
      servers.mockResolvedValue({ "server-ninja": { name: "ninja" } } as never);
    }
  });

  it("an audit listing names a nameless server whose reported name holds the separator", async () => {
    // The stored name is checked first; a server stored without one falls back
    // to the name its backend reports, which gets the same check after the
    // session is acquired.
    const recorder = vi.fn().mockResolvedValue(undefined);
    setAuditRecorderForTesting(recorder);
    const ninja = await backend();
    const odd = await backend();
    vi.spyOn(odd.session.client, "getServerVersion").mockReturnValue({
      name: "bad__name\npassword=SECRET",
      version: "1.0.0",
    });
    servers.mockResolvedValue({
      "server-ninja": { name: "ninja" },
      "server-odd": {},
    } as never);
    getSessionMock.mockImplementation(
      async (_sessionId: string, serverUuid: string) =>
        serverUuid === "server-odd" ? odd.session : ninja.session,
    );
    vi.mocked(logger.info).mockClear();

    try {
      await call(await connectConsumer(), REAL_TOOL, { mode: "list" });
      await rowsAfter(recorder, 1);
      expect(
        causesOf(vi.mocked(logger.info).mock.calls.map(([l]) => String(l))),
      ).toEqual([
        "Audit listing for session sess-1 in namespace ns-1 did not list server bad__namepassword=[redacted]: the server name contains the tool-name separator",
      ]);
      expect(logger.warn).toHaveBeenCalledWith(
        "Audit listing for session sess-1 in namespace ns-1 could not list 1 server(s) (bad__namepassword=[redacted]); calls to their tools keep the count-only args_shape",
      );
    } finally {
      servers.mockResolvedValue({ "server-ninja": { name: "ninja" } } as never);
    }
  });

  it("reports a closed session as a cause only when the proxy knew it was closed", async () => {
    // The pool answers nothing for its own reasons (here a gate), and the
    // session closes while that acquisition is in flight. The line says what
    // the pool said and notes the session state beside it. It must not claim
    // the closure was the cause, or the #233 re-measure would count every
    // pool refusal that coincided with a close as the closed-session path.
    const recorder = vi.fn().mockResolvedValue(undefined);
    setAuditRecorderForTesting(recorder);
    const ninja = await backend();
    servers.mockResolvedValue({
      "server-ninja": { name: "ninja" },
      "server-down": { name: "down" },
    } as never);
    const release = holdNextListing();
    let openGate!: () => void;
    const gate = new Promise<void>((resolve) => {
      openGate = resolve;
    });
    let gateArmed = false;
    getSessionMock.mockImplementation(
      async (_sessionId: string, serverUuid: string) => {
        if (serverUuid !== "server-down") return ninja.session;
        if (gateArmed) await gate;
        return undefined;
      },
    );
    const { consumer, cleanup } = await connectWithCleanup();
    vi.mocked(logger.info).mockClear();

    try {
      await call(consumer, REAL_TOOL, { mode: "list" });
      // The call's own acquisitions are done; the listing is still held at
      // its namespace read, so only its acquisitions meet the gate.
      await vi.waitFor(() => expect(listings).toHaveBeenCalledTimes(1));
      gateArmed = true;
      const before = getSessionMock.mock.calls.length;
      release();
      await vi.waitFor(() =>
        expect(getSessionMock.mock.calls.length).toBeGreaterThan(before + 1),
      );
      await cleanup();
      openGate();
      await rowsAfter(recorder, 1);
      const lines = causesOf(
        vi.mocked(logger.info).mock.calls.map(([l]) => String(l)),
      ).filter((line) => line.includes("server down:"));
      expect(lines).toEqual([
        "Audit listing for session sess-1 in namespace ns-1 did not list server down: the pool returned no session (server gated, at the connection cap, or backend unreachable) (the session was closed when this was logged)",
      ]);
      expect(lines[0]).not.toContain("had closed before");
    } finally {
      servers.mockResolvedValue({ "server-ninja": { name: "ninja" } } as never);
    }
  });

  it("a client listing never builds an audit cause", async () => {
    // Three failures on the client-facing path: the pool answers nothing, the
    // acquisition rejects, and the backend request throws. Each site's cause
    // is lazy, so none of them reaches the formatter that an audit listing
    // pays for.
    const spy = vi.mocked(describeListingFailure);
    const ninja = await backend();
    const request = ninja.session.client.request.bind(ninja.session.client);
    vi.spyOn(ninja.session.client, "request").mockImplementation(((
      req: { method: string },
      ...rest: unknown[]
    ) =>
      req.method === "tools/list"
        ? Promise.reject(new Error("listing refused"))
        : (request as (...args: unknown[]) => Promise<unknown>)(
            req,
            ...rest,
          )) as never);
    servers.mockResolvedValue({
      "server-ninja": { name: "ninja" },
      "server-empty": { name: "empty" },
      "server-throws": { name: "throws" },
    } as never);
    getSessionMock.mockImplementation(
      async (_sessionId: string, serverUuid: string) => {
        if (serverUuid === "server-empty") return undefined;
        if (serverUuid === "server-throws") throw new Error("pool refused");
        return ninja.session;
      },
    );
    spy.mockClear();
    vi.mocked(logger.info).mockClear();
    vi.mocked(logger.error).mockClear();

    try {
      // Nothing lists, so the proxy answers a retryable error; that is fine.
      await list(await connectConsumer()).catch(() => undefined);
      // The client path did log its own failures, so the sites were reached.
      const errors = vi
        .mocked(logger.error)
        .mock.calls.map(([line]) => String(line));
      expect(
        errors.some((line) => line.startsWith("Error fetching tools from")),
      ).toBe(true);
      expect(
        errors.some((line) =>
          line.startsWith("Error preparing tools listing for"),
        ),
      ).toBe(true);
      expect(errors.some((line) => line.includes("no session available"))).toBe(
        true,
      );
      expect(spy).not.toHaveBeenCalled();
      expect(
        causesOf(vi.mocked(logger.info).mock.calls.map(([l]) => String(l))),
      ).toEqual([]);
    } finally {
      servers.mockResolvedValue({ "server-ninja": { name: "ninja" } } as never);
    }
  });

  it("a client listing writes no audit cause line", async () => {
    const ninja = await backend();
    servers.mockResolvedValue({
      "server-ninja": { name: "ninja" },
      "server-down": { name: "down" },
    } as never);
    getSessionMock.mockImplementation(
      async (_sessionId: string, serverUuid: string) =>
        serverUuid === "server-down" ? undefined : ninja.session,
    );
    vi.mocked(logger.info).mockClear();

    try {
      await list(await connectConsumer());
      expect(
        causesOf(vi.mocked(logger.info).mock.calls.map(([l]) => String(l))),
      ).toEqual([]);
    } finally {
      servers.mockResolvedValue({ "server-ninja": { name: "ninja" } } as never);
    }
  });

  it("a session closed while its audit listing runs acquires no backend session", async () => {
    const recorder = vi.fn().mockResolvedValue(undefined);
    setAuditRecorderForTesting(recorder);
    const target = await backend();
    getSessionMock.mockResolvedValue(target.session);
    const release = holdNextListing();
    const { consumer, cleanup } = await connectWithCleanup();
    vi.mocked(logger.info).mockClear();

    await call(consumer, REAL_TOOL, { mode: "list" });
    await vi.waitFor(() => expect(listings).toHaveBeenCalledTimes(1));
    const acquiredBeforeClose = getSessionMock.mock.calls.length;
    await cleanup();
    release();

    const [row] = await rowsAfter(recorder, 1);
    expect(row.args_shape).toEqual({ keys: [], unverified_keys: 1 });
    expect(getSessionMock).toHaveBeenCalledTimes(acquiredBeforeClose);
    // The silent path of the gap: the closed session is now the logged cause.
    expect(
      causesOf(vi.mocked(logger.info).mock.calls.map(([l]) => String(l))),
    ).toEqual([
      "Audit listing for session sess-1 in namespace ns-1 did not list server ninja: the session had closed before the listing asked the pool for a backend session",
    ]);
  });

  it("the kill switch stores NULL and lists nothing", async () => {
    process.env.TOOL_AUDIT_ARGS_SHAPE = "off";
    const recorder = vi.fn().mockResolvedValue(undefined);
    setAuditRecorderForTesting(recorder);
    const target = await backend();
    getSessionMock.mockResolvedValue(target.session);

    await call(await connectConsumer(), REAL_TOOL, { mode: "list" });

    const [row] = await rowsAfter(recorder, 1);
    expect(row.args_shape).toBeNull();
    expect(row.called_at).toBeUndefined();
    expect(listings).not.toHaveBeenCalled();
  });
});

describe("the audit rows for those outcomes", () => {
  // Every case makes exactly one call, so it waits for that call's row rather
  // than one timer tick: the row is written after the call settles, and on the
  // timeout path that write lands later than a single tick under full-suite
  // load (CI on #207 read zero rows once; a fixed flush passed locally 8 of 8).
  const rowsFor = async (
    run: (consumer: Client) => Promise<unknown>,
    target: Backend,
  ) => {
    const recorder = vi.fn().mockResolvedValue(undefined);
    setAuditRecorderForTesting(recorder);
    getSessionMock.mockResolvedValue(target.session);
    const consumer = await connectConsumer();
    await run(consumer).catch(() => undefined);
    await vi.waitFor(() => expect(recorder).toHaveBeenCalledTimes(1));
    return recorder.mock.calls.map((callArgs) => callArgs[0]);
  };

  it("a redirect is recorded tool_retired with the argument shape", async () => {
    const [row] = await rowsFor(
      (consumer) =>
        call(consumer, "ninja__add_note", { mode: "x1", ticket: 5 }),
      await backend(),
    );

    expect(row).toMatchObject({
      server_name: "ninja",
      tool_name: "add_note",
      success: false,
      error_code: "tool_retired",
      // A retired name is never listed, so its schema is unknown: counts only.
      args_shape: { keys: [], unverified_keys: 2 },
    });
  });

  it("an unmapped unknown name is recorded unknown_tool", async () => {
    const [row] = await rowsFor(
      (consumer) => call(consumer, "ninja__never_existed"),
      await backend(),
    );
    expect(row).toMatchObject({
      success: false,
      error_code: "unknown_tool",
    });
  });

  it("the filter's unresolved-server denial for an unmapped name is unknown_tool", async () => {
    const [row] = await rowsFor(
      (consumer) => call(consumer, "gone__unlisted"),
      await backend(),
    );
    expect(row).toMatchObject({ success: false, error_code: "unknown_tool" });
  });

  it("an in-band refusal from a real backend is inband_error with its code", async () => {
    const refusing = await backend(async () => ({
      content: [
        {
          type: "text",
          text: JSON.stringify({ error: true, code: "invalid_input" }),
        },
      ],
      structuredContent: { error: true, code: "invalid_input", message: "m" },
    }));
    const [row] = await rowsFor(async (consumer) => {
      await list(consumer);
      return call(consumer, REAL_TOOL, { mode: "list" });
    }, refusing);

    expect(row).toMatchObject({
      success: false,
      error_code: "inband_error",
      error_detail: "invalid_input",
      args_shape: { sel: { mode: "list" }, keys: ["mode"] },
    });
  });

  it("a real backend's in-band refusal reaches the client exactly as the backend sent it", async () => {
    const body = { error: true, code: "invalid_input", message: "m" };
    const refusing = await backend(async () => ({
      content: [{ type: "text", text: JSON.stringify(body) }],
      structuredContent: body,
    }));
    getSessionMock.mockResolvedValue(refusing.session);

    const result = await call(await connectConsumer(), REAL_TOOL);

    // The classifier is observation only: the wire is the backend's own bytes.
    expect(result.isError).toBeFalsy();
    expect(result.structuredContent).toEqual(body);
    expect(JSON.parse((result.content[0] as { text: string }).text)).toEqual(
      body,
    );
  });

  it("a success is recorded success with no error class", async () => {
    const [row] = await rowsFor(
      (consumer) => call(consumer, REAL_TOOL),
      await backend(),
    );
    expect(row).toMatchObject({ success: true });
    expect(row.error_code).toBeUndefined();
  });

  it("a timeout is recorded with the numeric code, unchanged by the hint", async () => {
    config.mcpTimeoutMs = 50;
    let release: () => void = () => undefined;
    const slow = await backend(
      () =>
        new Promise((resolve) => {
          release = () => resolve(real);
        }),
    );
    cleanups.push(async () => release());
    const [row] = await rowsFor((consumer) => call(consumer, REAL_TOOL), slow);
    expect(row).toMatchObject({ success: false, error_code: "-32001" });
  });
});
