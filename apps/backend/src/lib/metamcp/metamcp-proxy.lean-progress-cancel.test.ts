/**
 * The lean tool listing and the tool-call progress, cancel and total-timeout
 * work, together, through a real `createServer`.
 *
 * Why this file exists. A lean session runs a tool through `call_tool` (the
 * read-only door, no prompt) or `call_write_tool` (every other tool). The
 * request is rewritten to the real tool name and must then behave exactly like
 * a direct call: backend progress reaches the consumer under the consumer's own
 * token, only the consumer's own explicit cancel stops its own backend request,
 * the audit row names the real tool and the right session, a broker refusal and
 * a total timeout come back as they do for a direct call, and a closed
 * transport leaves the backend operation running. Each file that pins one of
 * those features drives a plain call; none drives both, so this one pins the
 * seam where the lean prelude hands the rewritten request, its per-call
 * context and the per-call progress and cancel data to the middleware chain.
 *
 * Harness. The real audit, retired-tool, override, filter, classified-target
 * and timeout-hint middleware run over the in-memory table stand-in (as in
 * metamcp-proxy.lean.test.ts). Consumers are real SDK clients over
 * `InMemoryTransport`; the backend is the shared tool-call harness's real SDK
 * `Server` behind a real SDK `Client` (tool-call-harness.test-util.ts), so the
 * SDK's progress, cancel and timeout logic runs on both hops. Only the pool is
 * faked at `getSession`, and it hands every session the SAME backend client,
 * as the production pool does. The wire between gateway and backend is watched
 * at the backend's transport, so a cancel is counted where the backend
 * receives it, with the request id it names.
 *
 * Oracles. Differential: a direct real-name call through a session that is not
 * lean is the oracle for a lean call's result, error shape and audit row. The
 * MCP spec pages basic/utilities/progress (a notification carries the token of
 * the request it belongs to) and basic/utilities/cancellation (a cancel stops
 * that request only; a closed link is not a cancel). The SDK's own
 * shared/protocol.js for the mechanics each test cites.
 */
import { createHash } from "node:crypto";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import {
  type CallToolResult,
  CallToolResultSchema,
  ErrorCode,
  ListToolsRequestSchema,
  McpError,
  ProgressNotificationSchema,
  type Tool,
} from "@modelcontextprotocol/sdk/types.js";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { M365BrokerError } from "../m365/errors";
import type { SessionPresentation } from "./endpoint-presentation";
import type {
  FakeQuery,
  FakeToolMappingState,
} from "./metamcp-middleware/tool-mapping-db.fixtures";
import {
  type BackendCall,
  type BackendExtra,
  flush,
  gateSends,
  makeBackend,
  methodOf,
  sendProgress,
  type TestBackend,
} from "./tool-call-harness.test-util";

const { state, queries, getSessionMock, serverStateMock, config } = vi.hoisted(
  () => ({
    state: {
      servers: [],
      mappings: [],
      mounts: [],
      namespaces: [],
    } as FakeToolMappingState,
    queries: [] as FakeQuery[],
    getSessionMock: vi.fn(),
    serverStateMock: vi.fn(),
    config: {
      timeoutMs: 5_000,
      maxTotalMs: 600_000,
      resetOnProgress: true,
      /** Runs once the handler is about to read the timeout, just before the send. */
      beforeTimeoutRead: undefined as (() => Promise<void>) | undefined,
    },
  }),
);

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
  namespacesRepository: {
    findServersForNamespaceToolName: vi.fn().mockResolvedValue([]),
  },
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
    getMcpResetTimeoutOnProgress: async () => config.resetOnProgress,
    getMcpTimeout: async () => {
      await config.beforeTimeoutRead?.();
      return config.timeoutMs;
    },
    getMcpMaxTotalTimeout: async () => config.maxTotalMs,
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
  const getMcpServers = vi.fn(
    async (namespaceUuid: string, includeInactive = false) =>
      Object.fromEntries(
        mountedHere(namespaceUuid, includeInactive).map((mount) => [
          mount.serverUuid,
          {
            uuid: mount.serverUuid,
            name:
              state.servers.find((server) => server.uuid === mount.serverUuid)
                ?.name ?? "",
            type: "STDIO",
          },
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
    getNamespaceServerStates: vi.fn(async () => []),
  };
});
vi.mock("./mcp-server-pool", () => ({
  mcpServerPool: {
    getSession: getSessionMock,
    invalidateServerConnection: vi.fn(),
    cleanupSession: vi.fn().mockResolvedValue(undefined),
    isPooledClient: () => true,
    probeServerTools: vi.fn().mockResolvedValue(false),
    // tools/list only: a warm pool, so it does not try to warm one up.
    getPoolStatus: () => ({ idle: 1, active: 1 }),
  },
}));
vi.mock("./cold-connect-broker-fallback", () => ({
  resolveColdConnectBrokerFallback: () => undefined,
}));
vi.mock("./tool-call-warmup", () => ({
  acquireSessionWithBoundedWarmup: vi.fn(async () => undefined),
}));

import { setGatewayEventSinkForTesting } from "../gateway-events/sink";
import { setAuditRecorderForTesting } from "./metamcp-middleware/auditing.functional";
import { clearFilterCache } from "./metamcp-middleware/filter-tools.functional";
import { clearOverrideCache } from "./metamcp-middleware/tool-overrides.functional";
import { createServer } from "./metamcp-proxy";
import { toolsSyncCache } from "./tools-sync-cache";

type AuditEntry = Parameters<
  NonNullable<Parameters<typeof setAuditRecorderForTesting>[0]>
>[0];

const NS = "ns-lean-combined";
const DESK = { uuid: "server-desk", name: "desk" };
const T0 = Date.parse("2026-11-13T12:00:00.000Z");
const LEAN: SessionPresentation = {
  toolListing: "lean",
  omitOutputSchemas: false,
};

const READ: Tool = {
  name: "read",
  description: "Read tickets from the desk",
  inputSchema: { type: "object", properties: { id: { type: "string" } } },
  annotations: { readOnlyHint: true },
};
const WRITE: Tool = {
  name: "write",
  description: "Update a ticket on the desk",
  inputSchema: { type: "object", properties: { id: { type: "string" } } },
  annotations: { readOnlyHint: false, destructiveHint: false },
};

/** The two doors, each with a tool it may run. */
const DOORS = [
  { door: "call_tool", tool: "read" },
  { door: "call_write_tool", tool: "write" },
] as const;
type Door = (typeof DOORS)[number];

/** The same consumer token value, as a string and as a number. */
const TOKENS = [
  { kind: "string", value: "tok-shared" },
  { kind: "number", value: 7_654_321 },
] as const;

// ---------------------------------------------------------------------------
// Backend: the shared harness backend, listing a read-only and a write tool,
// holding each call until the test releases it or the backend request aborts.

interface WireCall {
  requestId: string | number;
  name: string;
  args: Record<string, unknown>;
  progressToken: unknown;
}

interface LiveCall {
  id: string;
  call: BackendCall;
  progress: (value: number, total?: number) => Promise<void>;
  finish: () => void;
}

interface Desk extends TestBackend {
  /** tools/call requests as the backend received them, with their ids. */
  wire: { calls: WireCall[]; cancels: Array<{ requestId: unknown }> };
  /** Calls in arrival order, until released, aborted or closed. */
  live: LiveCall[];
  liveOf: (id: string) => LiveCall;
  /** Ids whose handler ended on its own, never by an abort. */
  completed: string[];
  /** Ids whose handler returned because its request was aborted. */
  abortedIds: string[];
}

const cleanups: Array<() => Promise<unknown> | unknown> = [];
const envBackup = new Map<string, string | undefined>();

function setEnv(name: string, value: string | undefined): void {
  if (!envBackup.has(name)) envBackup.set(name, process.env[name]);
  if (value === undefined) delete process.env[name];
  else process.env[name] = value;
}

async function makeDesk(): Promise<Desk> {
  const live: LiveCall[] = [];
  const completed: string[] = [];
  const abortedIds: string[] = [];
  const made = await makeBackend(
    async (extra: BackendExtra, call: BackendCall) => {
      const id = String(call.args.id);
      let finish: () => void = () => undefined;
      const released = new Promise<void>((resolve) => {
        finish = resolve;
      });
      live.push({
        id,
        call,
        progress: (value, total) => sendProgress(extra, value, total),
        finish,
      });
      await new Promise<void>((resolve) => {
        void released.then(resolve);
        if (call.signal.aborted) return resolve();
        call.signal.addEventListener("abort", () => resolve(), { once: true });
      });
      (call.signal.aborted ? abortedIds : completed).push(id);
      return {
        content: [{ type: "text", text: `finished ${id} by ${call.name}` }],
      };
    },
    { serverName: DESK.name },
  );
  made.server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [READ, WRITE],
  }));
  cleanups.push(() => made.close());

  const wire: Desk["wire"] = { calls: [], cancels: [] };
  const transport = made.server.transport;
  if (!transport) throw new Error("the backend is not connected");
  const deliver = transport.onmessage;
  transport.onmessage = (message, extra) => {
    const seen = message as unknown as {
      id?: string | number;
      method?: string;
      params?: Record<string, unknown>;
    };
    if (seen.method === "tools/call" && seen.id !== undefined) {
      const params = seen.params ?? {};
      const meta = params._meta as Record<string, unknown> | undefined;
      wire.calls.push({
        requestId: seen.id,
        name: String(params.name),
        args: (params.arguments ?? {}) as Record<string, unknown>,
        progressToken: meta?.progressToken,
      });
    } else if (seen.method === "notifications/cancelled") {
      wire.cancels.push({ requestId: seen.params?.requestId });
    }
    deliver?.(message, extra);
  };

  return {
    ...made,
    wire,
    live,
    liveOf: (id) => {
      // The newest call with this id (the lib target has no `findLast`).
      for (let index = live.length - 1; index >= 0; index -= 1) {
        if (live[index].id === id) return live[index];
      }
      throw new Error(`the backend has no call "${id}" yet`);
    },
    completed,
    abortedIds,
  };
}

let desk: Desk;

// ---------------------------------------------------------------------------
// Consumers

interface ProgressSeen {
  token: string | number;
  progress: number;
  total?: number;
}

interface Consumer {
  client: Client;
  sessionId: string;
  /** Progress notifications and the "result" marker, in arrival order. */
  log: Array<ProgressSeen | "result">;
  progress: () => ProgressSeen[];
  /** The JSON-RPC ids of the tools/call requests this consumer sent. */
  callIds: Array<string | number>;
  /** Lets the held progress notifications through (see `holdProgress`). */
  releaseProgress: () => void;
  close: () => Promise<void>;
}

async function connectConsumer(
  sessionId: string,
  lean: boolean = true,
  options: {
    /** Holds every progress notification on the gateway's side of the link. */
    holdProgress?: boolean;
  } = {},
): Promise<Consumer> {
  const { server, cleanup } = lean
    ? await createServer(NS, sessionId, false, LEAN)
    : await createServer(NS, sessionId);
  const [consumerSide, gatewaySide] = InMemoryTransport.createLinkedPair();
  let releaseProgress: () => void = () => undefined;
  if (options.holdProgress) {
    const gate = new Promise<void>((resolve) => {
      releaseProgress = resolve;
    });
    gateSends(
      gatewaySide,
      (message) => methodOf(message) === "notifications/progress",
      () => gate,
    );
  }
  const callIds: Consumer["callIds"] = [];
  const sendFromConsumer = consumerSide.send.bind(consumerSide);
  consumerSide.send = async (message, sendOptions) => {
    const seen = message as unknown as {
      id?: string | number;
      method?: string;
    };
    if (seen.method === "tools/call" && seen.id !== undefined) {
      callIds.push(seen.id);
    }
    return sendFromConsumer(message, sendOptions);
  };
  await server.connect(gatewaySide);
  const client = new Client({ name: "consumer", version: "1.0.0" });
  const log: Consumer["log"] = [];
  client.setNotificationHandler(ProgressNotificationSchema, (notification) => {
    log.push({
      token: notification.params.progressToken,
      progress: notification.params.progress,
      ...(notification.params.total !== undefined
        ? { total: notification.params.total }
        : {}),
    });
  });
  await client.connect(consumerSide);
  let closed = false;
  const close = async () => {
    if (closed) return;
    closed = true;
    await client.close();
    await cleanup();
  };
  cleanups.push(close);
  return {
    client,
    sessionId,
    log,
    progress: () =>
      log.filter((entry): entry is ProgressSeen => entry !== "result"),
    callIds,
    releaseProgress,
    close,
  };
}

interface CallOptions {
  /** The call's id argument; the backend keys its held call by it. */
  id: string;
  token?: string | number;
  signal?: AbortSignal;
}

/**
 * A lean call: the meta tool named `door`, carrying the real tool's name and
 * arguments. The consumer's own progress token is sent in `_meta` as given,
 * which the SDK keeps when no `onprogress` is passed.
 */
function leanCall(
  consumer: Consumer,
  door: Door["door"],
  tool: string,
  options: CallOptions,
): Promise<CallToolResult> {
  return consumer.client.request(
    {
      method: "tools/call",
      params: {
        name: door,
        arguments: {
          name: `${DESK.name}__${tool}`,
          arguments: { id: options.id },
        },
        ...(options.token !== undefined
          ? { _meta: { progressToken: options.token } }
          : {}),
      },
    },
    CallToolResultSchema,
    { signal: options.signal, timeout: 10_000_000 },
  ) as Promise<CallToolResult>;
}

/** The direct real-name call, the oracle for what a lean call must do. */
function directCall(
  consumer: Consumer,
  tool: string,
  options: CallOptions,
): Promise<CallToolResult> {
  return consumer.client.request(
    {
      method: "tools/call",
      params: {
        name: `${DESK.name}__${tool}`,
        arguments: { id: options.id },
        ...(options.token !== undefined
          ? { _meta: { progressToken: options.token } }
          : {}),
      },
    },
    CallToolResultSchema,
    { signal: options.signal, timeout: 10_000_000 },
  ) as Promise<CallToolResult>;
}

async function rejectionOf(promise: Promise<unknown>): Promise<McpError> {
  try {
    await promise;
  } catch (error) {
    return error as McpError;
  }
  throw new Error("expected the call to reject");
}

/** What a call came to: its result, or the protocol error's shape. */
async function outcomeOf(promise: Promise<CallToolResult>) {
  try {
    return { result: await promise };
  } catch (error) {
    const failure = error as McpError;
    return {
      error: {
        code: failure.code,
        message: failure.message,
        data: failure.data,
      },
    };
  }
}

const textOf = (result: CallToolResult): string =>
  (result.content[0] as { text: string }).text;

/**
 * Waits for a condition by yielding microtask turns, bounded and clock-free:
 * every hop in this file is an in-memory promise chain.
 */
async function until(condition: () => boolean, what: string): Promise<void> {
  for (let turn = 0; turn < 500; turn += 1) {
    if (condition()) return;
    await flush(50);
  }
  throw new Error(`never reached: ${what}`);
}

/**
 * Drives one progressing call past the total cap: updates at 400, 800 and
 * 1100 ms against a 500 ms request timeout that each update resets, and a
 * 1000 ms total cap that the third update finds exceeded (shared/protocol.js,
 * `_resetTimeout`). Needs `useCap()` first. Returns the call's rejection.
 */
async function overrunCap(
  start: () => Promise<CallToolResult>,
): Promise<McpError> {
  const before = desk.live.length;
  const outcome = rejectionOf(start());
  await until(() => desk.live.length === before + 1, "the backend call");
  const held = desk.live[before];
  for (const [advance, step] of [
    [400, 1],
    [400, 2],
    [300, 3],
  ] as const) {
    await vi.advanceTimersByTimeAsync(advance);
    await held.progress(step);
  }
  const failure = await outcome;
  // SDK 1.32.0 (shared/protocol.js `_resetTimeout`) forgets a capped request
  // but leaves the per-request timer of its last progress armed, and that
  // timer sends its own `notifications/cancelled` (the request id again) once
  // it fires 500 ms later. These tests pin what the gateway does at the cap,
  // so each leg ends before that timer, and the next leg's clock cannot make
  // it count as a cancel of the next call.
  vi.clearAllTimers();
  return failure;
}

/** Fake every timer, so the SDK's own timeout and cap logic runs for real. */
function useCap(): void {
  vi.useRealTimers();
  vi.useFakeTimers();
  vi.setSystemTime(new Date(T0));
  config.timeoutMs = 500;
  config.maxTotalMs = 1_000;
}

function auditRows() {
  const rows: AuditEntry[] = [];
  setAuditRecorderForTesting(async (entry: AuditEntry) => {
    rows.push(entry);
  });
  return {
    rows,
    arrived: (count: number) =>
      until(() => rows.length >= count, `${count} audit row(s)`),
    ofSession: (sessionId: string) =>
      rows.filter((row) => row.session_id === sessionId),
  };
}

/** A row without what differs between two honest runs of the same call. */
const sameRow = ({
  session_id: _session,
  latency_ms: _latency,
  called_at: _calledAt,
  ...rest
}: AuditEntry) => rest;

const sha256 = (value: unknown) =>
  createHash("sha256").update(JSON.stringify(value)).digest("hex");

beforeEach(async () => {
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(new Date(T0));
  clearFilterCache();
  clearOverrideCache();
  toolsSyncCache.clear();
  for (const name of [
    "MCP_LEAN_LISTING",
    "MCP_ENDPOINT_PRESENTATION",
    "MCP_TOOL_CALL_PROGRESS",
    "MCP_TOOL_CALL_CANCEL",
  ]) {
    setEnv(name, undefined);
  }
  config.timeoutMs = 5_000;
  config.maxTotalMs = 600_000;
  config.resetOnProgress = true;
  config.beforeTimeoutRead = undefined;
  state.servers = [DESK];
  state.mounts = [
    { namespaceUuid: NS, serverUuid: DESK.uuid, status: "ACTIVE" },
  ];
  state.namespaces = [{ uuid: NS, toolPolicy: "allow_all" }];
  state.mappings = [];
  state.failOn = undefined;
  state.beforeQueryResult = undefined;
  queries.length = 0;
  setAuditRecorderForTesting(null);
  setGatewayEventSinkForTesting(null);
  desk = await makeDesk();
  getSessionMock.mockReset();
  getSessionMock.mockImplementation(async () => desk.session);
  serverStateMock.mockReset();
  serverStateMock.mockResolvedValue({ error_status: "NONE" });
});

afterEach(async () => {
  vi.useRealTimers();
  config.beforeTimeoutRead = undefined;
  vi.restoreAllMocks();
  // Disabled, never `undefined`: that re-resolves the database-backed sink and
  // recorder on the next write, and a write still in flight when a test ends
  // could then replace the next test's recorder.
  setAuditRecorderForTesting(null);
  setGatewayEventSinkForTesting(null);
  clearFilterCache();
  clearOverrideCache();
  while (cleanups.length > 0) {
    await Promise.resolve(cleanups.pop()?.()).catch(() => undefined);
  }
  for (const [name, value] of envBackup) {
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  }
  envBackup.clear();
});

// ---------------------------------------------------------------------------

describe("progress on a rewritten lean call", () => {
  it.each(
    DOORS.flatMap((door) => TOKENS.map((token) => ({ ...door, ...token }))),
  )(
    "$door relays backend progress under the consumer's $kind token, in order and before the result, and the backend sees the gateway's own token",
    async ({ door, tool, value }) => {
      const audit = auditRows();
      // The consumer link holds the notifications, so the backend's whole run
      // is over before any of them is delivered.
      const lean = await connectConsumer("sess-progress", true, {
        holdProgress: true,
      });

      let settled = false;
      const result = leanCall(lean, door, tool, {
        id: "p1",
        token: value,
      }).then((answer) => {
        settled = true;
        lean.log.push("result");
        return answer;
      });
      await until(() => desk.live.length === 1, "the backend call");
      for (const step of [1, 2, 3]) await desk.liveOf("p1").progress(step, 3);
      desk.liveOf("p1").finish();
      await flush(300);
      // The proxy awaits the relay before it returns the result.
      expect(settled).toBe(false);
      lean.releaseProgress();
      expect(textOf(await result)).toBe(`finished p1 by ${tool}`);

      // The consumer's own token comes back, as the type it was sent as.
      expect(lean.log).toEqual([
        { token: value, progress: 1, total: 3 },
        { token: value, progress: 2, total: 3 },
        { token: value, progress: 3, total: 3 },
        "result",
      ]);
      // The backend got the gateway's token (the SDK's own: its request id),
      // never the consumer's, on the real tool's name.
      expect(desk.wire.calls).toHaveLength(1);
      expect(desk.wire.calls[0].name).toBe(tool);
      expect(desk.wire.calls[0].progressToken).toBe(
        desk.wire.calls[0].requestId,
      );
      expect(desk.wire.calls[0].progressToken).not.toBe(value);
      expect(desk.live[0].call.token).toBe(desk.wire.calls[0].requestId);
      // One audit row, for the real tool, under the lean session.
      await audit.arrived(1);
      await flush();
      expect(audit.rows).toHaveLength(1);
      expect(audit.rows[0]).toMatchObject({
        server_name: DESK.name,
        tool_name: tool,
        session_id: "sess-progress",
        params_hash: sha256({ id: "p1" }),
        success: true,
      });
    },
  );

  it.each(DOORS)(
    "$door relays nothing for a consumer that sent no token",
    async ({ door, tool }) => {
      const lean = await connectConsumer("sess-no-token");

      const result = leanCall(lean, door, tool, { id: "n1" });
      await until(() => desk.live.length === 1, "the backend call");
      await desk.liveOf("n1").progress(1);
      await desk.liveOf("n1").progress(2);
      desk.liveOf("n1").finish();
      await result;
      await flush();

      expect(lean.progress()).toEqual([]);
    },
  );
});

describe("an explicit cancel of a rewritten lean call", () => {
  it.each(DOORS)(
    "$door: aborts exactly its own backend request and audits the real tool as cancelled",
    async ({ door, tool }) => {
      const audit = auditRows();
      const lean = await connectConsumer("sess-cancel");

      const controller = new AbortController();
      const outcome = rejectionOf(
        leanCall(lean, door, tool, {
          id: "c1",
          token: "tok-cancel",
          signal: controller.signal,
        }),
      );
      await until(() => desk.live.length === 1, "the backend call");
      expect(desk.wire.cancels).toEqual([]);

      controller.abort();
      await outcome;
      await until(() => desk.wire.cancels.length === 1, "the backend cancel");
      await until(() => desk.abortedIds.includes("c1"), "the backend abort");

      expect(desk.wire.cancels).toEqual([
        { requestId: desk.wire.calls[0].requestId },
      ]);
      expect(desk.completed).toEqual([]);
      await audit.arrived(1);
      await flush();
      expect(audit.rows).toHaveLength(1);
      expect(audit.rows[0]).toMatchObject({
        server_name: DESK.name,
        tool_name: tool,
        session_id: "sess-cancel",
        success: false,
        error_code: "cancelled",
        error_detail: "outcome_unknown",
      });
    },
  );
});

describe("two lean sessions sharing one backend client", () => {
  // Both sessions send the same token value on calls that run at once, with
  // the same consumer-side request id (asserted below).
  const COMBINATIONS = [
    { a: DOORS[0], b: DOORS[1], kind: "string", token: TOKENS[0].value },
    { a: DOORS[1], b: DOORS[0], kind: "number", token: TOKENS[1].value },
    { a: DOORS[1], b: DOORS[1], kind: "string", token: TOKENS[0].value },
    { a: DOORS[0], b: DOORS[0], kind: "number", token: TOKENS[1].value },
  ] as const;

  it.each(COMBINATIONS)(
    "A through $a.door and B through $b.door, equal $kind tokens: progress, cancel and audit stay with their own session",
    async ({ a, b, token }) => {
      const audit = auditRows();
      const sessionA = await connectConsumer("sess-A");
      const sessionB = await connectConsumer("sess-B");

      const cancelA = new AbortController();
      const callA = rejectionOf(
        leanCall(sessionA, a.door, a.tool, {
          id: "A",
          token,
          signal: cancelA.signal,
        }),
      );
      const callB = leanCall(sessionB, b.door, b.tool, { id: "B", token });
      await until(() => desk.live.length === 2, "both backend calls");
      // Each client numbers its own requests, so the two calls carry the same
      // consumer-side request id: nothing but per-call data tells them apart.
      expect(sessionA.callIds).toHaveLength(1);
      expect(sessionB.callIds).toEqual(sessionA.callIds);
      const requestOf = (id: string) =>
        desk.wire.calls.find((entry) => entry.args.id === id)?.requestId;
      expect(requestOf("A")).toBeDefined();
      expect(requestOf("B")).toBeDefined();
      expect(requestOf("A")).not.toBe(requestOf("B"));

      // Interleaved progress, distinguishable by value.
      await desk.liveOf("A").progress(101);
      await desk.liveOf("B").progress(1);
      await desk.liveOf("A").progress(102);
      await desk.liveOf("B").progress(2);
      await until(
        () =>
          sessionA.progress().length === 2 && sessionB.progress().length === 2,
        "the interleaved progress",
      );

      // A's explicit cancel: the backend sees one cancel, for A's request.
      cancelA.abort();
      await callA;
      await until(() => desk.wire.cancels.length === 1, "A's backend cancel");
      await until(() => desk.abortedIds.includes("A"), "A's backend abort");
      expect(desk.wire.cancels).toEqual([{ requestId: requestOf("A") }]);
      expect(desk.liveOf("B").call.signal.aborted).toBe(false);

      // B keeps going, reports once more, and finishes with its own result.
      await desk.liveOf("B").progress(3);
      await until(() => sessionB.progress().length === 3, "B's last update");
      desk.liveOf("B").finish();
      const answerB = await callB;
      await flush();

      expect(textOf(answerB)).toBe(`finished B by ${b.tool}`);
      expect(answerB.isError).toBeFalsy();
      expect(desk.wire.cancels).toHaveLength(1);
      expect(desk.completed).toEqual(["B"]);
      expect(desk.abortedIds).toEqual(["A"]);
      // Each consumer got only its own call's progress, under the shared token.
      expect(sessionA.progress()).toEqual([
        { token, progress: 101 },
        { token, progress: 102 },
      ]);
      expect(sessionB.progress()).toEqual([
        { token, progress: 1 },
        { token, progress: 2 },
        { token, progress: 3 },
      ]);
      // Audit: the real tool, the right session, the right outcome.
      // Hashes bind each row to its own arguments even when both tools match.
      await audit.arrived(2);
      await flush();
      expect(audit.rows).toHaveLength(2);
      expect(audit.ofSession("sess-A")).toHaveLength(1);
      expect(audit.ofSession("sess-B")).toHaveLength(1);
      expect(audit.ofSession("sess-A")[0]).toMatchObject({
        server_name: DESK.name,
        tool_name: a.tool,
        params_hash: sha256({ id: "A" }),
        success: false,
        error_code: "cancelled",
        error_detail: "outcome_unknown",
      });
      expect(audit.ofSession("sess-B")[0]).toMatchObject({
        server_name: DESK.name,
        tool_name: b.tool,
        params_hash: sha256({ id: "B" }),
        success: true,
      });
    },
  );
});

describe("a rewritten lean call after replay-safe recovery", () => {
  it.each([
    { a: DOORS[0], b: DOORS[1] },
    { a: DOORS[1], b: DOORS[0] },
  ])(
    "A through $a.door and B through $b.door: the replacement keeps progress, cancel and audit with their own session",
    async ({ a, b }) => {
      const audit = auditRows();
      const sessionA = await connectConsumer("sess-retry-A");
      const sessionB = await connectConsumer("sess-retry-B");
      await Promise.all(
        [sessionA, sessionB].map((consumer) =>
          consumer.client.callTool({ name: "search_tools", arguments: {} }),
        ),
      );
      // Keep both routes on the old client, then really close it: the SDK's
      // pre-send "Not connected" permits recovery without running either tool.
      const stale = desk;
      desk = await makeDesk();
      await stale.close();
      getSessionMock.mockClear();

      const token = "tok-retry-shared";
      const cancelA = new AbortController();
      const callA = rejectionOf(
        leanCall(sessionA, a.door, a.tool, {
          id: "A",
          token,
          signal: cancelA.signal,
        }),
      );
      const callB = leanCall(sessionB, b.door, b.tool, { id: "B", token });
      await until(() => desk.live.length === 2, "both recovered backend calls");
      expect(getSessionMock).toHaveBeenCalledTimes(2);
      expect(sessionB.callIds).toEqual(sessionA.callIds);
      const requestOf = (id: string) =>
        desk.wire.calls.find((entry) => entry.args.id === id)?.requestId;
      expect(requestOf("A")).toBeDefined();
      expect(requestOf("B")).toBeDefined();
      expect(requestOf("A")).not.toBe(requestOf("B"));
      for (const call of desk.wire.calls) {
        expect(call.progressToken).toBe(call.requestId);
        expect(call.progressToken).not.toBe(token);
      }

      await desk.liveOf("A").progress(101);
      await desk.liveOf("B").progress(1);
      await until(
        () =>
          sessionA.progress().length === 1 && sessionB.progress().length === 1,
        "both recovered progress updates",
      );
      cancelA.abort();
      await callA;
      await until(() => desk.abortedIds.includes("A"), "A's recovered abort");
      expect(desk.wire.cancels).toEqual([{ requestId: requestOf("A") }]);
      expect(desk.liveOf("B").call.signal.aborted).toBe(false);
      await desk.liveOf("B").progress(2);
      desk.liveOf("B").finish();
      expect(textOf(await callB)).toBe(`finished B by ${b.tool}`);
      await audit.arrived(2);
      await flush();

      expect(stale.wire.calls).toEqual([]);
      expect(stale.wire.cancels).toEqual([]);
      expect(desk.wire.calls).toHaveLength(2);
      expect(desk.wire.cancels).toEqual([{ requestId: requestOf("A") }]);
      expect(desk.abortedIds).toEqual(["A"]);
      expect(desk.completed).toEqual(["B"]);
      expect(sessionA.progress()).toEqual([{ token, progress: 101 }]);
      expect(sessionB.progress()).toEqual([
        { token, progress: 1 },
        { token, progress: 2 },
      ]);
      expect(audit.rows).toHaveLength(2);
      expect(audit.ofSession("sess-retry-A")).toHaveLength(1);
      expect(audit.ofSession("sess-retry-A")[0]).toMatchObject({
        server_name: DESK.name,
        tool_name: a.tool,
        params_hash: sha256({ id: "A" }),
        success: false,
        error_code: "cancelled",
        error_detail: "outcome_unknown",
      });
      expect(audit.ofSession("sess-retry-B")).toHaveLength(1);
      expect(audit.ofSession("sess-retry-B")[0]).toMatchObject({
        server_name: DESK.name,
        tool_name: b.tool,
        params_hash: sha256({ id: "B" }),
        success: true,
      });
    },
  );

  it.each(DOORS)(
    "$door: a cancel during shared recovery prevents its retry while the sibling still runs",
    async ({ door, tool }) => {
      const audit = auditRows();
      const lean = await connectConsumer("sess-recovery-cancel");
      await lean.client.callTool({ name: "search_tools", arguments: {} });
      const stale = desk;
      desk = await makeDesk();
      await stale.close();
      getSessionMock.mockClear();
      let reached!: () => void;
      const held = new Promise<void>((resolve) => {
        reached = resolve;
      });
      let release!: () => void;
      const gate = new Promise<void>((resolve) => {
        release = resolve;
      });
      getSessionMock.mockImplementationOnce(async () => {
        reached();
        await gate;
        return desk.session;
      });

      const controller = new AbortController();
      const cancelled = rejectionOf(
        leanCall(lean, door, tool, {
          id: "cancelled",
          token: "tok-cancelled",
          signal: controller.signal,
        }),
      );
      await held;
      const sibling = leanCall(lean, door, tool, {
        id: "sibling",
        token: "tok-sibling",
      });
      try {
        await flush(300);
        controller.abort();
        await cancelled;
        await flush(300);
        expect(getSessionMock).toHaveBeenCalledTimes(1);
        expect(desk.wire.calls).toEqual([]);
      } finally {
        release();
      }
      await until(() => desk.live.length === 1, "the sibling's recovered call");
      expect(desk.wire.calls[0].args).toEqual({ id: "sibling" });
      await desk.liveOf("sibling").progress(1);
      desk.liveOf("sibling").finish();
      expect(textOf(await sibling)).toBe(`finished sibling by ${tool}`);
      await audit.arrived(2);
      await flush();

      expect(getSessionMock).toHaveBeenCalledTimes(1);
      expect(stale.wire.calls).toEqual([]);
      expect(desk.wire.calls).toHaveLength(1);
      expect(desk.wire.cancels).toEqual([]);
      expect(desk.completed).toEqual(["sibling"]);
      expect(lean.progress()).toEqual([{ token: "tok-sibling", progress: 1 }]);
      expect(audit.rows).toHaveLength(2);
      expect(
        audit.rows.find(
          (row) => row.params_hash === sha256({ id: "cancelled" }),
        ),
      ).toMatchObject({
        session_id: "sess-recovery-cancel",
        tool_name: tool,
        success: false,
        error_code: "cancelled",
        error_detail: "outcome_unknown",
      });
      expect(
        audit.rows.find((row) => row.params_hash === sha256({ id: "sibling" })),
      ).toMatchObject({
        session_id: "sess-recovery-cancel",
        tool_name: tool,
        success: true,
      });
    },
  );

  it.each(DOORS)(
    "$door: a broker refusal on the retry keeps the direct call's enrollment result and audit row",
    async ({ door, tool }) => {
      const audit = auditRows();
      const plain = await connectConsumer("sess-retry-broker-direct", false);
      const lean = await connectConsumer("sess-retry-broker-lean");
      await plain.client.listTools();
      await lean.client.callTool({ name: "search_tools", arguments: {} });
      const stale = desk;
      desk = await makeDesk();
      await stale.close();
      getSessionMock.mockClear();
      const real = desk.session.client.request.bind(desk.session.client);
      vi.spyOn(desk.session.client, "request").mockImplementation(((
        request: { method: string },
        schema: never,
        options: never,
      ) =>
        request.method === "tools/call"
          ? Promise.reject(
              new M365BrokerError(
                "credential_missing",
                "No account.",
                "https://enroll.example.test/m365",
              ),
            )
          : real(request as never, schema, options)) as never);

      const direct = await outcomeOf(
        directCall(plain, tool, { id: "broker", token: "tok-direct" }),
      );
      const viaLean = await outcomeOf(
        leanCall(lean, door, tool, { id: "broker", token: "tok-lean" }),
      );
      expect(getSessionMock).toHaveBeenCalledTimes(2);
      expect(viaLean).toEqual(direct);
      expect(viaLean.result?.isError).toBe(true);
      expect(
        JSON.parse(textOf(viaLean.result as CallToolResult)),
      ).toMatchObject({
        error: "credential_missing",
        enroll_url: "https://enroll.example.test/m365",
      });
      expect(stale.wire.calls).toEqual([]);
      expect(desk.wire.calls).toEqual([]);
      expect(desk.wire.cancels).toEqual([]);
      expect(lean.progress()).toEqual([]);
      await audit.arrived(2);
      await flush();
      expect(audit.rows).toHaveLength(2);
      expect(sameRow(audit.rows[1])).toEqual(sameRow(audit.rows[0]));
      expect(audit.rows[1]).toMatchObject({
        server_name: DESK.name,
        tool_name: tool,
        session_id: "sess-retry-broker-lean",
        params_hash: sha256({ id: "broker" }),
        success: false,
      });
    },
  );

  it.each(DOORS)(
    "$door: a progressing retry keeps the direct call's total timeout and cancels only that retry",
    async ({ door, tool }) => {
      useCap();
      const audit = auditRows();
      const plain = await connectConsumer("sess-retry-cap-direct", false);
      const lean = await connectConsumer("sess-retry-cap-lean");
      await plain.client.listTools();
      await lean.client.callTool({ name: "search_tools", arguments: {} });
      const stale = desk;
      desk = await makeDesk();
      await stale.close();
      const failedRequests = vi.spyOn(stale.session.client, "request");
      getSessionMock.mockClear();

      const direct = await overrunCap(() =>
        directCall(plain, tool, { id: "cap", token: "tok-direct" }),
      );
      await until(
        () => desk.wire.cancels.length === 1,
        "the direct retry cancel",
      );
      // The direct leg outlived the catalog's one-second TTL. Start the lean
      // leg at the same clock time so it retains the stale route and really
      // exercises recovery, instead of refreshing onto the replacement.
      vi.setSystemTime(new Date(T0));
      const viaLean = await overrunCap(() =>
        leanCall(lean, door, tool, { id: "cap", token: "tok-lean" }),
      );
      await until(
        () => desk.wire.cancels.length === 2,
        "the lean retry cancel",
      );

      expect(getSessionMock).toHaveBeenCalledTimes(2);
      expect(viaLean.code).toBe(ErrorCode.RequestTimeout);
      expect(
        failedRequests.mock.calls.filter(
          ([request]) => request.method === "tools/call",
        ),
      ).toHaveLength(2);
      expect(viaLean.message).toContain("Maximum total timeout exceeded");
      expect({
        code: viaLean.code,
        message: viaLean.message,
        data: viaLean.data,
      }).toEqual({
        code: direct.code,
        message: direct.message,
        data: direct.data,
      });
      expect(stale.wire.calls).toEqual([]);
      expect(stale.wire.cancels).toEqual([]);
      expect(desk.wire.calls).toHaveLength(2);
      expect(desk.wire.cancels).toEqual(
        desk.wire.calls.map((call) => ({ requestId: call.requestId })),
      );
      expect(desk.abortedIds).toEqual(["cap", "cap"]);
      await audit.arrived(2);
      await flush();
      expect(audit.rows).toHaveLength(2);
      expect(sameRow(audit.rows[1])).toEqual(sameRow(audit.rows[0]));
      expect(audit.rows[1]).toMatchObject({
        server_name: DESK.name,
        tool_name: tool,
        session_id: "sess-retry-cap-lean",
        success: false,
      });
    },
  );
});

describe("a closed consumer transport on a rewritten lean call", () => {
  it.each(DOORS)(
    "$door: closing the link sends the backend no cancel, and the backend call runs to completion",
    async ({ door, tool }) => {
      const audit = auditRows();
      const lean = await connectConsumer("sess-close");

      const outcome = rejectionOf(
        leanCall(lean, door, tool, { id: "x1", token: "tok-close" }),
      );
      await until(() => desk.live.length === 1, "the backend call");

      await lean.client.close();
      await outcome;
      await flush(300);

      // shared/protocol.js _onclose aborts every handler's signal and clears
      // the transport in the same synchronous run: the gateway reads that
      // state to tell a close from a cancel.
      expect(desk.wire.cancels).toEqual([]);
      expect(desk.live[0].call.signal.aborted).toBe(false);
      expect(desk.completed).toEqual([]);

      desk.liveOf("x1").finish();
      await until(() => desk.completed.includes("x1"), "the call completing");
      expect(desk.abortedIds).toEqual([]);
      expect(desk.wire.cancels).toEqual([]);
      expect(desk.wire.calls).toHaveLength(1);
      // The operation ran to its end and is audited under the real name, not
      // as a cancel.
      await audit.arrived(1);
      await flush();
      expect(audit.rows).toHaveLength(1);
      expect(audit.rows[0]).toMatchObject({
        server_name: DESK.name,
        tool_name: tool,
        session_id: "sess-close",
      });
      expect(audit.rows[0].error_code).not.toBe("cancelled");
    },
  );
});

describe("the total timeout on a rewritten lean call", () => {
  it.each(DOORS)(
    "$door: a call that outlives the total cap fails with a direct call's error, and the backend request is cancelled",
    async ({ door, tool }) => {
      useCap();
      const audit = auditRows();
      const plain = await connectConsumer("sess-cap-direct", false);
      const lean = await connectConsumer("sess-cap-lean");

      const direct = await overrunCap(() =>
        directCall(plain, tool, { id: "cap", token: "tok-direct" }),
      );
      await until(() => desk.wire.cancels.length === 1, "the direct cancel");
      const viaLean = await overrunCap(() =>
        leanCall(lean, door, tool, { id: "cap", token: "tok-lean" }),
      );
      await until(() => desk.wire.cancels.length === 2, "the lean cancel");

      expect(direct.code).toBe(ErrorCode.RequestTimeout);
      expect(direct.message).toContain("Maximum total timeout exceeded");
      // The very same error shape, text and data included.
      expect({
        code: viaLean.code,
        message: viaLean.message,
        data: viaLean.data,
      }).toEqual({
        code: direct.code,
        message: direct.message,
        data: direct.data,
      });
      expect(
        (viaLean.data as { maxTotalTimeout?: number }).maxTotalTimeout,
      ).toBe(1_000);
      // Each call's own backend request was cancelled, once, and no other.
      const [directRequest, leanRequest] = desk.wire.calls.map(
        (entry) => entry.requestId,
      );
      expect(desk.wire.cancels).toEqual([
        { requestId: directRequest },
        { requestId: leanRequest },
      ]);
      expect(desk.abortedIds).toEqual(["cap", "cap"]);
      // The lean call's row is the direct call's row, for the real tool.
      await audit.arrived(2);
      await flush();
      expect(audit.rows).toHaveLength(2);
      expect(sameRow(audit.rows[1])).toEqual(sameRow(audit.rows[0]));
      expect(audit.rows[1]).toMatchObject({
        server_name: DESK.name,
        tool_name: tool,
        session_id: "sess-cap-lean",
        success: false,
      });
    },
  );
});

describe("a typed M365 broker refusal on a rewritten lean call", () => {
  it.each(DOORS)(
    "$door: answers with the enrollment result a direct call gets, sends the backend nothing, and audits the same row",
    async ({ door, tool }) => {
      const audit = auditRows();
      const real = desk.session.client.request.bind(desk.session.client);
      vi.spyOn(desk.session.client, "request").mockImplementation(((
        request: { method: string },
        schema: never,
        options: never,
      ) =>
        request.method === "tools/call"
          ? Promise.reject(
              new M365BrokerError(
                "credential_missing",
                "No account.",
                "https://enroll.example.test/m365",
              ),
            )
          : real(request as never, schema, options)) as never);
      const plain = await connectConsumer("sess-broker-direct", false);
      const lean = await connectConsumer("sess-broker-lean");

      const direct = await outcomeOf(
        directCall(plain, tool, { id: "b1", token: "tok-direct" }),
      );
      const viaLean = await outcomeOf(
        leanCall(lean, door, tool, { id: "b1", token: "tok-lean" }),
      );

      expect(viaLean).toEqual(direct);
      const answer = viaLean.result as CallToolResult;
      expect(answer.isError).toBe(true);
      expect(JSON.parse(textOf(answer))).toMatchObject({
        error: "credential_missing",
        enroll_url: "https://enroll.example.test/m365",
      });
      expect(desk.wire.calls).toEqual([]);
      expect(desk.wire.cancels).toEqual([]);
      expect(lean.progress()).toEqual([]);
      await audit.arrived(2);
      await flush();
      expect(audit.rows).toHaveLength(2);
      expect(sameRow(audit.rows[1])).toEqual(sameRow(audit.rows[0]));
      expect(audit.rows[1]).toMatchObject({
        server_name: DESK.name,
        tool_name: tool,
        session_id: "sess-broker-lean",
        success: false,
      });
    },
  );
});

describe("kill switches, each alone", () => {
  describe("MCP_TOOL_CALL_PROGRESS=off", () => {
    it.each(DOORS)(
      "$door: the consumer's token reaches the backend verbatim and nothing is relayed",
      async ({ door, tool }) => {
        setEnv("MCP_TOOL_CALL_PROGRESS", "off");
        const lean = await connectConsumer("sess-progress-off");

        const result = leanCall(lean, door, tool, {
          id: "o1",
          token: "tok-verbatim",
        });
        await until(() => desk.live.length === 1, "the backend call");
        // The backend answers under the token it was given: the consumer's
        // own, since nothing replaced it. Nobody here relays it.
        expect(desk.live[0].call.token).toBe("tok-verbatim");
        expect(desk.wire.calls[0].progressToken).toBe("tok-verbatim");
        await desk.liveOf("o1").progress(1);
        await desk.liveOf("o1").progress(2);
        desk.liveOf("o1").finish();
        expect(textOf(await result)).toBe(`finished o1 by ${tool}`);
        await flush();

        expect(lean.progress()).toEqual([]);
      },
    );

    it("leaves the cancel link on: an explicit cancel still reaches its own backend request", async () => {
      setEnv("MCP_TOOL_CALL_PROGRESS", "off");
      const lean = await connectConsumer("sess-progress-off-cancel");

      const controller = new AbortController();
      const outcome = rejectionOf(
        leanCall(lean, "call_tool", "read", {
          id: "o2",
          token: "tok-verbatim",
          signal: controller.signal,
        }),
      );
      await until(() => desk.live.length === 1, "the backend call");
      controller.abort();
      await outcome;
      await until(() => desk.wire.cancels.length === 1, "the backend cancel");

      expect(desk.wire.cancels).toEqual([
        { requestId: desk.wire.calls[0].requestId },
      ]);
    });
  });

  describe("MCP_TOOL_CALL_CANCEL=off", () => {
    it.each(DOORS)(
      "$door: an explicit cancel does not reach the backend request",
      async ({ door, tool }) => {
        setEnv("MCP_TOOL_CALL_CANCEL", "off");
        const audit = auditRows();
        const lean = await connectConsumer("sess-cancel-off");

        const controller = new AbortController();
        const outcome = rejectionOf(
          leanCall(lean, door, tool, {
            id: "k1",
            token: "tok-cancel-off",
            signal: controller.signal,
          }),
        );
        await until(() => desk.live.length === 1, "the backend call");
        controller.abort();
        await outcome;
        await flush(300);

        expect(desk.wire.cancels).toEqual([]);
        expect(desk.live[0].call.signal.aborted).toBe(false);
        // The operation is still running, and runs to its end.
        expect(desk.completed).toEqual([]);
        desk.liveOf("k1").finish();
        await until(() => desk.completed.includes("k1"), "the call ending");
        expect(desk.abortedIds).toEqual([]);
        expect(desk.wire.cancels).toEqual([]);
        // Nothing was cancelled at the gateway either, so no cancelled row.
        await audit.arrived(1);
        await flush();
        expect(audit.rows).toHaveLength(1);
        expect(audit.rows[0]).toMatchObject({
          server_name: DESK.name,
          tool_name: tool,
          session_id: "sess-cancel-off",
        });
        expect(audit.rows[0].error_code).not.toBe("cancelled");
      },
    );

    it("leaves the progress relay on: backend progress still reaches the consumer under its own token", async () => {
      setEnv("MCP_TOOL_CALL_CANCEL", "off");
      const lean = await connectConsumer("sess-cancel-off-progress");

      const result = leanCall(lean, "call_write_tool", "write", {
        id: "k2",
        token: "tok-still-relayed",
      });
      await until(() => desk.live.length === 1, "the backend call");
      await desk.liveOf("k2").progress(1);
      await desk.liveOf("k2").progress(2);
      await until(() => lean.progress().length === 2, "the relayed updates");
      desk.liveOf("k2").finish();
      await result;

      expect(lean.progress()).toEqual([
        { token: "tok-still-relayed", progress: 1 },
        { token: "tok-still-relayed", progress: 2 },
      ]);
      expect(desk.wire.calls[0].progressToken).not.toBe("tok-still-relayed");
    });

    it.each(DOORS)(
      "$door: a call that outlives the total cap fails as a direct call does and the backend gets no cancel",
      async ({ door, tool }) => {
        setEnv("MCP_TOOL_CALL_CANCEL", "off");
        useCap();
        const plain = await connectConsumer("sess-cap-off-direct", false);
        const lean = await connectConsumer("sess-cap-off-lean");

        const direct = await overrunCap(() =>
          directCall(plain, tool, { id: "cap-off", token: "tok-direct" }),
        );
        const viaLean = await overrunCap(() =>
          leanCall(lean, door, tool, { id: "cap-off", token: "tok-lean" }),
        );
        await flush(300);

        expect(direct.message).toContain("Maximum total timeout exceeded");
        expect({
          code: viaLean.code,
          message: viaLean.message,
          data: viaLean.data,
        }).toEqual({
          code: direct.code,
          message: direct.message,
          data: direct.data,
        });
        expect(desk.wire.calls).toHaveLength(2);
        expect(desk.wire.cancels).toEqual([]);
        expect(desk.live.every((entry) => !entry.call.signal.aborted)).toBe(
          true,
        );
      },
    );
  });

  describe("the read-only recheck just before the send", () => {
    // The call has passed the early classified-target check, the filter and
    // the routing when the namespace's override for the same tool turns
    // read-only off. The handler is then held where it reads the timeout, the
    // last await before the send. Only the recheck at the send can refuse it.
    const SWITCHES = [
      { label: "both switches on", name: undefined, value: undefined },
      {
        label: "MCP_TOOL_CALL_PROGRESS=off",
        name: "MCP_TOOL_CALL_PROGRESS",
        value: "off",
      },
      {
        label: "MCP_TOOL_CALL_CANCEL=off",
        name: "MCP_TOOL_CALL_CANCEL",
        value: "off",
      },
    ] as const;

    it.each(SWITCHES)(
      "refuses a target that changed after the filter and sends nothing, so cancels nothing ($label)",
      async ({ name, value }) => {
        if (name) setEnv(name, value);
        const audit = auditRows();
        const lean = await connectConsumer("sess-recheck");
        await lean.client.callTool({ name: "search_tools", arguments: {} });

        let reached: () => void = () => undefined;
        const held = new Promise<void>((resolve) => {
          reached = resolve;
        });
        let release: () => void = () => undefined;
        const gate = new Promise<void>((resolve) => {
          release = resolve;
        });
        config.beforeTimeoutRead = async () => {
          config.beforeTimeoutRead = undefined;
          reached();
          await gate;
        };
        const controller = new AbortController();
        const pending = leanCall(lean, "call_tool", "read", {
          id: "r1",
          token: "tok-recheck",
          signal: controller.signal,
        });
        await held;
        // The setter: the same tool is no longer read-only, and the catalog
        // snapshot the verdict came from is revoked.
        state.mappings.push({
          namespaceUuid: NS,
          serverUuid: DESK.uuid,
          toolName: "read",
          status: "ACTIVE",
          overrideAnnotations: { readOnlyHint: false },
        });
        clearOverrideCache(NS);
        release();

        const refused = await pending;
        await flush(300);

        expect(refused.isError).toBe(true);
        expect(textOf(refused)).toContain("changed");
        expect(textOf(refused)).toContain("search_tools");
        expect(textOf(refused)).not.toContain("call_write_tool");
        // Nothing reached the backend, so there was nothing to cancel.
        expect(desk.wire.calls).toEqual([]);
        expect(desk.wire.cancels).toEqual([]);
        expect(desk.live).toEqual([]);
        expect(lean.progress()).toEqual([]);
        await audit.arrived(1);
        await flush();
        expect(audit.rows).toHaveLength(1);
        expect(audit.rows[0]).toMatchObject({
          server_name: DESK.name,
          tool_name: "read",
          session_id: "sess-recheck",
          success: false,
          error_code: "tool_error",
        });
      },
    );
  });
});
