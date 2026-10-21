/**
 * tools/call routing for a name the session's routing map does not hold,
 * driven end to end through `createServer` (tool-call-routing.ts).
 *
 * The defect: when a call missed the routing map, the proxy walked every
 * server in the namespace and, if the owning server had no live session at
 * that moment, the only rescue resolved the server from the namespace's
 * ACTIVE tool mapping rows. A namespace with no rows (the `allow_all`
 * default) could never be rescued, and every miss answered
 * `Unknown tool: <name>`, the text a typo gets. Parallel calls to a real tool
 * intermittently "did not exist".
 *
 * A real SDK consumer `Client` talks to the gateway's own `Server`. Backend
 * sessions are fakes that list a fixed tool set and count what they ran; the
 * pool is a fake `getSession` the test scripts, and the bounded warm-up is the
 * REAL one (short timeout), so the fallback's retry is exercised as written.
 * The filter is replaced by a stand-in that binds the context the real filter
 * would (`toolPolicy`, `allowedToolServerUuids`), so each case controls the
 * policy directly; the real filter in front of this path is covered by
 * metamcp-proxy.override-filter.test.ts.
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import {
  CallToolResult,
  CallToolResultSchema,
  McpError,
} from "@modelcontextprotocol/sdk/types.js";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { ConnectedClient } from "./client";

const {
  getSessionMock,
  invalidateServerConnectionMock,
  isPooledClientMock,
  findServersMock,
  serverStatesMock,
  filterState,
} = vi.hoisted(() => ({
  getSessionMock: vi.fn(),
  invalidateServerConnectionMock: vi.fn(),
  isPooledClientMock: vi.fn(),
  findServersMock: vi.fn(),
  serverStatesMock: vi.fn(),
  filterState: {
    toolPolicy: "allow_all" as "allow_all" | "allowlist" | undefined,
    allowed: undefined as string[] | undefined,
  },
}));

vi.mock("@/utils/logger", () => ({
  default: { error: vi.fn(), warn: vi.fn(), info: vi.fn(), debug: vi.fn() },
}));

vi.mock("../../db", () => ({ db: {} }));
vi.mock("../../db/schema", () => ({}));
vi.mock("../../db/repositories/namespaces.repo", () => ({
  namespacesRepository: {
    findServersForNamespaceToolName: findServersMock,
  },
}));
vi.mock("../../db/repositories/oauth-sessions.repo", () => ({
  oauthSessionsRepository: {},
}));
vi.mock("../../trpc/tools.impl", () => ({ toolsImplementations: {} }));

vi.mock("../config.service", () => ({
  configService: {
    getMcpResetTimeoutOnProgress: async () => false,
    getMcpTimeout: async () => 5_000,
    getMcpMaxTotalTimeout: async () => 60_000,
    // Per-attempt cap of the real bounded warm-up (two attempts).
    getMcpToolCallReconnectWarmupTimeout: async () => 50,
  },
}));

vi.mock("./fetch-metamcp", () => ({
  getMcpServers: vi.fn(),
  getNamespaceServerStates: serverStatesMock,
}));

vi.mock("./mcp-server-pool", () => ({
  mcpServerPool: {
    getSession: getSessionMock,
    invalidateServerConnection: invalidateServerConnectionMock,
    isPooledClient: isPooledClientMock,
    cleanupSession: vi.fn(),
  },
}));

vi.mock("./metamcp-middleware/auditing.functional", () => ({
  createAuditingMiddleware: () => (next: unknown) => next,
}));
// Binds what the real filter binds for an allowed call: the policy it judged
// under and the mounted servers it judged.
vi.mock("./metamcp-middleware/filter-tools.functional", () => ({
  createFilterCallToolMiddleware:
    () =>
    (next: (request: unknown, context: unknown) => unknown) =>
    (request: unknown, context: object) =>
      next(request, {
        ...context,
        toolPolicy: filterState.toolPolicy,
        allowedToolServerUuids: filterState.allowed,
      }),
  createFilterListToolsMiddleware: () => (next: unknown) => next,
}));
vi.mock("./metamcp-middleware/tool-overrides.functional", () => ({
  createToolOverridesCallToolMiddleware: () => (next: unknown) => next,
  createToolOverridesListToolsMiddleware: () => (next: unknown) => next,
}));
vi.mock("./cold-connect-broker-fallback", () => ({
  resolveColdConnectBrokerFallback: () => undefined,
}));

import { getMcpServers } from "./fetch-metamcp";
import { createServer } from "./metamcp-proxy";

const NS = "ns-1";
const SERVERS = {
  alpha: { uuid: "server-alpha", name: "alpha" },
  beta: { uuid: "server-beta", name: "beta" },
  gamma: { uuid: "server-gamma", name: "gamma" },
};
const TOOL = "gamma__run_report";

interface FakeBackend {
  session: ConnectedClient;
  /** Backend tool names it was asked to run. */
  ran: string[];
  /** How many tools/list requests it answered or failed. */
  lists: () => number;
}

/**
 * A pooled session for a backend serving `tools`. `failCall` rejects the next
 * tools/call sends with the given error (before anything runs); `failList`
 * rejects every tools/list.
 */
function fakeBackend(
  options: {
    tools?: string[];
    failCall?: () => Error | undefined;
    failList?: Error;
  } = {},
): FakeBackend {
  const tools = options.tools ?? ["run_report", "inspect_user"];
  const ran: string[] = [];
  let lists = 0;
  const request = vi.fn(
    async (req: { method: string; params: { name?: string } }) => {
      if (req.method === "tools/list") {
        lists += 1;
        if (options.failList) throw options.failList;
        return {
          tools: tools.map((name) => ({
            name,
            inputSchema: { type: "object" },
          })),
        };
      }
      const failure = options.failCall?.();
      if (failure) throw failure;
      ran.push(req.params.name ?? "");
      // Yield so parallel calls genuinely overlap.
      await new Promise((resolve) => setTimeout(resolve, 5));
      return {
        content: [{ type: "text", text: `ran ${req.params.name}` }],
      } satisfies CallToolResult;
    },
  );
  const client = {
    request,
    getServerCapabilities: () => ({ tools: {} }),
    getServerVersion: () => ({ name: "gamma", version: "1.0.0" }),
  } as unknown as Client;
  return {
    session: {
      client,
      cleanup: async () => undefined,
      listChangedSubscribers: new Set(),
    } as unknown as ConnectedClient,
    ran,
    lists: () => lists,
  };
}

const cleanups: Array<() => Promise<unknown>> = [];

async function connectConsumer(sessionId = "sess-1"): Promise<Client> {
  const { server } = await createServer(NS, sessionId);
  const [consumerSide, gatewaySide] = InMemoryTransport.createLinkedPair();
  await server.connect(gatewaySide);
  const consumer = new Client({ name: "consumer", version: "1.0.0" });
  await consumer.connect(consumerSide);
  cleanups.push(() => consumer.close());
  return consumer;
}

const call = (consumer: Client, name = TOOL) =>
  consumer.request(
    { method: "tools/call", params: { name, arguments: {} } },
    CallToolResultSchema,
    { timeout: 10_000 },
  );

async function rejectionOf(promise: Promise<unknown>): Promise<McpError> {
  try {
    await promise;
  } catch (error) {
    return error as McpError;
  }
  throw new Error("expected the tools/call to reject");
}

const unavailableText = (reason: string, server = "gamma", tool = TOOL) =>
  `Backend "${server}" is unavailable (${reason}): tool "${tool}" was not run. Retry the call.`;

/** The routable servers getMcpServers returns, by key. */
function mount(...keys: Array<keyof typeof SERVERS>): void {
  vi.mocked(getMcpServers).mockResolvedValue(
    Object.fromEntries(
      keys.map((key) => [
        SERVERS[key].uuid,
        { uuid: SERVERS[key].uuid, name: SERVERS[key].name },
      ]),
    ) as never,
  );
}

const serversAskedFor = () =>
  getSessionMock.mock.calls.map(([, serverUuid]) => serverUuid);

beforeEach(() => {
  getSessionMock.mockReset();
  invalidateServerConnectionMock.mockReset();
  invalidateServerConnectionMock.mockResolvedValue(undefined);
  isPooledClientMock.mockReset();
  isPooledClientMock.mockReturnValue(true);
  findServersMock.mockReset();
  // The production case: a namespace with no tool mapping rows.
  findServersMock.mockResolvedValue([]);
  serverStatesMock.mockReset();
  serverStatesMock.mockResolvedValue([]);
  filterState.toolPolicy = "allow_all";
  filterState.allowed = undefined;
  mount("alpha", "beta", "gamma");
});

afterEach(async () => {
  while (cleanups.length > 0) {
    await cleanups
      .pop()?.()
      .catch(() => undefined);
  }
});

describe("prefix-first routing: only the prefix's server is touched", () => {
  it("opens one session, for the prefix's server, in a three-server namespace", async () => {
    const gamma = fakeBackend();
    getSessionMock.mockResolvedValue(gamma.session);

    const result = await call(await connectConsumer());

    expect(result.content).toEqual([{ type: "text", text: "ran run_report" }]);
    // The other two servers were never asked for a session. Before the fix
    // the lookup opened (or waited on) one for every server listed first.
    expect(serversAskedFor()).toEqual([SERVERS.gamma.uuid]);
  });

  it("answers Unknown tool at once for a prefix no mounted server carries", async () => {
    const error = await rejectionOf(
      call(await connectConsumer(), "nosuch__run_report"),
    );

    expect(error.message).toBe(
      "MCP error -32603: Unknown tool: nosuch__run_report",
    );
    expect(getSessionMock).not.toHaveBeenCalled();
    expect(findServersMock).toHaveBeenCalledTimes(1);
    expect(serverStatesMock).toHaveBeenCalledTimes(1);
  });

  it("answers Unknown tool when the server listed its tools without this one", async () => {
    const gamma = fakeBackend({ tools: ["inspect_user"] });
    getSessionMock.mockResolvedValue(gamma.session);

    const error = await rejectionOf(call(await connectConsumer()));

    expect(error.message).toBe(`MCP error -32603: Unknown tool: ${TOOL}`);
    expect(gamma.ran).toEqual([]);
    // An authoritative listing is not a reason to wait: no warm-up retry.
    expect(getSessionMock).toHaveBeenCalledTimes(1);
  });
});

describe("zero mapping rows under allow_all: the prefix's server is warmed", () => {
  it("succeeds when the pool has no session once, then a live one", async () => {
    const gamma = fakeBackend();
    getSessionMock
      .mockResolvedValueOnce(undefined)
      .mockResolvedValue(gamma.session);

    const result = await call(await connectConsumer());

    expect(result.content).toEqual([{ type: "text", text: "ran run_report" }]);
    expect(gamma.ran).toEqual(["run_report"]);
    // No row resolved the tool; the bounded warm-up on the prefix's server did.
    expect(findServersMock).toHaveBeenCalledWith(NS, "run_report");
    expect(serversAskedFor()).toEqual([SERVERS.gamma.uuid, SERVERS.gamma.uuid]);
    // The warmed session was listed before routing: the tool is confirmed.
    expect(gamma.lists()).toBe(1);
  });

  it("8 parallel calls from a fresh session all succeed when the first acquisition fails", async () => {
    const gamma = fakeBackend();
    getSessionMock
      .mockResolvedValueOnce(undefined)
      .mockResolvedValue(gamma.session);
    const consumer = await connectConsumer();

    const results = await Promise.allSettled(
      Array.from({ length: 8 }, () => call(consumer)),
    );

    expect(results.map((r) => r.status)).toEqual(
      Array.from({ length: 8 }, () => "fulfilled"),
    );
    expect(gamma.ran).toHaveLength(8);
  });

  it("answers backend unavailable, never Unknown tool, when the warm-up is exhausted", async () => {
    getSessionMock.mockResolvedValue(undefined);

    const error = await rejectionOf(call(await connectConsumer()));

    expect(error.message).toBe(
      `MCP error -32603: ${unavailableText("no_session")}`,
    );
    expect(error.data).toEqual({
      code: "backend_unavailable",
      server: "gamma",
      tool: TOOL,
      reason: "no_session",
      executed: false,
      retryable: true,
    });
    // One primary attempt plus the warm-up's two.
    expect(serversAskedFor()).toEqual([
      SERVERS.gamma.uuid,
      SERVERS.gamma.uuid,
      SERVERS.gamma.uuid,
    ]);
  });
});

describe("allowlist policy: nothing is routed without an ACTIVE row", () => {
  beforeEach(() => {
    filterState.toolPolicy = "allowlist";
  });

  it("does not warm the prefix's server for a tool with no row", async () => {
    const gamma = fakeBackend();
    getSessionMock
      .mockResolvedValueOnce(undefined)
      .mockResolvedValue(gamma.session);

    const error = await rejectionOf(call(await connectConsumer()));

    // The server is mounted, so the answer is honest about it, but the
    // widened fallback did not run: one acquisition, nothing executed.
    expect(error.message).toBe(
      `MCP error -32603: ${unavailableText("no_session")}`,
    );
    expect(getSessionMock).toHaveBeenCalledTimes(1);
    expect(gamma.ran).toEqual([]);
  });

  it("still recovers through an ACTIVE row in the reconnect window", async () => {
    const gamma = fakeBackend();
    getSessionMock
      .mockResolvedValueOnce(undefined)
      .mockResolvedValue(gamma.session);
    findServersMock.mockResolvedValue([
      { serverUuid: SERVERS.gamma.uuid, serverName: "gamma" },
    ]);

    const result = await call(await connectConsumer());

    expect(result.content).toEqual([{ type: "text", text: "ran run_report" }]);
  });

  it("keeps Unknown tool when the warmed ACTIVE-row server has no tools capability", async () => {
    const gamma = fakeBackend();
    vi.spyOn(gamma.session.client, "getServerCapabilities").mockReturnValue({});
    getSessionMock
      .mockResolvedValueOnce(undefined)
      .mockResolvedValue(gamma.session);
    findServersMock.mockResolvedValue([
      { serverUuid: SERVERS.gamma.uuid, serverName: "gamma" },
    ]);

    const error = await rejectionOf(call(await connectConsumer()));

    expect(error.message).toBe(`MCP error -32603: Unknown tool: ${TOOL}`);
    expect(gamma.ran).toEqual([]);
  });

  it("never widens when no filter judged the call (no policy on the context)", async () => {
    filterState.toolPolicy = undefined;
    const gamma = fakeBackend();
    getSessionMock
      .mockResolvedValueOnce(undefined)
      .mockResolvedValue(gamma.session);

    const error = await rejectionOf(call(await connectConsumer()));

    expect(error.message).toContain("(no_session)");
    expect(gamma.ran).toEqual([]);
  });
});

describe("a mounted server that cannot be used is never reported as an unknown tool", () => {
  it("an error-gated server answers backend unavailable (error_gated)", async () => {
    // getMcpServers leaves an error-gated server out of the routable set.
    mount("alpha", "beta");
    serverStatesMock.mockResolvedValue([
      {
        uuid: SERVERS.gamma.uuid,
        name: "gamma",
        mountStatus: "ACTIVE",
        errorStatus: "ERROR",
      },
    ]);

    const error = await rejectionOf(call(await connectConsumer()));

    expect(error.message).toBe(
      `MCP error -32603: ${unavailableText("error_gated")}`,
    );
    expect(getSessionMock).not.toHaveBeenCalled();
  });

  it("an INACTIVE mount stays an unknown tool (switched off on purpose)", async () => {
    mount("alpha", "beta");
    serverStatesMock.mockResolvedValue([
      {
        uuid: SERVERS.gamma.uuid,
        name: "gamma",
        mountStatus: "INACTIVE",
        errorStatus: "NONE",
      },
    ]);

    const error = await rejectionOf(call(await connectConsumer()));

    expect(error.message).toBe(`MCP error -32603: Unknown tool: ${TOOL}`);
  });

  it("an error-gated server the filter did not judge stays an unknown tool", async () => {
    mount("alpha", "beta");
    filterState.allowed = ["server-other"];
    serverStatesMock.mockResolvedValue([
      {
        uuid: SERVERS.gamma.uuid,
        name: "gamma",
        mountStatus: "ACTIVE",
        errorStatus: "ERROR",
      },
    ]);

    const error = await rejectionOf(call(await connectConsumer()));

    expect(error.message).toBe(`MCP error -32603: Unknown tool: ${TOOL}`);
  });

  it("a routable server the first read missed answers backend unavailable (routing_lookup_failed)", async () => {
    // getMcpServers answers an empty set on a database error rather than
    // throwing; the second read finds the server mounted, ACTIVE, not gated.
    vi.mocked(getMcpServers).mockResolvedValue({});
    serverStatesMock.mockResolvedValue([
      {
        uuid: SERVERS.gamma.uuid,
        name: "gamma",
        mountStatus: "ACTIVE",
        errorStatus: "NONE",
      },
    ]);

    const error = await rejectionOf(call(await connectConsumer()));

    expect(error.message).toBe(
      `MCP error -32603: ${unavailableText("routing_lookup_failed")}`,
    );
    expect(getSessionMock).not.toHaveBeenCalled();
  });

  it("a failed server read answers backend unavailable (routing_lookup_failed)", async () => {
    mount("alpha", "beta");
    serverStatesMock.mockRejectedValue(new Error("connection refused"));

    const error = await rejectionOf(call(await connectConsumer()));

    expect(error.message).toBe(
      `MCP error -32603: ${unavailableText("routing_lookup_failed")}`,
    );
  });

  it("a tool lookup that keeps failing answers backend unavailable (tool_lookup_failed)", async () => {
    const gamma = fakeBackend({ failList: new Error("socket hang up") });
    getSessionMock.mockResolvedValue(gamma.session);

    const error = await rejectionOf(call(await connectConsumer()));

    expect(error.message).toBe(
      `MCP error -32603: ${unavailableText("tool_lookup_failed")}`,
    );
    expect(gamma.ran).toEqual([]);
  });
});

describe("same-named mounted servers: every possible owner must be accounted for", () => {
  const peerUuid = "server-gamma-peer";

  beforeEach(() => {
    vi.mocked(getMcpServers).mockResolvedValue({
      [SERVERS.gamma.uuid]: { uuid: SERVERS.gamma.uuid, name: "gamma" },
      [peerUuid]: { uuid: peerUuid, name: "gamma" },
    } as never);
    filterState.allowed = [SERVERS.gamma.uuid, peerUuid];
  });

  it("keeps Unknown tool when every owner answers without the tool", async () => {
    const first = fakeBackend({ tools: ["inspect_user"] });
    const second = fakeBackend({ tools: ["inspect_user"] });
    getSessionMock.mockImplementation(async (_sessionId, uuid: string) =>
      uuid === peerUuid ? second.session : first.session,
    );
    serverStatesMock.mockResolvedValue(
      [SERVERS.gamma.uuid, peerUuid].map((uuid) => ({
        uuid,
        name: "gamma",
        mountStatus: "ACTIVE",
        errorStatus: "NONE",
      })),
    );

    const error = await rejectionOf(call(await connectConsumer()));

    expect(error.message).toBe(`MCP error -32603: Unknown tool: ${TOOL}`);
    expect(getSessionMock).toHaveBeenCalledTimes(2);
    expect(first.ran).toEqual([]);
    expect(second.ran).toEqual([]);
  });

  it("warms the second owner when the first comes back without the tool", async () => {
    const first = fakeBackend({ tools: ["inspect_user"] });
    const second = fakeBackend();
    const attempts = new Map<string, number>();
    getSessionMock.mockImplementation(async (_sessionId, uuid: string) => {
      const count = (attempts.get(uuid) ?? 0) + 1;
      attempts.set(uuid, count);
      if (count === 1) return undefined;
      return uuid === peerUuid ? second.session : first.session;
    });

    const result = await call(await connectConsumer());

    expect(result.content).toEqual([{ type: "text", text: "ran run_report" }]);
    expect(first.ran).toEqual([]);
    expect(second.ran).toEqual(["run_report"]);
    expect(serversAskedFor()).toEqual([
      SERVERS.gamma.uuid,
      peerUuid,
      SERVERS.gamma.uuid,
      peerUuid,
    ]);
  });

  it("keeps a peer's failed lookup when the first owner warms without the tool", async () => {
    const first = fakeBackend({ tools: ["inspect_user"] });
    const second = fakeBackend({ failList: new Error("socket hang up") });
    let firstAttempts = 0;
    getSessionMock.mockImplementation(async (_sessionId, uuid: string) => {
      if (uuid === peerUuid) return second.session;
      firstAttempts += 1;
      return firstAttempts === 1 ? undefined : first.session;
    });

    const error = await rejectionOf(call(await connectConsumer()));

    expect(error.message).toBe(
      `MCP error -32603: ${unavailableText("tool_lookup_failed")}`,
    );
    expect(first.ran).toEqual([]);
    expect(second.ran).toEqual([]);
  });

  it.each([
    ["ERROR", "error_gated"],
    ["NONE", "routing_lookup_failed"],
  ])(
    "checks an omitted peer (%s) after the reachable owner lists without the tool",
    async (errorStatus, reason) => {
      mount("gamma");
      const first = fakeBackend({ tools: ["inspect_user"] });
      getSessionMock.mockResolvedValue(first.session);
      serverStatesMock.mockResolvedValue([
        {
          uuid: SERVERS.gamma.uuid,
          name: "gamma",
          mountStatus: "ACTIVE",
          errorStatus: "NONE",
        },
        {
          uuid: peerUuid,
          name: "gamma",
          mountStatus: "ACTIVE",
          errorStatus,
        },
      ]);

      const error = await rejectionOf(call(await connectConsumer()));

      expect(error.message).toBe(
        `MCP error -32603: ${unavailableText(reason)}`,
      );
      expect(first.ran).toEqual([]);
    },
  );
});

describe("replay recovery is shared by parallel calls on one dead client", () => {
  it("8 parallel calls on a client that refuses the send: one invalidation, one new session", async () => {
    let dead = false;
    const stale = fakeBackend({
      failCall: () => (dead ? new Error("Not connected") : undefined),
    });
    const fresh = fakeBackend();
    getSessionMock.mockResolvedValueOnce(stale.session);
    const consumer = await connectConsumer();
    // Warm the routing map with one successful call, then let the pooled
    // client die under it.
    await call(consumer);
    dead = true;
    getSessionMock.mockReset();
    getSessionMock.mockResolvedValue(fresh.session);
    let pooled = true;
    isPooledClientMock.mockImplementation(() => pooled);
    invalidateServerConnectionMock.mockImplementation(async () => {
      // An invalidation detaches every client of the server.
      pooled = false;
    });

    const results = await Promise.allSettled(
      Array.from({ length: 8 }, () => call(consumer)),
    );

    expect(results.map((r) => r.status)).toEqual(
      Array.from({ length: 8 }, () => "fulfilled"),
    );
    expect(fresh.ran).toHaveLength(8);
    // One invalidation and one acquisition for all eight. Before, each call
    // invalidated the server (retiring the replacement a sibling had built)
    // and acquired its own session.
    expect(invalidateServerConnectionMock).toHaveBeenCalledTimes(1);
    expect(getSessionMock).toHaveBeenCalledTimes(1);
    // The route moved to the new client: no call took the dynamic lookup.
    expect(fresh.lists()).toBe(0);

    // A later call goes straight to the new client.
    await call(consumer);
    expect(fresh.ran).toHaveLength(9);
    expect(getSessionMock).toHaveBeenCalledTimes(1);
  });

  it("does not invalidate again when another recovery already retired the client", async () => {
    let dead = false;
    const stale = fakeBackend({
      failCall: () => (dead ? new Error("Not connected") : undefined),
    });
    const fresh = fakeBackend();
    getSessionMock.mockResolvedValueOnce(stale.session);
    const consumer = await connectConsumer();
    await call(consumer);
    dead = true;
    getSessionMock.mockResolvedValue(fresh.session);
    // Another session's recovery already detached this client.
    isPooledClientMock.mockReturnValue(false);

    const result = await call(consumer);

    expect(result.content).toEqual([{ type: "text", text: "ran run_report" }]);
    expect(invalidateServerConnectionMock).not.toHaveBeenCalled();
  });

  it("drops the dead route when no new session can be had", async () => {
    let dead = false;
    const stale = fakeBackend({
      failCall: () => (dead ? new Error("Not connected") : undefined),
    });
    getSessionMock.mockResolvedValueOnce(stale.session);
    const consumer = await connectConsumer();
    await call(consumer);
    dead = true;
    getSessionMock.mockResolvedValue(undefined);

    const error = await rejectionOf(call(consumer));
    expect(error.message).toContain("Failed to re-initialize session");

    // The next call does not reuse the dead client: it routes afresh and,
    // with the server still unreachable, says so honestly.
    const next = await rejectionOf(call(consumer));
    expect(next.message).toBe(
      `MCP error -32603: ${unavailableText("no_session")}`,
    );
  });
});
