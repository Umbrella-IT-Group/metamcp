/**
 * A user with no Microsoft 365 grant, driven end to end through
 * `createServer`: a real consumer `Client`, the real proxy handlers, the REAL
 * m365 client chain behind the pool (`connectMetaMcpClient` over a real SDK
 * transport, the real injected fetch, a mint stub that throws what the broker
 * throws for an unenrolled user) and a fake backend. Only the pool itself is
 * a stand-in: it connects through `connectMetaMcpClient` the way the real one
 * does, shares the connection between sessions, and treats the connection's
 * drop callback as the pool's invalidation cascade.
 *
 * The defect: the user's missing grant failed their listing (the handshake and
 * `tools/list` needed their token), so m365 was left out of their tools, the
 * namespace logged `tools/list DEGRADED` (the line the namespace-degraded
 * alert counts), every session's pooled m365 connection was invalidated, and
 * the session was owed a re-notify that re-listed into the same failure.
 *
 * What it pins:
 *   - the user lists the m365 tools, with no error line, no DEGRADED line,
 *     no drop and nothing owed;
 *   - their tool call is answered with the structured enrollment result (code,
 *     enroll URL, action) and one `m365_broker_refusal` line, and no error line;
 *   - one user's refusal does not disturb another session's call on the same
 *     pooled connection, which carries only its own user's token;
 *   - negative controls: a server that cannot be reached, a listing that
 *     fails, and a typed broker error that DOES reach the listing handler
 *     (the method gate regressing) are all still loud and still owed.
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import logger from "@/utils/logger";

import type { ConnectedClient } from "./client";

const {
  getSessionMock,
  probeMock,
  listingMock,
  serverStateMock,
  invalidateMock,
} = vi.hoisted(() => ({
  getSessionMock: vi.fn(),
  probeMock: vi.fn(),
  listingMock: vi.fn(),
  serverStateMock: vi.fn(),
  invalidateMock: vi.fn(),
}));

vi.mock("@/utils/logger", () => ({
  default: { error: vi.fn(), warn: vi.fn(), info: vi.fn(), debug: vi.fn() },
}));

vi.mock("../../db", () => ({ db: {} }));
vi.mock("../../db/index", () => ({ db: {} }));
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
vi.mock("../../trpc/tools.impl", () => ({
  toolsImplementations: { syncFromListing: vi.fn(async () => undefined) },
}));
vi.mock("../audit/admin-event", () => ({ emitAdminEvent: vi.fn() }));
vi.mock("./server-error-tracker", () => ({
  serverErrorTracker: {
    getServerMaxAttempts: vi.fn().mockResolvedValue(3),
    isServerInErrorState: vi.fn().mockResolvedValue(false),
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

vi.mock("./mcp-server-pool", () => ({
  mcpServerPool: {
    getSession: getSessionMock,
    probeServerTools: probeMock,
    isServerInErrorState: async () => false,
    invalidateServerConnection: invalidateMock,
    isPooledClient: () => false,
    cleanupSession: vi.fn(),
    getPoolStatus: () => ({ idle: 1, active: 1 }),
  },
}));

vi.mock("./metamcp-middleware/auditing.functional", () => ({
  createAuditingMiddleware: () => (next: unknown) => next,
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
vi.mock("./tool-call-warmup", () => ({
  acquireSessionWithBoundedWarmup: vi.fn(async () => undefined),
}));

// The real watch with short delays, as in the re-notify suite.
vi.mock("./tools-list-renotify", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./tools-list-renotify")>();
  return {
    ...actual,
    toolsListRenotifyWatch: new actual.ToolsListRenotifyWatch({
      delaysMs: [30, 60, 120],
    }),
  };
});

import { M365BrokerError } from "../m365/errors";
import {
  ENROLL,
  makeCreateClient,
  makeFakeBackend,
  makeMint,
  type SeenRequest,
} from "../m365/fake-streamable-backend.test-util";
import { runWithM365UserContext } from "../m365/request-context";
import { connectMetaMcpClient } from "./client";
import { createServer } from "./metamcp-proxy";
import { toolsListRenotifyWatch } from "./tools-list-renotify";
import { toolsSyncCache } from "./tools-sync-cache";

const M365 = "server-m365";
const NS = "ns-1";
const M365_PARAMS = {
  uuid: M365,
  name: "m365",
  description: "",
  type: "STREAMABLE_HTTP",
  url: "http://backend:3000/mcp",
  created_at: new Date().toISOString(),
  status: "active",
};

const cleanups: Array<() => Promise<unknown>> = [];

interface Consumer {
  client: Client;
  userId: string;
}

async function connectConsumer(
  userId: string,
  sessionId: string,
): Promise<Consumer> {
  const { server, cleanup } = await createServer(NS, sessionId);
  const [consumerSide, gatewaySide] = InMemoryTransport.createLinkedPair();
  await server.connect(gatewaySide);
  const client = new Client({ name: "consumer", version: "1.0.0" });
  await client.connect(consumerSide);
  cleanups.push(() => client.close());
  cleanups.push(cleanup);
  return { client, userId };
}

/** Every request a consumer makes carries its own user, as the router does. */
const asUser = <T>(consumer: Consumer, fn: () => Promise<T>): Promise<T> =>
  runWithM365UserContext({ userId: consumer.userId }, fn);

const listTools = (consumer: Consumer) =>
  asUser(consumer, () => consumer.client.listTools());

const callTool = (consumer: Consumer) =>
  asUser(consumer, () =>
    consumer.client.callTool({ name: "m365__mail_search", arguments: {} }),
  );

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

const errorLines = (): string[] =>
  vi.mocked(logger.error).mock.calls.map((call) => String(call[0]));
const infoLines = (): string[] =>
  vi.mocked(logger.info).mock.calls.map((call) => String(call[0]));
const refusalLines = (): string[] =>
  infoLines().filter((line) => line.includes("m365_broker_refusal"));

/** The pool stand-in: connect the real m365 chain once, share it, drop on error. */
function poolOver(
  mint: ReturnType<typeof makeMint>,
  backend: ReturnType<typeof makeFakeBackend>,
) {
  let pooled: Promise<ConnectedClient | undefined> | undefined;
  const dropped = vi.fn();
  getSessionMock.mockImplementation(async () => {
    if (!pooled) {
      pooled = connectMetaMcpClient(
        M365_PARAMS as never,
        undefined,
        (reason, error) => {
          dropped(reason, error);
          invalidateMock(M365);
        },
        { createClient: makeCreateClient(mint, backend.fetchImpl as never) },
      );
      void pooled.then((connected) => {
        if (connected) cleanups.push(() => connected.cleanup());
        else pooled = undefined;
      });
    }
    return pooled;
  });
  return { dropped };
}

beforeEach(() => {
  toolsSyncCache.clear();
  getSessionMock.mockReset();
  probeMock.mockReset();
  probeMock.mockResolvedValue(true);
  listingMock.mockReset();
  listingMock.mockResolvedValue({
    routable: { [M365]: M365_PARAMS },
    errorGated: {},
  });
  invalidateMock.mockReset();
  serverStateMock.mockReset();
  serverStateMock.mockResolvedValue({ error_status: "NONE" });
  for (const level of ["error", "warn", "info", "debug"] as const) {
    vi.mocked(logger[level]).mockClear();
  }
  delete process.env.MCP_TOOLS_LIST_RENOTIFY;
});

afterEach(async () => {
  while (cleanups.length > 0) {
    await cleanups
      .pop()?.()
      .catch(() => undefined);
  }
  vi.restoreAllMocks();
});

describe("an unenrolled m365 user through the gateway", () => {
  it("lists the m365 tools with no error, no DEGRADED line, no drop and nothing owed", async () => {
    const backend = makeFakeBackend();
    const { dropped } = poolOver(makeMint(), backend);
    const consumer = await connectConsumer("user-unenrolled", "sess-1");

    const listed = await listTools(consumer);

    expect(listed.tools.map((t) => t.name)).toEqual(["m365__mail_search"]);
    // Nothing for the namespace-degraded alert to count, and nothing at all
    // at ERROR level.
    expect(errorLines()).toEqual([]);
    expect(
      infoLines()
        .concat(errorLines())
        .some((l) => l.includes("DEGRADED")),
    ).toBe(false);
    expect(dropped).not.toHaveBeenCalled();
    expect(invalidateMock).not.toHaveBeenCalled();
    // Owed no re-notify: it was reached.
    expect(toolsListRenotifyWatch.watchedServerCount()).toBe(0);
    await sleep(120);
    expect(probeMock).not.toHaveBeenCalled();
    // The listing reached the backend with no credential and no user id.
    expect(backend.seen.length).toBeGreaterThan(0);
    for (const request of backend.seen) {
      expect(request.authorization).toBeNull();
      expect(request.userId).toBeNull();
    }
  });

  it("answers their tool call with the enrollment result and one refusal line, and logs no error", async () => {
    const backend = makeFakeBackend();
    const { dropped } = poolOver(makeMint(), backend);
    const consumer = await connectConsumer("user-unenrolled", "sess-1");
    await listTools(consumer);

    const result = await callTool(consumer);

    expect(result.isError).toBe(true);
    const payload = JSON.parse(
      (result.content as Array<{ text: string }>)[0].text,
    );
    expect(payload.error).toBe("credential_missing");
    expect(payload.enroll_url).toBe(ENROLL);
    expect(payload.action).toContain("enrollment URL");

    // One INFO refusal line, a 12-hex hash, no raw id.
    const lines = refusalLines();
    expect(lines).toHaveLength(1);
    expect(JSON.parse(lines[0]).user_hash).toMatch(/^[0-9a-f]{12}$/);
    expect(lines[0]).not.toContain("user-unenrolled");
    // No ERROR line for a per-user state, and no drop.
    expect(errorLines()).toEqual([]);
    expect(dropped).not.toHaveBeenCalled();
    expect(invalidateMock).not.toHaveBeenCalled();
    // The tool never ran and no token was sent.
    expect(backend.seen.some((r) => r.rpcMethod === "tools/call")).toBe(false);
    // The connection is intact: the user can list again straight away.
    expect((await listTools(consumer)).tools).toHaveLength(1);
    expect(toolsListRenotifyWatch.watchedServerCount()).toBe(0);
  });

  it("repeated calls repeat only the refusal: no error lines, no drops, one backend session", async () => {
    const backend = makeFakeBackend();
    const { dropped } = poolOver(makeMint(), backend);
    const consumer = await connectConsumer("user-unenrolled", "sess-1");
    await listTools(consumer);

    for (let i = 0; i < 3; i++) {
      expect((await callTool(consumer)).isError).toBe(true);
    }

    expect(refusalLines()).toHaveLength(3);
    expect(errorLines()).toEqual([]);
    expect(dropped).not.toHaveBeenCalled();
    expect(
      backend.seen.filter((r) => r.rpcMethod === "initialize"),
    ).toHaveLength(1);
  });

  it("one user's refusal does not disturb another session on the same pooled connection", async () => {
    const backend = makeFakeBackend();
    const { dropped } = poolOver(
      makeMint({ "user-enrolled": "graph-token-enrolled" }),
      backend,
    );
    const unenrolled = await connectConsumer("user-unenrolled", "sess-1");
    const enrolled = await connectConsumer("user-enrolled", "sess-2");
    await listTools(unenrolled);
    await listTools(enrolled);

    const [refused, ran] = await Promise.all([
      callTool(unenrolled),
      callTool(enrolled),
    ]);

    expect(refused.isError).toBe(true);
    expect(ran.isError).toBeFalsy();
    // The enrolled user's call, and only that call, carried a token: their own.
    const calls = backend.seen.filter(
      (r: SeenRequest) => r.rpcMethod === "tools/call",
    );
    expect(calls).toHaveLength(1);
    expect(calls[0].authorization).toBe("Bearer graph-token-enrolled");
    expect(calls[0].userId).toBe("user-enrolled");
    expect(backend.seen.some((r) => r.userId === "user-unenrolled")).toBe(
      false,
    );
    // No session's connection was invalidated, and neither is owed anything.
    expect(dropped).not.toHaveBeenCalled();
    expect(invalidateMock).not.toHaveBeenCalled();
    expect(toolsListRenotifyWatch.watchedServerCount()).toBe(0);
    expect((await callTool(enrolled)).isError).toBeFalsy();
    expect(errorLines()).toEqual([]);
  });
});

describe("a refusal on the retry after a lost backend session", () => {
  const fakeSession = (callError: Error): ConnectedClient =>
    ({
      client: {
        request: vi.fn(async (req: { method: string }) => {
          if (req.method === "tools/list") {
            return {
              tools: [{ name: "mail_search", inputSchema: { type: "object" } }],
            };
          }
          throw callError;
        }),
        getServerCapabilities: () => ({ tools: {} }),
        getServerVersion: () => ({ name: "m365", version: "1.0.0" }),
      },
      cleanup: async () => undefined,
      listChangedSubscribers: new Set(),
    }) as unknown as ConnectedClient;

  it("is answered with the enrollment result and logs no error line", async () => {
    // The first send fails before the backend ran it ("Not connected"), so
    // the call is replayed on a fresh session; the user's grant then turns out
    // to be unusable. That refusal is the answer, not a tool failure.
    const stale = fakeSession(new Error("Not connected"));
    const fresh = fakeSession(
      new M365BrokerError("credential_expired", "Expired.", ENROLL),
    );
    getSessionMock.mockResolvedValueOnce(stale).mockResolvedValue(fresh);
    const consumer = await connectConsumer("user-expired", "sess-1");
    await listTools(consumer);

    const result = await callTool(consumer);

    expect(result.isError).toBe(true);
    const payload = JSON.parse(
      (result.content as Array<{ text: string }>)[0].text,
    );
    expect(payload.error).toBe("credential_expired");
    expect(payload.enroll_url).toBe(ENROLL);
    expect(errorLines()).toEqual([]);
    expect(refusalLines()).toHaveLength(1);
  });
});

describe("negative controls: genuine failures are still loud and still owed", () => {
  const degraded = () =>
    errorLines().filter((l) => l.includes("DEGRADED for namespace"));

  it("an unreachable server is left out, logs DEGRADED and arms the re-notify watch", async () => {
    getSessionMock.mockResolvedValue(undefined);
    const consumer = await connectConsumer("user-enrolled", "sess-1");

    await expect(listTools(consumer)).rejects.toThrow(/could not reach/);

    expect(degraded()).toHaveLength(1);
    expect(degraded()[0]).toContain("(m365)");
    expect(errorLines().some((l) => l.includes("no session available"))).toBe(
      true,
    );
    expect(toolsListRenotifyWatch.watchedServerCount()).toBe(1);
  });

  it("a plain error from the listing logs DEGRADED and arms the watch", async () => {
    const backend = makeFakeBackend();
    poolOver(makeMint({ "user-enrolled": "t" }), backend);
    const consumer = await connectConsumer("user-enrolled", "sess-1");
    await listTools(consumer);
    // The backend now fails its listing with an ordinary error.
    const pooled = (await getSessionMock()) as ConnectedClient;
    vi.spyOn(pooled.client, "request").mockRejectedValue(
      new Error("backend exploded"),
    );
    toolsSyncCache.clear();

    await expect(listTools(consumer)).rejects.toThrow(/could not reach/);

    expect(
      errorLines().some((l) => l.includes("Error fetching tools from: m365")),
    ).toBe(true);
    expect(degraded()).toHaveLength(1);
    expect(toolsListRenotifyWatch.watchedServerCount()).toBe(1);
  });

  it("a typed broker error that reaches the LISTING handler stays loud: ERROR, DEGRADED and owed", async () => {
    // After the method gate a per-user error cannot occur on a listing. If it
    // ever does, the gate regressed, and the one signal that catches that
    // must not be hidden.
    const backend = makeFakeBackend();
    poolOver(makeMint({ "user-enrolled": "t" }), backend);
    const consumer = await connectConsumer("user-enrolled", "sess-1");
    await listTools(consumer);
    const pooled = (await getSessionMock()) as ConnectedClient;
    vi.spyOn(pooled.client, "request").mockRejectedValue(
      new M365BrokerError("credential_missing", "No account.", ENROLL),
    );
    toolsSyncCache.clear();

    await expect(listTools(consumer)).rejects.toThrow(/could not reach/);

    expect(
      errorLines().some((l) => l.includes("Error fetching tools from: m365")),
    ).toBe(true);
    expect(degraded()).toHaveLength(1);
    expect(toolsListRenotifyWatch.watchedServerCount()).toBe(1);
  });
});
