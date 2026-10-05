/**
 * Evicting an idle session at the per-credential ceiling, driven end to end
 * through the REAL StreamableHTTP router over a real socket.
 *
 * The event this guards against: one key sat at 300/300 for forty minutes
 * while two thirds of what it held were idle sessions its clients had opened
 * and never closed, and the gateway refused every new session instead of
 * reclaiming one. The quota module's unit tests pin the selection rules; this
 * file pins what the ROUTE does with them, which is where the costly failures
 * would be: admitting over the ceiling, evicting a session a live client is
 * using, deleting the row a returning client needs to recover, or handing a
 * request that lands mid-teardown a transport that is not its own.
 *
 * What is real here: the router, the session manager, the idle sweeper, the
 * quota module and its throttled event helper, the SDK transports and a real
 * SDK `Server` per pooled instance (so `initialize` and `ping` are answered by
 * the SDK, not by a stub), and transport-recovery hydration (so a recovered
 * transport genuinely serves a request). What is faked: the DB-touching
 * boundaries (`mcp_sessions` as an in-memory table, `@/db`, the server pool's
 * bookkeeping), the express auth middlewares, and the durable event sink.
 *
 * Time: the idle floor is 120s, so `Date` alone is faked and stepped forward;
 * timers stay real because the sockets need them.
 */
import type { Server as HttpServer } from "node:http";

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import express from "express";
import {
  afterAll,
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";

const h = vi.hoisted(() => {
  const rows = new Map<string, unknown>();
  const trace: string[] = [];
  return {
    rows,
    trace,
    logger: { error: vi.fn(), warn: vi.fn(), info: vi.fn(), debug: vi.fn() },
    record: vi.fn(),
    getServer: vi.fn(),
    cleanupSession: vi.fn(),
    persist: vi.fn(async (row: { session_id: string }) => {
      rows.set(row.session_id, {
        ...row,
        created_at: new Date(),
        last_seen_at: new Date(),
      });
    }),
    findById: vi.fn(async (sessionId: string) => {
      trace.push(`findById:${sessionId}`);
      return rows.get(sessionId) ?? null;
    }),
    deleteRow: vi.fn(async (sessionId: string) => {
      rows.delete(sessionId);
    }),
  };
});

vi.mock("@/utils/logger", () => ({ default: h.logger }));

// `/health/sessions` is read here through its builder, never the route, so the
// admin gate (which pulls in better-auth) is stubbed out.
vi.mock("../../lib/health-upstream", () => ({
  isAdminHealthRequest: vi.fn().mockResolvedValue(false),
}));

vi.mock("@/db", () => ({ db: {}, pool: { on: vi.fn() } }));

vi.mock("@/middleware/api-key-oauth.middleware", () => ({
  authenticateApiKey: vi.fn(),
}));
vi.mock("@/middleware/lookup-endpoint-middleware", () => ({
  lookupEndpoint: vi.fn(),
}));
vi.mock("@/middleware/rate-limit.middleware", () => ({
  rateLimitMiddleware: vi.fn(),
}));

vi.mock("@/db/repositories/mcp-sessions.repo", () => ({
  mcpSessionsRepository: {
    persist: h.persist,
    findById: h.findById,
    touch: vi.fn().mockResolvedValue(undefined),
    delete: h.deleteRow,
    pruneOlderThan: vi.fn().mockResolvedValue(0),
  },
}));

vi.mock("../../lib/metamcp/consumer-identity-resolver", () => ({
  resolveClientIdentity: vi.fn().mockResolvedValue({ name: "test-consumer" }),
}));

vi.mock("../../lib/metamcp/metamcp-server-pool", () => ({
  metaMcpServerPool: {
    getServer: h.getServer,
    getServerInstance: vi.fn(),
    cleanupSession: h.cleanupSession,
    getMcpServerPoolStatus: vi.fn().mockReturnValue({ idle: 0, active: 0 }),
    getPoolStatus: vi.fn().mockReturnValue({ idle: 0, active: 0 }),
  },
}));

// The durable sink reaches `db/index`; only the envelope matters here.
vi.mock("../../lib/metamcp/log-store", () => ({
  metamcpLogStore: { record: h.record },
}));

import type { ApiKeyAuthenticatedRequest } from "@/middleware/api-key-oauth.middleware";
import { authenticateApiKey } from "@/middleware/api-key-oauth.middleware";
import { lookupEndpoint } from "@/middleware/lookup-endpoint-middleware";
import { rateLimitMiddleware } from "@/middleware/rate-limit.middleware";

import { countLiveSessionsForIdentity } from "../../lib/metamcp/credential-session-quota";
import type { SessionIdentity } from "../../lib/metamcp/session-auth";
import { __resetSessionCeilingThrottleForTesting } from "../../lib/metamcp/session-ceiling-events";
import streamableHttpRouter, {
  buildSessionsHealthPayload,
  publicSessionSweeper,
  reapIdleSession,
  recoverPersistedSession,
  resolveBoundSession,
} from "./streamable-http";

const PROTOCOL_VERSION = "2025-06-18";
const ORIGINAL_ENV = {
  ceiling: process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL,
  evict: process.env.MCP_SESSION_CEILING_EVICT_IDLE,
  minIdle: process.env.MCP_SESSION_CEILING_EVICT_MIN_IDLE_SECONDS,
};

/**
 * One api key per test. The router's session manager is module state shared
 * by the whole file, and the ceiling counts per credential, so a fresh key
 * gives each test its own budget without tearing down earlier tests' sessions.
 */
let keyCounter = 0;
let keyUuid = "";
let rawKey = "";
const identity = (): SessionIdentity => ({
  method: "api_key",
  credentialId: keyUuid,
});

let httpServer: HttpServer;
let baseUrl = "";

function restoreEnv(name: string, value: string | undefined): void {
  if (value === undefined) {
    delete process.env[name];
  } else {
    process.env[name] = value;
  }
}

/** A pooled instance backed by a real SDK server, as the pool would hand out. */
function makeServerInstance() {
  return {
    server: new Server(
      { name: "evict-test-gateway", version: "0.0.0" },
      { capabilities: {} },
    ),
    cleanup: vi.fn().mockResolvedValue(undefined),
    handlerContext: {} as Record<string, unknown>,
  };
}

/** The request shape `authenticateApiKey` leaves behind, for direct calls. */
function authReqFor(endpoint = "ep-1"): ApiKeyAuthenticatedRequest {
  return {
    headers: { "x-api-key": rawKey },
    query: {},
    namespaceUuid: `ns-${endpoint}`,
    endpointName: endpoint,
    endpoint: { uuid: `uuid-${endpoint}`, name: endpoint },
    authMethod: "api_key",
    apiKeyUuid: keyUuid,
  } as unknown as ApiKeyAuthenticatedRequest;
}

function initialize(endpoint = "ep-1"): Promise<Response> {
  return fetch(`${baseUrl}/metamcp/${endpoint}/mcp`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      "x-api-key": rawKey,
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: PROTOCOL_VERSION,
        capabilities: {},
        clientInfo: { name: "evict-test-client", version: "0.0.0" },
      },
    }),
  });
}

/** Open a session through the real initialize path and return its id. */
async function openSession(endpoint = "ep-1"): Promise<string> {
  const response = await initialize(endpoint);
  expect(response.status).toBe(200);
  await response.text();
  const sessionId = response.headers.get("mcp-session-id");
  if (!sessionId) throw new Error("initialize returned no Mcp-Session-Id");
  return sessionId;
}

function ping(sessionId: string, endpoint = "ep-1"): Promise<Response> {
  return fetch(`${baseUrl}/metamcp/${endpoint}/mcp`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      "x-api-key": rawKey,
      "mcp-session-id": sessionId,
      "mcp-protocol-version": PROTOCOL_VERSION,
    },
    body: JSON.stringify({ jsonrpc: "2.0", id: 7, method: "ping" }),
  });
}

/** Open the standalone GET stream a live Claude Code process holds. */
function openGetStream(
  sessionId: string,
  signal: AbortSignal,
  endpoint = "ep-1",
): Promise<Response> {
  return fetch(`${baseUrl}/metamcp/${endpoint}/mcp`, {
    method: "GET",
    headers: {
      accept: "text/event-stream",
      "x-api-key": rawKey,
      "mcp-session-id": sessionId,
      "mcp-protocol-version": PROTOCOL_VERSION,
    },
    signal,
  });
}

function advanceSeconds(seconds: number): void {
  vi.setSystemTime(Date.now() + seconds * 1000);
}

function isResident(sessionId: string, endpoint = "ep-1"): boolean {
  return resolveBoundSession(sessionId, authReqFor(endpoint)).outcome === "ok";
}

function transportOf(sessionId: string, endpoint = "ep-1") {
  const resolved = resolveBoundSession(sessionId, authReqFor(endpoint));
  if (resolved.outcome !== "ok") {
    throw new Error(`session ${sessionId} is not resident`);
  }
  return resolved.transport;
}

const infoLines = () => h.logger.info.mock.calls.map((call) => String(call[0]));
const warnLines = () => h.logger.warn.mock.calls.map((call) => String(call[0]));
const evictionLines = () =>
  infoLines().filter((line) =>
    line.startsWith("Concurrent-session ceiling: evicted idle session"),
  );
const refusalLines = () =>
  warnLines().filter((line) =>
    line.startsWith("Concurrent-session ceiling reached"),
  );

const refusalBody = (current: number, ceiling: number) => ({
  error: `Too many concurrent sessions for this credential (${current}/${ceiling}). Close idle sessions, or ask an administrator to raise MCP_MAX_SESSIONS_PER_CREDENTIAL.`,
});

beforeAll(async () => {
  vi.mocked(lookupEndpoint).mockImplementation(((
    req: express.Request,
    _res: express.Response,
    next: () => void,
  ) => {
    const endpoint = String(req.params.endpoint_name);
    Object.assign(req, {
      namespaceUuid: `ns-${endpoint}`,
      endpointName: endpoint,
      endpoint: { uuid: `uuid-${endpoint}`, name: endpoint },
      authMethod: "api_key",
      apiKeyUuid: keyUuid,
      auditRequestId: "req-evict",
      auditClientIp: "203.0.113.20",
    });
    next();
  }) as never);
  vi.mocked(authenticateApiKey).mockImplementation(((
    _req: express.Request,
    _res: express.Response,
    next: () => void,
  ) => next()) as never);
  vi.mocked(rateLimitMiddleware).mockImplementation(((
    _req: express.Request,
    _res: express.Response,
    next: () => void,
  ) => next()) as never);

  const app = express();
  app.use("/metamcp", streamableHttpRouter);
  await new Promise<void>((resolve) => {
    httpServer = app.listen(0, "127.0.0.1", resolve);
  });
  const address = httpServer.address();
  if (typeof address === "object" && address) {
    baseUrl = `http://127.0.0.1:${address.port}`;
  }
});

afterAll(async () => {
  await new Promise<void>((resolve) => httpServer.close(() => resolve()));
});

beforeEach(() => {
  vi.clearAllMocks();
  h.trace.length = 0;
  __resetSessionCeilingThrottleForTesting();
  keyCounter += 1;
  keyUuid = `3f7f8a1e-0000-4000-8000-${String(keyCounter).padStart(12, "0")}`;
  rawKey = `evict-test-key-${keyCounter}`;
  h.getServer.mockImplementation(async () => makeServerInstance());
  h.cleanupSession.mockResolvedValue(undefined);
  delete process.env.MCP_SESSION_CEILING_EVICT_IDLE;
  delete process.env.MCP_SESSION_CEILING_EVICT_MIN_IDLE_SECONDS;
  vi.useFakeTimers({ toFake: ["Date"] });
});

afterEach(() => {
  vi.useRealTimers();
  restoreEnv("MCP_MAX_SESSIONS_PER_CREDENTIAL", ORIGINAL_ENV.ceiling);
  restoreEnv("MCP_SESSION_CEILING_EVICT_IDLE", ORIGINAL_ENV.evict);
  restoreEnv(
    "MCP_SESSION_CEILING_EVICT_MIN_IDLE_SECONDS",
    ORIGINAL_ENV.minIdle,
  );
});

describe("POST initialize at the ceiling — an idle session is evicted and the new one admitted", () => {
  it("admits with 200, keeps the count at the ceiling, evicts the longest-idle session and keeps its row", async () => {
    process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL = "3";
    const oldest = await openSession();
    advanceSeconds(10);
    const middle = await openSession("ep-2");
    advanceSeconds(10);
    const newest = await openSession();
    advanceSeconds(200);
    const victimTransport = transportOf(oldest);
    const closeSpy = vi.spyOn(victimTransport, "close");
    const evictionsBefore = (
      buildSessionsHealthPayload(true).ceilingEvictions as { total: number }
    ).total;

    const response = await initialize();

    expect(response.status).toBe(200);
    await response.text();
    const admitted = response.headers.get("mcp-session-id");
    expect(admitted).toBeTruthy();
    expect([oldest, middle, newest]).not.toContain(admitted);

    // Count unchanged: the victim left, the new session took its slot.
    expect(countLiveSessionsForIdentity(identity())).toBe(3);
    expect(isResident(oldest)).toBe(false);
    expect(isResident(middle, "ep-2")).toBe(true);
    expect(isResident(newest)).toBe(true);
    expect(isResident(admitted as string)).toBe(true);
    // The victim was torn down through the row-PRESERVING path: transport
    // closed, pool state released, idle tracking dropped, row kept.
    expect(closeSpy).toHaveBeenCalledTimes(1);
    expect(h.cleanupSession).toHaveBeenCalledWith(oldest);
    expect(publicSessionSweeper.getLastActivity(oldest)).toBeUndefined();
    expect(h.deleteRow).not.toHaveBeenCalled();
    expect(h.rows.has(oldest)).toBe(true);

    // One INFO line naming what was evicted; the refusal WARN, which a
    // Grafana rule matches, does not fire for an admission.
    expect(evictionLines()).toEqual([
      'Concurrent-session ceiling: evicted idle session on ep-1 (idle 220s) for api_key credential "test-consumer" to admit a new session (3/3) live: ep-1=2, ep-2=1; in-flight 0, idle 3, oldest idle 220s',
    ]);
    expect(refusalLines()).toEqual([]);
    // The throttled History event, at info level.
    const evictedEvents = h.record.mock.calls
      .map((call) => call[0])
      .filter((entry) =>
        String(entry.message).startsWith("idle session evicted"),
      );
    expect(evictedEvents).toHaveLength(1);
    expect(evictedEvents[0]).toMatchObject({
      category: "client",
      level: "info",
      serverName: "ep-1",
      clientName: "test-consumer",
    });
    expect(evictedEvents[0].message).toContain("(3/3): ep-1, idle 220s");
    // The admin health payload counts it.
    expect(
      (buildSessionsHealthPayload(true).ceilingEvictions as { total: number })
        .total,
    ).toBe(evictionsBefore + 1);
  });

  it("refuses with today's exact 429 body when every session is under the idle floor", async () => {
    process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL = "2";
    const first = await openSession();
    const second = await openSession();
    advanceSeconds(119);
    const getServerCalls = h.getServer.mock.calls.length;

    const response = await initialize();

    expect(response.status).toBe(429);
    expect(await response.json()).toEqual(refusalBody(2, 2));
    expect(isResident(first)).toBe(true);
    expect(isResident(second)).toBe(true);
    expect(countLiveSessionsForIdentity(identity())).toBe(2);
    expect(h.cleanupSession).not.toHaveBeenCalled();
    expect(h.getServer.mock.calls.length).toBe(getServerCalls);
    expect(evictionLines()).toEqual([]);
    expect(refusalLines()).toHaveLength(1);
    expect(refusalLines()[0]).toMatch(
      /^Concurrent-session ceiling reached for api_key credential "test-consumer": 2\/2 live sessions; refusing a new session\. Raise MCP_MAX_SESSIONS_PER_CREDENTIAL if this is a legitimate consumer\./,
    );
  });

  it("never evicts a session holding an open GET stream (a live Claude Code process), however long it has been quiet", async () => {
    process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL = "1";
    const live = await openSession();
    const abort = new AbortController();
    const stream = await openGetStream(live, abort.signal);
    expect(stream.status).toBe(200);
    try {
      expect(publicSessionSweeper.getActivity(live)?.inFlight).toBe(true);
      advanceSeconds(3600);

      const response = await initialize();

      expect(response.status).toBe(429);
      expect(await response.json()).toEqual(refusalBody(1, 1));
      expect(isResident(live)).toBe(true);
      expect(h.cleanupSession).not.toHaveBeenCalled();
      expect(evictionLines()).toEqual([]);
    } finally {
      abort.abort();
    }
  });

  it("kill switch off: refuses exactly as today even with idle sessions to evict", async () => {
    process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL = "2";
    process.env.MCP_SESSION_CEILING_EVICT_IDLE = "false";
    const first = await openSession();
    const second = await openSession();
    advanceSeconds(3600);

    const response = await initialize();

    expect(response.status).toBe(429);
    expect(await response.json()).toEqual(refusalBody(2, 2));
    expect(isResident(first)).toBe(true);
    expect(isResident(second)).toBe(true);
    expect(h.cleanupSession).not.toHaveBeenCalled();
    expect(evictionLines()).toEqual([]);
    expect(refusalLines()).toHaveLength(1);
    const refusedEvents = h.record.mock.calls.filter((call) =>
      String(call[0].message).startsWith("session refused"),
    );
    expect(refusedEvents).toHaveLength(1);
  });

  it("16 concurrent initializes against 16 idle sessions: 16 distinct victims, all admitted, never over the ceiling", async () => {
    process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL = "16";
    const originals: string[] = [];
    for (let i = 0; i < 16; i += 1) {
      originals.push(await openSession());
      advanceSeconds(1);
    }
    advanceSeconds(600);

    // Sample the count at the two points inside an admission where an
    // over-admission would show: when the pool hands out an instance (after
    // the eviction, before the new session is registered) and when its row
    // is persisted (after it is registered). The pool answer is delayed so
    // every admission's ceiling check runs while earlier ones are still
    // waiting on it: without that, requests arriving over one socket are
    // served almost one at a time and the window this test is about never
    // opens.
    const observed: number[] = [];
    let checksBeforeFirstRegistration = 0;
    h.getServer.mockImplementation(async () => {
      observed.push(countLiveSessionsForIdentity(identity()));
      checksBeforeFirstRegistration += 1;
      await new Promise((resolve) => setTimeout(resolve, 100));
      return makeServerInstance();
    });
    let registrations = 0;
    h.persist.mockImplementation(async (row: { session_id: string }) => {
      registrations += 1;
      if (registrations === 1) {
        // How many admissions had already evicted and were waiting on the
        // pool when the first one registered its session.
        expect(checksBeforeFirstRegistration).toBeGreaterThan(1);
      }
      observed.push(countLiveSessionsForIdentity(identity()));
      h.rows.set(row.session_id, {
        ...row,
        created_at: new Date(),
        last_seen_at: new Date(),
      });
    });

    const responses = await Promise.all(
      Array.from({ length: 16 }, () => initialize()),
    );

    expect(responses.map((r) => r.status)).toEqual(Array(16).fill(200));
    await Promise.all(responses.map((r) => r.text()));
    const admitted = responses.map((r) => r.headers.get("mcp-session-id"));
    expect(new Set(admitted).size).toBe(16);

    const victims = h.cleanupSession.mock.calls.map((call) => call[0]);
    expect(victims).toHaveLength(16);
    expect(new Set(victims)).toEqual(new Set(originals));
    for (const original of originals) {
      expect(isResident(original)).toBe(false);
    }
    for (const id of admitted) {
      expect(isResident(id as string)).toBe(true);
    }
    expect(countLiveSessionsForIdentity(identity())).toBe(16);
    expect(observed.length).toBeGreaterThanOrEqual(32);
    expect(Math.max(...observed)).toBeLessThanOrEqual(16);
    expect(h.deleteRow).not.toHaveBeenCalled();
    expect(evictionLines()).toHaveLength(16);
    expect(refusalLines()).toEqual([]);
    // Sixteen evictions, one durable event: the throttle collapses the burst.
    const evictedEvents = h.record.mock.calls.filter((call) =>
      String(call[0].message).startsWith("idle session evicted"),
    );
    expect(evictedEvents).toHaveLength(1);
  });
});

describe("a failed admission never holds the slot it reserved", () => {
  it("an initialize that fails after evicting hands its slot back", async () => {
    process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL = "2";
    const first = await openSession();
    const second = await openSession();
    advanceSeconds(300);
    // The pool cannot hand out an instance: the route throws after the
    // eviction, before any session is registered.
    h.getServer.mockResolvedValueOnce(undefined);

    const response = await initialize();

    expect(response.status).toBe(500);
    expect(h.cleanupSession).toHaveBeenCalledTimes(1);
    // One victim gone, nothing registered, and no reservation left behind.
    expect([isResident(first), isResident(second)].sort()).toEqual([
      false,
      true,
    ]);
    expect(countLiveSessionsForIdentity(identity())).toBe(1);

    // So the credential can open a session again without evicting.
    const retry = await initialize();
    expect(retry.status).toBe(200);
    await retry.text();
    expect(h.cleanupSession).toHaveBeenCalledTimes(1);
    expect(countLiveSessionsForIdentity(identity())).toBe(2);
  });
});

describe("the evicted client comes back — lazy recovery under the same id", () => {
  it("its next POST is served under the same session id from the preserved row", async () => {
    process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL = "1";
    const evicted = await openSession();
    const victimTransport = transportOf(evicted);
    advanceSeconds(300);
    const admit = await initialize();
    expect(admit.status).toBe(200);
    await admit.text();
    expect(isResident(evicted)).toBe(false);

    const response = await ping(evicted);

    expect(response.status).toBe(200);
    expect(response.headers.get("mcp-session-id")).toBe(evicted);
    expect(await response.text()).toContain('"result":{}');
    expect(h.findById).toHaveBeenCalledWith(evicted);
    expect(isResident(evicted)).toBe(true);
    expect(transportOf(evicted)).not.toBe(victimTransport);
    // Recovery has no ceiling check (unchanged): the returning client is
    // served even though the credential is at its ceiling again.
    expect(countLiveSessionsForIdentity(identity())).toBe(2);
  });

  it("its next GET (the standalone stream) is served under the same session id", async () => {
    process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL = "1";
    const evicted = await openSession();
    advanceSeconds(300);
    const admit = await initialize();
    expect(admit.status).toBe(200);
    await admit.text();
    expect(isResident(evicted)).toBe(false);

    const abort = new AbortController();
    try {
      const response = await openGetStream(evicted, abort.signal);

      expect(response.status).toBe(200);
      expect(response.headers.get("content-type")).toContain(
        "text/event-stream",
      );
      expect(h.findById).toHaveBeenCalledWith(evicted);
      expect(isResident(evicted)).toBe(true);
    } finally {
      abort.abort();
    }
  });
});

describe("a request that lands on the victim mid-teardown", () => {
  /** Block the victim's pool release until the test lets it finish. */
  function holdNextPoolRelease(): () => void {
    let release!: () => void;
    h.cleanupSession.mockImplementationOnce(
      () =>
        new Promise<void>((resolve) => {
          release = () => {
            h.trace.push("victim-teardown-finished");
            resolve();
          };
        }),
    );
    return () => release();
  }

  it("waits for the teardown, then is served by a freshly recovered transport, never the victim's or the newcomer's", async () => {
    process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL = "1";
    const victim = await openSession();
    const victimTransport = transportOf(victim);
    advanceSeconds(300);
    const finishTeardown = holdNextPoolRelease();

    const admitting = initialize();
    await vi.waitFor(() =>
      expect(h.cleanupSession).toHaveBeenCalledWith(victim),
    );
    expect(isResident(victim)).toBe(false);

    const returning = ping(victim);
    // Give the returning request every chance to run ahead of the teardown.
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(h.findById).not.toHaveBeenCalledWith(victim);
    const getServerCallsWhileBlocked = h.getServer.mock.calls.length;

    finishTeardown();
    const [admitResponse, returningResponse] = await Promise.all([
      admitting,
      returning,
    ]);

    expect(admitResponse.status).toBe(200);
    await admitResponse.text();
    const newcomer = admitResponse.headers.get("mcp-session-id") as string;
    expect(returningResponse.status).toBe(200);
    expect(returningResponse.headers.get("mcp-session-id")).toBe(victim);
    expect(await returningResponse.text()).toContain('"result":{}');

    // Recovery read the row only after the victim's teardown had finished.
    expect(h.trace.indexOf("victim-teardown-finished")).toBeGreaterThanOrEqual(
      0,
    );
    expect(h.trace.indexOf(`findById:${victim}`)).toBeGreaterThan(
      h.trace.indexOf("victim-teardown-finished"),
    );
    expect(h.getServer.mock.calls.length).toBeGreaterThan(
      getServerCallsWhileBlocked,
    );

    // Three distinct transports: nothing was crossed.
    const recovered = transportOf(victim);
    expect(recovered).not.toBe(victimTransport);
    expect(recovered).not.toBe(transportOf(newcomer));
    expect(h.deleteRow).not.toHaveBeenCalled();
  });

  it("gets the reinitialize 404 when the victim has no row to recover from", async () => {
    process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL = "1";
    const victim = await openSession();
    // A session whose row was never written (persist is best-effort).
    h.rows.delete(victim);
    advanceSeconds(300);
    const finishTeardown = holdNextPoolRelease();

    const admitting = initialize();
    await vi.waitFor(() =>
      expect(h.cleanupSession).toHaveBeenCalledWith(victim),
    );
    const returning = ping(victim);
    await new Promise((resolve) => setTimeout(resolve, 50));
    finishTeardown();
    const [admitResponse, returningResponse] = await Promise.all([
      admitting,
      returning,
    ]);

    expect(admitResponse.status).toBe(200);
    await admitResponse.text();
    expect(returningResponse.status).toBe(404);
    expect(
      returningResponse.headers.get("Mcp-Session-Reinitialize-Required"),
    ).toBe("true");
    expect(isResident(victim)).toBe(false);
  });
});

describe("cleanup never tears down a newer transport registered under the same id", () => {
  it("a reap whose close overlaps a recovery leaves the recovered transport, its tracking and its pool state alone", async () => {
    process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL = "10";
    const sessionId = await openSession();
    const original = transportOf(sessionId);
    const originalClose = original.close.bind(original);
    // While the old transport is closing, a recovery for the same id
    // completes and registers a new transport. This is the window the guard
    // exists for; the eviction path additionally keeps recovery out of it.
    vi.spyOn(original, "close").mockImplementation(async () => {
      const recovery = await recoverPersistedSession(
        sessionId,
        authReqFor("ep-1"),
      );
      expect(recovery.status).toBe("recovered");
      await originalClose();
    });

    await reapIdleSession(sessionId);

    expect(isResident(sessionId)).toBe(true);
    const resident = transportOf(sessionId);
    expect(resident).not.toBe(original);
    expect(publicSessionSweeper.getLastActivity(sessionId)).toBeDefined();
    expect(h.cleanupSession).not.toHaveBeenCalled();
    expect(warnLines()).toContain(
      `Session ${sessionId} was re-established under the same id while its old transport was closing; leaving the new transport and its pool state in place.`,
    );

    // And the newer transport really serves.
    const response = await ping(sessionId);
    expect(response.status).toBe(200);
    expect(await response.text()).toContain('"result":{}');
  });
});
