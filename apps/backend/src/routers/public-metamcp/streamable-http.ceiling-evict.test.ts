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
import { PingRequestSchema } from "@modelcontextprotocol/sdk/types.js";
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
  // How long the fake `mcp_sessions` lookup takes. Zero by default; the
  // concurrent-recovery tests raise it so two requests on one id are inside
  // recovery at the same time, as they are against a real database.
  const db = { findByIdDelayMs: 0 };
  return {
    rows,
    trace,
    db,
    // Raw api key -> key uuid for a second credential in the same test. The
    // endpoint lookup fake falls back to the test's own key for anything not
    // listed here.
    otherKeys: new Map<string, string>(),
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
      if (db.findByIdDelayMs > 0) {
        await new Promise((resolve) => setTimeout(resolve, db.findByIdDelayMs));
      }
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

import {
  countLiveSessionsForIdentity,
  setEvictionAdmissionWaitMsForTests,
} from "../../lib/metamcp/credential-session-quota";
import type { SessionIdentity } from "../../lib/metamcp/session-auth";
import { __resetSessionCeilingThrottleForTesting } from "../../lib/metamcp/session-ceiling-events";
import streamableHttpRouter, {
  buildSessionsHealthPayload,
  evictIdleSessionForAdmission,
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

function initialize(
  endpoint = "ep-1",
  signal?: AbortSignal,
): Promise<Response> {
  return fetch(`${baseUrl}/metamcp/${endpoint}/mcp`, {
    method: "POST",
    signal,
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

/**
 * JSON-RPC ids for `ping`, distinct per call as a real client's are: the SDK
 * transport routes each response by request id, so two concurrent requests
 * sharing one id on one session would answer only one of them.
 */
let pingId = 0;

function ping(
  sessionId: string,
  endpoint = "ep-1",
  key = rawKey,
): Promise<Response> {
  return fetch(`${baseUrl}/metamcp/${endpoint}/mcp`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      "x-api-key": key,
      "mcp-session-id": sessionId,
      "mcp-protocol-version": PROTOCOL_VERSION,
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: (pingId += 1),
      method: "ping",
    }),
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
const recoveryOverCeilingLines = () =>
  infoLines().filter((line) =>
    line.startsWith("Session recovery over the concurrent-session ceiling"),
  );
/** Every log line, any level, that mentions the ceiling at all. */
const ceilingLines = () =>
  [...infoLines(), ...warnLines()].filter((line) =>
    /concurrent-session|session ceiling/i.test(line),
  );

/**
 * The Grafana rule `warn-metamcp-credential-session-ceiling`
 * (Grafana-Logs alerting/metamcp-rules.yml) filters with this expression.
 */
const GRAFANA_CEILING_RULE =
  /Concurrent-session (ceiling reached|usage high) for|Concurrent-session ceiling: evicted idle session on/;

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
    const presented = String(req.headers["x-api-key"] ?? "");
    Object.assign(req, {
      namespaceUuid: `ns-${endpoint}`,
      endpointName: endpoint,
      endpoint: { uuid: `uuid-${endpoint}`, name: endpoint },
      authMethod: "api_key",
      apiKeyUuid: h.otherKeys.get(presented) ?? keyUuid,
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
  h.db.findByIdDelayMs = 0;
  h.otherKeys.clear();
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
  setEvictionAdmissionWaitMsForTests(undefined);
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

  it("concurrent initializes while every victim's close is slow: distinct victims, never over the ceiling", async () => {
    // The test above has fast closes, so each victim is fully torn down before
    // the next admission's ceiling check and would pass even if the evictor
    // left the victim in the manager until its teardown finished. Here every
    // close takes 150 ms, so the later admissions run their checks while the
    // first victim is still closing: only the evictor's SYNCHRONOUS removal
    // from the manager and the sweeper keeps them from choosing that same
    // victim again and admitting over the ceiling.
    process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL = "3";
    const originals: string[] = [];
    for (let i = 0; i < 3; i += 1) {
      originals.push(await openSession());
      advanceSeconds(1);
    }
    advanceSeconds(300);
    for (const id of originals) {
      const transport = transportOf(id);
      const close = transport.close.bind(transport);
      vi.spyOn(transport, "close").mockImplementation(async () => {
        await new Promise((resolve) => setTimeout(resolve, 150));
        await close();
      });
    }
    const observed: number[] = [];
    h.getServer.mockImplementation(async () => {
      observed.push(countLiveSessionsForIdentity(identity()));
      return makeServerInstance();
    });
    h.persist.mockImplementation(async (row: { session_id: string }) => {
      observed.push(countLiveSessionsForIdentity(identity()));
      h.rows.set(row.session_id, {
        ...row,
        created_at: new Date(),
        last_seen_at: new Date(),
      });
    });

    const responses = await Promise.all([
      initialize(),
      initialize(),
      initialize(),
    ]);

    expect(responses.map((r) => r.status)).toEqual([200, 200, 200]);
    await Promise.all(responses.map((r) => r.text()));
    const victims = h.cleanupSession.mock.calls.map((call) => call[0]);
    expect(victims).toHaveLength(3);
    expect(new Set(victims)).toEqual(new Set(originals));
    expect(observed.length).toBeGreaterThanOrEqual(6);
    expect(Math.max(...observed)).toBeLessThanOrEqual(3);
    expect(countLiveSessionsForIdentity(identity())).toBe(3);
    expect(evictionLines()).toHaveLength(3);
  });
});

describe("admission races before the first dispatch", () => {
  it("reserves the final free slot while a pool acquisition is pending", async () => {
    process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL = "1";
    let release!: () => void;
    h.getServer.mockImplementationOnce(async () => {
      await new Promise<void>((resolve) => {
        release = resolve;
      });
      return makeServerInstance();
    });
    const first = initialize();
    await vi.waitFor(() => expect(h.getServer).toHaveBeenCalledTimes(1));
    try {
      const second = await initialize();
      expect(second.status).toBe(429);
      expect(await second.json()).toEqual(refusalBody(1, 1));
    } finally {
      release();
      const response = await first;
      expect(response.status).toBe(200);
      await response.text();
    }
    expect(countLiveSessionsForIdentity(identity())).toBe(1);
  });

  it("does not evict a session whose initialize is still connecting", async () => {
    process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL = "1";
    const instance = makeServerInstance();
    const connect = instance.server.connect.bind(instance.server);
    let release!: () => void;
    vi.spyOn(instance.server, "connect").mockImplementationOnce(
      async (transport) => {
        await new Promise<void>((resolve) => {
          release = resolve;
        });
        await connect(transport);
      },
    );
    h.getServer.mockResolvedValueOnce(instance);
    const first = initialize();
    await vi.waitFor(() =>
      expect(instance.server.connect).toHaveBeenCalledTimes(1),
    );
    advanceSeconds(300);
    try {
      const second = await initialize();
      expect(second.status).toBe(429);
      expect(h.cleanupSession).not.toHaveBeenCalled();
    } finally {
      release();
      const response = await first;
      expect(response.status).toBe(200);
      await response.text();
    }
  });

  it("a failed free-slot acquisition releases its reservation", async () => {
    process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL = "1";
    h.getServer.mockResolvedValueOnce(undefined);
    const failed = await initialize();
    expect(failed.status).toBe(500);
    await failed.text();
    expect(countLiveSessionsForIdentity(identity())).toBe(0);
    const retry = await initialize();
    expect(retry.status).toBe(200);
    await retry.text();
    expect(countLiveSessionsForIdentity(identity())).toBe(1);
  });

  it("with eviction off, initialization activity tracking remains unchanged", async () => {
    process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL = "1";
    process.env.MCP_SESSION_CEILING_EVICT_IDLE = "false";
    const instance = makeServerInstance();
    const connect = instance.server.connect.bind(instance.server);
    let release!: () => void;
    vi.spyOn(instance.server, "connect").mockImplementationOnce(
      async (transport) => {
        await new Promise<void>((resolve) => {
          release = resolve;
        });
        await connect(transport);
      },
    );
    h.getServer.mockResolvedValueOnce(instance);
    const request = initialize();
    await vi.waitFor(() =>
      expect(instance.server.connect).toHaveBeenCalledTimes(1),
    );
    try {
      const id = String(h.getServer.mock.calls[0][0]);
      expect(publicSessionSweeper.getActivity(id)?.inFlight).toBe(false);
    } finally {
      release();
      const response = await request;
      expect(response.status).toBe(200);
      await response.text();
    }
  });

  it("a failed connect removes its partially registered session", async () => {
    process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL = "1";
    const instance = makeServerInstance();
    vi.spyOn(instance.server, "connect").mockRejectedValueOnce(
      new Error("connect failed"),
    );
    h.getServer.mockResolvedValueOnce(instance);
    const failed = await initialize();
    expect(failed.status).toBe(500);
    await failed.text();
    expect(countLiveSessionsForIdentity(identity())).toBe(0);
    expect(h.cleanupSession).toHaveBeenCalledTimes(1);
    expect(h.persist).not.toHaveBeenCalled();
    const retry = await initialize();
    expect(retry.status).toBe(200);
    await retry.text();
  });

  it("a real SDK request remains protected throughout its handler", async () => {
    process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL = "1";
    const instance = makeServerInstance();
    let release!: () => void;
    const handler = vi.fn(async () => {
      await new Promise<void>((resolve) => {
        release = resolve;
      });
      return {};
    });
    instance.server.setRequestHandler(PingRequestSchema, handler);
    h.getServer.mockResolvedValueOnce(instance);
    const id = await openSession();
    const request = ping(id);
    await vi.waitFor(() => expect(handler).toHaveBeenCalledTimes(1));
    advanceSeconds(300);
    try {
      expect(publicSessionSweeper.getActivity(id)?.inFlight).toBe(true);
      const second = await initialize();
      expect(second.status).toBe(429);
      expect(h.cleanupSession).not.toHaveBeenCalled();
    } finally {
      release();
      const response = await request;
      expect(response.status).toBe(200);
      await response.text();
    }
    expect(publicSessionSweeper.getActivity(id)?.inFlight).toBe(false);
  });

  it("cancellation while an eviction is closing releases the slot without acquiring a new pool", async () => {
    process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL = "1";
    const victim = await openSession();
    let finish!: () => void;
    h.cleanupSession.mockImplementationOnce(
      () =>
        new Promise<void>((resolve) => {
          finish = resolve;
        }),
    );
    advanceSeconds(300);
    const abort = new AbortController();
    const cancelled = initialize("ep-1", abort.signal).catch(() => null);
    await vi.waitFor(() =>
      expect(h.cleanupSession).toHaveBeenCalledWith(victim),
    );
    try {
      abort.abort();
      await cancelled;
      await vi.waitFor(() =>
        expect(countLiveSessionsForIdentity(identity())).toBe(0),
      );
      const replacement = await initialize();
      expect(replacement.status).toBe(200);
      await replacement.text();
    } finally {
      finish();
    }
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(h.getServer).toHaveBeenCalledTimes(2);
    expect(countLiveSessionsForIdentity(identity())).toBe(1);
  });

  it("cancellation during initialize connect drops the session before a late connect completes", async () => {
    process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL = "1";
    const instance = makeServerInstance();
    const connect = instance.server.connect.bind(instance.server);
    let release!: () => void;
    vi.spyOn(instance.server, "connect").mockImplementationOnce(
      async (transport) => {
        await new Promise<void>((resolve) => {
          release = resolve;
        });
        await connect(transport);
      },
    );
    h.getServer.mockResolvedValueOnce(instance);
    const abort = new AbortController();
    const cancelled = initialize("ep-1", abort.signal).catch(() => null);
    await vi.waitFor(() =>
      expect(instance.server.connect).toHaveBeenCalledTimes(1),
    );
    try {
      abort.abort();
      await cancelled;
      await vi.waitFor(() =>
        expect(countLiveSessionsForIdentity(identity())).toBe(0),
      );
    } finally {
      release();
    }
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(h.persist).not.toHaveBeenCalled();
    expect(countLiveSessionsForIdentity(identity())).toBe(0);
  });

  it("a cancelled admission releases its slot and never registers a late pool result", async () => {
    process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL = "1";
    let release!: () => void;
    let abandonedId = "";
    h.getServer.mockImplementationOnce(async (id: string) => {
      abandonedId = id;
      await new Promise<void>((resolve) => {
        release = resolve;
      });
      return makeServerInstance();
    });
    const abort = new AbortController();
    const abandoned = initialize("ep-1", abort.signal).catch(() => null);
    await vi.waitFor(() => expect(h.getServer).toHaveBeenCalledTimes(1));
    try {
      abort.abort();
      await abandoned;
      await vi.waitFor(() =>
        expect(countLiveSessionsForIdentity(identity())).toBe(0),
      );
      const replacement = await initialize();
      expect(replacement.status).toBe(200);
      await replacement.text();
    } finally {
      release();
    }
    await vi.waitFor(() =>
      expect(h.cleanupSession).toHaveBeenCalledWith(abandonedId),
    );
    expect(isResident(abandonedId)).toBe(false);
    expect(countLiveSessionsForIdentity(identity())).toBe(1);
  });

  it("eviction failure logs expose neither the victim id nor the exception", async () => {
    process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL = "1";
    const victim = await openSession();
    vi.spyOn(transportOf(victim), "close").mockRejectedValueOnce(
      new Error("https://private-token.example/secret"),
    );
    h.logger.info.mockClear();
    h.logger.warn.mockClear();
    h.logger.error.mockClear();
    await evictIdleSessionForAdmission(victim);
    const records = JSON.stringify(
      [
        ...h.logger.info.mock.calls,
        ...h.logger.warn.mock.calls,
        ...h.logger.error.mock.calls,
      ],
      (_key, value) => (value instanceof Error ? value.stack : value),
    );
    expect(records).not.toContain(victim);
    expect(records).not.toContain("private-token");
    expect(h.logger.warn).toHaveBeenCalled();
  });

  it("releases the pool even if the evicted transport fails to close", async () => {
    process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL = "1";
    const held = new Map<string, ReturnType<typeof makeServerInstance>>();
    h.getServer.mockImplementation(async (id: string) => {
      const instance = held.get(id) ?? makeServerInstance();
      held.set(id, instance);
      return instance;
    });
    h.cleanupSession.mockImplementation(async (id: string) => {
      held.delete(id);
    });
    const victim = await openSession();
    vi.spyOn(transportOf(victim), "close").mockRejectedValueOnce(
      new Error("private-close-fault"),
    );
    advanceSeconds(300);
    const admitted = await initialize();
    expect(admitted.status).toBe(200);
    await admitted.text();
    expect(h.cleanupSession).toHaveBeenCalledWith(victim);
    const returning = await ping(victim);
    expect(returning.status).toBe(200);
    expect(await returning.text()).toContain('"result":{}');
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
    // "Evict, never refuse" (2026-10-06): the credential is at its ceiling
    // again and the newcomer is under the idle floor, so there is nothing to
    // evict; the returning client is served anyway, over the ceiling, and
    // never refused. The block on recovery at the ceiling pins the rest.
    expect(countLiveSessionsForIdentity(identity())).toBe(2);
    expect(recoveryOverCeilingLines()).toHaveLength(1);
    expect(refusalLines()).toEqual([]);
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

describe("an evicting admission does not stall on a hung victim teardown", () => {
  it("admits after the bounded wait while the teardown carries on; the victim's own recovery gives up at the same bound with the reinitialize 404, and recovers once the teardown is done", async () => {
    process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL = "1";
    setEvictionAdmissionWaitMsForTests(100);
    const victim = await openSession();
    advanceSeconds(300);
    // The victim's backend release never finishes until the test says so,
    // like a backend whose DELETEs are timing out one after another.
    let finishTeardown!: () => void;
    h.cleanupSession.mockImplementationOnce(
      () =>
        new Promise<void>((resolve) => {
          finishTeardown = () => {
            h.trace.push("victim-teardown-finished");
            resolve();
          };
        }),
    );
    const tearingDownBefore = (
      buildSessionsHealthPayload(true).ceilingEvictions as {
        tearingDown: number;
      }
    ).tearingDown;

    // `Date` is faked in this file; `performance` is not.
    const started = performance.now();
    const response = await initialize();
    const elapsedMs = performance.now() - started;

    expect(response.status).toBe(200);
    await response.text();
    expect(elapsedMs).toBeLessThan(2_000);
    expect(h.cleanupSession).toHaveBeenCalledWith(victim);
    expect(warnLines()).toContain(
      "Session ceiling eviction: the evicted session's teardown on ep-1 has not finished after 100 ms; admitting the new session without waiting for it. The teardown continues in the background.",
    );
    expect(
      (
        buildSessionsHealthPayload(true).ceilingEvictions as {
          tearingDown: number;
        }
      ).tearingDown,
    ).toBe(tearingDownBefore + 1);
    expect(countLiveSessionsForIdentity(identity())).toBe(1);

    // Ruling (2), 2026-10-06: the victim's own recovery waits for the
    // teardown only up to the same bound, then answers the reinitialize 404
    // rather than rebuild its id over a teardown still in progress.
    const returning = await ping(victim);
    expect(returning.status).toBe(404);
    expect(returning.headers.get("Mcp-Session-Reinitialize-Required")).toBe(
      "true",
    );
    await returning.text();
    expect(h.findById).not.toHaveBeenCalledWith(victim);
    expect(warnLines()).toContain(
      "Lazy recovery: a ceiling eviction teardown has not finished after 100 ms; answering 404 so the client re-initializes. The teardown continues in the background.",
    );
    expect(isResident(victim)).toBe(false);

    // Once the teardown is done, the same id recovers from its kept row.
    finishTeardown();
    await vi.waitFor(() =>
      expect(
        (
          buildSessionsHealthPayload(true).ceilingEvictions as {
            tearingDown: number;
          }
        ).tearingDown,
      ).toBe(tearingDownBefore),
    );
    const later = await ping(victim);
    expect(later.status).toBe(200);
    expect(later.headers.get("mcp-session-id")).toBe(victim);
    expect(await later.text()).toContain('"result":{}');
    expect(h.trace.indexOf(`findById:${victim}`)).toBeGreaterThan(
      h.trace.indexOf("victim-teardown-finished"),
    );
  });
});

describe("two requests on one non-resident id at once: recovery runs once", () => {
  /**
   * A pool fake that behaves like `MetaMcpServerPool` where it matters here:
   * it hands back the instance it already holds for a session id instead of
   * building another, and forgets it on `cleanupSession`. With the default
   * fake (a fresh instance per call) two overlapping recoveries of one id
   * never meet in the pool, and the collision this block is about cannot
   * happen.
   */
  function usePoolKeyedBySessionId(): void {
    const held = new Map<string, ReturnType<typeof makeServerInstance>>();
    h.getServer.mockImplementation(async (sessionId: string) => {
      const existing = held.get(sessionId);
      if (existing) return existing;
      const instance = makeServerInstance();
      held.set(sessionId, instance);
      return instance;
    });
    h.cleanupSession.mockImplementation(async (sessionId: string) => {
      held.delete(sessionId);
    });
  }

  const recoveriesOf = (sessionId: string) =>
    h.getServer.mock.calls.filter((call) => call[0] === sessionId).length;

  it("after an eviction: both concurrent requests are served by ONE recovered transport", async () => {
    process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL = "1";
    usePoolKeyedBySessionId();
    const evicted = await openSession();
    advanceSeconds(300);
    const admit = await initialize();
    expect(admit.status).toBe(200);
    await admit.text();
    expect(isResident(evicted)).toBe(false);
    h.db.findByIdDelayMs = 40;

    const responses = await Promise.all([ping(evicted), ping(evicted)]);

    expect(responses.map((r) => r.status)).toEqual([200, 200]);
    for (const response of responses) {
      expect(response.headers.get("mcp-session-id")).toBe(evicted);
      expect(await response.text()).toContain('"result":{}');
    }
    // One recovery: one row read, one pool instance, one resident transport.
    expect(h.findById.mock.calls.filter((c) => c[0] === evicted)).toHaveLength(
      1,
    );
    expect(recoveriesOf(evicted)).toBe(2); // the original open, then one recovery
    expect(isResident(evicted)).toBe(true);
  });

  it("after an idle-sweeper reap: both concurrent requests are served", async () => {
    process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL = "10";
    usePoolKeyedBySessionId();
    const sessionId = await openSession();
    await reapIdleSession(sessionId);
    expect(isResident(sessionId)).toBe(false);
    h.db.findByIdDelayMs = 40;

    const responses = await Promise.all([ping(sessionId), ping(sessionId)]);

    expect(responses.map((r) => r.status)).toEqual([200, 200]);
    for (const response of responses) {
      expect(await response.text()).toContain('"result":{}');
    }
    expect(recoveriesOf(sessionId)).toBe(2);
  });

  it("a different credential waiting on the same id gets the 404, never the recovered transport", async () => {
    process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL = "10";
    usePoolKeyedBySessionId();
    const sessionId = await openSession();
    await reapIdleSession(sessionId);
    const intruderKey = `intruder-${rawKey}`;
    h.otherKeys.set(intruderKey, "9e9e9e9e-0000-4000-8000-000000000001");
    h.db.findByIdDelayMs = 60;

    const owner = ping(sessionId);
    await vi.waitFor(() => expect(h.findById).toHaveBeenCalledWith(sessionId));
    const intruder = ping(sessionId, "ep-1", intruderKey);
    const [ownerResponse, intruderResponse] = await Promise.all([
      owner,
      intruder,
    ]);

    expect(ownerResponse.status).toBe(200);
    expect(await ownerResponse.text()).toContain('"result":{}');
    // Same answer it gets when the session is already resident under its
    // owner: the reinitialize 404, which says nothing about whose id it is.
    expect(intruderResponse.status).toBe(404);
    expect(
      intruderResponse.headers.get("Mcp-Session-Reinitialize-Required"),
    ).toBe("true");
    expect(await intruderResponse.text()).not.toContain('"result"');
    expect(isResident(sessionId)).toBe(true);
  });

  it("a waiter whose leader failed runs its own recovery", async () => {
    process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL = "10";
    usePoolKeyedBySessionId();
    const sessionId = await openSession();
    await reapIdleSession(sessionId);
    const intruderKey = `intruder-${rawKey}`;
    h.otherKeys.set(intruderKey, "9e9e9e9e-0000-4000-8000-000000000002");
    h.db.findByIdDelayMs = 60;

    // The wrong credential arrives first and leads; its recovery fails the
    // principal check. The owner, waiting behind it, must not inherit that.
    const intruder = ping(sessionId, "ep-1", intruderKey);
    await vi.waitFor(() => expect(h.findById).toHaveBeenCalledWith(sessionId));
    const owner = ping(sessionId);
    const [intruderResponse, ownerResponse] = await Promise.all([
      intruder,
      owner,
    ]);

    expect(intruderResponse.status).toBe(401);
    expect(ownerResponse.status).toBe(200);
    expect(await ownerResponse.text()).toContain('"result":{}');
    expect(
      h.findById.mock.calls.filter((c) => c[0] === sessionId),
    ).toHaveLength(2);
    expect(isResident(sessionId)).toBe(true);
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
      "A session was re-established while its old transport was closing; leaving the new transport and its pool state in place.",
    );

    // And the newer transport really serves.
    const response = await ping(sessionId);
    expect(response.status).toBe(200);
    expect(await response.text()).toContain('"result":{}');
  });
});

describe("lazy recovery at the ceiling: evict, never refuse (Alex's rulings, 2026-10-06)", () => {
  /**
   * A session the gateway no longer holds in memory while its row survives:
   * what a returning client finds after an idle-sweeper reap, an eviction or a
   * restart. Reaped rather than evicted so the eviction under test is the
   * RECOVERY's own.
   */
  async function openThenReap(endpoint = "ep-1"): Promise<string> {
    const sessionId = await openSession(endpoint);
    await reapIdleSession(sessionId);
    expect(isResident(sessionId, endpoint)).toBe(false);
    expect(h.rows.has(sessionId)).toBe(true);
    return sessionId;
  }

  /** Forget the setup's calls, keeping every mock's behaviour. */
  function startObserving(): void {
    h.cleanupSession.mockClear();
    h.getServer.mockClear();
    h.findById.mockClear();
    h.deleteRow.mockClear();
    h.record.mockClear();
    h.logger.info.mockClear();
    h.logger.warn.mockClear();
    h.logger.error.mockClear();
    h.trace.length = 0;
  }

  /** Record the credential's count each time the pool is asked for a server. */
  function sampleCountOnPoolAcquire(): number[] {
    const observed: number[] = [];
    h.getServer.mockImplementation(async (sessionId: string) => {
      h.trace.push(`getServer:${sessionId}`);
      observed.push(countLiveSessionsForIdentity(identity()));
      return makeServerInstance();
    });
    return observed;
  }

  const ceilingEvents = () =>
    h.record.mock.calls
      .map((call) => String(call[0].message))
      .filter(
        (message) =>
          message.startsWith("session refused") ||
          message.startsWith("idle session evicted") ||
          message.startsWith("concurrent sessions at"),
      );

  const evictionsTotal = () =>
    (buildSessionsHealthPayload(true).ceilingEvictions as { total: number })
      .total;

  it("at the ceiling with an idle session: evicts exactly one victim, recovers under the same id, and the count never exceeds the ceiling", async () => {
    process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL = "2";
    const returning = await openThenReap();
    const oldest = await openSession();
    advanceSeconds(10);
    const other = await openSession("ep-2");
    advanceSeconds(300);
    const evictionsBefore = evictionsTotal();
    startObserving();
    const observed = sampleCountOnPoolAcquire();

    const response = await ping(returning);

    expect(response.status).toBe(200);
    expect(response.headers.get("mcp-session-id")).toBe(returning);
    expect(await response.text()).toContain('"result":{}');
    observed.push(countLiveSessionsForIdentity(identity()));
    // While the recovery acquired its pool instance (victim gone, slot
    // reserved) and after it registered: at the ceiling, never above it.
    expect(observed).toEqual([2, 2]);
    expect(h.cleanupSession.mock.calls).toEqual([[oldest]]);
    expect(isResident(oldest)).toBe(false);
    expect(isResident(other, "ep-2")).toBe(true);
    expect(isResident(returning)).toBe(true);
    // The victim's row is kept for its own recovery.
    expect(h.rows.has(oldest)).toBe(true);
    expect(h.deleteRow).not.toHaveBeenCalled();
    // The existing eviction INFO line, which the ceiling alert matches.
    expect(evictionLines()).toEqual([
      'Concurrent-session ceiling: evicted idle session on ep-1 (idle 310s) for api_key credential "test-consumer" to admit a new session (2/2) live: ep-1=1, ep-2=1; in-flight 0, idle 2, oldest idle 310s',
    ]);
    expect(evictionLines()[0]).toMatch(GRAFANA_CEILING_RULE);
    expect(recoveryOverCeilingLines()).toEqual([]);
    expect(refusalLines()).toEqual([]);
    expect(ceilingEvents()).toEqual([
      "idle session evicted to admit a new session at the concurrent-session ceiling (2/2): ep-1, idle 310s; live: ep-1=1, ep-2=1; in-flight 0, idle 2, oldest idle 310s",
    ]);
    expect(evictionsTotal()).toBe(evictionsBefore + 1);
  });

  it("at the ceiling with nothing evictable: still recovers (200, same id), over the ceiling, with one INFO line the alert does not match and never the refusal WARN", async () => {
    process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL = "1";
    const returning = await openThenReap();
    const live = await openSession();
    const abort = new AbortController();
    const stream = await openGetStream(live, abort.signal);
    expect(stream.status).toBe(200);
    try {
      // However long it has been quiet, a session holding its standalone GET
      // stream is a live client and is never evicted, not even to recover.
      advanceSeconds(3600);
      startObserving();
      const observed = sampleCountOnPoolAcquire();

      const response = await ping(returning);

      expect(response.status).toBe(200);
      expect(response.headers.get("mcp-session-id")).toBe(returning);
      expect(await response.text()).toContain('"result":{}');
      // Reserved while acquiring its pool instance, then registered: one
      // over the ceiling, and nobody evicted for it.
      expect(observed).toEqual([2]);
      expect(countLiveSessionsForIdentity(identity())).toBe(2);
      expect(isResident(live)).toBe(true);
      expect(isResident(returning)).toBe(true);
      expect(h.cleanupSession).not.toHaveBeenCalled();
      expect(recoveryOverCeilingLines()).toEqual([
        'Session recovery over the concurrent-session ceiling for api_key credential "test-consumer": 1/1 live sessions and none idle long enough to evict; recovering it anyway, since a reconnect is never refused. live: ep-1=1; in-flight 1, idle 0',
      ]);
      expect(recoveryOverCeilingLines()[0]).not.toMatch(GRAFANA_CEILING_RULE);
      expect(recoveryOverCeilingLines()[0]).not.toMatch(
        new RegExp(GRAFANA_CEILING_RULE.source, "i"),
      );
      expect(recoveryOverCeilingLines()[0]).not.toContain(returning);
      expect(recoveryOverCeilingLines()[0]).not.toContain(live);
      expect(recoveryOverCeilingLines()[0]).not.toContain(rawKey);
      // That one line is everything the ceiling said: no refusal, no
      // eviction, no 80% WARN, and no gateway event.
      expect(ceilingLines()).toEqual(recoveryOverCeilingLines());
      expect(ceilingEvents()).toEqual([]);
    } finally {
      abort.abort();
    }
  });

  it("below the ceiling: recovers without evicting, even past 80% with idle sessions to spare, and says nothing about the ceiling", async () => {
    process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL = "4";
    const returning = await openThenReap();
    const residents = [
      await openSession(),
      await openSession(),
      await openSession(),
    ];
    // 3/4 is past the 80% line, and all three are long idle.
    advanceSeconds(600);
    startObserving();
    const observed = sampleCountOnPoolAcquire();

    const response = await ping(returning);

    expect(response.status).toBe(200);
    expect(response.headers.get("mcp-session-id")).toBe(returning);
    expect(await response.text()).toContain('"result":{}');
    expect(h.cleanupSession).not.toHaveBeenCalled();
    for (const resident of residents) {
      expect(isResident(resident)).toBe(true);
    }
    // The recovery's slot is reserved while it acquires its pool instance.
    expect(observed).toEqual([4]);
    expect(countLiveSessionsForIdentity(identity())).toBe(4);
    expect(ceilingLines()).toEqual([]);
    expect(ceilingEvents()).toEqual([]);
  });

  it("registration replaces the recovery's reservation in the same step, so the recovered session is never counted twice", async () => {
    process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL = "4";
    const returning = await openThenReap();
    const resident = await openSession();
    startObserving();
    const observed = sampleCountOnPoolAcquire();
    // `beginTracking` runs synchronously right after the recovered session is
    // registered, before the recovery returns to release anything else.
    const beginTracking =
      publicSessionSweeper.beginTracking.bind(publicSessionSweeper);
    const spy = vi
      .spyOn(publicSessionSweeper, "beginTracking")
      .mockImplementation((sessionId: string) => {
        if (sessionId === returning) {
          observed.push(countLiveSessionsForIdentity(identity()));
        }
        beginTracking(sessionId);
      });
    try {
      const response = await ping(returning);
      expect(response.status).toBe(200);
      await response.text();
    } finally {
      spy.mockRestore();
    }

    // Pool acquisition: the resident session plus the reservation. At
    // registration: the resident and the recovered session, nothing more.
    expect(observed).toEqual([2, 2]);
    expect(isResident(resident)).toBe(true);
    expect(countLiveSessionsForIdentity(identity())).toBe(2);
  });

  it("kill switch off: recovery has no ceiling interaction at all (no eviction, no reservation, no ceiling line or event)", async () => {
    process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL = "1";
    process.env.MCP_SESSION_CEILING_EVICT_IDLE = "false";
    const returning = await openThenReap();
    const idleSession = await openSession();
    // Evictable if eviction were on.
    advanceSeconds(3600);
    startObserving();
    const observed = sampleCountOnPoolAcquire();

    const response = await ping(returning);

    expect(response.status).toBe(200);
    expect(response.headers.get("mcp-session-id")).toBe(returning);
    expect(await response.text()).toContain('"result":{}');
    // No reservation: only the resident session counted while it acquired.
    expect(observed).toEqual([1]);
    expect(h.cleanupSession).not.toHaveBeenCalled();
    expect(isResident(idleSession)).toBe(true);
    expect(countLiveSessionsForIdentity(identity())).toBe(2);
    expect(ceilingLines()).toEqual([]);
    expect(ceilingEvents()).toEqual([]);
  });

  it("a recovery that fails the credential check evicts nothing", async () => {
    process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL = "1";
    const returning = await openThenReap();
    const idleSession = await openSession();
    advanceSeconds(300);
    startObserving();

    // The same credential id, but a token whose hash is not the one the row
    // stores: recovery answers 401, and its ceiling decision is never taken.
    const response = await ping(returning, "ep-1", `${rawKey}-rotated`);

    expect(response.status).toBe(401);
    await response.text();
    expect(h.cleanupSession).not.toHaveBeenCalled();
    expect(isResident(idleSession)).toBe(true);
    expect(countLiveSessionsForIdentity(identity())).toBe(1);
    expect(ceilingLines()).toEqual([]);
  });

  it("concurrent recoveries and initializes at the ceiling: distinct victims, never over the ceiling, and no reservation left once all settle", async () => {
    process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL = "4";
    const returning = [await openThenReap(), await openThenReap()];
    const idleSessions: string[] = [];
    for (let i = 0; i < 4; i += 1) {
      idleSessions.push(await openSession());
      advanceSeconds(1);
    }
    advanceSeconds(600);
    startObserving();
    // The row lookup and the pool are both slow, so the four ceiling
    // decisions are taken while earlier requests are still waiting on the
    // pool, which is where a shared victim or a leaked slot would show.
    h.db.findByIdDelayMs = 30;
    const observed: number[] = [];
    let acquiring = 0;
    let maxAcquiring = 0;
    h.getServer.mockImplementation(async () => {
      observed.push(countLiveSessionsForIdentity(identity()));
      acquiring += 1;
      maxAcquiring = Math.max(maxAcquiring, acquiring);
      await new Promise((resolve) => setTimeout(resolve, 100));
      acquiring -= 1;
      return makeServerInstance();
    });
    h.persist.mockImplementation(async (row: { session_id: string }) => {
      observed.push(countLiveSessionsForIdentity(identity()));
      h.rows.set(row.session_id, {
        ...row,
        created_at: new Date(),
        last_seen_at: new Date(),
      });
    });

    const [recovered1, admitted1, recovered2, admitted2] = await Promise.all([
      ping(returning[0]),
      initialize(),
      ping(returning[1]),
      initialize(),
    ]);

    expect(
      [recovered1, admitted1, recovered2, admitted2].map((r) => r.status),
    ).toEqual([200, 200, 200, 200]);
    expect(recovered1.headers.get("mcp-session-id")).toBe(returning[0]);
    expect(recovered2.headers.get("mcp-session-id")).toBe(returning[1]);
    await Promise.all(
      [recovered1, admitted1, recovered2, admitted2].map((r) => r.text()),
    );
    const admitted = [admitted1, admitted2].map(
      (r) => r.headers.get("mcp-session-id") as string,
    );

    const victims = h.cleanupSession.mock.calls.map((call) => call[0]);
    expect(victims).toHaveLength(4);
    expect(new Set(victims)).toEqual(new Set(idleSessions));
    for (const id of idleSessions) {
      expect(isResident(id)).toBe(false);
    }
    for (const id of [...returning, ...admitted]) {
      expect(isResident(id)).toBe(true);
    }
    expect(maxAcquiring).toBeGreaterThan(1);
    expect(observed.length).toBeGreaterThanOrEqual(6);
    expect(Math.max(...observed)).toBeLessThanOrEqual(4);
    expect(evictionLines()).toHaveLength(4);
    expect(recoveryOverCeilingLines()).toEqual([]);
    expect(refusalLines()).toEqual([]);

    // Once everything has settled the count is exactly the four resident
    // sessions: a leaked reservation would make it 5. The next initialize
    // proves it from the outside: everything is fresh, so it is refused, and
    // the refusal reports 4/4.
    expect(countLiveSessionsForIdentity(identity())).toBe(4);
    const next = await initialize();
    expect(next.status).toBe(429);
    expect(await next.json()).toEqual(refusalBody(4, 4));
  });

  it("a recovery that fails after evicting hands its slot back", async () => {
    process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL = "2";
    const returning = await openThenReap();
    const first = await openSession();
    advanceSeconds(10);
    const second = await openSession();
    advanceSeconds(300);
    startObserving();
    // The pool cannot hand out an instance: the recovery fails after its
    // eviction, before anything is registered.
    h.getServer.mockResolvedValueOnce(undefined);

    const response = await ping(returning);

    expect(response.status).toBe(404);
    expect(response.headers.get("Mcp-Session-Reinitialize-Required")).toBe(
      "true",
    );
    await response.text();
    expect(h.cleanupSession.mock.calls).toEqual([[first]]);
    expect(isResident(returning)).toBe(false);
    expect(isResident(second)).toBe(true);
    // Only `second` is left; nothing holds the evicted slot.
    expect(countLiveSessionsForIdentity(identity())).toBe(1);

    const retry = await initialize();
    expect(retry.status).toBe(200);
    await retry.text();
    expect(h.cleanupSession).toHaveBeenCalledTimes(1);
    expect(countLiveSessionsForIdentity(identity())).toBe(2);
  });

  it("an evicting recovery lets its victim release the pool first, then takes its own", async () => {
    process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL = "1";
    const returning = await openThenReap();
    const victim = await openSession();
    advanceSeconds(300);
    startObserving();
    sampleCountOnPoolAcquire();
    let finishTeardown!: () => void;
    h.cleanupSession.mockImplementationOnce(
      () =>
        new Promise<void>((resolve) => {
          finishTeardown = () => {
            h.trace.push("victim-teardown-finished");
            resolve();
          };
        }),
    );

    const pending = ping(returning);
    await vi.waitFor(() =>
      expect(h.cleanupSession).toHaveBeenCalledWith(victim),
    );
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(h.trace).not.toContain(`getServer:${returning}`);
    finishTeardown();
    const response = await pending;

    expect(response.status).toBe(200);
    expect(await response.text()).toContain('"result":{}');
    expect(h.trace.indexOf(`getServer:${returning}`)).toBeGreaterThan(
      h.trace.indexOf("victim-teardown-finished"),
    );
  });

  it("an evicting recovery does not stall on a hung victim teardown: it goes ahead after the bound", async () => {
    process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL = "1";
    setEvictionAdmissionWaitMsForTests(100);
    const returning = await openThenReap();
    const victim = await openSession();
    advanceSeconds(300);
    startObserving();
    let finishTeardown!: () => void;
    h.cleanupSession.mockImplementationOnce(
      () =>
        new Promise<void>((resolve) => {
          finishTeardown = resolve;
        }),
    );
    try {
      const started = performance.now();
      const response = await ping(returning);
      const elapsedMs = performance.now() - started;

      expect(response.status).toBe(200);
      expect(response.headers.get("mcp-session-id")).toBe(returning);
      expect(await response.text()).toContain('"result":{}');
      expect(elapsedMs).toBeLessThan(2_000);
      expect(h.cleanupSession).toHaveBeenCalledWith(victim);
      expect(warnLines()).toContain(
        "Session ceiling eviction: the evicted session's teardown on ep-1 has not finished after 100 ms; admitting the recovered session without waiting for it. The teardown continues in the background.",
      );
      expect(countLiveSessionsForIdentity(identity())).toBe(1);
    } finally {
      finishTeardown();
    }
  });

  it(
    "a recovery waiting on its own id's hung eviction teardown answers the reinitialize 404 at about 5 s, and logs no session id",
    { timeout: 20_000 },
    async () => {
      process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL = "1";
      // The production bound: no test seam here.
      const victim = await openSession();
      advanceSeconds(300);
      let finishTeardown!: () => void;
      h.cleanupSession.mockImplementationOnce(
        () =>
          new Promise<void>((resolve) => {
            finishTeardown = resolve;
          }),
      );
      const admitting = initialize();
      await vi.waitFor(() =>
        expect(h.cleanupSession).toHaveBeenCalledWith(victim),
      );
      try {
        const started = performance.now();
        const returning = await ping(victim);
        const elapsedMs = performance.now() - started;

        expect(returning.status).toBe(404);
        expect(returning.headers.get("Mcp-Session-Reinitialize-Required")).toBe(
          "true",
        );
        expect(await returning.json()).toMatchObject({
          error: "Session not found",
        });
        expect(elapsedMs).toBeGreaterThanOrEqual(4_900);
        expect(elapsedMs).toBeLessThan(8_000);
        // It never rebuilt the id over the unfinished teardown.
        expect(h.findById).not.toHaveBeenCalledWith(victim);
        expect(isResident(victim)).toBe(false);
        expect(warnLines()).toContain(
          "Lazy recovery: a ceiling eviction teardown has not finished after 5000 ms; answering 404 so the client re-initializes. The teardown continues in the background.",
        );
        expect(warnLines().filter((line) => line.includes(victim))).toEqual([]);
        expect(
          infoLines().filter(
            (line) => line.includes("ceiling") && line.includes(victim),
          ),
        ).toEqual([]);
      } finally {
        finishTeardown();
      }
      const admitted = await admitting;
      expect(admitted.status).toBe(200);
      await admitted.text();
    },
  );

  it("the victim of a recovery's eviction can itself recover later, under its own id", async () => {
    process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL = "1";
    const first = await openThenReap();
    const second = await openSession();
    const secondTransport = transportOf(second);
    advanceSeconds(300);

    const firstBack = await ping(first);
    expect(firstBack.status).toBe(200);
    expect(firstBack.headers.get("mcp-session-id")).toBe(first);
    await firstBack.text();
    expect(isResident(second)).toBe(false);
    expect(h.rows.has(second)).toBe(true);

    advanceSeconds(300);
    startObserving();
    const secondBack = await ping(second);

    expect(secondBack.status).toBe(200);
    expect(secondBack.headers.get("mcp-session-id")).toBe(second);
    expect(await secondBack.text()).toContain('"result":{}');
    expect(transportOf(second)).not.toBe(secondTransport);
    // It recovered at the ceiling, so it evicted the now-idle `first`.
    expect(h.cleanupSession.mock.calls).toEqual([[first]]);
    expect(isResident(first)).toBe(false);
    expect(h.rows.has(first)).toBe(true);
    expect(countLiveSessionsForIdentity(identity())).toBe(1);
    expect(evictionLines()).toHaveLength(1);
  });
});
