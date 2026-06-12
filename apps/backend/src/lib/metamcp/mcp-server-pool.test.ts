/**
 * Unit tests for `McpServerPool.invalidateServerConnection`.
 *
 * The unit-under-test is the invalidation cascade introduced after the
 * 2026-05-14T17:29Z production case where PR #13's recovery path
 * engaged correctly (detector fired, `invalidateServerConnection`
 * logged), but the recovery's retry call ALSO got `Not connected`
 * because the cap-reuse branch in `getSession` handed back a stale
 * ConnectedClient cached under a DIFFERENT session's slot for the same
 * serverUuid.
 *
 * These tests poke the pool's internal maps directly (cast to
 * `any` once at the top so the tests don't have to negotiate the
 * private-field discipline). They do NOT exercise the
 * `connectMetaMcpClient` path — that's the integration layer; the
 * unit-under-test here is the invalidation surface.
 */

import { beforeEach, describe, expect, it, vi } from "vitest";

// `mcp-server-pool.ts` instantiates a `connectMetaMcpClient` -driven
// pool at module load time. Stub the heavy imports so the unit test
// doesn't need a postgres or a real upstream MCP.
vi.mock("./client", () => ({
  connectMetaMcpClient: vi.fn(),
}));
vi.mock("../config.service", () => ({
  configService: {
    getSessionLifetime: vi.fn().mockResolvedValue(null),
    getMaxConnections: vi.fn().mockResolvedValue(100),
    getMaxConnectionsPerServer: vi.fn().mockResolvedValue(5),
    getMcpTimeout: vi.fn().mockResolvedValue(60000),
    getMcpMaxTotalTimeout: vi.fn().mockResolvedValue(60000),
    getMcpResetTimeoutOnProgress: vi.fn().mockResolvedValue(true),
    getMaxAttempts: vi.fn().mockResolvedValue(3),
  },
}));
vi.mock("../../db/repositories/mcp-servers.repo", () => ({
  mcpServersRepository: {},
}));
vi.mock("./server-error-tracker", () => ({
  serverErrorTracker: {
    recordServerCrash: vi.fn(),
    resetServerAttempts: vi.fn(),
    markSuccess: vi.fn(),
    getServerAttempts: vi.fn().mockReturnValue(0),
    isServerInErrorState: vi.fn().mockResolvedValue(false),
    resetServerErrorState: vi.fn(),
  },
}));

import { McpServerPool } from "./mcp-server-pool";

// Bypass the private-constructor discipline once, file-wide, without a
// TS2673 per instantiation. Tests poke internals; the singleton
// accessor would leak state across describes.
const PoolConstructor = McpServerPool as unknown as new () => McpServerPool;

type FakeClient = {
  cleanup: ReturnType<typeof vi.fn>;
  closed: boolean;
  listChangedSubscribers: Set<() => void | Promise<void>>;
};

function makeFakeClient(): FakeClient {
  const fake: FakeClient = {
    cleanup: vi.fn(async () => {
      fake.closed = true;
      fake.listChangedSubscribers.clear();
    }),
    closed: false,
    listChangedSubscribers: new Set(),
  };
  return fake;
}

describe("McpServerPool.invalidateServerConnection — cascade across sessions", () => {
  let pool: McpServerPool;
  let internals: {
    activeSessions: Record<string, Record<string, FakeClient>>;
    idleSessions: Record<string, FakeClient>;
    sessionToServers: Record<string, Set<string>>;
    creatingIdleSessions: Set<string>;
  };

  beforeEach(() => {
    pool = new PoolConstructor();

    internals = pool as any;
    internals.activeSessions = {};
    internals.idleSessions = {};
    internals.sessionToServers = {};
    internals.creatingIdleSessions = new Set();
  });

  it("invalidates the cached client for the triggering session", async () => {
    const triggering = makeFakeClient();
    internals.activeSessions["session-A"] = {
      "server-1": triggering as never,
    };
    internals.sessionToServers["session-A"] = new Set(["server-1"]);

    await pool.invalidateServerConnection("session-A", "server-1");

    expect(triggering.cleanup).toHaveBeenCalledTimes(1);
    expect(triggering.closed).toBe(true);
    expect(internals.activeSessions["session-A"]?.["server-1"]).toBeUndefined();
    expect(internals.sessionToServers["session-A"]?.has("server-1")).toBe(
      false,
    );
  });

  it("cascades to every other session's slot for the same serverUuid", async () => {
    // Pre-2026-05-14 bug: only session-A's slot got invalidated; sessions
    // B + C kept their stale clients, and the next getSession() hit the
    // cap-reuse branch which handed one back to the recovery path.
    const clientA = makeFakeClient();
    const clientB = makeFakeClient();
    const clientC = makeFakeClient();
    internals.activeSessions["session-A"] = { "server-1": clientA as never };
    internals.activeSessions["session-B"] = { "server-1": clientB as never };
    internals.activeSessions["session-C"] = { "server-1": clientC as never };
    internals.sessionToServers["session-A"] = new Set(["server-1"]);
    internals.sessionToServers["session-B"] = new Set(["server-1"]);
    internals.sessionToServers["session-C"] = new Set(["server-1"]);

    await pool.invalidateServerConnection("session-A", "server-1");

    expect(clientA.cleanup).toHaveBeenCalled();
    expect(clientB.cleanup).toHaveBeenCalled();
    expect(clientC.cleanup).toHaveBeenCalled();
    expect(internals.activeSessions["session-A"]?.["server-1"]).toBeUndefined();
    expect(internals.activeSessions["session-B"]?.["server-1"]).toBeUndefined();
    expect(internals.activeSessions["session-C"]?.["server-1"]).toBeUndefined();
    expect(internals.sessionToServers["session-A"]?.has("server-1")).toBe(
      false,
    );
    expect(internals.sessionToServers["session-B"]?.has("server-1")).toBe(
      false,
    );
    expect(internals.sessionToServers["session-C"]?.has("server-1")).toBe(
      false,
    );
  });

  it("does NOT touch slots for other serverUuids on the same session", async () => {
    // A backend restart on server-1 should not blow away server-2's
    // healthy cached client on the same session.
    const stale = makeFakeClient();
    const healthy = makeFakeClient();
    internals.activeSessions["session-A"] = {
      "server-1": stale as never,
      "server-2": healthy as never,
    };
    internals.sessionToServers["session-A"] = new Set(["server-1", "server-2"]);

    await pool.invalidateServerConnection("session-A", "server-1");

    expect(stale.cleanup).toHaveBeenCalled();
    expect(healthy.cleanup).not.toHaveBeenCalled();
    expect(internals.activeSessions["session-A"]?.["server-1"]).toBeUndefined();
    expect(internals.activeSessions["session-A"]?.["server-2"]).toBe(healthy);
    expect(internals.sessionToServers["session-A"]?.has("server-2")).toBe(true);
  });

  it("also clears the idle slot for the affected serverUuid", async () => {
    const idle = makeFakeClient();
    internals.idleSessions["server-1"] = idle as never;

    await pool.invalidateServerConnection("session-A", "server-1");

    expect(idle.cleanup).toHaveBeenCalled();
    expect(internals.idleSessions["server-1"]).toBeUndefined();
  });

  it("clears the creatingIdleSessions guard so a pending creation can't re-store a stale client", async () => {
    internals.creatingIdleSessions.add("server-1");

    await pool.invalidateServerConnection("session-A", "server-1");

    expect(internals.creatingIdleSessions.has("server-1")).toBe(false);
  });

  it("continues cleaning up siblings when one cleanup throws", async () => {
    // The bug-fix needs to be defensive — one cleanup() failure must
    // not leave OTHER stale slots cached. Per-cleanup try/catch is
    // load-bearing for the cascade.
    const blowsUp = makeFakeClient();
    blowsUp.cleanup = vi.fn(async () => {
      throw new Error("cleanup raised");
    });
    const recovers = makeFakeClient();
    internals.activeSessions["session-A"] = { "server-1": blowsUp as never };
    internals.activeSessions["session-B"] = { "server-1": recovers as never };

    await pool.invalidateServerConnection("session-A", "server-1");

    expect(blowsUp.cleanup).toHaveBeenCalled();
    expect(recovers.cleanup).toHaveBeenCalled();
    // Slots dropped regardless of cleanup() exceptions.
    expect(internals.activeSessions["session-A"]?.["server-1"]).toBeUndefined();
    expect(internals.activeSessions["session-B"]?.["server-1"]).toBeUndefined();
  });

  it("is a no-op when no clients are cached for the serverUuid (defensive)", async () => {
    // The recovery path may call invalidate even when the maps have
    // already been drained by a concurrent cleanup. Don't throw.
    await expect(
      pool.invalidateServerConnection("session-A", "server-1"),
    ).resolves.not.toThrow();
  });

  // ---------------------------------------------------------------
  // list_changed fan-out on invalidation
  //
  // When the pool drops a ConnectedClient (recoverable backend error
  // surfaced via PR #13's detector OR a watchtower-restart cycle), we
  // fire the client's `listChangedSubscribers` BEFORE running cleanup.
  // metamcp-proxy.ts registers those subscribers; they invalidate
  // tools-sync-cache and emit `notifications/tools/list_changed`
  // upstream. Without this, the gateway swaps in a fresh
  // ConnectedClient but the consumer (Claude Code, Claude.ai) never
  // learns the tool list might have changed.
  // ---------------------------------------------------------------
  it("fires listChangedSubscribers on every doomed client before cleanup", async () => {
    const stale = makeFakeClient();
    const subscriberA = vi.fn();
    const subscriberB = vi.fn();
    stale.listChangedSubscribers.add(subscriberA);
    stale.listChangedSubscribers.add(subscriberB);
    internals.activeSessions["session-A"] = { "server-1": stale as never };

    await pool.invalidateServerConnection("session-A", "server-1");
    // Allow the fire-and-forget promise scheduled by the cascade to
    // resolve before we assert.
    await new Promise((resolve) => setImmediate(resolve));

    expect(subscriberA).toHaveBeenCalledTimes(1);
    expect(subscriberB).toHaveBeenCalledTimes(1);
    expect(stale.cleanup).toHaveBeenCalledTimes(1);
  });

  it("fires subscribers across active AND idle clients for the same serverUuid", async () => {
    const active = makeFakeClient();
    const idle = makeFakeClient();
    const activeSub = vi.fn();
    const idleSub = vi.fn();
    active.listChangedSubscribers.add(activeSub);
    idle.listChangedSubscribers.add(idleSub);
    internals.activeSessions["session-A"] = { "server-1": active as never };
    internals.idleSessions["server-1"] = idle as never;

    await pool.invalidateServerConnection("session-A", "server-1");
    await new Promise((resolve) => setImmediate(resolve));

    expect(activeSub).toHaveBeenCalledTimes(1);
    expect(idleSub).toHaveBeenCalledTimes(1);
  });

  it("isolates a throwing subscriber so cleanup still completes", async () => {
    // A bad subscriber must not strand the invalidation cascade. We
    // log-and-continue (see invalidateServerConnection body).
    const stale = makeFakeClient();
    stale.listChangedSubscribers.add(() => {
      throw new Error("subscriber blew up");
    });
    const healthySubscriber = vi.fn();
    stale.listChangedSubscribers.add(healthySubscriber);
    internals.activeSessions["session-A"] = { "server-1": stale as never };

    await expect(
      pool.invalidateServerConnection("session-A", "server-1"),
    ).resolves.not.toThrow();
    await new Promise((resolve) => setImmediate(resolve));

    expect(healthySubscriber).toHaveBeenCalledTimes(1);
    expect(stale.cleanup).toHaveBeenCalled();
    expect(internals.activeSessions["session-A"]?.["server-1"]).toBeUndefined();
  });

  it("does not fire subscribers on clients for other serverUuids", async () => {
    // Watchtower restarting `server-1` must not trigger fan-out on
    // healthy `server-2` clients.
    const target = makeFakeClient();
    const bystander = makeFakeClient();
    const targetSub = vi.fn();
    const bystanderSub = vi.fn();
    target.listChangedSubscribers.add(targetSub);
    bystander.listChangedSubscribers.add(bystanderSub);
    internals.activeSessions["session-A"] = {
      "server-1": target as never,
      "server-2": bystander as never,
    };

    await pool.invalidateServerConnection("session-A", "server-1");
    await new Promise((resolve) => setImmediate(resolve));

    expect(targetSub).toHaveBeenCalledTimes(1);
    expect(bystanderSub).not.toHaveBeenCalled();
  });
});

// -------------------------------------------------------------------
// Transport-drop cascade (PR #20)
//
// HTTP/SSE backends gain `onclose`/`onerror` callbacks that mirror
// STDIO's `onProcessCrash`. The pool wires those callbacks to a
// private `handleTransportDrop` that:
//   1. Cascade-invalidates every pool slot for the affected serverUuid
//      (reusing PR #16's path — which fires PR #19 list_changed
//      subscribers on the way out).
//   2. Resets the error-tracker count IF the last success was within
//      the recovery-reset threshold (transient bounce, not real
//      failure).
// -------------------------------------------------------------------

describe("McpServerPool.handleTransportDrop — recovery cascade", () => {
  let pool: McpServerPool;
  let internals: {
    activeSessions: Record<string, Record<string, FakeClient>>;
    idleSessions: Record<string, FakeClient>;
    serverLastSuccessAt: Record<string, number>;
    handleTransportDrop: (
      serverUuid: string,
      reason: "close" | "error",
      error?: Error,
    ) => Promise<void>;
  };

  beforeEach(async () => {
    const trackerModule = await import("./server-error-tracker");
    vi.mocked(trackerModule.serverErrorTracker.resetServerAttempts).mockClear();
    vi.mocked(trackerModule.serverErrorTracker.markSuccess).mockClear();

    pool = new PoolConstructor();
    internals = pool as never;
    internals.activeSessions = {};
    internals.idleSessions = {};
    internals.serverLastSuccessAt = {};
  });

  it("cascade-invalidates every pool slot on transport drop", async () => {
    const clientA = makeFakeClient();
    const clientB = makeFakeClient();
    internals.activeSessions["session-A"] = { "server-1": clientA as never };
    internals.activeSessions["session-B"] = { "server-1": clientB as never };

    await internals.handleTransportDrop("server-1", "close");

    expect(clientA.cleanup).toHaveBeenCalledTimes(1);
    expect(clientB.cleanup).toHaveBeenCalledTimes(1);
    expect(internals.activeSessions["session-A"]?.["server-1"]).toBeUndefined();
    expect(internals.activeSessions["session-B"]?.["server-1"]).toBeUndefined();
  });

  it("fires listChangedSubscribers on transport drop (PR #19 synergy)", async () => {
    // End-to-end: a transport drop should produce the same upstream
    // list_changed fan-out as PR #16's invalidation path. Without
    // this, watchtower-restart cycles would leave consumers unaware
    // their tools moved.
    const stale = makeFakeClient();
    const subscriber = vi.fn();
    stale.listChangedSubscribers.add(subscriber);
    internals.activeSessions["session-A"] = { "server-1": stale as never };

    await internals.handleTransportDrop("server-1", "close");
    await new Promise((resolve) => setImmediate(resolve));

    expect(subscriber).toHaveBeenCalledTimes(1);
  });

  it("resets error tracker when drop occurs within recovery threshold", async () => {
    const trackerModule = await import("./server-error-tracker");
    // Last success was 10ms ago — well within the 5min default.
    internals.serverLastSuccessAt["server-1"] = Date.now() - 10;

    await internals.handleTransportDrop("server-1", "close");

    expect(
      vi.mocked(trackerModule.serverErrorTracker.resetServerAttempts),
    ).toHaveBeenCalledWith("server-1");
  });

  it("does NOT reset error tracker when last success was beyond threshold", async () => {
    const trackerModule = await import("./server-error-tracker");
    // Last success was 10 min ago — exceeds default 5min threshold.
    internals.serverLastSuccessAt["server-1"] = Date.now() - 10 * 60 * 1000;

    await internals.handleTransportDrop("server-1", "close");

    expect(
      vi.mocked(trackerModule.serverErrorTracker.resetServerAttempts),
    ).not.toHaveBeenCalled();
  });

  it("does NOT reset error tracker when there is no recorded success", async () => {
    // Server never connected successfully — drop is a real failure
    // signal and the circuit breaker should accumulate normally.
    const trackerModule = await import("./server-error-tracker");

    await internals.handleTransportDrop("server-1", "error", new Error("boom"));

    expect(
      vi.mocked(trackerModule.serverErrorTracker.resetServerAttempts),
    ).not.toHaveBeenCalled();
  });
});

// -------------------------------------------------------------------
// Capacity eviction (LRU at the global cap)
//
// Before this, `maxTotalConnections` was a HARD refuse. Under
// persistent sessions (sessionLifetime=null) cleanupExpiredSessions
// no-ops and cleanupSession RECYCLES active→idle, so the idle pool
// grows until the cap is hit — then EVERY new connection is refused,
// including the recreation a backend needs after a Watchtower restart.
// The pool deadlocked on "connection limit reached" until a manual
// `docker restart metamcp` (observed 2026-05-27, autotask wedged 8+min).
//
// evictOneForCapacity reclaims one slot by DESTROYING (not recycling)
// the least-valuable connection: idle first, then oldest active.
// -------------------------------------------------------------------
describe("McpServerPool.evictOneForCapacity — LRU eviction at the cap", () => {
  let pool: McpServerPool;
  let internals: {
    activeSessions: Record<string, Record<string, FakeClient>>;
    idleSessions: Record<string, FakeClient>;
    sessionToServers: Record<string, Set<string>>;
    sessionTimestamps: Record<string, number>;
    evictOneForCapacity: (forServerUuid: string) => Promise<boolean>;
  };

  beforeEach(() => {
    pool = new PoolConstructor();
    internals = pool as never;
    internals.activeSessions = {};
    internals.idleSessions = {};
    internals.sessionToServers = {};
    internals.sessionTimestamps = {};
  });

  it("destroys an idle session and frees the slot (preferring a server other than the one being admitted)", async () => {
    const idleSelf = makeFakeClient();
    const idleOther = makeFakeClient();
    internals.idleSessions["server-1"] = idleSelf as never;
    internals.idleSessions["server-2"] = idleOther as never;

    const freed = await internals.evictOneForCapacity("server-1");

    expect(freed).toBe(true);
    // Evicts server-2's idle (not the server we're admitting); destroys it.
    expect(idleOther.cleanup).toHaveBeenCalledTimes(1);
    expect(internals.idleSessions["server-2"]).toBeUndefined();
    expect(internals.idleSessions["server-1"]).toBe(idleSelf);
  });

  it("falls back to the only idle slot even if it's the admitted server's", async () => {
    const idleSelf = makeFakeClient();
    internals.idleSessions["server-1"] = idleSelf as never;

    const freed = await internals.evictOneForCapacity("server-1");

    expect(freed).toBe(true);
    expect(idleSelf.cleanup).toHaveBeenCalledTimes(1);
    expect(internals.idleSessions["server-1"]).toBeUndefined();
  });

  it("destroys the oldest-touched active connection when no idle slots exist", async () => {
    const cOld = makeFakeClient();
    const cNew = makeFakeClient();
    internals.activeSessions["session-old"] = { "server-2": cOld as never };
    internals.activeSessions["session-new"] = { "server-3": cNew as never };
    internals.sessionToServers["session-old"] = new Set(["server-2"]);
    internals.sessionToServers["session-new"] = new Set(["server-3"]);
    internals.sessionTimestamps["session-old"] = 1000;
    internals.sessionTimestamps["session-new"] = 2000;

    const freed = await internals.evictOneForCapacity("server-1");

    expect(freed).toBe(true);
    // Oldest (session-old) destroyed; newer untouched.
    expect(cOld.cleanup).toHaveBeenCalledTimes(1);
    expect(cNew.cleanup).not.toHaveBeenCalled();
    expect(
      internals.activeSessions["session-old"]?.["server-2"],
    ).toBeUndefined();
    expect(internals.sessionToServers["session-old"]?.has("server-2")).toBe(
      false,
    );
    expect(internals.activeSessions["session-new"]?.["server-3"]).toBe(cNew);
  });

  it("never evicts the server being admitted, and returns false when nothing else is evictable", async () => {
    const cSelf = makeFakeClient();
    internals.activeSessions["session-A"] = { "server-1": cSelf as never };
    internals.sessionToServers["session-A"] = new Set(["server-1"]);
    internals.sessionTimestamps["session-A"] = 1000;

    const freed = await internals.evictOneForCapacity("server-1");

    expect(freed).toBe(false);
    expect(cSelf.cleanup).not.toHaveBeenCalled();
    expect(internals.activeSessions["session-A"]?.["server-1"]).toBe(cSelf);
  });

  it("returns false when the pool is empty (nothing to evict)", async () => {
    const freed = await internals.evictOneForCapacity("server-1");
    expect(freed).toBe(false);
  });
});

describe("McpServerPool.checkActiveSessionHealth — zombie active-connection sweep", () => {
  // Active StreamableHTTP connections to a swapped backend container die
  // silently (no socket, no onclose/onerror). At the per-server cap every
  // slot is active, so the idle health check sees nothing and the
  // cap-reuse branch in getSession serves the zombies forever
  // (incident 2026-06-11). The sweep pings distinct active clients and
  // cascade-invalidates after two consecutive failed sweeps.

  type PingableFakeClient = FakeClient & {
    client: { ping: ReturnType<typeof vi.fn> };
  };

  function makePingableClient(alive: boolean): PingableFakeClient {
    const fake = makeFakeClient() as PingableFakeClient;
    fake.client = {
      ping: alive
        ? vi.fn().mockResolvedValue({})
        : vi.fn().mockRejectedValue(new Error("Not connected")),
    };
    return fake;
  }

  let pool: McpServerPool;
  let internals: {
    activeSessions: Record<string, Record<string, PingableFakeClient>>;
    idleSessions: Record<string, PingableFakeClient>;
    sessionToServers: Record<string, Set<string>>;
    creatingIdleSessions: Set<string>;
    serverParamsCache: Record<string, unknown>;
    activePingFailures: Record<string, number>;
    checkActiveSessionHealth: () => Promise<void>;
  };

  beforeEach(() => {
    pool = new PoolConstructor();

    internals = pool as never;
    internals.activeSessions = {};
    internals.idleSessions = {};
    internals.sessionToServers = {};
    internals.creatingIdleSessions = new Set();
    internals.serverParamsCache = {};
    internals.activePingFailures = {};
  });

  it("leaves healthy active connections alone and clears the failure counter", async () => {
    const healthy = makePingableClient(true);
    internals.activeSessions["session-A"] = { "server-1": healthy };
    internals.sessionToServers["session-A"] = new Set(["server-1"]);
    internals.activePingFailures["server-1"] = 1; // prior strike

    await internals.checkActiveSessionHealth();

    expect(healthy.client.ping).toHaveBeenCalledTimes(1);
    expect(healthy.cleanup).not.toHaveBeenCalled();
    expect(internals.activePingFailures["server-1"]).toBeUndefined();
    expect(internals.activeSessions["session-A"]["server-1"]).toBe(healthy);
  });

  it("first failed sweep is strike one — no eviction yet", async () => {
    const dead = makePingableClient(false);
    internals.activeSessions["session-A"] = { "server-1": dead };
    internals.sessionToServers["session-A"] = new Set(["server-1"]);

    await internals.checkActiveSessionHealth();

    expect(dead.cleanup).not.toHaveBeenCalled();
    expect(internals.activePingFailures["server-1"]).toBe(1);
    expect(internals.activeSessions["session-A"]["server-1"]).toBe(dead);
  });

  it("second consecutive failed sweep cascade-invalidates every slot for the server", async () => {
    const deadA = makePingableClient(false);
    const deadB = makePingableClient(false);
    internals.activeSessions["session-A"] = { "server-1": deadA };
    internals.activeSessions["session-B"] = { "server-1": deadB };
    internals.sessionToServers["session-A"] = new Set(["server-1"]);
    internals.sessionToServers["session-B"] = new Set(["server-1"]);

    await internals.checkActiveSessionHealth(); // strike 1
    await internals.checkActiveSessionHealth(); // strike 2 → evict

    expect(deadA.cleanup).toHaveBeenCalledTimes(1);
    expect(deadB.cleanup).toHaveBeenCalledTimes(1);
    expect(internals.activeSessions["session-A"]?.["server-1"]).toBeUndefined();
    expect(internals.activeSessions["session-B"]?.["server-1"]).toBeUndefined();
    expect(internals.activePingFailures["server-1"]).toBeUndefined();
  });

  it("a healthy sweep between failures resets the strike counter", async () => {
    const flaky = makePingableClient(false);
    internals.activeSessions["session-A"] = { "server-1": flaky };
    internals.sessionToServers["session-A"] = new Set(["server-1"]);

    await internals.checkActiveSessionHealth(); // strike 1
    flaky.client.ping = vi.fn().mockResolvedValue({}); // backend recovers
    await internals.checkActiveSessionHealth(); // healthy → reset
    flaky.client.ping = vi.fn().mockRejectedValue(new Error("Not connected"));
    await internals.checkActiveSessionHealth(); // strike 1 again, NOT 2

    expect(flaky.cleanup).not.toHaveBeenCalled();
    expect(internals.activePingFailures["server-1"]).toBe(1);
  });

  it("pings a cap-reuse-shared client once, not once per session", async () => {
    const shared = makePingableClient(true);
    internals.activeSessions["session-A"] = { "server-1": shared };
    internals.activeSessions["session-B"] = { "server-1": shared };
    internals.activeSessions["session-C"] = { "server-1": shared };

    await internals.checkActiveSessionHealth();

    expect(shared.client.ping).toHaveBeenCalledTimes(1);
  });

  it("only invalidates the failing server, not its healthy neighbors", async () => {
    const dead = makePingableClient(false);
    const healthy = makePingableClient(true);
    internals.activeSessions["session-A"] = {
      "server-dead": dead,
      "server-ok": healthy,
    };
    internals.sessionToServers["session-A"] = new Set([
      "server-dead",
      "server-ok",
    ]);

    await internals.checkActiveSessionHealth(); // strike 1
    await internals.checkActiveSessionHealth(); // strike 2 → evict dead only

    expect(dead.cleanup).toHaveBeenCalledTimes(1);
    expect(healthy.cleanup).not.toHaveBeenCalled();
    expect(internals.activeSessions["session-A"]["server-ok"]).toBe(healthy);
  });

  it("MCP_ACTIVE_HEALTH_CHECK=false disables the sweep from the timer path", async () => {
    const prev = process.env.MCP_ACTIVE_HEALTH_CHECK;
    process.env.MCP_ACTIVE_HEALTH_CHECK = "false";
    try {
      const gatedPool = new PoolConstructor();
      const gated = gatedPool as never as typeof internals;
      gated.activeSessions = {};
      gated.idleSessions = {};
      gated.sessionToServers = {};
      gated.creatingIdleSessions = new Set();
      gated.serverParamsCache = {};
      gated.activePingFailures = {};

      const dead = makePingableClient(false);
      gated.activeSessions["session-A"] = { "server-1": dead };

      await (
        gatedPool as never as { checkIdleSessionHealth: () => Promise<void> }
      ).checkIdleSessionHealth();
      await (
        gatedPool as never as { checkIdleSessionHealth: () => Promise<void> }
      ).checkIdleSessionHealth();

      expect(dead.client.ping).not.toHaveBeenCalled();
      expect(dead.cleanup).not.toHaveBeenCalled();
    } finally {
      if (prev === undefined) {
        delete process.env.MCP_ACTIVE_HEALTH_CHECK;
      } else {
        process.env.MCP_ACTIVE_HEALTH_CHECK = prev;
      }
    }
  });
});

describe("McpServerPool half-open ERROR-gate probe", () => {
  // The DB error_status gate is otherwise sticky forever: once a server
  // is marked ERROR, connectMetaMcpClient refuses every attempt and the
  // only request-path reset (cold-start warmup) requires the WHOLE pool
  // to be empty — which never happens while other namespaces hold live
  // connections. Observed as the unkillable "No session for: autotask"
  // loop in incident 2026-06-11.

  type ProbeInternals = {
    activeSessions: Record<string, unknown>;
    idleSessions: Record<string, unknown>;
    sessionToServers: Record<string, Set<string>>;
    creatingIdleSessions: Set<string>;
    serverParamsCache: Record<string, unknown>;
    lastErrorProbeAt: Record<string, number>;
    errorProbeIntervalMs: number;
    checkIdleSessionHealth: () => Promise<void>;
  };

  let pool: McpServerPool;
  let internals: ProbeInternals;
  let tracker: {
    isServerInErrorState: ReturnType<typeof vi.fn>;
    resetServerErrorState: ReturnType<typeof vi.fn>;
  };
  let createIdleSpy: ReturnType<typeof vi.fn>;

  beforeEach(async () => {
    pool = new PoolConstructor();

    internals = pool as never;
    internals.activeSessions = {};
    internals.idleSessions = {};
    internals.sessionToServers = {};
    internals.creatingIdleSessions = new Set();
    internals.serverParamsCache = {
      "server-err": { uuid: "server-err", name: "errored-backend" },
    };
    internals.lastErrorProbeAt = {};

    tracker = (await import("./server-error-tracker"))
      .serverErrorTracker as never;
    tracker.isServerInErrorState.mockReset().mockResolvedValue(true);
    tracker.resetServerErrorState.mockReset();

    createIdleSpy = vi.fn();
    (
      pool as never as { createIdleSessionAsync: unknown }
    ).createIdleSessionAsync = createIdleSpy;
  });

  it("probes an ERROR-gated server once the interval has elapsed", async () => {
    await internals.checkIdleSessionHealth();

    expect(tracker.resetServerErrorState).toHaveBeenCalledTimes(1);
    expect(tracker.resetServerErrorState).toHaveBeenCalledWith("server-err");
    expect(createIdleSpy).toHaveBeenCalledWith(
      "server-err",
      internals.serverParamsCache["server-err"],
    );
  });

  it("does not re-probe within the interval", async () => {
    await internals.checkIdleSessionHealth();
    await internals.checkIdleSessionHealth();

    expect(tracker.resetServerErrorState).toHaveBeenCalledTimes(1);
  });

  it("re-probes after the interval has elapsed again", async () => {
    await internals.checkIdleSessionHealth();
    // Simulate the probe interval passing.
    internals.lastErrorProbeAt["server-err"] =
      Date.now() - internals.errorProbeIntervalMs - 1;
    await internals.checkIdleSessionHealth();

    expect(tracker.resetServerErrorState).toHaveBeenCalledTimes(2);
  });

  it("MCP_ERROR_PROBE_INTERVAL_MS=0 disables the probe", async () => {
    const prev = process.env.MCP_ERROR_PROBE_INTERVAL_MS;
    process.env.MCP_ERROR_PROBE_INTERVAL_MS = "0";
    try {
      const gatedPool = new PoolConstructor();
      const gated = gatedPool as never as ProbeInternals;
      gated.activeSessions = {};
      gated.idleSessions = {};
      gated.sessionToServers = {};
      gated.creatingIdleSessions = new Set();
      gated.serverParamsCache = {
        "server-err": { uuid: "server-err", name: "errored-backend" },
      };
      gated.lastErrorProbeAt = {};
      (
        gatedPool as never as { createIdleSessionAsync: unknown }
      ).createIdleSessionAsync = vi.fn();

      await gated.checkIdleSessionHealth();

      expect(tracker.resetServerErrorState).not.toHaveBeenCalled();
    } finally {
      if (prev === undefined) {
        delete process.env.MCP_ERROR_PROBE_INTERVAL_MS;
      } else {
        process.env.MCP_ERROR_PROBE_INTERVAL_MS = prev;
      }
    }
  });

  it("non-ERROR servers keep the plain idle-rebuild path, no gate reset", async () => {
    tracker.isServerInErrorState.mockResolvedValue(false);

    await internals.checkIdleSessionHealth();

    expect(tracker.resetServerErrorState).not.toHaveBeenCalled();
    expect(createIdleSpy).toHaveBeenCalledWith(
      "server-err",
      internals.serverParamsCache["server-err"],
    );
  });
});

describe("McpServerPool connect-failure stamp — /health/upstream truthfulness", () => {
  // HTTP/SSE backends never trip the ERROR circuit breaker (crash
  // counting is STDIO-only), so before this stamp a hard-down HTTP
  // backend read `reachable: true` on /health/upstream forever. The
  // pool stamps every failed connect attempt and clears the stamp on
  // success; the endpoint reads it via getPoolStatus.

  type StampInternals = {
    lastConnectFailureAt: Record<string, number>;
    serverLastSuccessAt: Record<string, number>;
    serverParamsCache: Record<string, unknown>;
    createNewConnection: (
      params: { uuid: string; name: string },
      namespaceUuid?: string,
    ) => Promise<unknown>;
    markServerSuccess: (serverUuid: string) => void;
  };

  let pool: McpServerPool;
  let internals: StampInternals;
  let connectMock: ReturnType<typeof vi.fn>;

  beforeEach(async () => {
    pool = new PoolConstructor();
    internals = pool as never;
    connectMock = (await import("./client"))
      .connectMetaMcpClient as unknown as ReturnType<typeof vi.fn>;
    connectMock.mockReset();
  });

  it("stamps lastConnectFailureAt when connectMetaMcpClient resolves undefined", async () => {
    connectMock.mockResolvedValue(undefined);

    const result = await internals.createNewConnection({
      uuid: "server-down",
      name: "down-backend",
    });

    expect(result).toBeUndefined();
    expect(internals.lastConnectFailureAt["server-down"]).toBeTypeOf("number");
  });

  it("clears the failure stamp on a successful connect", async () => {
    internals.lastConnectFailureAt["server-flap"] = 12345;
    connectMock.mockResolvedValue({ client: {}, cleanup: vi.fn() });

    const result = await internals.createNewConnection({
      uuid: "server-flap",
      name: "flapping-backend",
    });

    expect(result).toBeDefined();
    expect(internals.lastConnectFailureAt["server-flap"]).toBeUndefined();
    expect(internals.serverLastSuccessAt["server-flap"]).toBeTypeOf("number");
  });

  it("exposes failure/success stamps via getPoolStatus", () => {
    internals.lastConnectFailureAt["server-a"] = 111;
    internals.serverLastSuccessAt["server-b"] = 222;

    const status = pool.getPoolStatus();

    expect(status.lastConnectFailureAt).toEqual({ "server-a": 111 });
    expect(status.lastConnectSuccessAt).toEqual({ "server-b": 222 });
    expect(status.pingFailures).toEqual({});
  });

  it("getPoolStatus returns copies, not live references", () => {
    internals.lastConnectFailureAt["server-a"] = 111;

    const status = pool.getPoolStatus();
    const stamps = status.lastConnectFailureAt as Record<string, number>;
    stamps["server-a"] = 999;

    expect(internals.lastConnectFailureAt["server-a"]).toBe(111);
  });
});
