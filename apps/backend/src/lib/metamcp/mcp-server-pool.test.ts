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

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

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
import { toolsSyncCache } from "./tools-sync-cache";

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

// -------------------------------------------------------------------
// Periodic tool-definition sweep (Track A2)
//
// Prod backends deliver tool updates as container replaces that kill the
// process, and the SDK standalone GET stream (the only push channel) dies
// and exhausts its auto-reconnect before the replacement boots — so no
// push notification survives an update. The sweep is the pull signal: it
// re-lists tools over an existing pooled connection and compares the
// full-definition hash (Track A3) against a baseline the SWEEP ITSELF
// owns (`toolsSweepLastHash`), never `toolsSyncCache`. Review findings
// (2026-07-14) on the first cut, which compared against `toolsSyncCache`
// directly:
//   - Finding 1 (high): an idle-only server has zero
//     `listChangedSubscribers`, so the invalidation fan-out reaches no
//     one and `toolsSyncCache` never updates downstream. Comparing
//     against that frozen cache re-detected the SAME already-handled
//     change every ~60s tick, forever — invalidate → health-check timer
//     recreates the idle connection → re-detect — on exactly the
//     Watchtower-replace scenario the sweep targets.
//   - Finding 2 (medium): `tools.impl.sync` overwrites `toolsSyncCache`
//     with the namespace-FILTERED tool set whenever
//     `filterOutOverrideTools` drops a tool, while the sweep always lists
//     the UNFILTERED set — a permanent false-drift mismatch even for
//     servers with active consumers.
// A sweep-owned baseline (seed silently on first observation, update on
// every tick, invalidate only when the new hash differs from the sweep's
// OWN prior observation) makes both impossible: it always compares
// unfiltered-vs-unfiltered, and updating immediately on detection makes
// the invalidate fire exactly once per real change.
// -------------------------------------------------------------------
describe("McpServerPool.sweepToolDefinitions — periodic tools/list drift sweep", () => {
  type RequestableFakeClient = FakeClient & {
    client: { request: ReturnType<typeof vi.fn> };
  };

  type SweepTool = {
    name: string;
    description?: string | null;
    inputSchema?: unknown;
  };

  // A fake ConnectedClient whose tools/list returns `tools` in a single
  // (unpaginated) page. The sweep passes ListToolsResultSchema + a timeout
  // to request(); the mock ignores both and returns the shape directly.
  function makeRequestableClient(tools: SweepTool[]): RequestableFakeClient {
    const fake = makeFakeClient() as RequestableFakeClient;
    fake.client = {
      request: vi.fn().mockResolvedValue({ tools, nextCursor: undefined }),
    };
    return fake;
  }

  const baseline: SweepTool[] = [
    { name: "search", description: "old", inputSchema: { type: "object" } },
  ];
  // Same name + schema, reworded description — the exact drift name-only
  // hashing missed and A3's full-def hash now catches.
  const drifted: SweepTool[] = [
    { name: "search", description: "NEW", inputSchema: { type: "object" } },
  ];

  let pool: McpServerPool;
  let internals: {
    activeSessions: Record<string, Record<string, RequestableFakeClient>>;
    idleSessions: Record<string, RequestableFakeClient>;
    serverParamsCache: Record<string, unknown>;
    toolsSweepInProgress: boolean;
    toolsSweepLastHash: Record<string, string>;
    sweepToolDefinitions: () => Promise<void>;
  };

  beforeEach(() => {
    toolsSyncCache.clear();
    pool = new PoolConstructor();
    internals = pool as never;
    internals.activeSessions = {};
    internals.idleSessions = {};
    internals.serverParamsCache = {};
  });

  afterEach(() => {
    vi.restoreAllMocks();
    // Stop the real interval this pool started so it can't fire mid-suite.
    void pool.cleanupAll();
  });

  it("seeds silently on first observation — no invalidate fires from the seed tick", async () => {
    // No toolsSyncCache entry either — proves the sweep no longer gates on
    // (or needs) the shared cache to decide whether to re-list a server.
    const client = makeRequestableClient(baseline);
    internals.activeSessions["session-A"] = { "server-1": client };
    const invalidate = vi.spyOn(pool, "invalidateServerConnection");

    await internals.sweepToolDefinitions();

    expect(client.client.request).toHaveBeenCalledTimes(1);
    expect(invalidate).not.toHaveBeenCalled();
    expect(internals.toolsSweepLastHash["server-1"]).toBeDefined();
  });

  it("fires on the tick where the listed tools actually change, not the seed tick", async () => {
    const client = makeRequestableClient(baseline);
    internals.activeSessions["session-A"] = { "server-1": client };
    const invalidate = vi
      .spyOn(pool, "invalidateServerConnection")
      .mockResolvedValue();

    await internals.sweepToolDefinitions(); // seed, no fire
    expect(invalidate).not.toHaveBeenCalled();

    client.client.request = vi
      .fn()
      .mockResolvedValue({ tools: drifted, nextCursor: undefined });
    await internals.sweepToolDefinitions(); // real change → fire

    expect(invalidate).toHaveBeenCalledTimes(1);
    expect(invalidate).toHaveBeenCalledWith("<tools-sweep>", "server-1");
  });

  it("is a no-op across ticks when tools are unchanged", async () => {
    const client = makeRequestableClient(baseline);
    internals.activeSessions["session-A"] = { "server-1": client };
    const invalidate = vi.spyOn(pool, "invalidateServerConnection");

    await internals.sweepToolDefinitions();
    await internals.sweepToolDefinitions();
    await internals.sweepToolDefinitions();

    expect(client.client.request).toHaveBeenCalledTimes(3);
    expect(invalidate).not.toHaveBeenCalled();
  });

  it("isolates a per-server tools/list failure and still fires for its neighbor's real change", async () => {
    const bad = makeRequestableClient(baseline);
    const good = makeRequestableClient(baseline);
    internals.activeSessions["session-A"] = {
      "server-bad": bad,
      "server-good": good,
    };
    const invalidate = vi
      .spyOn(pool, "invalidateServerConnection")
      .mockResolvedValue();

    await internals.sweepToolDefinitions(); // both seed

    bad.client.request = vi.fn().mockRejectedValue(new Error("mid-restart"));
    good.client.request = vi
      .fn()
      .mockResolvedValue({ tools: drifted, nextCursor: undefined });

    await expect(internals.sweepToolDefinitions()).resolves.not.toThrow();

    expect(invalidate).toHaveBeenCalledWith("<tools-sweep>", "server-good");
    expect(invalidate).not.toHaveBeenCalledWith("<tools-sweep>", "server-bad");
    // The failed server's baseline is untouched (never re-hashed), not
    // corrupted by the failed attempt.
    expect(internals.toolsSweepLastHash["server-bad"]).toBe(
      toolsSyncCache.hashTools(baseline),
    );
  });

  it("skips an overlapping tick while a sweep is still in flight", async () => {
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const client = makeRequestableClient(baseline);
    client.client.request = vi.fn().mockImplementation(async () => {
      await gate; // hang until released to hold the first sweep open
      return { tools: baseline, nextCursor: undefined };
    });
    internals.activeSessions["session-A"] = { "server-1": client };

    const first = internals.sweepToolDefinitions(); // starts, hangs on request
    await internals.sweepToolDefinitions(); // second tick → guard skips it

    // The second call returned without issuing its own tools/list.
    expect(client.client.request).toHaveBeenCalledTimes(1);

    release();
    await first;
    expect(client.client.request).toHaveBeenCalledTimes(1);
  });

  it("uses an idle connection when the server has no active slot", async () => {
    const idle = makeRequestableClient(baseline);
    internals.idleSessions["server-1"] = idle;
    const invalidate = vi
      .spyOn(pool, "invalidateServerConnection")
      .mockResolvedValue();

    await internals.sweepToolDefinitions(); // seed
    expect(invalidate).not.toHaveBeenCalled();

    idle.client.request = vi
      .fn()
      .mockResolvedValue({ tools: drifted, nextCursor: undefined });
    await internals.sweepToolDefinitions(); // real change → fire

    expect(idle.client.request).toHaveBeenCalledTimes(1);
    expect(invalidate).toHaveBeenCalledWith("<tools-sweep>", "server-1");
  });

  // -----------------------------------------------------------------
  // Review-requested regression coverage (2026-07-14)
  // -----------------------------------------------------------------

  it("(a) multi-tick idle-only, zero subscribers: one real change produces exactly ONE invalidate, quiet after", async () => {
    // Idle-only: no active session, and makeFakeClient()'s
    // listChangedSubscribers set is empty — the exact Finding 1 shape.
    // With the OLD toolsSyncCache-compared design this would refire every
    // tick forever because nothing ever updates the shared cache for an
    // idle-only server.
    const idle = makeRequestableClient(baseline);
    internals.idleSessions["server-1"] = idle;
    const invalidate = vi
      .spyOn(pool, "invalidateServerConnection")
      .mockResolvedValue();

    await internals.sweepToolDefinitions(); // tick 1: seed, no fire
    expect(invalidate).not.toHaveBeenCalled();

    idle.client.request = vi
      .fn()
      .mockResolvedValue({ tools: drifted, nextCursor: undefined });
    await internals.sweepToolDefinitions(); // tick 2: the one real change
    expect(invalidate).toHaveBeenCalledTimes(1);

    // Tools stay drifted (unchanged from tick 2's observation) for every
    // subsequent tick — no downstream consumer ever touches toolsSyncCache
    // since there are no subscribers to notify.
    await internals.sweepToolDefinitions(); // tick 3
    await internals.sweepToolDefinitions(); // tick 4
    await internals.sweepToolDefinitions(); // tick 5

    expect(invalidate).toHaveBeenCalledTimes(1);
  });

  it("(b) baseline independence: a stale/filtered toolsSyncCache entry does not cause the sweep to fire when the listed set is unchanged", async () => {
    // Simulates tools.impl.sync (Finding 2): the shared cache holds a
    // namespace-FILTERED hash that permanently disagrees with the
    // UNFILTERED set the sweep lists. If the sweep compared against
    // toolsSyncCache this would read as permanent drift on every tick.
    const filteredAway: SweepTool[] = []; // e.g. every tool got filtered out
    toolsSyncCache.update("server-1", filteredAway);
    expect(toolsSyncCache.hasChanged("server-1", baseline)).toBe(true); // sanity: shared cache disagrees

    const client = makeRequestableClient(baseline);
    internals.activeSessions["session-A"] = { "server-1": client };
    const invalidate = vi.spyOn(pool, "invalidateServerConnection");

    await internals.sweepToolDefinitions(); // seed
    await internals.sweepToolDefinitions(); // same unfiltered tools again
    await internals.sweepToolDefinitions(); // and again

    expect(client.client.request).toHaveBeenCalledTimes(3);
    expect(invalidate).not.toHaveBeenCalled();
    // The shared cache's disagreement is untouched by the sweep — proof
    // it never wrote to or read from toolsSyncCache's stateful surface.
    expect(toolsSyncCache.hasChanged("server-1", baseline)).toBe(true);
  });

  it("(c) a non-advancing tools/list cursor trips the pagination guard, and the NEXT tick still runs", async () => {
    const client = makeRequestableClient([]);
    client.client.request = vi.fn().mockResolvedValue({
      tools: [{ name: "stuck", description: "d", inputSchema: {} }],
      nextCursor: "same-cursor", // identical every response: non-advancing
    });
    internals.activeSessions["session-A"] = { "server-1": client };

    await expect(internals.sweepToolDefinitions()).resolves.not.toThrow();

    // First request: cursor=undefined -> nextCursor="same-cursor" (no match
    // yet, page 1). Second request: cursor="same-cursor" -> nextCursor=
    // "same-cursor" again (matches the cursor just sent) -> guard trips,
    // pagination stops. Never loops.
    expect(client.client.request).toHaveBeenCalledTimes(2);
    expect(internals.toolsSweepInProgress).toBe(false);

    // The in-flight guard was released cleanly by the completed (not
    // hung) sweep — a subsequent tick runs too, proving no permanent wedge.
    client.client.request.mockClear();
    await internals.sweepToolDefinitions();
    expect(client.client.request).toHaveBeenCalledTimes(2);
  });

  it("caps pagination at the hard page limit even when the cursor keeps advancing", async () => {
    let page = 0;
    const client = makeRequestableClient([]);
    client.client.request = vi.fn().mockImplementation(async () => {
      page++;
      return { tools: [], nextCursor: `page-${page}` }; // always advances, never terminates on its own
    });
    internals.activeSessions["session-A"] = { "server-1": client };

    await expect(internals.sweepToolDefinitions()).resolves.not.toThrow();

    // TOOLS_SWEEP_MAX_PAGES (50) is the backstop for this shape — the
    // non-advancing-cursor check above can't catch an always-different
    // cursor, so a hard cap is the only thing that stops it.
    expect(client.client.request).toHaveBeenCalledTimes(50);
    expect(internals.toolsSweepInProgress).toBe(false);
  });
});

describe("McpServerPool tool-sweep timer lifecycle", () => {
  it("TOOLS_SWEEP_INTERVAL_SECONDS=0 disables the sweep (no timer)", () => {
    const prev = process.env.TOOLS_SWEEP_INTERVAL_SECONDS;
    process.env.TOOLS_SWEEP_INTERVAL_SECONDS = "0";
    try {
      const gatedPool = new PoolConstructor();
      expect(
        (gatedPool as never as { toolsSweepTimer: unknown }).toolsSweepTimer,
      ).toBeNull();
      void gatedPool.cleanupAll();
    } finally {
      if (prev === undefined) {
        delete process.env.TOOLS_SWEEP_INTERVAL_SECONDS;
      } else {
        process.env.TOOLS_SWEEP_INTERVAL_SECONDS = prev;
      }
    }
  });

  it("schedules a timer at the default interval and clears it on cleanupAll (clean shutdown)", async () => {
    const prev = process.env.TOOLS_SWEEP_INTERVAL_SECONDS;
    delete process.env.TOOLS_SWEEP_INTERVAL_SECONDS; // default 60s
    try {
      const timedPool = new PoolConstructor();
      const timerRef = timedPool as never as { toolsSweepTimer: unknown };
      expect(timerRef.toolsSweepTimer).not.toBeNull();

      await timedPool.cleanupAll();

      expect(timerRef.toolsSweepTimer).toBeNull();
    } finally {
      if (prev !== undefined) {
        process.env.TOOLS_SWEEP_INTERVAL_SECONDS = prev;
      }
    }
  });
});
