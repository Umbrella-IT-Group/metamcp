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
    pool = new McpServerPool();

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

    pool = new McpServerPool();
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
