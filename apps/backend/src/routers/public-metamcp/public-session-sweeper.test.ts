import { afterEach, describe, expect, it, vi } from "vitest";

import {
  PublicSessionSweeper,
  PublicSessionSweeperDeps,
} from "./public-session-sweeper";

// A controllable clock so idle-age math is deterministic (no wall-clock
// waiting). Tests advance `clock.now` explicitly.
function makeClock(start = 1_000_000) {
  let value = start;
  return {
    now: () => value,
    advance: (ms: number) => {
      value += ms;
    },
    set: (ms: number) => {
      value = ms;
    },
  };
}

const TTL_MS = 60_000; // 60s idle TTL for the behavior tests
const INTERVAL_MS = 5_000;

function makeSweeper(
  overrides: Partial<PublicSessionSweeperDeps> = {},
  config = { ttlMs: TTL_MS, intervalMs: INTERVAL_MS },
): {
  sweeper: PublicSessionSweeper;
  reap: ReturnType<typeof vi.fn>;
  clock: ReturnType<typeof makeClock>;
} {
  const clock = makeClock();
  const reap = vi.fn().mockResolvedValue(undefined);
  const sweeper = new PublicSessionSweeper("test", config, {
    reapSession: reap,
    now: clock.now,
    ...overrides,
  });
  return { sweeper, reap, clock };
}

describe("PublicSessionSweeper — idle reaping", () => {
  it("reaps a session idle beyond the TTL, exactly once", async () => {
    const { sweeper, reap, clock } = makeSweeper();
    sweeper.beginTracking("sess-idle");

    // Not yet past TTL — no reap.
    clock.advance(TTL_MS); // exactly TTL, strictly-greater check → survives
    let result = await sweeper.sweepOnce();
    expect(result.reaped).toBe(0);
    expect(reap).not.toHaveBeenCalled();

    // Cross the TTL.
    clock.advance(1);
    result = await sweeper.sweepOnce();
    expect(result.reaped).toBe(1);
    expect(reap).toHaveBeenCalledTimes(1);
    expect(reap).toHaveBeenCalledWith("sess-idle");

    // forget() ran inside the sweep → a second sweep reaps nothing more,
    // even though the wall clock is still past TTL.
    clock.advance(TTL_MS * 10);
    result = await sweeper.sweepOnce();
    expect(result.reaped).toBe(0);
    expect(reap).toHaveBeenCalledTimes(1);
  });

  it("never reaps a recently-active session", async () => {
    const { sweeper, reap, clock } = makeSweeper();
    sweeper.beginTracking("sess-active");

    // A request lands just before the sweep — activity is fresh.
    clock.advance(TTL_MS * 5);
    sweeper.touch("sess-active"); // request updates the stamp
    const result = await sweeper.sweepOnce();

    expect(result.reaped).toBe(0);
    expect(reap).not.toHaveBeenCalled();
    expect(sweeper.getLastActivity("sess-active")).toBe(clock.now());
  });

  it("never reaps a session with an in-flight request, even when its stamp is old", async () => {
    const { sweeper, reap, clock } = makeSweeper();
    sweeper.beginTracking("sess-longcall"); // session exists in memory
    sweeper.markInFlight("sess-longcall"); // request arrives; in-flight = 1

    // The call runs far longer than the idle TTL.
    clock.advance(TTL_MS * 100);
    let result = await sweeper.sweepOnce();
    expect(result.reaped).toBe(0);
    expect(reap).not.toHaveBeenCalled();
    expect(sweeper.getInFlight("sess-longcall")).toBe(1);

    // Once the call settles, the stamp is refreshed → still not reapable
    // immediately.
    sweeper.markSettled("sess-longcall");
    expect(sweeper.getInFlight("sess-longcall")).toBe(0);
    result = await sweeper.sweepOnce();
    expect(result.reaped).toBe(0);

    // ...but after a further idle stretch it becomes reapable.
    clock.advance(TTL_MS + 1);
    result = await sweeper.sweepOnce();
    expect(result.reaped).toBe(1);
    expect(reap).toHaveBeenCalledWith("sess-longcall");
  });

  it("counts overlapping in-flight requests (settle once ≠ idle)", async () => {
    const { sweeper, clock } = makeSweeper();
    sweeper.beginTracking("sess");
    sweeper.markInFlight("sess"); // 1
    sweeper.markInFlight("sess"); // 2
    sweeper.markSettled("sess"); // back to 1 — still in-flight
    expect(sweeper.getInFlight("sess")).toBe(1);

    clock.advance(TTL_MS * 100);
    const result = await sweeper.sweepOnce();
    expect(result.reaped).toBe(0); // one request still outstanding
  });

  it("reaps some and keeps others in the same sweep", async () => {
    const { sweeper, reap, clock } = makeSweeper();
    sweeper.beginTracking("old-1");
    sweeper.beginTracking("old-2");
    clock.advance(TTL_MS + 1);
    sweeper.beginTracking("fresh"); // fresh at sweep time
    sweeper.beginTracking("busy");
    sweeper.markInFlight("busy"); // in-flight, stamp is old-ish but guarded

    const result = await sweeper.sweepOnce();

    expect(result.reaped).toBe(2);
    const reaped = reap.mock.calls.map((c) => c[0]).sort();
    expect(reaped).toEqual(["old-1", "old-2"]);
    expect(sweeper.getLastActivity("fresh")).toBeDefined();
    expect(sweeper.getInFlight("busy")).toBe(1);
  });
});

describe("PublicSessionSweeper — sequential recheck-before-reap (snapshot-to-reap race)", () => {
  // Foreman review item 2 (PR #72 fixes round): sweepOnce snapshots
  // candidates once, but must re-check each one's current state
  // immediately before reaping it — not just at snapshot time — so a
  // request that lands while an EARLIER candidate's reap is still
  // awaiting real I/O can't have a LATER candidate's transport closed out
  // from under it. This only has teeth with sequential processing: while
  // "A"'s reap is gated open (simulating real async I/O), a "request"
  // lands on "B" (still queued, not yet reaped) and must save it.
  it("a session that becomes active again while an earlier candidate is mid-reap is saved by the recheck", async () => {
    let releaseA!: () => void;
    const gateA = new Promise<void>((resolve) => {
      releaseA = resolve;
    });
    const reap = vi.fn().mockImplementation(async (sessionId: string) => {
      if (sessionId === "A") {
        await gateA; // hold A's reap open — the real-I/O window
      }
    });
    const { sweeper, clock } = makeSweeper({ reapSession: reap });
    sweeper.beginTracking("A");
    sweeper.beginTracking("B");
    clock.advance(TTL_MS + 1); // both idle-eligible at snapshot time

    const sweepPromise = sweeper.sweepOnce(); // snapshots [A, B]; starts A's (gated) reap

    // While A's reap is still pending, a real request lands on B.
    sweeper.markInFlight("B");

    releaseA();
    const result = await sweepPromise;
    // markInFlight leaves B in-flight — settle it so state is clean for
    // the assertions below (mirrors a request that has now finished).
    sweeper.markSettled("B");

    expect(reap).toHaveBeenCalledWith("A");
    expect(reap).not.toHaveBeenCalledWith("B"); // recheck caught the request
    expect(result.reaped).toBe(1);
    expect(result.failed).toBe(0);
    // B's tracking is untouched by the sweep — not forgotten mid-request.
    expect(sweeper.getLastActivity("B")).toBeDefined();
  });

  it("a session touched (not just in-flight) between snapshot and its own reap is also saved", async () => {
    let releaseA!: () => void;
    const gateA = new Promise<void>((resolve) => {
      releaseA = resolve;
    });
    const reap = vi.fn().mockImplementation(async (sessionId: string) => {
      if (sessionId === "A") {
        await gateA;
      }
    });
    const { sweeper, clock } = makeSweeper({ reapSession: reap });
    sweeper.beginTracking("A");
    sweeper.beginTracking("B");
    clock.advance(TTL_MS + 1);

    const sweepPromise = sweeper.sweepOnce();
    sweeper.touch("B"); // a settled request re-stamps activity, no in-flight

    releaseA();
    const result = await sweepPromise;

    expect(reap).not.toHaveBeenCalledWith("B");
    expect(result.reaped).toBe(1);
  });
});

describe("PublicSessionSweeper — last-activity tracking", () => {
  it("beginTracking seeds a fresh entry unconditionally", () => {
    const { sweeper, clock } = makeSweeper();
    expect(sweeper.getLastActivity("s")).toBeUndefined();
    sweeper.beginTracking("s");
    expect(sweeper.getLastActivity("s")).toBe(clock.now());
  });

  it("touch updates the stamp to now for an already-tracked session", () => {
    const { sweeper, clock } = makeSweeper();
    sweeper.beginTracking("s");
    expect(sweeper.getLastActivity("s")).toBe(clock.now());
    clock.advance(1234);
    sweeper.touch("s");
    expect(sweeper.getLastActivity("s")).toBe(clock.now());
  });

  it("touch is a no-op for a session that was never tracked", () => {
    const { sweeper } = makeSweeper();
    sweeper.touch("never-seeded");
    expect(sweeper.getLastActivity("never-seeded")).toBeUndefined();
  });

  it("markInFlight and markSettled both stamp activity on a tracked session", () => {
    const { sweeper, clock } = makeSweeper();
    sweeper.beginTracking("s");
    sweeper.markInFlight("s");
    expect(sweeper.getLastActivity("s")).toBe(clock.now());
    clock.advance(500);
    sweeper.markSettled("s");
    expect(sweeper.getLastActivity("s")).toBe(clock.now());
  });

  it("markInFlight is a no-op for an untracked session — no dangling in-flight entry", () => {
    const { sweeper } = makeSweeper();
    sweeper.markInFlight("ghost");
    expect(sweeper.getInFlight("ghost")).toBe(0);
    expect(sweeper.getLastActivity("ghost")).toBeUndefined();
  });

  it("forget drops all tracking for a session", () => {
    const { sweeper } = makeSweeper();
    sweeper.beginTracking("s");
    sweeper.markInFlight("s");
    expect(sweeper.getLastActivity("s")).toBeDefined();
    expect(sweeper.getInFlight("s")).toBe(1);
    sweeper.forget("s");
    expect(sweeper.getLastActivity("s")).toBeUndefined();
    expect(sweeper.getInFlight("s")).toBe(0);
  });

  // Foreman review item 3 (PR #72 fixes round): a trailing markSettled
  // that lands AFTER a concurrent forget() (e.g. a client DELETE racing
  // an in-flight request) must not resurrect a zombie tracking entry for
  // a session whose transport/pool state is already gone.
  it("markSettled after a concurrent forget() does not resurrect the entry", () => {
    const { sweeper } = makeSweeper();
    sweeper.beginTracking("s");
    sweeper.markInFlight("s"); // request starts; in-flight = 1

    // A concurrent DELETE tears the session down mid-request.
    sweeper.forget("s");
    expect(sweeper.getLastActivity("s")).toBeUndefined();
    expect(sweeper.getInFlight("s")).toBe(0);

    // The original request's dispatch finally settles.
    sweeper.markSettled("s");

    // Must still be gone — not resurrected.
    expect(sweeper.getLastActivity("s")).toBeUndefined();
    expect(sweeper.getInFlight("s")).toBe(0);
  });

  it("touch after a concurrent forget() does not resurrect the entry", () => {
    const { sweeper } = makeSweeper();
    sweeper.beginTracking("s");
    sweeper.forget("s");
    sweeper.touch("s"); // a trailing request-arrival stamp
    expect(sweeper.getLastActivity("s")).toBeUndefined();
  });

  it("beginTracking re-seeds after a forget (lazy-recovery re-tracking)", () => {
    const { sweeper, clock } = makeSweeper();
    sweeper.beginTracking("s");
    sweeper.forget("s");
    expect(sweeper.getLastActivity("s")).toBeUndefined();

    clock.advance(10);
    sweeper.beginTracking("s"); // recovery path re-seeds
    expect(sweeper.getLastActivity("s")).toBe(clock.now());
  });
});

describe("PublicSessionSweeper — released-connection accounting", () => {
  it("reports the drop in backend active connections across the reap batch", async () => {
    const measure = vi
      .fn()
      .mockReturnValueOnce(5) // before
      .mockReturnValueOnce(3); // after
    const { sweeper, clock } = makeSweeper({
      measureActiveConnections: measure,
    });
    sweeper.beginTracking("s");
    clock.advance(TTL_MS + 1);

    const result = await sweeper.sweepOnce();
    expect(result.reaped).toBe(1);
    expect(result.released).toBe(2);

    const stats = sweeper.getStats();
    expect(stats.totalConnectionsReleased).toBe(2);
    expect(stats.lastReleasedCount).toBe(2);
  });

  it("floors released at 0 if the count somehow rose", async () => {
    const measure = vi.fn().mockReturnValueOnce(2).mockReturnValueOnce(4);
    const { sweeper, clock } = makeSweeper({
      measureActiveConnections: measure,
    });
    sweeper.beginTracking("s");
    clock.advance(TTL_MS + 1);
    const result = await sweeper.sweepOnce();
    expect(result.released).toBe(0);
  });

  it("does not probe connection count when there is nothing to reap", async () => {
    const measure = vi.fn().mockReturnValue(7);
    const { sweeper } = makeSweeper({ measureActiveConnections: measure });
    sweeper.beginTracking("s"); // fresh
    const result = await sweeper.sweepOnce();
    expect(result.reaped).toBe(0);
    expect(measure).not.toHaveBeenCalled();
  });
});

describe("PublicSessionSweeper — reap failure tolerance", () => {
  it("still forgets a session whose reap rejects, and reports the failure", async () => {
    const reap = vi.fn().mockRejectedValue(new Error("cleanup boom"));
    const { sweeper, clock } = makeSweeper({ reapSession: reap });
    sweeper.beginTracking("bad");
    clock.advance(TTL_MS + 1);

    const result = await sweeper.sweepOnce();
    expect(result.failed).toBe(1);
    expect(result.reaped).toBe(0);
    // Forgotten regardless — must not be re-selected every tick forever.
    expect(sweeper.getLastActivity("bad")).toBeUndefined();

    const again = await sweeper.sweepOnce();
    expect(again.failed).toBe(0);
    expect(reap).toHaveBeenCalledTimes(1);
  });
});

describe("PublicSessionSweeper — re-entrancy guard", () => {
  it("skips an overlapping sweep while one is still in flight", async () => {
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const reap = vi.fn().mockImplementation(async () => {
      await gate; // hold the first sweep open
    });
    const { sweeper, clock } = makeSweeper({ reapSession: reap });
    sweeper.beginTracking("s");
    clock.advance(TTL_MS + 1);

    const first = sweeper.sweepOnce(); // starts, hangs inside reap
    const second = await sweeper.sweepOnce(); // guard skips it immediately

    expect(second.reaped).toBe(0);
    expect(reap).toHaveBeenCalledTimes(1);

    release();
    const firstResult = await first;
    expect(firstResult.reaped).toBe(1);
    expect(reap).toHaveBeenCalledTimes(1);
  });
});

describe("PublicSessionSweeper — TTL / disable semantics", () => {
  it("TTL 0 disables reaping entirely (sweepOnce no-ops)", async () => {
    const { sweeper, reap, clock } = makeSweeper(
      {},
      { ttlMs: 0, intervalMs: INTERVAL_MS },
    );
    sweeper.beginTracking("s");
    clock.advance(10_000_000);
    const result = await sweeper.sweepOnce();
    expect(result.reaped).toBe(0);
    expect(reap).not.toHaveBeenCalled();
    expect(sweeper.isEnabled()).toBe(false);
  });
});

describe("PublicSessionSweeper — timer lifecycle", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it("start arms a timer at the interval; stop clears it", () => {
    const { sweeper } = makeSweeper();
    expect(sweeper.hasTimer()).toBe(false);
    sweeper.start();
    expect(sweeper.hasTimer()).toBe(true);
    sweeper.stop();
    expect(sweeper.hasTimer()).toBe(false);
  });

  it("start is idempotent (a second call while armed is a no-op)", () => {
    const { sweeper } = makeSweeper();
    sweeper.start();
    sweeper.start();
    expect(sweeper.hasTimer()).toBe(true);
    sweeper.stop();
  });

  it("TTL 0 arms no timer", () => {
    const { sweeper } = makeSweeper({}, { ttlMs: 0, intervalMs: INTERVAL_MS });
    sweeper.start();
    expect(sweeper.hasTimer()).toBe(false);
  });

  it("interval 0 arms no timer even with a live TTL", () => {
    const { sweeper } = makeSweeper({}, { ttlMs: TTL_MS, intervalMs: 0 });
    sweeper.start();
    expect(sweeper.hasTimer()).toBe(false);
  });

  it("the armed timer fires sweepOnce on each interval tick", async () => {
    vi.useFakeTimers();
    const clock = makeClock();
    const reap = vi.fn().mockResolvedValue(undefined);
    const sweeper = new PublicSessionSweeper(
      "test",
      { ttlMs: TTL_MS, intervalMs: INTERVAL_MS },
      { reapSession: reap, now: clock.now },
    );
    sweeper.beginTracking("s");
    clock.advance(TTL_MS + 1); // make "s" idle-eligible
    sweeper.start();

    await vi.advanceTimersByTimeAsync(INTERVAL_MS);
    expect(reap).toHaveBeenCalledTimes(1);
    expect(reap).toHaveBeenCalledWith("s");

    sweeper.stop();
  });
});

describe("PublicSessionSweeper.fromEnv — env parsing", () => {
  const KEYS = ["PUBLIC_SESSION_TTL_SECONDS", "SESSION_SWEEP_INTERVAL_SECONDS"];
  const saved: Record<string, string | undefined> = {};

  function withEnv(vars: Record<string, string | undefined>, fn: () => void) {
    for (const k of KEYS) saved[k] = process.env[k];
    try {
      for (const [k, v] of Object.entries(vars)) {
        if (v === undefined) delete process.env[k];
        else process.env[k] = v;
      }
      fn();
    } finally {
      for (const k of KEYS) {
        if (saved[k] === undefined) delete process.env[k];
        else process.env[k] = saved[k];
      }
    }
  }

  const deps = { reapSession: vi.fn().mockResolvedValue(undefined) };

  it("defaults to 24h TTL / 300s interval when unset", () => {
    withEnv(
      {
        PUBLIC_SESSION_TTL_SECONDS: undefined,
        SESSION_SWEEP_INTERVAL_SECONDS: undefined,
      },
      () => {
        const s = PublicSessionSweeper.fromEnv("test", deps);
        const stats = s.getStats();
        expect(stats.ttlSeconds).toBe(86400);
        expect(stats.intervalSeconds).toBe(300);
        expect(stats.enabled).toBe(true);
      },
    );
  });

  it("honors explicit values", () => {
    withEnv(
      {
        PUBLIC_SESSION_TTL_SECONDS: "3600",
        SESSION_SWEEP_INTERVAL_SECONDS: "120",
      },
      () => {
        const s = PublicSessionSweeper.fromEnv("test", deps);
        expect(s.getStats().ttlSeconds).toBe(3600);
        expect(s.getStats().intervalSeconds).toBe(120);
      },
    );
  });

  it("treats 0 as a valid disable (not a fallback to default)", () => {
    withEnv({ PUBLIC_SESSION_TTL_SECONDS: "0" }, () => {
      const s = PublicSessionSweeper.fromEnv("test", deps);
      expect(s.getStats().ttlSeconds).toBe(0);
      expect(s.isEnabled()).toBe(false);
    });
  });

  it("falls back to the default on a malformed or negative value", () => {
    withEnv({ PUBLIC_SESSION_TTL_SECONDS: "not-a-number" }, () => {
      const s = PublicSessionSweeper.fromEnv("test", deps);
      expect(s.getStats().ttlSeconds).toBe(86400);
    });
    withEnv({ SESSION_SWEEP_INTERVAL_SECONDS: "-5" }, () => {
      const s = PublicSessionSweeper.fromEnv("test", deps);
      expect(s.getStats().intervalSeconds).toBe(300);
    });
  });
});

describe("PublicSessionSweeper — stats surface", () => {
  it("accumulates counters across sweeps", async () => {
    const measure = vi
      .fn()
      .mockReturnValueOnce(4)
      .mockReturnValueOnce(2) // first sweep releases 2
      .mockReturnValueOnce(2)
      .mockReturnValueOnce(1); // second sweep releases 1
    const { sweeper, clock } = makeSweeper({
      measureActiveConnections: measure,
    });

    sweeper.beginTracking("a");
    clock.advance(TTL_MS + 1);
    await sweeper.sweepOnce(); // reaps "a"

    sweeper.beginTracking("b");
    clock.advance(TTL_MS + 1);
    await sweeper.sweepOnce(); // reaps "b"

    const stats = sweeper.getStats();
    expect(stats.totalSweeps).toBe(2);
    expect(stats.totalReaped).toBe(2);
    expect(stats.totalConnectionsReleased).toBe(3);
    expect(stats.lastReapedCount).toBe(1);
    expect(stats.lastSweepAt).not.toBeNull();
  });
});
