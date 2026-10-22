/**
 * The shared probe loop behind the tools/list re-notify (one loop per
 * backend, any number of owed sessions). Driven with fake timers.
 *
 * What it pins:
 *   - nothing is told until the probe says the backend lists again, and
 *     then every watcher of that backend is told exactly once;
 *   - the probe backs off and caps, and a connect event probes at once;
 *   - a cancelled watch is never told, and the loop stops when nobody is
 *     owed;
 *   - a probe that throws counts as "not yet", a watcher that throws cannot
 *     stop its siblings, and a connect landing mid-probe re-probes;
 *   - the kill switch reads the documented values.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@/utils/logger", () => ({
  default: { error: vi.fn(), warn: vi.fn(), info: vi.fn(), debug: vi.fn() },
}));

import {
  DEFAULT_RENOTIFY_PROBE_DELAYS_MS,
  toolsListRenotifyEnabled,
  ToolsListRenotifyWatch,
} from "./tools-list-renotify";

const DELAYS = [100, 200, 400];

describe("ToolsListRenotifyWatch", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it("tells every watcher once, only after the probe answers", async () => {
    const watch = new ToolsListRenotifyWatch({ delaysMs: DELAYS });
    let up = false;
    const probe = vi.fn(async () => up);
    const a = vi.fn();
    const b = vi.fn();
    watch.watch("srv", probe, a);
    watch.watch("srv", probe, b);

    await vi.advanceTimersByTimeAsync(100);
    expect(probe).toHaveBeenCalledTimes(1);
    expect(a).not.toHaveBeenCalled();

    up = true;
    await vi.advanceTimersByTimeAsync(200);
    expect(probe).toHaveBeenCalledTimes(2);
    expect(a).toHaveBeenCalledTimes(1);
    expect(b).toHaveBeenCalledTimes(1);
    expect(watch.watchedServerCount()).toBe(0);

    // Nothing left to probe or tell.
    await vi.advanceTimersByTimeAsync(10_000);
    expect(probe).toHaveBeenCalledTimes(2);
    expect(a).toHaveBeenCalledTimes(1);
  });

  it("backs off and caps at the last delay", async () => {
    const watch = new ToolsListRenotifyWatch({ delaysMs: DELAYS });
    const probe = vi.fn(async () => false);
    watch.watch("srv", probe, vi.fn());

    await vi.advanceTimersByTimeAsync(99);
    expect(probe).toHaveBeenCalledTimes(0);
    await vi.advanceTimersByTimeAsync(1); // t=100
    expect(probe).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(200); // t=300
    expect(probe).toHaveBeenCalledTimes(2);
    await vi.advanceTimersByTimeAsync(400); // t=700
    expect(probe).toHaveBeenCalledTimes(3);
    await vi.advanceTimersByTimeAsync(400); // t=1100, capped at 400
    expect(probe).toHaveBeenCalledTimes(4);
    await vi.advanceTimersByTimeAsync(399);
    expect(probe).toHaveBeenCalledTimes(4);
    await vi.advanceTimersByTimeAsync(1);
    expect(probe).toHaveBeenCalledTimes(5);
  });

  it("starts further along the backoff when asked", async () => {
    const watch = new ToolsListRenotifyWatch({ delaysMs: DELAYS });
    const probe = vi.fn(async () => false);
    watch.watch("srv", probe, vi.fn(), 2);
    await vi.advanceTimersByTimeAsync(399);
    expect(probe).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1);
    expect(probe).toHaveBeenCalledTimes(1);
  });

  it("probes at once when the pool connects to that backend", async () => {
    const watch = new ToolsListRenotifyWatch({ delaysMs: [60_000] });
    const probe = vi.fn(async () => true);
    const told = vi.fn();
    watch.watch("srv", probe, told);

    watch.notifyConnected("other"); // nobody owed for this one
    watch.notifyConnected("srv");
    await vi.advanceTimersByTimeAsync(0);
    expect(probe).toHaveBeenCalledTimes(1);
    expect(told).toHaveBeenCalledTimes(1);
  });

  it("re-probes when a connect lands while a probe is in flight", async () => {
    const watch = new ToolsListRenotifyWatch({ delaysMs: [100, 60_000] });
    let release!: (value: boolean) => void;
    const probe = vi
      .fn<() => Promise<boolean>>()
      .mockImplementationOnce(
        () => new Promise<boolean>((resolve) => (release = resolve)),
      )
      .mockResolvedValue(true);
    const told = vi.fn();
    watch.watch("srv", probe, told);

    await vi.advanceTimersByTimeAsync(100);
    expect(probe).toHaveBeenCalledTimes(1);
    watch.notifyConnected("srv"); // mid-probe
    release(false);
    await vi.advanceTimersByTimeAsync(0);
    expect(probe).toHaveBeenCalledTimes(2);
    expect(told).toHaveBeenCalledTimes(1);
  });

  it("backs off when each probe connects but fails to list", async () => {
    const watch = new ToolsListRenotifyWatch({ delaysMs: DELAYS });
    const probe = vi.fn(async () => {
      // probeServerTools can create an idle connection, which calls
      // markServerSuccess before its tools/list fails on a flapping backend.
      watch.notifyConnected("srv");
      return false;
    });
    const told = vi.fn();
    const cancel = watch.watch("srv", probe, told);

    try {
      await vi.advanceTimersByTimeAsync(110);
      expect(probe).toHaveBeenCalledTimes(2);
      await vi.advanceTimersByTimeAsync(190);
      expect(probe).toHaveBeenCalledTimes(2);
      await vi.advanceTimersByTimeAsync(10);
      expect(probe).toHaveBeenCalledTimes(4);
      await vi.advanceTimersByTimeAsync(390);
      expect(probe).toHaveBeenCalledTimes(4);
      expect(told).not.toHaveBeenCalled();
    } finally {
      cancel();
    }
  });

  it("never tells a cancelled watcher, and stops when nobody is owed", async () => {
    const watch = new ToolsListRenotifyWatch({ delaysMs: DELAYS });
    let up = false;
    const probe = vi.fn(async () => up);
    const kept = vi.fn();
    const cancelled = vi.fn();
    watch.watch("srv", probe, kept);
    const cancel = watch.watch("srv", probe, cancelled);
    cancel();
    cancel(); // idempotent

    up = true;
    await vi.advanceTimersByTimeAsync(100);
    expect(kept).toHaveBeenCalledTimes(1);
    expect(cancelled).not.toHaveBeenCalled();

    const lonely = vi.fn();
    const probe2 = vi.fn(async () => true);
    const cancel2 = watch.watch("srv2", probe2, lonely);
    cancel2();
    expect(watch.watchedServerCount()).toBe(0);
    await vi.advanceTimersByTimeAsync(10_000);
    expect(probe2).not.toHaveBeenCalled();
    expect(lonely).not.toHaveBeenCalled();
  });

  it("drops a probe result that lands after its watch was cancelled", async () => {
    const watch = new ToolsListRenotifyWatch({ delaysMs: DELAYS });
    let release!: (value: boolean) => void;
    const probe = vi.fn(
      () => new Promise<boolean>((resolve) => (release = resolve)),
    );
    const told = vi.fn();
    const cancel = watch.watch("srv", probe, told);
    await vi.advanceTimersByTimeAsync(100);
    cancel();
    release(true);
    await vi.advanceTimersByTimeAsync(0);
    expect(told).not.toHaveBeenCalled();
    expect(watch.watchedServerCount()).toBe(0);
  });

  it("treats a throwing probe as not answering and keeps going", async () => {
    const watch = new ToolsListRenotifyWatch({ delaysMs: DELAYS });
    const probe = vi
      .fn<() => Promise<boolean>>()
      .mockRejectedValueOnce(new Error("boom"))
      .mockResolvedValue(true);
    const told = vi.fn();
    watch.watch("srv", probe, told);
    await vi.advanceTimersByTimeAsync(100);
    expect(told).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(200);
    expect(told).toHaveBeenCalledTimes(1);
  });

  it("a throwing watcher cannot stop its siblings", async () => {
    const watch = new ToolsListRenotifyWatch({ delaysMs: DELAYS });
    const probe = vi.fn(async () => true);
    const bad = vi.fn(() => {
      throw new Error("bad watcher");
    });
    const good = vi.fn();
    watch.watch("srv", probe, bad);
    watch.watch("srv", probe, good);
    await vi.advanceTimersByTimeAsync(100);
    expect(bad).toHaveBeenCalledTimes(1);
    expect(good).toHaveBeenCalledTimes(1);
  });

  it("refuses an empty or negative delay schedule", () => {
    expect(() => new ToolsListRenotifyWatch({ delaysMs: [] })).toThrow();
    expect(() => new ToolsListRenotifyWatch({ delaysMs: [1, -1] })).toThrow();
    expect(DEFAULT_RENOTIFY_PROBE_DELAYS_MS[0]).toBe(2_000);
    expect(DEFAULT_RENOTIFY_PROBE_DELAYS_MS.at(-1)).toBe(60_000);
  });
});

describe("toolsListRenotifyEnabled", () => {
  it("is on by default and off only for false, off or 0", () => {
    expect(toolsListRenotifyEnabled({})).toBe(true);
    expect(toolsListRenotifyEnabled({ MCP_TOOLS_LIST_RENOTIFY: "true" })).toBe(
      true,
    );
    for (const off of ["false", "FALSE", " off ", "0"]) {
      expect(toolsListRenotifyEnabled({ MCP_TOOLS_LIST_RENOTIFY: off })).toBe(
        false,
      );
    }
  });
});
