/**
 * The module-scope cleanup sweep must not own the process's lifetime.
 *
 * `auth-rate-limiter` registers a 10-minute `setInterval` at import time, and
 * this module is on the import chain of the MCP bearer middleware and of
 * `middleware/trpc-rate-limit.middleware`. A timer that is not `unref`'d keeps
 * the event loop alive for anything that merely IMPORTS the module — a test
 * run, a CLI script, a shutdown that is waiting for the loop to drain — and it
 * does so with no visible cause, because a housekeeping sweep is not what
 * anyone looks at when a process refuses to exit. The HTTP server in `index.ts`
 * is what keeps this service running; nothing here should.
 *
 * The global is stubbed rather than the timer inspected because the interval is
 * created during module evaluation and never exported, so import order is the
 * only place to observe it.
 */

import { describe, expect, it, vi } from "vitest";

describe("the cleanup sweep registered at import time", () => {
  it("is unref'd, so importing this module cannot hold the event loop open", async () => {
    const unref = vi.fn();
    // Typed with the arguments it stands in for, so the interval assertion
    // below reads a real parameter rather than an untyped tuple.
    const setIntervalSpy = vi.fn((_handler: () => void, _ms?: number) => ({
      unref,
    }));
    vi.stubGlobal("setInterval", setIntervalSpy);
    vi.resetModules();

    try {
      await import("./auth-rate-limiter");

      // The spy firing at all is what keeps this from passing vacuously if the
      // sweep is ever moved out of module scope.
      expect(setIntervalSpy).toHaveBeenCalledTimes(1);
      expect(setIntervalSpy.mock.calls[0]?.[1]).toBe(10 * 60 * 1000);
      expect(unref).toHaveBeenCalledTimes(1);
    } finally {
      vi.unstubAllGlobals();
      vi.resetModules();
    }
  });
});
