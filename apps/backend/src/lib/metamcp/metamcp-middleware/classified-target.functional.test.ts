/**
 * The identity check of `call_tool`, alone: it compares the name the overrides
 * middleware resolved with the tool the read-only verdict was given for, and
 * only for a call that carries a verdict.
 */
import { getEventListeners } from "node:events";

import type {
  CallToolRequest,
  CallToolResult,
} from "@modelcontextprotocol/sdk/types.js";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { DEFAULT_MCP_MAX_TOTAL_TIMEOUT_MS } from "../../mcp-timeout-defaults";
import { CALL_TOOL_CATALOG_UNAVAILABLE_ANSWER } from "../lean-listing";
import { ToolCallCancelledError } from "../tool-call-cancelled";
import { runWithToolCallExtra } from "../tool-call-extra";
import {
  type ClassifiedCallContext,
  classifiedTargetDecision,
  classifiedTargetRefusal,
  createClassifiedTargetMiddleware,
  type ReverifyBudget,
  type ReverifyResult,
  TARGET_CHANGED_ANSWER,
} from "./classified-target.functional";

const request = (name: string): CallToolRequest => ({
  method: "tools/call",
  params: { name, arguments: { id: "1" } },
});

const OK: CallToolResult = { content: [{ type: "text", text: "ran" }] };

function run(
  name: string,
  context: Partial<ClassifiedCallContext>,
  onRefused?: () => void,
) {
  const handler = vi.fn(async () => OK);
  const wrapped = createClassifiedTargetMiddleware({ onRefused })(handler);
  const full: ClassifiedCallContext = {
    namespaceUuid: "ns",
    sessionId: "s",
    classifiedServerUuid: "desk-id",
    classifiedTargetIsCurrent: () => true,
    ...context,
  };
  return { handler, result: wrapped(request(name), full), full };
}

describe("createClassifiedTargetMiddleware", () => {
  it("lets a call through whose resolved name is the tool the verdict was given for, with the request and context untouched", async () => {
    const { handler, result, full } = run("desk__legacy", {
      classifiedTarget: "desk__legacy",
    });
    expect(await result).toBe(OK);
    expect(handler).toHaveBeenCalledTimes(1);
    const [seenRequest, seenContext] = handler.mock.calls[0] as unknown as [
      CallToolRequest,
      unknown,
    ];
    expect(seenRequest.params.name).toBe("desk__legacy");
    expect(seenContext).toBe(full);
  });

  it("refuses a call whose resolved name is any other tool, runs nothing, and says the tool changed", async () => {
    const onRefused = vi.fn();
    for (const resolved of [
      "desk__write",
      "desk__legacy ",
      "DESK__LEGACY",
      "other__legacy",
      "desk__modern",
    ]) {
      const { handler, result } = run(
        resolved,
        { classifiedTarget: "desk__legacy" },
        onRefused,
      );
      expect(await result, resolved).toEqual({
        isError: true,
        content: [{ type: "text", text: TARGET_CHANGED_ANSWER }],
      });
      expect(handler, resolved).not.toHaveBeenCalled();
    }
    expect(onRefused).toHaveBeenCalledTimes(5);
  });

  it("refuses with constant text that names the two ways to look again and echoes nothing, and does not point at call_write_tool", () => {
    expect(TARGET_CHANGED_ANSWER).toContain("changed");
    expect(TARGET_CHANGED_ANSWER).toContain("search_tools");
    expect(TARGET_CHANGED_ANSWER).toContain("describe_tool");
    expect(TARGET_CHANGED_ANSWER).not.toContain("call_write_tool");
    expect(TARGET_CHANGED_ANSWER).not.toContain("__");
  });

  it("does nothing for a call that carries no verdict: call_write_tool and a direct call run whatever name resolved", async () => {
    const onRefused = vi.fn();
    for (const name of ["desk__legacy", "desk__write", "anything"]) {
      const { handler, result } = run(name, {}, onRefused);
      expect(await result).toBe(OK);
      expect(handler).toHaveBeenCalledTimes(1);
    }
    expect(onRefused).not.toHaveBeenCalled();
  });

  it("treats an empty-string target as a verdict, never as no verdict", async () => {
    const { handler, result } = run("desk__write", { classifiedTarget: "" });
    expect((await result).isError).toBe(true);
    expect(handler).not.toHaveBeenCalled();
  });

  it("refuses revoked or incomplete hints even when the resolved name is unchanged", async () => {
    for (const context of [
      { classifiedTargetIsCurrent: () => false },
      { classifiedTargetIsCurrent: undefined },
      { classifiedServerUuid: undefined },
    ]) {
      const { handler, result } = run("desk__legacy", {
        classifiedTarget: "desk__legacy",
        ...context,
      });
      expect((await result).isError).toBe(true);
      expect(handler).not.toHaveBeenCalled();
    }
  });

  it("checks the actual backend UUID at dispatch even if its prefix and tool name stayed the same", () => {
    const context = {
      namespaceUuid: "ns",
      sessionId: "s",
      classifiedTarget: "desk__legacy",
      classifiedServerUuid: "original-id",
      classifiedTargetIsCurrent: () => true,
    };
    expect(
      classifiedTargetRefusal(request("desk__legacy"), context, "original-id"),
    ).toBeUndefined();
    expect(
      classifiedTargetRefusal(
        request("desk__legacy"),
        context,
        "replacement-id",
      )?.isError,
    ).toBe(true);
  });

  it("keeps two calls' verdicts apart: each is judged against its own context", async () => {
    const first = run("desk__a", { classifiedTarget: "desk__a" });
    const second = run("desk__a", { classifiedTarget: "desk__b" });
    expect(await first.result).toBe(OK);
    expect((await second.result).isError).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// A verdict revoked by a catalog invalidation is re-verified once.
//
// Cases marked "guard" pass on the parent by design: they hold the refusals
// that must stay refusals. Every other case in this section is new behaviour.
// The callback here is a stub that returns a chosen result: it proves what the
// check does with each result. What the REAL callback compares (hints, alias
// identity, backend UUID) is proven against the real prelude in
// lean-prelude.test.ts.
// ---------------------------------------------------------------------------

const REVOKED = () => false;
const STILL_CURRENT = () => true;
const DEFAULT_WAIT_MS = DEFAULT_MCP_MAX_TOTAL_TIMEOUT_MS;

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

const current = (isCurrent: () => boolean = STILL_CURRENT): ReverifyResult => ({
  kind: "current",
  isCurrent,
});

/** A revoked verdict at the early check, with every hook observable. */
function revoked(
  reverify: (() => Promise<ReverifyResult>) | undefined,
  context: Partial<ClassifiedCallContext> = {},
  options: {
    maxTotalTimeoutMs?: () => Promise<number>;
    name?: string;
  } = {},
) {
  const handler = vi.fn(async () => OK);
  const hooks = {
    onRefused: vi.fn(),
    onReverified: vi.fn(),
    onTimeoutSettingUnusable: vi.fn(),
  };
  const wrapped = createClassifiedTargetMiddleware({
    ...hooks,
    ...(options.maxTotalTimeoutMs
      ? { maxTotalTimeoutMs: options.maxTotalTimeoutMs }
      : {}),
  })(handler);
  const full: ClassifiedCallContext = {
    namespaceUuid: "ns",
    sessionId: "s",
    classifiedTarget: "desk__legacy",
    classifiedServerUuid: "desk-id",
    classifiedTargetIsCurrent: REVOKED,
    ...(reverify ? { reverifyClassifiedTarget: reverify } : {}),
    ...context,
  };
  return {
    handler,
    hooks,
    context: full,
    run: () => wrapped(request(options.name ?? "desk__legacy"), full),
  };
}

const UNAVAILABLE = {
  isError: true,
  content: [{ type: "text", text: CALL_TOOL_CATALOG_UNAVAILABLE_ANSWER }],
};
const CHANGED = {
  isError: true,
  content: [{ type: "text", text: TARGET_CHANGED_ANSWER }],
};

describe("a revoked verdict at the early check", () => {
  it("is re-verified once and the call runs with the fresh validity check, the recorded name and UUID unchanged, and the instance's context untouched", async () => {
    const fresh = () => true;
    const reverify = vi.fn(async () => current(fresh));
    const { handler, hooks, context, run } = revoked(reverify);
    expect(await run()).toBe(OK);
    expect(reverify).toHaveBeenCalledTimes(1);
    expect(handler).toHaveBeenCalledTimes(1);
    const [seenRequest, seen] = handler.mock.calls[0] as unknown as [
      CallToolRequest,
      ClassifiedCallContext,
    ];
    expect(seenRequest.params.name).toBe("desk__legacy");
    expect(seen.classifiedTargetIsCurrent).toBe(fresh);
    expect(seen.classifiedTarget).toBe("desk__legacy");
    expect(seen.classifiedServerUuid).toBe("desk-id");
    // A new object carries the refreshed check: the context the chain was
    // entered with keeps the verdict it came in with.
    expect(seen).not.toBe(context);
    expect(context.classifiedTargetIsCurrent).toBe(REVOKED);
    expect(hooks.onReverified).toHaveBeenCalledTimes(1);
    expect(hooks.onRefused).not.toHaveBeenCalled();
  });

  it.each([
    ["changed", { kind: "changed" } as const, CHANGED],
    ["unavailable", { kind: "unavailable" } as const, UNAVAILABLE],
  ])(
    "is refused when the listing says %s, with its own constant answer, and sends nothing",
    async (cause, result, answer) => {
      const reverify = vi.fn(async () => result);
      const { handler, hooks, run } = revoked(reverify);
      expect(await run()).toEqual(answer);
      expect(reverify).toHaveBeenCalledTimes(1);
      expect(handler).not.toHaveBeenCalled();
      expect(hooks.onRefused).toHaveBeenCalledWith(cause);
      expect(hooks.onReverified).not.toHaveBeenCalled();
    },
  );

  it("keeps the two refusal answers apart: only the unavailable one offers call_write_tool, since there the tool was not looked at", () => {
    expect(CALL_TOOL_CATALOG_UNAVAILABLE_ANSWER).not.toBe(
      TARGET_CHANGED_ANSWER,
    );
    expect(TARGET_CHANGED_ANSWER).not.toContain("call_write_tool");
  });

  it.each([
    ["a closure that says revoked again", () => current(() => false)],
    [
      "no validity check at all",
      () => ({ kind: "current", isCurrent: undefined }) as never,
    ],
  ])(
    "is refused when the fresh listing comes back with %s at the decision, after one callback",
    async (_label, result) => {
      const reverify = vi.fn(async () => result());
      const { handler, hooks, run } = revoked(reverify);
      expect(await run()).toEqual(CHANGED);
      expect(reverify).toHaveBeenCalledTimes(1);
      expect(handler).not.toHaveBeenCalled();
      expect(hooks.onRefused).toHaveBeenCalledWith("changed");
    },
  );

  it("lets an unexpected failure of the re-verification propagate, sends nothing, and reports no refusal", async () => {
    const boom = new Error("boom");
    const { handler, hooks, run } = revoked(async () => {
      throw boom;
    });
    await expect(run()).rejects.toBe(boom);
    expect(handler).not.toHaveBeenCalled();
    expect(hooks.onRefused).not.toHaveBeenCalled();
  });

  it("guard: refuses a revoked verdict that has no callback, as before", async () => {
    const { handler, run } = revoked(undefined);
    expect(await run()).toEqual(CHANGED);
    expect(handler).not.toHaveBeenCalled();
  });

  it("guard: an unrevoked verdict without a callback passes with the very same context", async () => {
    const { handler, context, run } = revoked(undefined, {
      classifiedTargetIsCurrent: STILL_CURRENT,
    });
    expect(await run()).toBe(OK);
    expect((handler.mock.calls[0] as unknown[])[1]).toBe(context);
  });

  it("guard: a verdict that still stands never starts a re-verification and never awaits before the handler", () => {
    const reverify = vi.fn(async () => current());
    const { handler, run } = revoked(reverify, {
      classifiedTargetIsCurrent: STILL_CURRENT,
    });
    const pending = run();
    // Synchronously: no listing, no callback, and no await in front of it.
    expect(handler).toHaveBeenCalledTimes(1);
    expect(reverify).not.toHaveBeenCalled();
    return pending;
  });

  it.each([
    ["the resolved name differs", { name: "desk__write" }, {}],
    ["the recorded UUID is missing", {}, { classifiedServerUuid: undefined }],
    [
      "the validity check is missing",
      {},
      { classifiedTargetIsCurrent: undefined },
    ],
  ])(
    "guard: is refused without a re-verification when %s, whether or not it was also revoked",
    async (_label, options, context) => {
      for (const isCurrent of [REVOKED, STILL_CURRENT]) {
        const reverify = vi.fn(async () => current());
        const { handler, run } = revoked(
          reverify,
          { classifiedTargetIsCurrent: isCurrent, ...context },
          options,
        );
        expect(await run()).toEqual(CHANGED);
        expect(reverify).not.toHaveBeenCalled();
        expect(handler).not.toHaveBeenCalled();
      }
    },
  );

  it("guard: a call that carries no verdict touches no closure and runs as before", async () => {
    const reverify = vi.fn(async () => current());
    const isCurrent = vi.fn(() => false);
    const { handler, context, run } = revoked(reverify, {
      classifiedTarget: undefined,
      classifiedTargetIsCurrent: isCurrent,
    });
    expect(await run()).toBe(OK);
    expect(reverify).not.toHaveBeenCalled();
    expect(isCurrent).not.toHaveBeenCalled();
    expect((handler.mock.calls[0] as unknown[])[1]).toBe(context);
  });
});

describe("classifiedTargetDecision: one re-verification per check point", () => {
  const decide = (
    context: ClassifiedCallContext,
    options: {
      budget: ReverifyBudget;
      resolvedServerUuid?: string;
    },
  ) => classifiedTargetDecision(request("desk__legacy"), context, options);

  const verdict = (
    reverify: () => Promise<ReverifyResult>,
    isCurrent: () => boolean = REVOKED,
  ): ClassifiedCallContext => ({
    namespaceUuid: "ns",
    sessionId: "s",
    classifiedTarget: "desk__legacy",
    classifiedServerUuid: "desk-id",
    classifiedTargetIsCurrent: isCurrent,
    reverifyClassifiedTarget: reverify,
  });

  it("refuses a second revocation at a check point that already used its attempt, without another callback", async () => {
    let live = true;
    const reverify = vi.fn(async () => current(() => live));
    const budget: ReverifyBudget = { used: false };
    const first = await decide(verdict(reverify), { budget });
    expect(first.refusal).toBeUndefined();
    expect(budget.used).toBe(true);
    live = false;
    const second = await decide(first.context as ClassifiedCallContext, {
      budget,
    });
    expect(second.refusal).toEqual(CHANGED);
    expect(reverify).toHaveBeenCalledTimes(1);
  });

  it("gives each check point its own attempt", async () => {
    const reverify = vi.fn(async () => current());
    const early = { used: false };
    const router = { used: false };
    await decide(verdict(reverify), { budget: early });
    await decide(verdict(reverify), { budget: router });
    expect(reverify).toHaveBeenCalledTimes(2);
    expect(early.used && router.used).toBe(true);
  });

  it("consumes the attempt before it awaits, so an overlapping entry at the same check point cannot start a second", async () => {
    const gate = deferred<ReverifyResult>();
    const reverify = vi.fn(() => gate.promise);
    const budget: ReverifyBudget = { used: false };
    const first = decide(verdict(reverify), { budget });
    expect(budget.used).toBe(true);
    const overlapping = await decide(verdict(reverify), { budget });
    expect(overlapping.refusal).toEqual(CHANGED);
    expect(reverify).toHaveBeenCalledTimes(1);
    gate.resolve(current());
    expect((await first).refusal).toBeUndefined();
  });

  it("guard: refuses a selected backend that is not the recorded one without a callback, revoked or not", async () => {
    for (const isCurrent of [REVOKED, STILL_CURRENT]) {
      const reverify = vi.fn(async () => current());
      const budget = { used: false };
      const decision = await decide(verdict(reverify, isCurrent), {
        budget,
        resolvedServerUuid: "replacement-id",
      });
      expect(decision.refusal).toEqual(CHANGED);
      expect(reverify).not.toHaveBeenCalled();
      expect(budget.used).toBe(false);
    }
  });

  it("checks the fresh closure against the selected backend too: a matching selection proceeds", async () => {
    const reverify = vi.fn(async () => current());
    const decision = await decide(verdict(reverify), {
      budget: { used: false },
      resolvedServerUuid: "desk-id",
    });
    expect(decision.refusal).toBeUndefined();
    expect(
      (decision.context as ClassifiedCallContext).classifiedTargetIsCurrent,
    ).toBe(STILL_CURRENT);
  });
});

describe("the wait for a re-verification is bounded", () => {
  const cancelEnv = process.env.MCP_TOOL_CALL_CANCEL;

  beforeEach(() => {
    vi.useFakeTimers();
    delete process.env.MCP_TOOL_CALL_CANCEL;
  });
  afterEach(() => {
    vi.useRealTimers();
    if (cancelEnv === undefined) delete process.env.MCP_TOOL_CALL_CANCEL;
    else process.env.MCP_TOOL_CALL_CANCEL = cancelEnv;
  });

  /** Runs the early check inside the store a real call has. */
  function inCall(
    run: () => Promise<CallToolResult>,
    options: { closed?: () => boolean; signal?: AbortSignal } = {},
  ) {
    const controller = new AbortController();
    const signal = options.signal ?? controller.signal;
    const outcome = runWithToolCallExtra(
      { signal, transportClosed: options.closed ?? (() => false) },
      run,
    );
    const state = { settled: false };
    void outcome.then(
      () => {
        state.settled = true;
      },
      () => {
        state.settled = true;
      },
    );
    return { controller, signal, outcome, state };
  }

  it("answers unavailable at the default limit when neither the listing nor the setting ever answers, and disposes its timer", async () => {
    const listing = deferred<ReverifyResult>();
    const setting = deferred<number>();
    const { handler, hooks, run } = revoked(() => listing.promise, undefined, {
      maxTotalTimeoutMs: () => setting.promise,
    });
    const { outcome, state } = inCall(run);
    await vi.advanceTimersByTimeAsync(DEFAULT_WAIT_MS - 1);
    expect(state.settled).toBe(false);
    await vi.advanceTimersByTimeAsync(1);
    expect(await outcome).toEqual(UNAVAILABLE);
    expect(hooks.onRefused).toHaveBeenCalledWith("unavailable");
    expect(vi.getTimerCount()).toBe(0);
    // A late answer cannot resume the call or make a noise of its own.
    listing.resolve(current());
    setting.resolve(1);
    await vi.advanceTimersByTimeAsync(0);
    expect(handler).not.toHaveBeenCalled();
    expect(hooks.onTimeoutSettingUnusable).not.toHaveBeenCalled();
  });

  it("measures a configured limit from the start of the wait, not from when the setting arrived", async () => {
    const listing = deferred<ReverifyResult>();
    const setting = deferred<number>();
    const { run } = revoked(() => listing.promise, undefined, {
      maxTotalTimeoutMs: () => setting.promise,
    });
    const { outcome, state } = inCall(run);
    await vi.advanceTimersByTimeAsync(400);
    setting.resolve(1_000);
    await vi.advanceTimersByTimeAsync(599);
    expect(state.settled).toBe(false);
    await vi.advanceTimersByTimeAsync(1);
    expect(await outcome).toEqual(UNAVAILABLE);
  });

  it("uses a configured limit longer than the default, up to that limit", async () => {
    const listing = deferred<ReverifyResult>();
    const { run } = revoked(() => listing.promise, undefined, {
      maxTotalTimeoutMs: async () => DEFAULT_WAIT_MS * 2,
    });
    const { outcome, state } = inCall(run);
    await vi.advanceTimersByTimeAsync(DEFAULT_WAIT_MS * 2 - 1);
    expect(state.settled).toBe(false);
    await vi.advanceTimersByTimeAsync(1);
    expect(await outcome).toEqual(UNAVAILABLE);
  });

  it("clamps a limit beyond what a timer can hold instead of firing at once", async () => {
    const listing = deferred<ReverifyResult>();
    const { run } = revoked(() => listing.promise, undefined, {
      maxTotalTimeoutMs: async () => Number.MAX_SAFE_INTEGER,
    });
    const { outcome, state } = inCall(run);
    await vi.advanceTimersByTimeAsync(DEFAULT_WAIT_MS * 3);
    expect(state.settled).toBe(false);
    await vi.advanceTimersByTimeAsync(2_147_483_647);
    expect(await outcome).toEqual(UNAVAILABLE);
  });

  it.each([0, -5, Number.NaN, Number.POSITIVE_INFINITY, "soon"])(
    "keeps the default limit and says so once when the setting is %s",
    async (bad) => {
      const listing = deferred<ReverifyResult>();
      const { hooks, run } = revoked(() => listing.promise, undefined, {
        maxTotalTimeoutMs: async () => bad as number,
      });
      const { outcome, state } = inCall(run);
      await vi.advanceTimersByTimeAsync(DEFAULT_WAIT_MS - 1);
      expect(state.settled).toBe(false);
      expect(hooks.onTimeoutSettingUnusable).toHaveBeenCalledTimes(1);
      await vi.advanceTimersByTimeAsync(1);
      expect(await outcome).toEqual(UNAVAILABLE);
      expect(hooks.onTimeoutSettingUnusable).toHaveBeenCalledTimes(1);
    },
  );

  it("keeps the default limit and says so once when the setting cannot be read", async () => {
    const listing = deferred<ReverifyResult>();
    const { hooks, run } = revoked(() => listing.promise, undefined, {
      maxTotalTimeoutMs: async () => {
        throw new Error("the settings table is unreachable");
      },
    });
    const { outcome } = inCall(run);
    await vi.advanceTimersByTimeAsync(DEFAULT_WAIT_MS);
    expect(await outcome).toEqual(UNAVAILABLE);
    expect(hooks.onTimeoutSettingUnusable).toHaveBeenCalledTimes(1);
  });

  it("does not touch the setting when the listing answers first, and leaves no timer behind", async () => {
    const setting = vi.fn(() => new Promise<number>(() => undefined));
    const { handler, hooks, run } = revoked(async () => current(), undefined, {
      maxTotalTimeoutMs: setting,
    });
    const { outcome } = inCall(run);
    expect(await outcome).toBe(OK);
    expect(handler).toHaveBeenCalledTimes(1);
    expect(vi.getTimerCount()).toBe(0);
    expect(hooks.onTimeoutSettingUnusable).not.toHaveBeenCalled();
  });

  it("settles on an explicit cancel while the listing is held, with the typed cancellation, and a late answer cannot resume it", async () => {
    const listing = deferred<ReverifyResult>();
    const { handler, hooks, run } = revoked(() => listing.promise);
    const { controller, signal, outcome } = inCall(run);
    expect(getEventListeners(signal, "abort").length).toBeGreaterThan(0);
    controller.abort();
    await expect(outcome).rejects.toBeInstanceOf(ToolCallCancelledError);
    expect(hooks.onRefused).not.toHaveBeenCalled();
    // Timer and listener are gone, and the shared load is not ours to abort.
    expect(vi.getTimerCount()).toBe(0);
    expect(getEventListeners(signal, "abort")).toHaveLength(0);
    listing.resolve(current());
    await vi.advanceTimersByTimeAsync(0);
    expect(handler).not.toHaveBeenCalled();
  });

  it("does not turn a listing that fails after the call was cancelled into a second failure", async () => {
    const listing = deferred<ReverifyResult>();
    const { run } = revoked(() => listing.promise);
    const { controller, outcome } = inCall(run);
    controller.abort();
    await expect(outcome).rejects.toBeInstanceOf(ToolCallCancelledError);
    // An unhandled rejection here would fail the whole run.
    listing.reject(new Error("the shared load failed for someone else too"));
    await vi.advanceTimersByTimeAsync(0);
  });

  it("settles at once when the consumer had already cancelled, before the listing is asked for", async () => {
    const reverify = vi.fn(async () => current());
    const { handler, run } = revoked(reverify);
    const cancelled = new AbortController();
    cancelled.abort();
    const { outcome } = inCall(run, { signal: cancelled.signal });
    await expect(outcome).rejects.toBeInstanceOf(ToolCallCancelledError);
    expect(reverify).not.toHaveBeenCalled();
    expect(handler).not.toHaveBeenCalled();
  });

  it("does not treat a closed transport as a cancel: the wait goes on and the call runs when the listing answers", async () => {
    const listing = deferred<ReverifyResult>();
    const { handler, run } = revoked(() => listing.promise);
    const { controller, outcome, state } = inCall(run, { closed: () => true });
    controller.abort();
    await vi.advanceTimersByTimeAsync(10);
    expect(state.settled).toBe(false);
    listing.resolve(current());
    expect(await outcome).toBe(OK);
    expect(handler).toHaveBeenCalledTimes(1);
  });

  it("with MCP_TOOL_CALL_CANCEL=off a cancel does not end the wait, and the deadline still does", async () => {
    process.env.MCP_TOOL_CALL_CANCEL = "off";
    const listing = deferred<ReverifyResult>();
    const { handler, run } = revoked(() => listing.promise);
    const { controller, signal, outcome, state } = inCall(run);
    expect(getEventListeners(signal, "abort")).toHaveLength(0);
    controller.abort();
    await vi.advanceTimersByTimeAsync(DEFAULT_WAIT_MS - 1);
    expect(state.settled).toBe(false);
    await vi.advanceTimersByTimeAsync(1);
    expect(await outcome).toEqual(UNAVAILABLE);
    expect(handler).not.toHaveBeenCalled();
  });

  it("waits only by its deadline when the call has no consumer signal at all", async () => {
    const listing = deferred<ReverifyResult>();
    const { run } = revoked(() => listing.promise);
    const outcome = run();
    await vi.advanceTimersByTimeAsync(DEFAULT_WAIT_MS);
    expect(await outcome).toEqual(UNAVAILABLE);
  });

  it("disposes its timer and listener when the listing answers", async () => {
    const { run } = revoked(async () => current());
    const { signal, outcome } = inCall(run);
    expect(await outcome).toBe(OK);
    expect(vi.getTimerCount()).toBe(0);
    expect(getEventListeners(signal, "abort")).toHaveLength(0);
  });
});
