import type {
  CallToolRequest,
  CallToolResult,
} from "@modelcontextprotocol/sdk/types.js";

import { DEFAULT_MCP_MAX_TOTAL_TIMEOUT_MS } from "../../mcp-timeout-defaults";
import {
  CALL_TOOL_CATALOG_UNAVAILABLE_ANSWER,
  DESCRIBE_TOOL,
  SEARCH_TOOL,
} from "../lean-listing";
import {
  cancelPassthroughEnabled,
  getToolCallExtra,
  linkCallerSignal,
} from "../tool-call-extra";
import {
  CallToolMiddleware,
  MetaMCPHandlerContext,
} from "./functional-middleware";

/**
 * What asking a fresh listing about a revoked verdict came to. One shared type
 * for the callback the prelude builds and the decision that consumes it.
 *
 * `current` carries the validity check of the listing that was read, and no
 * other proof exists: `changed` and `unavailable` carry none. The callback
 * only returns data. It never touches a context, so a wait that was cancelled
 * or timed out cannot leave a half-applied result behind.
 */
export type ReverifyResult =
  | { kind: "current"; isCurrent: () => boolean }
  | { kind: "changed" }
  | { kind: "unavailable" };

/**
 * The per-call context of a `call_tool` call (the read-only door of the lean
 * listing). Same pattern as `ToolFilterCallContext`: the proxy hands the chain a
 * CLONE of the instance context with the proof fields added, so nothing is shared
 * between concurrent calls, sessions or pooled instances.
 */
export interface ClassifiedCallContext extends MetaMCPHandlerContext {
  /**
   * The tool the read-only verdict was given for: its original full name
   * (`<server-prefix>__<tool>`), as the lean snapshot listed it. The UUID
   * below identifies the backend even when a replacement reuses its prefix.
   * Set by the lean prelude on a `call_tool` call and on no other call. Absent means no
   * verdict was relied on, and nothing here applies.
   */
  classifiedTarget?: string;
  /** A prefix can be reused by another backend; its UUID cannot. */
  classifiedServerUuid?: string;
  /**
   * False once a catalog invalidation revoked the verdict, even when the
   * target's name did not change. Only a current listing can give the verdict
   * again (`reverifyClassifiedTarget`); this check is replaced, on the call's
   * own clone, by the one that listing carries.
   */
  classifiedTargetIsCurrent?: () => boolean;
  /**
   * Reads a fresh listing and says whether the very tool the verdict was given
   * for still stands as read-only (see `createLeanPrelude`). Set with the
   * other fields, on `call_tool` only, never read from the wire. Without it a
   * revoked verdict is simply refused.
   */
  reverifyClassifiedTarget?: () => Promise<ReverifyResult>;
}

/**
 * What a `call_tool` call whose target changed after its read-only verdict
 * gets. Constant text that echoes nothing from the request. It does NOT point
 * at `call_write_tool`: the agent has not seen what the name means now, and a
 * tool that changed under its feet is a reason to look again, not to run it
 * through the other door unseen.
 */
export const TARGET_CHANGED_ANSWER = `call_tool did not run this tool: the tool behind this name changed after it was described. Run ${SEARCH_TOOL} or ${DESCRIBE_TOOL} again to see the current tool, then call it by the name you find.`;

const refusalWith = (text: string): CallToolResult => ({
  isError: true,
  content: [{ type: "text", text }],
});

/** One check of a verdict, with no await in it. */
type ClassifiedTargetCheck =
  | { kind: "pass" }
  | { kind: "refuse" }
  | { kind: "revoked"; reverify: () => Promise<ReverifyResult> };

/**
 * `revoked` means revocation is the ONLY thing wrong: the resolved name is the
 * recorded one, the recorded UUID is present, the selected backend (when one is
 * known) is the recorded one, and a validity check exists and says no. A
 * verdict with no validity check is incomplete proof, not a revocation, and
 * never earns a re-verification. A revoked verdict with no callback to ask is
 * refused.
 */
function checkClassifiedTarget(
  request: CallToolRequest,
  context: MetaMCPHandlerContext,
  resolvedServerUuid?: string,
): ClassifiedTargetCheck {
  const classified = context as ClassifiedCallContext;
  if (classified.classifiedTarget === undefined) return { kind: "pass" };
  if (
    request.params.name !== classified.classifiedTarget ||
    classified.classifiedServerUuid === undefined ||
    classified.classifiedTargetIsCurrent === undefined ||
    (resolvedServerUuid !== undefined &&
      resolvedServerUuid !== classified.classifiedServerUuid)
  ) {
    return { kind: "refuse" };
  }
  if (classified.classifiedTargetIsCurrent() === true) return { kind: "pass" };
  const reverify = classified.reverifyClassifiedTarget;
  return reverify === undefined
    ? { kind: "refuse" }
    : { kind: "revoked", reverify };
}

/**
 * Fail closed on identity and revoked hints for `call_tool`, synchronously.
 *
 * WHY. `call_tool` is the door a client may open without asking, because the
 * tool it runs is read-only. That verdict is read from the lean snapshot, and
 * the chain then resolves the name to a tool by itself: override alias
 * resolution, which an override change can redirect at any moment (an alias
 * rebound to a writer, an alias that now shadows a real tool's name) while the
 * snapshot, which lives up to a second, still describes the old tool. The
 * policy filter that runs next judges whether the NEW tool may run in this
 * namespace; it never looks at hints. So a verdict about one tool must not be
 * spent on another: this compares the tool the chain resolved with the tool the
 * verdict was given for, and on any difference refuses the call. A catalog
 * invalidation also revokes hints already handed to callers (a same-target
 * annotation change leaves the name and UUID unchanged), and a revoked verdict
 * is refused here too. It is `classifiedTargetDecision` that may give a revoked
 * verdict, and only a revoked one, a single look at a fresh listing first.
 *
 * This function answers the synchronous question and is the last word right
 * before a send: the router runs it with the selected backend UUID in the same
 * synchronous run as the backend request, so nothing can be invalidated
 * between the check and the send.
 *
 * WHO IS CHECKED. Only a call that carries a `classifiedTarget`, which only the
 * prelude sets, only for `call_tool`. `call_write_tool` may run any tool the
 * session may run and relied on no verdict; a direct call is a real-name call.
 * A request cannot carry the field: it is a server-side context field, never
 * read from the wire.
 */
export function classifiedTargetRefusal(
  request: CallToolRequest,
  context: MetaMCPHandlerContext,
  resolvedServerUuid?: string,
): CallToolResult | undefined {
  return checkClassifiedTarget(request, context, resolvedServerUuid).kind ===
    "pass"
    ? undefined
    : refusalWith(TARGET_CHANGED_ANSWER);
}

/**
 * How often a check point may ask for a fresh listing: once per call. The
 * object belongs to one check point of one call, so concurrent calls and the
 * two check points never spend each other's attempt. The router's lives
 * outside `callOnce` and so covers its first send and its replay together.
 */
export interface ReverifyBudget {
  used: boolean;
}

export type ClassifiedRefusalCause = "changed" | "unavailable";

/**
 * What the caller supplies to a decision: what it reports (so the caller owns
 * the wording of its log lines) and where the wait limit is read from.
 */
export interface ClassifiedTargetEnvironment {
  /** The decision refused the call, or the router's final check did. */
  onRefused?: (cause: ClassifiedRefusalCause) => void;
  /** A revoked verdict was given again by a current listing. */
  onReverified?: () => void;
  /** The MCP_MAX_TOTAL_TIMEOUT setting could not be used; the default applies. */
  onTimeoutSettingUnusable?: () => void;
  /** The setting, in milliseconds. Absent: the default limit, with no lookup. */
  maxTotalTimeoutMs?: () => Promise<number>;
}

export interface ClassifiedTargetDecisionOptions
  extends ClassifiedTargetEnvironment {
  /** The backend the router selected for this send; absent at the early check. */
  resolvedServerUuid?: string;
  budget: ReverifyBudget;
}

export type ClassifiedTargetDecision =
  | { refusal: CallToolResult; context?: undefined }
  | { refusal?: undefined; context: MetaMCPHandlerContext };

/** Largest delay a timer holds; a longer one would fire at once. */
const MAX_TIMER_MS = 2_147_483_647;

type Waited = ReverifyResult | { kind: "deadline" };

/**
 * The bounded, cancellable wait for one re-verification.
 *
 * The listing behind the callback is the catalog's shared, single-flight load:
 * its database work, pool acquisition, pages and recovery have no single bound
 * of their own, and `maxTotalTimeout` of the later backend request does not
 * cover a wait that happens before it. So this arms its own deadline first,
 * from MCP_MAX_TOTAL_TIMEOUT (the default until the setting arrives, then the
 * configured value measured from the START of the wait, never restarted), and
 * lets an explicit consumer cancel end the wait at once. Neither aborts the
 * load: it is shared with other callers, and a late result is theirs (this wait
 * has already settled, so it can neither update this call's proof nor resume
 * its send; a late failure reaches the other waiters of the load, and this
 * call has already been answered).
 *
 * The cancel follows the call chain's own rules (`linkCallerSignal`): only an
 * explicit cancel, never a closed transport, and not at all with
 * MCP_TOOL_CALL_CANCEL=off, where only the deadline ends the wait. Timer and
 * listener are disposed on every outcome.
 */
function awaitReverification(
  run: () => Promise<ReverifyResult>,
  options: ClassifiedTargetEnvironment,
): Promise<Waited> {
  return new Promise<Waited>((resolve, reject) => {
    const started = performance.now();
    const cancel = new AbortController();
    let settled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let unlink: (() => void) | undefined;

    const finish = (settle: () => void): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      unlink?.();
      settle();
    };
    const armDeadline = (ms: number): void => {
      clearTimeout(timer);
      timer = setTimeout(
        () => finish(() => resolve({ kind: "deadline" })),
        Math.min(ms, MAX_TIMER_MS),
      );
    };

    // Armed before anything is asked for, so nothing below can hang it.
    armDeadline(DEFAULT_MCP_MAX_TOTAL_TIMEOUT_MS);

    const extra = getToolCallExtra();
    if (extra !== undefined && cancelPassthroughEnabled()) {
      unlink = linkCallerSignal(extra.signal, cancel, extra.transportClosed);
    }
    const rejectCancelled = (): void =>
      finish(() => reject(cancel.signal.reason));
    if (cancel.signal.aborted) {
      // Cancelled before the wait began: the listing is not even asked for.
      rejectCancelled();
      return;
    }
    cancel.signal.addEventListener("abort", rejectCancelled, { once: true });

    let pending: Promise<ReverifyResult>;
    try {
      pending = run();
    } catch (error) {
      finish(() => reject(error));
      return;
    }
    pending.then(
      (result) => finish(() => resolve(result)),
      (error) => finish(() => reject(error)),
    );

    if (options.maxTotalTimeoutMs === undefined) return;
    const unusable = (): void => {
      if (!settled) options.onTimeoutSettingUnusable?.();
    };
    let lookup: Promise<number>;
    try {
      lookup = options.maxTotalTimeoutMs();
    } catch {
      unusable();
      return;
    }
    lookup.then((limit) => {
      if (settled) return;
      if (typeof limit !== "number" || !Number.isFinite(limit) || limit <= 0) {
        unusable();
        return;
      }
      const remaining = limit - (performance.now() - started);
      if (remaining <= 0) finish(() => resolve({ kind: "deadline" }));
      else armDeadline(remaining);
    }, unusable);
  });
}

/**
 * Decide whether a `call_tool` call may go on, looking at a fresh listing ONCE
 * when, and only when, revocation is all that stands in its way.
 *
 * WHY. A backend reconnect drops the catalog snapshot (the reconnected backend
 * may be a redeployed one whose tool now has other annotations under the same
 * name and UUID), which revokes every verdict taken from it. That is right, but
 * refusing without looking turned every reconnect into a spurious "the tool
 * changed" refusal of a read-only call, though nothing had changed. The gateway
 * can look, so it does: the callback re-reads the listing and gives the verdict
 * again only for the same requested name, the same full tool, the same backend
 * UUID and a read-only hint on the FRESH listing, with that listing still
 * current. Nothing is carried over on trust.
 *
 * WHAT. Checks synchronously first. An identity difference or incomplete proof
 * refuses at once and never calls back, even when the verdict is also revoked;
 * a verdict that stands passes with the context as it was. For revocation
 * alone: if this check point's `budget` is spent, refuse; otherwise spend it
 * BEFORE awaiting (so an overlapping entry cannot start another), wait within
 * the bounds of `awaitReverification`, and on `current` build a new context
 * that differs from the old one in the validity check only, and check again.
 * The context the chain was entered with is never changed, and neither is the
 * recorded identity. `changed` refuses with `TARGET_CHANGED_ANSWER`;
 * `unavailable` or the deadline refuse with the constant catalog answer; an
 * explicit cancel throws the typed cancellation, and an unexpected failure of
 * the callback propagates. A refusal sends nothing.
 *
 * The check after the await is not the last word: the decision returns to a
 * caller that may await again (the early middleware passes the call down the
 * chain, the router resumes). The router therefore runs
 * `classifiedTargetRefusal` once more, in its own continuation, in the same
 * synchronous run as the backend request.
 */
export async function classifiedTargetDecision(
  request: CallToolRequest,
  context: MetaMCPHandlerContext,
  options: ClassifiedTargetDecisionOptions,
): Promise<ClassifiedTargetDecision> {
  const refuse = (cause: ClassifiedRefusalCause): ClassifiedTargetDecision => {
    options.onRefused?.(cause);
    return {
      refusal: refusalWith(
        cause === "changed"
          ? TARGET_CHANGED_ANSWER
          : CALL_TOOL_CATALOG_UNAVAILABLE_ANSWER,
      ),
    };
  };
  const check = checkClassifiedTarget(
    request,
    context,
    options.resolvedServerUuid,
  );
  if (check.kind === "pass") return { context };
  if (check.kind === "refuse" || options.budget.used) return refuse("changed");

  options.budget.used = true;
  const waited = await awaitReverification(check.reverify, options);
  if (waited.kind === "unavailable" || waited.kind === "deadline") {
    return refuse("unavailable");
  }
  if (waited.kind === "changed") return refuse("changed");

  const refreshed: ClassifiedCallContext = {
    ...(context as ClassifiedCallContext),
    classifiedTargetIsCurrent: waited.isCurrent,
  };
  if (
    checkClassifiedTarget(request, refreshed, options.resolvedServerUuid)
      .kind !== "pass"
  ) {
    return refuse("changed");
  }
  options.onReverified?.();
  return { context: refreshed };
}

/**
 * The early check point: directly inside `createToolOverridesCallToolMiddleware`,
 * so `request.params.name` is the name that middleware resolved for execution
 * and the check precedes the filter and everything that executes. The audit
 * middleware is outside and records the refusal like any other refused call.
 * Moving this above the overrides middleware would compare the alias, not the
 * tool, and must not be done; the proxy test that rebinds an alias without
 * telling the process pins the order. The router checks again, with the
 * selected backend UUID, immediately before every backend send (the first send
 * and any recovery retry), because routing, filtering and timeout settings can
 * await after this check.
 *
 * A call with no verdict, and a verdict that stands, pass straight to the
 * handler with no await, no listing and no new context. Each call gets its own
 * one re-verification at this check point.
 */
export function createClassifiedTargetMiddleware(
  options: ClassifiedTargetEnvironment = {},
): CallToolMiddleware {
  return (handler) => async (request, context) => {
    if (classifiedTargetRefusal(request, context) === undefined) {
      return handler(request, context);
    }
    const decision = await classifiedTargetDecision(request, context, {
      ...options,
      budget: { used: false },
    });
    if (decision.refusal) return decision.refusal;
    return handler(request, decision.context);
  };
}
