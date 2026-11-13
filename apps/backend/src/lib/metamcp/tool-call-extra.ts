import { AsyncLocalStorage } from "node:async_hooks";

import { ErrorCode, McpError } from "@modelcontextprotocol/sdk/types.js";

import { ToolCallCancelledError } from "./tool-call-cancelled";
import type { ProgressRelay } from "./tool-progress-relay";

/**
 * What the SDK hands a request handler (`extra`) and the tools/call chain
 * needs: the consumer's abort signal and a progress relay.
 *
 * WHY AsyncLocalStorage. A MetaMCP server instance is pooled and its handler
 * context is per instance, so per-call data stored there would belong to
 * whichever request wrote it last (see caller-context-store.ts for the same
 * argument and the same precedent). The store is entered once, outside the
 * middleware chain, so no middleware signature changes and a middleware that
 * later re-enters the chain keeps the call's signal and relay.
 */
export interface ToolCallExtra {
  /** The consumer's request signal (`extra.signal`). */
  signal: AbortSignal;
  /**
   * True once the consumer's transport has closed. Read one promise turn after
   * an abort to tell a close apart from an explicit cancel (see
   * linkCallerSignal).
   */
  transportClosed: () => boolean;
  progress?: ProgressRelay;
}

const store = new AsyncLocalStorage<ToolCallExtra>();

export function runWithToolCallExtra<T>(extra: ToolCallExtra, fn: () => T): T {
  return store.run(extra, fn);
}

export function getToolCallExtra(): ToolCallExtra | undefined {
  return store.getStore();
}

/**
 * Registers a backend progress handler that does nothing. The SDK arms a
 * request's `resetTimeoutOnProgress` only through a registered handler (it
 * drops a notification whose token has none before any timeout reset), so a
 * call that has no consumer to relay to still needs one for the reset flag to
 * mean anything.
 */
export const NOOP_PROGRESS = (): void => undefined;

function flagEnabled(name: string, env: NodeJS.ProcessEnv): boolean {
  const raw = (env[name] ?? "true").trim().toLowerCase();
  return !["false", "off", "0"].includes(raw);
}

/**
 * `MCP_TOOL_CALL_PROGRESS=off` (or `false`, `0`): no relay and no registered
 * progress handler, so a backend request is exactly what it was before.
 * Read per call, but a changed env needs a restart to reach the process.
 */
export function progressPassthroughEnabled(
  env: NodeJS.ProcessEnv = process.env,
): boolean {
  return flagEnabled("MCP_TOOL_CALL_PROGRESS", env);
}

/**
 * `MCP_TOOL_CALL_CANCEL=off` (or `false`, `0`): a consumer's cancel does not
 * reach the backend and a total-timeout breach sends it no cancel, as before.
 */
export function cancelPassthroughEnabled(
  env: NodeJS.ProcessEnv = process.env,
): boolean {
  return flagEnabled("MCP_TOOL_CALL_CANCEL", env);
}

/**
 * Aborts `controller` when the consumer EXPLICITLY cancels, never when its
 * transport merely closes. Returns an unlink function.
 *
 * Why the difference matters: cancelling a backend request interrupts a call
 * that may be a write. A dropped connection (the legacy /sse endpoint closes
 * a session's handlers on any stream drop and has no keepalive) is not a
 * decision to stop, and the gateway has always let such a call finish.
 *
 * The SDK aborts a handler's signal for two reasons that cannot be told apart
 * by the signal's reason: `_oncancel` (the consumer's notification) and
 * `_onclose` (shared/protocol.js, which aborts every handler and then, in the
 * same synchronous run, clears the transport). So the decision is deferred by
 * one promise turn and read from the transport state: it is gone after a
 * close and still set after a cancel. `Promise.resolve().then` is used rather
 * than `queueMicrotask` so a test's fake timers cannot interfere.
 *
 * `unlink` must run before the request settles. The SDK registers its abort
 * listener on the backend request signal and never removes it, so aborting
 * after the request finished would still send the backend a cancel for a
 * request that is already done.
 *
 * KNOWN SDK LIMITATION (read in SDK 1.32.0, shared/protocol.js `_oncancel`):
 * a `notifications/cancelled` whose `requestId` is 0 is ignored, because the
 * SDK tests the id for falsiness (`if (!notification.params.requestId)`). So
 * the consumer's signal never aborts for a request with id 0 and this link
 * never fires. A client's first request (`initialize`) takes id 0 in the
 * TypeScript and Python SDKs, so a `tools/call` never carries id 0 from them
 * and their cancels work. Only a client that numbers differently and calls a
 * tool as its id 0 cannot cancel it. No workaround is built into SDK
 * internals; recheck this on the next SDK bump.
 */
export function linkCallerSignal(
  callerSignal: AbortSignal,
  controller: AbortController,
  transportClosed: () => boolean,
): () => void {
  let unlinked = false;

  const abortIfCancelled = (): void => {
    if (unlinked || transportClosed() || controller.signal.aborted) return;
    controller.abort(new ToolCallCancelledError());
  };

  if (callerSignal.aborted) {
    // Linked after the abort (a cancel that arrived while the call was being
    // routed). Nothing deferred is needed: any close has already cleared the
    // transport by the time this code runs.
    abortIfCancelled();
    return () => {
      unlinked = true;
    };
  }

  const onAbort = (): void => {
    void Promise.resolve().then(abortIfCancelled);
  };
  callerSignal.addEventListener("abort", onAbort, { once: true });
  return () => {
    unlinked = true;
    callerSignal.removeEventListener("abort", onAbort);
  };
}

/**
 * The SDK rejects a call that outlives `maxTotalTimeout` (checked when a
 * progress notification arrives) with McpError -32001 and
 * `data.maxTotalTimeout`, and does NOT send the backend a cancel for it: the
 * backend would keep working on a call nobody waits for. Its abort listener on
 * the request signal survives that rejection, so aborting the signal with the
 * SDK's own error makes it send the missing `notifications/cancelled`; its
 * `reject` is a no-op because the promise already settled. The returned error
 * stays the SDK's own, so the timeout hint still annotates it.
 *
 * Pinned by test, so an SDK change to this internal behaviour fails visibly.
 */
export function cancelAfterTotalTimeout(
  error: unknown,
  controller: AbortController,
): void {
  if (!(error instanceof McpError)) return;
  if (error.code !== ErrorCode.RequestTimeout) return;
  const data = error.data as { maxTotalTimeout?: unknown } | undefined;
  if (typeof data?.maxTotalTimeout !== "number") return;
  if (controller.signal.aborted) return;
  controller.abort(error);
}
