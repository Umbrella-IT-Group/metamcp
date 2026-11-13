import type {
  CallToolRequest,
  CallToolResult,
} from "@modelcontextprotocol/sdk/types.js";

import { DESCRIBE_TOOL, SEARCH_TOOL } from "../lean-listing";
import {
  CallToolMiddleware,
  MetaMCPHandlerContext,
} from "./functional-middleware";

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
  /** Revoked by a catalog invalidation even when the target's name did not change. */
  classifiedTargetIsCurrent?: () => boolean;
}

/**
 * What a `call_tool` call whose target changed after its read-only verdict
 * gets. Constant text that echoes nothing from the request. It does NOT point
 * at `call_write_tool`: the agent has not seen what the name means now, and a
 * tool that changed under its feet is a reason to look again, not to run it
 * through the other door unseen.
 */
export const TARGET_CHANGED_ANSWER = `call_tool did not run this tool: the tool behind this name changed after it was described. Run ${SEARCH_TOOL} or ${DESCRIBE_TOOL} again to see the current tool, then call it by the name you find.`;

/**
 * Fail closed on identity and revoked hints for `call_tool`.
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
 * verdict was given for, and on any difference refuses the call. Nothing runs
 * and nothing is retried. Invalidation also revokes hints already handed to
 * callers: a same-target annotation change leaves the name and UUID unchanged.
 *
 * WHERE. Directly inside `createToolOverridesCallToolMiddleware`, so
 * `request.params.name` is the name that middleware resolved for execution and
 * the check precedes the filter and everything that executes. The audit
 * middleware is outside and records the refusal like any other refused call.
 * Moving this above the overrides middleware would compare the alias, not the
 * tool, and must not be done; the proxy test that rebinds an alias without
 * telling the process pins the order. The router calls this check again,
 * with the selected backend UUID, immediately before every backend send (the
 * first send and any recovery retry). Routing, filtering and timeout settings
 * can await after the early check. A server prefix can also be reused by a new
 * backend, so a matching full name alone does not identify the tool.
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
  const classified = context as ClassifiedCallContext;
  if (
    classified.classifiedTarget !== undefined &&
    (request.params.name !== classified.classifiedTarget ||
      classified.classifiedServerUuid === undefined ||
      classified.classifiedTargetIsCurrent?.() !== true ||
      (resolvedServerUuid !== undefined &&
        resolvedServerUuid !== classified.classifiedServerUuid))
  ) {
    return {
      isError: true,
      content: [{ type: "text", text: TARGET_CHANGED_ANSWER }],
    };
  }
  return undefined;
}

export function createClassifiedTargetMiddleware(
  options: { onRefused?: () => void } = {},
): CallToolMiddleware {
  return (handler) => async (request, context) => {
    const refusal = classifiedTargetRefusal(request, context);
    if (refusal) {
      options.onRefused?.();
      return refusal;
    }
    return handler(request, context);
  };
}
