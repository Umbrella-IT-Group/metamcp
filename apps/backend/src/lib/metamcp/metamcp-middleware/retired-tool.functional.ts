import { CallToolResult } from "@modelcontextprotocol/sdk/types.js";

import logger from "@/utils/logger";

import {
  getRetiredEntry,
  renderEnvelope,
  RetiredEntry,
} from "../retired-tools";
import { isUnknownToolError, looksLikeUnknownTool } from "../unknown-tool";
import { CallToolMiddleware } from "./functional-middleware";
import { markRetiredToolResult } from "./retired-tool-marker";

/**
 * Retired-tool redirect: a call to a retired tool name answers with what
 * replaced it instead of a bare "Unknown tool".
 *
 * THE PRINCIPLE, and why it is built this way. The map may only change the
 * outcome of a call that has ALREADY failed as an unknown tool. This middleware
 * runs the rest of the chain first and looks at the map only afterwards, on the
 * two failure shapes below. It never consults the map before routing, so:
 *
 *   - a map entry can never shadow a live tool (a wrong, stale, too-early or
 *     re-introduced entry degrades to today's bare error rather than making a
 *     working tool unreachable for an automation that depends on it);
 *   - a call that succeeds, and every failure that is not an unknown-tool
 *     failure, passes through untouched, with ZERO map lookups and no I/O.
 *
 * THE TWO FAILURE SHAPES it rewrites (a retired name fails three different ways
 * today, and one middleware outside the filter has to cover all three):
 *   1. A THROWN error whose message is the gateway's own `Unknown tool: ...`
 *      (no route for the name). Everything else that throws is rethrown as the
 *      SAME error object: timeouts, broker errors, "Not connected" and the
 *      rest are never rewritten, which also preserves the rule that a timed-out
 *      tools/call is never re-sent.
 *   2. A RETURNED isError result whose first text block says no such tool: a
 *      backend answering for a name the gateway still routes to it, or the
 *      filter's fail-closed denial for a server prefix that no longer resolves
 *      (a deleted server).
 *
 * THE REDIRECT executes nothing and forwards nothing. It is not an alias: the
 * old name still does not answer, it only says what to call instead. The result
 * carries NO structuredContent on purpose: the SDK client validates
 * structuredContent against a cached output schema even for an error result, so
 * a retired tool's cached schema would turn this message into a validation
 * failure. It is registered in a process-local WeakMap so the audit middleware
 * can record it as `tool_retired` (and a backend cannot spoof that with text).
 *
 * Placed second in the chain, outside the filter, so it also sees the filter's
 * denial; the audit middleware stays outermost and records the redirect.
 */

type RetiredLookup = (name: string) => Promise<RetiredEntry | null>;

function buildRedirect(name: string, entry: RetiredEntry): CallToolResult {
  const envelope = renderEnvelope(name, entry);
  const result: CallToolResult = {
    isError: true,
    content: [{ type: "text", text: JSON.stringify(envelope) }],
  };
  return markRetiredToolResult(result, { replacement: entry.replacement });
}

/** True when a returned result is an isError "no such tool" answer. */
function isUnknownToolResult(result: unknown, expectedName: string): boolean {
  try {
    if (result === null || typeof result !== "object") return false;
    const candidate = result as { isError?: unknown; content?: unknown };
    if (candidate.isError !== true) return false;
    if (!Array.isArray(candidate.content) || candidate.content.length === 0) {
      return false;
    }
    const first: unknown = candidate.content[0];
    if (first === null || typeof first !== "object") return false;
    const block = first as { type?: unknown; text?: unknown };
    return (
      block.type === "text" && looksLikeUnknownTool(block.text, expectedName)
    );
  } catch {
    // A result that cannot be read is not rewritten.
    return false;
  }
}

export function createRetiredToolMiddleware(
  options: { lookup?: RetiredLookup } = {},
): CallToolMiddleware {
  const lookup = options.lookup ?? getRetiredEntry;

  // Never throws: a fault in the lookup means "no redirect", i.e. today's answer.
  const redirectFor = async (name: string): Promise<CallToolResult | null> => {
    try {
      const entry = await lookup(name);
      return entry ? buildRedirect(name, entry) : null;
    } catch (cause) {
      logger.warn(
        `[retired-tools] lookup failed, answering as before: ${
          cause instanceof Error ? cause.message : String(cause)
        }`,
      );
      return null;
    }
  };

  return (handler) => async (request, context) => {
    let result: CallToolResult;
    try {
      result = await handler(request, context);
    } catch (error) {
      if (isUnknownToolError(error, request.params.name)) {
        const redirect = await redirectFor(request.params.name);
        if (redirect) return redirect;
      }
      // The SAME error object, untouched.
      throw error;
    }

    if (isUnknownToolResult(result, request.params.name)) {
      const redirect = await redirectFor(request.params.name);
      if (redirect) return redirect;
    }
    return result;
  };
}
