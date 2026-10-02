import { ErrorCode, McpError } from "@modelcontextprotocol/sdk/types.js";

import { CallToolMiddleware } from "./functional-middleware";

/**
 * Adjudication hint on the gateway's own tools/call timeout.
 *
 * WHAT HAPPENS. When a backend tool call outlives the gateway's request timeout
 * (`MCP_TIMEOUT`, 60 s in production) the MCP SDK rejects with
 * `McpError(-32001, "Request timed out")`. That is the GATEWAY giving up waiting.
 * The SDK client also sends the backend a `notifications/cancelled` for the
 * request (protocol.js `cancel()`, the same function the timeout handler calls),
 * and a Python SDK backend acts on it by cancelling the handler. Whether that
 * cancel arrived before, during or after the work is not knowable here, so the
 * call's outcome is UNKNOWN: a write may have been applied, been cancelled
 * midway and be half applied, or still be finishing. The client only sees
 * "Request timed out", which reads as "it did not happen", so an agent retries,
 * and a retried write can run twice (the gateway itself never re-sends a
 * timed-out tools/call).
 *
 * The hint states only what is known (the gateway stopped waiting and asked the
 * backend to cancel, the outcome is unknown) and never claims the call was or
 * was not cancelled. An earlier wording said "it did not cancel the call"; that
 * was false, and it was being copied into the skills and the tool design spec.
 *
 * WHAT THIS CHANGES: text only. The same error code (-32001), the same `data`,
 * and the original message kept as its first sentence, with added text saying
 * the outcome is unknown and that a caller of a tool that changes anything
 * should read the target's state before retrying. Clients
 * that branch on the code, or match "Request timed out", behave exactly as
 * before. Nothing about routing, retry or what the backend sees changes.
 *
 * WHAT IT MATCHES, narrowly. Only the SDK's two locally raised timeouts:
 * "Request timed out" (carrying `data.timeout`) and "Maximum total timeout
 * exceeded" (carrying `data.maxTotalTimeout`). The code -32001 is overloaded: a
 * backend answering an unknown session id also uses it, with no such data and a
 * different message, and that answer must never be described as a timeout.
 *
 * It sits innermost, directly around the routing handler, so the audit
 * middleware (outermost) still records the same numeric code, and an error that
 * was already replay-safe-classified inside the handler is not touched.
 */

const TIMEOUT_MESSAGE =
  /^(?:MCP error -32001: )?(Request timed out|Maximum total timeout exceeded)$/;

interface TimeoutShape {
  base: string;
  seconds: number | null;
  data: unknown;
}

/** The SDK's locally raised timeout, or null for anything else. */
function asGatewayTimeout(error: unknown): TimeoutShape | null {
  if (!(error instanceof Error) || error.name !== "McpError") return null;
  const { code, data } = error as { code?: unknown; data?: unknown };
  if (code !== ErrorCode.RequestTimeout) return null;
  const match = TIMEOUT_MESSAGE.exec(error.message);
  if (!match) return null;

  const record =
    data !== null && typeof data === "object"
      ? (data as { timeout?: unknown; maxTotalTimeout?: unknown })
      : {};
  const ms =
    typeof record.timeout === "number"
      ? record.timeout
      : typeof record.maxTotalTimeout === "number"
        ? record.maxTotalTimeout
        : null;
  // A backend's own -32001 carries neither field; only the SDK's local timeout
  // does. Without one of them this is not the gateway's timeout.
  if (ms === null) return null;
  return { base: match[1], seconds: Math.round(ms / 1000), data };
}

export function gatewayTimeoutHint(seconds: number | null): string {
  const waited =
    seconds !== null && seconds > 0
      ? `The gateway stopped waiting after ${seconds} s`
      : "The gateway stopped waiting";
  return (
    `${waited} and asked the backend to cancel, but the outcome is unknown: ` +
    "the call may have been applied, partly applied, or still be finishing. " +
    "If this tool changes anything, read the target's current state before retrying: " +
    "a repeat call can apply the change twice. A read-only call is safe to retry."
  );
}

/** Rewrite a gateway timeout with the hint, or return the error unchanged. */
export function annotateGatewayTimeout(error: unknown): unknown {
  const shape = asGatewayTimeout(error);
  if (!shape) return error;
  return new McpError(
    ErrorCode.RequestTimeout,
    `${shape.base}. ${gatewayTimeoutHint(shape.seconds)}`,
    shape.data,
  );
}

export function createTimeoutHintMiddleware(): CallToolMiddleware {
  return (handler) => async (request, context) => {
    try {
      return await handler(request, context);
    } catch (error) {
      throw annotateGatewayTimeout(error);
    }
  };
}
