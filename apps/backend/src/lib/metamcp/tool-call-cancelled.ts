import { McpError } from "@modelcontextprotocol/sdk/types.js";

/**
 * The typed error a gateway-side tools/call is aborted with when its CONSUMER
 * sends `notifications/cancelled` for it.
 *
 * It keeps the McpError shape on purpose. `isToolCallReplaySafeError` returns
 * false for every McpError shape, so a cancelled call can never be replayed,
 * and the SDK's `cancel()` (shared/protocol.js) passes an McpError reason
 * through unwrapped instead of re-wrapping it as a request timeout.
 *
 * The code is the LSP RequestCancelled number. It is only ever seen in
 * process: the SDK drops the response of an aborted request instead of
 * sending it, so it never reaches a wire.
 *
 * Recognised by `instanceof` only. A backend can answer with any JSON-RPC
 * code, including this one, and that must not read as a consumer cancel.
 */
export const TOOL_CALL_CANCELLED_RPC_CODE = -32800;

/** The `tool_call_audit.error_code` of a cancelled call. */
export const TOOL_CALL_CANCELLED_CODE = "cancelled";

/**
 * The `tool_call_audit.error_detail` of a cancelled call. The cancel and the
 * backend's own answer race, so the backend may have finished the work: a row
 * carrying this detail means "outcome unknown" and is read as possibly
 * executed. (A token shape the audit classifier accepts: lowercase, digits
 * and underscores.)
 */
export const TOOL_CALL_OUTCOME_UNKNOWN_DETAIL = "outcome_unknown";

export class ToolCallCancelledError extends McpError {
  constructor() {
    super(TOOL_CALL_CANCELLED_RPC_CODE, "Tool call cancelled by the caller");
  }
}

export function isToolCallCancelledError(
  error: unknown,
): error is ToolCallCancelledError {
  return error instanceof ToolCallCancelledError;
}
