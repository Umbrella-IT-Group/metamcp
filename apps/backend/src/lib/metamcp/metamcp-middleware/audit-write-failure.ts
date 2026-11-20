import { describeDbError } from "@/lib/db-error-summary";
import logger from "@/utils/logger";

/**
 * Make a lost `tool_call_audit` row detectable.
 *
 * The audit write is detached from the tool call on purpose (a failed write
 * must never reach the caller), so before this module a failed insert (a
 * schema or migration mismatch, a constraint, a dropped connection) left no
 * trace at all. `tool_call_audit` is the evidence for key sweeps, retired-tool
 * caller counts and incident timelines, so a silent gap in it reads as
 * "nobody called this". The call itself is still in Live Logs and stdout; the
 * failed WRITE was the part nobody could see (#241).
 *
 * Same shape as `lib/gateway-events/sink` `reportGatewayEventDrop`, which is
 * the precedent for a lost history row: a RUNNING TOTAL since startup (a
 * per-window delta is stranded when the burst ends before the next report), a
 * WARN rather than an ERROR (a degraded record is not a failed request, and a
 * history sink that pages on a database blip is one somebody turns off), and
 * one line per window so an outage stays readable.
 *
 * WHAT THE LINE CARRIES: the server and tool names, the number of rows lost,
 * and `describeDbError(error)` (class, SQLSTATE or errno code, constraint,
 * table, column, and any exact allowlisted driver diagnostic). A Drizzle query
 * error's message holds bound values such as the params hash, caller identity
 * and args_shape. The summary keeps those values and the query text out.
 *
 * ponytail: one process-wide throttle window, so the line names only the call
 * that opened the window and the final total of a burst is readable only
 * through `toolCallAuditFailureCount()`; a per-server window or a trailing
 * flush if an operator ever needs the closing number in the log.
 */

/** How long one report attempt suppresses the next. */
const TOOL_CALL_AUDIT_FAILURE_REPORT_INTERVAL_MS = 60 * 1000;

/**
 * Bound the server and tool names from the request before escaping them.
 * An unknown tool name can be arbitrary caller-supplied text.
 */
const NAME_MAX = 128;

let toolCallAuditFailuresTotal = 0;
let nextToolCallAuditFailureReportAt = 0;

/** Test seam: forget the counter and the throttle window. */
export function resetToolCallAuditFailureReportingForTesting(): void {
  toolCallAuditFailuresTotal = 0;
  nextToolCallAuditFailureReportAt = 0;
}

/** Current lost-row count since startup, for assertions and diagnostics. */
export function toolCallAuditFailureCount(): number {
  return toolCallAuditFailuresTotal;
}

/**
 * Replace control characters to keep the warning on one line. Quote names
 * outside the identifier alphabet to keep their text within one field.
 */
function loggableName(value: unknown): string {
  if (typeof value !== "string" || value.length === 0) return "unknown";
  const name = value.slice(0, NAME_MAX).replace(/[^\x20-\x7e]/g, "?");
  return /^[\w.-]+$/.test(name) ? name : JSON.stringify(name);
}

/**
 * Count one lost audit row and, at most once a minute, say so.
 *
 * Never throws and never returns a promise: it runs inside the detached
 * catch of the audit write, where a throw would become an unhandled rejection
 * in the one place that exists to survive a failing database.
 */
export function reportToolCallAuditDrop(
  entry: { server_name?: unknown; tool_name?: unknown },
  error: unknown,
): void {
  toolCallAuditFailuresTotal += 1;
  try {
    // Wall-clock corrections must leave the rate limit intact.
    const now = performance.now();
    if (now < nextToolCallAuditFailureReportAt) return;
    nextToolCallAuditFailureReportAt =
      now + TOOL_CALL_AUDIT_FAILURE_REPORT_INTERVAL_MS;
    logger.warn(
      `[tool-call-audit] write failed, ${toolCallAuditFailuresTotal} audit row(s) lost since startup (tool call unaffected): server=${loggableName(entry.server_name)} tool=${loggableName(entry.tool_name)} cause=${describeDbError(error)}`,
    );
  } catch {
    // The count above is already kept. A logger that throws has no better
    // channel to report itself on, and this must not reject the detached chain.
  }
}
