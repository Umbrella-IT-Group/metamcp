import { createHash } from "node:crypto";

import logger from "@/utils/logger";

import { CallerContext, getCallerContext } from "../caller-context-store";
import { metamcpLogStore } from "../log-store";
import { parseToolName } from "../tool-name-parser";
import { isUnknownToolError } from "../unknown-tool";
import {
  ArgsShape,
  argsShapeEnabled,
  buildArgsShape,
} from "./audit-args-shape";
import { CallVerdict, classifyCallResult } from "./audit-classify";
import {
  CallToolMiddleware,
  MetaMCPHandlerContext,
} from "./functional-middleware";
import { getRetiredToolInfo } from "./retired-tool-marker";

/**
 * Auditing middleware — records every proxied `tools/call` to the Live Logs
 * store as a `tool_call` event (tool name, backend server, duration, ok/fail)
 * AND, fire-and-forget, to the `tool_call_audit` Postgres table so "who
 * called what when" is SQL-queryable after the in-memory ring buffer rolls.
 *
 * This is the activity signal the Live Logs view was missing: before this, the
 * only thing written to the store was connection errors, so the view showed
 * nothing but reconnect noise. Each entry is also mirrored to stdout by the
 * store (→ Loki/Grafana, the durable system of record).
 *
 * OUTCOME CLASSIFICATION. `success` and `error_code` come from
 * `classifyCallResult` (audit-classify), which reads the result WITHOUT
 * modifying it: this middleware returns the very same object it received, so
 * the wire is unchanged. A tool's in-band refusal (`{error: true, ...}` with
 * `isError` unset) is recorded as `success=false, error_code='inband_error'`
 * with the tool's code token in `error_detail`; a retired-name redirect as
 * `tool_retired`; a call to a name nobody serves as `unknown_tool`; any other
 * `isError` result as `tool_error`. A classifier fault is logged once and the
 * row is recorded exactly as it was before the classifier existed.
 *
 * Placed OUTERMOST in the call-tool chain so it captures the full outcome —
 * including calls denied by the filter/override middleware (those surface as a
 * `tool_call` error, which is exactly what you want when troubleshooting
 * "why can't this agent call X").
 *
 * DB-write discipline: this module's static graph stays DB-free (unit tests
 * import it without a database) — the repository is loaded lazily on first
 * use. Raw params are NEVER persisted; only a sha256 of the JSON-serialized
 * arguments (params can contain passwords) and the argument SHAPE: top-level
 * key names plus the value of a six-key allowlist of short enumerations
 * (audit-args-shape; the one deliberate exception to "no argument values").
 * An audit-write failure is swallowed and never fails or delays the tool call.
 */

type AuditRecorder = (entry: {
  client_name?: string | null;
  namespace_uuid?: string | null;
  session_id?: string | null;
  server_name: string;
  tool_name: string;
  params_hash?: string | null;
  success: boolean;
  error_code?: string | null;
  latency_ms?: number | null;
  // Caller binding (migration 0030) — see lib/metamcp/caller-context for
  // where each of these is resolved and what it may be trusted to mean.
  api_key_uuid?: string | null;
  auth_method?: string | null;
  user_id?: string | null;
  acts_as_user_id?: string | null;
  caller_ip?: string | null;
  request_id?: string | null;
  // Migration 0039. `args_shape` is computed at entry (never from a result);
  // `error_detail` is filled by the result classifier. NULL = not recorded.
  args_shape?: ArgsShape | null;
  error_detail?: string | null;
}) => Promise<void>;

/**
 * Pick the caller binding for this call, from ONE source.
 *
 * The request-scoped store wins whenever the call is running inside one,
 * because the handler context is per-INSTANCE and instances are pooled: under
 * parallel calls on a single session it describes whichever request stamped
 * it last, and on the Streamable-HTTP in-memory session lookup it is not
 * re-derived from the credential presented on THIS request at all. The
 * handler context remains the fallback for a call that reaches this
 * middleware outside any request scope.
 *
 * ATOMIC, never field-by-field. Coalescing each field independently would let
 * a row take its `api_key_uuid` from the live request and its `request_id`
 * from a stale stamp — a row that looks complete and is false. One source or
 * the other, whole.
 */
function selectCaller(context: MetaMCPHandlerContext): CallerContext {
  return getCallerContext() ?? context;
}

let auditRecorder: AuditRecorder | null | undefined;

async function resolveRecorder(): Promise<AuditRecorder | null> {
  if (auditRecorder !== undefined) return auditRecorder;
  try {
    const { toolCallAuditRepository } = await import(
      "../../../db/repositories/tool-call-audit.repo"
    );
    auditRecorder = (entry) => toolCallAuditRepository.record(entry);
  } catch {
    // No database in this process (unit tests, tooling) — disable for the
    // process lifetime rather than re-attempting the import per call.
    auditRecorder = null;
  }
  return auditRecorder;
}

/** Test seam: override or disable the persistence sink (undefined = re-resolve). */
export function setAuditRecorderForTesting(
  recorder: AuditRecorder | null | undefined,
): void {
  auditRecorder = recorder;
}

function hashParams(args: unknown): string | null {
  if (args === undefined || args === null) return null;
  try {
    return createHash("sha256").update(JSON.stringify(args)).digest("hex");
  } catch {
    return null;
  }
}

/**
 * The argument shape for this call, or null when the kill switch is off or the
 * builder cannot read the arguments. Null is the honest "not recorded"; a
 * builder fault must never reach the tool call, so it is swallowed here.
 */
function shapeOf(args: unknown): ArgsShape | null {
  if (!argsShapeEnabled()) return null;
  try {
    return buildArgsShape(args);
  } catch {
    return null;
  }
}

// The Grafana "MCP errors" panels count any metamcp line matching this as an
// error. The in-band and retired log lines are deliberately worded without
// these words (an in-band refusal is a handled outcome, not a gateway fault),
// so a detail token that happens to BE one of them is not echoed.
const DASHBOARD_ERROR_WORDS = /\b(error|fatal|panic|exception)\b/i;

/**
 * Classify a result without ever throwing. A fault in the classifier must not
 * reach the tool call or change what is recorded: it logs one WARN and the row
 * is written the way it was before the classifier existed (success follows
 * `isError`, class `tool_error`).
 */
function safeVerdict(result: unknown): CallVerdict {
  try {
    return classifyCallResult(result);
  } catch (error) {
    logger.warn(
      `Audit classifier fault; recording the call by isError only: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
    try {
      return (result as { isError?: unknown } | null | undefined)?.isError ===
        true
        ? { failed: true, errorCode: "tool_error" }
        : { failed: false };
    } catch {
      return { failed: false };
    }
  }
}

/** Live Logs level and text for a classified result. */
function describeOutcome(
  toolName: string,
  verdict: CallVerdict,
  durationMs: number,
  result: unknown,
): { level: "info" | "warn" | "error"; message: string } {
  if (!verdict.failed) {
    return { level: "info", message: `${toolName} (${durationMs}ms)` };
  }
  if (verdict.errorCode === "inband_error") {
    const detail =
      verdict.errorDetail && !DASHBOARD_ERROR_WORDS.test(verdict.errorDetail)
        ? verdict.errorDetail
        : "unclassified";
    return {
      level: "warn",
      message: `${toolName} refused in-band: ${detail} (${durationMs}ms)`,
    };
  }
  if (verdict.errorCode === "tool_retired") {
    const replacement = getRetiredToolInfo(result)?.replacement;
    return {
      level: "warn",
      message: replacement
        ? `${toolName} is retired; replacement ${replacement} (${durationMs}ms)`
        : `${toolName} is retired; no replacement (${durationMs}ms)`,
    };
  }
  // isError results (tool_error, unknown_tool) keep the original level and
  // text, so the dashboards that count them behave exactly as before.
  return {
    level: "error",
    message: `${toolName} returned an error (${durationMs}ms)`,
  };
}

function errorCode(error: unknown): string {
  // A thrown "Unknown tool: ..." is the gateway's own answer for a name nobody
  // serves. Record it as the class `unknown_tool` instead of the JS class name
  // `Error`, so unmapped or mistyped tool names are measurable too.
  if (isUnknownToolError(error)) return "unknown_tool";
  if (error && typeof error === "object") {
    const code = (error as { code?: unknown }).code;
    if (typeof code === "number" || typeof code === "string") {
      return String(code);
    }
    if (error instanceof Error) return error.name;
  }
  return "error";
}

function persist(entry: Parameters<AuditRecorder>[0]): void {
  void resolveRecorder()
    .then((recorder) => recorder?.(entry))
    .catch(() => {
      // Best-effort by design: an audit-write failure must never surface
      // into the tool call. Live Logs + stdout already carry the event.
    });
}

export function createAuditingMiddleware(): CallToolMiddleware {
  return (handler) => async (request, context) => {
    const start = performance.now();
    const fullName = request.params.name;
    const parsed = parseToolName(fullName);
    // parseToolName splits "<server>__<tool>"; fall back to the raw name if a
    // call arrives without the gateway prefix.
    const serverName = parsed?.serverName ?? "unknown";
    const toolName = parsed?.originalToolName ?? fullName;
    // Who is calling. Resolved ONCE, at entry, from a single source (see
    // selectCaller) so the success and failure rows below cannot be built from
    // different requests if a parallel call re-stamps the pooled context
    // mid-flight. Undefined on auth-off / passthrough endpoints.
    const source = selectCaller(context);
    const clientName = source.clientName;
    const caller = {
      api_key_uuid: source.apiKeyUuid ?? null,
      auth_method: source.authMethod ?? null,
      user_id: source.userId ?? null,
      acts_as_user_id: source.actsAsUserId ?? null,
      caller_ip: source.callerIp ?? null,
      request_id: source.requestId ?? null,
    };
    const paramsHash = hashParams(request.params.arguments);
    // Computed here, from the arguments as the caller sent them, before any
    // inner middleware (which builds a rewritten request) or the handler runs.
    const argsShape = shapeOf(request.params.arguments);

    try {
      const result = await handler(request, context);
      const durationMs = Math.round(performance.now() - start);
      // An MCP tool failure is a RESULT, not a throw: both a gateway denial
      // from the filter middleware (which answers HTTP 403 upstream) and a
      // backend tool's own error come back as `isError: true` with a normal
      // resolve. Recording those as success=true said "the tool ran" about a
      // call that was refused — the exact rows an investigation would filter
      // OUT while looking for denials. A tool's in-band refusal (isError
      // unset, a structured `error` envelope) is the same story one level
      // down, and the classifier reads it; see audit-classify.
      const verdict = safeVerdict(result);
      const failed = verdict.failed;
      const { level, message } = describeOutcome(
        toolName,
        verdict,
        durationMs,
        result,
      );
      metamcpLogStore.record({
        category: "tool_call",
        serverName,
        level,
        message,
        toolName,
        durationMs,
        clientName,
      });
      persist({
        client_name: clientName ?? null,
        namespace_uuid: context.namespaceUuid ?? null,
        session_id: context.sessionId ?? null,
        server_name: serverName,
        tool_name: toolName,
        params_hash: paramsHash,
        success: !failed,
        // A class from a small fixed vocabulary, never the result's text: the
        // MCP shape carries the reason as human text in `content`, which is not
        // something to put in a column. The class stays queryable and distinct
        // from the protocol-level codes the catch branch records; the tool's
        // own code token (when it gave one) rides `error_detail`.
        error_code: failed ? verdict.errorCode : undefined,
        error_detail: failed ? verdict.errorDetail : undefined,
        latency_ms: durationMs,
        args_shape: argsShape,
        ...caller,
      });
      return result;
    } catch (error) {
      const durationMs = Math.round(performance.now() - start);
      metamcpLogStore.record({
        category: "tool_call",
        serverName,
        level: "error",
        message: `${toolName} failed (${durationMs}ms)`,
        toolName,
        durationMs,
        clientName,
        error,
      });
      persist({
        client_name: clientName ?? null,
        namespace_uuid: context.namespaceUuid ?? null,
        session_id: context.sessionId ?? null,
        server_name: serverName,
        tool_name: toolName,
        params_hash: paramsHash,
        success: false,
        error_code: errorCode(error),
        latency_ms: durationMs,
        args_shape: argsShape,
        ...caller,
      });
      throw error;
    }
  };
}
