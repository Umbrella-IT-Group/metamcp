import { createHash } from "node:crypto";

import logger from "@/utils/logger";

import { isPerUserBrokerError } from "../../m365/errors";
import {
  BACKEND_UNAVAILABLE,
  isBackendUnavailableError,
} from "../backend-unavailable";
import { CallerContext, getCallerContext } from "../caller-context-store";
import { metamcpLogStore } from "../log-store";
import type { ToolArgSchema } from "../tool-arg-keys";
import { parseToolName } from "../tool-name-parser";
import { isUnknownToolError } from "../unknown-tool";
import {
  ArgsShape,
  argsShapeEnabled,
  buildArgsShape,
  snapshotArgsForShape,
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
 *
 * DEFERRED SHAPE. When the routing instance has no schema for the called name
 * and can list (`resolveMissingSchema`), the row is written after the call
 * settles AND that instance's own listing settles (at most
 * AUDIT_SCHEMA_WAIT_MS), from a snapshot of the arguments taken at entry. The
 * call itself runs and answers exactly as before; only the fire-and-forget row
 * waits. A listing that fails, times out or is skipped leaves the count-only
 * shape computed at entry. Such a row carries `called_at` from the moment the
 * call settled, so the wait does not move it.
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
  // Set only on a deferred-shape row (see DEFERRED SHAPE above); otherwise the
  // column default (insert time, right after the call) applies as before.
  called_at?: Date;
}) => Promise<void>;

/** Resolves a missing schema from the routing instance's own listing. */
export type MissingSchemaResolver = (
  name: string,
) => Promise<ToolArgSchema | undefined> | undefined;

/**
 * Longest a row waits for the routing instance's listing. The listing goes on
 * and serves later calls; this row keeps the count-only shape.
 */
export const AUDIT_SCHEMA_WAIT_MS = 15_000;

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
function shapeOf(
  toolName: string,
  args: unknown,
  schemaForTool?: (name: string) => ToolArgSchema | undefined,
): ArgsShape | null {
  if (!argsShapeEnabled()) return null;
  try {
    return buildArgsShape(args, schemaForTool?.(toolName));
  } catch {
    // Never echo the fault: a getter can put argument values in its message.
    logger.warn(
      "Audit argument shape fault; recording the call without args_shape",
    );
    return null;
  }
}

interface DeferredShape {
  /** What `buildArgsShape` reads, captured at entry (snapshotArgsForShape). */
  snapshot: unknown;
  /** The entry shape (counts only), recorded when no schema arrives. */
  fallback: ArgsShape;
}

/**
 * The entry snapshot to shape once the routing instance has listed, or
 * undefined when the entry shape is final: the kill switch is off, the schema
 * was known, the path cannot list, or a schema would not change the shape (no
 * keys, or not an object). `unverified_keys` is set exactly in the remaining
 * case. Never throws.
 */
function deferShape(
  args: unknown,
  entryShape: ArgsShape | null,
  canResolve: boolean,
): DeferredShape | undefined {
  if (!canResolve || entryShape?.unverified_keys === undefined) {
    return undefined;
  }
  try {
    return { snapshot: snapshotArgsForShape(args), fallback: entryShape };
  } catch {
    // Only a getter that throws on a second read gets here (shapeOf already
    // read the arguments once). The count-only entry shape stands.
    return undefined;
  }
}

/** `promise`'s value, or undefined once `ms` pass or it rejects. */
function within<T>(promise: Promise<T>, ms: number): Promise<T | undefined> {
  return new Promise((resolve) => {
    const timer = setTimeout(() => resolve(undefined), ms);
    timer.unref?.();
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      () => {
        clearTimeout(timer);
        resolve(undefined);
      },
    );
  });
}

/**
 * The shape for a deferred row. Checks the instance's registry again first (a
 * client listing can land while the call runs), then waits a bounded time for
 * the instance's own listing. Never rejects: any fault keeps the fallback.
 */
async function settleDeferredShape(
  toolName: string,
  deferred: DeferredShape,
  schemaForTool: ((name: string) => ToolArgSchema | undefined) | undefined,
  resolveMissingSchema: MissingSchemaResolver,
): Promise<ArgsShape> {
  try {
    let schema = schemaForTool?.(toolName);
    if (!schema) {
      const pending = resolveMissingSchema(toolName);
      if (!pending) return deferred.fallback;
      schema = await within(pending, AUDIT_SCHEMA_WAIT_MS);
    }
    return schema
      ? buildArgsShape(deferred.snapshot, schema)
      : deferred.fallback;
  } catch {
    // Same discipline as shapeOf: never echo the fault.
    logger.warn(
      "Audit argument shape fault after the call; recording the call with the count-only args_shape",
    );
    return deferred.fallback;
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
  // A mounted server that could not be used: the tool was not run. Its own
  // class, so a transient routing failure is never counted as a missing tool.
  if (isBackendUnavailableError(error)) return BACKEND_UNAVAILABLE;
  if (error && typeof error === "object") {
    const code = (error as { code?: unknown }).code;
    if (typeof code === "number" || typeof code === "string") {
      return String(code);
    }
    if (error instanceof Error) return error.name;
  }
  return "error";
}

function persist(
  entry: Parameters<AuditRecorder>[0],
  settleShape?: () => Promise<ArgsShape>,
): void {
  // Taken now, as the call settles, so a row that waits for a listing keeps
  // the time it would have had.
  const calledAt = settleShape ? new Date() : undefined;
  void resolveRecorder()
    .then(async (recorder) => {
      // No sink, no listing: the deferred lookup runs only for a row that
      // will be written.
      if (!recorder) return;
      if (!settleShape) return recorder(entry);
      return recorder({
        ...entry,
        args_shape: await settleShape(),
        called_at: calledAt,
      });
    })
    .catch(() => {
      // Best-effort by design: an audit-write failure must never surface
      // into the tool call. Live Logs + stdout already carry the event.
    });
}

/**
 * `schemaForTool` reads the routing instance's recorded schemas.
 * `resolveMissingSchema`, when given, obtains a missing one from that
 * instance's own listing after the call (see DEFERRED SHAPE above).
 */
export function createAuditingMiddleware(
  schemaForTool?: (name: string) => ToolArgSchema | undefined,
  resolveMissingSchema?: MissingSchemaResolver,
): CallToolMiddleware {
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
    // Only the routing instance's own published listing can verify these names.
    // Without a recorded schema this is the count-only shape; a path that can
    // list shapes the entry snapshot again once it has (DEFERRED SHAPE).
    const argsShape = shapeOf(
      fullName,
      request.params.arguments,
      schemaForTool,
    );
    const deferred = deferShape(
      request.params.arguments,
      argsShape,
      resolveMissingSchema !== undefined,
    );
    const settleShape =
      deferred && resolveMissingSchema
        ? () =>
            settleDeferredShape(
              fullName,
              deferred,
              schemaForTool,
              resolveMissingSchema,
            )
        : undefined;

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
      persist(
        {
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
        },
        settleShape,
      );
      return result;
    } catch (error) {
      const durationMs = Math.round(performance.now() - start);
      // A caller whose own Microsoft 365 enrollment is missing, expired,
      // revoked or MFA-gated gets the enroll-URL result from the proxy one
      // level up; that is an expected user state, not a tool fault, so it is
      // a WARN without a stack here. The audit row below still records the
      // call as failed with the broker code. Operator-actionable broker
      // errors (not_configured, mint_failed) and everything else stay ERROR.
      const enrollmentRefusal = isPerUserBrokerError(error);
      metamcpLogStore.record({
        category: "tool_call",
        serverName,
        level: enrollmentRefusal ? "warn" : "error",
        message: enrollmentRefusal
          ? `${toolName} refused: the caller's Microsoft 365 enrollment is needed (${errorCode(error)}, ${durationMs}ms)`
          : `${toolName} failed (${durationMs}ms)`,
        toolName,
        durationMs,
        clientName,
        ...(enrollmentRefusal ? {} : { error }),
      });
      persist(
        {
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
        },
        settleShape,
      );
      throw error;
    }
  };
}
