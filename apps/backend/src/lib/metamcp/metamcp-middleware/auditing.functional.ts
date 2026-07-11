import { createHash } from "node:crypto";

import { metamcpLogStore } from "../log-store";
import { parseToolName } from "../tool-name-parser";
import { CallToolMiddleware } from "./functional-middleware";

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
 * Placed OUTERMOST in the call-tool chain so it captures the full outcome —
 * including calls denied by the filter/override middleware (those surface as a
 * `tool_call` error, which is exactly what you want when troubleshooting
 * "why can't this agent call X").
 *
 * DB-write discipline: this module's static graph stays DB-free (unit tests
 * import it without a database) — the repository is loaded lazily on first
 * use. Raw params are NEVER persisted; only a sha256 of the JSON-serialized
 * arguments (params can contain passwords). An audit-write failure is
 * swallowed and never fails or delays the tool call.
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
}) => Promise<void>;

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

function errorCode(error: unknown): string {
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
    // Who is calling — stamped onto the handler context by the router layer
    // (Streamable-HTTP sets it on the acquired instance; OpenAPI sets it
    // per-call). Undefined on auth-off / passthrough endpoints.
    const clientName = context.clientName;
    const paramsHash = hashParams(request.params.arguments);

    try {
      const result = await handler(request, context);
      const durationMs = Math.round(performance.now() - start);
      metamcpLogStore.record({
        category: "tool_call",
        serverName,
        level: "info",
        message: `${toolName} (${durationMs}ms)`,
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
        success: true,
        latency_ms: durationMs,
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
      });
      throw error;
    }
  };
}
