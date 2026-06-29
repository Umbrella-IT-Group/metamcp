import { metamcpLogStore } from "../log-store";
import { parseToolName } from "../tool-name-parser";
import { CallToolMiddleware } from "./functional-middleware";

/**
 * Auditing middleware — records every proxied `tools/call` to the Live Logs
 * store as a `tool_call` event (tool name, backend server, duration, ok/fail).
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
 */
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
      throw error;
    }
  };
}
