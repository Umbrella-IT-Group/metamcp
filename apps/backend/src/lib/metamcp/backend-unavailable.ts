/**
 * The gateway's answer when a tools/call names a server that IS mounted in
 * the namespace but could not be used for this call.
 *
 * WHY A DISTINCT ERROR. Routing used to answer every miss with
 * `Unknown tool: <name>`, the same text a mistyped name gets. A caller that
 * reads that text concludes the tool does not exist, or that there was no
 * data, and either gives up or retries blindly; in an investigation that is a
 * false all-clear. When the prefix belongs to a mounted server the gateway
 * knows better: the tool may well exist, the backend was just not reachable
 * for this call, and nothing was executed. This error says exactly that, so a
 * caller can tell a transient failure from a typo. `Unknown tool` stays the
 * answer when no mounted server carries the prefix, or when every mounted
 * server under the prefix answered its tool list without the tool, so a
 * caller does not retry a name that will never resolve. A negative listing
 * from one server cannot rule out another mounted server with the same name.
 *
 * The message starts with "Backend", so it never matches the anchored
 * unknown-tool patterns (unknown-tool.ts), and the retired-tool redirect,
 * which only rewrites an unknown-tool failure, leaves it alone. The audit
 * middleware records it under its own class, `backend_unavailable`.
 *
 * The JSON-RPC answer carries code -32603 (the SDK maps a non-integer `code`
 * to InternalError, as it does for the plain `Unknown tool` Error) and this
 * module's `data` object, so a client can branch on `data.code` and
 * `data.retryable` instead of parsing text.
 *
 * PURE and import-free, so the audit middleware's static graph stays DB-free.
 */

/** The audit class and the `data.code` this error carries. */
export const BACKEND_UNAVAILABLE = "backend_unavailable" as const;

/**
 * Why the mounted server could not be used:
 *   - `error_gated`: the server's error gate is set (repeated crashes), so
 *     the pool does not connect to it until the gate is reset.
 *   - `no_session`: the pool returned no session even after the bounded
 *     warm-up (a connect failing or backing off, a connection cap, or a
 *     reconnect or teardown in flight; the pool does not say which).
 *   - `tool_lookup_failed`: a session existed but the server did not answer
 *     the tool list the gateway uses to confirm the tool.
 *   - `routing_lookup_failed`: the gateway could not read the namespace's
 *     servers, so it could not tell an unknown name from an unavailable one,
 *     or its read of the routable servers missed one that is mounted under
 *     the prefix, active and not gated (a failed or racing read).
 */
export type BackendUnavailableReason =
  | "error_gated"
  | "no_session"
  | "tool_lookup_failed"
  | "routing_lookup_failed";

export interface BackendUnavailableData {
  code: typeof BACKEND_UNAVAILABLE;
  server: string;
  tool: string;
  reason: BackendUnavailableReason;
  /** Always false: this error is only raised before the call is sent. */
  executed: false;
  retryable: true;
}

export class BackendUnavailableError extends Error {
  readonly code = BACKEND_UNAVAILABLE;
  readonly data: BackendUnavailableData;

  constructor(
    toolName: string,
    serverName: string,
    reason: BackendUnavailableReason,
  ) {
    // Both names are JSON-quoted: the tool name is caller-controlled (a URL
    // path segment on the OpenAPI bridge), and this text reaches log lines.
    super(
      `Backend ${JSON.stringify(serverName)} is unavailable (${reason}): tool ${JSON.stringify(toolName)} was not run. Retry the call.`,
    );
    this.name = "BackendUnavailableError";
    this.data = {
      code: BACKEND_UNAVAILABLE,
      server: serverName,
      tool: toolName,
      reason,
      executed: false,
      retryable: true,
    };
  }
}

/** True for this module's error, including a copy from another module graph. */
export function isBackendUnavailableError(
  error: unknown,
): error is BackendUnavailableError {
  if (error instanceof BackendUnavailableError) return true;
  if (error === null || typeof error !== "object") return false;
  try {
    return (error as { code?: unknown }).code === BACKEND_UNAVAILABLE;
  } catch {
    // An opaque value with a throwing accessor is not this error.
    return false;
  }
}
