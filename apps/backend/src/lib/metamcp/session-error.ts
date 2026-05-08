/**
 * Detect errors that indicate the backend MCP server's session registry no
 * longer knows our Mcp-Session-Id. Per the MCP Streamable HTTP spec, the
 * backend SHOULD respond with HTTP 404 when it cannot find the session; most
 * SDKs also surface a JSON-RPC error body with code -32001 or -32600 and
 * message "Session not found".
 *
 * The MCP TypeScript SDK's StreamableHTTPClientTransport wraps this as a
 * generic Error whose message embeds the HTTP status and raw JSON-RPC body,
 * so we match on substrings. Example:
 *
 *   Error POSTing to endpoint (HTTP 404):
 *   {"jsonrpc":"2.0","id":"server-error","error":{"code":-32600,"message":"Session not found"}}
 *
 * Production observation 2026-05-08: in some flows the SDK error reaches us
 * wrapped (e.g. via `.cause` from a higher-layer handler, or stringified
 * after passing through a non-Error rejection). The simple
 * `error.message.includes(...)` check missed all 138 events emitted between
 * a backend container restart and a manual MetaMCP restart, even though the
 * rendered string clearly contained all three matched substrings. To prevent
 * that gap from re-opening on the next backend deploy, this detector now:
 *
 *   1. Walks the `.cause` chain on Error inputs (max depth 8).
 *   2. Falls back to `String(error)` for non-Error throwables (some SDK
 *      paths reject with plain objects, McpError wrappers, or strings).
 *   3. Inspects a numeric/string `.code` field on object inputs (some
 *      RPC layers strip the message but preserve the code).
 *
 * When this fires, the cached backend connection is dead: MetaMCP must drop
 * it, send a new `initialize`, and replay the failed request. The MCP spec
 * states the client MUST start a new session in response to HTTP 404, so
 * this is the normative recovery path, not a workaround.
 */

const SESSION_NOT_FOUND = "Session not found";
const HTTP_404 = "HTTP 404";
const RPC_CODE_PATTERNS = ["-32001", "-32600"];
const MAX_CAUSE_DEPTH = 8;

function stringMatchesSessionLost(value: string): boolean {
  const mentionsSessionNotFound = value.includes(SESSION_NOT_FOUND);
  const mentionsHttp404 = value.includes(HTTP_404);
  const mentionsSessionErrorCode = RPC_CODE_PATTERNS.some((code) =>
    value.includes(code),
  );
  return (
    mentionsSessionNotFound && (mentionsHttp404 || mentionsSessionErrorCode)
  );
}

function objectHasSessionLostCode(candidate: unknown): boolean {
  if (typeof candidate !== "object" || candidate === null) {
    return false;
  }
  const code = (candidate as { code?: unknown }).code;
  if (typeof code === "number") {
    return code === -32001 || code === -32600;
  }
  if (typeof code === "string") {
    return code === "-32001" || code === "-32600";
  }
  return false;
}

export function isBackendSessionLostError(error: unknown): boolean {
  if (error == null) {
    return false;
  }

  // String inputs (some rejection paths surface a bare string).
  if (typeof error === "string") {
    return stringMatchesSessionLost(error);
  }

  // Walk Error.cause chain — match any link in the chain.
  let current: unknown = error;
  let depth = 0;
  while (current != null && depth < MAX_CAUSE_DEPTH) {
    if (current instanceof Error) {
      if (current.message && stringMatchesSessionLost(current.message)) {
        return true;
      }
      if (objectHasSessionLostCode(current)) {
        return true;
      }
      current = (current as { cause?: unknown }).cause;
      depth += 1;
      continue;
    }
    if (typeof current === "object") {
      // Plain object (e.g. JSON-RPC error envelope): inspect message + code.
      const obj = current as { message?: unknown; code?: unknown };
      if (
        typeof obj.message === "string" &&
        stringMatchesSessionLost(obj.message)
      ) {
        return true;
      }
      if (objectHasSessionLostCode(obj)) {
        return true;
      }
      // Last-ditch: render the whole object and substring-match. Catches
      // shapes like `{ jsonrpc, id, error: { code, message } }` where the
      // session-not-found markers live one level deep.
      try {
        const rendered = JSON.stringify(current);
        if (stringMatchesSessionLost(rendered)) {
          return true;
        }
      } catch {
        // Circular structure or non-serializable; ignore.
      }
      break;
    }
    break;
  }

  // Final fallback: stringify the original input. Covers throwables that
  // implement only `toString()` (e.g. some legacy transports emit a
  // class with a meaningful String(...) representation but no message).
  try {
    return stringMatchesSessionLost(String(error));
  } catch {
    return false;
  }
}
