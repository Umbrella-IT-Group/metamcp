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
 * Production observation: in some flows the SDK error reaches us
 * wrapped (e.g. via `.cause` from a higher-layer handler, or stringified
 * after passing through a non-Error rejection). The simple
 * `error.message.includes(...)` check missed every event emitted between
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
 *
 * Replay is for idempotent requests only. `tools/call` does not use this
 * detector to decide a replay; it uses the stricter
 * {@link isToolCallReplaySafeError} below, because a tool call can have side
 * effects and replaying one the backend already ran executes it twice.
 *
 * The -32001 code is overloaded. Backends answering an unknown
 * Mcp-Session-Id use it, and the MCP TypeScript SDK also uses it as
 * `ErrorCode.RequestTimeout`: every gateway-side request timeout rejects
 * with `McpError(-32001, "Request timed out")`, and an abort or a
 * `maxTotalTimeout` breach carries the same code. So the code is only ever a
 * confirming signal next to "Session not found", never a marker on its own.
 * Treating a bare -32001 as session-lost classed every 60 s timeout as a lost
 * session, and the tools/call path then re-sent the call, so a delete on a
 * client machine ran twice (found 2026-09-30).
 */

const SESSION_NOT_FOUND = "Session not found";
const HTTP_404 = "HTTP 404";
const RPC_CODE_PATTERNS = ["-32001", "-32600"];
const MAX_CAUSE_DEPTH = 8;

// Transport-disconnect signal raised by the MCP TypeScript SDK's Protocol
// class when a request is dispatched on a transport that has already been
// torn down. Produced verbatim ("Not connected") whenever the cached
// ConnectedClient's underlying StreamableHTTPClientTransport has been
// closed — either because the backend MCP container restarted (Watchtower
// image pull, manual `docker restart`, OOM kill) or because the SDK's
// session manager half-closed the stream after an idle / error condition.
//
// Distinct from "Session not found": the session-not-found path means the
// backend rejected the request because its session registry doesn't know
// our Mcp-Session-Id (recoverable by sending a new `initialize`). The
// "Not connected" path means our local transport has no live stream to
// send anything on (recoverable by invalidating the pool entry, opening
// a fresh transport, and re-initializing). Both end up at the same
// recovery action — invalidate + reconnect + retry — but the error
// envelopes are textually disjoint, so they need separate detectors.
const NOT_CONNECTED = "Not connected";
// JSON-RPC code -32603 = "Internal error". MetaMCP's tRPC bridge wraps
// the SDK-thrown "Not connected" rejection into this envelope before it
// reaches the consumer (Claude.ai connector, n8n httpRequest node, etc.).
// Production observation: consumer-side connectors see
// `-32603 "Not connected"` rather than the raw SDK Error, and the
// session-lost detector misses it. Pair the code with the
// "Not connected" message so we don't false-positive on every -32603
// from unrelated internal-error paths.
const RPC_CODE_TRANSPORT_LOST = "-32603";

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
  const { code, message } = candidate as { code?: unknown; message?: unknown };
  const hasSessionErrorCode =
    typeof code === "number"
      ? code === -32001 || code === -32600
      : typeof code === "string"
        ? code === "-32001" || code === "-32600"
        : false;
  // The code confirms a session loss only when the same object names it.
  // A bare -32001 is the SDK's RequestTimeout (see the header comment), and
  // a bare -32600 is JSON-RPC "Invalid Request"; neither means the backend
  // forgot our session.
  return (
    hasSessionErrorCode &&
    typeof message === "string" &&
    message.includes(SESSION_NOT_FOUND)
  );
}

function stringMatchesTransportLost(value: string): boolean {
  // The "Not connected" substring is the load-bearing marker; the
  // -32603 code is only a confirming signal when present in a JSON-RPC
  // envelope. A bare "Not connected" message from the SDK is sufficient.
  return value.includes(NOT_CONNECTED);
}

function objectHasTransportLostCode(candidate: unknown): boolean {
  // Only match -32603 when the rendered/structured object also carries
  // the "Not connected" marker — bare -32603 is JSON-RPC "Internal
  // error" and covers many unrelated failure modes.
  if (typeof candidate !== "object" || candidate === null) {
    return false;
  }
  const obj = candidate as { code?: unknown; message?: unknown };
  const code = obj.code;
  const isTransportCode =
    code === -32603 ||
    code === "-32603" ||
    (typeof code === "string" && code.includes(RPC_CODE_TRANSPORT_LOST));
  if (!isTransportCode) {
    return false;
  }
  if (
    typeof obj.message === "string" &&
    stringMatchesTransportLost(obj.message)
  ) {
    return true;
  }
  try {
    return stringMatchesTransportLost(JSON.stringify(candidate));
  } catch {
    return false;
  }
}

/**
 * Detect errors that indicate the cached backend client's transport is dead.
 *
 * Sibling of {@link isBackendSessionLostError}. The session-lost detector
 * matches the backend's "I don't know your Mcp-Session-Id" response (HTTP
 * 404 + JSON-RPC -32001/-32600 + "Session not found"). The transport-lost
 * detector matches the SDK's local "I have no live stream to send on"
 * rejection, surfaced as a bare `"Not connected"` Error from
 * `Protocol.request()` and also as a `-32603 "Not connected"` JSON-RPC
 * envelope on the consumer-facing side.
 *
 * When this fires, the recovery action is identical to the session-lost
 * path: invalidate the pooled `ConnectedClient`, open a fresh transport,
 * re-initialize, and replay the request once. The two detectors are kept
 * separate (rather than collapsed into one OR-of-substrings function) so
 * each has a tight predicate that doesn't false-positive on the much
 * larger noise floor of unrelated -32603 / 404 errors.
 *
 * Production observation: a rapid-deploy cadence on a backend MCP server
 * (image pulls + container restarts inside a few minutes) produced
 * disconnect windows where the consumer-side connector saw
 * `-32603 "Not connected"` on every call. The session-lost detector
 * missed all of these; the recovery path in `metamcp-proxy.ts` never
 * fired — so a routine backend redeploy left the gateway needing a manual
 * reboot, which is not an acceptable operating cost. This detector + the
 * matching recovery wiring in `metamcp-proxy.ts` close that gap.
 */
export function isBackendTransportLostError(error: unknown): boolean {
  if (error == null) {
    return false;
  }

  if (typeof error === "string") {
    return stringMatchesTransportLost(error);
  }

  let current: unknown = error;
  let depth = 0;
  const seen = new Set<unknown>();
  while (current != null && depth < MAX_CAUSE_DEPTH) {
    if (seen.has(current)) {
      // Circular .cause chain — bail out.
      break;
    }
    seen.add(current);

    if (current instanceof Error) {
      if (current.message && stringMatchesTransportLost(current.message)) {
        return true;
      }
      if (objectHasTransportLostCode(current)) {
        return true;
      }
      current = (current as { cause?: unknown }).cause;
      depth += 1;
      continue;
    }

    if (typeof current === "object") {
      const obj = current as { message?: unknown };
      if (
        typeof obj.message === "string" &&
        stringMatchesTransportLost(obj.message)
      ) {
        return true;
      }
      if (objectHasTransportLostCode(current)) {
        return true;
      }
      try {
        const rendered = JSON.stringify(current);
        if (stringMatchesTransportLost(rendered)) {
          return true;
        }
      } catch {
        // Non-serializable; fall through.
      }
      break;
    }
    break;
  }

  try {
    return stringMatchesTransportLost(String(error));
  } catch {
    return false;
  }
}

/**
 * Convenience predicate — either the session-lost OR transport-lost
 * detector fires. The idempotent recovery paths (the dynamic-find
 * `tools/list` in `metamcp-proxy.ts`, the aggregate list handlers, the
 * OpenAPI bridge's `tools/list`) use this so they engage the same
 * invalidate + reconnect + retry sequence regardless of which envelope the
 * failure arrived in. `tools/call` does NOT: it replays only on
 * {@link isToolCallReplaySafeError}.
 */
export function isRecoverableBackendError(error: unknown): boolean {
  return isBackendSessionLostError(error) || isBackendTransportLostError(error);
}

// An McpError is the backend's own JSON-RPC answer (or the SDK's local
// timeout / connection-closed rejection), never a transport-level refusal.
// Matched by name and by the message prefix McpError's constructor writes
// ("MCP error <code>: ..."), not by `instanceof`, so a second copy of the
// SDK in the tree cannot make the check miss.
const MCP_ERROR_MESSAGE_PREFIX = /^MCP error -?\d+: /;

function isMcpErrorShape(error: Error): boolean {
  return (
    error.name === "McpError" || MCP_ERROR_MESSAGE_PREFIX.test(error.message)
  );
}

/**
 * Decide whether a failed backend `tools/call` may be sent a second time.
 *
 * Stricter than {@link isRecoverableBackendError} on purpose. A list or read
 * is idempotent, so replaying it after any connection-loss shape costs at
 * most a duplicate read. A tool call is not: it can delete a file on a
 * client endpoint, reboot a machine or reset a password, and replaying one
 * the backend already ran executes it twice and loses the first result. A
 * double delete on a client machine was traced to exactly that on
 * 2026-09-30: a 60 s gateway timeout (-32001) was classed as session-lost
 * and the call was re-sent. So this returns true only when the failure
 * PROVES the backend never executed the request:
 *
 *   1. The backend answered our POST with HTTP 404 "Session not found". Its
 *      session layer refused the request before any handler ran, which is
 *      the MCP spec's signal to re-initialize. Evidence is the transport's
 *      own HTTP status: `StreamableHTTPError.code === 404`, or the SSE
 *      transport's "Error POSTing to endpoint (HTTP 404)" message.
 *   2. Our transport was already closed before the request was sent: the
 *      SDK's pre-send `Error("Not connected")`, raised by `Protocol.request`
 *      when it has no transport and by the SSE / stdio `send` when there is
 *      no endpoint or process. Nothing left the gateway.
 *
 * Everything else surfaces to the caller with no replay, because the
 * request may have reached the backend: a timeout (McpError -32001 "Request
 * timed out"), a connection dropped mid-call (McpError -32000 "Connection
 * closed"), a fetch failure such as a reset socket, a 5xx, and any McpError
 * at all, since that is a JSON-RPC answer from a backend that received the
 * request (a nested gateway relaying "-32603 Not connected" included).
 *
 * Only the error exactly as `client.request()` rejects is inspected, with no
 * `.cause` walk and no substring match: nothing wraps it on the tools/call
 * path, and a proof that has to be dug out of a wrapper or a rendered string
 * is not a proof. When the gateway cannot tell "never reached the backend"
 * from "sent and maybe executed", it must not replay. Do not widen this to
 * {@link isRecoverableBackendError}; that is the regression it exists to
 * prevent.
 */
export function isToolCallReplaySafeError(error: unknown): boolean {
  if (!(error instanceof Error) || isMcpErrorShape(error)) {
    return false;
  }

  // Case 2: the SDK's pre-send rejection. Exact match, so a backend message
  // that merely contains "Not connected" cannot qualify.
  if (error.message === NOT_CONNECTED) {
    return true;
  }

  // Case 1: an HTTP 404 answer carrying the session-not-found marker.
  const status = (error as { code?: unknown }).code;
  const answeredHttp404 = status === 404 || error.message.includes(HTTP_404);
  return answeredHttp404 && error.message.includes(SESSION_NOT_FOUND);
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
