import { isMcpErrorShape } from "./session-error";

/**
 * Names a backend's HTTP 401 or 403 answer by the SDK transports' own error
 * shapes, so the gateway can say "the backend refused this" instead of a bare
 * status code, and so a connect that the backend rejected does not retry.
 *
 * The match is on the transport's own markers (a numeric status plus the
 * message prefix the SDK writes), never on a substring: a 5xx whose body quotes
 * "401" is not an auth rejection (the same discipline as
 * isHttpSessionNotFoundError in session-error.ts). The fork sets no OAuth
 * provider on a backend transport, so the SDK's own auth branches never run
 * and these are the only shapes a refusal arrives in:
 *
 *   StreamableHTTPClientTransport POST: StreamableHTTPError, numeric `.code`,
 *     message "Streamable HTTP error: Error POSTing to endpoint: <body>".
 *   StreamableHTTPClientTransport stream open: the same class and prefix with
 *     "Failed to open SSE stream: ...".
 *   SSEClientTransport stream open: SseError, numeric `.code`, message
 *     "SSE error: ...". The event source is closed and no close event follows,
 *     so this one means the message channel is dead.
 *   SSEClientTransport POST: a plain Error with no `.code`, message
 *     "Error POSTing to endpoint (HTTP <status>): <body>".
 */

export type BackendAuthRejection = {
  status: 401 | 403;
  /**
   * "post": the backend answered one POST over a connection that is alive.
   * "stream": the stream or channel itself was refused, so it is not alive.
   */
  via: "post" | "stream";
};

const MAX_CAUSE_DEPTH = 8;

const STREAMABLE_PREFIX = "Streamable HTTP error: ";
const STREAMABLE_POST_PREFIX =
  "Streamable HTTP error: Error POSTing to endpoint";
const SSE_ERROR_PREFIX = "SSE error: ";
const SSE_POST_PATTERN = /^Error POSTing to endpoint \(HTTP (401|403)\): /;

function classifyOne(error: Error): BackendAuthRejection | undefined {
  const code = (error as { code?: unknown }).code;
  const message = error.message;

  if (code === 401 || code === 403) {
    if (message.startsWith(STREAMABLE_POST_PREFIX)) {
      return { status: code, via: "post" };
    }
    if (
      message.startsWith(SSE_ERROR_PREFIX) ||
      message.startsWith(STREAMABLE_PREFIX)
    ) {
      return { status: code, via: "stream" };
    }
    return undefined;
  }

  // The SSE transport's POST failure carries no `.code`; its message is the
  // only evidence, matched as an exact prefix.
  if (code === undefined) {
    const match = SSE_POST_PATTERN.exec(message);
    if (match) {
      return { status: match[1] === "401" ? 401 : 403, via: "post" };
    }
  }
  return undefined;
}

/**
 * The classification of `error` or of any link of its `.cause` chain, or
 * undefined when it is not a transport-shaped 401 or 403. An McpError shape is
 * skipped: that is a JSON-RPC answer (or the SDK's own timeout), never a
 * refusal at the HTTP layer.
 */
export function classifyBackendAuthRejection(
  error: unknown,
): BackendAuthRejection | undefined {
  const seen = new Set<unknown>();
  let current: unknown = error;
  for (let depth = 0; depth < MAX_CAUSE_DEPTH; depth += 1) {
    if (!(current instanceof Error) || seen.has(current)) return undefined;
    seen.add(current);
    if (!isMcpErrorShape(current)) {
      const found = classifyOne(current);
      if (found) return found;
    }
    current = (current as { cause?: unknown }).cause;
  }
  return undefined;
}

/**
 * Fixed text for a classified rejection: the status and the classification,
 * never any part of the backend's response body.
 *
 * At connect the handshake carries no caller identity, so a refusal there is
 * about the credentials the gateway itself sends. After connect a refusal can
 * be about one caller (the backend sees the verified caller on each request),
 * so that wording stays neutral.
 */
export function describeBackendAuthRejection(
  status: 401 | 403,
  phase: "connect" | "request",
): string {
  if (phase === "connect") {
    return status === 401
      ? "the backend rejected the gateway's credentials (HTTP 401)"
      : "the backend refused the gateway's access (HTTP 403)";
  }
  return `the backend answered the request with HTTP ${status}`;
}

/**
 * The value safe to put in a request-failure log. A classified refusal carries
 * fixed text and status only, including when wrapped in a cause chain. Other
 * failures keep their diagnostic error. Never use this for a consumer reply.
 */
export function backendErrorForLogging(error: unknown): unknown {
  const rejection = classifyBackendAuthRejection(error);
  return rejection
    ? describeBackendAuthRejection(rejection.status, "request")
    : error;
}
