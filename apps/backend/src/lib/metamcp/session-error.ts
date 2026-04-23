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
 * When this happens, the cached backend connection is dead: MetaMCP must drop
 * it, send a new `initialize`, and replay the failed request. The MCP spec
 * states the client MUST start a new session in response to HTTP 404, so this
 * is the normative recovery path, not a workaround.
 */
export function isBackendSessionLostError(error: unknown): boolean {
  if (!(error instanceof Error) || !error.message) {
    return false;
  }
  const message = error.message;
  const mentionsSessionNotFound = message.includes("Session not found");
  const mentionsHttp404 = message.includes("HTTP 404");
  const mentionsSessionErrorCode =
    message.includes("-32001") || message.includes("-32600");
  return (
    mentionsSessionNotFound && (mentionsHttp404 || mentionsSessionErrorCode)
  );
}
