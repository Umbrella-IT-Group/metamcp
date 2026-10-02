/**
 * "This tool name does not exist" predicates, shared by the audit classifier
 * and the retired-tool redirect.
 *
 * A call to a name nobody serves fails three different ways in this gateway,
 * and a caller (or an audit query) cannot tell them apart without text:
 *
 *   1. The gateway's own throw: `Unknown tool: <name>` (metamcp-proxy), or
 *      `Unknown tool: "<name>"` with JSON quoting on the OpenAPI bridge. The
 *      streamable-HTTP transport re-wraps it as `MCP error -N: ...`.
 *   2. The backend answering for a name the gateway still routes to it: a
 *      FastMCP backend returns an isError result `Unknown tool: '<name>'`; a
 *      TypeScript-SDK backend returns `Tool <name> not found`.
 *   3. The filter middleware's fail-closed denial when the server prefix no
 *      longer resolves at all (a deleted server):
 *      `Access denied to tool "<name>": server could not be resolved`.
 *
 * ANCHORED, deliberately: every pattern must match at the START of the text
 * (after an optional protocol prefix). A live tool's ordinary error text that
 * merely mentions an unknown tool somewhere inside a sentence must never match,
 * because a false positive here mislabels an audit row, and a false positive in
 * the redirect would rewrite a real error. The text is also capped at the first
 * 512 characters so the check stays O(1) on a large error body.
 *
 * KNOWN SHAPE OF A FALSE POSITIVE, accepted and documented: the third form is
 * also what the filter returns for a LIVE tool when the server-name lookup
 * fails for a transient database reason (the lookup fails closed). That call is
 * recorded as `unknown_tool` rather than `tool_error`. A stale map entry can
 * also redirect that refusal. Redirect callers must require the missing name
 * to match the requested tool, so a live tool's failure about an internal
 * helper cannot become a retirement notice for the live tool itself.
 *
 * PURE and import-free so the audit middleware's static graph stays DB-free.
 */

/** How much of an error text is inspected. */
export const UNKNOWN_TOOL_TEXT_WINDOW = 512;

// Optional protocol prefix the MCP SDK adds when it wraps a JSON-RPC error,
// e.g. `MCP error -32602: Unknown tool: x`.
const PROTOCOL_PREFIX = String.raw`(?:MCP error -?\d+:\s*)?`;

const UNKNOWN_TOOL_PATTERNS: readonly RegExp[] = [
  // Gateway throw and FastMCP backend answer.
  new RegExp(
    String.raw`^\s*${PROTOCOL_PREFIX}Unknown tool:\s*(?<quote>['"]?)(?<name>[^'"\s]{1,200})\k<quote>\s*$`,
  ),
  // TypeScript-SDK backend: "Tool <name> not found", name within 120 chars.
  new RegExp(
    String.raw`^\s*${PROTOCOL_PREFIX}Tool (?<quote>['"]?)(?<name>[^'"\s]{1,120})\k<quote> not found\s*$`,
  ),
  // Filter middleware fail-closed denial for an unresolvable server prefix.
  new RegExp(
    String.raw`^\s*${PROTOCOL_PREFIX}Access denied to tool "(?<name>[^"\r\n]{1,200})": server could not be resolved\s*$`,
  ),
];

/** True when the text reads as "no such tool". See the module header. */
export function looksLikeUnknownTool(
  text: unknown,
  expectedName?: string,
): boolean {
  if (typeof text !== "string" || text.length === 0) return false;
  const head = text.slice(0, UNKNOWN_TOOL_TEXT_WINDOW);
  for (const pattern of UNKNOWN_TOOL_PATTERNS) {
    const name = pattern.exec(head)?.groups?.name;
    if (name === undefined) continue;
    if (expectedName === undefined || name === expectedName) return true;
    // Backends see the local tool name, while the gateway and filter report
    // its full name. The retired map's server syntax contains no underscores,
    // so the first double underscore is the server/tool boundary here.
    const separator = expectedName.indexOf("__");
    if (separator >= 0 && name === expectedName.slice(separator + 2))
      return true;
  }
  return false;
}

/**
 * True when a THROWN value is the gateway's own unknown-tool error (or the
 * SDK-wrapped form of it). Only the message is read; an error of any other kind
 * (a timeout, a broker error, "Not connected") is never an unknown-tool error,
 * whatever its text mentions further in.
 */
export function isUnknownToolError(
  error: unknown,
  expectedName?: string,
): boolean {
  if (error === null || typeof error !== "object") return false;
  try {
    const message = (error as { message?: unknown }).message;
    return looksLikeUnknownTool(message, expectedName);
  } catch {
    // An opaque failure must travel up unchanged. Reading an accessor here
    // must not replace the handler's original thrown object with a new fault.
    return false;
  }
}
