/**
 * The cause text an audit listing logs for a server it could not list.
 *
 * An audit listing (tool-arg-keys.ts, AuditSchemaRefresher) is background work
 * no client waited on, so it logs one WARN for the namespace and no per-server
 * ERROR lines. That kept the cause out of the logs: an operator saw "could not
 * list 1 server(s) (autotask)" and nothing that said why. Each listing path now
 * adds one INFO line per unlistable server whose text comes from here.
 *
 * INFO, not DEBUG: production runs LOG_LEVEL=info, where DEBUG never reaches
 * the container's output and so never reaches the log store.
 *
 * Three rules for the text, each from a way a log line has gone wrong:
 *   - It never throws. A listing's outcome must not depend on whether its
 *     diagnostic could be built; a reason that cannot be read becomes a fixed
 *     string instead.
 *   - It is one bounded line with no credentials. A backend's message can hold
 *     newlines (a forged log line), a URL with a key in its query string or
 *     userinfo, a bearer token or a long body. The scrub runs before the
 *     bound, so a cut cannot leave half of a credential behind. Tool
 *     arguments are never in the text: the listing request carries none, and
 *     only the error's class and message are read.
 *   - It avoids the words the log panels count as failures (a whole-word,
 *     case-insensitive match on error, fatal, panic or exception). An error's
 *     own text often carries one ("Error POSTing to endpoint"), and a
 *     background listing the caller never saw must not raise those counts, so
 *     a matching word is cut to its first three letters and a star.
 */

const PANEL_WORDS = /\b(error|fatal|panic|exception)\b/gi;
const MAX_REASON_CHARS = 240;
const UNREADABLE = "the reason could not be read";

// Server-side reasons that carry no error object.
export const NO_SESSION_CAUSE =
  "the pool returned no session (server gated, at the connection cap, or backend unreachable)";
export const SEPARATOR_CAUSE =
  "the server name contains the tool-name separator";

const scrub = (text: string): string =>
  text
    .replace(/\s+/g, " ")
    // user:password@ in a URL
    .replace(/\b((?:https?|wss?):\/\/)[^\s/@]+@/gi, "$1[redacted]@")
    // a URL's query string, where API keys travel
    .replace(
      /\b((?:https?|wss?):\/\/[^\s?#"')>]+)\?[^\s"')>]*/gi,
      "$1?[redacted]",
    )
    // Authorization: Bearer x / Basic x, and a bare "Bearer x"
    .replace(/\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+/gi, "$1 [redacted]")
    // key=value and "key": "value" for the names a credential travels under
    .replace(
      /\b(authorization|x-gateway-auth|x-api-key|api[_-]?key|access[_-]?token|refresh[_-]?token|token|secret|password|passwd)(["']?\s*[:=]\s*["']?)[^\s,;"'&}]+/gi,
      "$1$2[redacted]",
    );

const truncate = (text: string): string =>
  text.length > MAX_REASON_CHARS
    ? `${text.slice(0, MAX_REASON_CHARS)}...`
    : text;

const maskPanelWords = (text: string): string =>
  text.replace(PANEL_WORDS, (word) => `${word.slice(0, 3)}*`);

/** "<class>: <message>" for a rejected listing step, safe to put in one log line. */
export function describeListingFailure(reason: unknown): string {
  try {
    const cls = reason instanceof Error ? String(reason.name) : typeof reason;
    const message =
      reason instanceof Error
        ? String(reason.message)
        : typeof reason === "string"
          ? reason
          : "";
    return maskPanelWords(
      truncate(scrub(message ? `${cls}: ${message}` : cls)),
    );
  } catch {
    // A getter on the reason threw. Say so rather than drop the line.
    return UNREADABLE;
  }
}
