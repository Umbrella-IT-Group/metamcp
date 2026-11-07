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
 * Rules for the text, each from a way a log line has gone wrong:
 *   - It never throws. A listing's outcome must not depend on whether its
 *     diagnostic could be built; a reason that cannot be read becomes a fixed
 *     string instead.
 *   - It costs the same however large the message is. The work is bounded
 *     before any pattern runs, every pattern is linear (see "Linear patterns"
 *     below), and callers build it only for an audit listing: a client-facing
 *     listing discards the text, so building it there would only spend time on
 *     the hot path.
 *   - It is one line of at most MAX_REASON_CHARS characters, the ellipsis of a
 *     cut line included. Whitespace collapses to one space and every control
 *     and format character is deleted (a backend message can carry newlines,
 *     NEL, U+2028, ESC sequences, NUL or bidirectional overrides), so a
 *     message cannot forge a log line or drive a terminal.
 *   - It carries no credentials, and fails closed: it redacts whole classes of
 *     value rather than a list of names. See scrub().
 *   - Tool arguments are never in the text: the listing request carries none,
 *     and only the error's class and message are read.
 *   - It avoids the words the log panels count as failures (a whole-word,
 *     case-insensitive match on error, fatal, panic or exception). An error's
 *     own text often carries one ("Error POSTing to endpoint"), and a
 *     background listing the caller never saw must not raise those counts, so
 *     a matching word is cut to its first three letters and a star.
 */

const PANEL_WORDS = /\b(error|fatal|panic|exception)\b/gi;
export const MAX_REASON_CHARS = 240;
const ELLIPSIS = "...";
// Bound on what the scrub reads. Applied first, so the work never grows with a
// backend's message. Safe because every pattern in scrub() is prefix-closed: a
// credential the cut lands inside still matches on the part before the cut and
// is redacted whole (a partial query, token, bearer, JWT or cookie matches; an
// unterminated quote redacts to the end). The one construct that needs text
// after it is URL userinfo, whose redaction needs the "@"; when the input was
// cut, an authority left open at the cut is redacted as if it had one. So a
// cut never leaves the first characters of a credential in the line. The bound
// is 17 times the output so an ordinary message is never cut at all.
const MAX_INPUT_CHARS = 4096;
const REDACTED = "[redacted]";
const UNREADABLE = "the reason could not be read";

// Server-side reasons that carry no error object.
export const NO_SESSION_CAUSE =
  "the pool returned no session (server gated, at the connection cap, or backend unreachable)";
export const SEPARATOR_CAUSE =
  "the server name contains the tool-name separator";
// Only for a listing that knows its session had already closed when it asked
// the pool for a backend session (metamcp-proxy.ts).
export const CLOSED_BEFORE_ACQUIRE_CAUSE =
  "the session had closed before the listing asked the pool for a backend session";

// Linear patterns. A regex backtracks quadratically when an unanchored prefix
// is scanned from every start position, as `https?://[^\s?#]+\?` is on a long
// run of back-to-back "http://". So no pattern here scans a variable-length
// prefix: each one starts at a literal ("://", "?", "Bearer", "eyJ"), or at
// the start of an identifier run (the lookbehind makes every other start fail
// in one step), and each class it scans stops at the next delimiter. The test
// runs 200 KB of adversarial shapes through scrub() against a time bound.
const ID = "A-Za-z0-9_.-";
// Control (Cc), format (Cf, which holds bidi overrides and the zero-width
// characters) and lone surrogates (Cs). Deleted, not replaced by a space: a
// control character inside a credential must not split it into a redacted half
// and a visible half.
const INVISIBLE = /[\p{Cc}\p{Cf}\p{Cs}]/gu;
// \s covers CR, LF, U+2028 and U+2029; NEL (U+0085) is a C1 control that
// still means a line break, so it joins them.
const WHITESPACE = /[\s\u0085]+/g;
// scheme://userinfo@host for any scheme. The authority ends at the first "/",
// "?" or "#" (a password holding one must be percent-encoded, per RFC 3986),
// and the greedy class runs to the LAST "@" in it, so "pa@ss" is not left
// half visible.
const USERINFO = /:\/\/[^\s/?#]*@/g;
const OPEN_AUTHORITY = /:\/\/[^\s/?#]*$/;
// Any query string, absolute or relative: keys travel there. The whole string
// goes, not its values, so no key list is needed.
const QUERY = /\?[^\s"'<>)\]}]+/g;
// Cookie and authorization headers: everything after the name to the closing
// quote, or to the end of the text when bare. A header value has no delimiter
// a one-line message could show, so the rest of the line is the value.
const HEADER_VALUE = new RegExp(
  `(?<![${ID}])([${ID}]*(?:cookie|authorization)[${ID}]*)(["']?\\s*[:=]\\s*)(?:"(?:[^"\\\\]|\\\\.)*(?:"|$)|'(?:[^'\\\\]|\\\\.)*(?:'|$)|.*$)`,
  "gi",
);
const BEARER = /\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+/gi;
// A JWT, even without its header name. Prefix-closed: the header segment alone
// matches, so a cut inside the payload still redacts.
const JWT = /\beyJ[\w-]+(?:\.[\w-]*){0,2}/g;
// name=value and "name": "value". The name is matched alone, so the value is
// consumed only for a sensitive name and a pair nested in another's value is
// still seen.
const NAME_SEPARATOR = new RegExp(
  `(?<![${ID}])([${ID}]+)["']?\\s*[:=]\\s*`,
  "g",
);
const VALUE =
  /"(?:[^"\\]|\\.)*(?:"|$)|'(?:[^'\\]|\\.)*(?:'|$)|[^\s,;&}\])"']*/y;
// A sensitive word anywhere in the identifier, in any case or separator style
// (client_secret, AUTOTASK_API_KEY, oauth-access-token, clientSecret, apiKey).
// "key" and "session" are broad on purpose: a miss leaks and a false match
// only hides one value. "auth" is matched as a word of its own so that
// "Unauthorized: invalid token" keeps its reason.
const SENSITIVE_NAME =
  /secret|token|passw|pwd|credential|signature|bearer|jwt|session|key/i;
const AUTH_WORD = /(?:^|[^a-z])auth(?![a-z])/i;
const AUTH_CAMEL = /[a-z]Auth(?![A-Za-z])/;
const isSensitiveName = (name: string): boolean =>
  SENSITIVE_NAME.test(name) || AUTH_WORD.test(name) || AUTH_CAMEL.test(name);

function redactPairs(text: string): string {
  let out = "";
  let copied = 0;
  for (const match of text.matchAll(NAME_SEPARATOR)) {
    // Inside a value already redacted.
    if (match.index < copied) continue;
    if (!isSensitiveName(match[1])) continue;
    const valueStart = match.index + match[0].length;
    VALUE.lastIndex = valueStart;
    const valueEnd = valueStart + (VALUE.exec(text)?.[0].length ?? 0);
    out += `${text.slice(copied, valueStart)}${REDACTED}`;
    copied = valueEnd;
  }
  return out + text.slice(copied);
}

/**
 * One line of text with no control characters and no credentials. `cut` is
 * true when `text` is a prefix of a longer message.
 */
function scrub(text: string, cut: boolean): string {
  let line = text.replace(WHITESPACE, " ").replace(INVISIBLE, "");
  line = line.replace(USERINFO, `://${REDACTED}@`);
  if (cut) line = line.replace(OPEN_AUTHORITY, `://${REDACTED}`);
  line = line.replace(QUERY, `?${REDACTED}`);
  line = line.replace(HEADER_VALUE, `$1$2${REDACTED}`);
  line = line.replace(BEARER, `$1 ${REDACTED}`);
  line = line.replace(JWT, REDACTED);
  return redactPairs(line);
}

/** scrub() on its own, for the test that runs it over adversarial input. */
export const scrubForTesting = scrub;

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
    const raw = message ? `${cls}: ${message}` : cls;
    const cut = raw.length > MAX_INPUT_CHARS;
    const text = scrub(cut ? raw.slice(0, MAX_INPUT_CHARS) : raw, cut);
    const clipped =
      cut || text.length > MAX_REASON_CHARS
        ? // The ellipsis counts toward the bound. A cut can split a surrogate
          // pair, so the invisible pass runs again on what is left.
          `${text.slice(0, MAX_REASON_CHARS - ELLIPSIS.length)}${ELLIPSIS}`.replace(
            INVISIBLE,
            "",
          )
        : text;
    return maskPanelWords(clipped);
  } catch {
    // A getter on the reason threw. Say so rather than drop the line.
    return UNREADABLE;
  }
}
