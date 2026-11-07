import { Buffer } from "node:buffer";

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
// prefix: each one starts at a literal ("//", "?", "Bearer"), or at
// the start of an identifier run (the lookbehind makes every other start fail
// in one step), and each class it scans stops at the next delimiter. The test
// runs 200 KB of adversarial shapes through scrub() against a time bound.
const ID = "A-Za-z0-9_.-";
// Control (Cc), format (Cf, which holds bidi overrides and the zero-width
// characters) and lone surrogates (Cs). Deleted, not replaced by a space: a
// control character inside a credential must not split it into a redacted half
// and a visible half.
const INVISIBLE = /[\p{Cc}\p{Cf}\p{Cs}\u2028\u2029]/gu;
// Collapse the remaining visible whitespace only after deleting controls and
// format characters. Replacing a tab or BOM first would split "pass<tab>word"
// into two harmless names and leave its credential visible.
const WHITESPACE = /\s+/g;
// scheme://userinfo@host for any scheme. Stop at the first path separator.
// Also cover protocol-relative URLs and malformed userinfo containing
// "?" or "#": an invalid URL can be echoed in the very error we are logging.
// The greedy class runs to the LAST "@", so "pa@ss" is not left half
// visible. Whitespace is allowed here too: malformed URLs can echo a raw
// password containing spaces rather than its percent-encoded form.
const USERINFO = /(:?\/\/)[^/]*@/g;
const OPEN_AUTHORITY = /(:?\/\/)[^/]*$/;
// Any query string, absolute or relative: keys travel there. The whole string
// goes, not its values, so no key list is needed.
// A raw query value may itself contain whitespace or punctuation. Like a
// sensitive name/value pair, no suffix after it is safe to retain.
const QUERY = /\?.*/;
const BEARER = /\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+/gi;
// A JWT header is JSON, but need not start with "eyJ": legal whitespace or a
// newline after its opening brace changes that prefix. Inspect each base64url
// run's decoded prefix instead. A partial header still matches, so cutting a
// long token cannot leave its prefix visible. Runs are visited only once.
const TOKEN_RUN = /(?<![\w-])[\w-]+(?:\.[\w-]*){0,2}/g;
// Error messages can embed another JSON string, including escaped field names.
// Decode syntax before finding credentials. The lookbehind avoids retrying
// the whole backslash run at every position when no escape follows it.
const ESCAPED_SYNTAX =
  /(?<!\\)\\+(?:u([\da-fA-F]{4})|x([\da-fA-F]{2})|(["'/])|([bfnrtv]))/g;
const ESCAPED_CONTROL: Record<string, string> = {
  b: "\b",
  f: "\f",
  n: "\n",
  r: "\r",
  t: "\t",
  v: "\v",
};
// name=value, "name": "value", and header tuples ('name', 'value'). Match the
// name alone so a credential nested in an ordinary value is still seen.
const NAME_SEPARATOR = new RegExp(
  `(?<![${ID}])([${ID}]+)["']?\\s*[:=,]\\s*`,
  "g",
);
// A failed stdio launch can echo its command and arguments, and remote
// failures can carry XML bodies. Neither uses a name=value separator.
const FLAG_VALUE = new RegExp(`(?<![${ID}])(--?[${ID}]+)\\s+`, "g");
const XML_TAG = /<([A-Za-z0-9_:.-]+)(?=[\s/>])/g;
// A sensitive word anywhere in the identifier, in any case or separator style
// (client_secret, AUTOTASK_API_KEY, oauth-access-token, clientSecret, apiKey).
// "key" and "session" are broad on purpose: a miss leaks and a false match
// only hides one value. "auth" is matched as a word of its own so that
// "Unauthorized: invalid token" keeps its reason.
const SENSITIVE_NAME =
  /secret|token|pass|pwd|credential|signature|bearer|jwt|session|key|cookie|authorization|authentication/i;
const AUTH_WORD = /(?:^|[^a-z])auth(?![a-z])/i;
const AUTH_CAMEL = /(?:^auth|Auth)(?=[A-Z]|$)/;
const isSensitiveName = (name: string): boolean =>
  SENSITIVE_NAME.test(name) || AUTH_WORD.test(name) || AUTH_CAMEL.test(name);

function redactPairs(text: string): string {
  let redactAt: number | undefined;
  for (const pattern of [NAME_SEPARATOR, FLAG_VALUE, XML_TAG]) {
    for (const match of text.matchAll(pattern)) {
      const name = match[1];
      if (
        !isSensitiveName(name) &&
        !(pattern === FLAG_VALUE && /^-[pu]$/i.test(name))
      ) {
        continue;
      }
      const valueStart = match.index + match[0].length;
      redactAt = Math.min(redactAt ?? valueStart, valueStart);
      break;
    }
  }
  // There is no safe value delimiter in free-form diagnostic text. A bare
  // password can contain punctuation or whitespace, and a JSON value can
  // be an object or an array. Drop the rest rather than expose its suffix.
  // Scan the name once, then test it in code: putting a sensitive word
  // between two greedy identifier classes made repeated "cookie" quadratic.
  return redactAt === undefined
    ? text
    : `${text.slice(0, redactAt)}${REDACTED}`;
}

/**
 * One line of text with no control characters and no credentials. `cut` is
 * true when `text` is a prefix of a longer message.
 */
function scrub(text: string, cut: boolean): string {
  let line = text.replace(
    ESCAPED_SYNTAX,
    (_match, unicode, hex, quote, control) =>
      quote ??
      ESCAPED_CONTROL[control] ??
      String.fromCharCode(parseInt(unicode ?? hex, 16)),
  );
  // A nested escape can reveal another encoded delimiter. Do not repeatedly
  // decode arbitrary nesting; retain only the prefix before the ambiguity.
  const unresolvedEscape = line.search(ESCAPED_SYNTAX);
  if (unresolvedEscape >= 0) {
    line = `${line.slice(0, unresolvedEscape)}${REDACTED}`;
  }
  // Inspect both forms: a control can be the separator after a secret flag,
  // or sit inside a sensitive name. Deleting it first alone misses the first
  // case; preserving it alone misses the second.
  line = redactPairs(
    redactPairs(line).replace(INVISIBLE, "").replace(WHITESPACE, " "),
  );
  line = line.replace(USERINFO, `$1${REDACTED}@`);
  if (cut || unresolvedEscape >= 0) {
    line = line.replace(OPEN_AUTHORITY, `$1${REDACTED}`);
  }
  line = line.replace(QUERY, `?${REDACTED}`);
  line = line.replace(BEARER, `$1 ${REDACTED}`);
  line = line.replace(TOKEN_RUN, (token) => {
    const header = token.split(".", 1)[0];
    return /^\s*\{/.test(Buffer.from(header, "base64url").toString("utf8"))
      ? REDACTED
      : token;
  });
  return line;
}

/** scrub() on its own, for the test that runs it over adversarial input. */
export const scrubForTesting = scrub;

const maskPanelWords = (text: string): string =>
  text.replace(PANEL_WORDS, (word) => `${word.slice(0, 3)}*`);

function formatListingText(raw: string): string {
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
}

/** Backend-reported names are untrusted log text just like the cause. */
export function describeListingLabel(label: string): string {
  try {
    return formatListingText(label);
  } catch {
    return UNREADABLE;
  }
}

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
    return formatListingText(raw);
  } catch {
    // A getter on the reason threw. Say so rather than drop the line.
    return UNREADABLE;
  }
}
