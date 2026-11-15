/**
 * What an admin-plane key reads of the gateway's diagnostic history
 * (`logs.history`, the `gateway_events` table).
 *
 * WHY. Those rows hold text no part of this gateway wrote: upstream transport
 * errors, backend output, connection detail. A person reading them in the
 * admin UI sees them as stored. A standing credential with no person in front
 * of it gets them reduced, so a credential an upstream server echoed into an
 * error (a URL carrying a token, an `Authorization` value, a `key=value`
 * secret) is not handed to whoever holds the key:
 *
 *  - URLs keep their scheme, host and path; user info is dropped, and a query
 *    string or fragment becomes `?[redacted]`.
 *  - A gateway API key (`sk_mt_...`), the value of an `Authorization` header
 *    (any scheme, `Bearer`, `Basic` and `Token` included, in any letter case),
 *    a `Cookie` or `Set-Cookie` line, a JSON web token, an AWS access key id,
 *    a PEM block, the value of a secret-named pair (`key=value`, `key: value`
 *    or the JSON form `"key": "value"`), a 32-character or longer hex run and
 *    any long opaque run of letters and digits are replaced by `[redacted]`.
 *  - `metadata` keeps only a text `error`, itself redacted; the session id is
 *    left out.
 *
 * Best effort by construction: a pattern list cannot recognise every secret.
 * It is the second line, after not putting secrets in error text; the first
 * line for a credential is that the history holds no request body, header or
 * stored server credential (lib/gateway-events/bounds). Pure.
 */

const REDACTED = "[redacted]";

// scheme://[userinfo@]host[path][?query][#fragment], stopping at whitespace
// and at characters that commonly close a URL in prose. User info ends at
// the last at sign, since a URL password can itself contain an at sign.
const URL_PATTERN =
  /\b([a-z][a-z0-9+.-]*:\/\/)(?:[^\s/?#"'<>]*@)?([^\s/?#"'<>]*)([^\s?#"'<>]*)(\?[^\s#"'<>]*)?(#[^\s"'<>]*)?/gi;
const GATEWAY_KEY_PATTERN = /\bsk_mt_[A-Za-z0-9]+/g;
// Consume a quoted header value as a whole, including escaped quotes. A
// Digest value contains several quoted parameters, so stopping at its first
// quote would expose the response proof and nonce farther along the value.
const AUTH_QUOTED_HEADER_PATTERN =
  /["']?\b(proxy-authorization|authorization)["']?\s*[:=]\s*("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')/gi;
// Only known single-token schemes can leave trailing diagnostic prose alone.
// Every other scheme (Digest and OAuth included) may carry several proof
// parameters, so discard its whole line instead of leaking the later ones.
const AUTH_LINE_PATTERN =
  /\b(proxy-authorization|authorization)["']?\s*[:=]\s*["']?(?:([a-z][a-z0-9_-]*)\s+)?[^\r\n]+/gi;
const SINGLE_TOKEN_AUTH_SCHEME =
  /^(bearer|basic|token|negotiate|ntlm|apikey|api-key|bot)$/i;
// An Authorization header (or its proxy form), in plain or JSON-quoted form.
// "Token" is only a scheme after the header name, not in ordinary prose.
const AUTH_HEADER_PATTERN =
  /\b(proxy-authorization|authorization)(["']?\s*[:=]\s*["']?)(?:(bearer|basic|token|digest|negotiate|ntlm|apikey|api-key|oauth|bot)\s+)?[^\s",;]+/gi;
const COOKIE_LINE_PATTERN = /\b(set-cookie|cookie)\s*:[^\r\n]*/gi;
const AUTH_SCHEME_PATTERN = /\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]+/gi;
const JWT_PATTERN =
  /\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*/g;
const AWS_KEY_ID_PATTERN =
  /\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA)[A-Z0-9]{16}\b/g;
// A PEM block, through its END line or, when the text was cut short, to the
// end of the text.
const PEM_BLOCK_PATTERN =
  /-----BEGIN [A-Z0-9 ]+-----[\s\S]*?(?:-----END [A-Z0-9 ]+-----|$)/g;
// A secret-named pair: `name=value`, `name: value` and the JSON form
// `"name": "value"`, the value a quoted string or a run up to a delimiter. A
// value already replaced is not matched again.
const SECRET_PAIR_PATTERN =
  /["']?\b(client[_-]?secret|api[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token|session[_-]?(?:id|token)|private[_-]?key|set[_-]?cookie|cookie|token|password|passwd|secret)["']?\s*[:=]\s*(?!\[redacted\])(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^\s",;&}\]]+)/gi;
// A hex run of 32 or more characters holding a digit and a letter (an md5,
// sha1 or sha256 digest, or a hex-encoded secret). A dashed uuid is broken by
// its dashes and stays readable.
const HEX_RUN_PATTERN = /\b[0-9a-fA-F]{32,}\b/g;
// 40 or more of the characters an opaque token is made of, holding at least
// one letter and one digit (so a long hyphenated name is left alone). A uuid
// is 36 and stays readable.
const OPAQUE_RUN_PATTERN = /[A-Za-z0-9_-]{40,}/g;

/** Replace credential-shaped substrings of diagnostic text. */
export function redactDiagnosticText(text: string): string {
  return text
    .replace(PEM_BLOCK_PATTERN, REDACTED)
    .replace(
      AUTH_QUOTED_HEADER_PATTERN,
      (_match, name: string, value: string) => {
        const scheme =
          /^(bearer|basic|token|digest|negotiate|ntlm|apikey|api-key|oauth|bot)\s+/i.exec(
            value.slice(1, -1),
          )?.[1];
        return `${name}: ${scheme ? `${scheme} ` : ""}${REDACTED}`;
      },
    )
    .replace(AUTH_LINE_PATTERN, (match, name: string, scheme?: string) => {
      if (scheme && SINGLE_TOKEN_AUTH_SCHEME.test(scheme)) return match;
      const label =
        scheme && /^(digest|oauth)$/i.test(scheme) ? `${scheme} ` : "";
      return `${name}: ${label}${REDACTED}`;
    })
    .replace(
      URL_PATTERN,
      (
        _match,
        scheme: string,
        host: string,
        path: string,
        query?: string,
        fragment?: string,
      ) =>
        `${scheme}${host}${path}${query !== undefined || fragment !== undefined ? `?${REDACTED}` : ""}`,
    )
    .replace(
      AUTH_HEADER_PATTERN,
      (_match, name: string, _separator: string, scheme?: string) =>
        `${name}: ${scheme ? `${scheme} ` : ""}${REDACTED}`,
    )
    .replace(
      COOKIE_LINE_PATTERN,
      (_match, name: string) => `${name}: ${REDACTED}`,
    )
    .replace(
      AUTH_SCHEME_PATTERN,
      (_match, scheme: string) => `${scheme} ${REDACTED}`,
    )
    .replace(GATEWAY_KEY_PATTERN, `sk_mt_${REDACTED}`)
    .replace(JWT_PATTERN, REDACTED)
    .replace(AWS_KEY_ID_PATTERN, REDACTED)
    .replace(SECRET_PAIR_PATTERN, (_match, name: string) => {
      return `${name}=${REDACTED}`;
    })
    .replace(HEX_RUN_PATTERN, (run) =>
      /[a-fA-F]/.test(run) && /[0-9]/.test(run) ? REDACTED : run,
    )
    .replace(OPAQUE_RUN_PATTERN, (run) =>
      /[A-Za-z]/.test(run) && /[0-9]/.test(run) ? REDACTED : run,
    );
}

/** One `logs.history` row, as the procedure returns it. */
export interface GatewayEventRow {
  uuid: string;
  occurredAt: string;
  category: string;
  level: string | null;
  serverUuid: string | null;
  serverName: string | null;
  clientName: string | null;
  sessionId: string | null;
  message: string;
  metadata: Record<string, unknown> | null;
}

/** The row as an admin-plane key reads it (see the module comment). */
export function projectGatewayEventForAdminPlane(
  row: GatewayEventRow,
): GatewayEventRow {
  const error = row.metadata?.error;
  return {
    ...row,
    sessionId: null,
    message: redactDiagnosticText(row.message),
    metadata:
      typeof error === "string" ? { error: redactDiagnosticText(error) } : null,
  };
}
