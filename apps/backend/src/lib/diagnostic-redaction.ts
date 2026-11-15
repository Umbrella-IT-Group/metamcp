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
 *  - A gateway API key (`sk_mt_...`), a `Bearer` or `Basic` value, a JSON web
 *    token, the value of a secret-named `key=value` or `key: value` pair, and
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
// and at characters that commonly close a URL in prose.
const URL_PATTERN =
  /\b([a-z][a-z0-9+.-]*:\/\/)(?:[^\s/?#@"'<>]*@)?([^\s/?#"'<>]*)([^\s?#"'<>]*)(\?[^\s#"'<>]*)?(#[^\s"'<>]*)?/gi;
const GATEWAY_KEY_PATTERN = /\bsk_mt_[A-Za-z0-9]+/g;
const AUTH_SCHEME_PATTERN =
  /\b(Bearer|bearer|Basic|basic)\s+[A-Za-z0-9._~+/=-]+/g;
const JWT_PATTERN =
  /\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*/g;
const SECRET_PAIR_PATTERN =
  /\b(client[_-]?secret|api[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token|token|password|passwd|secret)\s*[:=]\s*"?[^\s",;&]+"?/gi;
// 40 or more of the characters an opaque token is made of, holding at least
// one letter and one digit (so a long hyphenated name is left alone). A uuid
// is 36 and stays readable.
const OPAQUE_RUN_PATTERN = /[A-Za-z0-9_-]{40,}/g;

/** Replace credential-shaped substrings of diagnostic text. */
export function redactDiagnosticText(text: string): string {
  return text
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
      AUTH_SCHEME_PATTERN,
      (_match, scheme: string) => `${scheme} ${REDACTED}`,
    )
    .replace(GATEWAY_KEY_PATTERN, `sk_mt_${REDACTED}`)
    .replace(JWT_PATTERN, REDACTED)
    .replace(SECRET_PAIR_PATTERN, (match) => {
      const name = /^[A-Za-z_-]+/.exec(match)?.[0] ?? "secret";
      return `${name}=${REDACTED}`;
    })
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
