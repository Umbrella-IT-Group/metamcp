/**
 * Extra `form-action` sources for the OAuth consent document.
 *
 * WHY THIS EXISTS. The consent page's Approve is a plain form POST to
 * `/oauth/authorize/decision`, and the success response is a 302 to the
 * client's registered `redirect_uri` (`https://claude.ai/...`, `https://claude.com/...`,
 * `http://localhost:<port>/callback`, `http://127.0.0.1:<port>/...`). The
 * app-wide CSP (security-headers.ts, fork #150) pins `form-action 'self'`, and
 * Chromium enforces `form-action` against the whole redirect chain of a form
 * submission, not just the action URL (CSP3 dropped that navigation-response
 * check; Chromium kept it, Firefox never had it). So in Chrome and Edge the
 * browser cancelled the redirect AFTER the server had already minted the code
 * and cleared the single-use consent cookie: the page appeared to do nothing,
 * a second click got `access_denied` (csrf), and the client never received the
 * code, so no token was ever exchanged. Observed live 2026-09-05 (loopback,
 * Claude Code) and 2026-09-08 (claude.ai org connector and the existing team
 * connector from Claude Desktop); the last connect that worked was 2026-09-01,
 * two days before #150 merged.
 *
 * THE FIX. The consent document's CSP must also allow the origin the response
 * will redirect to. The middleware mints the CSP before the document renders,
 * and the only thing it has is the request URL, whose `areq` query parameter is
 * the signed authorization request (`base64url(JSON) "." hex(HMAC)`, see the
 * backend's consent-token.ts). This module reads `redirect_uri` out of that
 * payload WITHOUT verifying the signature, and that is deliberate and safe:
 * the value controls only which origin the browser lets THIS form's response
 * navigate to. A forged or tampered `areq` is refused by the backend at
 * decision time, so no redirect is ever issued for it; a genuine `areq`'s
 * `redirect_uri` is the client's registered redirect target, which is exactly
 * where OAuth requires the authorization response to go. Every other form
 * target stays blocked, and every other page keeps `form-action 'self'`.
 *
 * The accepted shape mirrors the backend's registration rules (utils.ts): only
 * `https:` and `http:` (loopback), no userinfo, and the emitted source is the
 * scheme plus host (host includes a non-default port). Anything else yields no
 * widening, never a partial or malformed source.
 */

/** The consent document, with or without the locale segment the middleware prepends. */
export function isConsentDocumentPath(pathname: string): boolean {
  return pathname === "/consent" || /^\/[a-z]{2}\/consent$/.test(pathname);
}

/** Longest `areq` this will look at; a real token is a few hundred bytes. */
const MAX_AREQ_LENGTH = 8192;

const HOST_SOURCE = /^https?:\/\/[A-Za-z0-9.-]+(:\d{1,5})?$/;
const IPV6_HOST_SOURCE = /^https?:\/\/\[[0-9A-Fa-f:.]+\](:\d{1,5})?$/;

/**
 * The CSP host-source (`scheme://host[:port]`) of the `redirect_uri` carried by
 * a consent `areq`, or null when the token is missing, malformed, or names a
 * redirect target outside the shapes the backend registers.
 */
export function consentRedirectOrigin(
  areq: string | null | undefined,
): string | null {
  if (
    typeof areq !== "string" ||
    areq.length === 0 ||
    areq.length > MAX_AREQ_LENGTH
  ) {
    return null;
  }

  const encoded = areq.split(".")[0];
  if (!encoded || !/^[A-Za-z0-9_-]+$/.test(encoded)) return null;

  let payload: unknown;
  try {
    payload = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
  } catch {
    return null;
  }
  if (!payload || typeof payload !== "object") return null;

  const redirectUri = (payload as { redirect_uri?: unknown }).redirect_uri;
  if (typeof redirectUri !== "string") return null;

  let url: URL;
  try {
    url = new URL(redirectUri);
  } catch {
    return null;
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") return null;
  if (url.username || url.password || !url.host) return null;

  const source = `${url.protocol}//${url.host}`;
  // A CSP source list is space- and semicolon-delimited; refuse anything outside
  // the host/port alphabet rather than trust URL parsing to have normalised it.
  if (!HOST_SOURCE.test(source) && !IPV6_HOST_SOURCE.test(source)) return null;
  return source;
}

/**
 * The extra `form-action` sources for a request: the consent document gets its
 * `redirect_uri` origin, every other path gets nothing.
 */
export function consentFormActionSources(
  pathname: string,
  areq: string | null | undefined,
): string[] {
  if (!isConsentDocumentPath(pathname)) return [];
  const origin = consentRedirectOrigin(areq);
  return origin ? [origin] : [];
}
