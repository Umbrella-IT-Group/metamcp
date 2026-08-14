import crypto from "crypto";

/**
 * Signed authorization-request ("areq") tokens for the OAuth consent screen.
 *
 * The consent screen splits what used to be one request into three: the browser
 * asks `/oauth/authorize` for authorization, a human approves on a page, and
 * `/oauth/authorize/decision` mints the code. The authorization parameters have
 * to survive that round trip through the user's browser, and the previous
 * version of this flow carried them as a plain base64 blob — which meant a
 * caller could edit client_id, redirect_uri or the PKCE challenge in flight and
 * hand the edited blob back. Everything the decision endpoint trusts therefore
 * travels HMAC-signed and short-lived, and is re-validated against the client
 * record on the way out anyway.
 *
 * The `csrf` nonce in the payload is the server's half of a double-submit pair:
 * the same value is written to an httpOnly cookie when the token is issued, so
 * approving requires possession of BOTH the token (in the URL of a page only
 * the signed-in user was redirected to) and the cookie (which SameSite=Lax
 * keeps off cross-site POSTs, and which httpOnly keeps out of reach of script).
 */

export interface ConsentRequestPayload {
  client_id: string;
  redirect_uri: string;
  /** Server-decided grant, carried for display only — see GRANTED_OAUTH_SCOPE. */
  scope: string;
  state?: string;
  code_challenge?: string;
  code_challenge_method?: string;
  /** The signed-in user the consent request belongs to. */
  user_id: string;
  /**
   * Consent-request id. NOT a secret and never compared for authorization —
   * it exists only to give this request its own cookie NAME. A real OAuth
   * client hits /oauth/authorize more than once (prefetch, retry, parallel
   * tabs); with one shared cookie name the second Set-Cookie overwrote the
   * first, so approving the page bound to the first request compared against
   * the second request's nonce and failed. Observed against a live Claude.ai
   * connect: two `consent requested` lines in the same second, then
   * `consent rejected reason=csrf` on Approve.
   */
  cid: string;
  /** Double-submit nonce; must equal the per-cid csrf cookie's value. */
  csrf: string;
  /** Absolute expiry, epoch milliseconds. */
  exp: number;
}

/**
 * Domain separation. BETTER_AUTH_SECRET also keys better-auth's own signatures,
 * so the signed material is prefixed with a constant no other consumer uses:
 * an areq token can never be presented as some other artifact derived from the
 * same key, nor the reverse. Bump the suffix if the payload shape ever changes
 * in a way older tokens must not satisfy.
 */
const SIGNING_CONTEXT = "metamcp.oauth.consent.v1";

/** Base name of the double-submit cookie on a plain-http (local) deployment. */
export const CONSENT_CSRF_COOKIE = "oauth_consent_csrf";

/**
 * Name of the same cookie wherever the deployment is https.
 *
 * The `__Host-` prefix is a browser-enforced contract: the cookie is accepted
 * only with Secure and Path=/ and NO Domain attribute, which locks it to this
 * exact host. That matters because a sibling subdomain — anything else under
 * umbrellaitgroup.com — can otherwise set a cookie that is sent to this host
 * too. It could not forge a valid nonce, but it could plant a same-named one
 * and jam consent for every user indefinitely. A `__Host-` cookie cannot be
 * planted by a sibling at all. The prefix requires Secure, so plain-http local
 * stacks keep the unprefixed name.
 */
export const CONSENT_CSRF_COOKIE_HOST_PREFIXED = "__Host-oauth_consent_csrf";

/**
 * The cookie name for ONE consent request.
 *
 * Suffixed with the request's `cid` so concurrent authorizations get separate
 * cookies instead of overwriting each other — see ConsentRequestPayload.cid
 * for the live failure that forced this. The `__Host-` prefix is unaffected by
 * a suffix: it constrains the cookie's attributes (Secure, Path=/, no Domain),
 * not the rest of its name. `cid` is base64url, whose alphabet is all valid
 * cookie-name characters.
 */
export function consentCsrfCookieName(secure: boolean, cid: string): string {
  const base = secure ? CONSENT_CSRF_COOKIE_HOST_PREFIXED : CONSENT_CSRF_COOKIE;
  return `${base}_${cid}`;
}

/**
 * How long a pending consent request stays valid. Matches the authorization
 * code lifetime used elsewhere in this router — long enough for a human to
 * read the page, short enough that an abandoned tab stops being usable.
 */
export const CONSENT_REQUEST_TTL_MS = 10 * 60 * 1000;

/**
 * Read at call time rather than module load so a process that somehow starts
 * without the secret fails on the request instead of importing a module that
 * silently signs with `undefined`. `auth.ts` already hard-fails at boot without
 * it, so in a running server this never throws.
 */
function signingKey(): string {
  const secret = process.env.BETTER_AUTH_SECRET;
  if (!secret) {
    throw new Error(
      "BETTER_AUTH_SECRET environment variable is required to sign OAuth consent requests",
    );
  }
  return secret;
}

function computeMac(encodedPayload: string): string {
  return crypto
    .createHmac("sha256", signingKey())
    .update(`${SIGNING_CONTEXT}.${encodedPayload}`)
    .digest("hex");
}

/** `base64url(payload) + "." + hex(HMAC-SHA256(payload))`. */
export function signConsentRequest(payload: ConsentRequestPayload): string {
  const encoded = Buffer.from(JSON.stringify(payload)).toString("base64url");
  return `${encoded}.${computeMac(encoded)}`;
}

/**
 * Returns the payload only for a token this server signed that has not expired.
 * Every other input — wrong signature, truncated, re-encoded, malformed JSON,
 * missing a required field, past its exp — returns null, so callers can treat
 * null as "no authorization request" without classifying the failure.
 */
export function verifyConsentRequest(
  token: unknown,
  now: number = Date.now(),
): ConsentRequestPayload | null {
  if (typeof token !== "string") return null;

  const separator = token.indexOf(".");
  if (separator <= 0) return null;

  const encoded = token.slice(0, separator);
  const provided = token.slice(separator + 1);

  let expected: string;
  try {
    expected = computeMac(encoded);
  } catch {
    return null;
  }

  // timingSafeEqual throws on a length mismatch, so length is compared first.
  // The length of a hex SHA-256 is a public constant; nothing leaks here.
  if (provided.length !== expected.length) return null;
  if (!crypto.timingSafeEqual(Buffer.from(provided), Buffer.from(expected))) {
    return null;
  }

  let payload: unknown;
  try {
    payload = JSON.parse(Buffer.from(encoded, "base64url").toString());
  } catch {
    return null;
  }

  if (!payload || typeof payload !== "object") return null;
  const candidate = payload as Partial<ConsentRequestPayload>;

  if (
    typeof candidate.client_id !== "string" ||
    typeof candidate.redirect_uri !== "string" ||
    typeof candidate.scope !== "string" ||
    typeof candidate.user_id !== "string" ||
    // Required, so a token predating the per-cid cookie split cannot resolve
    // to a cookie name of "undefined". Any such token still in flight during a
    // rollout is refused and the client re-authorizes cleanly.
    typeof candidate.cid !== "string" ||
    candidate.cid.length === 0 ||
    typeof candidate.csrf !== "string" ||
    typeof candidate.exp !== "number"
  ) {
    return null;
  }

  if (now >= candidate.exp) return null;

  return candidate as ConsentRequestPayload;
}

/** Constant-time string comparison that tolerates undefined/mismatched input. */
export function safeEquals(a: unknown, b: unknown): boolean {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

/**
 * Read EVERY value a raw `Cookie` header carries under one name.
 *
 * Returning only the first match would make availability an attacker's to
 * decide: a `Cookie` header can legally repeat a name — a cookie with a more
 * specific Path, or one set by a sibling subdomain, is sent ahead of ours —
 * and a single planted value would then permanently fail the comparison for
 * that user. Collecting all of them and accepting a match on any turns that
 * into a no-op. It costs nothing in strength: the attacker still has to
 * produce the real nonce to be accepted, and `__Host-` (above) stops the
 * sibling-planting case at the browser.
 *
 * This codebase has no `cookie-parser` middleware, so `req.cookies` does not
 * exist; adding the dependency for one read is not worth it. Setting and
 * clearing still go through `res.cookie` / `res.clearCookie`, express core.
 */
export function readCookieValues(
  header: string | undefined,
  name: string,
): string[] {
  if (!header) return [];

  const values: string[] = [];

  for (const part of header.split(";")) {
    const separator = part.indexOf("=");
    if (separator < 0) continue;
    if (part.slice(0, separator).trim() !== name) continue;

    const raw = part.slice(separator + 1).trim();
    try {
      values.push(decodeURIComponent(raw));
    } catch {
      // A value that is not valid percent-encoding still has to compare
      // exactly against what we issued, so keep it unchanged rather than
      // throwing out of a request handler.
      values.push(raw);
    }
  }

  return values;
}
