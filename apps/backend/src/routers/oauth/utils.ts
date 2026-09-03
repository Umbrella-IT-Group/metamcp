import { createHash, randomBytes, timingSafeEqual } from "crypto";
import express from "express";

import { resolveClientIp } from "@/middleware/audit-context.middleware";
import logger from "@/utils/logger";

// OAuth 2.0 Authorization Parameters interface
export interface OAuthParams {
  client_id: string;
  redirect_uri: string;
  scope?: string;
  state?: string;
  code_challenge?: string;
  code_challenge_method?: string;
}

/**
 * Generate cryptographically secure authorization code
 * Follows OAuth 2.1 security requirements
 */
export function generateSecureAuthCode(): string {
  const randomPart = randomBytes(32).toString("base64url");
  return `mcp_code_${randomPart}`;
}

/**
 * Generate cryptographically secure access token
 * Follows OAuth 2.1 security requirements
 */
export function generateSecureAccessToken(): string {
  const randomPart = randomBytes(32).toString("base64url");
  return `mcp_token_${randomPart}`;
}

/**
 * Generate cryptographically secure refresh token
 * Follows OAuth 2.1 security requirements
 */
export function generateSecureRefreshToken(): string {
  const randomPart = randomBytes(32).toString("base64url");
  return `mcp_refresh_${randomPart}`;
}

/**
 * Generate cryptographically secure client ID
 * Follows OAuth 2.1 security requirements
 */
export function generateSecureClientId(): string {
  const randomPart = randomBytes(16).toString("base64url");
  return `mcp_client_${randomPart}`;
}

/**
 * Generate cryptographically secure client secret
 * Follows OAuth 2.1 security requirements
 */
export function generateSecureClientSecret(): string {
  const randomPart = randomBytes(32).toString("base64url");
  return `mcp_secret_${randomPart}`;
}

/**
 * Validate redirect URI according to OAuth 2.1 security requirements
 * Prevents open redirect vulnerabilities
 *
 * SUPERSEDED AT REGISTRATION by `isAllowedRedirectUri` below, which is the
 * only checker `buildClientRegistration` calls.
 *
 * STILL LIVE AT `/oauth/authorize`, where it now runs ALONGSIDE
 * `isAllowedRedirectUri` rather than instead of it. The follow-up this comment
 * used to describe (apply the strict checker at authorize too, once the stored
 * rows had been verified clean) has landed.
 *
 * WHAT IS LEFT OF IT, EXACTLY — because under the default configuration it is
 * now very nearly a subset of the other, and a future cleanup will want to
 * know what would actually be lost by deleting it. Its scheme rule is
 * subsumed: `isAllowedRedirectUri` already refuses plain http on a
 * non-loopback host in EVERY environment, so nothing this one refuses on
 * scheme grounds survives the other. The ONE surviving delta is the RFC 1918
 * refusal under NODE_ENV=`production`, and it only ever binds when an operator
 * has put a private-range host into DCR_REDIRECT_URI_ALLOWED_HOSTS: with the
 * default allowlist the other checker refuses `192.168.x` as host_not_allowed
 * anyway. That narrow case is the whole reason this function is still called.
 */
export function validateRedirectUri(
  uri: string,
  allowedHosts?: string[],
): boolean {
  try {
    const parsedUri = new URL(uri);

    // Only allow secure schemes (no custom: schemes)
    if (!["https:", "http:"].includes(parsedUri.protocol)) {
      return false;
    }

    // Bracket-stripped so the IPv6 literal `[::1]` compares against `::1`, and
    // matched EXACTLY via the shared set below — `localhost.evil.com` and
    // `evil.localhost` both carry a loopback label and neither is the loopback
    // interface.
    const hostname = parsedUri.hostname.replace(/^\[|\]$/g, "").toLowerCase();
    const isLoopback = LOOPBACK_HOSTNAMES.has(hostname);

    // Production requires HTTPS. Loopback is exempt from that requirement,
    // and the exemption itself is unconditional — it holds in every
    // environment, because it is a property of the host and not of NODE_ENV.
    //
    // RFC 8252 §7.3 has a native app receive its authorization code on
    // `http://127.0.0.1:<ephemeral>`: plain http, on a port the OS assigns at
    // runtime, because an installed client has no other loopback shape
    // available to it. Refusing that hardens nothing reachable from the
    // network — the loopback interface is not routable off-box — it only
    // removes the sole redirect such a client can offer.
    if (
      process.env.NODE_ENV === "production" &&
      !isLoopback &&
      parsedUri.protocol !== "https:"
    ) {
      return false;
    }

    // Prevent private IPs in production. The loopback addresses are absent by
    // design and not by omission: none of them falls in a private range, and
    // unlike `192.168.1.5` they are not reachable by anything else on the LAN.
    if (process.env.NODE_ENV === "production") {
      if (
        hostname.startsWith("192.168.") ||
        hostname.startsWith("10.") ||
        hostname.startsWith("172.")
      ) {
        return false;
      }
    }

    // Check against allowed hosts if provided.
    //
    // Both sides are normalised the same way the loopback test above is, and
    // for the same reason: a raw comparison silently failed whenever the two
    // spellings differed, so `["::1"]` never matched `http://[::1]/` (the
    // parser reports the host bracketed) and `["EXAMPLE.COM"]` never matched
    // anything at all. Entries are bracket-stripped as well as trimmed and
    // lowercased, so an operator may write an IPv6 host either way.
    //
    // An EMPTY array still means "no restriction", unlike
    // `resolveDcrAllowedHosts`, where empty is a configured "loopback only".
    // The two disagree because they are reached differently: this parameter is
    // an optional narrowing a caller opts into, and no caller passes it today.
    if (allowedHosts && allowedHosts.length > 0) {
      const normalisedAllowedHosts = allowedHosts.map((host) =>
        host
          .trim()
          .toLowerCase()
          .replace(/^\[|\]$/g, ""),
      );
      return normalisedAllowedHosts.includes(hostname);
    }

    return true;
  } catch {
    return false;
  }
}

/**
 * The port `apps/backend/src/index.ts` calls `app.listen()` on.
 *
 * Needed here because it is the one loopback port a redirect_uri must NOT use:
 * every request reaches this router through the Next.js rewrite, so
 * `localhost:12009` is the gateway talking to itself. No external OAuth client
 * has a callback listener there, which makes `http://localhost:12009/...` a
 * pure attack shape — the security review run registered exactly that. Kept in step
 * with index.ts by `redirect-uri-allowlist.test.ts`, which reads the literal
 * back out of that file; a bare duplicated number would drift silently.
 */
export const GATEWAY_INTERNAL_PORT = 12009;

/**
 * Hostnames a NON-loopback redirect_uri may use at registration time.
 *
 * Locked to the Anthropic connector hosts because that is what the live data
 * says is real: of the 65 clients registered against this gateway before
 * 2026-08-14, every legitimate redirect_uri was loopback or one of these, and
 * every other host (evil.com, `your-gateway.example.com.evil.com`,
 * `…@evil.com`) was a security review probe. An allowlist is therefore the cheapest
 * complete fix: DCR is anonymous, so anything short of "the
 * server decides which hosts are acceptable" leaves an attacker free to
 * register a client whose consent screen shows a plausible name and whose code
 * lands on their own host.
 *
 * `anthropic.com` is included as headroom for a first-party callback move; it
 * is not currently used by any registered client.
 */
export const DEFAULT_DCR_REDIRECT_URI_ALLOWED_HOSTS: readonly string[] = [
  "claude.ai",
  "claude.com",
  "anthropic.com",
];

/**
 * Env override for the allowlist above: comma-separated hostnames.
 *
 * Setting it REPLACES the default rather than extending it, so an operator can
 * both add a host and remove one of ours without editing code. Setting it to
 * an empty value is meaningful, not a mistake — it means "loopback only".
 */
export const DCR_REDIRECT_URI_ALLOWED_HOSTS_ENV =
  "DCR_REDIRECT_URI_ALLOWED_HOSTS";

/**
 * Exactly the hostnames that count as loopback. Membership is EXACT, never a
 * suffix test: `localhost.evil.com` and `127.0.0.1.evil.com` both end in a
 * loopback label and both resolve to an attacker's server.
 *
 * `::1` is stored unbracketed because the WHATWG parser reports IPv6 hosts
 * bracketed (`new URL("http://[::1]/").hostname === "[::1]"`), and the check
 * strips the brackets before comparing.
 */
const LOOPBACK_HOSTNAMES: ReadonlySet<string> = new Set([
  "localhost",
  "127.0.0.1",
  "::1",
]);

/** Why a redirect_uri was refused. Machine-readable so tests can pin the rule. */
export type RedirectUriRejectionReason =
  | "not_a_string"
  | "unparseable"
  | "unsupported_scheme"
  | "insecure_scheme_non_loopback"
  | "userinfo_present"
  | "fragment_present"
  | "gateway_internal_port"
  | "host_not_allowed";

export type RedirectUriCheck =
  | { ok: true }
  | { ok: false; reason: RedirectUriRejectionReason };

/**
 * Resolve the effective non-loopback host allowlist.
 *
 * Read per call, not at module load, because the env is process configuration
 * an operator may set at deploy time and because a module-load snapshot cannot
 * be exercised by more than one test in a file.
 */
export function resolveDcrAllowedHosts(): string[] {
  const raw = process.env[DCR_REDIRECT_URI_ALLOWED_HOSTS_ENV];

  // `undefined` means "not configured" → default. An empty or whitespace-only
  // string is a configured value meaning "no non-loopback host is allowed".
  if (raw === undefined) {
    return [...DEFAULT_DCR_REDIRECT_URI_ALLOWED_HOSTS];
  }

  return raw
    .split(",")
    .map((host) => host.trim().toLowerCase())
    .filter((host) => host.length > 0);
}

/**
 * The registration-time redirect_uri gate — a HIGH-severity security review
 * finding: redirect_uri was validated by scheme only.
 *
 * `POST /oauth/register` takes no credential, so whatever passes this function
 * is a host a signed-in human can later be asked to approve on the consent
 * screen. Before it existed the endpoint 201-accepted `https://evil.com`, the
 * lookalike `https://your-gateway.example.com.evil.com`, and the userinfo trick
 * `https://your-gateway.example.com@evil.com` (whose real host is evil.com but
 * which reads as ours to a human skimming the URL). Only `javascript:`/`data:`
 * were refused.
 *
 * Pure and I/O-free: the only ambient input is the env allowlist, which
 * `options.allowedHosts` overrides for tests and for callers that have already
 * resolved it.
 *
 * Rules, all of which must pass:
 *  1. Parses under the WHATWG URL parser.
 *  2. `https` for non-loopback; `http` only for loopback. Every other scheme
 *     is refused, which generalises the old `javascript:`/`data:` special case.
 *  3. No userinfo — `username` and `password` must both be empty.
 *  4. No fragment (RFC 6749 §3.1.2 forbids one on a redirection endpoint).
 *  5. Loopback is an EXACT hostname match, any port except the gateway's own
 *     internal listener.
 *  6. Non-loopback hosts must match the allowlist exactly. Exact, not suffix:
 *     a suffix rule is what makes `your-gateway.example.com.evil.com` look
 *     legitimate, and it would also hand every `*.claude.ai` subdomain — user
 *     content included — a valid callback.
 */
export function isAllowedRedirectUri(
  uri: unknown,
  options?: { allowedHosts?: readonly string[] },
): RedirectUriCheck {
  if (typeof uri !== "string") {
    return { ok: false, reason: "not_a_string" };
  }

  let parsed: URL;
  try {
    parsed = new URL(uri);
  } catch {
    return { ok: false, reason: "unparseable" };
  }

  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    return { ok: false, reason: "unsupported_scheme" };
  }

  // Checked before the host rules on purpose. `https://good.example@evil.com`
  // has host evil.com, so the allowlist would refuse it anyway — but a URI
  // whose authority a human and a parser read differently is not something to
  // accept even when the host happens to be allowed
  // (`https://evil.com@claude.ai` is the mirror image).
  if (parsed.username !== "" || parsed.password !== "") {
    return { ok: false, reason: "userinfo_present" };
  }

  if (parsed.hash !== "") {
    return { ok: false, reason: "fragment_present" };
  }

  // Bracket-stripped so the IPv6 literal `[::1]` compares against `::1`.
  const hostname = parsed.hostname.replace(/^\[|\]$/g, "").toLowerCase();

  if (LOOPBACK_HOSTNAMES.has(hostname)) {
    // Any port a local client happens to bind is fine — an installed client
    // picks an ephemeral one — except the gateway's own.
    if (parsed.port === String(GATEWAY_INTERNAL_PORT)) {
      return { ok: false, reason: "gateway_internal_port" };
    }
    return { ok: true };
  }

  if (parsed.protocol !== "https:") {
    return { ok: false, reason: "insecure_scheme_non_loopback" };
  }

  const allowedHosts = (options?.allowedHosts ?? resolveDcrAllowedHosts()).map(
    (host) => host.trim().toLowerCase(),
  );

  if (!allowedHosts.includes(hostname)) {
    return { ok: false, reason: "host_not_allowed" };
  }

  return { ok: true };
}

/**
 * Hash a client secret for storage at rest (migration 0036).
 *
 * SALTED, unlike the random tokens this server hashes unsalted: a client
 * secret is handed to a confidential client and is a user-visible secret, so it
 * gets a per-secret salt (16 random bytes, hex) even though the generator emits
 * a 256-bit random value. `secret + salt` (secret first) is the exact order the
 * migration's SQL backfill concatenates, so a secret hashed here verifies
 * against a row the migration backfilled and vice versa.
 */
export function hashClientSecret(
  secret: string,
  salt?: string,
): { hash: string; salt: string } {
  const saltToUse = salt || randomBytes(16).toString("hex");
  const hash = createHash("sha256")
    .update(secret + saltToUse)
    .digest("hex");
  return { hash, salt: saltToUse };
}

/**
 * Verify a presented client secret against the stored salted hash in constant
 * time.
 *
 * The comparison goes through `timingSafeEqualSecret` rather than `===` so the
 * token endpoint is not a timing oracle for a confidential client's secret:
 * the recomputed digest and the stored digest are both fixed-length hex, and
 * `timingSafeEqualSecret` compares them without leaking how many leading
 * characters agree. Returns false (fail-closed) if no stored hash or salt is
 * present, a client configured for secret auth with no stored secret must not
 * authenticate.
 */
export function verifyClientSecret(
  secret: string,
  storedHash: string | null | undefined,
  salt: string | null | undefined,
): boolean {
  if (!storedHash || !salt) {
    return false;
  }
  const { hash } = hashClientSecret(secret, salt);
  return timingSafeEqualSecret(hash, storedHash);
}

/**
 * Constant-time equality for two secrets held in plaintext.
 *
 * WHY THE SHA-256 STEP. `timingSafeEqual` throws on buffers of unequal length,
 * so comparing the raw secrets directly would both leak the secret's length
 * through the thrown-vs-returned path and crash on a length mismatch. Hashing
 * each side first makes every comparison a fixed 32-byte-vs-32-byte check: the
 * lengths always match, and the time taken no longer depends on how many
 * leading characters two values share. This is the constant-time primitive
 * behind the OAuth client-secret compare: `verifyClientSecret` (migration 0036)
 * now recomputes the salted digest from the stored salt and calls this to
 * compare it against the stored hash, so the client-secret path reads a hash at
 * rest and no longer holds a plaintext secret. The extra sha256 this applies to
 * two already-hex digests is harmless: equal digests stay equal, unequal stay
 * unequal, and the compare stays fixed-length.
 *
 * Returns false for any non-string input rather than throwing, so a caller that
 * split a malformed `client:secret` and got `undefined` for the secret fails
 * closed on the same path as a wrong secret.
 */
export function timingSafeEqualSecret(
  presented: string | undefined | null,
  stored: string | undefined | null,
): boolean {
  if (typeof presented !== "string" || typeof stored !== "string") {
    return false;
  }
  const presentedHash = createHash("sha256").update(presented).digest();
  const storedHash = createHash("sha256").update(stored).digest();
  return timingSafeEqual(presentedHash, storedHash);
}

/**
 * The single scope this authorization server ever grants.
 *
 * RFC 7591 §3.2.1 and RFC 6749 §3.3 both put the scope decision on the
 * authorization server, not the caller: the AS "MAY fully or partially ignore
 * the scope requested by the client" and the response states what was actually
 * granted. The previous code echoed the caller's `scope` back and fell back to
 * the literal "admin", so an anonymous dynamic-registration request could ask
 * for — and be told it had been granted — an administrative scope.
 *
 * Substituting one non-administrative constant is a documentation fix, not an
 * access change: nothing in this codebase reads the OAuth scope string for an
 * authorization decision. `api-key-oauth.middleware` authenticates a bearer
 * token by resolving it to a user id and never inspects the scope, and the
 * real privilege gate is the better-auth session role (`requireAdmin` in
 * @repo/trpc, which reads `user.role` from the database). Existing tokens keep
 * working unchanged; what stops is this server advertising and recording
 * "admin" for callers who were never administrators.
 */
export const GRANTED_OAUTH_SCOPE = "mcp";

/**
 * Helper function to get the correct base URL from request
 * Prioritizes APP_URL environment variable, then checks proxy headers
 */
export function getBaseUrl(req: express.Request): string {
  // Prioritize APP_URL environment variable
  if (process.env.APP_URL) {
    return process.env.APP_URL;
  }

  // Check for forwarded headers from Next.js proxy
  const forwardedHost = req.headers["x-forwarded-host"] as string;
  const forwardedProto = req.headers["x-forwarded-proto"] as string;

  if (forwardedHost) {
    const protocol = forwardedProto || "http";
    return `${protocol}://${forwardedHost}`;
  }

  // Fallback to request host
  return `${req.protocol}://${req.get("host")}`;
}

/**
 * The issuer identifier this authorization server publishes, normalised to a
 * single trailing slash.
 *
 * ONE function so the value cannot drift between the two places that must agree
 * byte for byte. RFC 8414 metadata advertises this as `issuer`, and RFC 9207
 * requires every authorization response carry the same string as `iss`. A
 * strict client compares the two by simple string comparison (RFC 9207 2.4) and
 * aborts the flow on any difference, so a trailing-slash mismatch there is not
 * cosmetic: it breaks the mix-up defence the `iss` parameter exists for. The
 * slash matches the normalisation RFC 8414 / RFC 9728 discovery already applied
 * to the issuer and resource identifiers.
 */
export function getIssuerIdentifier(req: express.Request): string {
  const base = getBaseUrl(req);
  return base.endsWith("/") ? base : base + "/";
}

/**
 * Path prefixes the OAuth router actually serves, matched whole-segment so
 * `/oauthsomething` is not mistaken for one of ours.
 *
 * Lives here rather than in ./index.ts because TWO files need the same answer
 * and a second copy would drift: the router uses it to scope its anonymous
 * CORS policy, and `apps/backend/src/index.ts` uses it to steer these paths
 * away from the global 50mb body parser (see OAUTH_BODY_LIMIT).
 */
export const OAUTH_SERVED_PREFIXES = ["/oauth", "/.well-known"] as const;

/** Whole-segment prefix test for the paths above. */
export function isOAuthServedPath(path: string): boolean {
  return OAUTH_SERVED_PREFIXES.some(
    (prefix) => path === prefix || path.startsWith(`${prefix}/`),
  );
}

/**
 * Body-size ceiling for every `/oauth/*` POST.
 *
 * These routes used to ride the app-wide `express.json({ limit: "50mb" })`
 * registered ahead of the router in `apps/backend/src/index.ts`: because that
 * parser had already consumed and parsed the stream, the 10mb limit written
 * here never bound anything. So the largest single anonymous write this
 * gateway accepted was 50mb, on `/oauth/register`, which needs no credential
 * and stores what it is given.
 *
 * 256kb is chosen against the real bodies: a DCR registration under the caps in
 * ./client-registration.ts is a few kilobytes at worst, a token exchange and a
 * consent decision are a few hundred bytes. It is roughly two orders of
 * magnitude of headroom over the largest legitimate request and roughly two
 * hundred times smaller than what an anonymous caller could previously send.
 *
 * The parser must stay AHEAD of the rate limiters on these routes (it is
 * router-level middleware, they are per-route), so an oversized body is
 * refused with a 413 by the parser rather than being read in full and then
 * counted.
 */
export const OAUTH_BODY_LIMIT = "256kb";

/**
 * Middleware to add JSON parsing for OAuth POST endpoints
 */
export function jsonParsingMiddleware(
  req: express.Request,
  res: express.Response,
  next: express.NextFunction,
) {
  // Only apply JSON parsing for OAuth POST endpoints that need parsed body
  const needsJsonParsing =
    (req.path.startsWith("/oauth/") && req.method === "POST") ||
    (req.path === "/oauth/register" && req.method === "POST");

  if (needsJsonParsing) {
    return express.json({
      limit: OAUTH_BODY_LIMIT,
      type: "application/json",
    })(req, res, next);
  }
  next();
}

/**
 * Middleware to add URL-encoded form parsing for OAuth POST endpoints
 */
export function urlencodedParsingMiddleware(
  req: express.Request,
  res: express.Response,
  next: express.NextFunction,
) {
  // Only apply URL-encoded parsing for OAuth POST endpoints
  const needsUrlencodedParsing =
    (req.path.startsWith("/oauth/") && req.method === "POST") ||
    (req.path === "/oauth/register" && req.method === "POST");

  if (needsUrlencodedParsing) {
    return express.urlencoded({
      extended: true,
      limit: OAUTH_BODY_LIMIT,
    })(req, res, next);
  }
  next();
}

/**
 * Simple in-memory rate limiter for OAuth endpoints
 * In production, use Redis or similar for distributed rate limiting
 */
class RateLimiter {
  private attempts: Map<string, { count: number; resetTime: number }> =
    new Map();
  private maxAttempts: number;
  private windowMs: number;

  constructor(maxAttempts: number = 10, windowMs: number = 15 * 60 * 1000) {
    this.maxAttempts = maxAttempts;
    this.windowMs = windowMs;
  }

  isRateLimited(identifier: string): boolean {
    const now = Date.now();
    const record = this.attempts.get(identifier);

    if (!record || now > record.resetTime) {
      // Reset or create new record
      this.attempts.set(identifier, {
        count: 1,
        resetTime: now + this.windowMs,
      });
      return false;
    }

    if (record.count >= this.maxAttempts) {
      return true;
    }

    record.count++;
    return false;
  }

  reset(identifier: string): void {
    this.attempts.delete(identifier);
  }

  clear(): void {
    this.attempts.clear();
  }

  // Clean up old entries periodically
  cleanup(): void {
    const now = Date.now();
    for (const [key, record] of this.attempts) {
      if (now > record.resetTime) {
        this.attempts.delete(key);
      }
    }
  }
}

// Create rate limiter instances
const authEndpointLimiter = new RateLimiter(20, 1 * 60 * 1000); // 20 attempts per 1 minute
const tokenEndpointLimiter = new RateLimiter(20, 1 * 60 * 1000); // 20 attempts per 1 minute
const consentDecisionLimiter = new RateLimiter(20, 1 * 60 * 1000); // 20 decisions per user per 1 minute
const registrationEndpointLimiter = new RateLimiter(30, 1 * 60 * 1000); // 30 registrations per caller IP per 1 minute

// Clean up rate limiter entries every 10 minutes
setInterval(
  () => {
    authEndpointLimiter.cleanup();
    tokenEndpointLimiter.cleanup();
    consentDecisionLimiter.cleanup();
    registrationEndpointLimiter.cleanup();
  },
  10 * 60 * 1000,
);

/**
 * Rate limit the OAuth consent decision by USER, not by IP.
 *
 * The other two IP limiters (rateLimitAuth, rateLimitToken) key on
 * `resolveClientIp` — the edge CF-Connecting-IP — with `req.ip` only as the
 * fallback for direct-to-origin and local development. This endpoint keys on
 * the user instead, and for a reason those two do not share: a 429 here strands
 * a user who has ALREADY clicked Approve, with no way forward but to restart
 * the whole flow, so keying it on any IP would let one busy source refuse a
 * human mid-approval. Keying on the user bounds each account's own decision
 * rate and nobody else's.
 *
 * The user id comes from the verified areq token, so it is this server's own
 * signed value, not anything the caller asserted.
 */
export function isConsentDecisionRateLimited(userId: string): boolean {
  return consentDecisionLimiter.isRateLimited(`user:${userId}`);
}

/**
 * Test-only. The limiter lives at module scope, so without this every consent
 * test in a file shares one 20-per-minute budget and the suite starts failing
 * once it grows — as a 429, which looks like a passing negative assertion.
 * Production never calls this.
 */
export function resetConsentDecisionRateLimitForTests(): void {
  consentDecisionLimiter.clear();
}

/**
 * Rate limiting middleware for OAuth authorization endpoint.
 *
 * Keyed on `resolveClientIp` (the edge CF-Connecting-IP) with `req.ip` as the
 * fallback, exactly as rateLimitRegistration does. `trust proxy` is
 * deliberately off (see audit-context.middleware), so `req.ip` behind the
 * tunnel is one container-local address shared by every caller: keying on it
 * made this a single global bucket, so 20 requests a minute from any one source
 * held OAuth authorization exhausted for the whole organisation. CF-Connecting-IP
 * is per-caller, so each edge IP now gets its own bucket. The fallback degrades
 * to the old shared bucket only for direct-to-origin and local development.
 */
export function rateLimitAuth(
  req: express.Request,
  res: express.Response,
  next: express.NextFunction,
) {
  const identifier =
    resolveClientIp(req.headers) ||
    req.ip ||
    req.socket?.remoteAddress ||
    "unknown";

  if (authEndpointLimiter.isRateLimited(identifier)) {
    logger.info(
      `[RATE LIMIT] Authorization endpoint rate limited for IP: ${identifier} - Too many authorization attempts`,
    );
    return res.status(429).json({
      error: "too_many_requests",
      error_description:
        "Too many authorization attempts. Please try again later.",
    });
  }

  next();
}

/**
 * Rate limiting middleware for OAuth token endpoint.
 *
 * Keyed on `resolveClientIp` with a `req.ip` fallback, for the reason spelled
 * out on rateLimitAuth above: with `trust proxy` off, keying on `req.ip` made
 * this one global bucket behind the tunnel, so a single caller sending 20
 * requests a minute could hold token exchange 429ed org-wide — and this is the
 * endpoint claude.ai connectors call to exchange codes and refresh tokens, so
 * that is a live availability gap on the exposed plane. Per-edge-IP keying gives
 * each caller its own bucket.
 */
export function rateLimitToken(
  req: express.Request,
  res: express.Response,
  next: express.NextFunction,
) {
  const identifier =
    resolveClientIp(req.headers) ||
    req.ip ||
    req.socket?.remoteAddress ||
    "unknown";

  if (tokenEndpointLimiter.isRateLimited(identifier)) {
    logger.info(
      `[RATE LIMIT] Token endpoint rate limited for IP: ${identifier} - Too many token requests`,
    );
    return res.status(429).json({
      error: "too_many_requests",
      error_description: "Too many token requests. Please try again later.",
    });
  }

  next();
}

/**
 * Rate limiting middleware for the RFC 7591 dynamic-registration endpoint.
 *
 * WHY /oauth/register HAS ITS OWN LIMITER INSTANCE, separate from
 * /oauth/token's. It once shared `rateLimitToken`, and that was a
 * denial-of-service against pairing rather than a control on it: 20 anonymous
 * registrations in a minute spent the same bucket that legitimate claude.ai
 * token exchanges needed, so the connector's exchange came back 429. The
 * endpoint an attacker can reach for free must not be able to close the
 * endpoint a paired client depends on. A separate limiter instance keeps the
 * two budgets independent even now that all three key the same way.
 *
 * KEYED ON CF-Connecting-IP, with `req.ip` as the fallback — the same keying
 * rateLimitAuth and rateLimitToken now use. Cloudflare overwrites that header
 * at the edge on every request, so it is per-CALLER instead of per-container.
 * The trust assumption is exactly the one audit-context.middleware documents at
 * length: it holds only while the Cloudflare Tunnel is the sole ingress.
 * `req.ip` remains the fallback for direct-to-origin and local development,
 * where it degrades to a single shared bucket.
 *
 * THE RESIDUAL, PLAINLY: per-IP keying means the ceiling is per source
 * address, not global, so a distributed caller is not bounded by this at all.
 * That is deliberate. What bounds the damage of registration flooding is the
 * pair of changes it ships with — the input caps in ./client-registration.ts
 * (how big a row can be) and the retention sweep in ./client-retention.ts (how
 * long a never-used row survives) — and unlike a global ceiling, neither of
 * them can refuse a real connector trying to pair.
 */
export function rateLimitRegistration(
  req: express.Request,
  res: express.Response,
  next: express.NextFunction,
) {
  const identifier =
    resolveClientIp(req.headers) ||
    req.ip ||
    req.socket?.remoteAddress ||
    "unknown";

  if (registrationEndpointLimiter.isRateLimited(`register:${identifier}`)) {
    logger.info(
      `[RATE LIMIT] Registration endpoint rate limited for IP: ${identifier} - Too many registration attempts`,
    );
    return res.status(429).json({
      error: "too_many_requests",
      error_description:
        "Too many registration attempts. Please try again later.",
    });
  }

  next();
}

/**
 * Test-only, same rationale as resetConsentDecisionRateLimitForTests: the
 * limiter lives at module scope, so without this one file's registration tests
 * spend another file's budget and the failure shows up as a 429 that a
 * negative assertion happily accepts. Production never calls this.
 */
export function resetRegistrationRateLimitForTests(): void {
  registrationEndpointLimiter.clear();
}

/**
 * Security headers middleware for OAuth endpoints
 * Prevents common web vulnerabilities
 */
export function securityHeaders(
  req: express.Request,
  res: express.Response,
  next: express.NextFunction,
) {
  // Prevent clickjacking
  res.setHeader("X-Frame-Options", "DENY");

  // Prevent MIME type sniffing
  res.setHeader("X-Content-Type-Options", "nosniff");

  // XSS protection
  res.setHeader("X-XSS-Protection", "1; mode=block");

  // Referrer policy
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");

  // Content Security Policy for OAuth pages.
  //
  // `form-action 'self'` is set alongside `frame-ancestors 'none'`: any HTML
  // that ever appears on an /oauth backend route must not be able to POST a
  // form to an attacker's host. The former HTML sinks on these routes are now
  // JSON errors, so this is defense in depth — it means a future HTML
  // regression cannot become a way to submit a form off-origin and around the
  // consent screen this plane depends on.
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; form-action 'self';",
  );

  // Cache control for sensitive endpoints
  if (req.path.includes("/oauth/")) {
    res.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
    res.setHeader("Pragma", "no-cache");
    res.setHeader("Expires", "0");
  }

  next();
}
