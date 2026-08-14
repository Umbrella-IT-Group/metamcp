import { createHash, randomBytes } from "crypto";
import express from "express";

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
 * only checker `buildClientRegistration` calls. This one is deliberately left
 * in place for `/oauth/authorize`: the stricter rules would also apply to the
 * redirect_uris of clients that are ALREADY stored, and re-validating those
 * rows mid-incident is a separate, evidence-gated decision (see the
 * "belt-and-suspenders" note on `isAllowedRedirectUri`). Registration-time
 * enforcement plus removal of the red-team test clients is what closes
 * FIND-023; adopting the strict checker here too is the planned follow-up.
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

    // For production, only allow HTTPS
    if (
      process.env.NODE_ENV === "production" &&
      parsedUri.protocol !== "https:"
    ) {
      return false;
    }

    // Prevent localhost/private IPs in production
    if (process.env.NODE_ENV === "production") {
      const hostname = parsedUri.hostname.toLowerCase();
      if (
        hostname === "localhost" ||
        hostname === "127.0.0.1" ||
        hostname === "::1" ||
        hostname.startsWith("192.168.") ||
        hostname.startsWith("10.") ||
        hostname.startsWith("172.")
      ) {
        return false;
      }
    }

    // Check against allowed hosts if provided
    if (allowedHosts && allowedHosts.length > 0) {
      return allowedHosts.includes(parsedUri.hostname);
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
 * pure attack shape — the red-team run registered exactly that. Kept in step
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
 * every other host (evil.com, `mcp.umbrellaitgroup.com.evil.com`,
 * `…@evil.com`) was a red-team probe. An allowlist is therefore the cheapest
 * complete fix for FIND-023: DCR is anonymous, so anything short of "the
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
 * The registration-time redirect_uri gate — FIND-023 (HIGH, incident 65394).
 *
 * `POST /oauth/register` takes no credential, so whatever passes this function
 * is a host a signed-in human can later be asked to approve on the consent
 * screen. Before it existed the endpoint 201-accepted `https://evil.com`, the
 * lookalike `https://mcp.umbrellaitgroup.com.evil.com`, and the userinfo trick
 * `https://mcp.umbrellaitgroup.com@evil.com` (whose real host is evil.com but
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
 *     a suffix rule is what makes `mcp.umbrellaitgroup.com.evil.com` look
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
 * Hash client secret for secure storage
 * Uses SHA-256 with salt
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
 * Verify client secret against stored hash
 */
export function verifyClientSecret(
  secret: string,
  storedHash: string,
  salt: string,
): boolean {
  const { hash } = hashClientSecret(secret, salt);
  return hash === storedHash;
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
      limit: "10mb",
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
      limit: "10mb",
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
const tokenEndpointLimiter = new RateLimiter(20, 1 * 60 * 1000); // 10 attempts per 1 minute
const consentDecisionLimiter = new RateLimiter(20, 1 * 60 * 1000); // 20 decisions per user per 1 minute

// Clean up rate limiter entries every 10 minutes
setInterval(
  () => {
    authEndpointLimiter.cleanup();
    tokenEndpointLimiter.cleanup();
    consentDecisionLimiter.cleanup();
  },
  10 * 60 * 1000,
);

/**
 * Rate limit the OAuth consent decision by USER, not by IP.
 *
 * The other two limiters key on `req.ip`, which works only as well as the
 * deployment lets it: express has no `trust proxy` set here and the backend is
 * reached through the frontend's rewrite inside the same container, so `req.ip`
 * is the same container-local address for every human. An IP key on this
 * endpoint would therefore be one bucket shared by the whole organisation —
 * and unlike the others, a 429 here strands a user who has ALREADY clicked
 * Approve, with no way forward but to restart the whole flow.
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
 * Rate limiting middleware for OAuth authorization endpoint
 */
export function rateLimitAuth(
  req: express.Request,
  res: express.Response,
  next: express.NextFunction,
) {
  const identifier = req.ip || req.socket?.remoteAddress || "unknown";

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
 * Rate limiting middleware for OAuth token endpoint
 */
export function rateLimitToken(
  req: express.Request,
  res: express.Response,
  next: express.NextFunction,
) {
  const identifier = req.ip || req.socket?.remoteAddress || "unknown";

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

  // Content Security Policy for OAuth pages
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none';",
  );

  // Cache control for sensitive endpoints
  if (req.path.includes("/oauth/")) {
    res.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
    res.setHeader("Pragma", "no-cache");
    res.setHeader("Expires", "0");
  }

  next();
}
