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
