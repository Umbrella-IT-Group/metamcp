import { DatabaseEndpoint } from "@repo/zod-types";
import express from "express";

/**
 * Simple in-memory rate limiter for failed authentication attempts
 * In production, use Redis or similar for distributed rate limiting
 */
export class AuthRateLimiter {
  private attempts: Map<string, { count: number; resetTime: number }> =
    new Map();
  private readonly maxAttempts: number;
  private readonly windowMs: number;

  constructor(maxAttempts: number = 5, windowMs: number = 15 * 60 * 1000) {
    this.maxAttempts = maxAttempts;
    this.windowMs = windowMs;
  }

  isRateLimited(identifier: string): boolean {
    const now = Date.now();
    const record = this.attempts.get(identifier);

    if (!record) {
      this.attempts.set(identifier, {
        count: 1,
        resetTime: now + this.windowMs,
      });
      return false;
    }

    if (now > record.resetTime) {
      // Reset window
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

  /**
   * Read-only "is this identifier already over budget?".
   *
   * `isRateLimited` COUNTS the call it is asked about, which makes it the wrong
   * question for a gate that runs BEFORE the work: on an endpoint whose success
   * path must never accumulate — see getPublicOAuthRateLimitIdentifier — the
   * check itself would become the thing that eventually refuses a legitimate
   * caller. This one only reads, so the count moves only when something
   * actually failed.
   */
  isCurrentlyLimited(identifier: string): boolean {
    const record = this.attempts.get(identifier);
    if (!record) return false;
    if (Date.now() > record.resetTime) return false;
    return record.count >= this.maxAttempts;
  }

  recordFailedAttempt(identifier: string): void {
    const now = Date.now();
    const record = this.attempts.get(identifier);

    if (!record) {
      this.attempts.set(identifier, {
        count: 1,
        resetTime: now + this.windowMs,
      });
    } else if (now > record.resetTime) {
      // Reset window
      this.attempts.set(identifier, {
        count: 1,
        resetTime: now + this.windowMs,
      });
    } else {
      record.count++;
    }
  }

  // Clean up old entries every 10 minutes
  cleanup(): void {
    const now = Date.now();
    for (const [identifier, record] of this.attempts.entries()) {
      if (now > record.resetTime) {
        this.attempts.delete(identifier);
      }
    }
  }
}

// Create rate limiter instance for failed authentication attempts
export const authRateLimiter = new AuthRateLimiter(20, 1 * 60 * 1000); // 20 attempts per 1 minute

// Clean up rate limiter entries every 10 minutes
setInterval(
  () => {
    authRateLimiter.cleanup();
  },
  10 * 60 * 1000,
);

/**
 * Get rate limiting identifier for authentication attempts
 * Uses IP address and endpoint for rate limiting
 */
export function getAuthRateLimitIdentifier(
  req: express.Request,
  endpoint: DatabaseEndpoint,
): string {
  const ip = req.ip || req.socket?.remoteAddress || "unknown";
  const endpointId = endpoint.uuid || endpoint.name || "unknown";
  return `${ip}:${endpointId}`;
}

/**
 * Rate-limit identifier for the UNAUTHENTICATED OAuth token endpoints —
 * /oauth/introspect and /oauth/revoke.
 *
 * FAILURE-ONLY, and that is a hard requirement rather than a preference. This
 * fork deliberately does not set express `trust proxy` (see
 * middleware/audit-context.middleware for why), so `req.ip` is the same
 * in-container address for every caller arriving through the tunnel: one
 * bucket for the entire organisation. A limiter that counted SUCCESSES here
 * would therefore let any single busy client throttle everyone else's MCP
 * traffic — an outage caused by the control meant to prevent one.
 *
 * Counting only failures is safe against exactly that, because a legitimate
 * caller presents a token this server previously issued and never scores.
 * Only invented, expired or wrong-client tokens accumulate, which is the
 * traffic worth refusing. It is the workable substitute for RFC 7662 §2.1's
 * "MUST require authorization": the clients here are secretless public PKCE
 * clients, so there is no credential to require.
 *
 * Keyed per route so spam at one endpoint cannot spend the other's budget, and
 * namespaced away from the endpoint data plane's identifiers so it cannot
 * spend that budget either.
 */
export function getPublicOAuthRateLimitIdentifier(
  req: express.Request,
  route: "introspect" | "revoke",
): string {
  const ip = req.ip || req.socket?.remoteAddress || "unknown";
  return `oauth-public:${route}:${ip}`;
}
