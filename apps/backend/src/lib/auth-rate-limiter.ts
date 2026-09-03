import { DatabaseEndpoint } from "@repo/zod-types";
import express from "express";

import { resolveClientIp } from "@/lib/client-ip";

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
   *
   * It is also the right question wherever a call site RECORDS as well, which
   * every failed-credential path here does: check with this, then record, and a
   * failed request costs one count. Asking `isRateLimited` beside a
   * `recordFailedAttempt` costs two, and the enforced allowance is half the
   * constructor argument — see the budget note on getAuthRateLimitIdentifier.
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

// Create rate limiter instance for failed authentication attempts.
//
// Twenty failures per minute per (caller, endpoint), and the number here is
// now the number that is enforced. See the budget note on
// `getAuthRateLimitIdentifier` below for what it used to be and why.
export const authRateLimiter = new AuthRateLimiter(20, 1 * 60 * 1000);

// Failed admin-plane bearer verifications on `/trpc` (migration 0038), its own
// instance with its own Map. FAILURE-ONLY and keyed per client IP with the
// no-header class BUCKETED (see getAdminKeyRateLimitIdentifier), a limiter that
// counts only FAILED admin-key verifications can only ever inconvenience callers
// already failing to authenticate, so a shared no-header bucket is the cheap
// failure and a valid admin-plane request never scores. Separate from the
// sign-in limiter (which keys on `/api/auth` sign-in attempts and caps
// successes too) and from authRateLimiter (endpoint data plane): sharing a
// bucket would conflate three different questions. The 600/min/IP trpc request
// limiter still sits in front and bounds total volume. Same 20/min/IP
// failed-auth default as authRateLimiter.
export const trpcAdminKeyRateLimiter = new AuthRateLimiter(20, 1 * 60 * 1000);

// Clean up rate limiter entries every 10 minutes.
//
// `unref` because this sweep is housekeeping and must never own the process's
// lifetime — that belongs to the HTTP server in `index.ts`. Without it, merely
// IMPORTING this module (a test file, a CLI script, anything that reaches
// `AuthRateLimiter` or the identifier helpers below) registers a 10-minute
// timer that keeps the event loop alive until something force-exits, which is
// a hang with no visible cause. Same treatment as the sibling sweep in
// `middleware/trpc-rate-limit.middleware`. Both AuthRateLimiter instances in
// this module are swept by the one timer.
setInterval(
  () => {
    authRateLimiter.cleanup();
    trpcAdminKeyRateLimiter.cleanup();
  },
  10 * 60 * 1000,
).unref();

/**
 * Rate-limit identifier for failed authentication attempts against an endpoint,
 * keyed per (caller, endpoint).
 *
 * KEYED ON CF-Connecting-IP, not `req.ip`. It used to key on `req.ip`, and
 * behind this deployment that is the same in-container address for every
 * caller — the backend is reached through the frontend's Next.js rewrite, and
 * `trust proxy` is deliberately off (middleware/audit-context.middleware
 * documents why at length). So the budget was ONE bucket per endpoint for the
 * entire world, which inverts what the limiter is for: rather than bounding a
 * brute force, it handed anyone who could reach the endpoint a way to lock out
 * every legitimate caller of it for the rest of the window, at a cost of
 * eleven requests. A single consumer retrying a stale credential in a loop did
 * the same thing by accident.
 *
 * WHAT THE BUDGET IS: twenty failed attempts per minute per (caller, endpoint),
 * the twentieth answered as a normal 401 and the twenty-first refused with a
 * 429. The constructor argument and the enforced allowance are the same number.
 *
 * THEY USED NOT TO BE, and the reason is worth keeping because it is easy to
 * reintroduce. All three call sites in middleware/api-key-oauth.middleware
 * paired `recordFailedAttempt(id)` with `isRateLimited(id)`, and
 * `isRateLimited` COUNTS the question it is asked — precisely the hazard
 * `isCurrentlyLimited` exists to avoid and documents above. Two counts landed
 * per failed request, so refusal arrived on the eleventh failure rather than
 * the twenty-first: a nominal twenty enforced as roughly ten. The sites now
 * check with `isCurrentlyLimited` first and record afterwards, which costs one
 * count per failure, and the test file pins the exact boundary by driving that
 * production pair rather than the counter directly.
 *
 * The one behavioural difference beyond the allowance: a request refused with a
 * 429 no longer adds to the count, because it never reached the credential
 * check. Nothing depends on that count growing during a refusal — a record
 * inside an open window does not extend the window either — so a caller over
 * budget stays refused for exactly the rest of the window it opened.
 *
 * Cloudflare overwrites CF-Connecting-IP at the edge on every request, so it is
 * per-CALLER rather than per-container. The trust assumption is exactly the one
 * audit-context.middleware states: it holds only while the Cloudflare Tunnel is
 * the sole ingress. `req.ip` stays the fallback for direct-to-origin and local
 * development, where the identifier degrades to the shared bucket it was — no
 * worse than before, and never a throw on an auth-failure path.
 *
 * THE NO-HEADER CLASS IS BUCKETED HERE, NOT EXEMPTED, which is the opposite of
 * what `trpcRateLimitMiddleware` decides for the same class, so the divergence
 * is deliberate. That limiter caps request RATE and can afford to wave through
 * traffic that never crossed the tunnel; this one counts FAILED CREDENTIALS,
 * and exempting a class would mean anyone able to omit the header gets no
 * brute-force bound at all. Collapsing in-container and local-development
 * callers into one shared bucket is the cheap failure of the two: it can only
 * inconvenience callers that are already failing to authenticate.
 *
 * Same fix, same reasoning, as `rateLimitRegistration` in routers/oauth/utils
 * and `trpcRateLimitMiddleware` in middleware/trpc-rate-limit.middleware.
 *
 * THE RESIDUAL, PLAINLY, in two parts. Per-IP keying bounds a source address,
 * not a distributed caller; that is the same trade those two siblings took, and
 * what it buys is that the control can no longer be turned into the outage.
 * The second part is new and runs the other way: wherever CF-Connecting-IP is
 * caller-settable, a caller mints a FRESH bucket per request and the
 * failed-auth bound disappears entirely — where the old shared bucket, for all
 * its faults, still capped them. That is not hypothetical at the artifact
 * level: the shipped docker-compose publishes 12008 host-wide rather than
 * binding loopback, so an origin reachable beside the tunnel is a deployment
 * away. Same property, same re-check, as the header's trust assumption itself:
 * it must be revisited before any change to how this service is published.
 */
export function getAuthRateLimitIdentifier(
  req: express.Request,
  endpoint: DatabaseEndpoint,
): string {
  const ip =
    resolveClientIp(req.headers) ||
    req.ip ||
    req.socket?.remoteAddress ||
    "unknown";
  const endpointId = endpoint.uuid || endpoint.name || "unknown";
  return `${ip}:${endpointId}`;
}

/**
 * Rate-limit identifier for the UNAUTHENTICATED-in-effect public OAuth token
 * endpoints /oauth/introspect and /oauth/revoke. (/oauth/userinfo carries the
 * same failure-only discipline but keys on the edge client IP instead of this
 * shared in-container req.ip; see userinfoRateLimitIdentifier in userinfo.ts.)
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

/**
 * Rate-limit identifier for FAILED admin-plane bearer verifications on `/trpc`
 * (migration 0038), keyed per client IP.
 *
 * Keyed on CF-Connecting-IP like getAuthRateLimitIdentifier, for the same
 * reason: `req.ip` is the same in-container address for every caller behind the
 * Next.js rewrite (`trust proxy` is off), so it would be one shared bucket.
 *
 * THE NO-HEADER CLASS IS BUCKETED, not exempted, the opposite of
 * trpcRateLimitMiddleware's decision for the same class, and deliberate: this
 * counts FAILED CREDENTIALS, so exempting a class would hand anyone able to omit
 * the header an unbounded stream of admin-key guesses. Collapsing in-container
 * and local-development callers into one `no-trusted-ip` bucket is the cheap
 * failure: it can only inconvenience callers already failing to authenticate,
 * and a valid admin-plane request never scores. Namespaced so it can never
 * spend the endpoint data plane's or the public OAuth routes' budgets.
 */
export function getAdminKeyRateLimitIdentifier(req: express.Request): string {
  const ip =
    resolveClientIp(req.headers) ||
    req.ip ||
    req.socket?.remoteAddress ||
    "no-trusted-ip";
  return `trpc-admin-key:${ip}`;
}
