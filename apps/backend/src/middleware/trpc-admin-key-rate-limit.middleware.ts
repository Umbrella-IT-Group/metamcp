import express from "express";

import {
  AuthRateLimiter,
  getAdminKeyRateLimitIdentifier,
  trpcAdminKeyRateLimiter,
} from "@/lib/auth-rate-limiter";

/**
 * A failure-only 429 gate for the admin-plane (control-plane) bearer path on
 * `/trpc` (migration 0038). Mounted AFTER trpcRateLimitMiddleware, so the
 * 600/min/IP request cap still bounds total volume ahead of it and a 429 here
 * carries the CORS headers the browser needs to surface it.
 *
 * This middleware only CHECKS; the RECORD (one count per failed verification)
 * lives in lib/admin-plane-auth when a bearer fails to resolve. Split check and
 * record so a request costs exactly one count, the pattern lib/auth-rate-limiter
 * documents at length.
 *
 * COOKIE PRECEDENCE (foreman ruling): a request carrying a session cookie is
 * skipped entirely, so a stale Authorization header on a cookie-authenticated
 * user can never draw a 429. createContext resolves the cookie first and never
 * reaches the bearer path for such a request, so it also never RECORDS a failure
 *, the two halves agree. The residual is deliberate: a caller can attach a junk
 * cookie to skip this CHECK, but its bearer attempt is still recorded and
 * audited, and an admin-plane key is sk_mt_ + 64 chars of nanoid entropy, not
 * something a rate limiter is what stands between it and a guess (threat case 1:
 * the control is revocation and detection, not brute-force resistance). The
 * limiter's job is to keep FAILED verifications from amplifying audit writes,
 * which the record-on-failure half still does regardless of the cookie.
 */

export const ADMIN_KEY_RATE_LIMIT_WINDOW_MS = 60 * 1000;

export function createTrpcAdminKeyRateLimitMiddleware(
  limiter: AuthRateLimiter = trpcAdminKeyRateLimiter,
) {
  return (
    req: express.Request,
    res: express.Response,
    next: express.NextFunction,
  ) => {
    const authHeader = req.headers.authorization;
    // Only Bearer-carrying requests can reach the admin-plane path; nothing else
    // is this limiter's concern.
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      next();
      return;
    }

    // Cookie precedence: a cookie user is never refused here. See the header.
    if (req.headers.cookie) {
      next();
      return;
    }

    if (limiter.isCurrentlyLimited(getAdminKeyRateLimitIdentifier(req))) {
      // Retry-After is the window length rather than the exact remainder, the
      // limiter exposes no remainder, and an upper bound is the safe direction
      // for a client that honours it. Same shape as trpcRateLimitMiddleware.
      res.set(
        "Retry-After",
        String(Math.ceil(ADMIN_KEY_RATE_LIMIT_WINDOW_MS / 1000)),
      );
      res.status(429).json({
        error: "too_many_requests",
        error_description:
          "Too many failed authentication attempts. Please try again later.",
        timestamp: new Date().toISOString(),
      });
      return;
    }

    next();
  };
}

export const trpcAdminKeyRateLimitMiddleware =
  createTrpcAdminKeyRateLimitMiddleware();
