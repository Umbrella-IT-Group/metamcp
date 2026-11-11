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
 * COOKIE PRECEDENCE: a request carrying a Cookie header is DEFERRED, not
 * exempted. Whether a cookie authenticates is only known once its session is
 * resolved, and that happens in createContext (`trpc.ts`); resolving it here
 * as well would duplicate the session lookup on every cookie request. So this
 * middleware passes cookie-carrying requests on, and createContext runs the
 * same read-only check, on the same identifier, at the point it reaches the
 * bearer path: only when the cookie resolved no usable session. A user whose
 * cookie resolves a valid, enabled session never reaches that check, so a
 * stale Authorization header on a signed-in user can never draw a 429; a
 * cookie that resolves nothing gets the same budget as no cookie at all.
 * createContext answers that case with a tRPC TOO_MANY_REQUESTS (HTTP 429)
 * carrying the Retry-After and sentence below.
 *
 * The limiter's job is to keep FAILED verifications from amplifying audit
 * writes and database lookups. An admin-plane key is sk_mt_ + 64 chars of
 * nanoid entropy, so this is not what stands between a key and a guess
 * (threat case 1: the control is revocation and detection).
 */

export const ADMIN_KEY_RATE_LIMIT_WINDOW_MS = 60 * 1000;

/** The refusal sentence, shared with createContext's 429 for the same budget. */
export const ADMIN_KEY_RATE_LIMIT_MESSAGE =
  "Too many failed authentication attempts. Please try again later.";

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

    // Cookie-carrying requests are checked in createContext once the cookie
    // has resolved no session. See the header.
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
        error_description: ADMIN_KEY_RATE_LIMIT_MESSAGE,
        timestamp: new Date().toISOString(),
      });
      return;
    }

    next();
  };
}

export const trpcAdminKeyRateLimitMiddleware =
  createTrpcAdminKeyRateLimitMiddleware();
