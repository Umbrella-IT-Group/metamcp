import express from "express";

import type { AuditAttributedRequest } from "@/lib/audit/audit-emitter";
import { AuthRateLimiter } from "@/lib/auth-rate-limiter";

/**
 * A per-caller request cap on `/trpc`, which had none.
 *
 * WHY THIS ROUTER SPECIFICALLY. `routers/trpc.ts` mounted helmet, cors and the
 * handler and nothing else, so nothing bounded how fast one caller could reach
 * it. That is not merely a load question: `protectedProcedure` in
 * `@repo/trpc` emits an `authn.denied` audit row on EVERY unauthenticated
 * call, so an anonymous flood against any procedure name is a request-to-INSERT
 * amplifier against an append-only table (migration 0028 blocks UPDATE, DELETE
 * and TRUNCATE, so nothing can be reclaimed afterwards). `db/audit-db` already
 * bounds the damage a flood can do to the AUTH path — the audit pool is
 * `max: 2` with a 1s checkout timeout — but bounding the blast radius is not
 * the same as bounding the writes, and this is the writes.
 *
 * KEYED ON `auditClientIp`, NOT `req.ip`, and that is the whole design.
 * `req.ip` is what the two identifiers in `lib/auth-rate-limiter` key on, and
 * both are documented there as a SINGLE SHARED ORG BUCKET: this fork
 * deliberately leaves express `trust proxy` unset (see
 * `audit-context.middleware` for the reasoning), so behind the in-container
 * Next.js rewrite `req.ip` is the same loopback address for every human on
 * earth. A request-rate limiter on that key is not a limiter, it is a
 * scheduled outage — the first busy admin spends the budget for everyone.
 * `auditClientIp` is `CF-Connecting-IP`, which the Cloudflare edge OVERWRITES
 * rather than appends to, so it is both per-caller and not caller-forgeable
 * while the tunnel is the sole ingress. `auditContextMiddleware` is mounted
 * first in `index.ts`, so the field is always stamped by the time this runs.
 *
 * THE NO-HEADER CLASS IS EXEMPT, not bucketed together, and this is the
 * decision most worth re-reading before changing it. A request with no
 * `CF-Connecting-IP` did not come through the tunnel: in production that means
 * in-container traffic (the Next.js rewrite's own calls, health checks), and
 * outside production it means local development. Collapsing all of them into
 * one shared "unknown" key would re-create exactly the failure this limiter
 * exists to avoid — one bucket that any single caller can exhaust on behalf of
 * everyone else in it — and it would do so on the internal callers, which is
 * the worst set to throttle. The honest cost of exempting them: an attacker
 * who reaches the origin DIRECTLY skips this limiter. That attacker has
 * already defeated the ingress assumption every `actor_ip` in the archive
 * rests on, and the `max: 2` audit pool is what bounds them; re-opening a
 * shared-bucket outage to cover a case that already invalidates the trust
 * model is the wrong trade.
 *
 * BUDGET. 600 requests per minute per client IP, i.e. 10/s sustained. The
 * frontend uses `httpBatchLink`, so a dashboard's many procedure calls
 * collapse into few HTTP requests, and the bucket can legitimately hold a
 * whole office behind one NAT egress — the limit is set high above real UI
 * burst on purpose, because a limiter that trips on normal admin use gets
 * removed. It is a ceiling on abuse, not a throttle on use.
 *
 * RESIDUAL, stated rather than hidden: batching means one HTTP request may
 * carry several procedure calls, so this caps requests and not audit rows
 * exactly. It converts an unbounded row rate into a bounded multiple of 600 a
 * minute per IP, which is the property that matters; a per-batch cap would
 * need the tRPC adapter to expose one.
 *
 * NOTE it does NOT emit an audit row for a 429. Logging every refusal on the
 * path whose write volume is the thing being limited would reintroduce the
 * amplifier one layer up.
 */

/** Requests per window, per client IP. Deliberately far above real UI burst. */
export const TRPC_RATE_LIMIT_MAX = 600;
export const TRPC_RATE_LIMIT_WINDOW_MS = 60 * 1000;

const trpcRateLimiter = new AuthRateLimiter(
  TRPC_RATE_LIMIT_MAX,
  TRPC_RATE_LIMIT_WINDOW_MS,
);

// The limiter's Map grows one entry per distinct client IP per window, so an
// address-rotating flood would otherwise leak memory for the life of the
// process. `unref` so this timer never holds the event loop open — a
// housekeeping sweep must not be the reason a test run or a shutdown hangs.
setInterval(() => trpcRateLimiter.cleanup(), 10 * 60 * 1000).unref();

/**
 * Factory so a test can supply a limiter with a small budget instead of
 * driving 600 real requests through the middleware.
 */
export function createTrpcRateLimitMiddleware(
  limiter: AuthRateLimiter = trpcRateLimiter,
) {
  return (
    req: express.Request,
    res: express.Response,
    next: express.NextFunction,
  ) => {
    const clientIp = (req as AuditAttributedRequest).auditClientIp;
    if (!clientIp) {
      next();
      return;
    }

    // Namespaced so `/trpc` volume cannot spend the budget of the endpoint
    // data plane or the public OAuth routes, which share the class but not the
    // key space.
    if (limiter.isRateLimited(`trpc:${clientIp}`)) {
      // Retry-After is the window length rather than the exact remainder — the
      // limiter exposes no remainder, and an upper bound is the safe direction
      // to round for a client that honours it.
      res.set(
        "Retry-After",
        String(Math.ceil(TRPC_RATE_LIMIT_WINDOW_MS / 1000)),
      );
      res.status(429).json({ error: "Too many requests" });
      return;
    }

    next();
  };
}

export const trpcRateLimitMiddleware = createTrpcRateLimitMiddleware();
