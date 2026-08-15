import express from "express";

import type { AuditAttributedRequest } from "@/lib/audit/audit-emitter";
import { AuthRateLimiter } from "@/lib/auth-rate-limiter";
import logger from "@/utils/logger";

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
 * NOTE it does NOT emit an audit row for a 429. Writing a row per refusal on
 * the path whose write volume is the thing being limited would reintroduce the
 * amplifier one layer up. A refusal is reported to the LOG instead, throttled
 * to one line a minute — see `reportRefusal` for why silence was not an option
 * either.
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
// process. `unref` because a housekeeping sweep must not be the reason a test
// run or a shutdown hangs: this process's lifetime is owned by the HTTP server
// in `index.ts`, never by a cleanup timer. The sibling sweep in
// `lib/auth-rate-limiter` — a module this one imports, so it is registered
// either way — is unref'd for the same reason.
setInterval(() => trpcRateLimiter.cleanup(), 10 * 60 * 1000).unref();

/** How long one reported refusal suppresses the next report. */
const REFUSAL_REPORT_INTERVAL_MS = 60 * 1000;

let refusalsTotal = 0;
let lastRefusalReportAt = 0;

/** Test seam: forget the counter and the throttle window. */
export function resetTrpcRefusalReportingForTesting(): void {
  refusalsTotal = 0;
  lastRefusalReportAt = 0;
}

/**
 * Make a refusal DETECTABLE without re-creating the amplifier.
 *
 * The 429 path deliberately writes no audit row (see the header). But a
 * limiter nobody can observe is indistinguishable from no limiter at all: a
 * flood would show up only as users reporting that the dashboard is failing,
 * and an operator could not separate that from an unrelated outage. A log line
 * costs an append to a rotating file rather than a row in an append-only table
 * with no prune path, which is why it is the safe place to be loud.
 *
 * Same shape as `reportAuditWriteFailure` in `lib/audit/audit-emitter`, for the
 * same reasons: the FIRST refusal reports immediately because detection must
 * not wait out a window, and the count is a RUNNING TOTAL since startup rather
 * than a per-window delta, because a delta is stranded whenever the burst that
 * produced it stops before the next report fires. WARN and not ERROR — a
 * refused request is this control working, and an alert that pages on the
 * control working is an alert someone turns off.
 *
 * The IP is JSON-stringified rather than interpolated raw: it arrives as a
 * header value, and an embedded newline in an interpolated log line forges
 * whole log entries — the same defect this fork already fixed on the mcp-proxy
 * connect line. Its length is bounded where it is stamped
 * (`middleware/audit-context.middleware`, AUDIT_IP_MAX), so it cannot pad the
 * line either.
 */
function reportRefusal(clientIp: string): void {
  refusalsTotal += 1;
  const now = Date.now();
  // The `!== 0` half matters under a mocked clock: a suite that pins Date to
  // the epoch would otherwise have its very first refusal silently swallowed.
  if (
    lastRefusalReportAt !== 0 &&
    now - lastRefusalReportAt < REFUSAL_REPORT_INTERVAL_MS
  ) {
    return;
  }
  lastRefusalReportAt = now;
  logger.warn(
    `[trpc] rate limit refused ${JSON.stringify(clientIp)}, ` +
      `${refusalsTotal} request(s) refused since startup`,
  );
}

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

    // The `trpc:` prefix is descriptive, not load-bearing: `trpcRateLimiter`
    // is its own `AuthRateLimiter` INSTANCE with its own Map, so `/trpc` volume
    // could not reach the endpoint data plane's or the public OAuth routes'
    // budgets even unprefixed. It is kept so an identifier read out of a heap
    // dump or a debugger names where it came from, and so that moving this onto
    // a shared instance later cannot silently merge the key spaces.
    if (limiter.isRateLimited(`trpc:${clientIp}`)) {
      // Retry-After is the window length rather than the exact remainder — the
      // limiter exposes no remainder, and an upper bound is the safe direction
      // to round for a client that honours it.
      res.set(
        "Retry-After",
        String(Math.ceil(TRPC_RATE_LIMIT_WINDOW_MS / 1000)),
      );
      reportRefusal(clientIp);
      res.status(429).json({ error: "Too many requests" });
      return;
    }

    next();
  };
}

export const trpcRateLimitMiddleware = createTrpcRateLimitMiddleware();
