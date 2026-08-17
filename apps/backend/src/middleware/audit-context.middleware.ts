import { randomUUID } from "node:crypto";

import express from "express";

import type { AuditAttributedRequest } from "@/lib/audit/audit-emitter";
import { resolveClientIp } from "@/lib/client-ip";

/**
 * Stamps the two per-request fields every audit row needs: a request id and
 * the caller's real IP.
 *
 * WHY A CLIENT IP NEEDS ITS OWN MIDDLEWARE. Nothing in this gateway could
 * previously name the caller of a request. `req.ip` is read in three places
 * (`auth-rate-limiter.ts`, `oauth/utils.ts` twice) and in production it is the
 * same loopback address for every human on earth, because the backend is
 * reached through the frontend's in-container Next.js rewrite —
 * `oauth/utils.ts` already documents that for the consent limiter. An audit
 * log whose `actor_ip` column says `127.0.0.1` on every row does not answer
 * the one question a responder asks first, so this reads
 * `CF-Connecting-IP` instead.
 *
 * TRUST ASSUMPTION, stated because it is load-bearing: `CF-Connecting-IP` is
 * written by the Cloudflare edge and OVERWRITTEN (not appended to) on every
 * request, so a client cannot forge it THROUGH Cloudflare. It is only
 * trustworthy while the Cloudflare Tunnel is the sole ingress to this
 * gateway. Expose the origin directly — a LAN port map, a second ingress, a
 * bypassed tunnel — and the header becomes caller-controlled, and every
 * `actor_ip` in the archive becomes an assertion by the attacker. That
 * property must be re-checked before any change to how this service is
 * published.
 *
 * WHY `trust proxy` IS DELIBERATELY NOT SET HERE. The obvious companion
 * change — `app.set("trust proxy", <n>)` — is not made, and the omission is a
 * decision rather than an oversight. `trust proxy` does not affect this
 * middleware at all (it changes `req.ip`, which nothing here reads); what it
 * would change is the three EXISTING `req.ip` consumers, all of them rate
 * limiters. With it on, `req.ip` becomes an entry from `X-Forwarded-For`, and
 * unlike `CF-Connecting-IP` that header is APPENDED to — Cloudflare preserves
 * whatever the client sent and adds to it. Which entry express picks depends
 * on the exact hop count of `client → Cloudflare → cloudflared → Next.js
 * rewrite → express`, including whether the Next.js proxy appends a hop of
 * its own. Guess that number too high and the auth rate limiter keys on a
 * caller-supplied string, i.e. a brute-force limiter an attacker can evade by
 * rotating a header — strictly worse than today's single shared bucket.
 * Settling it requires one header dump from the live gateway (log the raw
 * `X-Forwarded-For` alongside `CF-Connecting-IP` for one real request), which
 * is a production observation, not something this change can assert. Audit
 * attribution does not need it, so it is left for the lane that can verify
 * it.
 *
 * Mounted FIRST in `index.ts`, before the body parser and every router, so
 * that every request — including the raw-stream `/mcp-proxy` and `/metamcp`
 * legs that skip JSON parsing — carries the fields. It only sets two
 * properties on `req`; it reads no body and consumes no stream.
 */

/**
 * Re-exported, not re-defined. The header name and the resolver moved to
 * `lib/client-ip` once the rate limiters started keying on them too — a `lib/`
 * module cannot import upward into `middleware/` without inverting this
 * codebase's layering. That file carries the rationale; these re-exports keep
 * every existing importer, and this file's own tests, pointed here.
 */
export { CLIENT_IP_HEADER, resolveClientIp } from "@/lib/client-ip";

export const auditContextMiddleware = (
  req: express.Request,
  _res: express.Response,
  next: express.NextFunction,
) => {
  const attributed = req as AuditAttributedRequest;
  try {
    attributed.auditRequestId = randomUUID();
    attributed.auditClientIp = resolveClientIp(req.headers);
  } catch {
    // Same contract as the emitter itself: attribution is best-effort and
    // must never fail the request it describes. A row with a null request_id
    // is a degraded record; a 500 here would be an outage on every route.
  }
  next();
};
