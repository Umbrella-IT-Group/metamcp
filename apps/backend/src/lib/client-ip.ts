import express from "express";

import { AUDIT_IP_MAX, clampAuditText } from "@/lib/audit/audit-emitter";

/**
 * Naming the caller of a request, for everything that needs to.
 *
 * WHY THIS SITS IN `lib/` RATHER THAN BESIDE THE MIDDLEWARE THAT INTRODUCED IT.
 * It was defined in `middleware/audit-context.middleware`, which is still where
 * the trust assumption and the `trust proxy` decision are written down at
 * length — read that first. It moved here because it stopped being an audit
 * concern: the rate limiters key on it too, and `lib/auth-rate-limiter` is a
 * `lib/` module. `middleware/` imports `lib/` throughout this codebase and
 * `lib/` imports `middleware/` nowhere, so importing upward would have made
 * those two directories mutually dependent — the shape that turns into a real
 * import cycle the first time anything else is added. `audit-context.middleware`
 * re-exports both names, so existing importers are unaffected.
 */

/** Cloudflare's single-value, edge-overwritten client IP header. */
export const CLIENT_IP_HEADER = "cf-connecting-ip";

/**
 * Pull the caller IP out of a header bag.
 *
 * Exported for tests. Returns undefined rather than a placeholder when the
 * header is absent (direct-to-origin calls, local development): a NULL
 * `actor_ip` is an honest "not known", while a fabricated one would be read
 * as evidence. Callers that need a key rather than a record — the rate
 * limiters — supply their own fallback instead.
 *
 * CLAMPED HERE, at the stamping site, rather than at each emitter. Every audit
 * row's `actor_ip` and every `x-audit-client-ip` the `/api/auth` relay stamps
 * are read from `auditClientIp`, so bounding it once here bounds all of them,
 * and a future emitter cannot forget to. See AUDIT_IP_MAX in
 * `lib/audit/audit-emitter` for why 64 loses no evidence. The bound does
 * double duty for the limiters: it is what stops a caller from spending
 * unbounded map memory by rotating a very long header value.
 */
export function resolveClientIp(
  headers: express.Request["headers"],
): string | undefined {
  const raw = headers[CLIENT_IP_HEADER];
  // Express lower-cases header names but an array is still possible if a
  // caller sends the header twice. Take the first value; a duplicated
  // CF-Connecting-IP is not something Cloudflare produces, so anything here
  // is malformed input and picking deterministically beats throwing.
  const value = Array.isArray(raw) ? raw[0] : raw;
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  return trimmed === "" ? undefined : clampAuditText(trimmed, AUDIT_IP_MAX);
}
