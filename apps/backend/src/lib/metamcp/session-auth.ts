/**
 * Auth-principal helpers for the lazy-session-recovery path.
 *
 * The `mcp_sessions` table stores a SHA-256 hash of the auth credential
 * (bearer token or API key) plus a method discriminator so two clients
 * authenticating against the same endpoint with different credentials
 * can't accidentally share a session.
 *
 * Raw tokens are NEVER persisted. Comparison is constant-time via
 * `crypto.timingSafeEqual` so a timing oracle can't leak the stored
 * hash. The hash is one-way; even a full DB compromise reveals only
 * "someone with a token whose SHA-256 looks like X" — not the token
 * itself.
 *
 * Token rotation / revocation invalidates the recovery path: a new
 * token produces a new hash, the stored principal no longer matches,
 * the router refuses the lazy-recovery and the client must reinit
 * (which persists the new principal). That's the intended behavior —
 * a revoked token must not survive a metamcp restart.
 */

import { createHash, timingSafeEqual } from "node:crypto";

export type AuthMethod = "api_key" | "oauth";

/**
 * Hash a token + method into the principal stored in `mcp_sessions`.
 * Returns a hex-encoded SHA-256 digest. The method is included as a
 * prefix so an API key value and a Bearer token value that happen to
 * be identical (vanishingly unlikely but theoretically possible)
 * produce distinct principals.
 */
export function hashAuthPrincipal(token: string, method: AuthMethod): string {
  return createHash("sha256")
    .update(`${method}:${token}`, "utf8")
    .digest("hex");
}

/**
 * Constant-time compare of two hex-encoded principals. Returns true
 * only when both inputs are non-empty, hex-decodable, and byte-equal.
 *
 * The caller passes the freshly-computed hash of the incoming token
 * and the stored `auth_principal` from the DB; if either is missing
 * or malformed the function short-circuits to `false` without
 * leaking which side failed.
 */
export function principalMatches(candidate: string, stored: string): boolean {
  if (!candidate || !stored) {
    return false;
  }
  if (candidate.length !== stored.length) {
    return false;
  }
  let candidateBuf: Buffer;
  let storedBuf: Buffer;
  try {
    candidateBuf = Buffer.from(candidate, "hex");
    storedBuf = Buffer.from(stored, "hex");
  } catch {
    return false;
  }
  if (candidateBuf.length === 0 || candidateBuf.length !== storedBuf.length) {
    return false;
  }
  return timingSafeEqual(candidateBuf, storedBuf);
}
