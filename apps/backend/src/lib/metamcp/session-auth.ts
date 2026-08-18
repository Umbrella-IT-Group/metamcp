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
 * The identity a live in-memory session is bound to, alongside its endpoint.
 *
 * WHY THIS EXISTS SEPARATELY FROM `hashAuthPrincipal`. The principal hash above
 * guards the DB-backed recovery path, where the only thing the stored row can
 * be compared against is the raw credential the caller just presented. The
 * IN-MEMORY pool has a better source: `authenticateApiKey` has already resolved
 * the credential to a row, so the session can be bound to WHO the caller is
 * rather than to the exact secret they used.
 *
 * `anonymous` is a real member of the method set, not a hole. An endpoint
 * published through `ALLOW_UNAUTHENTICATED_ENDPOINTS` has no credential on any
 * request, so there is nothing to tell two callers apart and binding cannot
 * invent it — every caller on such an endpoint shares one identity. That is the
 * stated cost of the escape hatch, not a weakening of this check: it applies
 * only where the operator has already declared the endpoint public.
 */
export type SessionIdentityMethod = AuthMethod | "anonymous";

export interface SessionIdentity {
  method: SessionIdentityMethod;
  /**
   * The api key's uuid, or the OAuth user's id. Null only for `anonymous` and
   * for the defensive case where an authenticated method resolved no id at all.
   */
  credentialId: string | null;
}

/**
 * Derive the session identity from an authenticated request.
 *
 * Structurally typed rather than taking `ApiKeyAuthenticatedRequest` so this
 * module keeps its zero-dependency import graph (node:crypto only) — the
 * express request shape satisfies it without this file knowing about express.
 *
 * GRANULARITY, which is a deliberate choice per auth method rather than an
 * oversight:
 *
 *  - api_key -> the KEY uuid. Two keys owned by the same user are two
 *    credentials, and one must not inherit the other's session. This is as
 *    tight as the token hash in practice, since a key's secret is not
 *    rotatable in place.
 *
 *  - oauth -> the USER id, deliberately NOT the token. An access token lives
 *    24h and a connector refreshes it while holding the same `Mcp-Session-Id`;
 *    binding to the token would force a re-initialize on every refresh for a
 *    caller who is plainly the same principal. The access-control question is
 *    "is this the same principal", and the user id answers exactly that.
 */
export function resolveSessionIdentity(req: {
  authMethod?: AuthMethod;
  apiKeyUuid?: string;
  oauthUserId?: string;
}): SessionIdentity {
  if (req.authMethod === "api_key") {
    return { method: "api_key", credentialId: req.apiKeyUuid ?? null };
  }
  if (req.authMethod === "oauth") {
    return { method: "oauth", credentialId: req.oauthUserId ?? null };
  }
  return { method: "anonymous", credentialId: null };
}

/**
 * True only when a presented identity is the one a session was created under.
 *
 * A missing stored identity never matches — a session with no recorded identity
 * is treated as belonging to nobody rather than to everybody, the same
 * fail-closed direction `bindingMatches` takes for a missing endpoint binding.
 *
 * A null `credentialId` on an AUTHENTICATED method never matches either, in
 * both directions. That case means the middleware admitted a caller it could
 * not name, which should be unreachable — every api-key branch stamps
 * `apiKeyUuid` and every OAuth branch refuses a token with no user. Refusing it
 * costs a re-initialize if it ever happens; matching it would make one
 * unnameable session reusable by every other unnameable caller.
 */
export function identityMatches(
  stored: SessionIdentity | undefined,
  presented: SessionIdentity,
): boolean {
  if (!stored) return false;
  if (stored.method !== presented.method) return false;
  if (stored.method === "anonymous") return true;
  return (
    stored.credentialId !== null &&
    stored.credentialId === presented.credentialId
  );
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
