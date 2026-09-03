import type express from "express";

import type { Session, User } from "../auth";
import { ApiKeysRepository } from "../db/repositories/api-keys.repo";
import logger from "../utils/logger";
import {
  auditRequestContext,
  credentialFingerprint,
  emit,
} from "./audit/audit-emitter";
import {
  getAdminKeyRateLimitIdentifier,
  trpcAdminKeyRateLimiter,
} from "./auth-rate-limiter";

/**
 * The CONTROL-plane (admin-plane, migration 0038) bearer resolver for `/trpc`.
 *
 * This is the module `createContext` reaches through a LAZY dynamic import, the
 * same way it reaches the disabled-account check: it touches the repositories
 * and thus `db/index`, so a top-level import here would make `trpc.ts`
 * un-loadable without a database, and error-formatter.test.ts imports `trpc.ts`
 * with `../auth` mocked precisely because the tRPC instance is independent of
 * all that. Deferring the import keeps that true; the database is touched when a
 * BEARER request arrives, not when the router is defined.
 *
 * WHY A SYNTHETIC SESSION IS SAFE. Nothing downstream reads a session field:
 * protectedProcedure only tests `!ctx.session` for truthiness, and no impl reads
 * `ctx.session.*`. The synthesized session is truthy, carries an explicit
 * `token: "admin-plane-key"` marker so a heap dump names its origin, and is
 * never written to the sessions table. The owning user's RBAC is what gates what
 * the request may then do: `user.role` is read FRESH from the joined users row
 * per request, so a demoted owner's key degrades to member on the very next
 * request and adminProcedure returns FORBIDDEN, the column, not the key, is the
 * lever.
 */

const apiKeysRepository = new ApiKeysRepository();

/**
 * Kill switch (foreman ruling): ADMIN_PLANE_TOKEN_AUTH_DISABLED disables the
 * bearer path process-wide for emergencies. Strict `"true"` only, unset, empty,
 * `1`, `yes` and `TRUE` are all OFF, matching ALLOW_UNAUTHENTICATED_ENDPOINTS
 * and the other security-gate env reads in this codebase, so a near-miss
 * spelling cannot silently disarm the feature the wrong way. Read per request so
 * it can be flipped without a rebuild.
 */
export function adminPlaneTokenAuthDisabled(): boolean {
  return process.env.ADMIN_PLANE_TOKEN_AUTH_DISABLED === "true";
}

// One boot warn when the kill switch is set, so an operator who disabled the
// bearer path in an emergency can see it in the boot log rather than discovering
// it when CI cannot authenticate. Latched so "one warn at boot" holds even if
// the boot path calls it more than once, same shape as
// warnIfGatewayBackendSecretUnset.
let adminPlaneDisabledWarned = false;
export function warnIfAdminPlaneTokenAuthDisabled(): void {
  if (adminPlaneDisabledWarned) return;
  adminPlaneDisabledWarned = true;
  if (adminPlaneTokenAuthDisabled()) {
    logger.warn(
      "ADMIN_PLANE_TOKEN_AUTH_DISABLED=true: the admin-plane (control-plane) " +
        "tRPC bearer path is OFF. Admin-plane API keys will not authenticate " +
        "on /trpc until this is unset. Cookie/SSO sessions are unaffected.",
    );
  }
}

/** Test seam: clear the boot-warn latch so a suite can drive it twice. */
export function __resetAdminPlaneDisabledWarningForTesting(): void {
  adminPlaneDisabledWarned = false;
}

/**
 * One audit row per admin-plane request that resolves to a usable identity.
 * actor_id is the KEY uuid (the credential that authenticated), request_id/ip/ua
 * from the request context, and the detail carries the owning user id plus a
 * fingerprint of the token, never the token itself. The fingerprint (sha256 +
 * last4) correlates repeated use of one key across rows and joins against
 * api_keys.key_hash without the audit table ever holding the secret.
 */
function emitAccepted(
  req: express.Request,
  token: string,
  userId: string,
  keyUuid: string,
): void {
  try {
    const ctx = auditRequestContext(req);
    emit({
      actor_type: "api_key",
      actor_id: keyUuid,
      actor_label: null,
      actor_ip: ctx.actor_ip,
      actor_user_agent: ctx.actor_user_agent,
      action: "authn.admin_key.accepted",
      target_type: "user",
      target_id: userId,
      outcome: "success",
      request_id: ctx.request_id,
      http_status: 200,
      detail: { user_id: userId, key: credentialFingerprint(token) },
    });
  } catch {
    // An audit failure must never change what authentication answers. Same
    // contract as emitMcpAuthDenial in the data-plane middleware.
  }
}

/**
 * One audit row per REFUSED admin-plane bearer, the forensic record for the
 * stolen/misused-key threat cases. actor_id is NULL, the key did not resolve to
 * a usable identity, and the reason distinguishes the four refusal causes. The
 * failure limiter above is what stops this becoming an INSERT amplifier.
 */
function emitDenied(
  req: express.Request,
  token: string,
  reason: "unknown_key" | "inactive" | "not_admin_plane" | "owner_disabled",
): void {
  try {
    const ctx = auditRequestContext(req);
    emit({
      actor_type: "api_key",
      actor_id: null,
      actor_label: null,
      actor_ip: ctx.actor_ip,
      actor_user_agent: ctx.actor_user_agent,
      action: "authn.admin_key.denied",
      target_type: null,
      target_id: null,
      outcome: "denied",
      request_id: ctx.request_id,
      http_status: 401,
      detail: { reason, key: credentialFingerprint(token) },
    });
  } catch {
    // See emitAccepted.
  }
}

/**
 * Resolve a bearer token to an admin-plane session, or null.
 *
 * Returns `{ user, session }` when the key is valid, active, admin_plane, and
 * its owner is not disabled. Returns null for every other case (unknown key,
 * inactive, data-plane key, disabled owner, kill switch), and createContext then
 * leaves the request unauthenticated, protectedProcedure returns its normal
 * UNAUTHORIZED. Fail-closed throughout.
 *
 * The rate-limit RECORD lives here (one count per failed verification); the
 * CHECK (the 429) lives in the middleware ahead of createContext, which skips it
 * for cookie-carrying requests so a valid cookie user is never refused.
 */
export async function resolveAdminPlaneSession(
  token: string,
  req: express.Request,
): Promise<{ user: User; session: Session } | null> {
  // Kill switch: the whole path is off. Not a failed verification and not an
  // "admin-plane request" to record or audit, a bearer here is simply
  // unauthenticated. Returning before the DB read also means a flood while the
  // switch is on cannot amplify audit writes.
  if (adminPlaneTokenAuthDisabled()) return null;

  const result = await apiKeysRepository.validateAdminPlaneApiKey(token);

  if (!result.valid) {
    trpcAdminKeyRateLimiter.recordFailedAttempt(
      getAdminKeyRateLimitIdentifier(req),
    );
    emitDenied(req, token, result.reason);
    return null;
  }

  // Disabled owner (account lock, migration 0027): fail closed, mirroring
  // usersRepository.isDisabled's contract. Counted as a failed verification,
  // a locked-out owner's key retrying in a loop must not run unbounded.
  if (result.disabled) {
    trpcAdminKeyRateLimiter.recordFailedAttempt(
      getAdminKeyRateLimitIdentifier(req),
    );
    emitDenied(req, token, "owner_disabled");
    return null;
  }

  emitAccepted(req, token, result.user.id, result.key_uuid);

  // Built from the joined users row and cast to the better-auth types. `role`
  // travels here fresh from the DB, so adminProcedure sees the owner's CURRENT
  // role. The session is synthetic (never persisted) and truthy; its marker
  // token names its origin in a heap dump.
  const user = {
    id: result.user.id,
    email: result.user.email,
    name: result.user.name,
    emailVerified: result.user.emailVerified,
    image: result.user.image,
    role: result.user.role,
    createdAt: result.user.createdAt,
    updatedAt: result.user.updatedAt,
  } as unknown as User;

  const session = {
    id: `admin-plane-${result.key_uuid}`,
    token: "admin-plane-key",
    userId: result.user.id,
    createdAt: new Date(),
    updatedAt: new Date(),
    // Near-future expiry so anything that reads it sees a live session; it is
    // never written and never renewed.
    expiresAt: new Date(Date.now() + 60 * 1000),
  } as unknown as Session;

  return { user, session };
}
