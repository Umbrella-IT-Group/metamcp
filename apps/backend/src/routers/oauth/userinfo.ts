import express from "express";

import {
  auditRequestContext,
  credentialFingerprint,
  emit,
} from "@/lib/audit/audit-emitter";
import {
  authRateLimiter,
  getPublicOAuthRateLimitIdentifier,
} from "@/lib/auth-rate-limiter";
import logger from "@/utils/logger";

import { oauthRepository, usersRepository } from "../../db/repositories";

const userinfoRouter = express.Router();

/**
 * Failure-only rate limiting for GET /oauth/userinfo, the same limiter shape
 * /oauth/introspect and /oauth/revoke carry (see token.ts and
 * getPublicOAuthRateLimitIdentifier). Failure-only is the requirement: with
 * `trust proxy` off the bucket is per-edge-IP and a caller presenting a token
 * this server issued must never score, so only tokens that resolve to nothing —
 * missing, malformed, unknown, or expired — accumulate. A disabled account's
 * real token is deliberately NOT counted, matching the introspect handler:
 * counting it would let one locked-out account's still-running client spend the
 * shared budget and refuse everyone on the same edge IP.
 *
 * `isCurrentlyLimited`, not `isRateLimited`, so the pre-work gate does not
 * itself count; failures are recorded explicitly on the branches below.
 */
function isUserinfoRateLimited(req: express.Request): boolean {
  return authRateLimiter.isCurrentlyLimited(
    getPublicOAuthRateLimitIdentifier(req, "userinfo"),
  );
}

function recordUserinfoFailure(req: express.Request): void {
  authRateLimiter.recordFailedAttempt(
    getPublicOAuthRateLimitIdentifier(req, "userinfo"),
  );
}

/**
 * Render a row timestamp for `detail`, tolerating a missing or null value.
 *
 * Local twin of the helper in ./token.ts, deliberately not shared: hoisting a
 * one-line formatter into `lib/audit` would put a router detail in the audit
 * library's API for no gain. `refresh_token_expires_at` is genuinely nullable,
 * and an emitter that called `.toISOString()` straight would turn one
 * unexpected null into a 500 on a request that was already being refused.
 */
function isoOrNull(value: Date | null | undefined): string | null {
  return value instanceof Date ? value.toISOString() : null;
}

/**
 * Record the destruction of an expired access token, before it is destroyed.
 *
 * The branch below DELETES a real, currently-stored token row and answers 401.
 * Until this emitter existed it wrote nothing anywhere — no audit row, no log
 * line — so the credential and every trace of when it had been minted vanished
 * in the same request. This is the same defect, and the same fix, as the
 * expired-code / expired-refresh / expired-introspect branches in ./token.ts,
 * whose `emitTokenLifecycle` header carries the full emit/no-emit doctrine.
 *
 * IT IS EMITTED FOR THE SAME REASON THEY ARE, which is not severity but replay
 * amplification: `audit_log` has no prune path, so a branch an anonymous caller
 * can reach with an invented string must never write to it. This branch cannot
 * be reached with an invented string — it requires a token this server issued
 * and still holds — and reaching it deletes that token, so a replay finds
 * nothing and writes nothing. One row per credential destroyed.
 *
 * THE RESIDUAL, STATED HERE BECAUSE THIS ENDPOINT CARRIES THE MOST OF IT: that
 * is one row per destroy ATTEMPT. Read-then-delete is not atomic and
 * `deleteAccessToken` returns void rather than a row count, so N concurrent
 * presentations of the SAME expired token each read the row before the first
 * delete commits and each write a row. /oauth/userinfo now carries the same
 * failure-only limiter as /oauth/introspect and /oauth/revoke (the expired
 * branch below records a failure), so a burst of the same expired token is
 * bounded at roughly one window's budget per edge IP rather than unbounded —
 * where before it had no limiter at all. Emit-first is kept anyway, because the
 * alternative is to emit AFTER a delete that reports what it removed, which
 * loses the record in precisely the failed-delete case this ordering exists
 * for. ./token.ts's `emitTokenLifecycle` header states the same trade for the
 * other three branches.
 *
 * `oauth.token.userinfo` rather than `oauth.userinfo`: the subject of the event
 * is the token, and this endpoint is the second half of the same token-metadata
 * plane as `oauth.token.introspect`. Keeping the prefix keeps one credential's
 * whole life queryable with `action LIKE 'oauth.token.%'`.
 *
 * The token is recorded ONLY as a sha256 + last-4 fingerprint, matching every
 * other emitter on this plane, so it stays joinable to the `oauth.token.issue`
 * row that minted it without the append-only table ever holding the credential.
 */
function emitExpiredTokenDestroyed(
  req: express.Request,
  tokenData: {
    client_id: string;
    user_id: string;
    created_at?: Date | null;
    expires_at?: Date | null;
    refresh_token_expires_at?: Date | null;
  },
  token: string,
): void {
  const audit = auditRequestContext(req);
  const fingerprint = credentialFingerprint(token);
  emit({
    actor_type: "user",
    actor_id: tokenData.user_id,
    actor_label: null,
    actor_ip: audit.actor_ip,
    actor_user_agent: audit.actor_user_agent,
    action: "oauth.token.userinfo",
    target_type: "oauth_client",
    target_id: tokenData.client_id,
    outcome: "failure",
    request_id: audit.request_id,
    http_status: 401,
    detail: {
      token_sha256: fingerprint.sha256,
      token_last4: fingerprint.last4,
      reason: "access_token_expired",
      token_type: "access_token",
      // The chain's age is the forensic content — it is what the deleted row
      // was carrying and what nothing else records once the row is gone.
      created_at: isoOrNull(tokenData.created_at),
      expires_at: isoOrNull(tokenData.expires_at),
      // In the row because this delete takes the WHOLE row: a refresh token
      // that had not itself expired dies with the access token.
      refresh_token_expires_at: isoOrNull(tokenData.refresh_token_expires_at),
    },
  });
}

/**
 * OAuth 2.0 UserInfo Endpoint
 * Returns information about the authenticated user
 */
userinfoRouter.get("/oauth/userinfo", async (req, res) => {
  try {
    // Runs before the token lookup, so an over-budget caller is refused for
    // free. Only failures below record against the budget, so a caller with a
    // real token is never throttled.
    if (isUserinfoRateLimited(req)) {
      logger.info(
        "[RATE LIMIT] /oauth/userinfo rate limited after repeated unresolvable tokens",
      );
      return res.status(429).json({
        error: "too_many_requests",
        error_description:
          "Too many failed token lookups. Please try again later.",
      });
    }

    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      recordUserinfoFailure(req);
      return res.status(401).json({
        error: "invalid_token",
        error_description: "Missing or invalid authorization header",
      });
    }

    const token = authHeader.substring(7); // Remove "Bearer " prefix

    // Validate MCP token format
    if (!token.startsWith("mcp_token_")) {
      recordUserinfoFailure(req);
      return res.status(401).json({
        error: "invalid_token",
        error_description: "Invalid access token format",
      });
    }

    // Look up token data (in production, this should validate signature and lookup in database)
    const tokenData = await oauthRepository.getAccessToken(token);
    if (!tokenData) {
      recordUserinfoFailure(req);
      return res.status(401).json({
        error: "invalid_token",
        error_description: "Token not found or expired",
      });
    }

    // Check if token has expired
    if (Date.now() > tokenData.expires_at.getTime()) {
      // Counted: an expired token resolves to nothing, and a caller replaying
      // one indefinitely is the shape being bounded. A real client hits this at
      // most once, when its own token ages out.
      recordUserinfoFailure(req);
      // Before the delete, and never awaited: `emit` is fire-and-forget by
      // contract, and ordering it first is what makes the record survive a
      // delete that throws. The row describes a credential that will not
      // exist to be looked up afterwards, so writing it second would lose it
      // in exactly the case an operator is investigating.
      emitExpiredTokenDestroyed(req, tokenData, token);
      await oauthRepository.deleteAccessToken(token);
      return res.status(401).json({
        error: "invalid_token",
        error_description: "Access token has expired",
      });
    }

    // `users.disabled` enforcement (migration 0027), same reasoning as the
    // introspect endpoint next door in token.ts. Access tokens live 24h in
    // this fork and this handler reads the token row alone, so a locked-out
    // account's outstanding token would otherwise keep answering with its
    // identity claims — `sub`, email, username and granted scope — to anyone
    // holding it.
    //
    // Answered with this handler's existing invalid-token 401 rather than a
    // new "account disabled" error: the token genuinely is invalid for this
    // account now, OAuth clients already treat 401 here as "re-authorize"
    // (where the authorize handler refuses them again), and reusing the
    // unknown-token wording keeps a disabled account indistinguishable on the
    // wire from a token that never existed. The row is not deleted — disable
    // is reversible; Revoke is what deletes.
    if (await usersRepository.isDisabled(tokenData.user_id)) {
      logger.warn(
        `[oauth] userinfo rejected reason=disabled user=${tokenData.user_id}`,
      );
      return res.status(401).json({
        error: "invalid_token",
        error_description: "Token not found or expired",
      });
    }

    // For MCP tokens, return basic user info based on the user_id stored with the token
    // In a real implementation, you would fetch actual user data from the database
    res.json({
      sub: tokenData.user_id,
      email: `user-${tokenData.user_id}@metamcp.local`,
      name: `MetaMCP User ${tokenData.user_id}`,
      preferred_username: `user_${tokenData.user_id}`,
      scope: tokenData.scope,
    });
  } catch (error) {
    logger.error("Error in OAuth userinfo endpoint:", error);
    res.status(500).json({
      error: "server_error",
      error_description: "Internal server error",
    });
  }
});

export default userinfoRouter;
