import { randomUUID } from "crypto";
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
import { requireIntrospectionCredential } from "./introspection-auth";
import {
  generateSecureAccessToken,
  generateSecureRefreshToken,
  rateLimitToken,
  verifyClientSecret,
} from "./utils";

const tokenRouter = express.Router();

// Umbrella fork: TTLs are env-var configurable. Defaults are tuned for max
// connectivity from clients that lack revoke-friendly UX (e.g. Claude.ai
// connectors): 24h access tokens with 365d refresh tokens. Refresh tokens
// rotate on every use (single-use), so a stolen refresh self-reveals when
// the legit client redeems the rotated copy and gets `invalid_grant`.
function readTtl(envName: string, fallbackSeconds: number): number {
  const raw = process.env[envName];
  if (!raw) return fallbackSeconds;
  const parsed = Number.parseInt(raw, 10);
  if (Number.isFinite(parsed) && parsed > 0) return parsed;
  logger.warn(
    `[oauth] ${envName}=${raw} is not a positive integer; using default ${fallbackSeconds}s`,
  );
  return fallbackSeconds;
}

const ACCESS_TOKEN_EXPIRY = readTtl(
  "OAUTH_ACCESS_TOKEN_TTL_SECONDS",
  24 * 60 * 60, // 24h default (was 1h upstream)
);
const REFRESH_TOKEN_EXPIRY = readTtl(
  "OAUTH_REFRESH_TOKEN_TTL_SECONDS",
  365 * 24 * 60 * 60, // 365d default (was 7d in PR #276)
);

logger.info(
  `[oauth] token TTLs: access=${ACCESS_TOKEN_EXPIRY}s refresh=${REFRESH_TOKEN_EXPIRY}s`,
);

// Umbrella fork: success-path grant observability. Until now the token endpoint
// logged only FAILURES, so nothing in `app.log` distinguished "the connector
// refreshed on schedule" from "the connector never refreshed and silently died
// when its access token expired" — the open question behind the 2026-08
// Claude.ai disconnect investigation. One grep-friendly line per issued token
// answers it from the log file alone: `grep '\[oauth\] token issued'`.
//
// SECRETS DISCIPLINE: the access token's LAST FOUR CHARACTERS only, and nothing
// else credential-shaped. Four characters are enough to tie an issued token to a
// later introspect/revoke line while being useless to an attacker who reads the
// log. Full access tokens, refresh tokens, authorization codes, and client
// secrets are never logged at any level.
function lastFour(secret: string): string {
  // Guard instead of trusting the caller: `slice(-4)` on a string shorter than
  // four characters returns the WHOLE string, which for a credential is a leak.
  // Generated tokens are always long, so this only fires on a caller bug.
  return secret.length >= 4 ? secret.slice(-4) : "????";
}

/**
 * Emit one line per successfully issued access token.
 *
 * `clientName` is passed only on the authorization_code path, where the client
 * row is already loaded for auth-method validation. The refresh path never
 * fetches it: a name lookup there would add a DB round-trip to a hot path purely
 * for logging, and it is not needed — every refresh chain begins with an
 * authorization_code grant, so the id-to-name mapping is already in the same log
 * file.
 */
function logTokenIssued(fields: {
  grantType: "authorization_code" | "refresh_token";
  clientId: string;
  clientName?: string | null;
  userId: string;
  accessToken: string;
  // Set only on the refresh path, where redemption always mints a replacement
  // refresh token (see handleRefreshTokenGrant). Omitted on the initial grant
  // because there was no prior refresh token to rotate, and `rotated=false`
  // there would read as "rotation is off".
  rotatedRefreshToken?: true;
}) {
  const parts = [
    "[oauth] token issued",
    `grant=${fields.grantType}`,
    `client=${fields.clientId}`,
  ];
  if (fields.clientName) {
    // JSON.stringify, not naive quoting: client_name arrives verbatim from the
    // UNAUTHENTICATED /oauth/register DCR endpoint, so an embedded newline or
    // quote would otherwise forge whole "[oauth] token issued" lines in this
    // log. stringify escapes both and supplies the surrounding quotes, keeping
    // benign output byte-identical. Length-clamped so a hostile registration
    // cannot bloat the log line.
    parts.push(
      `client_name=${JSON.stringify(fields.clientName.slice(0, 100))}`,
    );
  }
  parts.push(`user=${fields.userId}`);
  parts.push(`token=...${lastFour(fields.accessToken)}`);
  if (fields.rotatedRefreshToken) {
    parts.push("rotated=true");
  }

  logger.info(parts.join(" "));
}

/**
 * Record an issued or refreshed access token in `audit_log`.
 *
 * The durable twin of `logTokenIssued` above: that writes a grep-friendly
 * line to a ring buffer that dies on restart, this writes a queryable row
 * that cannot be cleared. The 2026-08-13 credential chain ran through here
 * and left nothing durable behind it.
 *
 * The token appears ONLY as a `credentialFingerprint` — sha256 plus last-4,
 * the same shape the MCP bearer detector records on refused requests, which
 * is deliberate: it means a token minted here and later refused there can be
 * matched across the two by hash, without either row holding anything usable.
 */
function emitTokenIssued(
  req: express.Request,
  fields: {
    action: "oauth.token.issue" | "oauth.token.refresh";
    grantType: string;
    clientId: string;
    clientName?: string | null;
    userId: string;
    accessToken: string;
  },
): void {
  const audit = auditRequestContext(req);
  const fingerprint = credentialFingerprint(fields.accessToken);
  emit({
    actor_type: "user",
    actor_id: fields.userId,
    actor_label: null,
    actor_ip: audit.actor_ip,
    actor_user_agent: audit.actor_user_agent,
    action: fields.action,
    target_type: "oauth_client",
    target_id: fields.clientId,
    outcome: "success",
    request_id: audit.request_id,
    http_status: 200,
    detail: {
      grant_type: fields.grantType,
      // Clamped for the same reason logTokenIssued clamps it: client_name
      // arrives verbatim from the UNAUTHENTICATED /oauth/register endpoint.
      client_name: fields.clientName ? fields.clientName.slice(0, 100) : null,
      access_token_sha256: fingerprint.sha256,
      access_token_last4: fingerprint.last4,
    },
  });
}

/**
 * Issue a new access token + refresh token pair and store them.
 *
 * `familyId` ties the pair into a refresh-token family (migration 0037). The
 * authorization_code grant omits it, starting a NEW family; the refresh grant
 * passes the rotated row's `family_id`, so a whole rotation chain shares one
 * family and reuse of any rotated-out member can revoke the entire lineage. The
 * id is a random uuid, unguessable, so it is never a value a caller can present.
 */
async function issueTokenPair(
  clientId: string,
  userId: string,
  scope: string,
  familyId: string = randomUUID(),
) {
  const accessToken = generateSecureAccessToken();
  const refreshToken = generateSecureRefreshToken();

  await oauthRepository.setAccessToken(accessToken, {
    client_id: clientId,
    user_id: userId,
    scope,
    expires_at: Date.now() + ACCESS_TOKEN_EXPIRY * 1000,
    family_id: familyId,
    // The refresh token and its expiry travel as one pair, so a token can never
    // be stored with a refresh token but no expiry — the never-reaped,
    // never-expiring shape migration 0035's CHECK also forbids at the column
    // level.
    refresh: {
      token: refreshToken,
      expires_at: Date.now() + REFRESH_TOKEN_EXPIRY * 1000,
    },
  });

  return { accessToken, refreshToken };
}

/**
 * OAuth 2.0 Token Endpoint
 * Handles token exchange requests from MCP clients
 * Supports authorization_code and refresh_token grant types
 */
tokenRouter.post("/oauth/token", rateLimitToken, async (req, res) => {
  try {
    // Check if body was parsed correctly
    if (!req.body || typeof req.body !== "object") {
      logger.error("Token endpoint: req.body is undefined or invalid", {
        body: req.body,
        bodyType: typeof req.body,
        contentType: req.headers["content-type"],
        method: req.method,
      });
      return res.status(400).json({
        error: "invalid_request",
        error_description:
          "Request body is missing or malformed. Ensure Content-Type is application/json or application/x-www-form-urlencoded",
      });
    }

    const { grant_type } = req.body;

    if (grant_type === "refresh_token") {
      return handleRefreshTokenGrant(req, res);
    }

    if (grant_type === "authorization_code") {
      return handleAuthorizationCodeGrant(req, res);
    }

    return res.status(400).json({
      error: "unsupported_grant_type",
      error_description:
        "Supported grant types: authorization_code, refresh_token",
    });
  } catch (error) {
    logger.error("Error in OAuth token endpoint:", error);
    res.status(500).json({
      error: "server_error",
      error_description: "Internal server error",
    });
  }
});

/**
 * Handle grant_type=authorization_code
 */
async function handleAuthorizationCodeGrant(
  req: express.Request,
  res: express.Response,
) {
  const { code, redirect_uri, client_id, code_verifier } = req.body;

  // Validate authorization code
  if (!code) {
    return res.status(400).json({
      error: "invalid_request",
      error_description: "Missing authorization code",
    });
  }

  // Look up the authorization code
  const codeData = await oauthRepository.getAuthCode(code);
  if (!codeData) {
    return res.status(400).json({
      error: "invalid_grant",
      error_description: "Invalid or expired authorization code",
    });
  }

  // Check if code has expired (10 minutes)
  if (Date.now() > codeData.expires_at.getTime()) {
    // Emitted before the delete for the reason given on the refresh-expiry
    // branch below: this is a rejection that destroys the row it just read, so
    // the row here is the only surviving evidence the code ever existed. The
    // client is UNAUTHENTICATED at this point — auth-method validation happens
    // further down — but the branch is still bounded, because reaching it
    // requires a real, currently-stored authorization code and consumes it.
    emitTokenLifecycle(req, {
      action: "oauth.token.issue",
      clientId: codeData.client_id,
      userId: codeData.user_id,
      token: code,
      outcome: "failure",
      httpStatus: 400,
      detail: {
        reason: "authorization_code_expired",
        token_type: "authorization_code",
        grant_type: "authorization_code",
        created_at: isoOrNull(codeData.created_at),
        expires_at: isoOrNull(codeData.expires_at),
      },
    });
    await oauthRepository.deleteAuthCode(code);
    return res.status(400).json({
      error: "invalid_grant",
      error_description: "Authorization code has expired",
    });
  }

  // Validate client_id and redirect_uri match the original request
  if (codeData.client_id !== client_id) {
    return res.status(400).json({
      error: "invalid_client",
      error_description: "Client ID does not match",
    });
  }

  if (codeData.redirect_uri !== redirect_uri) {
    return res.status(400).json({
      error: "invalid_grant",
      error_description: "Redirect URI does not match",
    });
  }

  // Validate client_id against registered clients
  const clientData = await oauthRepository.getClient(client_id);
  if (!clientData) {
    return res.status(400).json({
      error: "invalid_client",
      error_description: "Client not found or not registered",
    });
  }

  // Validate client authentication based on registered auth method
  if (clientData.token_endpoint_auth_method === "client_secret_basic") {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Basic ")) {
      return res.status(401).json({
        error: "invalid_client",
        error_description: "Client authentication required via Basic auth",
      });
    }

    const credentials = Buffer.from(
      authHeader.substring(6),
      "base64",
    ).toString();
    const [authClientId, authClientSecret] = credentials.split(":");

    // The client_id half is not a secret, so a plain compare is fine; the
    // secret half is verified against the salted hash at rest (migration 0036)
    // in constant time (verifyClientSecret -> timingSafeEqualSecret) so the
    // token endpoint is not a timing oracle for a confidential client's secret.
    if (
      authClientId !== client_id ||
      !verifyClientSecret(
        authClientSecret,
        clientData.client_secret,
        clientData.client_secret_salt,
      )
    ) {
      return res.status(401).json({
        error: "invalid_client",
        error_description: "Invalid client credentials",
      });
    }
  } else if (clientData.token_endpoint_auth_method === "client_secret_post") {
    const { client_secret } = req.body;
    if (
      !client_secret ||
      !verifyClientSecret(
        client_secret,
        clientData.client_secret,
        clientData.client_secret_salt,
      )
    ) {
      return res.status(401).json({
        error: "invalid_client",
        error_description: "Invalid client secret",
      });
    }
  }
  // For "none" auth method, no additional validation needed

  // OAuth 2.1 Security: PKCE is mandatory for all clients
  if (!codeData.code_challenge) {
    return res.status(400).json({
      error: "invalid_grant",
      error_description:
        "Authorization code was not issued with PKCE challenge",
    });
  }

  if (!code_verifier) {
    return res.status(400).json({
      error: "invalid_request",
      error_description: "PKCE code verifier is required",
    });
  }

  // Verify code challenge. Only S256 is honored — the "plain" method is
  // rejected rather than verified. The AS metadata advertises S256 only, and a
  // "plain" challenge equals the verifier and travels in the /oauth/authorize
  // query string (logged, left in browser history), so it gives no protection
  // against code interception. The authorize handler refuses to mint a "plain"
  // code, so a stored one is not reachable through the normal flow; this branch
  // is the defense-in-depth twin that refuses it here too.
  const crypto = await import("crypto");
  let challengeFromVerifier: string;

  if (codeData.code_challenge_method === "S256") {
    const hash = crypto.createHash("sha256").update(code_verifier).digest();
    challengeFromVerifier = hash.toString("base64url");
  } else {
    return res.status(400).json({
      error: "invalid_grant",
      error_description: "Unsupported code challenge method",
    });
  }

  if (challengeFromVerifier !== codeData.code_challenge) {
    return res.status(400).json({
      error: "invalid_grant",
      error_description: "PKCE verification failed",
    });
  }

  // `users.disabled` enforcement (migration 0027). The authorize handler
  // already refuses to MINT a code for a disabled account, but a code minted
  // in the seconds before the admin pressed disable stays redeemable for its
  // full 10-minute TTL — and one redemption here buys a 24h access token plus
  // a 365d refresh token. Guarding only the mint would leave that ten-minute
  // window open on the exact credential chain the abuse turns on.
  //
  // Placed before the single-use delete below for the same reason as the
  // refresh path: a refused grant leaves no wreckage, so re-enabling the
  // account inside the TTL restores a working flow instead of a burnt code.
  if (await usersRepository.isDisabled(codeData.user_id)) {
    logger.warn(
      `[oauth] token rejected reason=disabled grant=authorization_code client=${codeData.client_id} user=${codeData.user_id}`,
    );
    return res.status(400).json({
      error: "invalid_grant",
      error_description: "Invalid or expired authorization code",
    });
  }

  // Code is valid; consume it atomically. Single-use is enforced by the DELETE
  // itself (consumeAuthCode is DELETE ... RETURNING), not by the earlier read:
  // on two concurrent redemptions of the same code only one delete removes the
  // row, so exactly one caller proceeds and the loser is refused invalid_grant
  // rather than both minting a token pair for the same code.
  const consumed = await oauthRepository.consumeAuthCode(code);
  if (!consumed) {
    return res.status(400).json({
      error: "invalid_grant",
      error_description: "Invalid or expired authorization code",
    });
  }

  // Issue access token + refresh token
  const { accessToken, refreshToken } = await issueTokenPair(
    codeData.client_id,
    codeData.user_id,
    codeData.scope,
  );

  logTokenIssued({
    grantType: "authorization_code",
    clientId: codeData.client_id,
    clientName: clientData.client_name,
    userId: codeData.user_id,
    accessToken,
  });

  // After issueTokenPair, i.e. after setAccessToken committed the row — a
  // token that failed to persist must not leave a row saying it was issued.
  emitTokenIssued(req, {
    action: "oauth.token.issue",
    grantType: "authorization_code",
    clientId: codeData.client_id,
    clientName: clientData.client_name,
    userId: codeData.user_id,
    accessToken,
  });

  res.json({
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: ACCESS_TOKEN_EXPIRY,
    refresh_token: refreshToken,
    scope: codeData.scope,
  });
}

/**
 * Handle grant_type=refresh_token
 * Issues a new access token + refresh token pair (token rotation).
 */
async function handleRefreshTokenGrant(
  req: express.Request,
  res: express.Response,
) {
  const { refresh_token, client_id } = req.body;

  if (!refresh_token) {
    return res.status(400).json({
      error: "invalid_request",
      error_description: "Missing refresh_token parameter",
    });
  }

  // Look up the token row by refresh_token
  const tokenData = await oauthRepository.getByRefreshToken(refresh_token);
  if (!tokenData) {
    // Not a live token — but it may be a refresh token this family already
    // rotated OUT (migration 0037). Refresh tokens are single-use, so a
    // rotated-out token presented again is reuse: either the legitimate client
    // is a step behind (its rotation reply was lost) or the token was stolen
    // and the thief rotated it. Both are handled the safe way — revoke the
    // whole family — because the two are indistinguishable at the wire and
    // leaving the live chain running is the failure that matters. The reuse row
    // is emitted BEFORE the revoke, and never awaited, for the reason
    // emitTokenLifecycle documents: the record has to survive a delete that
    // throws, and the delete is exactly what destroys the family being
    // investigated. Collapsing the family (live rows AND markers) makes a
    // replay after revocation take this same branch with no marker to match, so
    // it falls through to the unknown-token response below — one reuse row per
    // family compromise, not one per replay.
    const reused = await oauthRepository.getRotatedRefreshToken(refresh_token);
    if (reused) {
      emitTokenLifecycle(req, {
        action: "oauth.token.reuse",
        clientId: reused.client_id,
        userId: reused.user_id,
        token: refresh_token,
        outcome: "denied",
        httpStatus: 400,
        detail: {
          reason: "refresh_token_reuse",
          family_id: reused.family_id,
        },
      });
      const revoked = await oauthRepository.revokeFamily(reused.family_id);
      logger.warn(
        `[oauth] refresh token reuse detected; family revoked ` +
          `client=${reused.client_id} user=${reused.user_id} tokens_revoked=${revoked}`,
      );
    }
    // Byte-identical to the reuse response above and to the disabled-account
    // and expired branches: a holder of a stolen or stale refresh token learns
    // only "this no longer works", never that they tripped detection.
    return res.status(400).json({
      error: "invalid_grant",
      error_description: "Invalid refresh token",
    });
  }

  // Check refresh token expiry. A NULL expiry is treated as expired, NOT as
  // "valid forever": a row with a refresh token and no expiry is the
  // never-reaped shape (see migration 0035), and honoring it would
  // make it an immortal credential. Migration 0035's CHECK makes that shape
  // unrepresentable going forward; this guard is the defense-in-depth twin that
  // refuses a legacy row if one ever presents it.
  if (
    !tokenData.refresh_token_expires_at ||
    Date.now() > tokenData.refresh_token_expires_at.getTime()
  ) {
    // Emitted BEFORE the delete, and never awaited — `emit` is fire-and-forget
    // by contract (see lib/audit/audit-emitter). Ordering it first is what
    // makes the record survive a delete that throws: the whole point of the
    // row is that the credential it describes no longer exists to be looked
    // up, so writing it after the destruction would lose it in exactly the
    // case an operator is investigating.
    emitTokenLifecycle(req, {
      action: "oauth.token.refresh",
      clientId: tokenData.client_id,
      userId: tokenData.user_id,
      // The refresh token as PRESENTED — `token_sha256` in the row. It is a
      // different string from the access token in the same row, which is
      // recorded separately below.
      token: refresh_token,
      outcome: "failure",
      httpStatus: 400,
      detail: {
        reason: "refresh_token_expired",
        token_type: "refresh_token",
        // The destroyed row's ACCESS token, under the same keys
        // `emitTokenIssued` writes — this is the join back to the
        // `oauth.token.issue` / `oauth.token.refresh` row that minted the
        // chain, which is the only place its age is now recorded. Since
        // migration 0036 the stored `access_token` IS the sha256 the audit log
        // records, and `access_token_last4` its tail, so they are used directly
        // passing the stored hash through credentialFingerprint would hash it
        // a second time and break the join.
        access_token_sha256: tokenData.access_token,
        access_token_last4: tokenData.access_token_last4,
        created_at: isoOrNull(tokenData.created_at),
        expires_at: isoOrNull(tokenData.expires_at),
        refresh_token_expires_at: isoOrNull(tokenData.refresh_token_expires_at),
      },
    });
    await oauthRepository.deleteAccessTokenByHash(tokenData.access_token);
    return res.status(400).json({
      error: "invalid_grant",
      error_description: "Refresh token has expired",
    });
  }

  // Validate client_id matches (if provided)
  if (client_id && tokenData.client_id !== client_id) {
    return res.status(400).json({
      error: "invalid_client",
      error_description: "Client ID does not match",
    });
  }

  // `users.disabled` enforcement (migration 0027) — the plane the 2026-08-13
  // attacker actually held. Refresh tokens live 365 days in this fork and the
  // authorize handler is nowhere on this path, so without this check a
  // disabled account keeps minting fresh 24h access tokens for a year from a
  // credential it already has. Disable has to mean the NEXT request fails, and
  // this is the request it makes.
  //
  // Deliberately placed BEFORE the rotation delete below: disable is a
  // reversible lockout, not a revocation. Rejecting after the delete would
  // destroy the token row and permanently break the connector even after an
  // admin presses Enable, quietly turning Disable into Revoke. Leaving the row
  // intact costs nothing — this check re-runs and refuses on every retry for
  // as long as the account stays disabled.
  //
  // The response is byte-identical to the unknown-refresh-token branch above.
  // A holder of a stolen refresh token learns only "this no longer works", not
  // that they tripped an admin lock — the `reason=disabled` distinction lives
  // in the server log, where the operator reads it and the attacker does not.
  if (await usersRepository.isDisabled(tokenData.user_id)) {
    logger.warn(
      `[oauth] token rejected reason=disabled grant=refresh_token client=${tokenData.client_id} user=${tokenData.user_id}`,
    );
    return res.status(400).json({
      error: "invalid_grant",
      error_description: "Invalid refresh token",
    });
  }

  // Record the rotated-out refresh token BEFORE deleting the row, so a later
  // presentation of it is detected as reuse (migration 0037). The marker is
  // keyed on the stored hash — tokenData.refresh_token is already that digest,
  // so it is passed through unchanged rather than re-hashed. The row was found
  // BY its refresh token and passed the expiry guard above, so both the hash
  // and its expiry are present on the real path; the guard only satisfies the
  // nullable column types. Recorded before the delete so there is no window in
  // which the token is neither live nor marked as rotated.
  if (tokenData.refresh_token && tokenData.refresh_token_expires_at) {
    await oauthRepository.recordRotatedRefreshToken({
      refreshTokenHash: tokenData.refresh_token,
      familyId: tokenData.family_id,
      clientId: tokenData.client_id,
      userId: tokenData.user_id,
      expiresAt: tokenData.refresh_token_expires_at,
    });
  }

  // Delete old token row (rotation: old refresh token is single-use). The row
  // is in hand from getByRefreshToken, so delete by its stored hash rather than
  // re-hashing it through deleteAccessToken.
  await oauthRepository.deleteAccessTokenByHash(tokenData.access_token);

  // Issue new access token + refresh token. The new pair inherits the rotated
  // row's family, so reuse of any rotated-out member revokes the whole chain.
  const { accessToken, refreshToken } = await issueTokenPair(
    tokenData.client_id,
    tokenData.user_id,
    tokenData.scope,
    tokenData.family_id,
  );

  // `rotated=true` is unconditional here because this handler always mints a
  // replacement refresh token and deletes the redeemed one above. It is logged
  // anyway so the 48h traffic read can tell a rotating client from a client that
  // is somehow reusing a refresh token, without re-reading this file.
  logTokenIssued({
    grantType: "refresh_token",
    clientId: tokenData.client_id,
    userId: tokenData.user_id,
    accessToken,
    rotatedRefreshToken: true,
  });

  emitTokenIssued(req, {
    action: "oauth.token.refresh",
    grantType: "refresh_token",
    clientId: tokenData.client_id,
    userId: tokenData.user_id,
    accessToken,
  });

  res.json({
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: ACCESS_TOKEN_EXPIRY,
    refresh_token: refreshToken,
    scope: tokenData.scope,
  });
}

/**
 * Render a row timestamp for `detail`, tolerating a missing or null value.
 *
 * `refresh_token_expires_at` is genuinely nullable in the schema, and the
 * remaining columns are only NOT NULL as far as the type system is concerned —
 * an emitter that called `.toISOString()` straight would turn one unexpected
 * null into a throw on a rejection path, i.e. a 500 on a request that was
 * already being refused. A null in the column is also honest output: it says
 * the row carried no such instant.
 */
function isoOrNull(value: Date | null | undefined): string | null {
  return value instanceof Date ? value.toISOString() : null;
}

/**
 * Record a lifecycle event for a credential that ACTUALLY EXISTS — issued,
 * refreshed, introspected, revoked, or REJECTED AND DESTROYED.
 *
 * WHAT IS AND IS NOT EMITTED HERE, because /oauth/revoke is unauthenticated
 * and `audit_log` has no prune path. The two public endpoints carry a
 * FAILURE-only limiter (see isPublicOAuthEndpointLimited below), which bounds
 * unresolvable-token spam but deliberately does NOT bound the success paths —
 * so every "is this branch replayable?" judgement below still stands
 * unchanged:
 *
 *  - UNKNOWN token, either endpoint: NOTHING. One anonymous request would
 *    equal one permanent INSERT recording a string the caller invented, and
 *    RFC 7009 requires /oauth/revoke to answer 200 to garbage, so the flood is
 *    not even distinguishable at the wire.
 *  - REVOKE of a real token: emitted. It is self-limiting — revocation
 *    DELETES the row, so a replay of the same token finds nothing and writes
 *    nothing. One row per credential killed, which is the forensic record.
 *  - INTROSPECT reporting ACTIVE: deliberately NOT emitted. Introspection does
 *    not consume the token, so unlike revoke it is unbounded: whoever holds
 *    one stolen credential — the 2026-08-13 scenario exactly — can replay it
 *    forever, each replay a permanent row. And the event has little to add:
 *    `oauth.token.issue` already recorded that this credential exists, under
 *    the same fingerprint. The failure-only limiter does not change this: a
 *    caller replaying a REAL token never scores against it, by design, so the
 *    branch is exactly as unbounded as it was. Bounding the ROW COUNT needs a
 *    prune path on `audit_log`, not a limiter on the endpoint.
 *  - INTROSPECT reporting INACTIVE because the ACCOUNT IS DISABLED: emitted.
 *    That one is bounded by the same argument in reverse — it requires a real
 *    token belonging to a locked-out account, i.e. a credential an
 *    administrator has already acted against, and a relying party still asking
 *    about it is exactly what an operator wants to see.
 *  - REVOKE refused because the CLIENT DOES NOT MATCH: emitted, and it is the
 *    highest-signal event either endpoint produces. Same bound as the two
 *    above: it cannot be reached without presenting a REAL, currently-issued
 *    token, and it is rate-limited on top, so it is not replay amplification.
 *    A caller naming a different client than the token was issued to is not a
 *    confused client.
 *  - REFRESH-TOKEN REUSE that revokes a family (migration 0037): emitted, and
 *    it is the highest-signal event on the grant half of /oauth/token. It is
 *    reachable only by presenting a refresh token that was already rotated OUT
 *    of a live family, and detection COLLAPSES the family — the live rows and
 *    the rotated-token markers alike — so a replay of the same token afterwards
 *    finds no marker and falls through to the silent unknown-token path. That
 *    is the bound: one reuse row per family compromise, not one per replay,
 *    which is tighter than the destroy-attempt bound below. `outcome` is
 *    `denied` rather than `failure`, so a query for active attacks filters on
 *    it. Emit-first here too — the revoke is the delete that must not be able to
 *    lose the record.
 *  - A REJECTION THAT DESTROYS THE ROW IT JUST READ: emitted. Three branches
 *    qualify — an EXPIRED AUTHORIZATION CODE and an EXPIRED REFRESH TOKEN on
 *    /oauth/token, and an EXPIRED ACCESS TOKEN on /oauth/introspect. Each is
 *    bounded by exactly the argument that admits revoke above: it cannot be
 *    reached without presenting a REAL, currently-stored credential, and
 *    reaching it DELETES that credential, so a replay of the same string finds
 *    nothing and writes nothing. One row per credential destroyed. These were
 *    the only deletes in this file that left no trace anywhere — not even a
 *    `logger` line — so a stale credential simply vanished, and with it the
 *    only evidence of when the chain behind it was minted. That is what the
 *    `created_at` / `expires_at` / `refresh_token_expires_at` values in
 *    `detail` are for: they date the chain that just ended, and the destroyed
 *    row's `access_token_sha256` joins this row to the `oauth.token.issue` row
 *    that minted it.
 *  - Every OTHER refusal on the grant half of /oauth/token — missing or
 *    mismatched client, bad client secret, PKCE failure, unknown code, unknown
 *    refresh token, disabled account: still NOTHING here. None of them
 *    destroys a row, so none is self-limiting; an invented code or refresh
 *    token can be replayed forever. The two disabled-account refusals also
 *    leave the row deliberately intact, because disable must stay reversible,
 *    and they already carry a `logger.warn`.
 *
 * THE RESIDUAL ON THAT BOUND, STATED PLAINLY RATHER THAN IMPLIED AWAY: it is
 * one row per destroy ATTEMPT, not per credential. Read-then-delete is not
 * atomic and neither delete reports whether it removed anything —
 * `deleteAccessToken` and `deleteAuthCode` both return void — so N concurrent
 * presentations of the SAME expired credential each read the row before the
 * first delete commits, and each writes a row. /oauth/token is per-edge-IP
 * limited by `rateLimitToken`, /oauth/introspect sits behind the failure
 * limiter plus the RFC 7662 credential gate, and GET /oauth/userinfo now
 * carries the same failure-only limiter (see userinfo.ts) — but that limiter
 * counts failures rather than successes, so a burst of the SAME expired token
 * can still spend a window's worth of destroy-emits before the bucket fills.
 * Emit-first is the half of
 * that trade being kept ON PURPOSE: the record has to survive a delete that
 * throws, which is the case an operator is investigating, and buying
 * exactly-once instead would mean gating the emit on a delete that returns a
 * row count — trading the forensic guarantee for a counting one. So the bound
 * is one BURST per real credential, once, where the same burst wrote zero rows
 * before these emitters existed. Bounding it further needs the prune path on
 * `audit_log`, same as the introspect-active case above.
 *
 * GET /oauth/userinfo has the same destroy-on-expiry branch and emits the same
 * shape, but from ./userinfo.ts — this emitter is private to the token router.
 *
 * A FAILURE ROW REUSES THE VERB OF THE OPERATION IT REFUSED (`oauth.token.issue`
 * for a dead authorization code, `oauth.token.refresh` for a dead refresh
 * token) rather than inventing a `*.expired` verb, matching the revoke
 * client-mismatch row above. `outcome` is what separates them, so any query
 * counting successful grants must filter on `outcome = 'success'` and not on
 * `action` alone.
 *
 * The credential is recorded as a fingerprint only, matching `emitTokenIssued`,
 * so an operator can follow one credential from mint to destruction by hash.
 */
function emitTokenLifecycle(
  req: express.Request,
  fields: {
    action:
      | "oauth.token.issue"
      | "oauth.token.refresh"
      | "oauth.token.introspect"
      | "oauth.token.revoke"
      | "oauth.token.reuse";
    clientId: string;
    userId: string;
    token: string;
    // `denied` is the reuse verb's outcome (migration 0037): a refused request
    // that also acted against the caller (it revoked the family), which a query
    // for active attacks can filter on distinctly from a plain `failure`.
    outcome: "success" | "failure" | "denied";
    /**
     * Defaults to 200 because every other caller here answers 200 — including
     * the refusals, which is the point of RFC 7662's `{active:false}` and RFC
     * 7009's 200-to-garbage. The client-mismatch refusal is the one that does
     * not, and a row claiming 200 for a 400 would misreport the only wire fact
     * the table carries about that request.
     */
    httpStatus?: number;
    detail?: Record<string, unknown>;
  },
): void {
  const audit = auditRequestContext(req);
  const fingerprint = credentialFingerprint(fields.token);
  emit({
    actor_type: "user",
    actor_id: fields.userId,
    actor_label: null,
    actor_ip: audit.actor_ip,
    actor_user_agent: audit.actor_user_agent,
    action: fields.action,
    target_type: "oauth_client",
    target_id: fields.clientId,
    outcome: fields.outcome,
    request_id: audit.request_id,
    http_status: fields.httpStatus ?? 200,
    detail: {
      token_sha256: fingerprint.sha256,
      token_last4: fingerprint.last4,
      ...(fields.detail ?? {}),
    },
  });
}

/**
 * Failure-only rate limiting for /oauth/introspect and /oauth/revoke.
 *
 * /oauth/revoke takes no credential and cannot: the clients are secretless
 * public PKCE clients, revocation already requires the token value, and
 * destroying a credential is the safe direction to fail. Bounding that traffic
 * by FAILURE is the substitute, and it has to be by failure rather than by
 * request. `rateLimitToken`, the per-IP limiter already on /oauth/token, would
 * be an outage on it: `trust proxy` is deliberately off, so every caller
 * through the tunnel shares ONE `req.ip` bucket.
 *
 * /oauth/introspect now DOES require one (see ./introspection-auth, which
 * carries the RFC 7662 §2.1 reasoning). It keeps this limiter regardless,
 * running ahead of the credential check so that anonymous spraying is bounded
 * by the same budget as unresolvable tokens instead of being free.
 *
 * A caller presenting a token this server issued therefore never scores, no
 * matter how often it asks. Only tokens that resolve to nothing — invented,
 * expired, or presented with a client_id they were not issued to — count.
 *
 * THE RESIDUAL, STATED PLAINLY RATHER THAN IMPLIED AWAY: the bucket is still
 * per-IP and `trust proxy` is still off, so failure-only makes legitimate
 * traffic incapable of filling the bucket — it does NOT make the bucket
 * un-fillable. Anyone who can reach these endpoints can spend it with 20
 * invented-token POSTs and hold it there indefinitely, and everyone sharing
 * that source address is refused with them. That is accepted, not solved, and
 * it is only acceptable because the gateway's own traffic no longer arrives
 * here at all: `api-key-oauth.middleware.ts` reads the token row in-process, so
 * no MCP client depends on this endpoint answering. Anything that reintroduces
 * an internal caller must revisit this decision first.
 *
 * Split into check and record on purpose: the check runs BEFORE the database
 * lookup, so refusing costs nothing, and `isCurrentlyLimited` is used rather
 * than `isRateLimited` because the latter counts the question it is asked.
 */
function isPublicOAuthEndpointLimited(
  req: express.Request,
  route: "introspect" | "revoke",
): boolean {
  return authRateLimiter.isCurrentlyLimited(
    getPublicOAuthRateLimitIdentifier(req, route),
  );
}

function recordPublicOAuthEndpointFailure(
  req: express.Request,
  route: "introspect" | "revoke",
): void {
  authRateLimiter.recordFailedAttempt(
    getPublicOAuthRateLimitIdentifier(req, route),
  );
}

function sendPublicOAuthEndpointRateLimited(
  res: express.Response,
  route: "introspect" | "revoke",
): express.Response {
  logger.info(
    `[RATE LIMIT] /oauth/${route} rate limited after repeated unresolvable tokens`,
  );
  return res.status(429).json({
    error: "too_many_requests",
    error_description: "Too many failed token lookups. Please try again later.",
  });
}

/**
 * OAuth 2.0 Token Introspection Endpoint
 * Allows first-party resource servers to introspect access tokens
 */
tokenRouter.post("/oauth/introspect", async (req, res) => {
  try {
    if (isPublicOAuthEndpointLimited(req, "introspect")) {
      return sendPublicOAuthEndpointRateLimited(res, "introspect");
    }

    // RFC 7662 §2.1: this endpoint MUST require authorization, and until now
    // it required none — an anonymous caller could ask it whether any token
    // value was live and get back `scope`, `client_id` and `sub`. See
    // ./introspection-auth for what credential is required, why an API key is
    // the right one, and why /oauth/revoke is deliberately left public.
    //
    // Placed AFTER the limiter check and counted as a failure, so anonymous
    // spraying is bounded by the same budget as unresolvable tokens rather
    // than being free. The residual is the one already documented on
    // isPublicOAuthEndpointLimited: the bucket is per-IP with `trust proxy`
    // off, so it can be held down by anyone who can reach the endpoint. That
    // was accepted when no legitimate caller depended on this route, and
    // gating it does not change who depends on it.
    const credential = await requireIntrospectionCredential(req);
    if (!credential.ok) {
      recordPublicOAuthEndpointFailure(req, "introspect");
      logger.info(
        `[oauth] introspect refused reason=${credential.reason} — RFC 7662 requires an authenticated caller`,
      );
      // 401 with a challenge, per RFC 7662 §2.3. No audit row: the request
      // carries no identity to attribute one to, and an anonymous caller who
      // can be refused for free must not be able to write to `audit_log`,
      // which has no prune path.
      return res
        .status(401)
        .set("WWW-Authenticate", 'Bearer realm="oauth-introspection"')
        .json({
          error: "invalid_client",
          error_description:
            "Token introspection requires a first-party API key",
        });
    }

    // Check if body was parsed correctly
    if (!req.body || typeof req.body !== "object") {
      recordPublicOAuthEndpointFailure(req, "introspect");
      return res.status(400).json({
        error: "invalid_request",
        error_description: "Request body is missing or malformed",
      });
    }

    const { token } = req.body;

    if (!token) {
      recordPublicOAuthEndpointFailure(req, "introspect");
      return res.status(400).json({
        error: "invalid_request",
        error_description: "Missing token parameter",
      });
    }

    // Check if token exists and is valid
    const tokenData = await oauthRepository.getAccessToken(token);

    if (!tokenData || !token.startsWith("mcp_token_")) {
      recordPublicOAuthEndpointFailure(req, "introspect");
      return res.json({
        active: false,
      });
    }

    // Check if token has expired
    if (Date.now() > tokenData.expires_at.getTime()) {
      // Counted: an expired token is still a token that resolves to nothing,
      // and a caller replaying one indefinitely is the shape being bounded. A
      // real client hits this at most once, when its own token ages out.
      recordPublicOAuthEndpointFailure(req, "introspect");
      // Emitted before the delete, same reasoning as the grant-half branches.
      // No `httpStatus`: RFC 7662 answers an inactive token with 200 and
      // `{active:false}`, which is the emitter's default.
      //
      // `refresh_token_expires_at` is in the row deliberately. This delete
      // takes the WHOLE row, so a refresh token that had not itself expired
      // dies with the access token — the record has to show what was
      // destroyed, not just what was asked about.
      emitTokenLifecycle(req, {
        action: "oauth.token.introspect",
        clientId: tokenData.client_id,
        userId: tokenData.user_id,
        token,
        outcome: "failure",
        detail: {
          active: false,
          reason: "access_token_expired",
          token_type: "access_token",
          created_at: isoOrNull(tokenData.created_at),
          expires_at: isoOrNull(tokenData.expires_at),
          refresh_token_expires_at: isoOrNull(
            tokenData.refresh_token_expires_at,
          ),
        },
      });
      await oauthRepository.deleteAccessToken(token);
      return res.json({
        active: false,
      });
    }

    // `users.disabled` enforcement (migration 0027). Introspection is the
    // authoritative "is this credential live?" answer a resource server asks
    // for, and the token row knows nothing about the account behind it — so
    // without this check a locked-out account's still-unexpired token reports
    // `active: true` along with its scope, client_id and `sub`. That both
    // tells a relying party to honour a credential every other plane now
    // refuses, and confirms to whoever holds the token that the account is
    // still there.
    //
    // `{ active: false }` alone is the correct wire answer rather than an
    // error: RFC 7662 §2.2 defines `active` as covering a token that has been
    // revoked or otherwise invalidated by the resource owner, and requires
    // that no other member be returned for an inactive token.
    //
    // The row is deliberately NOT deleted here (contrast the expiry branch
    // above): disable is a reversible lockout, and deleting would turn it
    // into a revocation that outlives Enable.
    //
    // The check lives in this handler rather than in the introspection helper
    // `middleware/api-key-oauth.middleware.ts` calls, which stays a pure
    // token-row lookup — the data plane it feeds does its own isDisabled
    // check on the resolved identity, and one plane's account policy has no
    // business hiding inside the other's lookup.
    //
    // Deliberately NOT counted against the failure limiter: the credential is
    // real and was issued by this server, so a relying party asking about it
    // is a legitimate caller doing the right thing. Counting it would let one
    // locked-out account's still-running client spend the shared per-IP budget
    // and refuse everyone else — the outage this limiter is shaped to avoid.
    if (await usersRepository.isDisabled(tokenData.user_id)) {
      logger.warn(
        `[oauth] introspect reported inactive reason=disabled client=${tokenData.client_id} user=${tokenData.user_id}`,
      );
      emitTokenLifecycle(req, {
        action: "oauth.token.introspect",
        clientId: tokenData.client_id,
        userId: tokenData.user_id,
        token,
        outcome: "failure",
        detail: { active: false, reason: "disabled" },
      });
      return res.json({
        active: false,
      });
    }

    // No audit row on this branch — see emitTokenLifecycle's header. An
    // active introspection does not consume the token, so it is the one
    // outcome in this file an attacker can replay without limit.

    // Token is active, return introspection details
    res.json({
      active: true,
      scope: tokenData.scope,
      client_id: tokenData.client_id,
      token_type: "Bearer",
      exp: Math.floor(tokenData.expires_at.getTime() / 1000),
      iat: Math.floor(tokenData.created_at.getTime() / 1000),
      sub: tokenData.user_id,
    });
  } catch (error) {
    logger.error("Error in OAuth introspect endpoint:", error);
    res.status(500).json({
      error: "server_error",
      error_description: "Internal server error",
    });
  }
});

/**
 * OAuth 2.0 Token Revocation Endpoint
 * Allows clients to revoke access tokens or refresh tokens
 *
 * DELIBERATELY UNAUTHENTICATED, and it is the only public OAuth endpoint left
 * that way after `/oauth/introspect` was gated. That asymmetry is a decision,
 * not an oversight, so it is recorded here where the next reviewer will look
 * rather than only in ./introspection-auth.ts.
 *
 * The two endpoints ask opposite questions. Introspection HANDS OUT the answer
 * to "is this credential live, and whose is it?", which RFC 7662 §2.1 says
 * MUST be authorized — it is a validation oracle for a stolen token and a
 * user-id disclosure, and it is replayable. Revocation DESTROYS a credential,
 * and it cannot be reached without already presenting the token value, so an
 * attacker gains nothing they did not already have. Failing in the direction
 * of destroying credentials is the safe direction to fail.
 *
 * RFC 7009 §2.1 asks the server to verify the token was issued to the
 * requesting client, and the CLIENT REALITY here is why that cannot become a
 * gate: these are secretless public PKCE clients
 * (`token_endpoint_auth_method: "none"`), so they hold nothing to authenticate
 * WITH. Requiring a credential would break revocation for exactly the clients
 * least able to protect a token in the first place — the claude.ai and Claude
 * Code connectors among them. The non-blocking `client_id` comparison below is
 * what is achievable, and what it buys is a signal rather than a barrier; see
 * its own comment.
 *
 * The compensating controls are the failure-only rate limiter this handler
 * opens with (`isPublicOAuthEndpointLimited`) and the audited client-mismatch
 * branch. Revisit this only if revocation ever stops requiring the token value.
 */
tokenRouter.post("/oauth/revoke", async (req, res) => {
  try {
    if (isPublicOAuthEndpointLimited(req, "revoke")) {
      return sendPublicOAuthEndpointRateLimited(res, "revoke");
    }

    // Check if body was parsed correctly
    if (!req.body || typeof req.body !== "object") {
      recordPublicOAuthEndpointFailure(req, "revoke");
      return res.status(400).json({
        error: "invalid_request",
        error_description: "Request body is missing or malformed",
      });
    }

    const { token, client_id } = req.body;

    if (!token) {
      recordPublicOAuthEndpointFailure(req, "revoke");
      return res.status(400).json({
        error: "invalid_request",
        error_description: "Missing token parameter",
      });
    }

    /**
     * RFC 7009 §2.1 asks the server to "verify whether the token was issued to
     * the client making the revocation request". This check is NON-BLOCKING
     * when client_id is absent, mirroring handleRefreshTokenGrant above, so
     * BE CLEAR ABOUT WHAT IT DOES AND DOES NOT BUY: it does not stop anyone
     * holding a stolen token from revoking it, because omitting client_id
     * skips the comparison entirely. The MUST is not satisfied and cannot be
     * satisfied here — these are secretless public PKCE clients, so a supplied
     * client_id is an unauthenticated claim either way, and refusing the
     * clients that omit it would break revocation for the ones least able to
     * protect a token in the first place. Revocation destroying a credential
     * is also the safe direction to fail.
     *
     * What it does buy is a signal: a caller that names a DIFFERENT client
     * than the token was issued to is not a confused client, and that mismatch
     * is the highest-value event either of these endpoints produces.
     */
    const clientMismatch = (tokenClientId: string): boolean =>
      Boolean(client_id) && tokenClientId !== client_id;

    /**
     * Refuse a revocation whose client_id names someone else, loudly.
     *
     * This branch IS audited, unlike the other refusals on these two endpoints,
     * and the reason is the one that governs every emit decision in this file
     * (see emitTokenLifecycle): replay amplification. An unknown-token refusal
     * records a string the caller invented and can be repeated forever. This
     * one requires a REAL, currently-issued token presented under the wrong
     * client — it cannot be produced without already holding a live credential,
     * and it is rate-limited on top. Bounded, and it answers the question an
     * operator actually asks: "did anyone use this credential from somewhere it
     * was not issued to?"
     */
    const refuseClientMismatch = (
      tokenData: { client_id: string; user_id: string },
      tokenType: "access_token" | "refresh_token",
    ): express.Response => {
      recordPublicOAuthEndpointFailure(req, "revoke");
      logger.warn(
        `[oauth] revoke rejected reason=client_mismatch token_client=${tokenData.client_id} presented_client=${JSON.stringify(String(client_id).slice(0, 100))} user=${tokenData.user_id}`,
      );
      emitTokenLifecycle(req, {
        action: "oauth.token.revoke",
        clientId: tokenData.client_id,
        userId: tokenData.user_id,
        token,
        outcome: "failure",
        httpStatus: 400,
        detail: {
          reason: "client_mismatch",
          token_type: tokenType,
          // Clamped: `client_id` is unauthenticated request text on an
          // endpoint that takes no credential, and `audit_log` has no prune
          // path, so an unbounded value here is a write-amplification
          // primitive. Recorded because "which client did they claim to be" is
          // the whole content of the event.
          presented_client_id: String(client_id).slice(0, 100),
        },
      });
      return res.status(400).json({
        error: "invalid_client",
        error_description: "Client ID does not match",
      });
    };

    // Try revoking as access token
    const accessTokenData = await oauthRepository.getAccessToken(token);
    if (accessTokenData) {
      if (clientMismatch(accessTokenData.client_id)) {
        return refuseClientMismatch(accessTokenData, "access_token");
      }
      await oauthRepository.deleteAccessToken(token);
      emitTokenLifecycle(req, {
        action: "oauth.token.revoke",
        clientId: accessTokenData.client_id,
        userId: accessTokenData.user_id,
        token,
        outcome: "success",
        detail: { token_type: "access_token" },
      });
    } else {
      // Try revoking as refresh token
      const tokenData = await oauthRepository.getByRefreshToken(token);
      if (tokenData) {
        if (clientMismatch(tokenData.client_id)) {
          return refuseClientMismatch(tokenData, "refresh_token");
        }
        // The row is in hand from getByRefreshToken, so delete by its stored
        // hash rather than re-hashing it through deleteAccessToken.
        await oauthRepository.deleteAccessTokenByHash(tokenData.access_token);
        emitTokenLifecycle(req, {
          action: "oauth.token.revoke",
          clientId: tokenData.client_id,
          userId: tokenData.user_id,
          token,
          outcome: "success",
          detail: { token_type: "refresh_token" },
        });
      } else {
        // RFC 7009: return success even if token doesn't exist — but count it.
        // The 200 is what makes this endpoint an unauthenticated oracle worth
        // spraying, and a caller whose tokens never resolve is not a client.
        recordPublicOAuthEndpointFailure(req, "revoke");
      }
    }

    // RFC 7009 specifies that revocation endpoint should return 200 OK
    res.status(200).send();
  } catch (error) {
    logger.error("Error in OAuth revoke endpoint:", error);
    res.status(500).json({
      error: "server_error",
      error_description: "Internal server error",
    });
  }
});

export default tokenRouter;
