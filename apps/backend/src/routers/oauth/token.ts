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
import {
  generateSecureAccessToken,
  generateSecureRefreshToken,
  rateLimitToken,
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
    parts.push(`client_name=${JSON.stringify(fields.clientName.slice(0, 100))}`);
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
 */
async function issueTokenPair(
  clientId: string,
  userId: string,
  scope: string,
) {
  const accessToken = generateSecureAccessToken();
  const refreshToken = generateSecureRefreshToken();

  await oauthRepository.setAccessToken(accessToken, {
    client_id: clientId,
    user_id: userId,
    scope,
    expires_at: Date.now() + ACCESS_TOKEN_EXPIRY * 1000,
    refresh_token: refreshToken,
    refresh_token_expires_at:
      Date.now() + REFRESH_TOKEN_EXPIRY * 1000,
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

    if (
      authClientId !== client_id ||
      authClientSecret !== clientData.client_secret
    ) {
      return res.status(401).json({
        error: "invalid_client",
        error_description: "Invalid client credentials",
      });
    }
  } else if (clientData.token_endpoint_auth_method === "client_secret_post") {
    const { client_secret } = req.body;
    if (!client_secret || client_secret !== clientData.client_secret) {
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

  // Verify code challenge
  const crypto = await import("crypto");
  let challengeFromVerifier: string;

  if (codeData.code_challenge_method === "S256") {
    const hash = crypto.createHash("sha256").update(code_verifier).digest();
    challengeFromVerifier = hash.toString("base64url");
  } else if (codeData.code_challenge_method === "plain") {
    challengeFromVerifier = code_verifier;
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
  // window open on the exact credential chain the incident turned on.
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

  // Code is valid, delete it (authorization codes are single-use)
  await oauthRepository.deleteAuthCode(code);

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
    return res.status(400).json({
      error: "invalid_grant",
      error_description: "Invalid refresh token",
    });
  }

  // Check refresh token expiry
  if (
    tokenData.refresh_token_expires_at &&
    Date.now() > tokenData.refresh_token_expires_at.getTime()
  ) {
    await oauthRepository.deleteAccessToken(tokenData.access_token);
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

  // Delete old token row (rotation: old refresh token is single-use)
  await oauthRepository.deleteAccessToken(tokenData.access_token);

  // Issue new access token + refresh token
  const { accessToken, refreshToken } = await issueTokenPair(
    tokenData.client_id,
    tokenData.user_id,
    tokenData.scope,
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
 * Record an introspection or revocation of a token that ACTUALLY EXISTS.
 *
 * WHAT IS AND IS NOT EMITTED HERE, because both endpoints are unauthenticated
 * and `audit_log` has no prune path. Both now carry a FAILURE-only limiter
 * (see isPublicOAuthEndpointLimited below), which bounds unresolvable-token
 * spam but deliberately does NOT bound the success paths — so every "is this
 * branch replayable?" judgement below still stands unchanged:
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
 *    about it is exactly what an incident responder wants to see.
 *
 * The token is recorded as a fingerprint only, matching `emitTokenIssued`, so
 * an operator can follow one credential from mint to revocation by hash.
 */
function emitTokenLifecycle(
  req: express.Request,
  fields: {
    action: "oauth.token.introspect" | "oauth.token.revoke";
    clientId: string;
    userId: string;
    token: string;
    outcome: "success" | "failure";
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
    http_status: 200,
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
 * Both endpoints take no credential — RFC 7662 §2.1 says an introspection
 * endpoint MUST require authorization, and there is nothing here to require it
 * of: the clients are secretless public PKCE clients. Bounding the traffic by
 * FAILURE is the substitute, and it has to be by failure rather than by
 * request. `rateLimitToken`, the per-IP limiter already on /oauth/token, would
 * be an outage on these two: `trust proxy` is deliberately off, so every
 * caller through the tunnel shares ONE `req.ip` bucket.
 *
 * A caller presenting a token this server issued therefore never scores, no
 * matter how often it asks. Only tokens that resolve to nothing — invented,
 * expired, or presented with a client_id they were not issued to — count.
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
 * Allows clients to introspect access tokens
 */
tokenRouter.post("/oauth/introspect", async (req, res) => {
  try {
    if (isPublicOAuthEndpointLimited(req, "introspect")) {
      return sendPublicOAuthEndpointRateLimited(res, "introspect");
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
     * RFC 7009 §2.1: the server "MUST verify whether the token was issued to
     * the client making the revocation request". Without this a caller holding
     * any valid token could revoke it while claiming to be a different client,
     * and — more usefully to an attacker — a client_id supplied here was simply
     * ignored, so nothing distinguished the legitimate holder from anyone else.
     *
     * NON-BLOCKING when client_id is absent, mirroring handleRefreshTokenGrant
     * above: these are public clients with no secret, many of which omit
     * client_id entirely on revocation, and refusing those would break
     * revocation for the clients most in need of it.
     */
    const clientMismatch = (tokenClientId: string): boolean =>
      Boolean(client_id) && tokenClientId !== client_id;

    // Try revoking as access token
    const accessTokenData = await oauthRepository.getAccessToken(token);
    if (accessTokenData) {
      if (clientMismatch(accessTokenData.client_id)) {
        recordPublicOAuthEndpointFailure(req, "revoke");
        return res.status(400).json({
          error: "invalid_client",
          error_description: "Client ID does not match",
        });
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
          recordPublicOAuthEndpointFailure(req, "revoke");
          return res.status(400).json({
            error: "invalid_client",
            error_description: "Client ID does not match",
          });
        }
        await oauthRepository.deleteAccessToken(tokenData.access_token);
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
