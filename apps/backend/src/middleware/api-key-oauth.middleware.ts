import { DatabaseEndpoint } from "@repo/zod-types";
import express from "express";

import logger from "@/utils/logger";

import { ApiKeysRepository } from "../db/repositories/api-keys.repo";
import { oauthRepository } from "../db/repositories/oauth.repo";
import { usersRepository } from "../db/repositories/users.repo";
import { resolveActsAsUserId } from "../lib/api-key-identity";
import {
  type AuditActorType,
  auditRequestContext,
  type AuditRequestFields,
  credentialFingerprint,
  emit,
} from "../lib/audit/audit-emitter";
import {
  sendApiKeyRequiredResponse,
  sendAuthenticationRequiredChallenge,
  sendOAuthChallengeResponse,
} from "../lib/auth-challenge";
import {
  authRateLimiter,
  getAuthRateLimitIdentifier,
} from "../lib/auth-rate-limiter";
import {
  ENDPOINT_ACCESS_DENIED_MESSAGE,
  isOAuthUserAllowedOnEndpoint,
  recordAccessDenial,
} from "../lib/endpoint-access-control";
import { GRANTED_OAUTH_SCOPE } from "../routers/oauth/utils";

// Extend Express Request interface for our custom properties.
//
// `AuditRequestFields` (auditRequestId / auditClientIp) is inherited rather
// than assumed: `auditContextMiddleware` stamps those two on every request
// and the tool-call audit path reads them off this type. Declared here, a
// rename on the stamping side is a compile error at the read sites instead of
// two silently NULL audit columns.
export interface ApiKeyAuthenticatedRequest
  extends express.Request,
    AuditRequestFields {
  namespaceUuid: string;
  endpointName: string;
  endpoint: DatabaseEndpoint;
  apiKeyUserId?: string;
  apiKeyUuid?: string;
  // Acts-as identity (api_keys.acts_as_user_id, migration 0024): the
  // better-auth user whose delegated m365 identity this key's requests
  // exercise. Undefined for unbound keys — the m365 injection then
  // fail-closes. Consumed ONLY by the streamable-http m365 context gate.
  apiKeyActsAsUserId?: string;
  oauthUserId?: string; // For OAuth-authenticated requests
  authMethod?: "api_key" | "oauth"; // Track which auth method was used
}

const apiKeysRepository = new ApiKeysRepository();

/**
 * Validate an OAuth bearer token against the stored token row.
 *
 * THIS USED TO BE AN HTTP CALL TO OUR OWN /oauth/introspect, once per
 * OAuth-authenticated MCP request. Three things were wrong with that, in
 * increasing order of consequence: it spent a whole socket, request parse and
 * JSON round-trip to run a query this process could run directly; it made the
 * data plane depend on the gateway being reachable from inside its own
 * container; and it meant the ONLY realistic traffic on a public,
 * unauthenticated endpoint was our own, which is what made that endpoint
 * impossible to rate-limit without throttling every MCP client on the gateway
 * (`trust proxy` is off, so they all share one `req.ip` bucket). Reading the
 * row here takes the internal traffic off the public endpoint entirely, so
 * bounding it costs legitimate callers nothing. Same query, same repository —
 * `oauthRepository.getAccessToken` is exactly what the introspect handler
 * calls.
 *
 * The expiry check is replicated from that handler. The expired row is
 * deliberately NOT deleted here, unlike there, and the reason is NOT that
 * something else sweeps it — `oauthRepository.cleanupExpired()` deletes a
 * token row only when the refresh token is ALSO expired or null, so a row with
 * a dead 24h access token and a live 365d refresh token is never swept and
 * should not be. The reason is that deleting is WRONG on this path:
 * `deleteAccessToken` removes the whole row, refresh token included, so the
 * old self-call was destroying a client's live refresh token every time it
 * arrived with a just-expired access token — turning a routine "refresh now"
 * into "re-authorize from scratch". A read path must not revoke.
 *
 * `users.disabled` is deliberately NOT checked here either — see
 * findDisabledIdentity below and the matching note in routers/oauth/token.ts:
 * this stays a pure token-row lookup and the two call sites resolve the
 * account. That is also what makes the refusal HONEST. Through introspection,
 * a disabled account's token came back `active: false`, so the caller was told
 * "invalid_token" and its retries counted against the shared failed-attempt
 * limiter — one locked-out account's still-running connector could 429 every
 * other client behind the same IP. It now reaches the account check and is
 * refused as `account_disabled`, with the audit row that says so.
 *
 * TWO ACCEPTED SIDE EFFECTS of that 401 -> 403 move, recorded because they are
 * the price of it and neither is obvious from the diff:
 *
 *  (a) The refusal is now DISTINGUISHABLE. A caller learns that its token is
 *      real and the account behind it is locked (403) rather than that the
 *      token is simply bad (401) — a small oracle for someone holding a stolen
 *      credential. Accepted: they already hold the credential, `/oauth/token`
 *      answers the same question through refresh, and an operator reading
 *      `account_disabled` rows during a lockout is worth more than denying
 *      that inference.
 *  (b) A disabled account's requests are UNBOUNDED. They cost two DB round
 *      trips each (token row, then `isDisabled`) and are counted by NO
 *      limiter, because the failed-attempt limiter is only reached from the
 *      invalid-credential branch. A connector retrying in a tight loop after
 *      its owner is locked out therefore keeps costing queries indefinitely.
 *      Accepted for now — it needs a live credential, and the audit rows make
 *      it visible — but it is the thing to bound if disable is ever used on an
 *      account with a busy machine client.
 */
async function validateOAuthToken(token: string): Promise<{
  valid: boolean;
  user_id?: string;
  scopes?: string[];
  error?: string;
}> {
  try {
    // Check if this is our MCP OAuth token format
    if (token.startsWith("mcp_token_")) {
      const tokenData = await oauthRepository.getAccessToken(token);

      if (!tokenData) {
        return { valid: false, error: "Token is not active" };
      }

      if (Date.now() > tokenData.expires_at.getTime()) {
        return { valid: false, error: "Token is not active" };
      }

      return {
        valid: true,
        user_id: tokenData.user_id,
        // Fall back to the scope this server grants, not "admin". Nothing
        // reads `scopes` for an authorization decision today (the gate is
        // the better-auth session role), but a write-only field that says
        // "admin" is the exact string a future reader would trust.
        scopes: tokenData.scope
          ? tokenData.scope.split(" ")
          : [GRANTED_OAUTH_SCOPE],
      };
    }

    // Token is not a recognized MCP token format
    return { valid: false, error: "Unsupported token format" };
  } catch (error) {
    logger.error("Error validating OAuth token:", error);
    return { valid: false, error: "OAuth validation failed" };
  }
}

/**
 * `users.disabled` enforcement for the DATA plane (migration 0027).
 *
 * The login hook, the tRPC context and the OAuth authorize handler all refuse
 * a disabled account, but every one of them sits on the HUMAN plane. This
 * middleware is the machine plane — bearer tokens and API keys — and it is the
 * plane the 2026-08-13 attacker actually used. Without this gate "disabled"
 * meant "cannot obtain NEW credentials", which is worth very little against
 * someone already holding one: OAuth access tokens live 24h, refresh tokens
 * 365d, and API keys never expire.
 *
 * Checked against the EFFECTIVE identity, which for an API key can be two
 * accounts: the key's owner and — for an admin key carrying an acts-as
 * binding — the user it impersonates. Either being disabled refuses the
 * request. A disabled owner must not keep acting through anyone, and an
 * enabled admin must not keep acting AS someone who was just locked out.
 *
 * Returns the first disabled account id so the caller can name it in the log.
 */
async function findDisabledIdentity(
  candidateUserIds: Array<string | null | undefined>,
): Promise<string | undefined> {
  for (const userId of candidateUserIds) {
    // Public API keys carry no owner (`user_id` is NULL by design — see
    // checkApiKeyAccess) and unscoped keys carry no acts-as target. There is
    // no account behind those, so there is nothing to lock out and skipping is
    // not a fail-open hole. Calling isDisabled(undefined) instead would match
    // no row, fail CLOSED to `true`, and take every public API key on the
    // gateway offline the moment this shipped.
    if (!userId) continue;
    // Sequential on purpose: at most two ids, and the common answer is "not
    // disabled" for the first one, so this is one indexed primary-key select
    // on a path that has already spent a DB round-trip validating the
    // credential itself.
    if (await usersRepository.isDisabled(userId)) return userId;
  }
  return undefined;
}

/**
 * Extract authentication token from request headers and query parameters
 */
function extractAuthToken(
  req: express.Request,
  endpoint: DatabaseEndpoint,
): {
  token?: string;
  source: "x-api-key" | "authorization" | "query" | "none";
  isOAuthLikeToken: boolean;
} {
  // Check for API key in X-API-Key header
  const apiKeyHeader = req.headers["x-api-key"] as string;
  if (apiKeyHeader) {
    return {
      token: apiKeyHeader,
      source: "x-api-key",
      isOAuthLikeToken: false,
    };
  }

  // Check Authorization header (Bearer token)
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith("Bearer ")) {
    const token = authHeader.substring(7);
    return {
      token,
      source: "authorization",
      isOAuthLikeToken: token.startsWith("mcp_token_"),
    };
  }

  // Check query parameters for API key (if enabled)
  if (endpoint.enable_api_key_auth && endpoint.use_query_param_auth) {
    const queryApiKey =
      (req.query.api_key as string) || (req.query.apikey as string);
    if (queryApiKey) {
      return {
        token: queryApiKey,
        source: "query",
        isOAuthLikeToken: false,
      };
    }
  }

  return { source: "none", isOAuthLikeToken: false };
}

/**
 * Record a refused MCP bearer attempt to the durable audit log.
 *
 * THIS IS THE STOLEN-KEY DETECTOR, and its absence is the single largest
 * forensic gap a security review exposed. This middleware is the layer
 * every machine-plane caller passes through — API keys and OAuth bearer
 * tokens, i.e. the credential class the attacker actually held — and until
 * now it wrote NOTHING on refusal. Not a log line, not a counter. A stolen
 * key being tried against endpoint after endpoint was indistinguishable from
 * silence.
 *
 * WHAT IS AND IS NOT STORED: the presented credential is fingerprinted
 * (sha256 + last 4), never written. That is deliberately enough to answer
 * "is this the same credential that was refused 400 times last night, and is
 * it one of ours?" — and useless to anyone who later reads the audit table.
 * `key_uuid` / `user_id` are recorded when the credential resolved to a row;
 * on an invalid credential there is nothing to resolve and the actor is
 * honestly `anonymous`.
 *
 * NOISE, stated because it is a deliberate trade: the no-credential 401s are
 * emitted too, even though every well-behaved MCP client produces one on its
 * first request (that 401 IS the OAuth discovery handshake). They carry
 * `reason: "no_credential"` so a query can exclude them in one predicate.
 * Dropping them at the source instead would also drop unauthenticated
 * endpoint scanning, which is exactly the recon phase such an attack begins
 * with. Volume management belongs in Phase 2 retention, not in deciding not
 * to see it.
 *
 * Fire-and-forget: `emit` never throws and is never awaited, and this
 * wrapper adds its own guard so that even a future change to the envelope
 * construction cannot turn a logging bug into a failed auth response.
 */
function emitMcpAuthDenial(
  req: express.Request,
  endpoint: DatabaseEndpoint | undefined,
  denial: {
    httpStatus: number;
    /** Machine-readable denial cause, queried far more often than the status. */
    reason: string;
    presentedToken?: string;
    authMethod?: "api_key" | "oauth";
    actorType?: AuditActorType;
    actorId?: string | null;
  },
): void {
  try {
    const requestContext = auditRequestContext(req);
    emit({
      actor_type: denial.actorType ?? "anonymous",
      actor_id: denial.actorId ?? null,
      actor_label: null,
      actor_ip: requestContext.actor_ip,
      actor_user_agent: requestContext.actor_user_agent,
      action:
        denial.httpStatus === 429 ? "mcp.auth.ratelimited" : "mcp.auth.denied",
      target_type: "endpoint",
      target_id: endpoint?.uuid ?? null,
      outcome: "denied",
      request_id: requestContext.request_id,
      http_status: denial.httpStatus,
      detail: {
        reason: denial.reason,
        auth_method: denial.authMethod ?? null,
        endpoint_name: endpoint?.name ?? null,
        credential: credentialFingerprint(denial.presentedToken),
      },
    });
  } catch {
    // An audit failure must never change what this middleware answers. See
    // lib/audit/audit-emitter for the full contract.
  }
}

/**
 * Apply the access-group gate to an OAuth caller, answering 403 when it refuses.
 *
 * Returns `true` when the request was ANSWERED (i.e. the caller must stop), and
 * `false` when the caller may continue to `next()`. That shape rather than a
 * boolean "allowed" so the two OAuth branches below stay a flat sequence of
 * early returns like every other check in this middleware, instead of growing a
 * nested conditional around their `next()`.
 *
 * Placed AFTER `checkOAuthAccess` at both call sites: an endpoint the caller
 * cannot reach on ownership grounds keeps its existing, more specific message,
 * and the group gate only ever narrows a request that would otherwise have been
 * served. On an endpoint with `restricted` false this costs one boolean read
 * and no round trip — see `lib/endpoint-access-control`.
 *
 * The deny path writes an `endpoint.access.denied` audit row through the same
 * fire-and-forget emitter as every other refusal here, throttled per
 * (user, endpoint) with a suppressed-since-last count so a retrying connector
 * cannot flood a table that has no prune path. Emission never affects the
 * answer: `emit` swallows its own failures and the envelope build is guarded.
 */
async function refuseByAccessGroup(
  req: express.Request,
  res: express.Response,
  endpoint: DatabaseEndpoint,
  userId: string | undefined,
  presentedToken: string,
): Promise<boolean> {
  // The gate is off for this endpoint: no cache read, no query, nothing. This
  // early return is what makes the feature inert at cutover, with nothing
  // seeded and nothing flagged.
  if (!endpoint.restricted) return false;

  // A token carrying no user cannot belong to a group. `checkOAuthAccess`
  // already refuses that case before this runs, so the `undefined` arm is
  // defence in depth rather than a reachable branch — and it fails CLOSED,
  // which is the only safe direction on an endpoint an operator switched on.
  const allowed = userId
    ? await isOAuthUserAllowedOnEndpoint(userId, endpoint)
    : false;
  if (allowed) return false;

  const { emit: shouldEmit, suppressed } = recordAccessDenial(
    userId ?? "",
    endpoint.uuid,
  );
  if (shouldEmit) {
    try {
      const requestContext = auditRequestContext(req);
      emit({
        actor_type: "user",
        actor_id: userId ?? null,
        actor_label: null,
        actor_ip: requestContext.actor_ip,
        actor_user_agent: requestContext.actor_user_agent,
        action: "endpoint.access.denied",
        target_type: "endpoint",
        target_id: endpoint.uuid,
        outcome: "denied",
        request_id: requestContext.request_id,
        http_status: 403,
        detail: {
          reason: "access_group_denied",
          auth_method: "oauth",
          endpoint_name: endpoint.name,
          credential: credentialFingerprint(presentedToken),
          // Attempts swallowed by the throttle since the last row was written,
          // so volume survives even though per-attempt timestamps do not.
          suppressed_since_last: suppressed,
        },
      });
    } catch {
      // An audit failure must never change what this middleware answers. Same
      // contract as emitMcpAuthDenial above.
    }
  }

  logger.warn(
    `[auth] oauth token rejected reason=access_group endpoint=${endpoint.uuid} user=${userId ?? "unattributed"}`,
  );

  res.status(403).json({
    error: "access_denied",
    // `error_description` rather than `message`, matching every other 403 on
    // the OAuth branches of this middleware. The string is verbatim operator
    // copy and is asserted byte-for-byte in endpoint-access-groups.test.ts —
    // it is the only sentence a refused user ever sees.
    error_description: ENDPOINT_ACCESS_DENIED_MESSAGE,
    timestamp: new Date().toISOString(),
  });
  return true;
}

/**
 * Deployment escape hatch for an endpoint with BOTH auth toggles off.
 *
 * CONDITION 1 below used to `next()` such an endpoint straight through with a
 * `// Pass through without authentication` comment, and that is exactly what
 * it did: one mis-set pair of toggles in the admin UI published that
 * namespace's entire tool set to anyone who could reach the gateway, with no
 * credential to steal, no audit actor to name and no rate-limit bucket to
 * fill. Nothing about the request announced it was public; it simply was. An
 * MCP gateway serving an integration estate should not have a configuration
 * that silently means "no authentication", so the default is now refusal and
 * an operator who genuinely wants a public endpoint has to say so at the
 * deployment level, where it is reviewable, rather than in a per-endpoint
 * checkbox.
 *
 * Read per request rather than captured at module load: a security escape
 * hatch must reflect the process environment as it is now, and a per-request
 * `process.env` read costs nothing on a path that is about to make at least
 * one database round-trip.
 *
 * Strict `"true"`: unset, empty, `1`, `yes` and `TRUE` are all OFF. This is
 * the same comparison `BOOTSTRAP_DEBUG` and `TRANSFORM_LOCALHOST_TO_DOCKER_INTERNAL`
 * use, and a gate that removes authentication should not be openable by a
 * near-miss spelling.
 */
function unauthenticatedEndpointsAllowed(): boolean {
  return process.env.ALLOW_UNAUTHENTICATED_ENDPOINTS === "true";
}

/**
 * Endpoint uuids already named in a CONDITION 1 warning this process.
 *
 * Deduped because the warning describes a CONFIGURATION, which does not change
 * between two requests a millisecond apart, while the requests hitting it can
 * arrive as fast as a scanner can send them. Logging every one would turn an
 * operator notice into a log-flood amplifier, and the misconfigured endpoint is
 * unauthenticated, so an attacker controls the request rate. The durable
 * per-request record still exists: every refusal emits an audit row via
 * `emitMcpAuthDenial`, which is the queryable surface. This Set is only the
 * "look at your logs" signal, and it resets on restart, so a misconfiguration
 * that survives a redeploy is announced again.
 */
const warnedUnauthenticatedEndpoints = new Set<string>();

function warnUnauthenticatedEndpoint(
  endpoint: DatabaseEndpoint,
  outcome: string,
): void {
  const key = endpoint.uuid || endpoint.name;
  if (warnedUnauthenticatedEndpoints.has(key)) return;
  warnedUnauthenticatedEndpoints.add(key);
  logger.warn(
    `[auth] endpoint "${endpoint.name}" (${endpoint.uuid}) has NO authentication configured: ${outcome}`,
  );
}

/**
 * Test seam for the dedupe Set above. Exported rather than made public state
 * because a per-process Set is the right shape for the log-flood problem and
 * the wrong shape for a test file that needs two independent cases.
 */
export function __resetUnauthenticatedEndpointWarnings(): void {
  warnedUnauthenticatedEndpoints.clear();
}

/**
 * Enhanced authentication middleware organized by 4 clear conditions
 * to prevent infinite retry issues with MCP inspector
 */
export const authenticateApiKey = async (
  req: express.Request,
  res: express.Response,
  next: express.NextFunction,
) => {
  const authReq = req as ApiKeyAuthenticatedRequest;
  const endpoint = authReq.endpoint;

  // Extract token information
  const { token, source, isOAuthLikeToken } = extractAuthToken(req, endpoint);

  // ===== CONDITION 1: Both API key and OAuth OFF =====
  if (!endpoint?.enable_api_key_auth && !endpoint?.enable_oauth) {
    // A missing endpoint record is a ROUTING bug, not a deliberate "publish
    // this namespace" choice, so the escape hatch below deliberately does not
    // cover it: there is no namespace an operator could have opted into and
    // nothing downstream to serve. It fails closed unconditionally.
    if (endpoint && unauthenticatedEndpointsAllowed()) {
      warnUnauthenticatedEndpoint(
        endpoint,
        "served WITHOUT AUTHENTICATION because ALLOW_UNAUTHENTICATED_ENDPOINTS=true",
      );
      return next();
    }

    if (endpoint) {
      warnUnauthenticatedEndpoint(
        endpoint,
        "REFUSED: both enable_api_key_auth and enable_oauth are off. Turn one on, or set ALLOW_UNAUTHENTICATED_ENDPOINTS=true to publish it unauthenticated on purpose",
      );
    }
    emitMcpAuthDenial(req, endpoint, {
      httpStatus: 401,
      reason: "unauthenticated_endpoint_refused",
    });
    return sendAuthenticationRequiredChallenge(req, res);
  }

  try {
    // ===== CONDITION 2: API key ON, OAuth OFF =====
    if (endpoint.enable_api_key_auth && !endpoint.enable_oauth) {
      if (!token) {
        // No token provided - request API key
        emitMcpAuthDenial(req, endpoint, {
          httpStatus: 401,
          reason: "no_credential",
        });
        return sendApiKeyRequiredResponse(req, res);
      }

      // Validate API key
      const apiKeyResult = await apiKeysRepository.validateApiKey(token);

      if (apiKeyResult?.valid) {
        // Admin-bound acts-as identity (migration 0024) — stamped on BOTH
        // api-key branches so the m365 context gate sees it regardless of
        // whether the endpoint also has OAuth enabled. Runtime pairing
        // re-check via resolveActsAsUserId: never stamped for an unscoped
        // row.
        const actsAsUserId = resolveActsAsUserId(apiKeyResult);

        // `users.disabled` gate (migration 0027) — see findDisabledIdentity.
        // Runs BEFORE the endpoint access check so a locked-out account gets
        // one uniform refusal everywhere instead of scope-specific messages
        // that map out which endpoints its key could otherwise reach. Nothing
        // is stamped on the request and next() is never reached, so the
        // downstream m365 identity injection never sees this caller.
        const disabledUserId = await findDisabledIdentity([
          apiKeyResult.user_id,
          actsAsUserId,
        ]);
        if (disabledUserId) {
          logger.warn(
            `[auth] api key rejected reason=disabled endpoint=${endpoint.uuid} key=${apiKeyResult.key_uuid} user=${disabledUserId}`,
          );
          emitMcpAuthDenial(req, endpoint, {
            httpStatus: 403,
            reason: "account_disabled",
            presentedToken: token,
            authMethod: "api_key",
            actorType: "api_key",
            actorId: apiKeyResult.key_uuid,
          });
          return res.status(403).json({
            error: "Access denied",
            message:
              "This credential is not currently permitted to access this gateway.",
            timestamp: new Date().toISOString(),
          });
        }

        // API key valid - perform access control and pass
        authReq.apiKeyUserId = apiKeyResult.user_id || undefined;
        authReq.apiKeyUuid = apiKeyResult.key_uuid;
        authReq.apiKeyActsAsUserId = actsAsUserId;
        authReq.authMethod = "api_key";

        const accessCheckResult = checkApiKeyAccess(apiKeyResult, endpoint);
        if (!accessCheckResult.allowed) {
          emitMcpAuthDenial(req, endpoint, {
            httpStatus: 403,
            reason: "endpoint_access_denied",
            presentedToken: token,
            authMethod: "api_key",
            actorType: "api_key",
            actorId: apiKeyResult.key_uuid,
          });
          return res.status(403).json({
            error: "Access denied",
            message: accessCheckResult.message,
            timestamp: new Date().toISOString(),
          });
        }

        return next();
      } else {
        // API key invalid - check rate limiting
        const rateLimitId = getAuthRateLimitIdentifier(req, endpoint);

        // READ-ONLY check, and it runs BEFORE the record on purpose: one failed
        // request must cost exactly one count. `isRateLimited` counts the
        // question it is asked, so pairing it with `recordFailedAttempt` landed
        // two counts per failure and refused on the eleventh attempt against a
        // nominal twenty. See the budget note in lib/auth-rate-limiter.
        if (authRateLimiter.isCurrentlyLimited(rateLimitId)) {
          emitMcpAuthDenial(req, endpoint, {
            httpStatus: 429,
            reason: "too_many_failed_attempts",
            presentedToken: token,
            authMethod: "api_key",
          });
          return res.status(429).json({
            error: "too_many_requests",
            error_description:
              "Too many failed authentication attempts. Please try again later.",
            timestamp: new Date().toISOString(),
          });
        }

        // Recorded only once the caller is inside its budget: a request already
        // refused above never reached the credential check, so counting it
        // would be counting the limiter's own answer.
        authRateLimiter.recordFailedAttempt(rateLimitId);

        emitMcpAuthDenial(req, endpoint, {
          httpStatus: 401,
          reason: "invalid_api_key",
          presentedToken: token,
          authMethod: "api_key",
        });
        return res.status(401).json({
          error: "invalid_api_key",
          error_description: "The provided API key is invalid or expired",
          timestamp: new Date().toISOString(),
        });
      }
    }

    // ===== CONDITION 3: API key ON, OAuth ON =====
    if (endpoint.enable_api_key_auth && endpoint.enable_oauth) {
      if (!token) {
        // No token provided - allow OAuth flow
        emitMcpAuthDenial(req, endpoint, {
          httpStatus: 401,
          reason: "no_credential",
        });
        return sendOAuthChallengeResponse(req, res, endpoint);
      }

      // If token looks like OAuth token or came from Authorization header, try OAuth first
      if (isOAuthLikeToken || source === "authorization") {
        const oauthResult = await validateOAuthToken(token);

        if (oauthResult.valid) {
          // `users.disabled` gate (migration 0027) — see findDisabledIdentity.
          // Introspection deliberately stays a pure token-row lookup, so the
          // account check has to happen here, at the call site that turns a
          // token into a caller.
          const disabledUserId = await findDisabledIdentity([
            oauthResult.user_id,
          ]);
          if (disabledUserId) {
            logger.warn(
              `[auth] oauth token rejected reason=disabled endpoint=${endpoint.uuid} user=${disabledUserId}`,
            );
            emitMcpAuthDenial(req, endpoint, {
              httpStatus: 403,
              reason: "account_disabled",
              presentedToken: token,
              authMethod: "oauth",
              actorType: "user",
              actorId: oauthResult.user_id ?? null,
            });
            return res.status(403).json({
              error: "access_denied",
              error_description:
                "This credential is not currently permitted to access this gateway.",
              timestamp: new Date().toISOString(),
            });
          }

          // OAuth token valid - perform access control and pass
          authReq.oauthUserId = oauthResult.user_id;
          authReq.authMethod = "oauth";

          const accessCheckResult = checkOAuthAccess(oauthResult, endpoint);
          if (!accessCheckResult.allowed) {
            emitMcpAuthDenial(req, endpoint, {
              httpStatus: 403,
              reason: "endpoint_access_denied",
              presentedToken: token,
              authMethod: "oauth",
              actorType: "user",
              actorId: oauthResult.user_id ?? null,
            });
            return res.status(403).json({
              error: "access_denied",
              error_description: accessCheckResult.message,
              timestamp: new Date().toISOString(),
            });
          }

          // Access-group gate (migration 0033), AFTER the ownership check so an
          // endpoint refused on ownership grounds keeps its more specific
          // message. No-op unless this endpoint has `restricted` set.
          if (
            await refuseByAccessGroup(
              req,
              res,
              endpoint,
              oauthResult.user_id,
              token,
            )
          ) {
            return;
          }

          return next();
        }
      }

      // Try API key validation
      const apiKeyResult = await apiKeysRepository.validateApiKey(token);

      if (apiKeyResult?.valid) {
        // Admin-bound acts-as identity (migration 0024) — stamped on BOTH
        // api-key branches so the m365 context gate sees it regardless of
        // whether the endpoint also has OAuth enabled. Runtime pairing
        // re-check via resolveActsAsUserId: never stamped for an unscoped
        // row.
        const actsAsUserId = resolveActsAsUserId(apiKeyResult);

        // `users.disabled` gate (migration 0027) — see findDisabledIdentity.
        // Runs BEFORE the endpoint access check so a locked-out account gets
        // one uniform refusal everywhere instead of scope-specific messages
        // that map out which endpoints its key could otherwise reach. Nothing
        // is stamped on the request and next() is never reached, so the
        // downstream m365 identity injection never sees this caller.
        const disabledUserId = await findDisabledIdentity([
          apiKeyResult.user_id,
          actsAsUserId,
        ]);
        if (disabledUserId) {
          logger.warn(
            `[auth] api key rejected reason=disabled endpoint=${endpoint.uuid} key=${apiKeyResult.key_uuid} user=${disabledUserId}`,
          );
          emitMcpAuthDenial(req, endpoint, {
            httpStatus: 403,
            reason: "account_disabled",
            presentedToken: token,
            authMethod: "api_key",
            actorType: "api_key",
            actorId: apiKeyResult.key_uuid,
          });
          return res.status(403).json({
            error: "Access denied",
            message:
              "This credential is not currently permitted to access this gateway.",
            timestamp: new Date().toISOString(),
          });
        }

        // API key valid - perform access control and pass
        authReq.apiKeyUserId = apiKeyResult.user_id || undefined;
        authReq.apiKeyUuid = apiKeyResult.key_uuid;
        authReq.apiKeyActsAsUserId = actsAsUserId;
        authReq.authMethod = "api_key";

        const accessCheckResult = checkApiKeyAccess(apiKeyResult, endpoint);
        if (!accessCheckResult.allowed) {
          emitMcpAuthDenial(req, endpoint, {
            httpStatus: 403,
            reason: "endpoint_access_denied",
            presentedToken: token,
            authMethod: "api_key",
            actorType: "api_key",
            actorId: apiKeyResult.key_uuid,
          });
          return res.status(403).json({
            error: "Access denied",
            message: accessCheckResult.message,
            timestamp: new Date().toISOString(),
          });
        }

        return next();
      } else {
        // Both OAuth and API key failed - check rate limiting
        const rateLimitId = getAuthRateLimitIdentifier(req, endpoint);

        // READ-ONLY check, and it runs BEFORE the record on purpose: one failed
        // request must cost exactly one count. `isRateLimited` counts the
        // question it is asked, so pairing it with `recordFailedAttempt` landed
        // two counts per failure and refused on the eleventh attempt against a
        // nominal twenty. See the budget note in lib/auth-rate-limiter.
        if (authRateLimiter.isCurrentlyLimited(rateLimitId)) {
          emitMcpAuthDenial(req, endpoint, {
            httpStatus: 429,
            reason: "too_many_failed_attempts",
            presentedToken: token,
          });
          return res.status(429).json({
            error: "too_many_requests",
            error_description:
              "Too many failed authentication attempts. Please try again later.",
            timestamp: new Date().toISOString(),
          });
        }

        // Recorded only once the caller is inside its budget — see the note on
        // the api-key branch above.
        authRateLimiter.recordFailedAttempt(rateLimitId);

        emitMcpAuthDenial(req, endpoint, {
          httpStatus: 401,
          reason: "invalid_credentials",
          presentedToken: token,
        });
        return res.status(401).json({
          error: "invalid_credentials",
          error_description:
            "Authentication failed. Invalid credentials provided.",
          timestamp: new Date().toISOString(),
        });
      }
    }

    // ===== CONDITION 4: API key OFF, OAuth ON =====
    if (!endpoint.enable_api_key_auth && endpoint.enable_oauth) {
      if (!token) {
        // No token provided - allow OAuth flow
        emitMcpAuthDenial(req, endpoint, {
          httpStatus: 401,
          reason: "no_credential",
        });
        return sendOAuthChallengeResponse(req, res, endpoint);
      }

      // Validate OAuth token
      const oauthResult = await validateOAuthToken(token);

      if (oauthResult.valid) {
        // `users.disabled` gate (migration 0027) — see findDisabledIdentity.
        // Same check as the OAuth branch of CONDITION 3; both call sites carry
        // it because either one alone leaves the other endpoint shape open.
        const disabledUserId = await findDisabledIdentity([
          oauthResult.user_id,
        ]);
        if (disabledUserId) {
          logger.warn(
            `[auth] oauth token rejected reason=disabled endpoint=${endpoint.uuid} user=${disabledUserId}`,
          );
          emitMcpAuthDenial(req, endpoint, {
            httpStatus: 403,
            reason: "account_disabled",
            presentedToken: token,
            authMethod: "oauth",
            actorType: "user",
            actorId: oauthResult.user_id ?? null,
          });
          return res.status(403).json({
            error: "access_denied",
            error_description:
              "This credential is not currently permitted to access this gateway.",
            timestamp: new Date().toISOString(),
          });
        }

        // OAuth token valid - perform access control and pass
        authReq.oauthUserId = oauthResult.user_id;
        authReq.authMethod = "oauth";

        const accessCheckResult = checkOAuthAccess(oauthResult, endpoint);
        if (!accessCheckResult.allowed) {
          emitMcpAuthDenial(req, endpoint, {
            httpStatus: 403,
            reason: "endpoint_access_denied",
            presentedToken: token,
            authMethod: "oauth",
            actorType: "user",
            actorId: oauthResult.user_id ?? null,
          });
          return res.status(403).json({
            error: "access_denied",
            error_description: accessCheckResult.message,
            timestamp: new Date().toISOString(),
          });
        }

        // Access-group gate (migration 0033). Both OAuth branches carry it:
        // either one alone would leave the other endpoint shape ungated, the
        // same reason the `users.disabled` check is duplicated here.
        if (
          await refuseByAccessGroup(
            req,
            res,
            endpoint,
            oauthResult.user_id,
            token,
          )
        ) {
          return;
        }

        return next();
      } else {
        // OAuth token invalid - check rate limiting
        const rateLimitId = getAuthRateLimitIdentifier(req, endpoint);

        // READ-ONLY check, and it runs BEFORE the record on purpose: one failed
        // request must cost exactly one count. `isRateLimited` counts the
        // question it is asked, so pairing it with `recordFailedAttempt` landed
        // two counts per failure and refused on the eleventh attempt against a
        // nominal twenty. See the budget note in lib/auth-rate-limiter.
        if (authRateLimiter.isCurrentlyLimited(rateLimitId)) {
          emitMcpAuthDenial(req, endpoint, {
            httpStatus: 429,
            reason: "too_many_failed_attempts",
            presentedToken: token,
            authMethod: "oauth",
          });
          return res.status(429).json({
            error: "too_many_requests",
            error_description:
              "Too many failed authentication attempts. Please try again later.",
            timestamp: new Date().toISOString(),
          });
        }

        // Recorded only once the caller is inside its budget — see the note on
        // the api-key branch above.
        authRateLimiter.recordFailedAttempt(rateLimitId);

        emitMcpAuthDenial(req, endpoint, {
          httpStatus: 401,
          reason: "invalid_token",
          presentedToken: token,
          authMethod: "oauth",
        });
        return res.status(401).json({
          error: "invalid_token",
          error_description:
            "The provided OAuth token is invalid or has expired.",
          timestamp: new Date().toISOString(),
        });
      }
    }

    // Fallback - should not reach here with the conditions above
    return res.status(500).json({
      error: "Internal server error",
      message: "Invalid authentication configuration",
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    logger.error("Error in authentication middleware:", error);
    return res.status(500).json({
      error: "Internal server error",
      message: "Failed to validate authentication",
      timestamp: new Date().toISOString(),
    });
  }
};

/**
 * Re-exported from lib/api-key-identity so this module stays the address unit
 * tests and existing callers already use, while the tRPC validate oracle can
 * import the pure function without loading this module's db-backed
 * dependencies. See that file for what the resolver enforces and why.
 */
export { resolveActsAsUserId };

/**
 * Check if API key has access to the endpoint.
 *
 * Scope semantics (migration 0023):
 * - validation.endpoint_uuid non-NULL — the key is scoped to exactly ONE
 *   endpoint and is denied everywhere else.
 * - validation.endpoint_uuid NULL/undefined — legacy/unscoped (grandfathered):
 *   reaches every enable_api_key_auth endpoint as before, UNLESS the endpoint
 *   sets require_scoped_api_key, which opts it out of gateway-wide keys.
 *
 * Exported for unit tests (api-key-access.test.ts); production callers are the
 * two authenticateApiKey branches above.
 */
export function checkApiKeyAccess(
  validation: { user_id?: string | null; endpoint_uuid?: string | null },
  endpoint: DatabaseEndpoint,
): { allowed: boolean; message?: string } {
  const isScopedKey =
    validation.endpoint_uuid !== null && validation.endpoint_uuid !== undefined;

  // A scoped key is valid ONLY on the endpoint it is bound to.
  if (isScopedKey && validation.endpoint_uuid !== endpoint.uuid) {
    return {
      allowed: false,
      message:
        "This API key is scoped to a different endpoint. Use a key scoped to this endpoint, or an unscoped (gateway-wide) key.",
    };
  }

  // An endpoint may opt out of legacy gateway-wide keys entirely: when
  // require_scoped_api_key is set, only keys explicitly scoped to THIS
  // endpoint authenticate — unscoped (grandfathered) keys are refused.
  if (!isScopedKey && endpoint.require_scoped_api_key) {
    return {
      allowed: false,
      message:
        "This endpoint requires an endpoint-scoped API key. Unscoped (gateway-wide) API keys are not accepted here — mint a key scoped to this endpoint.",
    };
  }

  const isPublicApiKey = validation.user_id === null;
  const isPrivateEndpoint = endpoint.user_id !== null;

  if (isPublicApiKey && isPrivateEndpoint) {
    return {
      allowed: false,
      message:
        "Public API keys cannot access private endpoints. Use a private API key owned by the endpoint owner.",
    };
  }

  if (
    !isPublicApiKey &&
    isPrivateEndpoint &&
    endpoint.user_id !== validation.user_id
  ) {
    return {
      allowed: false,
      message: "You can only access endpoints you own or public endpoints.",
    };
  }

  return { allowed: true };
}

/**
 * Check if OAuth token user has access to the endpoint.
 *
 * Scope note (migration 0023): `endpoint.require_scoped_api_key` is
 * DELIBERATELY not consulted here. That toggle governs API KEYS only —
 * it refuses grandfathered gateway-wide *keys* on a sensitive endpoint.
 * OAuth consumers are authenticated humans identified by their better-auth
 * user id, not bearer secrets that could be over-broadly scoped; access is
 * already gated by endpoint ownership below (public endpoints: any
 * authenticated user; private endpoints: the owner only), and delegated
 * identity injection (m365) acts strictly as that user. There is no
 * "unscoped OAuth token" to refuse, so applying the API-key-only flag to
 * OAuth would be a category error. The flag's UI copy and the tRPC field
 * comment state this API-key-only limit explicitly.
 *
 * THE MIRROR IMAGE, since migration 0033: `endpoints.restricted` and the access
 * groups behind it are OAUTH-ONLY, and API keys are deliberately exempt from
 * THEM for the same category reason read the other way. A key is admin-minted
 * and already scoped per endpoint; the group model asks "which PERSON is this",
 * which a machine credential cannot answer meaningfully — its owner is an
 * administrative detail, not the identity it acts as. So the two mechanisms
 * cover the two credential classes and neither reaches across. That gate is
 * applied by `refuseByAccessGroup` above, AFTER this function has passed, so a
 * private endpoint owned by someone else still gets the specific message below
 * rather than the generic group refusal.
 */
function checkOAuthAccess(
  oauthResult: { user_id?: string; scopes?: string[] },
  endpoint: DatabaseEndpoint,
): { allowed: boolean; message?: string } {
  // If no user_id in token, deny access
  if (!oauthResult.user_id) {
    return {
      allowed: false,
      message: "OAuth token missing user information",
    };
  }

  // Check endpoint access based on user permissions:
  // 1. Public endpoints (user_id is null) - accessible to all authenticated users
  // 2. Private endpoints (user_id is not null) - only accessible to the owner

  if (endpoint.user_id === null) {
    // Public endpoint - any authenticated user can access
    return { allowed: true };
  }

  if (endpoint.user_id === oauthResult.user_id) {
    // Private endpoint owned by the user - allowed
    return { allowed: true };
  }

  // Private endpoint owned by someone else - denied
  return {
    allowed: false,
    message: `Access denied. This is a private endpoint owned by another user. You can only access public endpoints or endpoints you own.`,
  };
}
