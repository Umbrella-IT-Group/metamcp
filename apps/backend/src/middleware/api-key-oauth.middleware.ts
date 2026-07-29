import { DatabaseEndpoint } from "@repo/zod-types";
import express from "express";

import logger from "@/utils/logger";

import { ApiKeysRepository } from "../db/repositories/api-keys.repo";
import {
  authRateLimiter,
  getAuthRateLimitIdentifier,
} from "../lib/auth-rate-limiter";

// Extend Express Request interface for our custom properties
export interface ApiKeyAuthenticatedRequest extends express.Request {
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
 * Helper function to get the correct base URL from request
 * Prioritizes APP_URL environment variable, then checks proxy headers
 */
function getBaseUrl(req: express.Request): string {
  // Prioritize APP_URL environment variable
  if (process.env.APP_URL) {
    return process.env.APP_URL;
  }

  // Check for forwarded headers from Next.js proxy
  const forwardedHost = req.headers["x-forwarded-host"] as string;
  const forwardedProto = req.headers["x-forwarded-proto"] as string;

  if (forwardedHost) {
    const protocol = forwardedProto || "http";
    return `${protocol}://${forwardedHost}`;
  }

  // Fallback to request host
  return `${req.protocol}://${req.get("host")}`;
}

/**
 * Validates OAuth bearer token using MCP token introspection
 * @param token OAuth bearer token
 * @param req Express request object
 * @returns OAuth validation result
 */
async function validateOAuthToken(
  token: string,
  req: express.Request,
): Promise<{
  valid: boolean;
  user_id?: string;
  scopes?: string[];
  error?: string;
}> {
  try {
    // Check if this is our MCP OAuth token format
    if (token.startsWith("mcp_token_")) {
      // For MCP tokens, use introspection endpoint to validate
      // This allows us to check against the stored token data
      try {
        const baseUrl = getBaseUrl(req);
        const introspectUrl = new URL("/oauth/introspect", baseUrl);

        const introspectRequest = new Request(introspectUrl.toString(), {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ token }),
        });

        const introspectResponse = await fetch(introspectRequest);

        if (!introspectResponse.ok) {
          return { valid: false, error: "Token introspection failed" };
        }

        const introspectData = (await introspectResponse.json()) as {
          active?: boolean;
          sub?: string;
          scope?: string;
        };

        if (!introspectData.active) {
          return { valid: false, error: "Token is not active" };
        }

        return {
          valid: true,
          user_id: introspectData.sub,
          scopes: introspectData.scope
            ? introspectData.scope.split(" ")
            : ["admin"],
        };
      } catch (error) {
        logger.error("Error introspecting MCP token:", error);
        return { valid: false, error: "Token validation failed" };
      }
    }

    // Token is not a recognized MCP token format
    return { valid: false, error: "Unsupported token format" };
  } catch (error) {
    logger.error("Error validating OAuth token:", error);
    return { valid: false, error: "OAuth validation failed" };
  }
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
    return next(); // Pass through without authentication
  }

  try {
    // ===== CONDITION 2: API key ON, OAuth OFF =====
    if (endpoint.enable_api_key_auth && !endpoint.enable_oauth) {
      if (!token) {
        // No token provided - request API key
        return sendApiKeyRequiredResponse(res);
      }

      // Validate API key
      const apiKeyResult = await apiKeysRepository.validateApiKey(token);

      if (apiKeyResult?.valid) {
        // API key valid - perform access control and pass
        authReq.apiKeyUserId = apiKeyResult.user_id || undefined;
        authReq.apiKeyUuid = apiKeyResult.key_uuid;
        // Admin-bound acts-as identity (migration 0024) — stamped on BOTH
        // api-key branches so the m365 context gate sees it regardless of
        // whether the endpoint also has OAuth enabled. Runtime pairing
        // re-check via resolveActsAsUserId: never stamped for an unscoped
        // row.
        authReq.apiKeyActsAsUserId = resolveActsAsUserId(apiKeyResult);
        authReq.authMethod = "api_key";

        const accessCheckResult = checkApiKeyAccess(apiKeyResult, endpoint);
        if (!accessCheckResult.allowed) {
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
        authRateLimiter.recordFailedAttempt(rateLimitId);

        if (authRateLimiter.isRateLimited(rateLimitId)) {
          return res.status(429).json({
            error: "too_many_requests",
            error_description:
              "Too many failed authentication attempts. Please try again later.",
            timestamp: new Date().toISOString(),
          });
        }

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
        return sendOAuthChallengeResponse(req, res, endpoint);
      }

      // If token looks like OAuth token or came from Authorization header, try OAuth first
      if (isOAuthLikeToken || source === "authorization") {
        const oauthResult = await validateOAuthToken(token, req);

        if (oauthResult.valid) {
          // OAuth token valid - perform access control and pass
          authReq.oauthUserId = oauthResult.user_id;
          authReq.authMethod = "oauth";

          const accessCheckResult = checkOAuthAccess(oauthResult, endpoint);
          if (!accessCheckResult.allowed) {
            return res.status(403).json({
              error: "access_denied",
              error_description: accessCheckResult.message,
              timestamp: new Date().toISOString(),
            });
          }

          return next();
        }
      }

      // Try API key validation
      const apiKeyResult = await apiKeysRepository.validateApiKey(token);

      if (apiKeyResult?.valid) {
        // API key valid - perform access control and pass
        authReq.apiKeyUserId = apiKeyResult.user_id || undefined;
        authReq.apiKeyUuid = apiKeyResult.key_uuid;
        // Admin-bound acts-as identity (migration 0024) — stamped on BOTH
        // api-key branches so the m365 context gate sees it regardless of
        // whether the endpoint also has OAuth enabled. Runtime pairing
        // re-check via resolveActsAsUserId: never stamped for an unscoped
        // row.
        authReq.apiKeyActsAsUserId = resolveActsAsUserId(apiKeyResult);
        authReq.authMethod = "api_key";

        const accessCheckResult = checkApiKeyAccess(apiKeyResult, endpoint);
        if (!accessCheckResult.allowed) {
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
        authRateLimiter.recordFailedAttempt(rateLimitId);

        if (authRateLimiter.isRateLimited(rateLimitId)) {
          return res.status(429).json({
            error: "too_many_requests",
            error_description:
              "Too many failed authentication attempts. Please try again later.",
            timestamp: new Date().toISOString(),
          });
        }

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
        return sendOAuthChallengeResponse(req, res, endpoint);
      }

      // Validate OAuth token
      const oauthResult = await validateOAuthToken(token, req);

      if (oauthResult.valid) {
        // OAuth token valid - perform access control and pass
        authReq.oauthUserId = oauthResult.user_id;
        authReq.authMethod = "oauth";

        const accessCheckResult = checkOAuthAccess(oauthResult, endpoint);
        if (!accessCheckResult.allowed) {
          return res.status(403).json({
            error: "access_denied",
            error_description: accessCheckResult.message,
            timestamp: new Date().toISOString(),
          });
        }

        return next();
      } else {
        // OAuth token invalid - check rate limiting
        const rateLimitId = getAuthRateLimitIdentifier(req, endpoint);
        authRateLimiter.recordFailedAttempt(rateLimitId);

        if (authRateLimiter.isRateLimited(rateLimitId)) {
          return res.status(429).json({
            error: "too_many_requests",
            error_description:
              "Too many failed authentication attempts. Please try again later.",
            timestamp: new Date().toISOString(),
          });
        }

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
 * Runtime re-check of the identity-requires-scope pairing (migration 0024):
 * an acts-as identity is honored ONLY on a row that also carries a single-
 * endpoint scope. Mint-time enforcement (zod + impl) cannot reach rows
 * written outside the app — psql / admin_cli is a routine ops path here, and
 * migration 0024's CHECK constraint could be dropped or predate a row — so
 * without this gate an unscoped-but-bound row would become a GATEWAY-WIDE
 * identity key honored by the streamable-http m365 context gate on every
 * endpoint the key reaches. Fail-closed: no scope → no identity, the key
 * still authenticates but injection stays inert.
 *
 * Exported for unit tests (api-key-access.test.ts); production callers are
 * the two authenticateApiKey branches above.
 */
export function resolveActsAsUserId(validation: {
  endpoint_uuid?: string | null;
  acts_as_user_id?: string | null;
}): string | undefined {
  if (
    validation.endpoint_uuid === null ||
    validation.endpoint_uuid === undefined
  ) {
    return undefined;
  }
  return validation.acts_as_user_id || undefined;
}

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

/**
 * Send API key required response (no WWW-Authenticate header to prevent OAuth flow)
 */
function sendApiKeyRequiredResponse(res: express.Response): express.Response {
  return res.status(401).json({
    error: "authentication_required",
    error_description: "Authentication required via API key",
    supported_methods: [
      "X-API-Key header",
      "query parameter (api_key or apikey)",
    ],
    timestamp: new Date().toISOString(),
  });
}

/**
 * Send OAuth challenge response with proper WWW-Authenticate header
 */
function sendOAuthChallengeResponse(
  req: express.Request,
  res: express.Response,
  endpoint: DatabaseEndpoint,
): express.Response {
  const baseUrl = getBaseUrl(req);

  // Set WWW-Authenticate header for OAuth flow
  const bearerChallenge = [
    `Bearer realm="MetaMCP"`,
    `scope="admin"`,
    `resource_metadata="${baseUrl}/.well-known/oauth-protected-resource"`,
  ].join(", ");

  res.set("WWW-Authenticate", bearerChallenge);

  const authMethods = ["Authorization header (Bearer token)"];

  // Add API key methods if also enabled
  if (endpoint.enable_api_key_auth) {
    authMethods.push("X-API-Key header");
    if (endpoint.use_query_param_auth) {
      authMethods.push("query parameter (api_key or apikey)");
    }
  }

  const errorDescription = endpoint.enable_api_key_auth
    ? "Authentication required via OAuth bearer token or API key"
    : "Authentication required via OAuth bearer token";

  return res.status(401).json({
    error: "authentication_required",
    error_description: errorDescription,
    resource_metadata: `${baseUrl}/.well-known/oauth-protected-resource`,
    supported_methods: authMethods,
    timestamp: new Date().toISOString(),
  });
}
