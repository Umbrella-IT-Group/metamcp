import express from "express";

import logger from "@/utils/logger";

import { endpointsRepository } from "../../db/repositories";
import { getBaseUrl, getIssuerIdentifier, GRANTED_OAUTH_SCOPE } from "./utils";

const metadataRouter = express.Router();

const PROTECTED_RESOURCE_PATH = "/.well-known/oauth-protected-resource";
const AUTHORIZATION_SERVER_PATH = "/.well-known/oauth-authorization-server";

/**
 * The mount `apps/backend/src/index.ts` gives the public MCP router, i.e. the
 * first path segment of every protected resource this gateway serves
 * (`/metamcp/<endpoint_name>/mcp`, `/sse`, `/api`).
 */
const PUBLIC_MCP_MOUNT = "metamcp";

/**
 * What a `/.well-known/oauth-*` request is asking about.
 *
 * RFC 9728 §3.1 builds a resource's metadata URL by inserting the well-known
 * segment between the host and the resource path, so a request for
 * `/metamcp/foo/mcp` arrives here as
 * `/.well-known/oauth-protected-resource/metamcp/foo/mcp` — that suffix is the
 * only thing that says WHICH endpoint the caller means. A bare request names
 * no endpoint at all.
 */
type DiscoveryTarget =
  | { kind: "endpoint"; name: string }
  | { kind: "unscoped" }
  | { kind: "unknown" };

function classifyDiscoveryRequest(
  reqPath: string,
  wellKnownPath: string,
): DiscoveryTarget {
  if (!reqPath.startsWith(wellKnownPath)) {
    return { kind: "unknown" };
  }

  const segments = reqPath
    .slice(wellKnownPath.length)
    .split("/")
    .filter((segment) => segment.length > 0);

  if (segments.length === 0) {
    return { kind: "unscoped" };
  }

  // Anything that is not a public MCP resource path is not a resource this
  // server can answer for. Treated as unknown rather than falling back to the
  // unscoped document, so a junk suffix cannot be used to fish the metadata
  // out of a deployment whose real endpoints are all OAuth-disabled.
  const rawName = segments[1];
  if (segments[0] !== PUBLIC_MCP_MOUNT || rawName === undefined) {
    return { kind: "unknown" };
  }

  let name: string;
  try {
    // `req.path` is still percent-encoded; `lookupEndpoint` matches against
    // the DECODED `req.params.endpoint_name`, so decode to ask the same
    // question of the same table.
    name = decodeURIComponent(rawName);
  } catch {
    return { kind: "unknown" };
  }

  return { kind: "endpoint", name };
}

/**
 * Gate for both discovery documents — upstream issue #277.
 *
 * Claude Code v2.1.85 (2026-03-26) added RFC 9728 discovery: it probes these
 * paths BEFORE connecting to any HTTP MCP server and, if it finds authorization
 * server metadata, starts an OAuth flow and abandons the bearer token the user
 * configured. Serving these documents unconditionally therefore breaks
 * API-key-only endpoints — the client is told to authenticate a way the
 * endpoint does not accept, every session.
 *
 * So the answer is scoped to what the caller asked about:
 *  - a named endpoint answers for itself (`enable_oauth`);
 *  - the unscoped document can only honestly say whether this gateway runs an
 *    OAuth authorization server at all, so it is served exactly when at least
 *    one endpoint has OAuth enabled.
 *
 * Fails CLOSED on an unrecognised path. A refusal is always the same 404 body
 * whether the endpoint does not exist or merely has OAuth off, so discovery
 * cannot be used to enumerate endpoint names.
 */
async function shouldServeDiscovery(target: DiscoveryTarget): Promise<boolean> {
  if (target.kind === "unknown") {
    return false;
  }

  if (target.kind === "unscoped") {
    return await endpointsRepository.hasOAuthEnabledEndpoint();
  }

  const endpoint = await endpointsRepository.findByName(target.name);
  return endpoint?.enable_oauth === true;
}

function sendDiscoveryNotFound(res: express.Response): express.Response {
  res.set({
    "Content-Type": "application/json",
    // Never cached: `enable_oauth` is a runtime toggle, and a shared cache
    // holding this 404 would keep a just-enabled endpoint undiscoverable for
    // the hour the success path asks for.
    "Cache-Control": "no-store",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET",
    "Access-Control-Allow-Headers": "Content-Type",
  });

  return res.status(404).json({
    error: "not_found",
    error_description:
      "No OAuth authorization server is available for this resource",
  });
}

/**
 * OAuth 2.0 Protected Resource Metadata endpoint
 * Implementation follows RFC 9728 and MCP OAuth specification
 * https://datatracker.ietf.org/doc/rfc9728/
 * https://modelcontextprotocol.io/specification/draft/basic/authorization
 */
const protectedResourceHandler: express.RequestHandler = async (req, res) => {
  try {
    const target = classifyDiscoveryRequest(req.path, PROTECTED_RESOURCE_PATH);
    if (!(await shouldServeDiscovery(target))) {
      return sendDiscoveryNotFound(res);
    }

    const baseUrl = getBaseUrl(req);

    // For MCP implementation, we point to our better-auth OAuth server
    // The authorization server is hosted at the same base URL
    const authServerUrl = baseUrl;

    // Ensure the resource URL has a trailing slash for OAuth validation
    // This is required by RFC 9728 for exact resource matching
    const resourceUrl = baseUrl.endsWith("/") ? baseUrl : baseUrl + "/";

    const metadata = {
      // Resource identifier - the protected resource's canonical URI
      resource: resourceUrl,

      // List of OAuth authorization server issuer identifiers
      // Point to our better-auth authorization server
      authorization_servers: [authServerUrl],

      // Supported bearer token methods (required by RFC 9728)
      bearer_methods_supported: ["header"],

      // OAuth scopes supported by this protected resource. One scope, and
      // it is not an administrative one: this document is served
      // unauthenticated to anyone doing RFC 9728 discovery, so advertising
      // "admin" both overstated what a token here carries and told a
      // stranger which string to ask for. Actual privilege comes from the
      // better-auth session role, not from this value — see
      // GRANTED_OAUTH_SCOPE.
      scopes_supported: [
        GRANTED_OAUTH_SCOPE, // Access to MCP resources this user already owns
      ],

      // Resource name for display purposes
      resource_name: "MetaMCP Protected Resource",

      // OAuth 2.0 DPoP support (disabled for now)
      dpop_bound_access_tokens_required: false,

      // Authorization details types supported (for fine-grained access)
      authorization_details_types_supported: ["mcp_endpoint_access"],

      // Resource server capabilities
      resource_server_capabilities: {
        // Supported token formats
        token_types_supported: ["Bearer"],

        // Token introspection support (proxied through frontend)
        introspection_endpoint: `${baseUrl}/oauth/introspect`,

        // Revocation support (proxied through frontend)
        revocation_endpoint: `${baseUrl}/oauth/revoke`,
      },
    };

    res.set({
      "Content-Type": "application/json",
      "Cache-Control": "public, max-age=3600", // Cache for 1 hour
      "Access-Control-Allow-Origin": "*", // Allow CORS for discovery
      "Access-Control-Allow-Methods": "GET",
      "Access-Control-Allow-Headers": "Content-Type",
    });

    return res.json(metadata);
  } catch (error) {
    logger.error("Error generating OAuth protected resource metadata:", error);
    return res.status(500).json({
      error: "internal_server_error",
      error_description: "Failed to generate OAuth metadata",
    });
  }
};

/**
 * OAuth 2.0 Authorization Server Metadata endpoint
 * This provides discovery information for MCP-compatible OAuth endpoints
 * Implementation follows RFC 8414 for OAuth 2.0 Authorization Server Metadata
 */
const authorizationServerHandler: express.RequestHandler = async (req, res) => {
  try {
    const target = classifyDiscoveryRequest(
      req.path,
      AUTHORIZATION_SERVER_PATH,
    );
    if (!(await shouldServeDiscovery(target))) {
      return sendDiscoveryNotFound(res);
    }

    const baseUrl = getBaseUrl(req);

    // The issuer identifier, trailing-slash-normalised. Shared with the RFC
    // 9207 `iss` on the authorization response through getIssuerIdentifier so
    // the two cannot drift; a strict client rejects the flow if they differ.
    const issuerUrl = getIssuerIdentifier(req);

    const metadata = {
      // Issuer identifier (required by RFC 8414)
      issuer: issuerUrl,

      // MCP-compatible OAuth endpoints (proxied through frontend)
      authorization_endpoint: `${baseUrl}/oauth/authorize`,
      token_endpoint: `${baseUrl}/oauth/token`,
      registration_endpoint: `${baseUrl}/oauth/register`,
      userinfo_endpoint: `${baseUrl}/oauth/userinfo`,

      // Supported response types (required by RFC 8414)
      response_types_supported: ["code"],

      // Supported response modes
      response_modes_supported: ["query"],

      // Supported grant types for MCP
      grant_types_supported: ["authorization_code", "refresh_token"],

      // Authentication methods
      token_endpoint_auth_methods_supported: [
        "client_secret_basic",
        "client_secret_post",
        "none",
      ],

      // Token revocation endpoint
      revocation_endpoint: `${baseUrl}/oauth/revoke`,

      // Code challenge methods - PKCE support (OAuth 2.1 compliant)
      code_challenge_methods_supported: ["S256"],

      // RFC 9207: the authorization response carries the `iss` parameter, so a
      // client can detect an authorization-server mix-up. See the redirect in
      // authorization.ts, which sets `iss` on every authorization response.
      authorization_response_iss_parameter_supported: true,

      // OAuth 2.1 compliance indicators
      require_pushed_authorization_requests: false,
      require_request_uri_registration: false,
    };

    res.set({
      "Content-Type": "application/json",
      "Cache-Control": "public, max-age=3600", // Cache for 1 hour
      "Access-Control-Allow-Origin": "*", // Allow CORS for discovery
      "Access-Control-Allow-Methods": "GET",
      "Access-Control-Allow-Headers": "Content-Type",
    });

    return res.json(metadata);
  } catch (error) {
    logger.error(
      "Error generating OAuth authorization server metadata:",
      error,
    );
    return res.status(500).json({
      error: "server_error",
      error_description: "Failed to generate authorization server metadata",
    });
  }
};

// Two registrations per document, not one: the bare path is what a client
// falls back to, and the `*rest` path is the RFC 9728 §3.1 form that names an
// endpoint. Before the gate existed only the bare form was routed, so the
// endpoint-scoped probe every modern MCP client makes first fell through to
// Express's default HTML 404.
metadataRouter.get(PROTECTED_RESOURCE_PATH, protectedResourceHandler);
metadataRouter.get(
  `${PROTECTED_RESOURCE_PATH}/*rest`,
  protectedResourceHandler,
);
metadataRouter.get(AUTHORIZATION_SERVER_PATH, authorizationServerHandler);
metadataRouter.get(
  `${AUTHORIZATION_SERVER_PATH}/*rest`,
  authorizationServerHandler,
);

export default metadataRouter;
