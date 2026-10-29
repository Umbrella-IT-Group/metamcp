import { DatabaseEndpoint } from "@repo/zod-types";
import express from "express";

import { getBaseUrl, GRANTED_OAUTH_SCOPE } from "../routers/oauth/utils";
import { matchPublicMcpResourcePath } from "./public-mcp-resource";

/**
 * The 401 challenge shapes for the `/metamcp/<name>/*` data plane, extracted
 * out of `middleware/api-key-oauth.middleware` so that
 * `middleware/lookup-endpoint-middleware` can send the same challenge for an
 * endpoint name that does not exist.
 *
 * A SEPARATE MODULE rather than an export from the middleware, and the reason
 * is a hard one rather than taste: that middleware imports `ApiKeysRepository`,
 * which imports `db/index`, which THROWS at module load when `DATABASE_URL` is
 * unset. Importing a response-shaping function from there would have made
 * every consumer, and every test that mounts one, require a database
 * connection string to render a 401. Nothing in this file touches the
 * database, and nothing in it should.
 */

/**
 * The ONE body every unauthenticated caller of `/metamcp/<name>/*` gets, no
 * matter which of the three no-credential paths produced it.
 *
 * WHY IT HAD TO BECOME ONE BODY. These responses used to describe the endpoint
 * they came from. `supported_methods` listed exactly which of `X-API-Key`,
 * `?api_key=` and Bearer that endpoint accepted, and `error_description` said
 * "via API key" or "via OAuth bearer token" or "via OAuth bearer token or API
 * key". So an anonymous caller could read an endpoint's
 * `enable_api_key_auth` / `enable_oauth` / `use_query_param_auth` triple off a
 * single unauthenticated request, before proving anything at all. Paired with
 * the name-enumeration oracle this same change removes (see
 * `lookup-endpoint-middleware`), that is a map of the estate and of its
 * weakest doors, assembled by a scanner.
 *
 * Nothing consumed the removed fields: `supported_methods` had no reader
 * anywhere in this repo, and the varying `error_description` was prose. What a
 * client actually needs in order to authenticate is the `WWW-Authenticate`
 * challenge and `resource_metadata`.
 *
 * `resource_metadata` is included on EVERY path, including the ones with no
 * OAuth configured, and it is the same URL on every path for a given request
 * URL (see `resourceMetadataUrl`). It is derived from the request path alone,
 * never from the endpoint row, so it discloses nothing about the endpoint
 * being challenged; giving API-key-only endpoints a different value would
 * reintroduce the differential this body exists to remove.
 */
function buildAuthenticationRequiredBody(
  resourceMetadata: string,
): Record<string, unknown> {
  return {
    error: "authentication_required",
    error_description: "Authentication required",
    resource_metadata: resourceMetadata,
    timestamp: new Date().toISOString(),
  };
}

/**
 * The RFC 9728 metadata URL a 401 points at: the path-scoped document for the
 * resource that was requested (RFC 9728 §5.1, and the MCP authorization spec,
 * whose clients fetch exactly this URL), or the unscoped document when the
 * request path is not exactly a public MCP resource.
 *
 * Built only from operator configuration and checked parts. The base is
 * `getBaseUrl`, which returns the normalized `APP_URL` (required at boot by
 * `auth.ts`, so its header-derived fallback is not reached by the running
 * server). The path is `matchPublicMcpResourcePath`'s rebuild of
 * `/metamcp/<name>/(mcp|sse|api)`: a name in the RFC 3986 unreserved alphabet
 * (or percent-encoded) and a literal transport. Raw request text is never
 * interpolated, because this value lands inside the quoted `resource_metadata`
 * parameter of `WWW-Authenticate`, where a `"` from a request path would end
 * the parameter early, and because a suffix after the transport would point
 * the client at a document that discovery refuses.
 *
 * Depends on the request URL only, never on whether that endpoint exists or
 * which auth toggles it has: a guessed name and a real endpoint requested at
 * the same URL get the same value. A path that does not match (a trailing
 * slash, `/message`, `/api/<tool>`, an extra segment) keeps the unscoped URL
 * every challenge advertised before, so those clients see no change.
 */
function resourceMetadataUrl(req: express.Request): string {
  const discoveryUrl = `${getBaseUrl(req)}/.well-known/oauth-protected-resource`;
  // Express keeps the public mount in `baseUrl` and the still-encoded rest of
  // the path, without the query string, in `path`.
  const resource = matchPublicMcpResourcePath(
    `${req.baseUrl ?? ""}${req.path ?? ""}`,
  );
  return resource ? `${discoveryUrl}${resource.path}` : discoveryUrl;
}

/**
 * The challenge for a caller whose request cannot be attributed to any usable
 * endpoint configuration: an endpoint name that does not exist (see
 * `lookup-endpoint-middleware`), and an endpoint whose authentication is
 * entirely off and therefore refused (CONDITION 1).
 *
 * Deliberately BYTE-IDENTICAL, header included, to what an OAuth-enabled
 * endpoint answers for the same request URL. The URL-specific metadata
 * pointer cannot reveal whether the endpoint exists.
 *
 * RESIDUAL, recorded because it is the honest limit of this fix rather than an
 * oversight. An endpoint with `enable_oauth` OFF still answers without the
 * `WWW-Authenticate` header (see `sendApiKeyRequiredResponse`), so an
 * API-KEY-ONLY endpoint stays distinguishable from a non-existent name by that
 * header's absence. Closing it would mean advertising OAuth on an endpoint
 * that does not accept OAuth tokens, which walks an OAuth-capable client
 * through discovery to a token that CONDITION 2 then rejects as a malformed
 * API key: the retry loop the header's absence exists to prevent, and not
 * something this change can verify without live connector testing. It is the
 * next step for whoever can run that test.
 */
export function sendAuthenticationRequiredChallenge(
  req: express.Request,
  res: express.Response,
): express.Response {
  const metadata = resourceMetadataUrl(req);

  res.set(
    "WWW-Authenticate",
    [
      `Bearer realm="MetaMCP"`,
      // Advertise the scope this server actually grants, not "admin". The
      // challenge is what an unauthenticated client copies into its next
      // authorization request. See GRANTED_OAUTH_SCOPE.
      `scope="${GRANTED_OAUTH_SCOPE}"`,
      `resource_metadata="${metadata}"`,
    ].join(", "),
  );

  return res.status(401).json(buildAuthenticationRequiredBody(metadata));
}

/**
 * Send API key required response (no WWW-Authenticate header, to prevent the
 * OAuth flow being started against an endpoint that does not accept OAuth
 * tokens). The body is the shared one, `resource_metadata` included. On a
 * public MCP resource path that is the scoped document, which answers 404 for
 * an endpoint with OAuth off: the honest answer for this endpoint, where the
 * unscoped document this body used to name answers 200 whenever any other
 * endpoint runs OAuth. See the RESIDUAL note on
 * `sendAuthenticationRequiredChallenge` for why the header asymmetry survives.
 */
export function sendApiKeyRequiredResponse(
  req: express.Request,
  res: express.Response,
): express.Response {
  return res
    .status(401)
    .json(buildAuthenticationRequiredBody(resourceMetadataUrl(req)));
}

/**
 * Send OAuth challenge response with proper WWW-Authenticate header.
 *
 * The endpoint argument is not read. The challenge used to be assembled from
 * that endpoint's toggles, which is precisely the fingerprint removed above,
 * and the scoped `resource_metadata` comes from the request path, not the row,
 * so a known OAuth endpoint and an unknown name get the same challenge. It
 * stays in the signature so both call sites keep recording which endpoint
 * they are challenging on behalf of.
 */
export function sendOAuthChallengeResponse(
  req: express.Request,
  res: express.Response,
  _endpoint: DatabaseEndpoint,
): express.Response {
  return sendAuthenticationRequiredChallenge(req, res);
}
