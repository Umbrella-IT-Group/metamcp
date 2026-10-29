import { DatabaseEndpoint } from "@repo/zod-types";
import express from "express";

import { getBaseUrl, GRANTED_OAUTH_SCOPE } from "../routers/oauth/utils";

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
 * Path-scoped resource metadata is included in OAuth challenges. Its URL is
 * derived solely from the request path: a guessed name and a real endpoint
 * requested at the same URL must have identical no-credential responses.
 * API-key-only endpoints still omit the WWW-Authenticate header and keep
 * the legacy unscoped metadata URL in their response body.
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

function resourceMetadataUrl(
  req: express.Request,
  endpointScoped: boolean,
): string {
  const discoveryUrl = `${getBaseUrl(req)}/.well-known/oauth-protected-resource`;
  if (!endpointScoped) return discoveryUrl;

  // Express retains the public /metamcp mount in baseUrl and the encoded
  // resource suffix in path (without query parameters). Depend only on the
  // requested URL, never on whether that endpoint exists or permits OAuth.
  const resourcePath = `${req.baseUrl ?? ""}${req.path ?? ""}`;
  return resourcePath.startsWith("/metamcp/")
    ? `${discoveryUrl}${resourcePath}`
    : discoveryUrl;
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
  const metadata = resourceMetadataUrl(req, true);

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
 * tokens). The body is now the shared one; see the RESIDUAL note on
 * `sendAuthenticationRequiredChallenge` for why the header asymmetry survives.
 */
export function sendApiKeyRequiredResponse(
  req: express.Request,
  res: express.Response,
): express.Response {
  return res
    .status(401)
    .json(buildAuthenticationRequiredBody(resourceMetadataUrl(req, false)));
}

/**
 * Send OAuth challenge response with proper WWW-Authenticate header.
 *
 * The endpoint argument remains unused: known OAuth-enabled endpoints and
 * unknown names deliberately get the same path-scoped challenge shape.
 */
export function sendOAuthChallengeResponse(
  req: express.Request,
  res: express.Response,
  _endpoint: DatabaseEndpoint,
): express.Response {
  return sendAuthenticationRequiredChallenge(req, res);
}
