import { DatabaseEndpoint } from "@repo/zod-types";
import express from "express";

import { GRANTED_OAUTH_SCOPE } from "../routers/oauth/utils";

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
 * challenge and `resource_metadata`, and both are unchanged, so the OAuth
 * discovery handshake every MCP connector performs on its first request still
 * behaves exactly as it did.
 *
 * `resource_metadata` is now included on EVERY path, including the ones with
 * no OAuth configured. It is a gateway-level URL, not an endpoint-level one,
 * so it discloses nothing about the endpoint being challenged, and omitting it
 * on some paths would reintroduce the differential this exists to remove.
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

function resourceMetadataUrl(req: express.Request): string {
  return `${getBaseUrl(req)}/.well-known/oauth-protected-resource`;
}

/**
 * The challenge for a caller whose request cannot be attributed to any usable
 * endpoint configuration: an endpoint name that does not exist (see
 * `lookup-endpoint-middleware`), and an endpoint whose authentication is
 * entirely off and therefore refused (CONDITION 1).
 *
 * Deliberately BYTE-IDENTICAL, header included, to what a real OAuth-enabled
 * endpoint answers an unauthenticated request with. That identity is the whole
 * mechanism: it is the only way a probe for a name that does not exist cannot
 * be told apart from a probe for one that does.
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
 * tokens). The body is now the shared one; see the RESIDUAL note on
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
 * The endpoint argument is no longer read. The challenge used to be assembled
 * from that endpoint's toggles, which is precisely the fingerprint removed
 * above. It stays in the signature so both call sites keep recording which
 * endpoint they are challenging on behalf of, and so an endpoint-specific
 * challenge, if one is ever justified, has an obvious place to land.
 */
export function sendOAuthChallengeResponse(
  req: express.Request,
  res: express.Response,
  _endpoint: DatabaseEndpoint,
): express.Response {
  return sendAuthenticationRequiredChallenge(req, res);
}
