/**
 * What a group's mapping onto one endpoint actually does today.
 *
 * `restricted` alone cannot say, and reporting it alone is wrong in the
 * reassuring direction. The access-group gate governs OAUTH callers only, and
 * the API-key plane is a separate way in, so:
 *
 *   off        the endpoint has not opted in; the mapping is legal and inert.
 *   noOauth    it opted in, but accepts no OAuth callers, so nothing is gated.
 *   oauthOnly  it gates OAuth callers, but unscoped API keys still bypass the
 *              gate (require_scoped_api_key is off); the only remaining case
 *              is a legacy row from before the create/update pairing, which the
 *              boot-time pairing check flags for an operator to close.
 *   enforcing  no ungated path in: OAuth is gated to groups AND the API-key
 *              plane is closed to unscoped keys (API keys off entirely, or
 *              require_scoped_api_key on so only endpoint-scoped keys pass,
 *              which are themselves a deliberate per-endpoint grant, not a
 *              bypass of the access-group intent).
 *
 * `require_scoped_api_key` is what moved a restricted-plus-API-keys endpoint
 * out of "oauthOnly" and into "enforcing": the endpoint create/update pairing
 * forces it on with `restricted`, so a restricted endpoint is scoped-only by
 * construction rather than wide open on the key plane.
 */
export interface EndpointGateInput {
  restricted: boolean;
  enable_oauth: boolean;
  enable_api_key_auth: boolean;
  require_scoped_api_key: boolean;
}

export function endpointGateState(
  endpoint: EndpointGateInput,
): "off" | "noOauth" | "oauthOnly" | "enforcing" {
  if (!endpoint.restricted) return "off";
  if (!endpoint.enable_oauth) return "noOauth";
  if (endpoint.enable_api_key_auth && !endpoint.require_scoped_api_key) {
    return "oauthOnly";
  }
  return "enforcing";
}
