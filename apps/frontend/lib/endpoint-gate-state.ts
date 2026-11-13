/**
 * What a group's mapping onto one endpoint actually does today.
 *
 * `restricted` alone cannot say, and reporting it alone can be wrong in the
 * reassuring direction. The access-group gate applies to every caller that can
 * arrive at the endpoint: an OAuth sign-in is judged as the user, an API key as
 * its owner (an ownerless key is refused), for gateway-wide and
 * endpoint-scoped keys alike. So the gate is only inert when no caller can
 * arrive through it:
 *
 *   off        the endpoint has not opted in; the mapping is legal and inert.
 *   noAuth     it opted in, but accepts neither OAuth callers nor API keys, so
 *              nobody reaches it and nothing is gated.
 *   enforcing  it opted in and accepts at least one of the two.
 *
 * `require_scoped_api_key` is deliberately NOT an input. It is a separate
 * switch that only decides whether gateway-wide keys are accepted at all; the
 * owner rule applies to a key whichever way that switch is set, so it cannot
 * move an endpoint between these states.
 */
export interface EndpointGateInput {
  restricted: boolean;
  enable_oauth: boolean;
  enable_api_key_auth: boolean;
}

export function endpointGateState(
  endpoint: EndpointGateInput,
): "off" | "noAuth" | "enforcing" {
  if (!endpoint.restricted) return "off";
  if (!endpoint.enable_oauth && !endpoint.enable_api_key_auth) return "noAuth";
  return "enforcing";
}
