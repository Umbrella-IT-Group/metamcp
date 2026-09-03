import { endpointsRepository } from "../db/repositories";
import logger from "../utils/logger";

/**
 * Boot-time check for the restricted => require_scoped_api_key pairing.
 *
 * The pairing is enforced at every write path (endpoint create, endpoint
 * update, and the setEndpointRestricted toggle): turning an endpoint's OAuth
 * access-group gate on also forces its scoped-key requirement on, so a
 * restricted endpoint can never keep admitting unscoped gateway-wide API keys.
 *
 * Rows written before that enforcement can still be in the unpaired state
 * (restricted=true, require_scoped_api_key=false), where the OAuth plane is
 * gated but the API-key plane is wide open. Those are DELIBERATELY not mutated
 * in a migration: flipping require_scoped_api_key on could lock out a live
 * consumer that authenticates with an unscoped key, so each one is an operator
 * decision made with knowledge of who it affects. This module only surfaces the
 * list so the fix is a conscious act rather than a silent one.
 */
export interface UnpairedRestrictedEndpoint {
  uuid: string;
  name: string;
}

/**
 * Endpoints where the access-group gate is on but unscoped API keys still reach
 * them. Reads every endpoint once; intended for boot, not the request path.
 */
export async function findUnpairedRestrictedEndpoints(): Promise<
  UnpairedRestrictedEndpoint[]
> {
  const endpoints = await endpointsRepository.findAll();
  return endpoints
    .filter(
      (endpoint) =>
        endpoint.restricted === true &&
        endpoint.require_scoped_api_key !== true,
    )
    .map((endpoint) => ({ uuid: endpoint.uuid, name: endpoint.name }));
}

/**
 * Log a WARN listing any unpaired restricted endpoints at boot. Non-fatal by
 * design: a stale row is an operator decision to make, never a reason to
 * refuse to start, and every failure is swallowed after logging for the same
 * reason. Returns the list so the caller (and a test) can assert on it.
 */
export async function warnOnUnpairedRestrictedEndpoints(): Promise<
  UnpairedRestrictedEndpoint[]
> {
  try {
    const unpaired = await findUnpairedRestrictedEndpoints();
    if (unpaired.length > 0) {
      logger.warn(
        `${unpaired.length} restricted endpoint(s) still admit unscoped API keys ` +
          `(restricted=true, require_scoped_api_key=false): the OAuth gate is on but ` +
          `the API-key path is open on [${unpaired
            .map((endpoint) => endpoint.name)
            .join(
              ", ",
            )}]. Enable require_scoped_api_key on each to close it. ` +
          `Left unchanged on purpose so an unscoped-key consumer is not locked out ` +
          `without an operator deciding to.`,
      );
    }
    return unpaired;
  } catch (err) {
    logger.error("Endpoint pairing check failed (continuing):", err);
    return [];
  }
}
