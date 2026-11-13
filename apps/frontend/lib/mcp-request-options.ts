/**
 * Fallbacks for the MCP request options the Inspector sends, kept apart from
 * the connection hook so the rule can be tested.
 *
 * The values an administrator stored (Settings, MCP) are always used as
 * stored: a stored 60000 total cap stays 60000 and a stored `false` for reset
 * on progress stays false. The constants below only fill a value that has not
 * loaded yet (the settings query is still in flight, or it failed).
 *
 * The total cap is ten minutes, matching the gateway's default for a call that
 * keeps reporting progress; a silent call still times out at the per-request
 * timeout. With the cap at the per-request timeout, as it used to be, a
 * progress-reporting call was cut off at one minute despite resetting its
 * timer on every update.
 */

export const DEFAULT_MCP_TIMEOUT_MS = 60_000;
export const DEFAULT_MCP_MAX_TOTAL_TIMEOUT_MS = 600_000;

export interface RequestTimeoutInputs {
  timeout?: number;
  maxTotalTimeout?: number;
  resetTimeoutOnProgress?: boolean;
}

/**
 * Per field: the caller's own option, else the stored setting, else the
 * fallback. `??` (not `||`) so a stored `false` or `0` is not replaced.
 */
export function resolveRequestTimeouts(
  stored: RequestTimeoutInputs,
  override: RequestTimeoutInputs = {},
): Required<RequestTimeoutInputs> {
  return {
    resetTimeoutOnProgress:
      override.resetTimeoutOnProgress ?? stored.resetTimeoutOnProgress ?? true,
    timeout: override.timeout ?? stored.timeout ?? DEFAULT_MCP_TIMEOUT_MS,
    maxTotalTimeout:
      override.maxTotalTimeout ??
      stored.maxTotalTimeout ??
      DEFAULT_MCP_MAX_TOTAL_TIMEOUT_MS,
  };
}
