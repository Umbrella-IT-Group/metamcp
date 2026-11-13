// Skeleton: the final exported API with the fallbacks as they were before this
// change (a 60 second total cap).

export const DEFAULT_MCP_TIMEOUT_MS = 60_000;
export const DEFAULT_MCP_MAX_TOTAL_TIMEOUT_MS = 60_000;

export interface RequestTimeoutInputs {
  timeout?: number;
  maxTotalTimeout?: number;
  resetTimeoutOnProgress?: boolean;
}

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
