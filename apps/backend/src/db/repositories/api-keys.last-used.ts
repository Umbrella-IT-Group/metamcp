// Throttle policy for api_keys.last_used_at writes. Kept in its own
// dependency-free module (no db import) so validateApiKey's fire-and-forget
// write decision is unit-testable without a live postgres — the same DB-free
// module doctrine as consumer-identity-resolver.ts / mint-service.ts.

// Only rewrite last_used_at when the recorded value is NULL (key never used)
// or at least this stale. WHY 15 min: the public-endpoint auth path runs
// validateApiKey on every request, so an unthrottled write would add a row
// update per call — a key hammered thousands of times an hour would issue
// thousands of writes. The throttle caps that at ~4/hour per key while
// keeping last_used_at accurate to the window for the admin view.
export const LAST_USED_THROTTLE_MS = 15 * 60 * 1000;

// Returns true when validateApiKey should issue a (fire-and-forget)
// last_used_at write. `nowMs` is injected rather than read from Date.now()
// inside so the decision is deterministic under test.
export function shouldTouchLastUsed(
  lastUsedAt: Date | null | undefined,
  nowMs: number,
  thresholdMs: number = LAST_USED_THROTTLE_MS,
): boolean {
  if (!lastUsedAt) {
    return true;
  }
  return nowMs - lastUsedAt.getTime() >= thresholdMs;
}
