import { randomUUID } from "node:crypto";

/**
 * A UUID generated once per metamcp process. Used by the lazy-session
 * recovery path (PR #15) to refuse recovering sessions that were
 * initialized against a previous metamcp process — that older process
 * may have advertised different MCP server capabilities at init time,
 * and the client's cached capability set is no longer guaranteed
 * accurate. Forcing a fresh `initialize` lets the client re-negotiate.
 *
 * Capability changes within a single process lifetime are impossible
 * (capabilities are baked into `new Server({...})` at proxy
 * construction), so a boot_id match is sufficient to skip the forced
 * re-init.
 */
export const GATEWAY_BOOT_ID = randomUUID();

/**
 * Pure predicate consumed by `recoverPersistedSession`
 * (`routers/public-metamcp/streamable-http.ts`). Returns true when the
 * stored row's `gateway_boot_id` belongs to a prior process — recovery
 * must be refused so the client re-negotiates capabilities via a fresh
 * `initialize`.
 *
 * Returns false when:
 *   - `stored` is null (pre-PR-22 row, no metadata to compare; pruner
 *     reaps these within `MCP_SESSION_TTL_DAYS`)
 *   - `stored` equals `current` (same-process row, capabilities are
 *     baked into `new Server({...})` and can't have drifted)
 *
 * Extracted into a named helper so the recovery decision is unit-
 * testable without standing up the full streamable-http router import
 * chain (express + SDK transports + pool + DB).
 */
export function shouldRefuseRecoveryForBootIdMismatch(
  stored: string | null,
  current: string,
): boolean {
  if (stored === null) return false;
  return stored !== current;
}
