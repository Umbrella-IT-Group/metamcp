/**
 * Single source of truth for the MCP server-capability set this gateway
 * advertises at upstream `Server({...})` construction time.
 *
 * Two consumers import from here:
 *
 *   1. `metamcp-proxy.ts` — declares these capabilities on the upstream
 *      `Server` instance (the value clients see when they `initialize`).
 *   2. `gateway-boot-id.ts` — hashes the same object into
 *      `GATEWAY_CAPABILITY_HASH`, stamped onto every persisted
 *      `mcp_sessions` row so lazy-recovery (PR #15 / #22 / #23) can refuse
 *      cross-restart rows whose negotiated capability set no longer
 *      matches what the current process actually advertises.
 *
 * Keeping the declaration and the hashed input pointing at the SAME
 * object is load-bearing — if a future PR changes capabilities here, the
 * hash updates automatically and lazy-recovery starts refusing rows
 * stamped against the prior code version. Don't fork or duplicate this
 * object; mutate it here and let both consumers re-derive.
 *
 * Frozen so any accidental in-place mutation throws in dev rather than
 * silently desyncing the declared capability set from the hashed one.
 */
export const GATEWAY_CAPABILITIES = Object.freeze({
  prompts: {},
  resources: {},
  // Advertise `listChanged: true` so spec-conformant upstream clients
  // (Claude Code, Claude.ai connectors) actually act on
  // `notifications/tools/list_changed`. Without this capability
  // declaration the notification is silently ignored even when emitted,
  // defeating the whole propagation chain. Introduced PR #19.
  tools: Object.freeze({ listChanged: true }),
}) as {
  prompts: Record<string, never>;
  resources: Record<string, never>;
  tools: { listChanged: true };
};
