import { createHash, randomUUID } from "node:crypto";

import { GATEWAY_CAPABILITIES } from "./gateway-capabilities";

/**
 * A UUID generated once per metamcp process. Used by the lazy-session
 * recovery path (PR #15) to distinguish "same process" from "crossed a
 * restart" without touching the wall clock. PR #22 used this alone as
 * the recovery refusal trigger; PR #23 narrows that refusal by also
 * comparing `GATEWAY_CAPABILITY_HASH` (see below) — most restarts don't
 * change capabilities and forcing a re-init on every restart triggered
 * an Anthropic-connector 404 gap.
 */
export const GATEWAY_BOOT_ID = randomUUID();

/**
 * Deterministic SHA-256 of the upstream-advertised capability set. Two
 * metamcp processes built from the same source declare the SAME
 * capabilities (capabilities are baked into `new Server({...})` at proxy
 * construction), so two processes with the same code version produce
 * the same hash — even though their `GATEWAY_BOOT_ID`s differ.
 *
 * Hashing the canonical-JSON form of `GATEWAY_CAPABILITIES` means a
 * future capability change in `gateway-capabilities.ts` automatically
 * shifts the hash, and lazy-recovery starts refusing rows stamped
 * against the prior code version. No manual bump required.
 *
 * Lazy-evaluated under `getCapabilityHash()` so the hash isn't computed
 * at module load (cheap, but the lazy pattern keeps tests fast and lets
 * a future dynamic-capability iteration plug in without changing
 * consumers). The result is captured once and reused — capabilities
 * cannot drift within a single process lifetime.
 */
let cachedCapabilityHash: string | null = null;

function computeCapabilityHash(): string {
  // JSON.stringify is deterministic for plain objects with stable key
  // order. `GATEWAY_CAPABILITIES` is hand-authored with a fixed key
  // order in source so this is safe; if we ever generate the object
  // dynamically we should switch to a canonical-JSON serializer.
  const canonical = JSON.stringify(GATEWAY_CAPABILITIES);
  return createHash("sha256").update(canonical).digest("hex");
}

export const GATEWAY_CAPABILITY_HASH: string = (() => {
  if (cachedCapabilityHash === null) {
    cachedCapabilityHash = computeCapabilityHash();
  }
  return cachedCapabilityHash;
})();

/**
 * Pure predicate kept from PR #22. Retained as a named export so the
 * boot-id half of the decision stays unit-addressable for the truth
 * table tests. PR #23 wraps this in `shouldRefuseRecovery` below.
 *
 * Returns true when stored is a non-null UUID that differs from
 * `current` — i.e. the stored row was persisted by a prior process.
 * Returns false when stored is null (pre-PR-22 row, no metadata) or
 * equal (same process — capabilities cannot have changed).
 */
export function shouldRefuseRecoveryForBootIdMismatch(
  stored: string | null,
  current: string,
): boolean {
  if (stored === null) return false;
  return stored !== current;
}

/**
 * PR #23 sibling of the boot-id predicate. Returns true when both stored
 * and current are non-null AND differ. Null stored means a pre-PR-23
 * row, deferred to the combined predicate's null-handling branch.
 */
export function shouldRefuseRecoveryForCapabilityMismatch(
  stored: string | null,
  current: string,
): boolean {
  if (stored === null) return false;
  return stored !== current;
}

/**
 * Stored-row snapshot consumed by `shouldRefuseRecovery`. Both fields
 * are nullable to cover pre-PR-22 + pre-PR-23 rows (`gateway_boot_id`
 * was added in PR #22; `capability_hash` in PR #23).
 */
export interface StoredRecoveryMetadata {
  gateway_boot_id: string | null;
  capability_hash: string | null;
}

/**
 * Current-process snapshot consumed by `shouldRefuseRecovery`. Both
 * fields are non-null — they reflect this module's `GATEWAY_BOOT_ID`
 * and `GATEWAY_CAPABILITY_HASH`.
 */
export interface CurrentRecoveryMetadata {
  bootId: string;
  capabilityHash: string;
}

/**
 * The combined refusal predicate consumed by
 * `recoverPersistedSession`. Narrows PR #22's blanket boot-id refusal
 * to "refuse only when capabilities actually changed across the
 * restart." Background: PR #22 forced a client re-initialize on every
 * metamcp restart (including capability-neutral restarts like OAuth
 * fixes, dep bumps, transport-disconnect tweaks). The Anthropic MCP
 * connector doesn't honor the spec's HTTP-404 → start-new-session
 * contract; it wraps the 404+`Mcp-Session-Reinitialize-Required`
 * response as `-32600 "Anthropic Proxy: Invalid content from server"`
 * and surfaces the error to the user (already documented in
 * UMBRELLA_FORK.md for PR #18). Result before this PR: every restart
 * broke claude.ai sessions until manual `/mcp reconnect`.
 *
 * Decision table:
 *
 *   - Same boot_id (`stored.gateway_boot_id === current.bootId`):
 *       allow. Same process — capabilities are baked into
 *       `new Server({...})` and cannot have changed.
 *
 *   - Different boot_id, same capability_hash: allow. Different
 *       process built from the same source — the negotiated capability
 *       set the client cached is still accurate.
 *
 *   - Different boot_id, different capability_hash: refuse. Different
 *       process built from different source — the client's cached
 *       capability set is stale and a fresh `initialize` is required.
 *
 *   - Both stored fields null (pre-PR-22 row): allow. No metadata to
 *       compare; pruner reaps these within `MCP_SESSION_TTL_DAYS`
 *       (default 7) so the null branch is finite and self-clearing.
 *
 *   - Stored capability_hash null but boot_id non-null (PR #22 row
 *       persisted before PR #23 landed): treat as conservative refusal
 *       when the boot_id also differs. The PR #22 row already knew the
 *       boot_id mismatch was significant; missing capability_hash
 *       can't downgrade that. When the boot_id matches we still allow
 *       (same process — capabilities can't have changed).
 */
export function shouldRefuseRecovery(
  stored: StoredRecoveryMetadata,
  current: CurrentRecoveryMetadata,
): boolean {
  // Same-process row — capabilities can't have changed. Allow.
  if (
    stored.gateway_boot_id !== null &&
    stored.gateway_boot_id === current.bootId
  ) {
    return false;
  }

  // Capability hash present + matching — different process, same code
  // version. Safe to recover. Allow.
  if (
    stored.capability_hash !== null &&
    stored.capability_hash === current.capabilityHash
  ) {
    return false;
  }

  // Both stamps null — pre-PR-22 row, no metadata to compare. Allow.
  if (stored.gateway_boot_id === null && stored.capability_hash === null) {
    return false;
  }

  // Otherwise: boot_id differs and either capability_hash also differs
  // OR capability_hash is null (PR #22 row whose boot_id already
  // mismatches — treat conservatively, the boot_id mismatch alone was
  // PR #22's full justification). Refuse.
  return true;
}
