import { eq } from "drizzle-orm";

import type { DbTransaction } from "../db/repositories/db-executor";
import { apiKeysTable } from "../db/schema";
import {
  type GlobalIpPolicy,
  type IpPolicyMode,
  matchClientIp,
  readMode,
} from "./api-key-ip-policy";

/**
 * Self-lockout rails for an admin-plane key changing an IP policy.
 *
 * An admin-plane key that sets an `enforce` policy its own request address is
 * not in cannot call the gateway again: the next request is refused, and the
 * key can only be repaired from the admin UI. A bare `lock-key` typo, or a
 * list built from a stale last-used address, would do that. These rails refuse
 * the write instead, with the request's TRUSTED address (the Cloudflare-
 * supplied one the audit context already carries, never a request field) tested
 * against the policy the write would leave in force.
 *
 * Scope, exactly: a request authenticated by an admin-plane key, changing
 *  - its OWN key's policy (`setIpPolicy` with the calling key's uuid), judged
 *    against the key's new list, or against the global policy if the write
 *    makes the key follow it; or
 *  - the GLOBAL policy (`setGlobalIpPolicy`) while the calling key follows it.
 * A human administrator's session is unchanged (it has no key to lock out, and
 * the UI is the recovery path), and so is every write to a key other than the
 * caller's. The kill switch (API_KEY_IP_POLICY_DISABLED) does not exempt a
 * write: the rail judges the policy being stored, which is what will bind once
 * the switch is lifted.
 *
 * Fails closed: an effective `enforce` policy with no address to test, or one
 * that does not parse, is refused. The IPv4-mapped rule is matchClientIp's
 * (node:net BlockList), the same code that evaluates the policy at request
 * time, so the rail and the gate cannot disagree.
 */

export const SELF_LOCKOUT_REFUSALS = {
  ownList:
    "This change would lock this key out: its new enforce list does not include the address of this request.",
  globalList:
    "This change would lock this key out: the global enforce list it follows does not include the address of this request.",
  noAddress:
    "This change would set an enforce policy, but this request carries no trusted address to check it against.",
} as const;

export type SelfLockoutSource = "ownList" | "globalList";

/**
 * The refusal for an effective policy and a trusted address, or null if the
 * address stays admitted. Pure.
 */
export function selfLockoutRefusal(
  effective: { mode: IpPolicyMode; cidrs: readonly string[] },
  address: string | null | undefined,
  source: SelfLockoutSource,
): string | null {
  if (effective.mode !== "enforce") return null;
  if (address === null || address === undefined || address === "") {
    return SELF_LOCKOUT_REFUSALS.noAddress;
  }
  const status = matchClientIp(effective.cidrs, address);
  if (status === "in_list" || status === "any_ip_exemption") return null;
  return SELF_LOCKOUT_REFUSALS[source];
}

/**
 * For the global policy after a `setGlobalIpPolicy` write, inside its
 * transaction: if the calling key follows the global policy (no list of its
 * own), the new global policy must still admit this request. The caller's key
 * row is read FOR SHARE, so a concurrent change to that key's own policy
 * finishes first or waits for this transaction. The config advisory locks were
 * taken by the write itself, which runs first, so the lock order is always
 * config then key, the order `setIpPolicy` uses as well.
 */
export async function globalPolicyRefusalForCaller(
  tx: DbTransaction,
  callerKeyUuid: string,
  address: string | null | undefined,
  after: GlobalIpPolicy,
): Promise<string | null> {
  const [caller] = await tx
    .select({ allowed_cidrs: apiKeysTable.allowed_cidrs })
    .from(apiKeysTable)
    .where(eq(apiKeysTable.uuid, callerKeyUuid))
    .for("share");
  // The caller's key is gone, or has a list of its own: the global policy does
  // not govern it.
  if (!caller || caller.allowed_cidrs !== null) return null;
  return selfLockoutRefusal(after, address, "globalList");
}

/**
 * The global policy (read under shared locks) in force for a key that is about
 * to follow it, as an effective policy.
 */
export function followedGlobalPolicy(global: GlobalIpPolicy): {
  mode: IpPolicyMode;
  cidrs: readonly string[];
} {
  return { mode: readMode(global.mode), cidrs: global.cidrs };
}
