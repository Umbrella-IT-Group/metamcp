import { createHash } from "node:crypto";

import { ApiKeysSerializer } from "../db/serializers/api-keys.serializer";
import { apiKeyIpPolicyDisabled } from "./api-key-ip-policy";
import {
  ApiKeyMintRefusal,
  assertAgentSettableIpPolicy,
} from "./api-key-mint-rules";

/**
 * The rules of the narrow key lifecycle procedures: `apiKeys.reactivate`,
 * `apiKeys.rename` and `apiKeys.remove` (with the `apiKeys.removalImpact`
 * read that prepares a removal).
 *
 * WHY THESE AND NOT THE BROAD UPDATE. `apiKeys.update` can re-activate,
 * rename and re-own any key for an administrator, admin-plane keys included,
 * and `apiKeys.delete` deletes any key. A standing operator-scope key must
 * not hold either: the gateway cannot tell which tooling holds the key, so a
 * power it grants has to be bounded on the server. These procedures do one
 * thing each, to one DATA-plane key, and the same rules hold for every caller
 * (a person keeps the broad procedures for anything else):
 *
 *  - Never an admin-plane key, of either scope, the calling key included. An
 *    admin-plane key's re-activation could restore a credential a person
 *    contained; its rename or deletion could hide or destroy the human kill
 *    path for the operator or CI key.
 *  - reactivate: the key must be one the agent mint could create today. No
 *    acts-as identity; an owner who is an existing, enabled user; an endpoint
 *    the mint would allow that owner (a public endpoint, a restricted one only
 *    for an explicit member of a group mapped to it), or gateway-wide reach
 *    only for an owner who is not an administrator; and the key's OWN policy
 *    already an `enforce` list of one to eight entries, each IPv4 /24 or
 *    narrower and IPv6 /48 or narrower, while the IP-policy kill switch is
 *    off. So a re-activated key is never wider than a key the operator could
 *    have minted, and re-activation never loosens a policy (narrow it first
 *    with `apiKeys.setIpPolicy`). The owner, endpoint and grant are read in
 *    the write's transaction, under the locks the mint takes.
 *  - rename: a name of the mint's shape, unused by any other key of the same
 *    owner (inactive keys included) and not the name of any admin-plane key,
 *    so a data-plane key cannot be made to look like the key a person would
 *    contain. A rename changes no access.
 *  - remove: leaf-only. The key must already be inactive, so every removal
 *    follows a reversible, audited deactivation; nothing in the database
 *    references a key row, so deleting it cascades to nothing. The caller
 *    confirms the key's current name and the fingerprint of its current state
 *    (`apiKeyRemovalFingerprint`), read with `apiKeys.removalImpact`: a
 *    mistake guard that refuses a removal prepared against a key that has
 *    changed since. It does not replace the leaf rule, which holds without it.
 *
 * Every refusal is one fixed sentence that names no key, owner or value, and
 * is recorded by the caller as a `denied` audit row naming the rule.
 *
 * Pure: no database and no logger. The repository reads and locks the rows
 * and calls these checks.
 */

export type KeyLifecycleRule =
  | "target_admin_plane"
  | "target_acts_as"
  | "owner_ineligible"
  | "endpoint_not_eligible"
  | "gateway_wide_admin_owner"
  | "ip_policy_not_narrow"
  | "ip_policy_disabled"
  | "name_invalid"
  | "name_taken"
  | "name_admin_plane"
  | "key_active"
  | "confirm_name_mismatch"
  | "impact_changed"
  | "key_changed";

export const KEY_LIFECYCLE_REFUSALS: Readonly<
  Record<
    KeyLifecycleRule,
    { code: "FORBIDDEN" | "BAD_REQUEST" | "CONFLICT"; message: string }
  >
> = {
  target_admin_plane: {
    code: "FORBIDDEN",
    message:
      "An admin-plane API key cannot be re-activated, renamed or removed through this procedure. Do this in the admin UI.",
  },
  target_acts_as: {
    code: "FORBIDDEN",
    message:
      "A key that acts as a user cannot be re-activated through this procedure. Do this in the admin UI.",
  },
  owner_ineligible: {
    code: "FORBIDDEN",
    message:
      "The key's owner must be an existing, enabled user. A public key, or a key of a disabled user, is re-activated in the admin UI.",
  },
  endpoint_not_eligible: {
    code: "FORBIDDEN",
    message:
      "The key's endpoint must be public, and restricted only when the key's owner is a member of a group mapped to it. Re-activate any other key in the admin UI.",
  },
  gateway_wide_admin_owner: {
    code: "FORBIDDEN",
    message:
      "A gateway-wide key of an administrator cannot be re-activated through this procedure, because it would reach every restricted endpoint. Do this in the admin UI.",
  },
  ip_policy_not_narrow: {
    code: "FORBIDDEN",
    message:
      "Only a key locked to a narrow IP list of its own can be re-activated: mode enforce, 1 to 8 entries, each IPv4 /24 or IPv6 /48 or narrower. Narrow the key's policy first, or re-activate it in the admin UI.",
  },
  ip_policy_disabled: {
    code: "FORBIDDEN",
    message:
      "API key IP policies are switched off on this gateway, so a key cannot be re-activated through this procedure.",
  },
  name_invalid: {
    code: "BAD_REQUEST",
    message:
      "name must be 1 to 100 characters: letters, numbers, spaces, underscores and hyphens.",
  },
  name_taken: {
    code: "BAD_REQUEST",
    message:
      "name is already used by a key of this owner (inactive keys count). Use a new name.",
  },
  name_admin_plane: {
    code: "BAD_REQUEST",
    message:
      "name is used by an admin-plane API key. Use a different name, so that no key can be mistaken for one.",
  },
  key_active: {
    code: "CONFLICT",
    message:
      "Only an inactive key can be removed. Deactivate it first, then read its removal impact again.",
  },
  confirm_name_mismatch: {
    code: "BAD_REQUEST",
    message: "confirm_name must equal the key's current name.",
  },
  impact_changed: {
    code: "CONFLICT",
    message:
      "The key changed after its removal impact was read. Read it again and confirm the new fingerprint.",
  },
  key_changed: {
    code: "CONFLICT",
    message: "The key changed while this request was applied. Retry it.",
  },
};

/** A refusal of one rule, carrying its fixed code and sentence. */
export class ApiKeyLifecycleRefusal extends Error {
  readonly rule: KeyLifecycleRule;
  readonly code: "FORBIDDEN" | "BAD_REQUEST" | "CONFLICT";

  constructor(rule: KeyLifecycleRule) {
    super(KEY_LIFECYCLE_REFUSALS[rule].message);
    this.name = "ApiKeyLifecycleRefusal";
    this.rule = rule;
    this.code = KEY_LIFECYCLE_REFUSALS[rule].code;
  }
}

/** The columns of a key the lifecycle rules read. No credential material. */
export interface LifecycleKeyRow {
  uuid: string;
  name: string;
  last4: string;
  is_active: boolean;
  admin_plane: boolean;
  user_id: string | null;
  endpoint_uuid: string | null;
  acts_as_user_id: string | null;
  allowed_cidrs: string[] | null;
  ip_policy_mode: string;
  created_at: Date;
  last_used_at: Date | null;
}

export type LifecycleOperation = "reactivate" | "rename" | "remove";

/**
 * The kind of key an operation may act on: never an admin-plane key, and for
 * a re-activation never a key that acts as a user (the agent mint never
 * creates one).
 */
export function assertLifecycleTarget(
  row: Pick<LifecycleKeyRow, "admin_plane" | "acts_as_user_id">,
  operation: LifecycleOperation,
): void {
  if (row.admin_plane !== false) {
    throw new ApiKeyLifecycleRefusal("target_admin_plane");
  }
  if (operation === "reactivate" && row.acts_as_user_id !== null) {
    throw new ApiKeyLifecycleRefusal("target_acts_as");
  }
}

/**
 * The key's own policy must already be what the agent mint would create: the
 * kill switch off, and an `enforce` list of its own within the mint's bound.
 * Reuses the mint's own predicate so the two cannot drift apart.
 */
export function assertReactivationPolicy(
  row: Pick<LifecycleKeyRow, "allowed_cidrs" | "ip_policy_mode">,
): void {
  if (apiKeyIpPolicyDisabled()) {
    throw new ApiKeyLifecycleRefusal("ip_policy_disabled");
  }
  try {
    assertAgentSettableIpPolicy({
      mode: row.ip_policy_mode,
      cidrs: row.allowed_cidrs,
    });
  } catch (error) {
    if (error instanceof ApiKeyMintRefusal) {
      throw new ApiKeyLifecycleRefusal("ip_policy_not_narrow");
    }
    throw error;
  }
}

/**
 * The mint's name rule (api-key-mint-rules rule 6), as a lifecycle refusal.
 * A literal space, not `\s`: the refusal sentence promises letters, numbers,
 * spaces, underscores and hyphens, and `\s` would also admit a newline, a tab,
 * a no-break space and a line separator.
 */
const NAME_PATTERN = /^[a-zA-Z0-9_ -]+$/;

export function assertRenameName(name: string): void {
  if (
    typeof name !== "string" ||
    name.length < 1 ||
    name.length > 100 ||
    !NAME_PATTERN.test(name)
  ) {
    throw new ApiKeyLifecycleRefusal("name_invalid");
  }
}

/**
 * What stops a removal of this key now, or null when it may be removed. The
 * admin-plane rule is reported first, so the answer for an admin-plane key
 * does not depend on its state.
 */
export function removalBlocker(
  row: Pick<LifecycleKeyRow, "admin_plane" | "is_active">,
): "target_admin_plane" | "key_active" | null {
  if (row.admin_plane !== false) return "target_admin_plane";
  if (row.is_active !== false) return "key_active";
  return null;
}

/**
 * The confirmation a removal must carry: the key's current name, exactly, and
 * the fingerprint of its current state. Judged against the row locked in the
 * removal's transaction.
 */
export function assertRemovalConfirmed(
  row: LifecycleKeyRow,
  confirmName: string,
  fingerprint: string,
): void {
  if (confirmName !== row.name) {
    throw new ApiKeyLifecycleRefusal("confirm_name_mismatch");
  }
  if (fingerprint !== apiKeyRemovalFingerprint(row)) {
    throw new ApiKeyLifecycleRefusal("impact_changed");
  }
}

/**
 * The fingerprint of a key's current state for a removal: sha256 over the
 * operation and every column a removal is judged on or records, in a fixed
 * order. Any change to the key between the impact read and the removal (a
 * rename, a re-activation, a policy change, a use) changes it. Holds no
 * credential material: the key's hash is not an input.
 */
export function apiKeyRemovalFingerprint(row: LifecycleKeyRow): string {
  const canonical = JSON.stringify([
    "apikey.remove.v1",
    row.uuid.toLowerCase(),
    row.name,
    row.is_active,
    row.admin_plane,
    row.user_id,
    row.endpoint_uuid,
    row.acts_as_user_id,
    row.allowed_cidrs,
    row.ip_policy_mode,
    row.created_at.toISOString(),
    row.last_used_at ? row.last_used_at.toISOString() : null,
  ]);
  return `sha256:${createHash("sha256").update(canonical).digest("hex")}`;
}

/**
 * What a removal records of the key it deletes: identifying metadata, picked
 * field by field, so nothing else on the row (the key's hash above all) can
 * reach the audit row even if a caller passes a wider object. The prefix is
 * the display form every key list already shows.
 */
export function apiKeySnapshot(row: LifecycleKeyRow): {
  name: string;
  key_prefix: string;
  owner_user_id: string | null;
  endpoint_uuid: string | null;
  acts_as_user_id: string | null;
  is_active: boolean;
  admin_plane: boolean;
  allowed_cidrs: string[] | null;
  ip_policy_mode: string;
  created_at: string;
  last_used_at: string | null;
} {
  return {
    name: row.name,
    key_prefix: ApiKeysSerializer.keyPrefix(row.last4),
    owner_user_id: row.user_id,
    endpoint_uuid: row.endpoint_uuid,
    acts_as_user_id: row.acts_as_user_id,
    is_active: row.is_active,
    admin_plane: row.admin_plane,
    allowed_cidrs: row.allowed_cidrs ? [...row.allowed_cidrs] : null,
    ip_policy_mode: row.ip_policy_mode,
    created_at: row.created_at.toISOString(),
    last_used_at: row.last_used_at ? row.last_used_at.toISOString() : null,
  };
}
