import type { AuditActor } from "@repo/trpc";

import {
  type LockedAccount,
  ownsActiveAdminPlaneKey,
} from "../db/repositories/admin-plane-locks";
import type { DbTransaction } from "../db/repositories/db-executor";
import { AdminRuleRefusal } from "./audit/admin-write";

/**
 * The rails on changing a user account (users.setDisabled, users.revokeAccess,
 * users.delete), judged inside the change's transaction against rows locked
 * by `lockAccountTarget` (db/repositories/admin-plane-locks).
 *
 *  1. An admin-plane key may not change an administrator's account, or the
 *     account that owns an active admin-plane key. Those accounts are the
 *     human recovery path and the owners of the control-plane credentials; a
 *     key that could disable them could cut off the people who can revoke it.
 *     Reading the account list stays allowed. Acting on keys (deactivate,
 *     narrowing an IP policy) is a key action, governed by the key action
 *     table in the fork README, not by this rail.
 *  2. For every caller, a person's session included: the last enabled
 *     administrator may not be disabled or deleted, which would leave the
 *     gateway with nobody who can administer it. Judged on the enabled
 *     administrators as locked (every one of their rows, in id order), not on
 *     an unlocked count, so two concurrent disables of the last two cannot
 *     both pass. The self guards (no disabling, revoking or deleting your own
 *     account) stay where they are, ahead of this.
 *
 * Every refusal is a fixed sentence and a coded error, recorded as a denied
 * row after the transaction rolls back.
 */

export type AccountChange = "disable" | "enable" | "revoke" | "delete";

export const ACCOUNT_RAIL_REFUSALS = {
  protectedTarget:
    "An admin-plane API key cannot change an administrator's account or the account that owns an active admin-plane key. Do this in the admin UI.",
  lastAdministrator:
    "This would leave the gateway with no enabled administrator. Enable or promote another administrator first.",
} as const;

const ACTIONS: Record<AccountChange, string> = {
  disable: "user.disabled.set",
  enable: "user.enabled.set",
  revoke: "user.access.revoked",
  delete: "user.delete",
};

export async function assertAccountChangeAllowed(
  tx: DbTransaction,
  actor: AuditActor | undefined | null,
  target: LockedAccount,
  enabledAdminIds: readonly string[] | null,
  change: AccountChange,
): Promise<void> {
  const refuse = (
    code: "FORBIDDEN" | "CONFLICT",
    message: string,
    rule: string,
  ) =>
    new AdminRuleRefusal(code, message, {
      action: ACTIONS[change],
      target_type: "user",
      target_id: target.id,
      detail: { rule },
    });

  if (actor?.admin_plane) {
    if (target.role === "admin") {
      throw refuse(
        "FORBIDDEN",
        ACCOUNT_RAIL_REFUSALS.protectedTarget,
        "account_admin_target",
      );
    }
    if (await ownsActiveAdminPlaneKey(tx, target.id)) {
      throw refuse(
        "FORBIDDEN",
        ACCOUNT_RAIL_REFUSALS.protectedTarget,
        "account_admin_plane_owner",
      );
    }
  }

  if (
    (change === "disable" || change === "delete") &&
    enabledAdminIds !== null &&
    target.role === "admin" &&
    target.disabled !== true &&
    !enabledAdminIds.some((id) => id !== target.id)
  ) {
    throw refuse(
      "CONFLICT",
      ACCOUNT_RAIL_REFUSALS.lastAdministrator,
      "last_enabled_administrator",
    );
  }
}
