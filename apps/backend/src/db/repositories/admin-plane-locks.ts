import { and, asc, eq, sql } from "drizzle-orm";

import { apiKeysTable, usersTable } from "../schema";
import type { DbTransaction } from "./db-executor";

/**
 * The lock order every control-plane write follows, and the helpers for the
 * locks this module owns.
 *
 * One order for every writer, an admin-plane key's and a human
 * administrator's alike, so no two transactions can each hold a lock the other
 * waits for. A transaction takes only the locks it needs, but always in this
 * order, outermost first:
 *
 *  1. The admin-plane change budget lock of the acting key
 *     (`lockAdminPlaneBudget`, advisory, `metamcp.admin_plane.budget`). The
 *     first statement of every admin-plane change transaction
 *     (lib/audit/admin-write `runAuditedTransaction`); a human session has no
 *     budget and never takes it.
 *  2. Configuration setting locks (`metamcp.config`, one per setting id, taken
 *     sorted by configRepo.setConfigs, shared by getConfigsShared): the global
 *     API-key IP policy.
 *  3. Endpoint namespace locks (`lockEndpointNamespaces`, advisory,
 *     `metamcp.endpoint.namespace`, one per namespace uuid, sorted): every
 *     write that can add or move a route to a namespace or change an
 *     endpoint's `restricted` flag.
 *  4. a. The per-user OAuth credential lock (`metamcp.oauth.user`,
 *        db/repositories/oauth-user-lock), taken by users.revokeAccess before
 *        the user row.
 *     b. User rows: the enabled administrators FOR UPDATE ordered by id, then
 *        the target account FOR UPDATE (`lockAccountTarget`); a key mint and
 *        a key re-activation take the key owner's row FOR SHARE.
 *  5. Endpoint rows (FOR UPDATE for a write, FOR SHARE for a key mint or a
 *     key re-activation).
 *  6. Access group rows (FOR UPDATE for a group delete).
 *  7. API key rows (FOR UPDATE for a policy change, a deactivation, a
 *     re-activation, a rename or a removal). A re-activation reads its key
 *     once without a lock to learn which owner and endpoint rows to lock
 *     first, then locks the key here and refuses if those have changed.
 *  8. MCP server rows (FOR UPDATE, in uuid order, for an error reset). No
 *     transaction that holds one takes a lock listed above it.
 *  9. The audit row insert, last, in the same transaction.
 *
 * Every lock here is transaction-scoped (released at COMMIT or ROLLBACK, never
 * leaked past a process that dies mid-request) and database-wide, so separate
 * gateway replicas share them.
 */

/** Advisory-lock namespace of the per-key change budget (order position 1). */
export const ADMIN_PLANE_BUDGET_LOCK_NAMESPACE = "metamcp.admin_plane.budget";

/** Advisory-lock namespace of the per-namespace endpoint gate (position 3). */
export const ENDPOINT_NAMESPACE_LOCK_NAMESPACE = "metamcp.endpoint.namespace";

/**
 * Take the change budget lock of one admin-plane key for the rest of `tx`.
 * Two requests of the same key queue here, so each counts the rows the other
 * committed before it judges its own change.
 */
export async function lockAdminPlaneBudget(
  tx: DbTransaction,
  keyUuid: string,
): Promise<void> {
  await tx.execute(
    sql`SELECT pg_advisory_xact_lock(hashtext(${ADMIN_PLANE_BUDGET_LOCK_NAMESPACE}), hashtext(${keyUuid.toLowerCase()}))`,
  );
}

/**
 * Take the endpoint gate lock of each namespace, deduplicated and in ascending
 * uuid order, for the rest of `tx`. Lower-cased first, because Postgres reads a
 * uuid case-insensitively and two spellings of one namespace must share a lock.
 */
export async function lockEndpointNamespaces(
  tx: DbTransaction,
  namespaceUuids: readonly string[],
): Promise<void> {
  const ordered = [
    ...new Set(namespaceUuids.map((uuid) => uuid.toLowerCase())),
  ].sort();
  for (const namespaceUuid of ordered) {
    await tx.execute(
      sql`SELECT pg_advisory_xact_lock(hashtext(${ENDPOINT_NAMESPACE_LOCK_NAMESPACE}), hashtext(${namespaceUuid}))`,
    );
  }
}

/** A user row as the account rails judge it, read under its row lock. */
export interface LockedAccount {
  id: string;
  role: string | null;
  disabled: boolean;
}

/**
 * Lock the rows an account change is judged against (order position 4b):
 * every enabled administrator FOR UPDATE in id order, then the target FOR
 * UPDATE. Returns the target (null when no such account) and the ids of the
 * enabled administrators as locked.
 *
 * Locking every enabled administrator, not counting them, is what makes the
 * last-administrator rule race-free: two transactions disabling the last two
 * administrators each need both rows, take them in the same order, and the
 * second sees the first's result once it gets them.
 */
export async function lockAccountTarget(
  tx: DbTransaction,
  targetId: string,
): Promise<{ target: LockedAccount | null; enabledAdminIds: string[] }> {
  const admins = await tx
    .select({ id: usersTable.id, disabled: usersTable.disabled })
    .from(usersTable)
    .where(eq(usersTable.role, "admin"))
    .orderBy(asc(usersTable.id))
    .for("update");
  const [target] = await tx
    .select({
      id: usersTable.id,
      role: usersTable.role,
      disabled: usersTable.disabled,
    })
    .from(usersTable)
    .where(eq(usersTable.id, targetId))
    .for("update");
  return {
    target: target ?? null,
    // Re-read after the target lock is held: the admin rows were locked first,
    // so their disabled flags cannot change under this transaction.
    enabledAdminIds: admins
      .filter((admin) => admin.disabled !== true)
      .map((admin) => admin.id),
  };
}

/**
 * Does this account own an ACTIVE admin-plane key? Every admin-plane key the
 * account owns is locked FOR SHARE (order position 7, after the user rows), so
 * a concurrent re-activation of one of them waits for the caller's
 * transaction instead of slipping in behind the answer.
 */
export async function ownsActiveAdminPlaneKey(
  tx: DbTransaction,
  userId: string,
): Promise<boolean> {
  const keys = await tx
    .select({ is_active: apiKeysTable.is_active })
    .from(apiKeysTable)
    .where(
      and(eq(apiKeysTable.user_id, userId), eq(apiKeysTable.admin_plane, true)),
    )
    .for("share");
  return keys.some((key) => key.is_active === true);
}

/**
 * Lock an account for users.revokeAccess (order positions 4a then 4b): the
 * user's OAuth credential lock first, the order the revoke always took it in,
 * then the account row FOR UPDATE. Returns the account as locked, or null.
 */
export async function lockAccountForRevoke(
  tx: DbTransaction,
  userId: string,
): Promise<LockedAccount | null> {
  // Lazy: the OAuth lock module loads the pool at import, which a module
  // that only names lock helpers must not.
  const { lockOAuthUser } = await import("./oauth-user-lock");
  await lockOAuthUser(tx, userId);
  const [target] = await tx
    .select({
      id: usersTable.id,
      role: usersTable.role,
      disabled: usersTable.disabled,
    })
    .from(usersTable)
    .where(eq(usersTable.id, userId))
    .for("update");
  return target ?? null;
}
