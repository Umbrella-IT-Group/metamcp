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
 *     key re-activation). A removal can then share-lock a remaining restricted
 *     sibling (under the same namespace gate), then lock its own presentation
 *     row FOR UPDATE (db/repositories/topology-removal.repo).
 *     5a. Namespace rows (FOR UPDATE for a tool policy change or a removal),
 *     then, for a removal, the namespace's own mounts and tool rows FOR
 *     UPDATE in uuid order. An endpoint insert or move takes FOR KEY SHARE
 *     on the namespace through its foreign-key check.
 *  6. Access group rows (FOR UPDATE for a group delete).
 *  7. API key name locks (`lockApiKeyName`, advisory, `metamcp.api_key.name`,
 *     one per owner and name): a rename takes the lock of the name it is
 *     taking before the uniqueness check, so two renames to one name are
 *     judged one after the other. Held by renames only.
 *  8. API key rows (FOR UPDATE for a policy change, a deactivation, a
 *     re-activation, a rename or a removal). A re-activation reads its key
 *     once without a lock to learn which owner and endpoint rows to lock
 *     first, then locks the key here and refuses if those have changed; a
 *     rename does the same to learn the owner whose name lock to take.
 *  9. a. MCP server name locks (`lockMcpServerName`, advisory,
 *        `metamcp.mcp_server.name`, one per name): a create, the full update
 *        and a rename take the lock of the name they would hold, before the
 *        server row, so two writers of one name are judged one after the
 *        other.
 *     b. MCP server rows (FOR UPDATE, in uuid order, for an error reset; one
 *        row for an update or a rename, after its name lock; one row for a
 *        removal). No transaction that holds one takes a lock listed above it.
 *     c. A server's tool catalog rows (FOR UPDATE in uuid order, for a
 *        removal, after its server row).
 *     d. A server's upstream OAuth session (FOR KEY SHARE for a removal,
 *        after its catalog).
 * 10. The audit row insert, last, in the same transaction.
 *
 * Every lock here is transaction-scoped (released at COMMIT or ROLLBACK, never
 * leaked past a process that dies mid-request) and database-wide, so separate
 * gateway replicas share them.
 */

/** Advisory-lock namespace of the per-key change budget (order position 1). */
export const ADMIN_PLANE_BUDGET_LOCK_NAMESPACE = "metamcp.admin_plane.budget";

/** Advisory-lock namespace of the per-namespace endpoint gate (position 3). */
export const ENDPOINT_NAMESPACE_LOCK_NAMESPACE = "metamcp.endpoint.namespace";

/** Advisory-lock namespace of the per-owner API key name (position 7). */
export const API_KEY_NAME_LOCK_NAMESPACE = "metamcp.api_key.name";

/** Advisory-lock namespace of the MCP server name (position 9a). */
export const MCP_SERVER_NAME_LOCK_NAMESPACE = "metamcp.mcp_server.name";

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

/**
 * Take the lock of one key name of one owner (`null` for the public keys) for
 * the rest of `tx`. The database's per-owner unique rule covers a name taken
 * by an owner's keys, not by public keys (a NULL owner is distinct to it), and
 * a check made before a concurrent rename commits sees neither row: under this
 * lock the second rename's check runs after the first has committed.
 */
export async function lockApiKeyName(
  tx: DbTransaction,
  ownerId: string | null,
  name: string,
): Promise<void> {
  // A newline cannot be in an owner id or in a name that passed the name
  // rule, so two different pairs never share a lock text.
  const subject = `${ownerId ?? ""}\n${ownerId === null ? "public" : "owner"}\n${name}`;
  await tx.execute(
    sql`SELECT pg_advisory_xact_lock(hashtext(${API_KEY_NAME_LOCK_NAMESPACE}), hashtext(${subject}))`,
  );
}

/**
 * Take the lock of one MCP server name for the rest of `tx`, whatever the
 * owner. The database's unique rule on (name, owner) does not cover a NULL
 * owner, so a check for another server of the same name made before a
 * concurrent write commits sees neither row: under this lock the second
 * writer's check runs after the first has committed. One lock per name, not
 * per name and owner, so a write that changes a server's owner needs no
 * knowledge of the owner it is leaving.
 */
export async function lockMcpServerName(
  tx: DbTransaction,
  name: string,
): Promise<void> {
  await tx.execute(
    sql`SELECT pg_advisory_xact_lock(hashtext(${MCP_SERVER_NAME_LOCK_NAMESPACE}), hashtext(${name}))`,
  );
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
