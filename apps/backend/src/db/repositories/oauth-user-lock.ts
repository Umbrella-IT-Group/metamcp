import { sql } from "drizzle-orm";

import { db } from "../index";

/**
 * The executor every OAuth credential write accepts: the shared pool, or the
 * transaction a caller already holds. Repository helpers default to `db`, so a
 * caller outside a transaction is unchanged, and a caller inside one passes its
 * `tx` so the write commits or rolls back with everything else it did.
 */
export type OAuthTx = Parameters<Parameters<typeof db.transaction>[0]>[0];
export type OAuthDbExecutor = typeof db | OAuthTx;

/**
 * Namespace of the per-user OAuth credential lock. The two-key advisory lock
 * is `(hashtext(namespace), hashtext(user id))`, the same shape
 * config.repo.ts uses for its per-setting lock, so the two can never be
 * mistaken for each other. A hashtext collision between two users only makes
 * them wait for each other; it never lets either skip the lock.
 */
export const OAUTH_USER_LOCK_NAMESPACE = "metamcp.oauth.user";

/**
 * Take the per-user OAuth credential lock for the rest of `tx`.
 *
 * WHY ONE LOCK PER USER. Every transaction that can mint or delete an OAuth
 * credential for a user takes this lock first: the refresh grant (claim the
 * presented refresh token, record the rotated marker, insert the new pair),
 * authorization-code redemption, consent approval (code insertion), reuse
 * detection's family revoke, /oauth/revoke, and the administrator's
 * users.revokeAccess. Holding it means no other credential change for that
 * user can interleave, so a revoke that commits is never undone by a mint
 * that read the old state before it. A lock per refresh-token family would
 * not be enough: revokeAccess spans every family the user has.
 *
 * Transaction-scoped (`pg_advisory_xact_lock`), so it is released by COMMIT
 * or ROLLBACK and can never leak past the transaction, including when the
 * process dies mid-request. It is NOT re-entrant across transactions: a
 * helper called from inside a locked transaction must be handed that `tx`,
 * never open a second transaction for the same user, or it waits for itself.
 *
 * Statements after this one see every row committed before the lock was
 * granted (READ COMMITTED takes a fresh snapshot per statement), which is why
 * callers re-read and re-validate the credential after taking it.
 */
export async function lockOAuthUser(
  tx: OAuthTx,
  userId: string,
): Promise<void> {
  await tx.execute(
    sql`SELECT pg_advisory_xact_lock(hashtext(${OAUTH_USER_LOCK_NAMESPACE}), hashtext(${userId}))`,
  );
}

/**
 * Run `fn` in one transaction holding the user's OAuth credential lock.
 * Everything `fn` writes through the `tx` it is given commits together or not
 * at all.
 */
export async function withOAuthUserLock<T>(
  userId: string,
  fn: (tx: OAuthTx) => Promise<T>,
): Promise<T> {
  return db.transaction(async (tx) => {
    await lockOAuthUser(tx, userId);
    return fn(tx);
  });
}
