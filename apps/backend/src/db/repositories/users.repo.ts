import { and, count, desc, eq, gt, max, sql } from "drizzle-orm";

import { db } from "../index";
import {
  apiKeysTable,
  oauthAccessTokensTable,
  oauthAuthorizationCodesTable,
  sessionsTable,
  usersTable,
} from "../schema";

/**
 * The admin user listing, as a query builder rather than an executed query,
 * so its SQL can be asserted without a database.
 *
 * The three counts are CORRELATED SUBQUERIES rather than LEFT JOIN + GROUP BY
 * on purpose: three independent one-to-many joins against the same driving
 * table multiply each other's rows, so a user with 2 sessions and 3 keys
 * would report 6 of each. Subqueries keep every count independent, and each
 * predicate is indexed (`sessions.user_id` is the FK,
 * `oauth_access_tokens_user_id_idx`, `api_keys_user_id_idx`).
 *
 * `now` is captured once by the caller and passed into all the liveness
 * predicates, so one user's counts are consistent with each other instead of
 * being evaluated at three slightly different instants.
 *
 * `.mapWith(Number)` on every count is load-bearing, NOT decoration: postgres
 * `count(*)` is bigint (OID 20) and node-postgres decodes bigint as a STRING
 * to avoid precision loss. Interpolating a subquery into a raw `sql` fragment
 * bypasses the decoder drizzle's own `count()` helper would have attached, so
 * without this the procedure returns "3" where its `.output()` schema demands
 * a number and every list call fails zod validation at runtime.
 *
 * An explicit column list is used, never `select()` — the serializer is the
 * redaction boundary, but not pulling columns nobody asked for is the cheaper
 * first layer.
 */
export function buildUserListQuery(now: Date) {
  const lastActive = db
    .select({ value: max(sessionsTable.updatedAt) })
    .from(sessionsTable)
    .where(eq(sessionsTable.userId, usersTable.id));

  const activeSessions = db
    .select({ value: count() })
    .from(sessionsTable)
    .where(
      and(
        eq(sessionsTable.userId, usersTable.id),
        gt(sessionsTable.expiresAt, now),
      ),
    );

  const activeTokens = db
    .select({ value: count() })
    .from(oauthAccessTokensTable)
    .where(
      and(
        eq(oauthAccessTokensTable.user_id, usersTable.id),
        gt(oauthAccessTokensTable.expires_at, now),
      ),
    );

  const activeKeys = db
    .select({ value: count() })
    .from(apiKeysTable)
    .where(
      and(
        eq(apiKeysTable.user_id, usersTable.id),
        eq(apiKeysTable.is_active, true),
      ),
    );

  return db
    .select({
      id: usersTable.id,
      email: usersTable.email,
      name: usersTable.name,
      role: usersTable.role,
      emailVerified: usersTable.emailVerified,
      created_at: usersTable.createdAt,
      updated_at: usersTable.updatedAt,
      last_active_at: sql<Date | null>`${lastActive}`.as("last_active_at"),
      active_session_count: sql<number>`${activeSessions}`
        .mapWith(Number)
        .as("active_session_count"),
      active_oauth_token_count: sql<number>`${activeTokens}`
        .mapWith(Number)
        .as("active_oauth_token_count"),
      active_api_key_count: sql<number>`${activeKeys}`
        .mapWith(Number)
        .as("active_api_key_count"),
    })
    .from(usersTable)
    .orderBy(desc(usersTable.createdAt));
}

/**
 * Read + administrative surface over the better-auth users table.
 *
 * Account LIFECYCLE (sign-up, password, verification) still belongs to
 * better-auth — nothing here mints or mutates credentials. What this adds is
 * the administrative half better-auth does not provide: enumerate the
 * accounts that exist, and remove or de-fang one.
 *
 * That enumeration used to be deliberately absent ("the admin UI takes a user
 * id, it does not enumerate accounts"). The 2026-08-13 incident overturned
 * that call: an attacker's self-registered member accounts were invisible in
 * the GUI, because no surface anywhere listed users. An access path that
 * cannot be seen cannot be audited, so the listing is now the point.
 */
export class UsersRepository {
  async findById(
    id: string,
  ): Promise<{ id: string; email: string; name: string } | undefined> {
    const [user] = await db
      .select({
        id: usersTable.id,
        email: usersTable.email,
        name: usersTable.name,
      })
      .from(usersTable)
      .where(eq(usersTable.id, id));

    return user;
  }

  /**
   * Read a user's RBAC role straight from the database.
   *
   * Exists for authorization checks that run OUTSIDE tRPC, where there is no
   * `ctx.user` to read `role` from — currently the express `/health/upstream`
   * handler, which decides whether to attach server topology to its response.
   * Those paths only have a session user id, and re-reading the role here
   * keeps the decision independent of how better-auth happens to serialise
   * the session (`additionalFields` in auth.ts), which is a presentation
   * detail rather than the record of record.
   *
   * Returns undefined for an unknown id, so callers can fail closed on a
   * strict `=== "admin"` test rather than on the absence of a truthy value.
   */
  async findRoleById(id: string): Promise<string | undefined> {
    const [user] = await db
      .select({ role: usersTable.role })
      .from(usersTable)
      .where(eq(usersTable.id, id));

    return user?.role;
  }

  /**
   * Every account, newest first, with the three live access-path counts
   * beside it (sessions, OAuth tokens, API keys).
   *
   * Delegates to `buildUserListQuery` so the query SHAPE can be asserted in a
   * unit test (`.toSQL()`) — this fork has no live-DB test harness, so the
   * only way to keep a hand-built correlated subquery honest is to pin the
   * generated SQL. See users.repo.list-query.test.ts.
   */
  async listAll(now: Date = new Date()) {
    return await buildUserListQuery(now);
  }

  /**
   * Hard-delete an account.
   *
   * Every table that references `users.id` declares `onDelete: "cascade"` —
   * sessions, accounts (the password hash lives there), api_keys via both
   * `user_id` and `acts_as_user_id`, oauth_authorization_codes,
   * oauth_access_tokens, m365_user_tokens, and the owned mcp_servers /
   * namespaces / endpoints. So one DELETE severs every access path this
   * account had; no dependent cleanup is needed here, and adding manual
   * deletes would only create a second, drift-prone copy of the FK graph.
   *
   * The owned-resource half of that cascade is the sharp edge: deleting a
   * user also deletes the MCP servers, namespaces and endpoints they own
   * (rows with `user_id` NULL are public/shared and survive). The UI says so
   * in the confirmation dialog — this is a destructive administrative action,
   * not a soft disable. `revokeAccess` is the non-destructive option.
   *
   * Returns false when no row matched so the caller can report "not found"
   * rather than a successful delete that deleted nothing.
   */
  async deleteById(id: string): Promise<boolean> {
    const deleted = await db
      .delete(usersTable)
      .where(eq(usersTable.id, id))
      .returning({ id: usersTable.id });

    return deleted.length > 0;
  }

  /**
   * Sever every live access path for an account WITHOUT deleting it.
   *
   * The kill switch for an intrusion where the account record is still
   * evidence: sign-in sessions, OAuth access/refresh tokens and pending
   * authorization codes are deleted, and owned API keys are deactivated
   * (`is_active = false`, the same flag the key-auth path already checks) —
   * but the row, its email, and its creation timestamp survive for the
   * incident write-up. Deleting first destroys the authoritative record of
   * who the account was.
   *
   * API keys are DEACTIVATED rather than deleted for the same reason, and
   * because `is_active` is the existing revocation mechanism the admin key
   * view already renders.
   *
   * This does NOT prevent the account from signing in again — there is no
   * `disabled` column on `users` and better-auth owns the sign-in path.
   * Revoke buys the operator the time to decide; `deleteById` is the
   * permanent answer. The UI copy states this distinction outright so nobody
   * mistakes a revoke for a ban.
   *
   * Each statement reports its own row count so the caller can show what was
   * actually severed instead of a bare success flag.
   */
  async revokeAccess(id: string): Promise<{
    sessions_deleted: number;
    oauth_tokens_deleted: number;
    authorization_codes_deleted: number;
    api_keys_deactivated: number;
  }> {
    const [sessions, tokens, codes, keys] = await Promise.all([
      db
        .delete(sessionsTable)
        .where(eq(sessionsTable.userId, id))
        .returning({ id: sessionsTable.id }),
      db
        .delete(oauthAccessTokensTable)
        .where(eq(oauthAccessTokensTable.user_id, id))
        .returning({ token: oauthAccessTokensTable.access_token }),
      db
        .delete(oauthAuthorizationCodesTable)
        .where(eq(oauthAuthorizationCodesTable.user_id, id))
        .returning({ code: oauthAuthorizationCodesTable.code }),
      db
        .update(apiKeysTable)
        .set({ is_active: false })
        .where(
          and(eq(apiKeysTable.user_id, id), eq(apiKeysTable.is_active, true)),
        )
        .returning({ uuid: apiKeysTable.uuid }),
    ]);

    return {
      sessions_deleted: sessions.length,
      oauth_tokens_deleted: tokens.length,
      authorization_codes_deleted: codes.length,
      api_keys_deactivated: keys.length,
    };
  }
}

// Export the repository instance
export const usersRepository = new UsersRepository();
