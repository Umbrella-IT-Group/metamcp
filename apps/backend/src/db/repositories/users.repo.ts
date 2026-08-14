import { and, count, desc, eq, gt, inArray, ne, or, sql } from "drizzle-orm";

import { db } from "../index";
import {
  apiKeysTable,
  endpointsTable,
  m365UserTokensTable,
  mcpServersTable,
  namespacesTable,
  oauthAccessTokensTable,
  oauthAuthorizationCodesTable,
  sessionsTable,
  usersTable,
} from "../schema";

/**
 * Hard ceiling on the admin user listing.
 *
 * The page this feeds is the one an operator opens DURING an incident, and
 * the incident that motivated it was self-registration abuse — precisely the
 * scenario that produces thousands of accounts. An unbounded listing gets
 * slowest exactly when it is needed most, so the query takes a LIMIT and the
 * response reports the true total separately. See `listAll`.
 */
export const USER_LIST_LIMIT = 500;

/**
 * The admin user listing, as a query builder rather than an executed query,
 * so its SQL can be asserted without a database.
 *
 * The counts are CORRELATED SUBQUERIES rather than LEFT JOIN + GROUP BY on
 * purpose: three independent one-to-many joins against the same driving table
 * multiply each other's rows, so a user with 2 sessions and 3 keys would
 * report 6 of each. Subqueries keep every count independent, and each
 * predicate is indexed (`sessions.user_id` is the FK,
 * `oauth_access_tokens_user_id_idx`, `api_keys_user_id_idx`,
 * `api_keys_acts_as_user_id_idx`).
 *
 * `now` is captured once by the caller and passed into all the liveness
 * predicates, so one user's counts are consistent with each other instead of
 * being evaluated at three slightly different instants.
 *
 * DRIVER DECODERS ARE LOAD-BEARING on every raw `sql` fragment here, and this
 * is the single sharpest edge in the file. Interpolating a subquery into a
 * raw fragment discards the decoder drizzle would have taken from the column
 * type, so node-postgres returns its WIRE representation: `count(*)` is
 * bigint and arrives as a STRING, `max(timestamptz)` arrives as a STRING.
 * The TypeScript type still claims `number` / `Date`, so nothing fails to
 * compile — the failure lands at runtime in the router's `.output()` schema
 * ("expected date, received string") and takes the whole listing with it.
 * `.mapWith(Number)` / `.mapWith(sessionsTable.updatedAt)` reattach the
 * decoders. Verified against a real postgres in
 * access-queries.integration.test.ts; do not remove either without running
 * that suite.
 *
 * An explicit column list is used, never `select()` — the serializer is the
 * redaction boundary, but not pulling columns nobody asked for is the cheaper
 * first layer.
 */
export function buildUserListQuery(now: Date, limit: number = USER_LIST_LIMIT) {
  const lastActive = db
    .select({ value: sql`max(${sessionsTable.updatedAt})` })
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

  // Both ownership AND delegation. A key owned by somebody else but carrying
  // `acts_as_user_id = this user` (migration 0024) authenticates requests
  // that run AS this identity against M365 — it is a live access path for
  // this account no matter whose key it is. Counting only `user_id` made the
  // column under-report the very thing an operator reads it for.
  const activeKeys = db
    .select({ value: count() })
    .from(apiKeysTable)
    .where(
      and(
        or(
          eq(apiKeysTable.user_id, usersTable.id),
          eq(apiKeysTable.acts_as_user_id, usersTable.id),
        ),
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
      disabled: usersTable.disabled,
      disabled_at: usersTable.disabled_at,
      disabled_by: usersTable.disabled_by,
      created_at: usersTable.createdAt,
      updated_at: usersTable.updatedAt,
      // An explicit decoder function rather than `.mapWith(column)`, for two
      // reasons. Runtime: `max()` over zero rows returns NULL, and this
      // fragment must survive that — a user who has never held a session is
      // the common case, not an edge case. Types: passing the column would
      // narrow the result to the column's own NOT NULL `Date`, which is a
      // lie about a scalar subquery that genuinely can be null, and the lie
      // would propagate into the serializer's signature.
      last_session_refresh_at: sql<Date | null>`${lastActive}`
        .mapWith((value: unknown): Date | null =>
          value === null || value === undefined
            ? null
            : (sessionsTable.updatedAt.mapFromDriverValue(value) as Date),
        )
        .as("last_session_refresh_at"),
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
    .orderBy(desc(usersTable.createdAt))
    .limit(limit);
}

/**
 * Read + administrative surface over the better-auth users table.
 *
 * Account LIFECYCLE (sign-up, password, verification) still belongs to
 * better-auth — nothing here mints or mutates credentials. What this adds is
 * the administrative half better-auth does not provide: enumerate the
 * accounts that exist, and lock or remove one.
 *
 * That enumeration used to be deliberately absent ("the admin UI takes a user
 * id, it does not enumerate accounts"). The 2026-08-13 incident overturned
 * that call: an attacker's self-registered member accounts were invisible in
 * the GUI, because no surface anywhere listed users. An access path that
 * cannot be seen cannot be audited, so the listing is now the point.
 *
 * Three tiers of administrative action, weakest first:
 *   revokeAccess — sever live access, account survives and can sign in again
 *   setDisabled  — lock the account out, everything preserved as evidence
 *   deleteById   — destroy the account and everything the FK graph reaches
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
   * Is this account locked?
   *
   * The enforcement primitive for `disabled`, read fresh from the database on
   * every check rather than from a serialized session. That matters: a
   * better-auth session is minted once and lives 30 days in this fork, so a
   * flag captured at sign-in time would let a disabled account keep working
   * for a month. Disabling has to take effect on the NEXT request, which
   * means re-reading the column.
   *
   * Returns TRUE for an unknown id — fail closed. A session pointing at a
   * user row that no longer exists is not a user this gateway should serve,
   * and the alternative (defaulting to "enabled") would turn a mid-cascade
   * race into an open door.
   */
  async isDisabled(id: string): Promise<boolean> {
    const [user] = await db
      .select({ disabled: usersTable.disabled })
      .from(usersTable)
      .where(eq(usersTable.id, id));

    return user?.disabled ?? true;
  }

  /**
   * Accounts, newest first, capped at `limit`, plus the true total so the UI
   * can say "showing 500 of 4,312" instead of silently truncating. A silent
   * truncation on this screen would recreate the incident in miniature: the
   * account you are hunting is simply not rendered.
   */
  async listAll(now: Date = new Date(), limit: number = USER_LIST_LIMIT) {
    const [users, [totals]] = await Promise.all([
      buildUserListQuery(now, limit),
      db.select({ value: count() }).from(usersTable),
    ]);

    return { users, total: totals?.value ?? users.length };
  }

  /**
   * Lock or unlock an account.
   *
   * `disabled_at` / `disabled_by` are written on lock and CLEARED on unlock,
   * so the columns always describe the CURRENT lock rather than accumulating
   * a half-history that nobody can interpret. (The durable audit trail is the
   * server log line the impl writes; these columns answer "who locked this,
   * and when" for the account as it stands.)
   *
   * Returns undefined when no row matched, so the caller can report "not
   * found" instead of a successful lock that locked nothing.
   */
  async setDisabled(
    id: string,
    disabled: boolean,
    actorUserId: string,
  ): Promise<{ id: string; disabled: boolean } | undefined> {
    const [updated] = await db
      .update(usersTable)
      .set({
        disabled,
        disabled_at: disabled ? new Date() : null,
        disabled_by: disabled ? actorUserId : null,
        updatedAt: new Date(),
      })
      .where(eq(usersTable.id, id))
      .returning({ id: usersTable.id, disabled: usersTable.disabled });

    return updated;
  }

  /**
   * What a `deleteById` on this account would destroy.
   *
   * Deleting a user is irreversible and its blast radius is NOT confined to
   * that user — a fact the first version of this feature got wrong in its
   * confirmation dialog. Two FK paths reach other people's rows, both
   * verified against a real postgres (see access-queries.integration.test.ts):
   *
   *   1. `namespaces.user_id` cascades, and `endpoints.namespace_uuid`
   *      cascades from namespaces — so an endpoint owned by user B that lives
   *      in user A's namespace dies when A is deleted.
   *   2. `api_keys.acts_as_user_id` cascades — so a key owned by admin B that
   *      acts as identity A dies when A is deleted. Deleting a CI/sync
   *      identity therefore revokes another administrator's production key.
   *   And transitively, `api_keys.endpoint_uuid` cascades from any endpoint
   *      killed by (1), whoever owns that key.
   *
   * The counts are split own/other precisely because the "other" numbers are
   * the ones that must stop an operator mid-click. Computed in one pass
   * before the confirmation, never derived from the delete itself — by then
   * it is too late to decide.
   */
  async previewDeleteImpact(id: string) {
    // Every endpoint that dies: those the user owns, plus every endpoint —
    // whoever owns it — sitting inside a namespace the user owns.
    const doomedNamespaces = db
      .select({ uuid: namespacesTable.uuid })
      .from(namespacesTable)
      .where(eq(namespacesTable.user_id, id));

    const doomedEndpointsWhere = or(
      eq(endpointsTable.user_id, id),
      inArray(endpointsTable.namespace_uuid, doomedNamespaces),
    );

    const doomedEndpoints = db
      .select({ uuid: endpointsTable.uuid })
      .from(endpointsTable)
      .where(doomedEndpointsWhere);

    const [
      [ownNamespaces],
      [ownEndpoints],
      [otherEndpoints],
      [ownServers],
      [ownKeys],
      [otherKeys],
      [sessions],
      [tokens],
      [m365],
    ] = await Promise.all([
      db
        .select({ value: count() })
        .from(namespacesTable)
        .where(eq(namespacesTable.user_id, id)),
      db
        .select({ value: count() })
        .from(endpointsTable)
        .where(eq(endpointsTable.user_id, id)),
      // The cross-user half of (1): somebody else's endpoint in this user's
      // namespace. `ne` rather than "not eq" so NULL-owned (public) endpoints
      // are excluded from the alarming number — they have no other owner to
      // surprise.
      db
        .select({ value: count() })
        .from(endpointsTable)
        .where(and(doomedEndpointsWhere, ne(endpointsTable.user_id, id))),
      db
        .select({ value: count() })
        .from(mcpServersTable)
        .where(eq(mcpServersTable.user_id, id)),
      db
        .select({ value: count() })
        .from(apiKeysTable)
        .where(eq(apiKeysTable.user_id, id)),
      // The cross-user half of (2) and its transitive form: a key owned by
      // somebody else that dies because it acts as this identity, or because
      // it is scoped to an endpoint this delete destroys.
      db
        .select({ value: count() })
        .from(apiKeysTable)
        .where(
          and(
            ne(apiKeysTable.user_id, id),
            or(
              eq(apiKeysTable.acts_as_user_id, id),
              inArray(apiKeysTable.endpoint_uuid, doomedEndpoints),
            ),
          ),
        ),
      db
        .select({ value: count() })
        .from(sessionsTable)
        .where(eq(sessionsTable.userId, id)),
      db
        .select({ value: count() })
        .from(oauthAccessTokensTable)
        .where(eq(oauthAccessTokensTable.user_id, id)),
      db
        .select({ value: count() })
        .from(m365UserTokensTable)
        .where(eq(m365UserTokensTable.user_id, id)),
    ]);

    return {
      own_namespaces: ownNamespaces?.value ?? 0,
      own_endpoints: ownEndpoints?.value ?? 0,
      own_mcp_servers: ownServers?.value ?? 0,
      own_api_keys: ownKeys?.value ?? 0,
      other_users_endpoints: otherEndpoints?.value ?? 0,
      other_users_api_keys: otherKeys?.value ?? 0,
      sessions: sessions?.value ?? 0,
      oauth_tokens: tokens?.value ?? 0,
      m365_tokens: m365?.value ?? 0,
    };
  }

  /**
   * Hard-delete an account.
   *
   * Every table that references `users.id` declares `onDelete: "cascade"`
   * (except `users.disabled_by`, which is SET NULL) — sessions, accounts (the
   * password hash lives there), api_keys via both `user_id` and
   * `acts_as_user_id`, oauth_authorization_codes, oauth_access_tokens,
   * m365_user_tokens, and the owned mcp_servers / namespaces / endpoints. So
   * one DELETE severs every access path this account had; no dependent
   * cleanup is needed here, and adding manual deletes would only create a
   * second, drift-prone copy of the FK graph.
   *
   * THE CASCADE IS NOT CONFINED TO THIS USER. It reaches other people's rows
   * through two paths — endpoints owned by someone else inside this user's
   * namespaces, and API keys owned by someone else that act as this identity
   * or are scoped to a doomed endpoint. `previewDeleteImpact` quantifies both
   * and the confirmation dialog shows them; an earlier version of this
   * comment and that dialog both claimed only the user's own private
   * resources were affected, which a live postgres disproved.
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
   * The soft tier: sign-in sessions, OAuth access/refresh tokens and pending
   * authorization codes are deleted, API keys that can act as this identity
   * are deactivated, and the M365 delegation is forced back to
   * `reauth_required` — but the row, its email, and its creation timestamp
   * survive for the incident write-up. Deleting first destroys the
   * authoritative record of who the account was.
   *
   * Five statements, ONE TRANSACTION. They used to run under `Promise.all`,
   * which meant a mid-flight failure could leave sessions deleted but keys
   * still live while the caller was told the revoke had failed — the operator
   * then believes access is intact when it is half-cut, or vice versa. Either
   * way the reported state is a lie. A transaction makes it all-or-nothing,
   * so "failed" genuinely means nothing changed.
   *
   * Coverage notes, each earned:
   *   - api_keys matches `user_id` OR `acts_as_user_id`. A key owned by
   *     another admin but bound to this identity authenticates requests that
   *     run AS this user against M365; leaving it active leaves the identity
   *     usable, which is the whole thing revocation is for.
   *   - m365_user_tokens is set to `reauth_required` rather than deleted: the
   *     mint path already treats that status as missing (so access stops
   *     now), and the row stays as an audit record of the enrollment.
   *   - OAuth tokens are deleted regardless of expiry. An expired ACCESS
   *     token can still carry a live REFRESH token.
   *
   * This does NOT prevent the account from signing in again — that is what
   * `setDisabled` is for. Revoke buys time; disable locks; delete destroys.
   * The UI copy states the distinction outright so nobody mistakes one for
   * another.
   */
  async revokeAccess(id: string): Promise<{
    sessions_deleted: number;
    oauth_tokens_deleted: number;
    authorization_codes_deleted: number;
    api_keys_deactivated: number;
    m365_tokens_revoked: number;
  }> {
    return await db.transaction(async (tx) => {
      const sessions = await tx
        .delete(sessionsTable)
        .where(eq(sessionsTable.userId, id))
        .returning({ id: sessionsTable.id });

      const tokens = await tx
        .delete(oauthAccessTokensTable)
        .where(eq(oauthAccessTokensTable.user_id, id))
        .returning({ token: oauthAccessTokensTable.access_token });

      const codes = await tx
        .delete(oauthAuthorizationCodesTable)
        .where(eq(oauthAuthorizationCodesTable.user_id, id))
        .returning({ code: oauthAuthorizationCodesTable.code });

      const keys = await tx
        .update(apiKeysTable)
        .set({ is_active: false })
        .where(
          and(
            or(
              eq(apiKeysTable.user_id, id),
              eq(apiKeysTable.acts_as_user_id, id),
            ),
            eq(apiKeysTable.is_active, true),
          ),
        )
        .returning({ uuid: apiKeysTable.uuid });

      const m365 = await tx
        .update(m365UserTokensTable)
        .set({ status: "reauth_required" })
        .where(
          and(
            eq(m365UserTokensTable.user_id, id),
            ne(m365UserTokensTable.status, "reauth_required"),
          ),
        )
        .returning({ uuid: m365UserTokensTable.uuid });

      return {
        sessions_deleted: sessions.length,
        oauth_tokens_deleted: tokens.length,
        authorization_codes_deleted: codes.length,
        api_keys_deactivated: keys.length,
        m365_tokens_revoked: m365.length,
      };
    });
  }
}

// Export the repository instance
export const usersRepository = new UsersRepository();
