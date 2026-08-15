/**
 * Coerce a value the driver may have handed back as a wire string into the
 * `Date` the wire contract demands.
 *
 * This exists because of a real production-shaped failure: `users.list`
 * returned `last_session_refresh_at` from a raw `sql` fragment, raw fragments
 * carry no driver decoder, and node-postgres therefore returned the
 * timestamptz as the string `'2026-08-14 13:07:51.558+00'`. The router's
 * `.output()` schema rejected it — `invalid_type: expected date, received
 * string` — so the entire listing failed for any account that had ever held a
 * session. The type system was no help: the query's TS type already claimed
 * `Date`.
 *
 * The repository now attaches `.mapWith(sessionsTable.updatedAt)`, which is
 * the real fix. This is the second layer: a serializer that cannot be broken
 * by a future query rewrite that forgets the decoder again. Cheap, and the
 * failure it prevents is total.
 *
 * An unparseable value becomes null rather than an Invalid Date — a null
 * renders as "Never" in the UI, whereas an Invalid Date would sail through
 * `z.date()` (it IS a Date) and surface as "Invalid Date" in the table.
 */
function toDateOrNull(value: Date | string | null | undefined): Date | null {
  if (value === null || value === undefined) return null;
  const date = value instanceof Date ? value : new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

export class UsersSerializer {
  // Admin listing for the Access dashboard's Users section.
  //
  // Written as a strict allow-list — every emitted field is named here — so a
  // column added to `users` later cannot reach the wire just by existing. The
  // `users` table holds no credential material today (better-auth stores the
  // password hash on `accounts.password`, and the session token on
  // `sessions.token`), but "there is nothing secret in this table right now"
  // is a property of the schema at one point in time, not a guarantee, and
  // this is the surface the access review made administrator-visible.
  //
  // Same discipline as serializeAdminApiKeyList / serializeOAuthClientList:
  // the serializer drops, the router's `.output()` schema re-checks. Two
  // independent layers, so one of them being edited carelessly is not enough
  // to leak.
  static serializeUserList(
    dbUsers: Array<{
      id: string;
      email: string;
      name: string;
      role: string;
      emailVerified: boolean;
      // Widened past the column's NOT NULL because the point of the `?? true`
      // below is to survive a driver/query regression that stops producing a
      // real boolean here — a type that forbids the bad value would optimise
      // the defence away.
      disabled: boolean | null | undefined;
      disabled_at: Date | string | null;
      disabled_by: string | null;
      created_at: Date | string;
      updated_at: Date | string;
      last_session_refresh_at: Date | string | null;
      active_session_count: number;
      active_oauth_token_count: number;
      active_api_key_count: number;
    }>,
  ) {
    return dbUsers.map((user) => ({
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      emailVerified: user.emailVerified === true,
      // Fail CLOSED, matching usersRepository.isDisabled's `?? true`. The
      // enforcement path and the badge that reports it must agree about what
      // an absent value means, and the two answers are not equally safe: a
      // `=== true` read of a lost value badges the account ENABLED, so the
      // dashboard would tell an admin that the attacker they just locked out
      // is still active — the one lie this screen exists to prevent. Reading
      // it as disabled is the harmless direction: the admin sees a lock that
      // enforcement is also applying.
      disabled: user.disabled ?? true,
      disabled_at: toDateOrNull(user.disabled_at),
      disabled_by: user.disabled_by,
      // Coerced for the same reason as last_session_refresh_at below — these
      // are ordinary typed columns today and need no help, but the cost of
      // being wrong here is the whole listing, so every date on this response
      // goes through one path.
      created_at: toDateOrNull(user.created_at) ?? new Date(0),
      updated_at: toDateOrNull(user.updated_at) ?? new Date(0),
      // The field that actually broke. See toDateOrNull above.
      last_session_refresh_at: toDateOrNull(user.last_session_refresh_at),
      // Number() is a belt-and-braces coercion on top of the repository's
      // `.mapWith(Number)`: postgres count(*) is bigint and node-postgres
      // hands bigint back as a string, which would fail the `.output()`
      // schema. Cheap here, and it keeps the serializer honest if the query
      // is ever rewritten without the mapper.
      active_session_count: Number(user.active_session_count),
      active_oauth_token_count: Number(user.active_oauth_token_count),
      active_api_key_count: Number(user.active_api_key_count),
    }));
  }
}
