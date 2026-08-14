export class UsersSerializer {
  // Admin listing for the Access dashboard's Users section.
  //
  // Written as a strict allow-list — every emitted field is named here — so a
  // column added to `users` later cannot reach the wire just by existing. The
  // `users` table holds no credential material today (better-auth stores the
  // password hash on `accounts.password`, and the session token on
  // `sessions.token`), but "there is nothing secret in this table right now"
  // is a property of the schema at one point in time, not a guarantee, and
  // this is the surface the 2026-08-13 incident made administrator-visible.
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
      created_at: Date;
      updated_at: Date;
      last_active_at: Date | null;
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
      emailVerified: user.emailVerified,
      created_at: user.created_at,
      updated_at: user.updated_at,
      last_active_at: user.last_active_at,
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
