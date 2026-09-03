export class OAuthTokensSerializer {
  // Admin listing of live OAuth access tokens for the Access dashboard.
  //
  // There is no `access_token` / `refresh_token` field to drop here, and that
  // is deliberate: the repository query never selects either column, so the
  // secret does not exist in this process to be leaked by a careless spread.
  // This serializer is the SECOND layer — it re-states the exact wire shape
  // as an allow-list, mirroring OAuthClientsSerializer's rule that a
  // management listing must never become an exfiltration surface. Refresh
  // tokens are reported as presence only, computed in SQL.
  //
  // Never replace this with a spread of the row. The whole point of naming
  // every field is that adding a column to `oauth_access_tokens` cannot
  // silently widen the response.
  static serializeActiveTokenList(
    dbTokens: Array<{
      user_id: string;
      access_token_last4: string;
      user_email: string | null;
      client_id: string;
      client_name: string | null;
      scope: string;
      created_at: Date;
      expires_at: Date;
      has_refresh_token: boolean;
      refresh_token_expires_at: Date | null;
    }>,
  ) {
    return dbTokens.map((token) => ({
      user_id: token.user_id,
      // The token's four-character tail (migration 0036). Safe to display and
      // already recorded in the audit log; the full access_token digest and the
      // refresh token stay out of both the query and this allow-list.
      access_token_last4: token.access_token_last4,
      user_email: token.user_email,
      client_id: token.client_id,
      client_name: token.client_name,
      scope: token.scope,
      created_at: token.created_at,
      expires_at: token.expires_at,
      // `=== true`, NOT `Boolean(...)`. Boolean() is truthy-coercion: the
      // string "false" — exactly what a driver hands back for a boolean it
      // did not decode — coerces to TRUE, so a decode regression would flip
      // this badge to "has a refresh token" for every row rather than failing
      // loudly. A strict comparison degrades to `false` instead, which is the
      // safe direction for a security display.
      has_refresh_token: token.has_refresh_token === true,
      refresh_token_expires_at: token.refresh_token_expires_at,
    }));
  }
}
