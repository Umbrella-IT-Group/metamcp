export class OAuthClientsSerializer {
  // Admin list view for the OAuth Clients page. Deliberately DROPS
  // `client_secret` and reports only whether one exists — the same rule
  // serializeAdminApiKeyList applies to raw API keys. A registered OAuth
  // client's secret is a credential for the whole gateway, so a listing that
  // echoed it would turn the management page into an exfiltration surface and
  // would quietly break the "shown once at creation" promise the create
  // dialog makes.
  static serializeOAuthClientList(
    dbClients: Array<{
      client_id: string;
      client_secret: string | null;
      client_name: string;
      redirect_uris: string[];
      grant_types: string[];
      response_types: string[];
      token_endpoint_auth_method: string;
      scope: string | null;
      created_at: Date;
      // OAuthClientSchema types this optional even though the column is NOT
      // NULL with a default, so accept both shapes and normalize below —
      // the wire contract exposes one nullable field, not two absent-ish ones.
      updated_at?: Date | null;
    }>,
  ) {
    return dbClients.map((client) => ({
      client_id: client.client_id,
      client_name: client.client_name,
      redirect_uris: client.redirect_uris,
      grant_types: client.grant_types,
      response_types: client.response_types,
      token_endpoint_auth_method: client.token_endpoint_auth_method,
      scope: client.scope,
      has_client_secret: client.client_secret !== null,
      created_at: client.created_at,
      updated_at: client.updated_at ?? null,
    }));
  }
}
