import type { OAuthClientRegistrationSource } from "@repo/zod-types";

export class OAuthClientsSerializer {
  // Admin list view for the OAuth Clients page. Deliberately DROPS
  // `client_secret` and `client_secret_salt` and reports only whether a secret
  // exists — the same rule serializeAdminApiKeyList applies to raw API keys. A
  // registered OAuth client's secret is a credential for the whole gateway, so
  // a listing that echoed it would turn the management page into an
  // exfiltration surface and would quietly break the "shown once at creation"
  // promise the create dialog makes.
  //
  // Built field by field (never a spread of the row), so a column added to
  // oauth_clients later does not reach the browser until someone decides it
  // should. `registered_from_ip` is the one value read from the audit log, and
  // only that value: never the audit row's detail.
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
      approval_status: string;
      // The shared enum, not a local literal union: a value added there (the
      // "cimd" source) must reach this signature, or the list route's output
      // schema and this type disagree and the page fails to parse.
      registration_source?: OAuthClientRegistrationSource | null;
      approved_by?: string | null;
      approved_at?: Date | null;
      rejected_at?: Date | null;
      registered_from_ip?: string | null;
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
      approval_status: client.approval_status,
      registration_source: client.registration_source ?? null,
      approved_by: client.approved_by ?? null,
      approved_at: client.approved_at ?? null,
      rejected_at: client.rejected_at ?? null,
      registered_from_ip: client.registered_from_ip ?? null,
      created_at: client.created_at,
      updated_at: client.updated_at ?? null,
    }));
  }
}
