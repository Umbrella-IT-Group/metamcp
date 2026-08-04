import {
  OAuthAccessToken,
  OAuthAccessTokenCreateInput,
  OAuthAuthorizationCode,
  OAuthAuthorizationCodeCreateInput,
  OAuthClient,
  OAuthClientCreateInput,
} from "@repo/zod-types";
import { eq, lt, and, isNull, desc } from "drizzle-orm";

import { db } from "../index";
import {
  oauthAccessTokensTable,
  oauthAuthorizationCodesTable,
  oauthClientsTable,
} from "../schema";

export class OAuthRepository {
  // ===== Registered Clients =====

  async getClient(clientId: string): Promise<OAuthClient | null> {
    const result = await db
      .select()
      .from(oauthClientsTable)
      .where(eq(oauthClientsTable.client_id, clientId))
      .limit(1);
    return result[0] || null;
  }

  async upsertClient(clientData: OAuthClientCreateInput): Promise<void> {
    await db
      .insert(oauthClientsTable)
      .values(clientData)
      .onConflictDoUpdate({
        target: oauthClientsTable.client_id,
        set: {
          redirect_uris: clientData.redirect_uris,
          updated_at: new Date(),
        },
      });
  }

  // Admin listing for the OAuth Clients management UI. Newest first, matching
  // how every other admin list in the app is ordered. Returns whole rows: the
  // caller (the tRPC impl) is responsible for dropping `client_secret` before
  // it leaves the server — see OAuthClientsSerializer.
  async listClients(): Promise<OAuthClient[]> {
    return db
      .select()
      .from(oauthClientsTable)
      .orderBy(desc(oauthClientsTable.created_at));
  }

  // Hard delete — there is no is_active/soft-delete column on oauth_clients,
  // same as api_keys. Both child tables (oauth_authorization_codes,
  // oauth_access_tokens) declare `onDelete: "cascade"` against client_id, so
  // removing the client also revokes every code and token already issued to
  // it. That cascade is the point: deleting a client the operator no longer
  // trusts must not leave live tokens behind.
  //
  // Returns false when no row matched, so the caller can answer "not found"
  // instead of reporting a successful delete that deleted nothing.
  async deleteClient(clientId: string): Promise<boolean> {
    const deleted = await db
      .delete(oauthClientsTable)
      .where(eq(oauthClientsTable.client_id, clientId))
      .returning({ client_id: oauthClientsTable.client_id });

    return deleted.length > 0;
  }

  // ===== Authorization Codes =====

  async getAuthCode(code: string): Promise<OAuthAuthorizationCode | null> {
    const result = await db
      .select()
      .from(oauthAuthorizationCodesTable)
      .where(eq(oauthAuthorizationCodesTable.code, code))
      .limit(1);
    return result[0] || null;
  }

  async setAuthCode(
    code: string,
    data: OAuthAuthorizationCodeCreateInput,
  ): Promise<void> {
    await db.insert(oauthAuthorizationCodesTable).values({
      code,
      client_id: data.client_id,
      redirect_uri: data.redirect_uri,
      scope: data.scope,
      user_id: data.user_id,
      code_challenge: data.code_challenge,
      code_challenge_method: data.code_challenge_method,
      expires_at: new Date(data.expires_at),
    });
  }

  async deleteAuthCode(code: string): Promise<void> {
    await db
      .delete(oauthAuthorizationCodesTable)
      .where(eq(oauthAuthorizationCodesTable.code, code));
  }

  // ===== Access Tokens =====

  async getAccessToken(token: string): Promise<OAuthAccessToken | null> {
    const result = await db
      .select()
      .from(oauthAccessTokensTable)
      .where(eq(oauthAccessTokensTable.access_token, token))
      .limit(1);
    return result[0] || null;
  }

  async setAccessToken(
    token: string,
    data: OAuthAccessTokenCreateInput & {
      refresh_token?: string;
      refresh_token_expires_at?: number;
    },
  ): Promise<void> {
    await db.insert(oauthAccessTokensTable).values({
      access_token: token,
      client_id: data.client_id,
      user_id: data.user_id,
      scope: data.scope,
      expires_at: new Date(data.expires_at),
      refresh_token: data.refresh_token ?? null,
      refresh_token_expires_at: data.refresh_token_expires_at
        ? new Date(data.refresh_token_expires_at)
        : null,
    });
  }

  async deleteAccessToken(token: string): Promise<void> {
    await db
      .delete(oauthAccessTokensTable)
      .where(eq(oauthAccessTokensTable.access_token, token));
  }

  // ===== Refresh Tokens =====

  async getByRefreshToken(refreshToken: string) {
    const result = await db
      .select()
      .from(oauthAccessTokensTable)
      .where(eq(oauthAccessTokensTable.refresh_token, refreshToken))
      .limit(1);
    return result[0] || null;
  }

  // ===== Cleanup =====

  async cleanupExpired(): Promise<void> {
    const now = new Date();
    await Promise.all([
      db
        .delete(oauthAuthorizationCodesTable)
        .where(lt(oauthAuthorizationCodesTable.expires_at, now)),
      // Delete tokens where both access token AND refresh token are expired
      // (or refresh token is null)
      db
        .delete(oauthAccessTokensTable)
        .where(
          and(
            lt(oauthAccessTokensTable.expires_at, now),
            lt(oauthAccessTokensTable.refresh_token_expires_at, now),
          ),
        ),
      db
        .delete(oauthAccessTokensTable)
        .where(
          and(
            lt(oauthAccessTokensTable.expires_at, now),
            isNull(oauthAccessTokensTable.refresh_token),
          ),
        ),
    ]);
  }
}

export const oauthRepository = new OAuthRepository();
