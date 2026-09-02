import {
  OAuthAccessToken,
  OAuthAccessTokenCreateInput,
  OAuthAuthorizationCode,
  OAuthAuthorizationCodeCreateInput,
  OAuthClient,
  OAuthClientCreateInput,
} from "@repo/zod-types";
import { and, desc, eq, gt, isNull, lt, notExists, sql } from "drizzle-orm";

import { db } from "../index";
import {
  oauthAccessTokensTable,
  oauthAuthorizationCodesTable,
  oauthClientsTable,
  usersTable,
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

  // Retention sweep for anonymous dynamic registrations: delete clients that
  // were minted by DCR, were created longer ago than `olderThanDays`, and have
  // NEVER produced an authorization code or an access token. All three
  // conditions, and the first is not optional.
  //
  // `/oauth/register` needs no credential, so this is the only table in the
  // schema an unauthenticated caller can grow without bound. See
  // ../../routers/oauth/client-retention.ts for why "no child rows" is a sound
  // never-used test here (it rests on the 365-day refresh TTL keeping a token
  // row alive for any client that ever paired) and for the env that tunes it.
  //
  // THE DISCRIMINATOR, and why it is a column rather than a client_id prefix.
  // `oauth_clients` has two mint paths: this sweep's target, the anonymous DCR
  // endpoint, and the admin UI's create-client dialog (trpc/oauth-clients.impl
  // -> the same buildClientRegistration core). Both therefore call the same
  // generateSecureClientId, so EVERY row from either door reads
  // `mcp_client_<random>` — matching that prefix would delete admin-minted
  // clients too, and an admin-minted client with no tokens is usually one that
  // was pre-provisioned for a partner who has not paired yet. Migration 0029
  // added `registration_source` so the two are distinguishable at all, and
  // this equality is the only thing that reads it.
  //
  // `eq(..., "dcr")` and not `ne(..., "admin")`: the column is NULL for every
  // row written before 0029, whose provenance nobody recorded. A NULL is an
  // unknown, an unknown might be an admin's, and the safe reading of an
  // unknown is to keep the row. `ne` would also drop them (SQL NULL
  // comparisons are UNKNOWN, so neither predicate MATCHES a NULL — but stating
  // the intent positively is what stops the next edit from getting it wrong).
  //
  // NOT EXISTS rather than a LEFT JOIN with an IS NULL: the join form would
  // multiply the client row by its children before filtering, and postgres can
  // answer the anti-join directly off the two client_id indexes. `returning`
  // gives the caller a real count, so the log line reports what happened
  // instead of that the statement ran.
  async pruneUnusedClients(olderThanDays: number): Promise<number> {
    if (!Number.isFinite(olderThanDays) || olderThanDays <= 0) return 0;

    const cutoff = new Date(Date.now() - olderThanDays * 24 * 60 * 60 * 1000);

    const deleted = await db
      .delete(oauthClientsTable)
      .where(
        and(
          eq(oauthClientsTable.registration_source, "dcr"),
          lt(oauthClientsTable.created_at, cutoff),
          notExists(
            db
              .select({ one: sql`1` })
              .from(oauthAuthorizationCodesTable)
              .where(
                eq(
                  oauthAuthorizationCodesTable.client_id,
                  oauthClientsTable.client_id,
                ),
              ),
          ),
          notExists(
            db
              .select({ one: sql`1` })
              .from(oauthAccessTokensTable)
              .where(
                eq(
                  oauthAccessTokensTable.client_id,
                  oauthClientsTable.client_id,
                ),
              ),
          ),
        ),
      )
      .returning({ client_id: oauthClientsTable.client_id });

    return deleted.length;
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

  // Atomic single-use consumption of an authorization code. DELETE ...
  // RETURNING in one statement is the single-use gate: `code` is the primary
  // key, so this matches at most one row, and under two concurrent redemptions
  // of the same code postgres serializes the deletes — exactly one returns the
  // row and the other returns none. The caller issues tokens only when this
  // returned true, so a read-then-delete race can no longer mint two token
  // pairs for one code. `deleteAuthCode` above stays for the cleanup deletes
  // (expired codes) where no such gate is needed.
  async consumeAuthCode(code: string): Promise<boolean> {
    const deleted = await db
      .delete(oauthAuthorizationCodesTable)
      .where(eq(oauthAuthorizationCodesTable.code, code))
      .returning({ code: oauthAuthorizationCodesTable.code });

    return deleted.length === 1;
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
      // The refresh token and its expiry travel together as one optional pair,
      // not as two independent optionals. A token stored with a refresh token
      // but a NULL expiry escapes every reaper predicate in cleanupExpired and
      // is treated as valid forever by the refresh grant; bundling
      // them makes that shape unrepresentable at this write path, and migration
      // 0035's CHECK enforces the same invariant at the column level.
      refresh?: { token: string; expires_at: number };
    },
  ): Promise<void> {
    await db.insert(oauthAccessTokensTable).values({
      access_token: token,
      client_id: data.client_id,
      user_id: data.user_id,
      scope: data.scope,
      expires_at: new Date(data.expires_at),
      refresh_token: data.refresh?.token ?? null,
      refresh_token_expires_at: data.refresh
        ? new Date(data.refresh.expires_at)
        : null,
    });
  }

  async deleteAccessToken(token: string): Promise<void> {
    await db
      .delete(oauthAccessTokensTable)
      .where(eq(oauthAccessTokensTable.access_token, token));
  }

  // Admin listing of LIVE access tokens — "who is connected over OAuth right
  // now", which before the Access dashboard had no answer outside psql.
  //
  // Filtered to non-expired rows only: `cleanupExpired` is opportunistic, so
  // the table accumulates dead rows and an unfiltered listing would bury the
  // handful of tokens that still authenticate. Expiry is evaluated against a
  // single caller-supplied `now` so every row in one response is judged
  // against the same instant.
  //
  // LEFT JOINs (not inner) on users and clients: a token whose user or client
  // row is gone is precisely the anomaly an administrator must be able to
  // see, and an inner join would silently hide it.
  //
  // Selects METADATA ONLY. `access_token` and `refresh_token` are not in the
  // projection at all — a bearer credential for the whole gateway must not be
  // pulled out of the database just to be dropped later. `refresh_token` is
  // reduced to a boolean in SQL so the value never enters the process.
  async listActiveAccessTokens(now: Date = new Date()) {
    return await db
      .select({
        user_id: oauthAccessTokensTable.user_id,
        user_email: usersTable.email,
        client_id: oauthAccessTokensTable.client_id,
        client_name: oauthClientsTable.client_name,
        scope: oauthAccessTokensTable.scope,
        created_at: oauthAccessTokensTable.created_at,
        expires_at: oauthAccessTokensTable.expires_at,
        // `.mapWith(Boolean)` for the same reason the user listing's counts
        // carry `.mapWith(Number)`: a raw `sql` fragment has NO driver
        // decoder, so whatever node-postgres puts on the wire is what the
        // caller gets. A postgres `boolean` happens to decode to a JS boolean
        // natively, so this is currently a no-op — but the guard is explicit
        // because the trap is invisible until it bites: change this
        // expression to anything bigint-shaped (`count(...) > 0` rewritten as
        // a count, say) and it silently starts returning a STRING that the
        // router's `.output()` schema rejects at runtime. Verified against a
        // real postgres in access-queries.integration.test.ts.
        has_refresh_token:
          sql<boolean>`${oauthAccessTokensTable.refresh_token} IS NOT NULL`
            .mapWith(Boolean)
            .as("has_refresh_token"),
        refresh_token_expires_at:
          oauthAccessTokensTable.refresh_token_expires_at,
      })
      .from(oauthAccessTokensTable)
      .leftJoin(usersTable, eq(oauthAccessTokensTable.user_id, usersTable.id))
      .leftJoin(
        oauthClientsTable,
        eq(oauthAccessTokensTable.client_id, oauthClientsTable.client_id),
      )
      .where(gt(oauthAccessTokensTable.expires_at, now))
      .orderBy(desc(oauthAccessTokensTable.created_at));
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
