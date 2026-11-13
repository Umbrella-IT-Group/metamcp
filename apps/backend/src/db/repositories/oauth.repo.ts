import {
  OAuthAccessToken,
  OAuthAccessTokenCreateInput,
  OAuthAuthorizationCode,
  OAuthAuthorizationCodeCreateInput,
  OAuthClient,
  OAuthClientCreateInput,
} from "@repo/zod-types";
import { and, desc, eq, gt, gte, isNull, lt, or, sql } from "drizzle-orm";

import { apiKeyLast4, hashApiKey } from "@/lib/api-key-hash";
import { hashClientSecret } from "@/routers/oauth/utils";

import { db } from "../index";
import {
  auditLogTable,
  oauthAccessTokensTable,
  oauthAuthorizationCodesTable,
  oauthClientsTable,
  oauthRotatedRefreshTokensTable,
  oauthSpentAuthorizationCodesTable,
  usersTable,
} from "../schema";
import {
  lockOAuthUser,
  type OAuthDbExecutor,
  type OAuthTx,
  withOAuthUserLock,
} from "./oauth-user-lock";

export class OAuthRepository {
  // ===== Per-user credential lock =====

  // See ./oauth-user-lock for why every OAuth mint and revoke for a user runs
  // under one transaction-scoped advisory lock. Exposed on the repository so
  // the routers reach it through the same seam their tests already mock.
  async withUserLock<T>(
    userId: string,
    fn: (tx: OAuthTx) => Promise<T>,
  ): Promise<T> {
    return withOAuthUserLock(userId, fn);
  }

  // ===== Registered Clients =====

  async getClient(
    clientId: string,
    executor: OAuthDbExecutor = db,
  ): Promise<OAuthClient | null> {
    const result = await executor
      .select()
      .from(oauthClientsTable)
      .where(eq(oauthClientsTable.client_id, clientId))
      .limit(1);
    return result[0] || null;
  }

  async upsertClient(clientData: OAuthClientCreateInput): Promise<void> {
    // Salted-hash the client secret at rest (migration 0036). This is the
    // single write choke for both mint paths (the anonymous DCR endpoint and
    // the admin create dialog), so hashing here covers both without either
    // caller changing, the plaintext they return to the client once is a
    // separate variable captured before this call, never this stored value. A
    // public/PKCE client has no secret (null), which stays null. The salt goes
    // in its own column so verifyClientSecret can recompute the digest.
    const hashed = clientData.client_secret
      ? hashClientSecret(clientData.client_secret)
      : null;
    await db
      .insert(oauthClientsTable)
      .values({
        ...clientData,
        client_secret: hashed ? hashed.hash : clientData.client_secret,
        client_secret_salt: hashed ? hashed.salt : null,
      })
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
  // caller (the tRPC impl) is responsible for dropping `client_secret` and
  // `client_secret_salt` before they leave the server — see
  // OAuthClientsSerializer.
  //
  // `registered_from_ip` is the source address of the successful anonymous
  // registration, from its `oauth.dcr.register` audit row: the only
  // attribution an anonymous registration has, shown so an administrator
  // deciding on a pending client can see where it came from. Only that one
  // column is read; the audit row's detail never leaves the database here.
  // Deduplicate successful registrations once before joining, so each client
  // appears once with its earliest address. A correlated lookup would scan
  // the append-only audit log again for every client, making this inventory
  // quadratic as anonymous registrations accumulate. NULL for admin and legacy
  // rows (they have no such audit row) and when the detached audit write did
  // not land.
  async listClients(): Promise<
    Array<OAuthClient & { registered_from_ip: string | null }>
  > {
    const registrations = db
      .selectDistinctOn([auditLogTable.target_id], {
        client_id: auditLogTable.target_id,
        actor_ip: auditLogTable.actor_ip,
      })
      .from(auditLogTable)
      .where(
        and(
          eq(auditLogTable.action, "oauth.dcr.register"),
          eq(auditLogTable.outcome, "success"),
        ),
      )
      .orderBy(auditLogTable.target_id, auditLogTable.occurred_at)
      .as("client_registrations");

    const rows = await db
      .select({
        client: oauthClientsTable,
        registered_from_ip: registrations.actor_ip,
      })
      .from(oauthClientsTable)
      .leftJoin(
        registrations,
        eq(registrations.client_id, oauthClientsTable.client_id),
      )
      .orderBy(desc(oauthClientsTable.created_at));

    return rows.map((row) => ({
      ...row.client,
      registered_from_ip: row.registered_from_ip ?? null,
    }));
  }

  // ===== Approval decisions (migration 0042) =====

  // Approve one PENDING SELF-REGISTERED client. A single conditional UPDATE is
  // the whole decision: the row must still exist, still be `dcr`, still be
  // `pending`, and still carry exactly the callbacks the caller validated. Two
  // administrators deciding at once therefore produce one winner: postgres
  // serializes the two UPDATEs on the row, and the second finds it no longer
  // pending and changes nothing. Returns the changed row, or null when nothing
  // matched (deleted, already decided, not self-registered, or callbacks that
  // changed after they were checked); the caller classifies the miss.
  //
  // The actor and time come from the caller's authenticated context; nothing
  // here reads a request body. Approval mints no grant or token: a user still
  // has to authorize the client themselves.
  async approvePendingDcrClient(
    clientId: string,
    validatedRedirectUris: string[],
    approvedBy: string,
    now: Date = new Date(),
  ): Promise<OAuthClient | null> {
    const updated = await db
      .update(oauthClientsTable)
      .set({
        approval_status: "approved",
        approved_by: approvedBy,
        approved_at: now,
        updated_at: now,
      })
      .where(
        and(
          eq(oauthClientsTable.client_id, clientId),
          eq(oauthClientsTable.registration_source, "dcr"),
          eq(oauthClientsTable.approval_status, "pending"),
          eq(oauthClientsTable.redirect_uris, validatedRedirectUris),
        ),
      )
      .returning();
    return updated[0] ?? null;
  }

  // Reject one PENDING SELF-REGISTERED client, the same single conditional
  // UPDATE as approval. rejected_at starts the one-day clock the retention
  // sweep counts from.
  async rejectPendingDcrClient(
    clientId: string,
    now: Date = new Date(),
  ): Promise<OAuthClient | null> {
    const updated = await db
      .update(oauthClientsTable)
      .set({
        approval_status: "rejected",
        rejected_at: now,
        updated_at: now,
      })
      .where(
        and(
          eq(oauthClientsTable.client_id, clientId),
          eq(oauthClientsTable.registration_source, "dcr"),
          eq(oauthClientsTable.approval_status, "pending"),
        ),
      )
      .returning();
    return updated[0] ?? null;
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

  // Retention sweep for anonymous self-registrations that no administrator
  // approved: delete DCR rows that are still PENDING and were created more
  // than `pendingOlderThanDays` ago, and DCR rows that were REJECTED more than
  // `rejectedOlderThanMs` ago (counted from rejected_at, not registration).
  //
  // Nothing else is ever deleted, and the predicates say so positively:
  //   - `registration_source = 'dcr'`, so admin-created rows (often unused on
  //     purpose: pre-provisioned for someone who has not connected yet) and
  //     legacy rows whose provenance is NULL never match. `eq` and not
  //     `ne(..., 'admin')`, so an unknown provenance is kept;
  //   - an approval status of exactly 'pending' or 'rejected', so an APPROVED
  //     row survives however long it goes unused. The previous predicate
  //     ("no code or token children") would have deleted an approved
  //     self-registration that simply had not connected yet.
  //
  // The status predicates live in the DELETE itself rather than in an earlier
  // candidate SELECT, so an administrator approving a row while a sweep runs
  // cannot have it removed from under them: postgres re-checks the WHERE on
  // the row it is about to delete, and an approved row no longer matches.
  //
  // `/oauth/register` needs no credential, so this is still the only bound on
  // how many rows an anonymous caller can leave behind. See
  // ../../routers/oauth/client-retention.ts for the env that sets the window.
  async pruneUnapprovedDcrClients(
    pendingOlderThanDays: number,
    rejectedOlderThanMs: number,
    now: Date = new Date(),
  ): Promise<number> {
    if (!Number.isFinite(pendingOlderThanDays) || pendingOlderThanDays <= 0) {
      return 0;
    }

    const pendingCutoff = new Date(
      now.getTime() - pendingOlderThanDays * 24 * 60 * 60 * 1000,
    );
    const rejectedCutoff = new Date(now.getTime() - rejectedOlderThanMs);

    const deleted = await db
      .delete(oauthClientsTable)
      .where(
        and(
          eq(oauthClientsTable.registration_source, "dcr"),
          or(
            and(
              eq(oauthClientsTable.approval_status, "pending"),
              lt(oauthClientsTable.created_at, pendingCutoff),
            ),
            and(
              eq(oauthClientsTable.approval_status, "rejected"),
              lt(oauthClientsTable.rejected_at, rejectedCutoff),
            ),
          ),
        ),
      )
      .returning({ client_id: oauthClientsTable.client_id });

    return deleted.length;
  }

  // ===== Authorization Codes =====

  // Codes are hashed at rest (migration 0036): the caller passes the plaintext
  // code it received, this hashes it and matches the stored digest, exactly as
  // the old exact-value lookup matched. The returned row's `code` is the hash;
  // callers that re-address the row (consume/delete) pass the plaintext again
  // and it re-hashes, so no caller ever handles the stored digest directly.
  async getAuthCode(
    code: string,
    executor: OAuthDbExecutor = db,
  ): Promise<OAuthAuthorizationCode | null> {
    const result = await executor
      .select()
      .from(oauthAuthorizationCodesTable)
      .where(eq(oauthAuthorizationCodesTable.code, hashApiKey(code)))
      .limit(1);
    return result[0] || null;
  }

  async setAuthCode(
    code: string,
    data: OAuthAuthorizationCodeCreateInput,
    executor: OAuthDbExecutor = db,
  ): Promise<void> {
    await executor.insert(oauthAuthorizationCodesTable).values({
      code: hashApiKey(code),
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
      .where(eq(oauthAuthorizationCodesTable.code, hashApiKey(code)));
  }

  // Atomic single-use consumption of an authorization code. DELETE ...
  // RETURNING in one statement is the single-use gate: `code` is the primary
  // key, so this matches at most one row, and under two concurrent redemptions
  // of the same code postgres serializes the deletes — exactly one returns the
  // row and the other returns none. The caller issues tokens only when this
  // returned true, so a read-then-delete race can no longer mint two token
  // pairs for one code. `deleteAuthCode` above stays for the cleanup deletes
  // (expired codes) where no such gate is needed.
  //
  // The authorization_code grant calls this inside the user's credential lock
  // (./oauth-user-lock) with the same `tx` that inserts the token pair, so a
  // code consumed here can never mint after users.revokeAccess committed: the
  // revoke either deleted the code first (this returns false) or runs after
  // the pair committed and deletes the pair.
  async consumeAuthCode(
    code: string,
    executor: OAuthDbExecutor = db,
  ): Promise<boolean> {
    const deleted = await executor
      .delete(oauthAuthorizationCodesTable)
      .where(eq(oauthAuthorizationCodesTable.code, hashApiKey(code)))
      .returning({ code: oauthAuthorizationCodesTable.code });

    return deleted.length === 1;
  }

  // ===== Access Tokens =====

  // Access tokens are hashed at rest (migration 0036): the caller passes the
  // plaintext bearer it received, this hashes it and matches the stored digest,
  // exactly as the old exact-value lookup matched. The returned row's
  // `access_token` is the hash; a caller holding the row (rotation) deletes it
  // through deleteAccessTokenByHash, while a caller holding the plaintext
  // (introspection, userinfo) deletes through deleteAccessToken.
  async getAccessToken(
    token: string,
    executor: OAuthDbExecutor = db,
  ): Promise<OAuthAccessToken | null> {
    const result = await executor
      .select()
      .from(oauthAccessTokensTable)
      .where(eq(oauthAccessTokensTable.access_token, hashApiKey(token)))
      .limit(1);
    return result[0] || null;
  }

  async setAccessToken(
    token: string,
    data: OAuthAccessTokenCreateInput & {
      // The refresh-token family this pair belongs to (migration 0037). The
      // caller passes a fresh id for an authorization_code grant and the
      // rotated row's id for a refresh grant, so a whole chain shares one
      // family and reuse of any rotated member can revoke it.
      family_id: string;
      // The refresh token and its expiry travel together as one optional pair,
      // not as two independent optionals. A token stored with a refresh token
      // but a NULL expiry escapes every reaper predicate in cleanupExpired and
      // is treated as valid forever by the refresh grant; bundling
      // them makes that shape unrepresentable at this write path, and migration
      // 0035's CHECK enforces the same invariant at the column level.
      refresh?: { token: string; expires_at: number };
    },
    executor: OAuthDbExecutor = db,
  ): Promise<void> {
    await executor.insert(oauthAccessTokensTable).values({
      // Hashed at rest (migration 0036); the plaintext is returned to the
      // client by the caller and never stored. last4 keeps the readable tail
      // for the admin view.
      access_token: hashApiKey(token),
      access_token_last4: apiKeyLast4(token),
      client_id: data.client_id,
      user_id: data.user_id,
      scope: data.scope,
      expires_at: new Date(data.expires_at),
      family_id: data.family_id,
      // The refresh token is hashed the same way; its expiry travels with it
      // as one pair (see migration 0035).
      refresh_token: data.refresh ? hashApiKey(data.refresh.token) : null,
      refresh_token_expires_at: data.refresh
        ? new Date(data.refresh.expires_at)
        : null,
    });
  }

  // Delete by the PLAINTEXT token (introspection revoke, userinfo expiry
  // cleanup): hashes to match the stored digest, mirroring getAccessToken.
  //
  // Returns how many rows it removed (0 or 1), so /oauth/revoke can tell a
  // revoked row from one that a concurrent refresh rotated away while the
  // revoke waited for the user lock.
  async deleteAccessToken(
    token: string,
    executor: OAuthDbExecutor = db,
  ): Promise<number> {
    const deleted = await executor
      .delete(oauthAccessTokensTable)
      .where(eq(oauthAccessTokensTable.access_token, hashApiKey(token)))
      .returning({ access_token: oauthAccessTokensTable.access_token });
    return deleted.length;
  }

  // Delete by the STORED hash, for callers that already hold the row (refresh
  // rotation reads the row by refresh token, then deletes the old access-token
  // row). Passing the row's `access_token` (already the digest) to
  // deleteAccessToken would hash it a second time and match nothing.
  async deleteAccessTokenByHash(
    accessTokenHash: string,
    executor: OAuthDbExecutor = db,
  ): Promise<void> {
    await executor
      .delete(oauthAccessTokensTable)
      .where(eq(oauthAccessTokensTable.access_token, accessTokenHash));
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
        // The token's readable tail (migration 0036), safe to show, unlike the
        // access_token digest and refresh_token, which stay out of the
        // projection entirely.
        access_token_last4: oauthAccessTokensTable.access_token_last4,
        user_email: usersTable.email,
        client_id: oauthAccessTokensTable.client_id,
        client_name: oauthClientsTable.client_name,
        // The issuing client's approval state (migration 0042), so the Access
        // view can mark a token whose client is not approved.
        client_approval_status: oauthClientsTable.approval_status,
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

  // Hashed lookup (migration 0036): the presented refresh token is hashed and
  // matched against the stored digest. The returned row's access_token is the
  // hash, so the refresh rotation deletes it via deleteAccessTokenByHash.
  async getByRefreshToken(
    refreshToken: string,
    executor: OAuthDbExecutor = db,
  ) {
    const result = await executor
      .select()
      .from(oauthAccessTokensTable)
      .where(eq(oauthAccessTokensTable.refresh_token, hashApiKey(refreshToken)))
      .limit(1);
    return result[0] || null;
  }

  // Claim a live refresh token for rotation: DELETE ... RETURNING on the
  // hashed `refresh_token` column (the live column; the rotated-marker table
  // keys `refresh_token_hash`). The DELETE is the single-use gate, the same
  // way consumeAuthCode is for codes: of two statements naming one token,
  // postgres lets exactly one remove the row, and only that caller may mint.
  // The refresh grant runs it inside the user's credential lock after
  // re-reading and validating the row, so a refusal never consumes the token
  // and the claim, the rotated marker and the new pair commit together.
  async claimRefreshToken(refreshToken: string, tx: OAuthTx) {
    return tx
      .delete(oauthAccessTokensTable)
      .where(eq(oauthAccessTokensTable.refresh_token, hashApiKey(refreshToken)))
      .returning();
  }

  // Delete the live row a refresh token belongs to (/oauth/revoke with a
  // refresh token). Returns the count for the same reason deleteAccessToken
  // does.
  async deleteByRefreshToken(
    refreshToken: string,
    executor: OAuthDbExecutor = db,
  ): Promise<number> {
    const deleted = await executor
      .delete(oauthAccessTokensTable)
      .where(eq(oauthAccessTokensTable.refresh_token, hashApiKey(refreshToken)))
      .returning({ access_token: oauthAccessTokensTable.access_token });
    return deleted.length;
  }

  // ===== Refresh-token family reuse detection (migration 0037) =====

  // Record a refresh token that has just been rotated OUT, so a later
  // presentation of it is detectable as reuse. Takes the STORED hash directly
  // (the caller holds the row from getByRefreshToken, whose refresh_token is
  // already the digest), not the plaintext — re-hashing a hash would key the
  // marker on a value no lookup can reproduce. onConflictDoNothing so a second
  // rotation of the same token (a concurrent refresh) is a no-op rather than a
  // primary-key crash. expires_at is the rotated token's own expiry, so
  // cleanupExpired reaps the marker with the family.
  async recordRotatedRefreshToken(
    data: {
      refreshTokenHash: string;
      familyId: string;
      clientId: string;
      userId: string;
      expiresAt: Date;
    },
    executor: OAuthDbExecutor = db,
  ): Promise<void> {
    await executor
      .insert(oauthRotatedRefreshTokensTable)
      .values({
        refresh_token_hash: data.refreshTokenHash,
        family_id: data.familyId,
        client_id: data.clientId,
        user_id: data.userId,
        expires_at: data.expiresAt,
      })
      .onConflictDoNothing();
  }

  // Look up a rotated-out refresh token by the PLAINTEXT presented value
  // (hashes it to match the stored digest, mirroring getByRefreshToken). A hit
  // means the presented token is not a live token but WAS rotated out of this
  // family — i.e. reuse. Returns the owning family/client/user so the refresh
  // grant can revoke and attribute it; null when the token was never issued.
  async getRotatedRefreshToken(
    refreshToken: string,
    executor: OAuthDbExecutor = db,
  ) {
    const result = await executor
      .select({
        family_id: oauthRotatedRefreshTokensTable.family_id,
        client_id: oauthRotatedRefreshTokensTable.client_id,
        user_id: oauthRotatedRefreshTokensTable.user_id,
      })
      .from(oauthRotatedRefreshTokensTable)
      .where(
        eq(
          oauthRotatedRefreshTokensTable.refresh_token_hash,
          hashApiKey(refreshToken),
        ),
      )
      .limit(1);
    return result[0] || null;
  }

  // Revoke an entire refresh-token family on reuse detection. Deletes the
  // family's LIVE access-token rows (the revocation the operator needs — every
  // token in the chain stops working) and its rotated-token markers (so a
  // replay of the stolen token after revocation takes the plain unknown-token
  // path and re-emits nothing: one reuse audit row per family compromise). The
  // live delete runs first and returns a count, so the caller can log how many
  // tokens the compromise cost. Deleting the markers is not gated on the live
  // delete because a family can be reused after its live rows already lapsed.
  //
  // Runs under the family owner's credential lock (./oauth-user-lock), so a
  // refresh of a family member that is waiting for the lock re-reads after
  // this commits, finds nothing, and cannot reinsert a pair into the revoked
  // family. A caller already holding the lock passes its `tx`; the lock is not
  // re-entrant across transactions, so opening a second one here would wait
  // on the caller forever. Without a `tx`, this opens its own transaction,
  // finds the family's owner from its live rows or markers, and locks that
  // user before deleting. A family belongs to one user: every member descends
  // from one authorization code.
  async revokeFamily(familyId: string, tx?: OAuthTx): Promise<number> {
    if (tx) {
      return this.revokeFamilyLocked(familyId, tx);
    }
    return db.transaction(async (ownTx) => {
      const owner = await this.familyOwner(familyId, ownTx);
      if (!owner) {
        return 0;
      }
      await lockOAuthUser(ownTx, owner);
      return this.revokeFamilyLocked(familyId, ownTx);
    });
  }

  private async familyOwner(
    familyId: string,
    executor: OAuthDbExecutor,
  ): Promise<string | null> {
    const [live] = await executor
      .select({ user_id: oauthAccessTokensTable.user_id })
      .from(oauthAccessTokensTable)
      .where(eq(oauthAccessTokensTable.family_id, familyId))
      .limit(1);
    if (live) return live.user_id;
    const [marker] = await executor
      .select({ user_id: oauthRotatedRefreshTokensTable.user_id })
      .from(oauthRotatedRefreshTokensTable)
      .where(eq(oauthRotatedRefreshTokensTable.family_id, familyId))
      .limit(1);
    return marker?.user_id ?? null;
  }

  private async revokeFamilyLocked(
    familyId: string,
    tx: OAuthTx,
  ): Promise<number> {
    const revoked = await tx
      .delete(oauthAccessTokensTable)
      .where(eq(oauthAccessTokensTable.family_id, familyId))
      .returning({ access_token: oauthAccessTokensTable.access_token });

    await tx
      .delete(oauthRotatedRefreshTokensTable)
      .where(eq(oauthRotatedRefreshTokensTable.family_id, familyId));

    return revoked.length;
  }

  // ===== Spent authorization codes (migration 0045) =====

  // Record a redeemed authorization code, in the SAME transaction as the token
  // pair it produced, so the tombstone exists exactly when the pair does. The
  // key is the same sha256 the live codes table uses (hashApiKey), never the
  // code. A plain insert on purpose: a conflict (the code hash is the primary
  // key, and consumeAuthCode already guaranteed single use) or a missing table
  // must fail the whole transaction loudly, so a login never succeeds without
  // its record. `tx` is required, not defaulted to the pool, so a caller cannot
  // write the record outside the transaction that issued the pair.
  async recordSpentCode(
    code: string,
    data: {
      family_id: string;
      client_id: string;
      user_id: string;
      redirect_uri: string;
      code_challenge: string;
      expires_at: Date;
    },
    tx: OAuthTx,
  ): Promise<void> {
    await tx.insert(oauthSpentAuthorizationCodesTable).values({
      code_hash: hashApiKey(code),
      family_id: data.family_id,
      client_id: data.client_id,
      user_id: data.user_id,
      redirect_uri: data.redirect_uri,
      code_challenge: data.code_challenge,
      expires_at: data.expires_at,
    });
  }

  // Look up a redeemed code by the PLAINTEXT presented value, only while its
  // record has not expired: an expired row is evidence nobody acts on, and the
  // reaper may simply not have run yet. `now` is a parameter so the expiry rule
  // is testable without a wall clock.
  async getSpentCode(
    code: string,
    executor: OAuthDbExecutor = db,
    now: Date = new Date(),
  ) {
    const result = await executor
      .select({
        family_id: oauthSpentAuthorizationCodesTable.family_id,
        client_id: oauthSpentAuthorizationCodesTable.client_id,
        user_id: oauthSpentAuthorizationCodesTable.user_id,
        redirect_uri: oauthSpentAuthorizationCodesTable.redirect_uri,
        code_challenge: oauthSpentAuthorizationCodesTable.code_challenge,
        expires_at: oauthSpentAuthorizationCodesTable.expires_at,
      })
      .from(oauthSpentAuthorizationCodesTable)
      .where(
        and(
          eq(oauthSpentAuthorizationCodesTable.code_hash, hashApiKey(code)),
          gte(oauthSpentAuthorizationCodesTable.expires_at, now),
        ),
      )
      .limit(1);
    return result[0] || null;
  }

  // The gate that makes exactly one replay act: DELETE ... RETURNING on the
  // primary key, the same shape as consumeAuthCode. Of two concurrent replays
  // exactly one gets the row back; the other (and every later replay) gets null
  // and does nothing, so one compromised code produces one audit row. Also
  // refuses an expired row, so the expiry rule cannot be bypassed by going
  // straight to the consume. Takes the caller's `tx` (the replay revoke runs
  // under the owner's credential lock and must not open a second transaction).
  async consumeSpentCode(code: string, tx: OAuthTx, now: Date = new Date()) {
    const deleted = await tx
      .delete(oauthSpentAuthorizationCodesTable)
      .where(
        and(
          eq(oauthSpentAuthorizationCodesTable.code_hash, hashApiKey(code)),
          gte(oauthSpentAuthorizationCodesTable.expires_at, now),
        ),
      )
      .returning({
        family_id: oauthSpentAuthorizationCodesTable.family_id,
        client_id: oauthSpentAuthorizationCodesTable.client_id,
        user_id: oauthSpentAuthorizationCodesTable.user_id,
      });
    return deleted[0] || null;
  }

  // How many rows revokeFamily would delete for this family right now: every
  // access-token row carrying the family id, the same set revokeFamilyLocked
  // removes. The replay handler reads it under the owner's credential lock
  // before revoking, so the audit row states what was actually live and a
  // replay after users.revokeAccess (which deletes the family's rows but leaves
  // the tombstone) is recorded as having revoked nothing.
  async countFamilyAccessTokens(
    familyId: string,
    executor: OAuthDbExecutor = db,
  ): Promise<number> {
    const [row] = await executor
      .select({ n: sql<number>`count(*)::int` })
      .from(oauthAccessTokensTable)
      .where(eq(oauthAccessTokensTable.family_id, familyId));
    return row?.n ?? 0;
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
      // Rotated-out refresh-token markers (migration 0037) expire WITH the
      // family: expires_at is the rotated token's own expiry, so a marker for a
      // family that was never reused dissolves here on its own. A family that IS
      // reused is collapsed at detection time by revokeFamily instead.
      db
        .delete(oauthRotatedRefreshTokensTable)
        .where(lt(oauthRotatedRefreshTokensTable.expires_at, now)),
      // `off` also bypasses this table in the periodic sweep: it is the full
      // rollback when the table is missing or broken. Existing records are
      // reaped once the feature is enabled again. Every other value keeps the
      // sweep, matching the token endpoint's fallback to `log`.
      ...(process.env.OAUTH_CODE_REPLAY?.trim().toLowerCase() === "off"
        ? []
        : [
            db
              .delete(oauthSpentAuthorizationCodesTable)
              .where(lt(oauthSpentAuthorizationCodesTable.expires_at, now)),
          ]),
    ]);
  }
}

export const oauthRepository = new OAuthRepository();
