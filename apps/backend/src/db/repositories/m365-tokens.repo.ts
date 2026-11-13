/**
 * Persistence layer for the M365 delegated-token broker
 * (`m365_user_tokens`). One row per enrolled gateway user; the
 * refresh token is stored as an AES-256-GCM envelope produced by
 * `lib/m365/crypto.ts` — this repository never sees plaintext tokens.
 *
 * The mint service's rotate-and-persist path calls `rotateRefreshToken`
 * immediately after a successful refresh grant to preserve the newest issued
 * token. Entra does not revoke the old token merely because it was redeemed
 * (see the protocol note in `lib/m365/mint-service.ts`). Callers serialize
 * per-user via the mint service's
 * single-flight lock, which is in-process only: the deployment runs exactly
 * one gateway process per database (see the single-flight note in
 * `lib/m365/mint-service.ts`; more than one replica reopens a documented
 * advisory-lock follow-up). Within that process every write that follows a
 * read is a compare-and-swap on the ciphertext that was read, so an
 * enrollment, a disconnect, a revoke or a boot rewrap that lands while a mint
 * is in flight wins instead of being overwritten.
 */
import { and, eq } from "drizzle-orm";

import { db } from "../index";
import { m365UserTokensTable } from "../schema";

export interface M365UserTokenRow {
  uuid: string;
  user_id: string;
  entra_oid: string;
  tenant_id: string;
  entra_upn: string | null;
  rt_ciphertext: string;
  kek_id: string;
  scopes_granted: string;
  status: string;
  created_at: Date;
  rotated_at: Date | null;
  last_used_at: Date | null;
}

export interface UpsertM365EnrollmentInput {
  user_id: string;
  entra_oid: string;
  tenant_id: string;
  entra_upn?: string;
  rt_ciphertext: string;
  kek_id: string;
  scopes_granted: string;
}

export class M365TokensRepository {
  async findByUserId(userId: string): Promise<M365UserTokenRow | undefined> {
    const [row] = await db
      .select()
      .from(m365UserTokensTable)
      .where(eq(m365UserTokensTable.user_id, userId))
      .limit(1);
    return row as M365UserTokenRow | undefined;
  }

  /**
   * Enrollment (and re-enrollment) both land here: a fresh interactive
   * auth-code exchange replaces whatever grant state existed before and
   * resets `status` to active.
   */
  async upsertEnrollment(
    input: UpsertM365EnrollmentInput,
  ): Promise<M365UserTokenRow> {
    const [row] = await db
      .insert(m365UserTokensTable)
      .values({
        user_id: input.user_id,
        entra_oid: input.entra_oid,
        tenant_id: input.tenant_id,
        entra_upn: input.entra_upn ?? null,
        rt_ciphertext: input.rt_ciphertext,
        kek_id: input.kek_id,
        scopes_granted: input.scopes_granted,
        status: "active",
        rotated_at: new Date(),
      })
      .onConflictDoUpdate({
        target: m365UserTokensTable.user_id,
        set: {
          entra_oid: input.entra_oid,
          tenant_id: input.tenant_id,
          entra_upn: input.entra_upn ?? null,
          rt_ciphertext: input.rt_ciphertext,
          kek_id: input.kek_id,
          scopes_granted: input.scopes_granted,
          status: "active",
          rotated_at: new Date(),
        },
      })
      .returning();
    return row as M365UserTokenRow;
  }

  /**
   * Compare-and-swap rotate-and-persist after a successful refresh grant.
   *
   * The write applies only while the row still holds the ciphertext the mint
   * READ (`expectedCiphertext`) and is still `active`, in ONE statement. The
   * ciphertext is both the generation of the grant and the version of its
   * rotation: a re-enrollment, a disconnect-and-reconnect, another writer's
   * rotation or a rewrap all change it, so a mint that was in flight across any
   * of them can no longer overwrite the newer state. Postgres re-evaluates the
   * WHERE clause against the committed row when a concurrent update commits
   * (Read Committed), so two rotations built from one read cannot both apply.
   *
   * `status` is deliberately NOT in the SET. A rotation used to write
   * `status = 'active'`, which silently reactivated a row an operator, or
   * `usersRepository.revokeAccess`, had set to `reauth_required` while the mint
   * was in flight. The `status = 'active'` predicate makes that revoke win
   * instead, and only `upsertEnrollment` (an interactive sign-in) reactivates.
   *
   * Returns false when nothing matched. That is a DEFINITE answer, not an
   * error: the caller reconciles against a fresh read rather than retrying.
   */
  async rotateRefreshToken(
    userId: string,
    rtCiphertext: string,
    kekId: string,
    expectedCiphertext: string,
  ): Promise<boolean> {
    const rows = await db
      .update(m365UserTokensTable)
      .set({
        rt_ciphertext: rtCiphertext,
        kek_id: kekId,
        rotated_at: new Date(),
        last_used_at: new Date(),
      })
      .where(
        and(
          eq(m365UserTokensTable.user_id, userId),
          eq(m365UserTokensTable.rt_ciphertext, expectedCiphertext),
          eq(m365UserTokensTable.status, "active"),
        ),
      )
      .returning({ uuid: m365UserTokensTable.uuid });
    return rows.length > 0;
  }

  /**
   * Mark a grant as needing interactive re-auth (refresh rejected), but only
   * while the row still holds the ciphertext whose redemption was rejected. A
   * rejection that arrives after a re-enrollment concerns the OLD grant and
   * must not mark the fresh one.
   */
  async markReauthRequired(
    userId: string,
    expectedCiphertext: string,
  ): Promise<void> {
    await db
      .update(m365UserTokensTable)
      .set({ status: "reauth_required" })
      .where(
        and(
          eq(m365UserTokensTable.user_id, userId),
          eq(m365UserTokensTable.rt_ciphertext, expectedCiphertext),
        ),
      );
  }

  /**
   * Every row's owner and envelope, in any status, for the boot converge. Two
   * columns only: nothing else about a row is needed to rewrap it.
   */
  async listEnvelopes(): Promise<{ user_id: string; rt_ciphertext: string }[]> {
    return await db
      .select({
        user_id: m365UserTokensTable.user_id,
        rt_ciphertext: m365UserTokensTable.rt_ciphertext,
      })
      .from(m365UserTokensTable);
  }

  /**
   * Replace a row's envelope with a re-sealed copy of the SAME refresh token,
   * only while it still holds `expectedCiphertext`. Touches neither `status`,
   * `rotated_at` nor `last_used_at`: a rewrap is not a rotation, and the row's
   * lifecycle (including a `reauth_required` mark) is not this method's to
   * change. False means the row moved on; the converge counts it and leaves it.
   */
  async replaceCiphertextIfUnchanged(
    userId: string,
    expectedCiphertext: string,
    nextCiphertext: string,
    kekId: string,
  ): Promise<boolean> {
    const rows = await db
      .update(m365UserTokensTable)
      .set({ rt_ciphertext: nextCiphertext, kek_id: kekId })
      .where(
        and(
          eq(m365UserTokensTable.user_id, userId),
          eq(m365UserTokensTable.rt_ciphertext, expectedCiphertext),
        ),
      )
      .returning({ uuid: m365UserTokensTable.uuid });
    return rows.length > 0;
  }

  async touchLastUsed(userId: string): Promise<void> {
    await db
      .update(m365UserTokensTable)
      .set({ last_used_at: new Date() })
      .where(eq(m365UserTokensTable.user_id, userId));
  }

  /** `/m365/disconnect` — the user-side revocation surface. */
  async deleteByUserId(userId: string): Promise<boolean> {
    const rows = await db
      .delete(m365UserTokensTable)
      .where(eq(m365UserTokensTable.user_id, userId))
      .returning({ uuid: m365UserTokensTable.uuid });
    return rows.length > 0;
  }
}

export const m365TokensRepository = new M365TokensRepository();
