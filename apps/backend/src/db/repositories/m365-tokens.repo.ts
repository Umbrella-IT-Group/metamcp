/**
 * Persistence layer for the M365 delegated-token broker
 * (`m365_user_tokens`). One row per enrolled gateway user; the
 * refresh token is stored as an AES-256-GCM envelope produced by
 * `lib/m365/crypto.ts` — this repository never sees plaintext tokens.
 *
 * The mint service's rotate-and-persist path calls `rotateRefreshToken`
 * IMMEDIATELY after a successful refresh grant (Entra invalidates the
 * old RT on redemption, so losing the new one strands the user into
 * re-enrollment). Callers serialize per-user via the mint service's
 * single-flight lock; there is no cross-process contention in the
 * single-container deployment (documented multi-instance follow-up:
 * advisory lock).
 */
import { eq } from "drizzle-orm";

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

  /** Atomic rotate-and-persist after a successful refresh grant. */
  async rotateRefreshToken(
    userId: string,
    rtCiphertext: string,
    kekId: string,
  ): Promise<boolean> {
    const rows = await db
      .update(m365UserTokensTable)
      .set({
        rt_ciphertext: rtCiphertext,
        kek_id: kekId,
        status: "active",
        rotated_at: new Date(),
        last_used_at: new Date(),
      })
      .where(eq(m365UserTokensTable.user_id, userId))
      .returning({ uuid: m365UserTokensTable.uuid });
    return rows.length > 0;
  }

  /** Mark a grant as needing interactive re-auth (refresh rejected). */
  async markReauthRequired(userId: string): Promise<void> {
    await db
      .update(m365UserTokensTable)
      .set({ status: "reauth_required" })
      .where(eq(m365UserTokensTable.user_id, userId));
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
