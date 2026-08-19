import { ApiKeyCreateInput, ApiKeyUpdateInput } from "@repo/zod-types";
import { and, desc, eq, isNull, or } from "drizzle-orm";
import { alias } from "drizzle-orm/pg-core";
import { customAlphabet } from "nanoid";

import { apiKeyLast4, hashApiKey } from "@/lib/api-key-hash";
import logger from "@/utils/logger";

import { db } from "../index";
import { apiKeysTable, usersTable } from "../schema";
import { shouldTouchLastUsed } from "./api-keys.last-used";

const nanoid = customAlphabet(
  "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
  64,
);

export class ApiKeysRepository {
  /**
   * Generate a new API key with the specified format: sk_mt_{64-char-nanoid}
   */
  private generateApiKey(): string {
    const keyPart = nanoid();
    const key = `sk_mt_${keyPart}`;

    return key;
  }

  async create(input: ApiKeyCreateInput): Promise<{
    uuid: string;
    name: string;
    key: string;
    user_id: string | null;
    endpoint_uuid: string | null;
    acts_as_user_id: string | null;
    created_at: Date;
  }> {
    const key = this.generateApiKey();

    const [createdApiKey] = await db
      .insert(apiKeysTable)
      .values({
        name: input.name,
        // Only the hash and the display tail are persisted (migration 0034);
        // the plaintext lives in this local variable and is handed back once,
        // below. There is no second chance to read it — if the caller loses
        // it, the key must be re-minted.
        key_hash: hashApiKey(key),
        last4: apiKeyLast4(key),
        user_id: input.user_id,
        // NULL = unscoped (legacy gateway-wide). The tRPC create path makes
        // NULL an explicit admin choice (all_endpoints: true) — see
        // api-keys.impl.ts; the repository just persists what it's given.
        endpoint_uuid: input.endpoint_uuid ?? null,
        // NULL = no acts-as identity (fail-closed m365 injection). The tRPC
        // create path enforces the admin-only + requires-endpoint-scope
        // policy; the repository just persists what it's given.
        acts_as_user_id: input.acts_as_user_id ?? null,
        is_active: input.is_active ?? true,
      })
      .returning({
        uuid: apiKeysTable.uuid,
        name: apiKeysTable.name,
        user_id: apiKeysTable.user_id,
        endpoint_uuid: apiKeysTable.endpoint_uuid,
        acts_as_user_id: apiKeysTable.acts_as_user_id,
        created_at: apiKeysTable.created_at,
      });

    if (!createdApiKey) {
      throw new Error("Failed to create API key");
    }

    return {
      ...createdApiKey,
      key, // Return the actual key
    };
  }

  // Find all API keys (both public and user-owned). Admin-only surface. LEFT
  // JOIN users so the caller gets each key's owner email (NULL for a public /
  // 'everyone' key) without an N+1 lookup, plus last_used_at for the admin
  // view. `last4` is the display tail the serializer renders as key_prefix;
  // no column here can reconstruct a usable credential (migration 0034).
  async findAll() {
    // Second users join, aliased: acts_as_user_id → the acted-as user's
    // email, so the admin view can label an identity-bound key with WHO it
    // acts as (NULL when unbound or the user row is gone mid-cascade).
    const actsAsUsers = alias(usersTable, "acts_as_users");
    return await db
      .select({
        uuid: apiKeysTable.uuid,
        name: apiKeysTable.name,
        last4: apiKeysTable.last4,
        created_at: apiKeysTable.created_at,
        last_used_at: apiKeysTable.last_used_at,
        is_active: apiKeysTable.is_active,
        user_id: apiKeysTable.user_id,
        endpoint_uuid: apiKeysTable.endpoint_uuid,
        acts_as_user_id: apiKeysTable.acts_as_user_id,
        acts_as_email: actsAsUsers.email,
        owner_email: usersTable.email,
      })
      .from(apiKeysTable)
      .leftJoin(usersTable, eq(apiKeysTable.user_id, usersTable.id))
      .leftJoin(actsAsUsers, eq(apiKeysTable.acts_as_user_id, actsAsUsers.id))
      .orderBy(desc(apiKeysTable.created_at));
  }

  // Find API keys accessible to a specific user (public + user's own keys)
  async findAccessibleToUser(userId: string) {
    return await db
      .select({
        uuid: apiKeysTable.uuid,
        name: apiKeysTable.name,
        last4: apiKeysTable.last4,
        created_at: apiKeysTable.created_at,
        is_active: apiKeysTable.is_active,
        user_id: apiKeysTable.user_id,
        endpoint_uuid: apiKeysTable.endpoint_uuid,
        acts_as_user_id: apiKeysTable.acts_as_user_id,
      })
      .from(apiKeysTable)
      .where(
        or(
          isNull(apiKeysTable.user_id), // Public API keys
          eq(apiKeysTable.user_id, userId), // User's own API keys
        ),
      )
      .orderBy(desc(apiKeysTable.created_at));
  }

  async validateApiKey(key: string): Promise<{
    valid: boolean;
    user_id?: string | null;
    key_uuid?: string;
    endpoint_uuid?: string | null;
    acts_as_user_id?: string | null;
  }> {
    const [apiKey] = await db
      .select({
        uuid: apiKeysTable.uuid,
        user_id: apiKeysTable.user_id,
        endpoint_uuid: apiKeysTable.endpoint_uuid,
        acts_as_user_id: apiKeysTable.acts_as_user_id,
        is_active: apiKeysTable.is_active,
        last_used_at: apiKeysTable.last_used_at,
      })
      .from(apiKeysTable)
      // Hash-for-hash comparison (migration 0034): the presented value is
      // hashed here and matched against the stored digest, because the key
      // itself is no longer in the table. The presented string is hashed
      // EXACTLY as it arrived — no trimming, no case folding — so the set of
      // credentials that authenticate is byte-for-byte the set the old
      // `WHERE key = $1` accepted. Callers differ on whitespace handling
      // (the middleware passes the header raw, the OAuth introspection route
      // trims it) and that asymmetry is theirs to own; normalising it here
      // would silently change which padded credentials are accepted.
      .where(eq(apiKeysTable.key_hash, hashApiKey(key)));

    if (!apiKey) {
      return { valid: false };
    }

    // Check if key is active
    if (!apiKey.is_active) {
      return { valid: false };
    }

    // Throttled, fire-and-forget last-used stamp. This is the hot auth path
    // for every public-endpoint request (n8n / Claude / other clients), so the
    // write is (a) throttled to the 15-min window in api-keys.last-used.ts and
    // (b) never awaited and never allowed to reject — a telemetry write must
    // not add latency to, or fail, request authentication.
    if (shouldTouchLastUsed(apiKey.last_used_at, Date.now())) {
      void this.touchLastUsedAt(apiKey.uuid);
    }

    return {
      valid: true,
      user_id: apiKey.user_id,
      key_uuid: apiKey.uuid,
      // Scope binding for checkApiKeyAccess: non-NULL = the ONE endpoint
      // this key may reach; NULL = legacy/unscoped (grandfathered).
      endpoint_uuid: apiKey.endpoint_uuid,
      // Acts-as identity for the streamable-http m365 context gate:
      // non-NULL = the admin-bound better-auth user this key's requests run
      // delegated m365 calls as; NULL = no identity (injection fail-closes).
      acts_as_user_id: apiKey.acts_as_user_id,
    };
  }

  // Fire-and-forget helper for validateApiKey. Self-contained try/catch so it
  // can never reject the caller: a failed last_used_at write is cosmetic (the
  // admin view shows a slightly stale timestamp) whereas propagating it would
  // fail request auth. The swallow is logged, not silent, so it stays
  // observable.
  private async touchLastUsedAt(uuid: string): Promise<void> {
    try {
      await db
        .update(apiKeysTable)
        .set({ last_used_at: new Date() })
        .where(eq(apiKeysTable.uuid, uuid));
    } catch (error) {
      logger.debug(
        "Failed to update api_keys.last_used_at (non-fatal):",
        error,
      );
    }
  }

  // Member-scoped update: uuid AND owned-by-this-user ONLY. Deliberately does
  // NOT match public (user_id IS NULL) keys — a member who lists public keys
  // has their UUIDs, and an `or(eq(user_id, userId), isNull(user_id))` WHERE
  // here would let any member deactivate or rename a key every other
  // consumer depends on. Public keys can only be mutated through
  // updateAsAdmin. A member's attempt against a public (or another user's)
  // uuid matches zero rows and falls into the same not-found path as any
  // other uuid that doesn't belong to them.
  async update(uuid: string, userId: string, input: ApiKeyUpdateInput) {
    const [updatedApiKey] = await db
      .update(apiKeysTable)
      .set({
        ...(input.name && { name: input.name }),
        ...(input.is_active !== undefined && { is_active: input.is_active }),
      })
      .where(and(eq(apiKeysTable.uuid, uuid), eq(apiKeysTable.user_id, userId)))
      .returning({
        uuid: apiKeysTable.uuid,
        name: apiKeysTable.name,
        // Read back solely so ApiKeysSerializer.serializeApiKey can render the
        // key_prefix from it. Since migration 0034 this is the stored display
        // tail rather than a slice of the secret, so the readback carries no
        // credential material at all. Kept here rather than formatted in SQL
        // so the ONE display rule stays in the serializer, where the list
        // surfaces share it — a second copy in a `.returning()` is exactly the
        // drift that rule exists to prevent.
        last4: apiKeysTable.last4,
        created_at: apiKeysTable.created_at,
        is_active: apiKeysTable.is_active,
      });

    if (!updatedApiKey) {
      throw new Error("Failed to update API key or API key not found");
    }

    return updatedApiKey;
  }

  // Member-scoped delete: uuid AND owned-by-this-user ONLY. Same reasoning as
  // update() above — a public key is not deletable through this path, only
  // through deleteAsAdmin. Without this, any member could DELETE a key every
  // other consumer (n8n/Claude/other clients) authenticates with, using a uuid they
  // can read off their own `list` query.
  async delete(uuid: string, userId: string) {
    const [deletedApiKey] = await db
      .delete(apiKeysTable)
      .where(and(eq(apiKeysTable.uuid, uuid), eq(apiKeysTable.user_id, userId)))
      .returning({
        uuid: apiKeysTable.uuid,
        name: apiKeysTable.name,
      });

    if (!deletedApiKey) {
      throw new Error("Failed to delete API key or API key not found");
    }

    return deletedApiKey;
  }

  // Admin bypass of the ownership WHERE: an admin may rename / activate /
  // deactivate ANY key by uuid, including public keys and other users'
  // private keys. Members go through update(), which is scoped to their OWN
  // keys only — a public key can be mutated exclusively through this method.
  async updateAsAdmin(uuid: string, input: ApiKeyUpdateInput) {
    const [updatedApiKey] = await db
      .update(apiKeysTable)
      .set({
        ...(input.name && { name: input.name }),
        ...(input.is_active !== undefined && { is_active: input.is_active }),
      })
      .where(eq(apiKeysTable.uuid, uuid))
      .returning({
        uuid: apiKeysTable.uuid,
        name: apiKeysTable.name,
        // Display tail only, same reasoning as update() above — consumed by
        // the serializer and never a credential in the first place.
        last4: apiKeysTable.last4,
        created_at: apiKeysTable.created_at,
        is_active: apiKeysTable.is_active,
      });

    if (!updatedApiKey) {
      throw new Error("Failed to update API key or API key not found");
    }

    return updatedApiKey;
  }

  // Admin bypass of the ownership WHERE: an admin may delete / revoke ANY key
  // by uuid, including public keys. Members go through delete(), which is
  // scoped to their OWN keys only — a public key can be deleted exclusively
  // through this method.
  async deleteAsAdmin(uuid: string) {
    const [deletedApiKey] = await db
      .delete(apiKeysTable)
      .where(eq(apiKeysTable.uuid, uuid))
      .returning({
        uuid: apiKeysTable.uuid,
        name: apiKeysTable.name,
      });

    if (!deletedApiKey) {
      throw new Error("Failed to delete API key or API key not found");
    }

    return deletedApiKey;
  }
}
