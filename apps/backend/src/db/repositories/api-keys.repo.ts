import { ApiKeyCreateInput, ApiKeyUpdateInput } from "@repo/zod-types";
import { and, desc, eq, isNull, or } from "drizzle-orm";
import { customAlphabet } from "nanoid";

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
    created_at: Date;
  }> {
    const key = this.generateApiKey();

    const [createdApiKey] = await db
      .insert(apiKeysTable)
      .values({
        name: input.name,
        key: key,
        user_id: input.user_id,
        is_active: input.is_active ?? true,
      })
      .returning({
        uuid: apiKeysTable.uuid,
        name: apiKeysTable.name,
        user_id: apiKeysTable.user_id,
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

  async findByUserId(userId: string) {
    return await db
      .select({
        uuid: apiKeysTable.uuid,
        name: apiKeysTable.name,
        key: apiKeysTable.key,
        created_at: apiKeysTable.created_at,
        is_active: apiKeysTable.is_active,
      })
      .from(apiKeysTable)
      .where(eq(apiKeysTable.user_id, userId))
      .orderBy(desc(apiKeysTable.created_at));
  }

  // Find all API keys (both public and user-owned). Admin-only surface. LEFT
  // JOIN users so the caller gets each key's owner email (NULL for a public /
  // 'everyone' key) without an N+1 lookup, plus last_used_at for the admin
  // view. The full `key` is selected only so the serializer can derive a
  // non-reversible prefix — the raw secret is dropped at the serializer
  // boundary (serializeAdminApiKeyList) and never leaves the admin API.
  async findAll() {
    return await db
      .select({
        uuid: apiKeysTable.uuid,
        name: apiKeysTable.name,
        key: apiKeysTable.key,
        created_at: apiKeysTable.created_at,
        last_used_at: apiKeysTable.last_used_at,
        is_active: apiKeysTable.is_active,
        user_id: apiKeysTable.user_id,
        owner_email: usersTable.email,
      })
      .from(apiKeysTable)
      .leftJoin(usersTable, eq(apiKeysTable.user_id, usersTable.id))
      .orderBy(desc(apiKeysTable.created_at));
  }

  // Find public API keys (no user ownership)
  async findPublicApiKeys() {
    return await db
      .select({
        uuid: apiKeysTable.uuid,
        name: apiKeysTable.name,
        key: apiKeysTable.key,
        created_at: apiKeysTable.created_at,
        is_active: apiKeysTable.is_active,
        user_id: apiKeysTable.user_id,
      })
      .from(apiKeysTable)
      .where(isNull(apiKeysTable.user_id))
      .orderBy(desc(apiKeysTable.created_at));
  }

  // Find API keys accessible to a specific user (public + user's own keys)
  async findAccessibleToUser(userId: string) {
    return await db
      .select({
        uuid: apiKeysTable.uuid,
        name: apiKeysTable.name,
        key: apiKeysTable.key,
        created_at: apiKeysTable.created_at,
        is_active: apiKeysTable.is_active,
        user_id: apiKeysTable.user_id,
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

  async findByUuid(uuid: string, userId: string) {
    const [apiKey] = await db
      .select({
        uuid: apiKeysTable.uuid,
        name: apiKeysTable.name,
        key: apiKeysTable.key,
        created_at: apiKeysTable.created_at,
        is_active: apiKeysTable.is_active,
        user_id: apiKeysTable.user_id,
      })
      .from(apiKeysTable)
      .where(
        and(eq(apiKeysTable.uuid, uuid), eq(apiKeysTable.user_id, userId)),
      );

    return apiKey;
  }

  // Find API key by UUID with access control (user can access their own keys + public keys)
  async findByUuidWithAccess(uuid: string, userId?: string) {
    const [apiKey] = await db
      .select({
        uuid: apiKeysTable.uuid,
        name: apiKeysTable.name,
        key: apiKeysTable.key,
        created_at: apiKeysTable.created_at,
        is_active: apiKeysTable.is_active,
        user_id: apiKeysTable.user_id,
      })
      .from(apiKeysTable)
      .where(
        and(
          eq(apiKeysTable.uuid, uuid),
          userId
            ? or(
                isNull(apiKeysTable.user_id), // Public API keys
                eq(apiKeysTable.user_id, userId), // User's own API keys
              )
            : isNull(apiKeysTable.user_id), // Only public if no user context
        ),
      );

    return apiKey;
  }

  async validateApiKey(key: string): Promise<{
    valid: boolean;
    user_id?: string | null;
    key_uuid?: string;
  }> {
    const [apiKey] = await db
      .select({
        uuid: apiKeysTable.uuid,
        user_id: apiKeysTable.user_id,
        is_active: apiKeysTable.is_active,
        last_used_at: apiKeysTable.last_used_at,
      })
      .from(apiKeysTable)
      .where(eq(apiKeysTable.key, key));

    if (!apiKey) {
      return { valid: false };
    }

    // Check if key is active
    if (!apiKey.is_active) {
      return { valid: false };
    }

    // Throttled, fire-and-forget last-used stamp. This is the hot auth path
    // for every public-endpoint request (Tara / n8n / Claude clients), so the
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
        key: apiKeysTable.key,
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
  // other consumer (Tara/n8n/Claude) authenticates with, using a uuid they
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
        key: apiKeysTable.key,
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
