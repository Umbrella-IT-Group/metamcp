import {
  CreateApiKeyRequestSchema,
  CreateApiKeyResponseSchema,
  DeleteApiKeyRequestSchema,
  DeleteApiKeyResponseSchema,
  ListAllApiKeysResponseSchema,
  ListApiKeysResponseSchema,
  UpdateApiKeyRequestSchema,
  UpdateApiKeyResponseSchema,
  ValidateApiKeyRequestSchema,
  ValidateApiKeyResponseSchema,
} from "@repo/zod-types";
import { TRPCError } from "@trpc/server";
import { z } from "zod";

import logger from "@/utils/logger";

import { ApiKeysRepository } from "../db/repositories";
import { ApiKeysSerializer } from "../db/serializers";

const apiKeysRepository = new ApiKeysRepository();

export const apiKeysImplementations = {
  create: async (
    input: z.infer<typeof CreateApiKeyRequestSchema>,
    userId: string,
    isAdmin: boolean,
  ): Promise<z.infer<typeof CreateApiKeyResponseSchema>> => {
    // RBAC on the mint path. `input.user_id === null` is the public
    // ('everyone') selection; `undefined` means "private to me". A member may
    // only mint keys owned by themselves — they cannot create a public key,
    // and they cannot assign a key to another user's id (ownership spoofing).
    // Both throw FORBIDDEN before any write. An admin may mint either.
    if (!isAdmin) {
      if (input.user_id === null) {
        throw new TRPCError({
          code: "FORBIDDEN",
          message:
            "Only administrators can create keys for everyone (public keys).",
        });
      }
      if (input.user_id !== undefined && input.user_id !== userId) {
        throw new TRPCError({
          code: "FORBIDDEN",
          message: "You can only create API keys owned by yourself.",
        });
      }
    }

    try {
      // Use input.user_id if provided, otherwise default to current user (private)
      const apiKeyUserId = input.user_id !== undefined ? input.user_id : userId;

      const result = await apiKeysRepository.create({
        name: input.name,
        user_id: apiKeyUserId,
        is_active: true,
      });

      return ApiKeysSerializer.serializeCreateApiKeyResponse(result);
    } catch (error) {
      // Preserve an intentional authorization error's code; only wrap the
      // unexpected ones.
      if (error instanceof TRPCError) {
        throw error;
      }
      logger.error("Error creating API key:", error);
      throw new Error(
        error instanceof Error ? error.message : "Internal server error",
      );
    }
  },

  // Deliberate: this member-facing list returns the FULL key value for
  // public ('everyone') keys, not just a prefix. That is the intended
  // "copy the shared key to configure your client" feature — a public key
  // exists to be handed to every consumer (Tara/n8n/Claude) in the first
  // place, so masking it here would only make the UI less useful without
  // reducing exposure (the secret is already distributed). This does NOT
  // apply to the admin cross-user view (listAll, below) — that one stays
  // prefix-masked because it also surfaces every user's PRIVATE keys, which
  // must never be reconstructable from an admin listing.
  list: async (
    userId: string,
  ): Promise<z.infer<typeof ListApiKeysResponseSchema>> => {
    try {
      const apiKeys = await apiKeysRepository.findAccessibleToUser(userId);

      return {
        apiKeys: ApiKeysSerializer.serializeApiKeyList(apiKeys),
      };
    } catch (error) {
      logger.error("Error fetching API keys:", error);
      throw new Error("Failed to fetch API keys");
    }
  },

  // Admin-only cross-user listing (gated by adminProcedure at the router). No
  // owner filter — returns every key with owner email + last_used_at, minus
  // the full secret (see serializeAdminApiKeyList).
  listAll: async (): Promise<z.infer<typeof ListAllApiKeysResponseSchema>> => {
    try {
      const apiKeys = await apiKeysRepository.findAll();

      return {
        apiKeys: ApiKeysSerializer.serializeAdminApiKeyList(apiKeys),
      };
    } catch (error) {
      logger.error("Error fetching all API keys:", error);
      throw new Error("Failed to fetch API keys");
    }
  },

  update: async (
    input: z.infer<typeof UpdateApiKeyRequestSchema>,
    userId: string,
    isAdmin: boolean,
  ): Promise<z.infer<typeof UpdateApiKeyResponseSchema>> => {
    try {
      // Admins bypass the ownership WHERE (may edit / revoke any key); members
      // stay owner-scoped.
      const result = isAdmin
        ? await apiKeysRepository.updateAsAdmin(input.uuid, {
            name: input.name,
            is_active: input.is_active,
          })
        : await apiKeysRepository.update(input.uuid, userId, {
            name: input.name,
            is_active: input.is_active,
          });

      return ApiKeysSerializer.serializeApiKey(result);
    } catch (error) {
      logger.error("Error updating API key:", error);
      throw new Error(
        error instanceof Error ? error.message : "Internal server error",
      );
    }
  },

  delete: async (
    input: z.infer<typeof DeleteApiKeyRequestSchema>,
    userId: string,
    isAdmin: boolean,
  ): Promise<z.infer<typeof DeleteApiKeyResponseSchema>> => {
    try {
      // Admins bypass the ownership WHERE (may delete / revoke any key);
      // members stay owner-scoped.
      if (isAdmin) {
        await apiKeysRepository.deleteAsAdmin(input.uuid);
      } else {
        await apiKeysRepository.delete(input.uuid, userId);
      }

      return {
        success: true,
        message: "API key deleted successfully",
      };
    } catch (error) {
      logger.error("Error deleting API key:", error);
      return {
        success: false,
        message:
          error instanceof Error ? error.message : "Internal server error",
      };
    }
  },

  validate: async (
    input: z.infer<typeof ValidateApiKeyRequestSchema>,
  ): Promise<z.infer<typeof ValidateApiKeyResponseSchema>> => {
    try {
      const result = await apiKeysRepository.validateApiKey(input.key);
      return {
        valid: result.valid,
        user_id: result.user_id ?? undefined,
        key_uuid: result.key_uuid,
      };
    } catch (error) {
      logger.error("Error validating API key:", error);
      return { valid: false };
    }
  },
};
