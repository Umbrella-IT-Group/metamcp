import type { AuditActor } from "@repo/trpc";
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

import {
  ApiKeysRepository,
  endpointsRepository,
  usersRepository,
} from "../db/repositories";
import { ApiKeysSerializer } from "../db/serializers";
import { emitAdminEvent } from "../lib/audit/admin-event";

const apiKeysRepository = new ApiKeysRepository();

export const apiKeysImplementations = {
  create: async (
    input: z.infer<typeof CreateApiKeyRequestSchema>,
    userId: string,
    isAdmin: boolean,
    actor?: AuditActor,
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
      // Scope selection is admin-only, same FORBIDDEN-before-write style: a
      // member may neither bind a key to an endpoint nor mint a gateway-wide
      // (all_endpoints) key. Combined with the explicit-scope requirement
      // below, key minting is effectively an administrator operation.
      if (
        input.endpoint_uuid !== undefined ||
        input.all_endpoints !== undefined
      ) {
        throw new TRPCError({
          code: "FORBIDDEN",
          message:
            "Only administrators can set an API key's endpoint scope (endpoint_uuid / all_endpoints).",
        });
      }
      // Acts-as identity binding (migration 0024) is admin-only, same
      // FORBIDDEN-before-write style: a member must never mint a key that
      // exercises anyone's delegated m365 identity — least of all another
      // user's.
      if (input.acts_as_user_id !== undefined) {
        throw new TRPCError({
          code: "FORBIDDEN",
          message:
            "Only administrators can bind an API key to an acts-as identity (acts_as_user_id).",
        });
      }
    }

    // Explicit-scope gate (mirrors the zod superRefine so the invariant holds
    // even for callers that bypass the tRPC input schema): a new key must
    // either name the ONE endpoint it may reach, or deliberately opt into
    // gateway-wide reach with all_endpoints: true (stored as NULL scope).
    // Silently defaulting to global is impossible.
    if (input.endpoint_uuid && input.all_endpoints === true) {
      throw new TRPCError({
        code: "BAD_REQUEST",
        message:
          "Pass either endpoint_uuid or all_endpoints: true, not both — a key is scoped to one endpoint or explicitly global.",
      });
    }
    if (!input.endpoint_uuid && input.all_endpoints !== true) {
      throw new TRPCError({
        code: "BAD_REQUEST",
        message:
          "An API key must be scoped to an endpoint (endpoint_uuid). To mint a gateway-wide key, pass all_endpoints: true explicitly.",
      });
    }

    // Identity-requires-scope invariant (mirrors the zod superRefine so it
    // holds even for callers that bypass the tRPC input schema): an acts-as
    // binding without a single-endpoint scope would let the key exercise the
    // bound user's delegated m365 identity gateway-wide. Rejecting here
    // covers both all_endpoints: true and a missing scope — endpoint_uuid is
    // unset in either case. This pairing is the safety argument for the
    // whole feature (PR #84's endpoint scoping is what contains the
    // acted-as identity to ONE endpoint), so it must be impossible to skip.
    if (input.acts_as_user_id && !input.endpoint_uuid) {
      throw new TRPCError({
        code: "BAD_REQUEST",
        message:
          "An identity-bound API key must be scoped to exactly one endpoint — acts_as_user_id requires endpoint_uuid (all_endpoints is not allowed).",
      });
    }

    // Effective owner of the new key: input.user_id if provided (null =
    // public/'everyone'), otherwise the caller (private). Resolved BEFORE the
    // existence lookups below so the ownership invariant rejects without a
    // single DB read.
    const apiKeyUserId = input.user_id !== undefined ? input.user_id : userId;

    // Ownership invariant (mirrored in both zod superRefines): an
    // identity-bound key must be OWNED by the identity it exercises. This
    // kills BOTH dangerous combinations: a public ('everyone') owner — a
    // public key exists to be handed to every consumer, so a public
    // identity-bound key would be a fleet-distributed delegated Graph
    // credential — and a foreign owner, which hands one user's delegated
    // identity to another user's key. The intended flow (a key owned by the
    // user it acts as, e.g. admin-owned acting-as-self) still passes.
    if (input.acts_as_user_id && apiKeyUserId !== input.acts_as_user_id) {
      throw new TRPCError({
        code: "FORBIDDEN",
        message:
          "An identity-bound API key must be owned by the user it acts as — a public ('everyone') or foreign-owned key cannot carry an acts-as identity.",
      });
    }

    // The scope target must exist — reject before any write. (The FK would
    // also catch this, but a clean NOT_FOUND beats a constraint error.)
    if (input.endpoint_uuid) {
      const endpoint = await endpointsRepository.findByUuid(
        input.endpoint_uuid,
      );
      if (!endpoint) {
        throw new TRPCError({
          code: "NOT_FOUND",
          message: "The endpoint to scope this API key to does not exist.",
        });
      }
    }

    // The acts-as target must exist — same friendly-NOT_FOUND-over-FK-error
    // reasoning as the endpoint check above.
    if (input.acts_as_user_id) {
      const actsAsUser = await usersRepository.findById(input.acts_as_user_id);
      if (!actsAsUser) {
        throw new TRPCError({
          code: "NOT_FOUND",
          message: "The user this API key would act as does not exist.",
        });
      }
    }

    try {
      const result = await apiKeysRepository.create({
        name: input.name,
        user_id: apiKeyUserId,
        // all_endpoints: true is the explicit escape hatch — stores NULL
        // (legacy gateway-wide scope). Otherwise the validated endpoint uuid.
        endpoint_uuid: input.endpoint_uuid ?? null,
        // Validated acts-as identity (admin-only, requires the endpoint
        // scope above). NULL = no identity, m365 injection fail-closes.
        acts_as_user_id: input.acts_as_user_id ?? null,
        is_active: true,
      });

      // The row exists — emit before serialising, since the serialiser is the
      // only thing between here and a response body carrying the FULL key.
      // `detail` gets the uuid, the name and the scope that decides how far
      // the key reaches; it must never get `result.key`, which is the
      // credential itself and is returned to the caller exactly once.
      emitAdminEvent(actor, {
        action: "apikey.create",
        target_type: "api_key",
        target_id: result.uuid,
        detail: {
          name: result.name,
          owner_user_id: apiKeyUserId,
          endpoint_uuid: input.endpoint_uuid ?? null,
          all_endpoints: input.all_endpoints === true,
          acts_as_user_id: input.acts_as_user_id ?? null,
        },
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

  // Member-facing list: the caller's own keys plus every public
  // ('everyone') key. Returns key_prefix only — never a usable secret — for
  // ALL of them (see serializeApiKeyList).
  //
  // This previously returned public keys' FULL value, justified as the
  // "copy the shared key to configure your client" convenience. That
  // reasoning was wrong: a public key being distributed to its intended
  // consumers out-of-band is not the same as every self-registered member
  // being able to read it on demand, and `list` is reachable by any member.
  // A member-role caller could read live gateway-wide production keys through
  // exactly this call. The convenience is gone deliberately;
  // an operator who needs gateway access gets an endpoint-scoped key minted
  // for them instead (create is admin-only and scope is mandatory).
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
    actor?: AuditActor,
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

      // Deactivating a key is a REVOCATION and gets its own verb — during an
      // incident "which credentials were killed, by whom, when" is a question
      // asked directly of the action column, and burying it inside a generic
      // `apikey.update` alongside renames would make it un-greppable.
      emitAdminEvent(actor, {
        action: input.is_active === false ? "apikey.revoke" : "apikey.update",
        target_type: "api_key",
        target_id: input.uuid,
        detail: { name: result.name, is_active: result.is_active },
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
    actor?: AuditActor,
  ): Promise<z.infer<typeof DeleteApiKeyResponseSchema>> => {
    try {
      // Admins bypass the ownership WHERE (may delete / revoke any key);
      // members stay owner-scoped.
      if (isAdmin) {
        await apiKeysRepository.deleteAsAdmin(input.uuid);
      } else {
        await apiKeysRepository.delete(input.uuid, userId);
      }

      emitAdminEvent(actor, {
        action: "apikey.delete",
        target_type: "api_key",
        target_id: input.uuid,
        detail: { as_admin: isAdmin },
      });

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
      // Deliberately does NOT echo the key's endpoint scope. `validate` is a
      // protectedProcedure any member can call with an arbitrary key string;
      // returning endpoint_uuid would widen the existing key oracle (a caller
      // could probe not just validity but which endpoint a guessed key is
      // bound to). Scope is enforced server-side in checkApiKeyAccess; it is
      // never disclosed here.
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
