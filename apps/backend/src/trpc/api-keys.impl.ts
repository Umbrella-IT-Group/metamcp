import type { AuditActor } from "@repo/trpc";
import {
  CreateApiKeyRequestSchema,
  CreateApiKeyResponseSchema,
  DeactivateApiKeyRequestSchema,
  DeactivateApiKeyResponseSchema,
  DeleteApiKeyRequestSchema,
  DeleteApiKeyResponseSchema,
  GetGlobalIpPolicyResponseSchema,
  ListAllApiKeysResponseSchema,
  ListApiKeysResponseSchema,
  SetApiKeyIpPolicyRequestSchema,
  SetApiKeyIpPolicyResponseSchema,
  SetGlobalIpPolicyRequestSchema,
  SetGlobalIpPolicyResponseSchema,
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
import { resolveActsAsUserId } from "../lib/api-key-identity";
import {
  apiKeyIpPolicyDisabled,
  type IpPolicyMode,
  normalizeCidrList,
} from "../lib/api-key-ip-policy";
import {
  ApiKeyMintRefusal,
  MINT_REFUSALS,
  validateAgentMintRequest,
} from "../lib/api-key-mint-rules";
import {
  followedGlobalPolicy,
  globalPolicyRefusalForCaller,
  selfLockoutRefusal,
} from "../lib/api-key-self-lockout";
import { emitAdminEvent } from "../lib/audit/admin-event";
import {
  ADMIN_AUDIT_WRITE_FAILED_MESSAGE,
  AdminAuditWriteError,
  runAuditedTransaction,
  withAdminAudit,
} from "../lib/audit/admin-write";
import { configService } from "../lib/config.service";

const apiKeysRepository = new ApiKeysRepository();

/**
 * Validate a requested IP policy (migration 0041) for a write, returning the
 * canonical list. Shared by the per-key and the global setter so both refuse
 * the same things with the same words. Every refusal is BAD_REQUEST before any
 * write.
 *
 * Two guards beyond CIDR syntax, both against an administrator locking out
 * callers by accident:
 *  - enforce with an EMPTY list is refused. It would refuse every request for
 *    the key (or, globally, for every key that follows the global policy).
 *    To stop a key, deactivate it; that is the revocation with a name.
 *  - (per-key only) a mode other than off with allowed_cidrs null is refused:
 *    a per-key mode is only read when the key has its own list, so accepting
 *    it would store a setting that does nothing while looking like a policy.
 */
function validatedCidrs(
  cidrs: string[],
  mode: IpPolicyMode,
  scope: "key" | "global",
): string[] {
  const normalized = normalizeCidrList(cidrs);
  if (!normalized.ok) {
    throw new TRPCError({
      code: "BAD_REQUEST",
      message: `Invalid allowlist entries: ${normalized.errors.join("; ")}`,
    });
  }
  if (mode === "enforce" && normalized.cidrs.length === 0) {
    throw new TRPCError({
      code: "BAD_REQUEST",
      message:
        scope === "key"
          ? "Enforce with an empty list would refuse every request for this key. Add at least one CIDR, or deactivate the key instead."
          : "Enforce with an empty global list would refuse every key that follows the global policy. Add at least one CIDR.",
    });
  }
  return normalized.cidrs;
}

/** The fixed refusal for a caller that is not an operator-scope key. */
function notAnOperatorRefusal(): TRPCError {
  return new TRPCError({
    code: MINT_REFUSALS.caller_not_operator.code,
    message: MINT_REFUSALS.caller_not_operator.message,
  });
}

/**
 * Create a data-plane key on behalf of an admin-plane key.
 *
 * Reached ONLY when the request authenticated with an admin-plane key, which
 * is decided from `actor.admin_plane`: the provenance `auditActor(ctx)` builds
 * from the origin `createContext` set from the verified key row. Nothing the
 * caller sends picks this branch, and nothing the caller sends can leave it
 * for the human branch below (that needs an actor without that provenance).
 *
 * The caller must be an `operator`-scope key whose owner is still an
 * administrator, checked here as well as by the procedure scope sets, so a
 * direct call to this function, a missing scope and an unknown scope all fail
 * closed with the sentence every other admin-plane refusal carries.
 *
 * Every rule in lib/api-key-mint-rules.ts is enforced before the first write
 * (the field checks, the kill switch) or inside the one transaction that
 * writes the key (the owner, the endpoint, the name). The key row, its IP
 * policy and its single `apikey.create` audit row are inserted in that
 * transaction, the audit row awaited, so there is no unlocked intermediate key
 * and no key without its record. The raw value is returned once, after
 * commit, and is in no audit row, log line or error.
 */
async function createForAdminPlane(
  input: Record<string, unknown>,
  isAdmin: boolean,
  actor: AuditActor,
): Promise<z.infer<typeof CreateApiKeyResponseSchema>> {
  if (actor.admin_plane?.scope !== "operator" || isAdmin !== true) {
    throw notAnOperatorRefusal();
  }

  let request: ReturnType<typeof validateAgentMintRequest>;
  try {
    request = validateAgentMintRequest(input);
  } catch (error) {
    throw mintFailure(error);
  }

  try {
    const created = await runAuditedTransaction(
      actor,
      (tx) => apiKeysRepository.mintDataPlaneKey(tx, request),
      (key) => ({
        action: "apikey.create",
        target_type: "api_key",
        target_id: key.uuid,
        // Never the key. `key_admin_plane` is named apart from the legacy
        // `admin_plane` field because an admin-plane actor's event carries the
        // acting key under `detail.admin_plane`.
        detail: {
          name: key.name,
          owner_user_id: request.ownerUserId,
          endpoint_uuid: request.endpointUuid,
          all_endpoints: request.allEndpoints,
          acts_as_user_id: null,
          key_admin_plane: false,
          key_admin_plane_scope: "sync",
          ip_policy: { mode: "enforce", allowed_cidrs: request.allowedCidrs },
        },
      }),
    );
    return ApiKeysSerializer.serializeCreateApiKeyResponse(created);
  } catch (error) {
    throw mintFailure(error);
  }
}

/**
 * Turn anything that can go wrong in an agent mint into an error that is safe
 * to return: a rule refusal keeps its fixed sentence, everything else becomes
 * a fixed one. The original error is never attached and never logged beyond
 * its type: a driver error can carry statement parameters, and this path
 * handles a freshly generated credential.
 */
function mintFailure(error: unknown): TRPCError {
  if (error instanceof TRPCError) return error;
  if (error instanceof ApiKeyMintRefusal) {
    return new TRPCError({ code: error.code, message: error.message });
  }
  if (error instanceof AdminAuditWriteError) {
    return new TRPCError({
      code: "INTERNAL_SERVER_ERROR",
      message: ADMIN_AUDIT_WRITE_FAILED_MESSAGE,
    });
  }
  logger.error(
    `Error creating API key for an admin-plane key (${error instanceof Error ? error.name : typeof error})`,
  );
  return new TRPCError({
    code: "INTERNAL_SERVER_ERROR",
    message: "The API key could not be created.",
  });
}

export const apiKeysImplementations = {
  create: async (
    input: z.infer<typeof CreateApiKeyRequestSchema>,
    userId: string,
    isAdmin: boolean,
    actor?: AuditActor,
  ): Promise<z.infer<typeof CreateApiKeyResponseSchema>> => {
    // A request that authenticated with an admin-plane key takes the agent mint
    // branch and never reaches the human branch below. The branch is picked by
    // the verified provenance in `actor`, not by anything in `input`.
    if (actor?.admin_plane) {
      return createForAdminPlane(
        input as unknown as Record<string, unknown>,
        isAdmin,
        actor,
      );
    }

    // Scope (migration 0043) only means something on an admin-plane key. The
    // zod superRefine says the same; this is for a caller that bypassed it.
    if (input.admin_plane_scope !== undefined && input.admin_plane !== true) {
      throw new TRPCError({
        code: "BAD_REQUEST",
        message:
          "admin_plane_scope applies only to an admin-plane key, pass admin_plane: true with it.",
      });
    }

    // Admin-plane (control-plane) mint policy (migration 0038), enforced here
    // and mirrored in the zod superRefine for schema-bypassing callers.
    // ADMIN-ONLY: only an admin session may mint a control-plane key. PLANE
    // EXCLUSIVITY: a control-plane key has no endpoint to reach and carries no
    // acts-as identity, so those data-plane inputs must be absent (and the
    // mandatory-scope gate below is skipped for it). Owner-must-be-admin is
    // enforced once the effective owner is resolved. Kept FORBIDDEN/BAD_REQUEST
    // -before-write, the same shape as the acts-as guards below.
    if (input.admin_plane === true) {
      if (!isAdmin) {
        throw new TRPCError({
          code: "FORBIDDEN",
          message:
            "Only administrators can create admin-plane (control-plane) API keys.",
        });
      }
      if (
        input.endpoint_uuid !== undefined ||
        input.all_endpoints !== undefined
      ) {
        throw new TRPCError({
          code: "BAD_REQUEST",
          message:
            "An admin-plane key has no endpoint scope, do not pass endpoint_uuid or all_endpoints.",
        });
      }
      if (input.acts_as_user_id !== undefined) {
        throw new TRPCError({
          code: "BAD_REQUEST",
          message:
            "An admin-plane key carries no acts-as identity, do not pass acts_as_user_id.",
        });
      }
    }

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
    // Data-plane scope gate. Skipped for an admin-plane key: it is the ONE
    // place the mandatory-scope rule is relaxed, and only for control-plane
    // keys, which have no endpoint to name (the guard above already rejected a
    // scope on them).
    if (input.admin_plane !== true) {
      if (input.endpoint_uuid && input.all_endpoints === true) {
        throw new TRPCError({
          code: "BAD_REQUEST",
          message:
            "Pass either endpoint_uuid or all_endpoints: true, not both, a key is scoped to one endpoint or explicitly global.",
        });
      }
      if (!input.endpoint_uuid && input.all_endpoints !== true) {
        throw new TRPCError({
          code: "BAD_REQUEST",
          message:
            "An API key must be scoped to an endpoint (endpoint_uuid). To mint a gateway-wide key, pass all_endpoints: true explicitly.",
        });
      }
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

    // Owner-must-be-admin at mint for an admin-plane key. This is
    // defense in depth, not the enforcement of record: the owner's role is
    // re-read fresh per request at authentication, so a later demotion still
    // fails closed. Rejecting here keeps a useless-and-dangerous artifact, a
    // member-owned (or public) control-plane key, from being created at all. A
    // public ('everyone') owner has no user and no role to become; the
    // requires-owner CHECK forbids it too, but a precise message beats a
    // constraint error.
    if (input.admin_plane === true) {
      if (apiKeyUserId === null) {
        throw new TRPCError({
          code: "FORBIDDEN",
          message:
            "An admin-plane key cannot be public ('everyone'), it must be owned by an administrator.",
        });
      }
      const ownerRole = await usersRepository.findRoleById(apiKeyUserId);
      if (ownerRole !== "admin") {
        throw new TRPCError({
          code: "FORBIDDEN",
          message: "An admin-plane key's owner must be an administrator.",
        });
      }
    }

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

    // Optional IP policy at creation (migration 0041), the human flow's way to
    // create a key already locked. Validated like setIpPolicy validates a list;
    // the prefix bounds an agent-created key must meet do not apply to a human
    // administrator. A key created without one follows the global policy, as
    // before.
    const ipPolicy =
      input.ip_policy !== undefined
        ? {
            allowed_cidrs: validatedCidrs(
              input.ip_policy.allowed_cidrs,
              input.ip_policy.mode,
              "key",
            ),
            ip_policy_mode: input.ip_policy.mode,
          }
        : undefined;

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
        // Plane flag (migration 0038). true only after the admin-only +
        // owner-must-be-admin + plane-exclusivity gates above; the CHECK
        // constraints refuse a straddling row regardless.
        admin_plane: input.admin_plane === true,
        // Scope (migration 0043): the administrator's choice for an admin-plane
        // key, `sync` when they made none. The repository drops it for a
        // data-plane key.
        ...(input.admin_plane === true && input.admin_plane_scope !== undefined
          ? { admin_plane_scope: input.admin_plane_scope }
          : {}),
        ...(ipPolicy ?? {}),
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
          // Greppable "a control-plane key was minted" (migration 0038). Never
          // the key itself, detail already carries no credential material.
          admin_plane: input.admin_plane === true,
          // The scope of a control-plane key (migration 0043) and the policy a
          // key was created with. Absent when not applicable.
          ...(input.admin_plane === true
            ? { admin_plane_scope: input.admin_plane_scope ?? "sync" }
            : {}),
          ...(ipPolicy
            ? {
                allowed_cidrs: ipPolicy.allowed_cidrs,
                ip_policy_mode: ipPolicy.ip_policy_mode,
              }
            : {}),
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
    // Re-activation is an administrator's decision. A member may rename and
    // deactivate their own keys, but if they could also re-activate one, an
    // administrator's deactivation of it could be undone by that member, or
    // by anyone holding the member's session. Every member request carrying
    // `is_active: true` is refused, a combined rename included, so nothing of
    // it is written. No read of the key's current state first: refusing
    // every such request also covers a stale form and cannot race an
    // administrator's deactivation. Outside the try below so the FORBIDDEN
    // reaches the caller instead of being rewrapped as a generic error.
    if (!isAdmin && input.is_active === true) {
      throw new TRPCError({
        code: "FORBIDDEN",
        message: "Only an administrator can re-activate an API key",
      });
    }
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
      // investigation "which credentials were killed, by whom, when" is a
      // question asked directly of the action column, and burying it inside a
      // generic `apikey.update` alongside renames would make it un-greppable.
      // Re-activating (only an administrator reaches it, see above) reverses
      // that containment and gets its own verb for the same reason. The verb
      // follows the REQUEST, not the returned row: a rename that omits
      // `is_active` stays `apikey.update` even when the key is active.
      emitAdminEvent(actor, {
        action:
          input.is_active === true
            ? "apikey.reactivate"
            : input.is_active === false
              ? "apikey.revoke"
              : "apikey.update",
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

  /**
   * Deactivate one key, the containment write an operator-scope admin-plane key
   * and an administrator's session may both make. Input is the uuid and
   * nothing else; the procedure cannot rename, re-activate or delete.
   *
   * The calling key is refused (the uuid is compared lowercased, since
   * Postgres reads a uuid case-insensitively and an upper-case spelling of the
   * caller's own uuid must not slip past): a key that locks itself out is not
   * containment. Re-activation stays an administrator's act in the UI, so what
   * an agent deactivates only a human can undo.
   *
   * The state change and its `apikey.revoke` audit row (the verb the UI's
   * deactivation writes, with `detail.via = "deactivate"`) are one transaction
   * whoever calls, the row awaited: an audit failure leaves the key active. An
   * already-inactive key returns `changed: false` and records nothing.
   */
  deactivate: async (
    input: z.infer<typeof DeactivateApiKeyRequestSchema>,
    actor?: AuditActor,
  ): Promise<z.infer<typeof DeactivateApiKeyResponseSchema>> => {
    const uuid = input.uuid.toLowerCase();
    if (actor?.admin_plane?.key_uuid.toLowerCase() === uuid) {
      throw new TRPCError({
        code: "BAD_REQUEST",
        message: "A key cannot deactivate itself.",
      });
    }

    let outcome: Awaited<ReturnType<typeof apiKeysRepository.deactivate>>;
    try {
      outcome = await runAuditedTransaction(
        actor,
        (tx) => apiKeysRepository.deactivate(tx, uuid),
        (written) =>
          written.status === "deactivated"
            ? {
                action: "apikey.revoke",
                target_type: "api_key",
                target_id: uuid,
                detail: {
                  name: written.key.name,
                  is_active: false,
                  via: "deactivate",
                },
              }
            : null,
      );
    } catch (error) {
      if (error instanceof AdminAuditWriteError) {
        throw new TRPCError({
          code: "INTERNAL_SERVER_ERROR",
          message: ADMIN_AUDIT_WRITE_FAILED_MESSAGE,
        });
      }
      throw error;
    }
    if (outcome.status === "not_found") {
      throw new TRPCError({ code: "NOT_FOUND", message: "API key not found" });
    }
    return ApiKeysSerializer.serializeDeactivatedApiKey(
      outcome.key,
      outcome.status === "deactivated",
    );
  },

  // ---- IP allowlists (migration 0041), admin-only at the router ----

  setIpPolicy: async (
    input: z.infer<typeof SetApiKeyIpPolicyRequestSchema>,
    actor?: AuditActor,
  ): Promise<z.infer<typeof SetApiKeyIpPolicyResponseSchema>> => {
    if (input.allowed_cidrs === null && input.ip_policy_mode !== "off") {
      throw new TRPCError({
        code: "BAD_REQUEST",
        message:
          "A per-key mode needs a per-key list. Pass allowed_cidrs with the mode, or allowed_cidrs: null with mode off to make the key follow the global policy.",
      });
    }
    const allowedCidrs =
      input.allowed_cidrs === null
        ? null
        : validatedCidrs(input.allowed_cidrs, input.ip_policy_mode, "key");

    // Self-lockout rail: an admin-plane key changing ITS OWN policy may not
    // leave an enforce policy that excludes the address of this request. The
    // uuid is compared lowercased because Postgres reads a uuid
    // case-insensitively. A human session and a write to any other key are
    // unaffected.
    const callerKeyUuid = actor?.admin_plane?.key_uuid.toLowerCase();
    const changesOwnPolicy =
      callerKeyUuid !== undefined && input.uuid.toLowerCase() === callerKeyUuid;

    const result = await withAdminAudit(
      actor,
      async (...tx) => {
        if (changesOwnPolicy) {
          const handle = tx[0];
          if (!handle) {
            // Unreachable: an admin-plane actor always gets a transaction.
            throw new TRPCError({
              code: "INTERNAL_SERVER_ERROR",
              message: "Internal server error",
            });
          }
          // Taken first, in the order setGlobalIpPolicy takes them (the config
          // locks, then the key row), so the two cannot deadlock. A key that
          // is about to follow the global policy is judged against the global
          // policy as it will be when this commits.
          const effective =
            allowedCidrs === null
              ? followedGlobalPolicy(
                  await configService.getApiKeyIpPolicyInTransaction(handle),
                )
              : { mode: input.ip_policy_mode, cidrs: allowedCidrs };
          const refusal = selfLockoutRefusal(
            effective,
            actor?.actor_ip,
            allowedCidrs === null ? "globalList" : "ownList",
          );
          if (refusal) {
            throw new TRPCError({ code: "BAD_REQUEST", message: refusal });
          }
        }
        return apiKeysRepository.setIpPolicy(
          input.uuid,
          {
            allowed_cidrs: allowedCidrs,
            ip_policy_mode: input.ip_policy_mode,
          },
          ...tx,
        );
      },
      // After the write, with the value it replaced (read under the same row
      // lock), so "what did this change" is answerable from the row alone.
      // CIDRs and modes only: no credential material.
      (written) =>
        written
          ? {
              action: "apikey.ip_policy.set",
              target_type: "api_key",
              target_id: input.uuid,
              detail: {
                name: written.after.name,
                old_value: written.before,
                new_value: {
                  allowed_cidrs: written.after.allowed_cidrs,
                  ip_policy_mode: written.after.ip_policy_mode,
                },
              },
            }
          : null,
    );
    if (!result) {
      throw new TRPCError({ code: "NOT_FOUND", message: "API key not found" });
    }

    return ApiKeysSerializer.serializeApiKeyIpPolicy(result.after);
  },

  getGlobalIpPolicy: async (): Promise<
    z.infer<typeof GetGlobalIpPolicyResponseSchema>
  > => {
    const policy = await configService.getApiKeyIpPolicy();
    return {
      mode: policy.mode,
      allowed_cidrs: policy.cidrs,
      problems: policy.problems,
      kill_switch_active: apiKeyIpPolicyDisabled(),
    };
  },

  setGlobalIpPolicy: async (
    input: z.infer<typeof SetGlobalIpPolicyRequestSchema>,
    actor?: AuditActor,
  ): Promise<z.infer<typeof SetGlobalIpPolicyResponseSchema>> => {
    const cidrs = validatedCidrs(input.allowed_cidrs, input.mode, "global");

    const callerKeyUuid = actor?.admin_plane?.key_uuid;

    const { after } = await withAdminAudit(
      actor,
      async (...tx) => {
        const snapshots = await configService.setApiKeyIpPolicy(
          { mode: input.mode, cidrs },
          ...tx,
        );
        // Self-lockout rail: an admin-plane key that FOLLOWS the global policy
        // may not set one that excludes the address of this request. Checked
        // after the write and inside its transaction, with the config locks
        // the write took still held, so a refusal rolls the write back and no
        // other writer can slip in between. A human session is unaffected.
        if (callerKeyUuid !== undefined) {
          const handle = tx[0];
          if (!handle) {
            // Unreachable: an admin-plane actor always gets a transaction.
            throw new TRPCError({
              code: "INTERNAL_SERVER_ERROR",
              message: "Internal server error",
            });
          }
          const refusal = await globalPolicyRefusalForCaller(
            handle,
            callerKeyUuid,
            actor?.actor_ip,
            snapshots.after,
          );
          if (refusal) {
            throw new TRPCError({ code: "BAD_REQUEST", message: refusal });
          }
        }
        return snapshots;
      },
      (snapshots) => ({
        action: "config.api_key_ip_policy.set",
        target_type: "config_key",
        target_id: "API_KEY_IP_POLICY",
        detail: {
          old_value: {
            mode: snapshots.before.mode,
            allowed_cidrs: snapshots.before.cidrs,
          },
          new_value: {
            mode: snapshots.after.mode,
            allowed_cidrs: snapshots.after.cidrs,
          },
        },
      }),
    );

    // Read back inside the write transaction so another writer cannot replace
    // this mutation's response, or a later read failure turn success into 500.
    return { mode: after.mode, allowed_cidrs: after.cidrs };
  },

  validate: async (
    input: z.infer<typeof ValidateApiKeyRequestSchema>,
  ): Promise<z.infer<typeof ValidateApiKeyResponseSchema>> => {
    try {
      // NO IP check, deliberately (migration 0041): this is an admin UI
      // oracle, not an authentication, and it has no caller address worth
      // judging (the browser's, not the key holder's). Passing one would
      // make the answer depend on where the administrator is sitting. The
      // second argument of validateApiKey is the explicit opt-in, so its
      // absence here is the opt-out; api-keys.impl.test.ts pins it.
      const result = await apiKeysRepository.validateApiKey(input.key);

      // Disabled-identity gate (migration 0027). The DATA plane already
      // refuses such a key — the api-key/OAuth middleware runs
      // findDisabledIdentity around validateApiKey and answers 403 with an
      // account_disabled audit event — so this procedure is the last surface
      // that would still call such a key "valid". Nothing authenticates
      // through it (it is an oracle for the admin UI), which is why the check
      // belongs HERE and not inside validateApiKey: pushing it into the
      // repository would add a users read to the hot auth path and strip the
      // middleware's containment response of the very audit event an
      // investigation greps for. The cost is at most two queries on a cold
      // path, and the benefit is that the two planes give the same answer to
      // the disabled-identity question. They still differ deliberately
      // elsewhere: the middleware also enforces endpoint scope, which this
      // procedure has no endpoint to check against and does not disclose (see
      // the note on the return below).
      //
      // Checked against the SAME candidate list the data plane refuses on —
      // the key's owner AND, for an admin key carrying an acts-as binding,
      // the identity it impersonates. Checking only the owner left the exact
      // hole this gate exists to close: an enabled admin's scoped key would
      // still be reported valid while acting as an account that was just
      // locked out, and the middleware would refuse the very same key.
      if (result.valid) {
        // resolveActsAsUserId is the very function the data-plane middleware
        // runs, shared rather than reimplemented so the identity-requires-
        // scope pairing (migration 0024) cannot drift between the planes: it
        // returns undefined unless endpoint_uuid is non-NULL, so an unscoped
        // key is unaffected and no second query is spent on it.
        for (const candidateUserId of [
          result.user_id,
          resolveActsAsUserId(result),
        ]) {
          // user_id NULL is a public / service key with no owner to disable,
          // and an unbound key has no acts-as target. There is nothing to
          // check, and calling isDisabled(undefined) would match no row and
          // fail CLOSED, silently invalidating every public key.
          if (!candidateUserId) continue;
          if (await usersRepository.isDisabled(candidateUserId)) {
            // Bare not-valid, with no user_id / key_uuid: `validate` is a
            // protectedProcedure any member may call with an arbitrary key
            // string, so a distinct "exists but an identity behind it is
            // disabled" answer would widen the key oracle instead of
            // narrowing it. Such a key is indistinguishable from a key that
            // does not exist — including which of the two identities was the
            // disabled one.
            return { valid: false };
          }
        }
      }

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
