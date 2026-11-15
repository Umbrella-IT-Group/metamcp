import type { AuditActor } from "@repo/trpc";
import {
  AccessGroupEndpointRequestSchema,
  AccessGroupMemberRequestSchema,
  AccessGroupMutationResponseSchema,
  CreateAccessGroupRequestSchema,
  CreateAccessGroupResponseSchema,
  DeleteAccessGroupRequestSchema,
  GetAccessGroupRequestSchema,
  GetAccessGroupResponseSchema,
  GetEndpointAccessRequestSchema,
  GetEndpointAccessResponseSchema,
  ListAccessGroupsResponseSchema,
  ListEndpointOptionsResponseSchema,
  SetEndpointRestrictedRequestSchema,
  UpdateAccessGroupRequestSchema,
} from "@repo/zod-types";
import { TRPCError } from "@trpc/server";
import { z } from "zod";

import { describeDbError } from "@/lib/db-error-summary";
import logger from "@/utils/logger";

import { accessGroupsRepository } from "../db/repositories/access-groups.repo";
import { endpointGateRepository } from "../db/repositories/endpoint-gate.repo";
import { endpointsRepository } from "../db/repositories/endpoints.repo";
import { usersRepository } from "../db/repositories/users.repo";
import {
  AdminRuleRefusal,
  withAdminAudit,
  withAdminAuditTx,
} from "../lib/audit/admin-write";
import { clampAuditText } from "../lib/audit/audit-emitter";
import {
  ACCESS_GROUP_UPDATE_FIELDS,
  describeUpdate,
} from "../lib/audit/before-state";
import { invalidateEndpointAccessCache } from "../lib/endpoint-access-control";
import {
  ENDPOINT_GATE_REFUSALS,
  isOwnRecentRestriction,
  judgeEndpointUnrestrict,
} from "../lib/endpoint-namespace-gate";

/**
 * The refusal an admin-plane key gets for deleting a group that still has a
 * member or a mapped endpoint. Fixed, naming no group, member or endpoint.
 */
export const GROUP_DELETE_NOT_EMPTY_REFUSAL =
  "An admin-plane API key can delete an access group only once it has no members and no mapped endpoints. Remove them first, each as its own change.";

/**
 * Rethrow a coded refusal (a rule of the endpoint gate or a group rail, the
 * change budget, a scope or audit refusal already coded) out of a
 * catch-all, so it reaches the caller as itself and never as `success: false`
 * inside an HTTP 200, which a caller's tooling cannot tell from an unknown
 * outcome.
 */
function rethrowCoded(error: unknown): void {
  if (error instanceof TRPCError) throw error;
}

/**
 * Admin CRUD over access groups and the per-endpoint gate they drive
 * (migration 0033).
 *
 * EVERY MUTATION HERE INVALIDATES THE DECISION CACHE, unconditionally, on the
 * success path and only AFTER the write has committed. Uniform rather than
 * "only the ones that can change an answer": `create` and `update` cannot
 * change one today, but a later change that lets `create` seed members would
 * silently inherit a missing invalidation, and the cost of over-invalidating is
 * a cold cache and one extra round trip per key. The failure mode of
 * under-invalidating is a revoked user still being served for up to a minute.
 * After the commit rather than inside it, because a decision recomputed in the
 * window between invalidating and committing would be cached against the old
 * rows for the rest of the TTL. See `lib/endpoint-access-control`.
 *
 * EVERY MUTATION HERE IS AUDITED, and WHO made it decides how. These grants are
 * the authorization boundary for OAuth callers and for API keys, so who was
 * added to what, and when an endpoint's gate was switched on, must be
 * answerable from `audit_log` and not from inference. A request authenticated
 * with an admin-plane API key (the operator scope may call all of them) writes
 * its audit row in the SAME transaction as the change, awaited: if the row
 * cannot be written the change is rolled back, including everything a group
 * delete cascades to, and no success event is emitted twice. A human
 * administrator's session keeps the best-effort record it always had. Both go
 * through `withAdminAudit`; see `lib/audit/admin-write`. Emitted BELOW every
 * early return, so a mutation that matched nothing leaves no row claiming it
 * did.
 */
export const accessGroupsImplementations = {
  list: async (): Promise<z.infer<typeof ListAccessGroupsResponseSchema>> => {
    try {
      const groups = await accessGroupsRepository.listWithCounts();
      return {
        success: true as const,
        data: groups.map((group) => ({
          uuid: group.uuid,
          name: group.name,
          description: group.description,
          created_at: group.created_at.toISOString(),
          member_count: group.member_count,
          endpoint_count: group.endpoint_count,
        })),
      };
    } catch (error) {
      logger.error("Error listing access groups:", describeDbError(error));
      return {
        success: false as const,
        data: [],
        message: "Failed to list access groups",
      };
    }
  },

  get: async (
    input: z.infer<typeof GetAccessGroupRequestSchema>,
  ): Promise<z.infer<typeof GetAccessGroupResponseSchema>> => {
    try {
      const group = await accessGroupsRepository.findDetailByUuid(input.uuid);
      if (!group) {
        return { success: false as const, message: "Access group not found" };
      }

      return {
        success: true as const,
        data: {
          uuid: group.uuid,
          name: group.name,
          description: group.description,
          created_at: group.created_at.toISOString(),
          member_count: group.member_count,
          endpoint_count: group.endpoint_count,
          members: group.members,
          endpoints: group.endpoints,
        },
      };
    } catch (error) {
      logger.error("Error fetching access group:", describeDbError(error));
      return {
        success: false as const,
        message: "Failed to fetch access group",
      };
    }
  },

  /**
   * Every endpoint on the gateway, reduced to what a picker needs.
   *
   * Deliberately NOT `endpoints.list`, which is `protectedProcedure` and scoped
   * to the caller (`findAllAccessibleToUserWithNamespaces` — public endpoints
   * plus their own). An administrator mapping a group has to be able to see an
   * endpoint owned by somebody else, and that query silently cannot show it.
   *
   * Deliberately NOT a new `endpoints.listAll` either: three columns is the
   * whole of what this screen needs, while the endpoint row also carries the
   * namespace binding, the rate-limit configuration and the full auth posture.
   * A narrower query is a narrower disclosure surface, and this one is reachable
   * only through `adminProcedure`.
   */
  listEndpoints: async (): Promise<
    z.infer<typeof ListEndpointOptionsResponseSchema>
  > => {
    try {
      const endpoints = await endpointsRepository.findAll();
      return {
        success: true as const,
        data: endpoints.map((endpoint) => ({
          uuid: endpoint.uuid,
          name: endpoint.name,
          restricted: endpoint.restricted,
        })),
      };
    } catch (error) {
      logger.error(
        "Error listing endpoints for access groups:",
        describeDbError(error),
      );
      return {
        success: false as const,
        data: [],
        message: "Failed to list endpoints",
      };
    }
  },

  getEndpointAccess: async (
    input: z.infer<typeof GetEndpointAccessRequestSchema>,
  ): Promise<z.infer<typeof GetEndpointAccessResponseSchema>> => {
    try {
      const endpoint = await endpointsRepository.findByUuid(
        input.endpoint_uuid,
      );
      if (!endpoint) {
        return { success: false as const, message: "Endpoint not found" };
      }

      const groups = await accessGroupsRepository.findGroupsForEndpoint(
        input.endpoint_uuid,
      );

      return {
        success: true as const,
        data: {
          endpoint_uuid: endpoint.uuid,
          restricted: endpoint.restricted,
          // Carried so the panel can tell "restricted" from "restricted AND
          // actually gating anyone" — see EndpointAccessSchema.
          enable_oauth: endpoint.enable_oauth,
          enable_api_key_auth: endpoint.enable_api_key_auth,
          // Carried so the panel can say whether gateway-wide keys are refused
          // here outright, a separate switch from `restricted`.
          require_scoped_api_key: endpoint.require_scoped_api_key,
          groups,
        },
      };
    } catch (error) {
      logger.error("Error fetching endpoint access:", describeDbError(error));
      return {
        success: false as const,
        message: "Failed to fetch endpoint access",
      };
    }
  },

  create: async (
    input: z.infer<typeof CreateAccessGroupRequestSchema>,
    actor?: AuditActor,
  ): Promise<z.infer<typeof CreateAccessGroupResponseSchema>> => {
    try {
      // Checked here as well as by the UNIQUE constraint, so the dialog can say
      // which name collided instead of surfacing a driver error. The constraint
      // is still the authority under a race between two tabs.
      const existing = await accessGroupsRepository.findByName(input.name);
      if (existing) {
        return {
          success: false as const,
          message: "An access group with that name already exists",
        };
      }

      const created = await withAdminAudit(
        actor,
        (...tx) =>
          accessGroupsRepository.create(
            {
              name: input.name,
              description: input.description ?? null,
            },
            ...tx,
          ),
        (group) => ({
          action: "group.create",
          target_type: "access_group",
          target_id: group.uuid,
          detail: { name: clampAuditText(group.name, 100) },
        }),
      );

      invalidateEndpointAccessCache();

      return {
        success: true as const,
        data: {
          uuid: created.uuid,
          name: created.name,
          description: created.description,
          created_at: created.created_at.toISOString(),
          member_count: 0,
          endpoint_count: 0,
        },
      };
    } catch (error) {
      rethrowCoded(error);
      logger.error("Error creating access group:", describeDbError(error));
      return {
        success: false as const,
        message:
          error instanceof Error ? error.message : "Internal server error",
      };
    }
  },

  update: async (
    input: z.infer<typeof UpdateAccessGroupRequestSchema>,
    actor?: AuditActor,
  ): Promise<z.infer<typeof AccessGroupMutationResponseSchema>> => {
    try {
      const duplicate = await accessGroupsRepository.findByName(input.name);
      if (duplicate && duplicate.uuid !== input.uuid) {
        return {
          success: false as const,
          message: "An access group with that name already exists",
        };
      }

      const updated = await withAdminAudit(
        actor,
        (...tx) =>
          accessGroupsRepository.updateReportingPrevious(
            {
              uuid: input.uuid,
              name: input.name,
              description: input.description ?? null,
            },
            ...tx,
          ),
        (written) =>
          written
            ? {
                action: "group.update",
                target_type: "access_group",
                target_id: written.group.uuid,
                detail: {
                  name: clampAuditText(written.group.name, 100),
                  // The previous and new value of each field this write
                  // changed, read under the group's row lock.
                  ...describeUpdate(
                    written.previous,
                    written.group,
                    ACCESS_GROUP_UPDATE_FIELDS,
                  ),
                },
              }
            : null,
      );

      if (!updated) {
        return { success: false as const, message: "Access group not found" };
      }

      invalidateEndpointAccessCache();

      return { success: true as const };
    } catch (error) {
      rethrowCoded(error);
      logger.error("Error updating access group:", describeDbError(error));
      return {
        success: false as const,
        message:
          error instanceof Error ? error.message : "Internal server error",
      };
    }
  },

  delete: async (
    input: z.infer<typeof DeleteAccessGroupRequestSchema>,
    actor?: AuditActor,
  ): Promise<z.infer<typeof AccessGroupMutationResponseSchema>> => {
    try {
      // For an admin-plane key a group delete is LEAF-ONLY: refused while the
      // group has any member or mapped endpoint, so every grant it carries is
      // removed first by its own reversible, audited and budgeted change, and
      // the delete itself takes nothing with it. The group row is locked
      // first, so a member or mapping added concurrently (its foreign key
      // waits on that lock) is either seen here or refused at its own insert.
      // A human administrator's delete keeps its cascade.
      //
      // The cascade to memberships and mappings runs inside the delete
      // statement, so a failed audit row rolls those back with the group.
      const deleted = await withAdminAudit(
        actor,
        async (...tx) => {
          const handle = tx[0];
          if (actor?.admin_plane && handle) {
            const contents = await accessGroupsRepository.lockGroupContents(
              handle,
              input.uuid,
            );
            if (contents && (contents.members > 0 || contents.mappings > 0)) {
              throw new AdminRuleRefusal(
                "CONFLICT",
                GROUP_DELETE_NOT_EMPTY_REFUSAL,
                {
                  action: "group.delete",
                  target_type: "access_group",
                  target_id: input.uuid,
                  detail: {
                    rule: "group_not_empty",
                    members: contents.members,
                    mappings: contents.mappings,
                  },
                },
              );
            }
          }
          return accessGroupsRepository.deleteByUuid(input.uuid, ...tx);
        },
        (group) =>
          group
            ? {
                action: "group.delete",
                target_type: "access_group",
                target_id: input.uuid,
                detail: { name: clampAuditText(group.name, 100) },
              }
            : null,
      );
      if (!deleted) {
        return { success: false as const, message: "Access group not found" };
      }

      // Deleting a group revokes every grant it carried (both mapping tables
      // cascade), so the cache must drop before the next request is served.
      invalidateEndpointAccessCache();

      return { success: true as const };
    } catch (error) {
      rethrowCoded(error);
      logger.error("Error deleting access group:", describeDbError(error));
      return {
        success: false as const,
        message:
          error instanceof Error ? error.message : "Internal server error",
      };
    }
  },

  addMember: async (
    input: z.infer<typeof AccessGroupMemberRequestSchema>,
    actor?: AuditActor,
  ): Promise<z.infer<typeof AccessGroupMutationResponseSchema>> => {
    try {
      // Resolved before the insert so an unknown id reads as "user not found"
      // rather than as a foreign-key violation the dialog cannot interpret.
      const [group, user] = await Promise.all([
        accessGroupsRepository.findByUuid(input.group_uuid),
        usersRepository.findById(input.user_id),
      ]);
      if (!group) {
        return { success: false as const, message: "Access group not found" };
      }
      if (!user) {
        return { success: false as const, message: "User not found" };
      }

      const added = await withAdminAudit(
        actor,
        (...tx) =>
          accessGroupsRepository.addMember(
            input.group_uuid,
            input.user_id,
            ...tx,
          ),
        // No row when nothing was added: a row claiming a grant was made would
        // be false.
        (wasAdded) =>
          wasAdded
            ? {
                action: "group.member.add",
                target_type: "access_group",
                target_id: input.group_uuid,
                detail: {
                  group_name: clampAuditText(group.name, 100),
                  user_id: input.user_id,
                  user_email: clampAuditText(user.email, 320),
                },
              }
            : null,
      );

      if (!added) {
        // Already a member. Reported as success — the caller's intent holds —
        // but with no audit row, because nothing changed.
        return {
          success: true as const,
          message: "User is already a member of this group",
        };
      }

      invalidateEndpointAccessCache();

      return { success: true as const };
    } catch (error) {
      rethrowCoded(error);
      logger.error("Error adding access group member:", describeDbError(error));
      return {
        success: false as const,
        message:
          error instanceof Error ? error.message : "Internal server error",
      };
    }
  },

  removeMember: async (
    input: z.infer<typeof AccessGroupMemberRequestSchema>,
    actor?: AuditActor,
  ): Promise<z.infer<typeof AccessGroupMutationResponseSchema>> => {
    try {
      const group = await accessGroupsRepository.findByUuid(input.group_uuid);
      if (!group) {
        return { success: false as const, message: "Access group not found" };
      }

      const removed = await withAdminAudit(
        actor,
        (...tx) =>
          accessGroupsRepository.removeMember(
            input.group_uuid,
            input.user_id,
            ...tx,
          ),
        (wasRemoved) =>
          wasRemoved
            ? {
                action: "group.member.remove",
                target_type: "access_group",
                target_id: input.group_uuid,
                detail: {
                  group_name: clampAuditText(group.name, 100),
                  user_id: input.user_id,
                },
              }
            : null,
      );

      if (!removed) {
        return {
          success: false as const,
          message: "User is not a member of this group",
        };
      }

      // THE REVOCATION PATH. Without this the removed user keeps being served
      // for the rest of the decision TTL, which is exactly the window an
      // operator removing someone in a hurry cannot afford.
      invalidateEndpointAccessCache();

      return { success: true as const };
    } catch (error) {
      rethrowCoded(error);
      logger.error(
        "Error removing access group member:",
        describeDbError(error),
      );
      return {
        success: false as const,
        message:
          error instanceof Error ? error.message : "Internal server error",
      };
    }
  },

  addEndpoint: async (
    input: z.infer<typeof AccessGroupEndpointRequestSchema>,
    actor?: AuditActor,
  ): Promise<z.infer<typeof AccessGroupMutationResponseSchema>> => {
    try {
      const [group, endpoint] = await Promise.all([
        accessGroupsRepository.findByUuid(input.group_uuid),
        endpointsRepository.findByUuid(input.endpoint_uuid),
      ]);
      if (!group) {
        return { success: false as const, message: "Access group not found" };
      }
      if (!endpoint) {
        return { success: false as const, message: "Endpoint not found" };
      }

      const added = await withAdminAudit(
        actor,
        (...tx) =>
          accessGroupsRepository.addEndpoint(
            input.group_uuid,
            input.endpoint_uuid,
            ...tx,
          ),
        (wasAdded) =>
          wasAdded
            ? {
                action: "group.endpoint.add",
                target_type: "access_group",
                target_id: input.group_uuid,
                detail: {
                  group_name: clampAuditText(group.name, 100),
                  endpoint_uuid: input.endpoint_uuid,
                  endpoint_name: clampAuditText(endpoint.name, 100),
                  // Whether the grant does anything yet. A mapping onto an
                  // endpoint that has not opted in is legal and inert, and a
                  // reader of this row should not have to join against
                  // `endpoints` to find that out.
                  endpoint_restricted: endpoint.restricted,
                },
              }
            : null,
      );

      if (!added) {
        return {
          success: true as const,
          message: "Endpoint is already mapped to this group",
        };
      }

      invalidateEndpointAccessCache();

      return { success: true as const };
    } catch (error) {
      rethrowCoded(error);
      logger.error(
        "Error mapping endpoint to access group:",
        describeDbError(error),
      );
      return {
        success: false as const,
        message:
          error instanceof Error ? error.message : "Internal server error",
      };
    }
  },

  removeEndpoint: async (
    input: z.infer<typeof AccessGroupEndpointRequestSchema>,
    actor?: AuditActor,
  ): Promise<z.infer<typeof AccessGroupMutationResponseSchema>> => {
    try {
      const group = await accessGroupsRepository.findByUuid(input.group_uuid);
      if (!group) {
        return { success: false as const, message: "Access group not found" };
      }

      const removed = await withAdminAudit(
        actor,
        (...tx) =>
          accessGroupsRepository.removeEndpoint(
            input.group_uuid,
            input.endpoint_uuid,
            ...tx,
          ),
        (wasRemoved) =>
          wasRemoved
            ? {
                action: "group.endpoint.remove",
                target_type: "access_group",
                target_id: input.group_uuid,
                detail: {
                  group_name: clampAuditText(group.name, 100),
                  endpoint_uuid: input.endpoint_uuid,
                },
              }
            : null,
      );

      if (!removed) {
        return {
          success: false as const,
          message: "Endpoint is not mapped to this group",
        };
      }

      invalidateEndpointAccessCache();

      return { success: true as const };
    } catch (error) {
      rethrowCoded(error);
      logger.error(
        "Error unmapping endpoint from access group:",
        describeDbError(error),
      );
      return {
        success: false as const,
        message:
          error instanceof Error ? error.message : "Internal server error",
      };
    }
  },

  setEndpointRestricted: async (
    input: z.infer<typeof SetEndpointRestrictedRequestSchema>,
    actor?: AuditActor,
  ): Promise<z.infer<typeof AccessGroupMutationResponseSchema>> => {
    try {
      const existing = await endpointsRepository.findByUuid(
        input.endpoint_uuid,
      );
      if (!existing) {
        return { success: false as const, message: "Endpoint not found" };
      }

      // One transaction for every actor. Under the endpoint's namespace lock
      // the row is re-read FOR UPDATE and the endpoint namespace gate judges
      // an actual opening (restricted to unrestricted) against the namespace's
      // other endpoints and, for an admin-plane key, against the provenance of
      // the current restriction (lib/endpoint-namespace-gate). The write keeps
      // that provenance marker true to the current restriction.
      const actorKeyUuid = actor?.admin_plane?.key_uuid.toLowerCase() ?? null;
      const outcome = await withAdminAuditTx(
        actor,
        async (tx) => {
          await endpointGateRepository.lockNamespaces(tx, [
            existing.namespace_uuid,
          ]);
          const locked = await endpointGateRepository.lockEndpoint(
            tx,
            input.endpoint_uuid,
          );
          if (
            !locked ||
            locked.namespace_uuid.toLowerCase() !==
              existing.namespace_uuid.toLowerCase()
          ) {
            const { code, message } = ENDPOINT_GATE_REFUSALS.endpoint_changed;
            throw new AdminRuleRefusal(code, message, {
              action: "endpoint.restricted.set",
              target_type: "endpoint",
              target_id: input.endpoint_uuid.toLowerCase(),
              detail: { rule: "endpoint_changed" },
            });
          }
          if (locked.restricted && input.restricted === false) {
            const restrictedSibling =
              await endpointGateRepository.restrictedSiblingExists(
                tx,
                locked.namespace_uuid,
                locked.uuid,
              );
            const rule = judgeEndpointUnrestrict({
              adminPlane: actorKeyUuid !== null,
              restrictedSibling,
              rollbackEligible: isOwnRecentRestriction(locked, actorKeyUuid),
            });
            if (rule) {
              const { code, message } = ENDPOINT_GATE_REFUSALS[rule];
              throw new AdminRuleRefusal(code, message, {
                action: "endpoint.restricted.set",
                target_type: "endpoint",
                target_id: locked.uuid,
                detail: { rule },
              });
            }
          }
          const endpoint = await endpointGateRepository.setRestricted(
            tx,
            locked.uuid,
            input.restricted,
            actorKeyUuid,
          );
          return endpoint ? { endpoint, previous: locked.restricted } : null;
        },
        (written) =>
          written
            ? {
                action: "endpoint.restricted.set",
                target_type: "endpoint",
                target_id: written.endpoint.uuid,
                detail: {
                  name: clampAuditText(written.endpoint.name, 100),
                  // Both values, because "who turned this on" and "what was it
                  // before" are the two questions asked of this row, and a
                  // single new value only answers the first. The previous
                  // value is the one read under the row lock.
                  previous: written.previous,
                  restricted: written.endpoint.restricted,
                  // The stored value, unchanged by this write: restricting an
                  // endpoint does not touch the scoped-key requirement, and the
                  // row records which of the two switches was on at that moment.
                  require_scoped_api_key:
                    written.endpoint.require_scoped_api_key,
                },
              }
            : null,
      );
      const updated = outcome?.endpoint;
      if (!updated) {
        return { success: false as const, message: "Endpoint not found" };
      }

      // Required in BOTH directions. Turning the gate off is obvious; turning
      // it on matters too, because decisions cached during an earlier
      // restricted period are keyed on (user, endpoint) and carry no record of
      // the gate's state, so they would be reused against the new mapping.
      invalidateEndpointAccessCache();

      return { success: true as const };
    } catch (error) {
      rethrowCoded(error);
      logger.error(
        "Error setting endpoint restriction:",
        describeDbError(error),
      );
      return {
        success: false as const,
        message:
          error instanceof Error ? error.message : "Internal server error",
      };
    }
  },
};
