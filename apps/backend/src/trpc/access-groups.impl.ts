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
import { z } from "zod";

import logger from "@/utils/logger";

import { accessGroupsRepository } from "../db/repositories/access-groups.repo";
import { endpointsRepository } from "../db/repositories/endpoints.repo";
import { usersRepository } from "../db/repositories/users.repo";
import { emitAdminEvent } from "../lib/audit/admin-event";
import { clampAuditText } from "../lib/audit/audit-emitter";
import { invalidateEndpointAccessCache } from "../lib/endpoint-access-control";

/**
 * Admin CRUD over access groups and the per-endpoint gate they drive
 * (migration 0033).
 *
 * EVERY MUTATION HERE INVALIDATES THE DECISION CACHE, unconditionally, on the
 * success path. Uniform rather than "only the ones that can change an answer":
 * `create` and `update` cannot change one today, but a later change that lets
 * `create` seed members would silently inherit a missing invalidation, and the
 * cost of over-invalidating is a cold cache and one extra round trip per key.
 * The failure mode of under-invalidating is a revoked user still being served
 * for up to a minute. See `lib/endpoint-access-control`.
 *
 * EVERY MUTATION HERE EMITS. These grants are the authorization boundary for
 * OAuth callers, so who was added to what, and when an endpoint's gate was
 * switched on, must be answerable from `audit_log` and not from inference.
 * Emitted AFTER the write and BELOW every early return, so a mutation that
 * matched nothing leaves no row claiming it did.
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
      logger.error("Error listing access groups:", error);
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
      logger.error("Error fetching access group:", error);
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
      logger.error("Error listing endpoints for access groups:", error);
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
          groups,
        },
      };
    } catch (error) {
      logger.error("Error fetching endpoint access:", error);
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

      const created = await accessGroupsRepository.create({
        name: input.name,
        description: input.description ?? null,
      });

      invalidateEndpointAccessCache();

      emitAdminEvent(actor, {
        action: "group.create",
        target_type: "access_group",
        target_id: created.uuid,
        detail: { name: clampAuditText(created.name, 100) },
      });

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
      logger.error("Error creating access group:", error);
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

      const updated = await accessGroupsRepository.update({
        uuid: input.uuid,
        name: input.name,
        description: input.description ?? null,
      });

      if (!updated) {
        return { success: false as const, message: "Access group not found" };
      }

      invalidateEndpointAccessCache();

      emitAdminEvent(actor, {
        action: "group.update",
        target_type: "access_group",
        target_id: updated.uuid,
        detail: { name: clampAuditText(updated.name, 100) },
      });

      return { success: true as const };
    } catch (error) {
      logger.error("Error updating access group:", error);
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
      const deleted = await accessGroupsRepository.deleteByUuid(input.uuid);
      if (!deleted) {
        return { success: false as const, message: "Access group not found" };
      }

      // Deleting a group revokes every grant it carried (both mapping tables
      // cascade), so the cache must drop before the next request is served.
      invalidateEndpointAccessCache();

      emitAdminEvent(actor, {
        action: "group.delete",
        target_type: "access_group",
        target_id: input.uuid,
        detail: { name: clampAuditText(deleted.name, 100) },
      });

      return { success: true as const };
    } catch (error) {
      logger.error("Error deleting access group:", error);
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

      const added = await accessGroupsRepository.addMember(
        input.group_uuid,
        input.user_id,
      );

      if (!added) {
        // Already a member. Reported as success — the caller's intent holds —
        // but with no audit row, because nothing changed and a row claiming a
        // grant was made would be false.
        return {
          success: true as const,
          message: "User is already a member of this group",
        };
      }

      invalidateEndpointAccessCache();

      emitAdminEvent(actor, {
        action: "group.member.add",
        target_type: "access_group",
        target_id: input.group_uuid,
        detail: {
          group_name: clampAuditText(group.name, 100),
          user_id: input.user_id,
          user_email: clampAuditText(user.email, 320),
        },
      });

      return { success: true as const };
    } catch (error) {
      logger.error("Error adding access group member:", error);
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

      const removed = await accessGroupsRepository.removeMember(
        input.group_uuid,
        input.user_id,
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

      emitAdminEvent(actor, {
        action: "group.member.remove",
        target_type: "access_group",
        target_id: input.group_uuid,
        detail: {
          group_name: clampAuditText(group.name, 100),
          user_id: input.user_id,
        },
      });

      return { success: true as const };
    } catch (error) {
      logger.error("Error removing access group member:", error);
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

      const added = await accessGroupsRepository.addEndpoint(
        input.group_uuid,
        input.endpoint_uuid,
      );

      if (!added) {
        return {
          success: true as const,
          message: "Endpoint is already mapped to this group",
        };
      }

      invalidateEndpointAccessCache();

      emitAdminEvent(actor, {
        action: "group.endpoint.add",
        target_type: "access_group",
        target_id: input.group_uuid,
        detail: {
          group_name: clampAuditText(group.name, 100),
          endpoint_uuid: input.endpoint_uuid,
          endpoint_name: clampAuditText(endpoint.name, 100),
          // Whether the grant does anything yet. A mapping onto an endpoint
          // that has not opted in is legal and inert, and a reader of this row
          // should not have to join against `endpoints` to find that out.
          endpoint_restricted: endpoint.restricted,
        },
      });

      return { success: true as const };
    } catch (error) {
      logger.error("Error mapping endpoint to access group:", error);
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

      const removed = await accessGroupsRepository.removeEndpoint(
        input.group_uuid,
        input.endpoint_uuid,
      );

      if (!removed) {
        return {
          success: false as const,
          message: "Endpoint is not mapped to this group",
        };
      }

      invalidateEndpointAccessCache();

      emitAdminEvent(actor, {
        action: "group.endpoint.remove",
        target_type: "access_group",
        target_id: input.group_uuid,
        detail: {
          group_name: clampAuditText(group.name, 100),
          endpoint_uuid: input.endpoint_uuid,
        },
      });

      return { success: true as const };
    } catch (error) {
      logger.error("Error unmapping endpoint from access group:", error);
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

      const updated = await accessGroupsRepository.setEndpointRestricted(
        input.endpoint_uuid,
        input.restricted,
      );
      if (!updated) {
        return { success: false as const, message: "Endpoint not found" };
      }

      // Required in BOTH directions. Turning the gate off is obvious; turning
      // it on matters too, because decisions cached during an earlier
      // restricted period are keyed on (user, endpoint) and carry no record of
      // the gate's state, so they would be reused against the new mapping.
      invalidateEndpointAccessCache();

      emitAdminEvent(actor, {
        action: "endpoint.restricted.set",
        target_type: "endpoint",
        target_id: updated.uuid,
        detail: {
          name: clampAuditText(updated.name, 100),
          // Both values, because "who turned this on" and "what was it before"
          // are the two questions asked of this row, and a single new value
          // only answers the first.
          previous: existing.restricted,
          restricted: updated.restricted,
        },
      });

      return { success: true as const };
    } catch (error) {
      logger.error("Error setting endpoint restriction:", error);
      return {
        success: false as const,
        message:
          error instanceof Error ? error.message : "Internal server error",
      };
    }
  },
};
