import { createHash } from "node:crypto";

import type { AuditActor } from "@repo/trpc";
import {
  ENDPOINT_INSTRUCTIONS_MAX,
  ENDPOINT_TITLE_MAX,
  type EndpointPresentation,
  GetEndpointPresentationRequestSchema,
  GetEndpointPresentationResponseSchema,
  SetEndpointPresentationRequestSchema,
  SetEndpointPresentationResponseSchema,
} from "@repo/zod-types";
import { z } from "zod";

import logger from "@/utils/logger";

import {
  endpointPresentationRepository,
  type EndpointPresentationRow,
} from "../db/repositories/endpoint-presentation.repo";
import { endpointsRepository } from "../db/repositories/endpoints.repo";
import { emitAdminEvent } from "../lib/audit/admin-event";
import { clampAuditText } from "../lib/audit/audit-emitter";
import { describeDbError } from "../lib/db-error-summary";
import {
  leanListingEnabled,
  presentationEnabled,
} from "../lib/metamcp/endpoint-presentation";

/**
 * Admin read and write of an endpoint's presentation settings (migration 0044).
 *
 * HUMAN ADMINISTRATOR ONLY, and that is decided by where the procedures are
 * registered, not by anything in here: they are `adminProcedure`s in neither
 * admin-plane procedure set, so an admin-plane key of either scope is refused
 * before this module runs (`packages/trpc/src/routers/frontend/endpoint-
 * presentation.ts`). The title and the instructions reach models.
 *
 * Ownership follows `endpoints.update`: allowed when the endpoint is public or
 * the caller owns it.
 *
 * NO CACHE AND NO POOL INVALIDATION. Sessions are pinned to what they were
 * created with and idle pool shells never carry presentation, so a saved
 * change reaches only sessions that start afterwards. Nothing here has to
 * reach into a live one.
 */

/** The same message `endpoints.update` gives a non-owner. */
const NOT_OWNER_MESSAGE =
  "Access denied: You can only change settings of endpoints you own";

type GetResponse = z.infer<typeof GetEndpointPresentationResponseSchema>;
type SetResponse = z.infer<typeof SetEndpointPresentationResponseSchema>;

/** What an endpoint with no row presents: every setting at its default. */
function defaultsFor(endpointUuid: string): EndpointPresentation {
  return {
    endpoint_uuid: endpointUuid,
    title: null,
    instructions: null,
    tool_listing: "full",
    omit_output_schemas: false,
    updated_at: null,
  };
}

function toWire(
  endpointUuid: string,
  row: EndpointPresentationRow | undefined,
): EndpointPresentation {
  if (!row) return defaultsFor(endpointUuid);
  return {
    endpoint_uuid: row.endpoint_uuid,
    title: row.title,
    instructions: row.instructions,
    tool_listing: row.tool_listing,
    omit_output_schemas: row.omit_output_schemas,
    updated_at: row.updated_at.toISOString(),
  };
}

export const endpointPresentationImplementations = {
  get: async (
    input: z.infer<typeof GetEndpointPresentationRequestSchema>,
    userId: string,
  ): Promise<GetResponse> => {
    try {
      const endpoint = await endpointsRepository.findByUuid(
        input.endpoint_uuid,
      );
      if (!endpoint) {
        return { success: false as const, message: "Endpoint not found" };
      }
      if (endpoint.user_id && endpoint.user_id !== userId) {
        return { success: false as const, message: NOT_OWNER_MESSAGE };
      }

      const row = await endpointPresentationRepository.findByEndpointUuid(
        endpoint.uuid,
      );
      return {
        success: true as const,
        data: {
          ...toWire(endpoint.uuid, row),
          // What the gateway will actually do, so the panel can say so when a
          // process-level kill switch makes a saved setting inert.
          effective: {
            presentation_enabled: presentationEnabled(),
            lean_enabled: leanListingEnabled(),
          },
        },
      };
    } catch (error) {
      logger.error(
        "Error reading endpoint presentation:",
        describeDbError(error),
      );
      return {
        success: false as const,
        message: "Failed to read endpoint presentation",
      };
    }
  },

  set: async (
    input: z.infer<typeof SetEndpointPresentationRequestSchema>,
    userId: string,
    actor?: AuditActor,
  ): Promise<SetResponse> => {
    try {
      // The router has already parsed this with the same schema. Parsed again
      // here because this function is the write boundary: whoever calls it, a
      // text is normalized and bounded before it can reach the database, and
      // the database CHECKs stay a backstop rather than the first refusal.
      const parsed = SetEndpointPresentationRequestSchema.safeParse(input);
      if (!parsed.success) {
        return {
          success: false as const,
          message:
            parsed.error.issues[0]?.message ?? "Invalid presentation settings",
        };
      }
      const next = parsed.data;

      const endpoint = await endpointsRepository.findByUuid(next.endpoint_uuid);
      if (!endpoint) {
        return { success: false as const, message: "Endpoint not found" };
      }
      if (endpoint.user_id && endpoint.user_id !== userId) {
        return { success: false as const, message: NOT_OWNER_MESSAGE };
      }

      const previous = await endpointPresentationRepository.findByEndpointUuid(
        endpoint.uuid,
      );

      // A row exists only while something is non-default, so "no row" is
      // provably today's behaviour. Setting everything back to default
      // therefore deletes it instead of storing a row of defaults.
      const allDefault =
        next.title === null &&
        next.instructions === null &&
        next.tool_listing === "full" &&
        !next.omit_output_schemas;

      let saved: EndpointPresentationRow | undefined;
      if (allDefault) {
        await endpointPresentationRepository.deleteByEndpointUuid(
          endpoint.uuid,
        );
      } else {
        saved = await endpointPresentationRepository.upsert({
          endpoint_uuid: endpoint.uuid,
          title: next.title,
          instructions: next.instructions,
          tool_listing: next.tool_listing,
          omit_output_schemas: next.omit_output_schemas,
        });
      }

      // Emitted AFTER the write. The text is kept in the audit log on purpose
      // (it is non-secret by contract, the panel says so, and it answers "what
      // were models told on that date"); audit_log is immutable, so it is
      // bounded here as everywhere. It never goes to a log line.
      emitAdminEvent(actor, {
        action: "endpoint.presentation.set",
        target_type: "endpoint",
        target_id: endpoint.uuid,
        detail: {
          name: clampAuditText(endpoint.name, 100),
          tool_listing: next.tool_listing,
          omit_output_schemas: next.omit_output_schemas,
          title:
            next.title === null
              ? null
              : clampAuditText(next.title, ENDPOINT_TITLE_MAX),
          instructions:
            next.instructions === null
              ? null
              : clampAuditText(next.instructions, ENDPOINT_INSTRUCTIONS_MAX),
          instructions_length: next.instructions?.length ?? 0,
          instructions_sha256_prefix:
            next.instructions === null
              ? null
              : createHash("sha256")
                  .update(next.instructions)
                  .digest("hex")
                  .slice(0, 16),
          previous: {
            tool_listing: previous?.tool_listing ?? "full",
            omit_output_schemas: previous?.omit_output_schemas ?? false,
            title:
              previous?.title == null
                ? null
                : clampAuditText(previous.title, ENDPOINT_TITLE_MAX),
            instructions:
              previous?.instructions == null
                ? null
                : clampAuditText(
                    previous.instructions,
                    ENDPOINT_INSTRUCTIONS_MAX,
                  ),
          },
        },
      });

      return {
        success: true as const,
        data: toWire(endpoint.uuid, saved),
      };
    } catch (error) {
      // Drizzle errors include bound values in their message and params, so
      // only a log-safe summary is logged:
      // the failure stays diagnosable without copying administrator text.
      logger.error(
        `Error saving endpoint presentation: ${describeDbError(error)}`,
      );
      return {
        success: false as const,
        message: "Failed to save endpoint presentation",
      };
    }
  },
};
