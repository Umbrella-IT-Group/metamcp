import type { AuditActor } from "@repo/trpc";
import {
  CreateToolRequestSchema,
  CreateToolResponseSchema,
  GetToolsByMcpServerUuidRequestSchema,
  GetToolsByMcpServerUuidResponseSchema,
} from "@repo/zod-types";
import { z } from "zod";

import logger from "@/utils/logger";

import { mcpServersRepository, toolsRepository } from "../db/repositories";
import { ToolsSerializer } from "../db/serializers";
import { emitAdminEvent } from "../lib/audit/admin-event";
import { toolsSyncCache } from "../lib/metamcp/tools-sync-cache";

/**
 * AUDITING NOTE for this file. Both writes below emit only when the database
 * was actually touched — `create` skips the empty-input branch and `sync`
 * skips the "tools unchanged" branch. These two procedures are called by the
 * inspector and the server detail pages on every refresh, so emitting on the
 * no-op branches would put an admin-triggered, unbounded stream of rows that
 * record nothing into the same table an investigation is read from. A row here
 * means the shared tools catalog for an MCP server changed.
 */

export const toolsImplementations = {
  getByMcpServerUuid: async (
    input: z.infer<typeof GetToolsByMcpServerUuidRequestSchema>,
    userId: string,
  ): Promise<z.infer<typeof GetToolsByMcpServerUuidResponseSchema>> => {
    try {
      // Scope the catalog the same way `mcpServers.get` scopes the server
      // itself: a private server (user_id set) is readable only by its owner,
      // public servers (no user_id) stay readable to any member. The tool
      // catalog (names, descriptions, input schemas) is the same per-user
      // disclosure surface, so it must gate on ownership before returning —
      // otherwise a member who obtains a private server's UUID can read
      // another user's tools. Admins are not exempted here, matching
      // mcpServers.get.
      const server = await mcpServersRepository.findByUuid(input.mcpServerUuid);
      if (server && server.user_id && server.user_id !== userId) {
        return {
          success: false as const,
          data: [],
          message:
            "Access denied: You can only view tools for servers you own or public servers",
        };
      }

      const tools = await toolsRepository.findByMcpServerUuid(
        input.mcpServerUuid,
      );

      return {
        success: true as const,
        data: ToolsSerializer.serializeToolList(tools),
        message: "Tools retrieved successfully",
      };
    } catch (error) {
      logger.error("Error fetching tools by MCP server UUID:", error);
      return {
        success: false as const,
        data: [],
        message: "Failed to fetch tools",
      };
    }
  },

  create: async (
    input: z.infer<typeof CreateToolRequestSchema>,
    actor?: AuditActor,
  ): Promise<z.infer<typeof CreateToolResponseSchema>> => {
    try {
      if (!input.tools || input.tools.length === 0) {
        return {
          success: true as const,
          count: 0,
          message: "No tools to save",
        };
      }

      const results = await toolsRepository.bulkUpsert({
        tools: input.tools,
        mcpServerUuid: input.mcpServerUuid,
      });

      emitAdminEvent(actor, {
        action: "tools.create",
        target_type: "mcp_server",
        target_id: input.mcpServerUuid,
        detail: { upserted: results.length },
      });

      return {
        success: true as const,
        count: results.length,
        message: `Successfully saved ${results.length} tools`,
      };
    } catch (error) {
      logger.error("Error saving tools to database:", error);
      return {
        success: false as const,
        count: 0,
        error: error instanceof Error ? error.message : "Internal server error",
      };
    }
  },

  /**
   * Smart sync with hash-check and cleanup
   * Only syncs if tools have actually changed (performance optimized)
   */
  sync: async (
    input: z.infer<typeof CreateToolRequestSchema>,
    actor?: AuditActor,
  ): Promise<z.infer<typeof CreateToolResponseSchema>> => {
    try {
      if (!input.tools || input.tools.length === 0) {
        return {
          success: true as const,
          count: 0,
          message: "No tools to sync",
        };
      }

      // Check if tools changed using a hash over the FULL definitions
      // (name + description + inputSchema) — a schema/description-only change
      // keeps names identical, so a name-only hash would skip the sync.
      const hasChanged = toolsSyncCache.hasChanged(
        input.mcpServerUuid,
        input.tools,
      );

      if (hasChanged) {
        // Update cache with the full definitions
        toolsSyncCache.update(input.mcpServerUuid, input.tools);

        // Perform sync with cleanup
        const { upserted, deleted } = await toolsRepository.syncTools({
          tools: input.tools,
          mcpServerUuid: input.mcpServerUuid,
        });

        const message =
          deleted.length > 0
            ? `Successfully synced ${upserted.length} tools (removed ${deleted.length} obsolete)`
            : `Successfully synced ${upserted.length} tools`;

        emitAdminEvent(actor, {
          action: "tools.sync",
          target_type: "mcp_server",
          target_id: input.mcpServerUuid,
          detail: { upserted: upserted.length, deleted: deleted.length },
        });

        return {
          success: true as const,
          count: upserted.length,
          message,
        };
      } else {
        return {
          success: true as const,
          count: input.tools.length,
          message: "Tools unchanged, skipped sync",
        };
      }
    } catch (error) {
      console.error("Error syncing tools to database:", error);
      return {
        success: false as const,
        count: 0,
        error: error instanceof Error ? error.message : "Internal server error",
      };
    }
  },
};
