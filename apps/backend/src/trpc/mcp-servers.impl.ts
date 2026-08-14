import type { AuditActor } from "@repo/trpc";
import {
  BulkImportMcpServersRequestSchema,
  BulkImportMcpServersResponseSchema,
  CreateMcpServerRequestSchema,
  CreateMcpServerResponseSchema,
  DeleteMcpServerResponseSchema,
  GetMcpServerResponseSchema,
  ListMcpServersResponseSchema,
  McpServerTypeEnum,
  ReconnectMcpServerRequestSchema,
  ReconnectMcpServerResponseSchema,
  UpdateMcpServerRequestSchema,
  UpdateMcpServerResponseSchema,
} from "@repo/zod-types";
import { z } from "zod";

import logger from "@/utils/logger";

import {
  mcpServersRepository,
  namespaceMappingsRepository,
} from "../db/repositories";
import { McpServersSerializer } from "../db/serializers";
import { emitAdminEvent } from "../lib/audit/admin-event";
import { clampAuditTextList } from "../lib/audit/audit-emitter";
import { mcpServerPool } from "../lib/metamcp/mcp-server-pool";
import { clearOverrideCache } from "../lib/metamcp/metamcp-middleware/tool-overrides.functional";
import { metaMcpServerPool } from "../lib/metamcp/metamcp-server-pool";
import { serverErrorTracker } from "../lib/metamcp/server-error-tracker";
import { convertDbServerToParams } from "../lib/metamcp/utils";

export const mcpServersImplementations = {
  create: async (
    input: z.infer<typeof CreateMcpServerRequestSchema>,
    userId: string,
    actor?: AuditActor,
  ): Promise<z.infer<typeof CreateMcpServerResponseSchema>> => {
    try {
      // Determine user ownership based on input.user_id or default to current user
      const effectiveUserId =
        input.user_id !== undefined ? input.user_id : null;

      const createdServer = await mcpServersRepository.create({
        ...input,
        user_id: effectiveUserId,
      });

      if (!createdServer) {
        return {
          success: false as const,
          message: "Failed to create MCP server",
        };
      }

      // Ensure idle session for the newly created server (async)
      const serverParams = await convertDbServerToParams(createdServer);
      if (serverParams) {
        mcpServerPool
          .ensureIdleSessionForNewServer(createdServer.uuid, serverParams)
          .then(() => {
            logger.info(
              `Ensured idle session for newly created server: ${createdServer.name} (${createdServer.uuid})`,
            );
          })
          .catch((error) => {
            logger.error(
              `Error ensuring idle session for newly created server ${createdServer.name} (${createdServer.uuid}):`,
              error,
            );
          });
      }

      // SECRETS. An MCP server row carries the VENDOR credentials this
      // gateway uses to reach a third party — `bearerToken`, `env`, and
      // `headers` (which is where an API key lives for an HTTP backend). None
      // of the three appears here, and none may be added: `audit_log` is
      // append-only and un-clearable by design, so a credential written into
      // it cannot be taken back out. Identity and transport only.
      emitAdminEvent(actor, {
        action: "mcpserver.create",
        target_type: "mcp_server",
        target_id: createdServer.uuid,
        detail: {
          name: createdServer.name,
          type: createdServer.type,
          owner_user_id: effectiveUserId,
        },
      });

      return {
        success: true as const,
        // create is adminProcedure — the caller is an admin by construction,
        // and the dialog echoes the values it just submitted.
        data: McpServersSerializer.serializeMcpServer(createdServer, true),
        message: "MCP server created successfully",
      };
    } catch (error) {
      logger.error("Error creating MCP server:", error);
      return {
        success: false as const,
        message:
          error instanceof Error ? error.message : "Internal server error",
      };
    }
  },

  list: async (
    userId: string,
    isAdmin: boolean,
  ): Promise<z.infer<typeof ListMcpServersResponseSchema>> => {
    try {
      // Find servers accessible to user (public + user's own)
      const servers =
        await mcpServersRepository.findAllAccessibleToUser(userId);

      return {
        success: true as const,
        // protectedProcedure: members reach this. Redaction, not an RBAC
        // gate — the member dashboard still lists every server it could
        // before, minus the connection URL and credential material.
        data: McpServersSerializer.serializeMcpServerList(servers, isAdmin),
        message: "MCP servers retrieved successfully",
      };
    } catch (error) {
      logger.error("Error fetching MCP servers:", error);
      return {
        success: false as const,
        data: [],
        message: "Failed to fetch MCP servers",
      };
    }
  },

  bulkImport: async (
    input: z.infer<typeof BulkImportMcpServersRequestSchema>,
    userId: string,
    actor?: AuditActor,
  ): Promise<z.infer<typeof BulkImportMcpServersResponseSchema>> => {
    try {
      const serversToInsert = [];
      const errors: string[] = [];
      let imported = 0;

      for (const [serverName, serverConfig] of Object.entries(
        input.mcpServers,
      )) {
        try {
          // Validate server name format
          if (!/^[a-zA-Z0-9_-]+$/.test(serverName)) {
            throw new Error(
              `Server name "${serverName}" is invalid. Server names must only contain letters, numbers, underscores, and hyphens.`,
            );
          }

          // Provide default type if not specified
          const serverWithDefaults = {
            name: serverName,
            type: serverConfig.type || ("STDIO" as const),
            description: serverConfig.description || null,
            command: serverConfig.command || null,
            args: serverConfig.args || [],
            env: serverConfig.env || {},
            url: serverConfig.url || null,
            bearerToken: undefined,
            headers: serverConfig.headers || {},
            user_id: userId, // Default bulk imported servers to current user
          };

          serversToInsert.push(serverWithDefaults);
        } catch (error) {
          errors.push(
            `Failed to process server "${serverName}": ${error instanceof Error ? error.message : "Unknown error"}`,
          );
        }
      }

      if (serversToInsert.length > 0) {
        const createdServers =
          await mcpServersRepository.bulkCreate(serversToInsert);
        imported = serversToInsert.length;

        // Ensure idle sessions for all imported servers (async)
        if (createdServers && createdServers.length > 0) {
          createdServers.forEach(async (server) => {
            try {
              const params = await convertDbServerToParams(server);
              if (params) {
                mcpServerPool
                  .ensureIdleSessionForNewServer(server.uuid, params)
                  .then(() => {
                    logger.info(
                      `Ensured idle session for bulk imported server: ${server.name} (${server.uuid})`,
                    );
                  })
                  .catch((error) => {
                    logger.error(
                      `Error ensuring idle session for bulk imported server ${server.name} (${server.uuid}):`,
                      error,
                    );
                  });
              }
            } catch (error) {
              logger.error(
                `Error processing idle session for bulk imported server ${server.name} (${server.uuid}):`,
                error,
              );
            }
          });
        }
      }

      // Guarded on a write having happened, like every other emit in this
      // change: if every entry fails the server-name check, `serversToInsert`
      // is empty, `bulkCreate` is never called, and a row here would claim an
      // import that did not occur.
      //
      // Server NAMES only, never the configs — a bulk import body is a JSON
      // blob of `env` and `headers`, i.e. the densest concentration of vendor
      // credentials this API accepts. Names answer "what appeared" without
      // copying any of it into an un-deletable table, and are clamped because
      // they are caller-supplied object keys with no length bound.
      if (imported > 0) {
        emitAdminEvent(actor, {
          action: "mcpserver.bulk_import",
          target_type: "mcp_server",
          detail: {
            imported,
            server_names: clampAuditTextList(
              serversToInsert.map((server) => server.name),
              50,
              128,
            ),
            error_count: errors.length,
          },
        });
      }

      return {
        success: true as const,
        imported,
        errors: errors.length > 0 ? errors : undefined,
        message: `Successfully imported ${imported} MCP servers${errors.length > 0 ? ` with ${errors.length} errors` : ""}`,
      };
    } catch (error) {
      logger.error("Error bulk importing MCP servers:", error);
      return {
        success: false as const,
        imported: 0,
        message:
          error instanceof Error
            ? error.message
            : "Internal server error during bulk import",
      };
    }
  },

  get: async (
    input: {
      uuid: string;
    },
    userId: string,
    isAdmin: boolean,
  ): Promise<z.infer<typeof GetMcpServerResponseSchema>> => {
    try {
      const server = await mcpServersRepository.findByUuid(input.uuid);

      // Check if user has access to this server (own server or public server)
      if (server && server.user_id && server.user_id !== userId) {
        return {
          success: false as const,
          message:
            "Access denied: You can only view servers you own or public servers",
        };
      }

      if (!server) {
        return {
          success: false as const,
          message: "MCP server not found",
        };
      }

      return {
        success: true as const,
        // protectedProcedure — same redaction contract as `list` above.
        data: McpServersSerializer.serializeMcpServer(server, isAdmin),
        message: "MCP server retrieved successfully",
      };
    } catch (error) {
      logger.error("Error fetching MCP server:", error);
      return {
        success: false as const,
        message: "Failed to fetch MCP server",
      };
    }
  },

  delete: async (
    input: {
      uuid: string;
    },
    userId: string,
    actor?: AuditActor,
  ): Promise<z.infer<typeof DeleteMcpServerResponseSchema>> => {
    try {
      // Check if server exists and user has permission to delete it
      const server = await mcpServersRepository.findByUuid(input.uuid);

      if (!server) {
        return {
          success: false as const,
          message: "MCP server not found",
        };
      }

      // Only server owner can delete their own servers, only admin can delete public servers
      if (server.user_id && server.user_id !== userId) {
        return {
          success: false as const,
          message: "Access denied: You can only delete servers you own",
        };
      }

      // Find affected namespaces before deleting the server
      const affectedNamespaceUuids =
        await namespaceMappingsRepository.findNamespacesByServerUuid(
          input.uuid,
        );

      // Clean up any idle sessions for this server
      await mcpServerPool.cleanupIdleSession(input.uuid);

      const deletedServer = await mcpServersRepository.deleteByUuid(input.uuid);

      if (!deletedServer) {
        return {
          success: false as const,
          message: "MCP server not found",
        };
      }

      // Invalidate idle MetaMCP servers for all affected namespaces (async)
      if (affectedNamespaceUuids.length > 0) {
        metaMcpServerPool
          .invalidateIdleServers(affectedNamespaceUuids)
          .then(() => {
            logger.info(
              `Invalidated idle MetaMCP servers for ${affectedNamespaceUuids.length} namespaces after deleting server: ${deletedServer.name} (${deletedServer.uuid})`,
            );
          })
          .catch((error) => {
            logger.error(
              `Error invalidating idle MetaMCP servers after deleting server ${deletedServer.uuid}:`,
              error,
            );
          });

        // Also invalidate OpenAPI sessions for affected namespaces
        metaMcpServerPool
          .invalidateOpenApiSessions(affectedNamespaceUuids)
          .then(() => {
            logger.info(
              `Invalidated OpenAPI sessions for ${affectedNamespaceUuids.length} namespaces after deleting server: ${deletedServer.name} (${deletedServer.uuid})`,
            );
          })
          .catch((error) => {
            logger.error(
              `Error invalidating OpenAPI sessions after deleting server ${deletedServer.uuid}:`,
              error,
            );
          });

        // Clear tool overrides cache for affected namespaces since server deletion affects tool availability
        affectedNamespaceUuids.forEach((namespaceUuid) => {
          clearOverrideCache(namespaceUuid);
        });
        logger.info(
          `Cleared tool overrides cache for ${affectedNamespaceUuids.length} namespaces after deleting server: ${deletedServer.name} (${deletedServer.uuid})`,
        );
      }

      emitAdminEvent(actor, {
        action: "mcpserver.delete",
        target_type: "mcp_server",
        target_id: deletedServer.uuid,
        detail: { name: deletedServer.name },
      });

      return {
        success: true as const,
        message: "MCP server deleted successfully",
      };
    } catch (error) {
      logger.error("Error deleting MCP server:", error);
      return {
        success: false as const,
        message:
          error instanceof Error ? error.message : "Internal server error",
      };
    }
  },

  update: async (
    input: z.infer<typeof UpdateMcpServerRequestSchema>,
    userId: string,
    actor?: AuditActor,
  ): Promise<z.infer<typeof UpdateMcpServerResponseSchema>> => {
    try {
      // Check if server exists and user has permission to update it
      const server = await mcpServersRepository.findByUuid(input.uuid);

      if (!server) {
        return {
          success: false as const,
          message: "MCP server not found",
        };
      }

      // Only server owner can update their own servers, only admin can update public servers
      if (server.user_id && server.user_id !== userId) {
        return {
          success: false as const,
          message: "Access denied: You can only update servers you own",
        };
      }

      // Determine user ownership based on input.user_id or keep existing ownership
      const effectiveUserId =
        input.user_id !== undefined ? input.user_id : server.user_id;

      const updatedServer = await mcpServersRepository.update({
        ...input,
        user_id: effectiveUserId,
      });

      if (!updatedServer) {
        return {
          success: false as const,
          message: "MCP server not found",
        };
      }

      // Reset error status for stdio servers when they are updated
      if (updatedServer.type === McpServerTypeEnum.enum.STDIO) {
        try {
          await serverErrorTracker.resetServerErrorState(updatedServer.uuid);
          logger.info(
            `Reset error status for updated stdio server: ${updatedServer.name} (${updatedServer.uuid})`,
          );
        } catch (error) {
          logger.error(
            `Error resetting error status for updated stdio server ${updatedServer.name} (${updatedServer.uuid}):`,
            error,
          );
        }
      }

      // Invalidate idle session for the updated server to refresh with new parameters (async)
      const serverParams = await convertDbServerToParams(updatedServer);
      if (serverParams) {
        mcpServerPool
          .invalidateIdleSession(updatedServer.uuid, serverParams)
          .then(() => {
            logger.info(
              `Invalidated and refreshed idle session for updated server: ${updatedServer.name} (${updatedServer.uuid})`,
            );
          })
          .catch((error) => {
            logger.error(
              `Error invalidating idle session for updated server ${updatedServer.name} (${updatedServer.uuid}):`,
              error,
            );
          });
      }

      // Find affected namespaces and invalidate their idle MetaMCP servers (async)
      const affectedNamespaceUuids =
        await namespaceMappingsRepository.findNamespacesByServerUuid(
          updatedServer.uuid,
        );

      if (affectedNamespaceUuids.length > 0) {
        metaMcpServerPool
          .invalidateIdleServers(affectedNamespaceUuids)
          .then(() => {
            logger.info(
              `Invalidated idle MetaMCP servers for ${affectedNamespaceUuids.length} namespaces after updating server: ${updatedServer.name} (${updatedServer.uuid})`,
            );
          })
          .catch((error) => {
            logger.error(
              `Error invalidating idle MetaMCP servers after updating server ${updatedServer.uuid}:`,
              error,
            );
          });

        // Also invalidate OpenAPI sessions for affected namespaces
        metaMcpServerPool
          .invalidateOpenApiSessions(affectedNamespaceUuids)
          .then(() => {
            logger.info(
              `Invalidated OpenAPI sessions for ${affectedNamespaceUuids.length} namespaces after updating server: ${updatedServer.name} (${updatedServer.uuid})`,
            );
          })
          .catch((error) => {
            logger.error(
              `Error invalidating OpenAPI sessions after updating server ${updatedServer.uuid}:`,
              error,
            );
          });

        // Clear tool overrides cache for affected namespaces since server update may affect tool availability
        affectedNamespaceUuids.forEach((namespaceUuid) => {
          clearOverrideCache(namespaceUuid);
        });
        logger.info(
          `Cleared tool overrides cache for ${affectedNamespaceUuids.length} namespaces after updating server: ${updatedServer.name} (${updatedServer.uuid})`,
        );
      }

      // Same credential ban as `create` above — an update is the call that
      // ROTATES a vendor token, so it is the likeliest place for one to leak
      // into a log.
      emitAdminEvent(actor, {
        action: "mcpserver.update",
        target_type: "mcp_server",
        target_id: updatedServer.uuid,
        detail: { name: updatedServer.name, type: updatedServer.type },
      });

      return {
        success: true as const,
        // update is adminProcedure — see the note on `create`.
        data: McpServersSerializer.serializeMcpServer(updatedServer, true),
        message: "MCP server updated successfully",
      };
    } catch (error) {
      logger.error("Error updating MCP server:", error);
      return {
        success: false as const,
        message:
          error instanceof Error ? error.message : "Internal server error",
      };
    }
  },

  reconnect: async (
    input: z.infer<typeof ReconnectMcpServerRequestSchema>,
    userId: string,
  ): Promise<z.infer<typeof ReconnectMcpServerResponseSchema>> => {
    try {
      // Check if server exists and user has permission to act on it
      const server = await mcpServersRepository.findByUuid(input.uuid);

      if (!server) {
        return {
          success: false as const,
          message: "MCP server not found",
        };
      }

      // Only server owner can reconnect their own servers, only admin can
      // reconnect public servers — same trust boundary as update/delete.
      if (server.user_id && server.user_id !== userId) {
        return {
          success: false as const,
          message: "Access denied: You can only reconnect servers you own",
        };
      }

      // Full pooled-connection cascade. Unlike the update path's
      // invalidateIdleSession (which rebuilds only the idle spare and leaves
      // live consumers on their stale connections), invalidateServerConnection
      // tears down EVERY active and idle slot for this serverUuid and fires
      // the list_changed subscribers, so a warm pooled connection still
      // serving its connect-time tool list after an upstream rename/add is
      // dropped and every downstream consumer re-lists on its next request.
      // This is the exact recovery cascade the transport-drop detector already
      // runs in prod; it creates no replacement — the next getSession
      // establishes a fresh connection (and fresh backend session) on demand.
      // The sessionId arg is logging-only; the cascade sweeps all sessions.
      await mcpServerPool.invalidateServerConnection(
        "<reconnect-trigger>",
        server.uuid,
      );

      // Clear the STDIO error circuit breaker so an ERROR-gated server can
      // actually rebuild on the next request — a gateway restart clears this
      // state too, and reconnect is the restart's replacement. Mirrors the
      // reset the active-session health sweep runs right after its own
      // invalidateServerConnection cascade. Best-effort: a reset failure must
      // not fail the reconnect (the connections are already dropped), so it is
      // logged, not thrown.
      await serverErrorTracker
        .resetServerErrorState(server.uuid)
        .catch((error) => {
          logger.error(
            `Error resetting error state during reconnect of ${server.name} (${server.uuid}):`,
            error,
          );
        });

      // Refresh the idle MetaMCP + OpenAPI aggregations and drop the tool
      // override caches for every namespace that includes this server, so the
      // aggregated endpoints re-list too. Best-effort fan-out: the primary
      // cascade above already dropped the connections and fired list_changed,
      // so a namespace-refresh failure is logged but does not fail the
      // reconnect.
      const affectedNamespaceUuids =
        await namespaceMappingsRepository.findNamespacesByServerUuid(
          server.uuid,
        );

      if (affectedNamespaceUuids.length > 0) {
        const [idleResult, openApiResult] = await Promise.allSettled([
          metaMcpServerPool.invalidateIdleServers(affectedNamespaceUuids),
          metaMcpServerPool.invalidateOpenApiSessions(affectedNamespaceUuids),
        ]);
        if (idleResult.status === "rejected") {
          logger.error(
            `Error invalidating idle MetaMCP servers during reconnect of ${server.uuid}:`,
            idleResult.reason,
          );
        }
        if (openApiResult.status === "rejected") {
          logger.error(
            `Error invalidating OpenAPI sessions during reconnect of ${server.uuid}:`,
            openApiResult.reason,
          );
        }

        affectedNamespaceUuids.forEach((namespaceUuid) => {
          clearOverrideCache(namespaceUuid);
        });
      }

      logger.info(
        `Reconnected MCP server ${server.name} (${server.uuid}): dropped ${affectedNamespaceUuids.length} namespace aggregation(s); tools re-list on next request`,
      );

      return {
        success: true as const,
        message: "Server reconnected — tools re-list on the next request",
      };
    } catch (error) {
      logger.error("Error reconnecting MCP server:", error);
      return {
        success: false as const,
        message:
          error instanceof Error ? error.message : "Internal server error",
      };
    }
  },
};
