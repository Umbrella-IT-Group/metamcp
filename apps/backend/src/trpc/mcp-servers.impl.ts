import type { AuditActor, ServerDetailLevel } from "@repo/trpc";
import {
  BulkImportMcpServersRequestSchema,
  BulkImportMcpServersResponseSchema,
  CreateMcpServerRequestSchema,
  CreateMcpServerResponseSchema,
  type DatabaseMcpServer,
  DeleteMcpServerResponseSchema,
  GetMcpServerResponseSchema,
  ListMcpServersResponseSchema,
  McpServerTypeEnum,
  ReconnectMcpServerRequestSchema,
  ReconnectMcpServerResponseSchema,
  ResetMcpServerErrorsRequestSchema,
  ResetMcpServerErrorsResponseSchema,
  UpdateMcpServerAnyRequestSchema,
  UpdateMcpServerMetadataRequestSchema,
  UpdateMcpServerResponseSchema,
} from "@repo/zod-types";
import { TRPCError } from "@trpc/server";
import { z } from "zod";

import { describeDbError } from "@/lib/db-error-summary";
import logger from "@/utils/logger";

import {
  mcpServersRepository,
  namespaceMappingsRepository,
} from "../db/repositories";
import {
  SERVER_NAME_TAKEN_MESSAGE,
  ServerNameTakenError,
} from "../db/repositories/mcp-server-name-rule";
import { ServerCredentialRetentionError } from "../db/repositories/mcp-server-update-plan";
import { McpServersSerializer } from "../db/serializers";
import { emitAdminEvent } from "../lib/audit/admin-event";
import {
  ADMIN_AUDIT_WRITE_FAILED_MESSAGE,
  AdminAuditWriteError,
  AdminRuleRefusal,
  recordDenialAfterRollback,
  withAdminAudit,
} from "../lib/audit/admin-write";
import { clampAuditTextList } from "../lib/audit/audit-emitter";
import {
  describeUpdate,
  MCP_SERVER_UPDATE_FIELDS,
} from "../lib/audit/before-state";
import { closeInspectorSessionsForServer } from "../lib/metamcp/inspector-sessions";
import { mcpServerPool } from "../lib/metamcp/mcp-server-pool";
import { clearOverrideCache } from "../lib/metamcp/metamcp-middleware/tool-overrides.functional";
import { metaMcpServerPool } from "../lib/metamcp/metamcp-server-pool";
import { resetServerErrors } from "../lib/metamcp/reset-server-errors";
import { serverErrorTracker } from "../lib/metamcp/server-error-tracker";
import {
  isStdioServerType,
  STDIO_SERVERS_DISABLED_MESSAGE,
  stdioServersAllowed,
} from "../lib/metamcp/stdio-policy";
import { convertDbServerToParams } from "../lib/metamcp/utils";
import { isVerifiedCallerHeaderName } from "../lib/metamcp/verified-caller";
import { topologyRemovalImplementations } from "./topology-removal.impl";

/**
 * The stdio policy gate for `create` and `update` (see
 * `lib/metamcp/stdio-policy.ts`). Called BEFORE each method's `try`: the broad
 * catch there turns any throw into `success: false` inside an HTTP 200, and a
 * policy refusal has to reach the client as a real BAD_REQUEST (HTTP 400).
 */
function refuseStdioServerUnlessAllowed(type: string | undefined): void {
  if (isStdioServerType(type) && !stdioServersAllowed()) {
    throw new TRPCError({
      code: "BAD_REQUEST",
      message: STDIO_SERVERS_DISABLED_MESSAGE,
    });
  }
}

/** How many refused bulk-import names the BAD_REQUEST message lists. */
const BULK_IMPORT_REFUSED_NAMES_SHOWN = 10;

/**
 * The stdio policy gate for `bulkImport`: the WHOLE request is refused, before
 * any row is written, when any entry is stdio or normalizes to stdio (no type,
 * an empty type, or a schema alias such as `std`, which the request schema
 * has already turned into "STDIO"). Refusing everything rather than importing
 * the HTTP/SSE entries keeps an import atomic: an administrator never has to
 * work out which half of a config landed. Called before the `try` for the
 * same reason as the gate above.
 */
function refuseStdioBulkImportUnlessAllowed(
  servers: z.infer<typeof BulkImportMcpServersRequestSchema>["mcpServers"],
): void {
  if (stdioServersAllowed()) return;
  const stdioNames = Object.entries(servers)
    .filter(([, config]) => isStdioServerType(config.type))
    .map(([name]) => name);
  if (stdioNames.length === 0) return;

  // Names are caller-supplied object keys with no length bound, so the list
  // is capped in count and length before it goes back in the message.
  const shown = stdioNames
    .slice(0, BULK_IMPORT_REFUSED_NAMES_SHOWN)
    .map((name) => JSON.stringify(name.slice(0, 64)))
    .join(", ");
  const more =
    stdioNames.length > BULK_IMPORT_REFUSED_NAMES_SHOWN
      ? ` and ${stdioNames.length - BULK_IMPORT_REFUSED_NAMES_SHOWN} more`
      : "";
  throw new TRPCError({
    code: "BAD_REQUEST",
    message:
      `${STDIO_SERVERS_DISABLED_MESSAGE} Nothing was imported. ` +
      `Entries that are stdio (an entry with no type is stdio): ${shown}${more}.`,
  });
}

/**
 * The refusal for a stored server header named `X-Umbrella-User-Id` or
 * `X-Umbrella-Caller`. One fixed sentence, so a client can match it.
 */
export const STORED_IDENTITY_HEADER_REFUSED =
  "X-Umbrella-User-Id and X-Umbrella-Caller are set by the gateway from the authenticated caller and cannot be stored as server headers. Remove them from the headers.";

function namesIdentityHeader(
  headers: Record<string, string> | undefined,
): boolean {
  return (
    headers !== undefined &&
    Object.keys(headers).some(isVerifiedCallerHeaderName)
  );
}

/**
 * Identity headers are gateway-set only (`lib/metamcp/verified-caller.ts`),
 * so `create` and `update` refuse either name as a stored header key, in any
 * casing and with surrounding whitespace ignored. Called before each method's
 * `try`, for the same reason as the stdio gate above.
 *
 * Rows that already store one are not rewritten here. The pooled transport
 * drops the stored copy on every connection (`storedHeadersForPool` in
 * `lib/metamcp/client.ts`), and so does the admin Inspector
 * (`storedHeadersFor` in `routers/mcp-proxy/server.ts`); an update that
 * leaves `headers` out keeps it inert, and one that sends it back is refused,
 * so it is removed on the next edit of the row's headers.
 */
function refuseStoredIdentityHeaders(
  headers: Record<string, string> | undefined,
): void {
  if (!namesIdentityHeader(headers)) return;
  throw new TRPCError({
    code: "BAD_REQUEST",
    message: STORED_IDENTITY_HEADER_REFUSED,
  });
}

/**
 * The same refusal for `bulkImport`: the WHOLE request is refused, before any
 * row is written, when any entry stores either header, so an import is never
 * half applied (as with the stdio gate).
 */
function refuseStoredIdentityHeadersInBulkImport(
  servers: z.infer<typeof BulkImportMcpServersRequestSchema>["mcpServers"],
): void {
  const named = Object.values(servers).some((config) =>
    namesIdentityHeader(config.headers),
  );
  if (!named) return;
  throw new TRPCError({
    code: "BAD_REQUEST",
    message: `${STORED_IDENTITY_HEADER_REFUSED} Nothing was imported.`,
  });
}

/**
 * The detail level a `create` or `update` reply carries, from the actor the
 * router built from the verified request context (`auditActor(ctx)`). Both
 * procedures are administrator-only, so an actor without admin-plane
 * provenance is a person signed in as an administrator, who sees the values
 * they just submitted. An admin-plane actor gets names only, and so does an
 * actor missing altogether (a direct call that did not come through a router):
 * no reply carries a stored connection by omission.
 */
function replyDetailFor(actor: AuditActor | undefined): ServerDetailLevel {
  return actor && !actor.admin_plane ? "full" : "names_only";
}

/**
 * The coded refusals of an operator-scope admin-plane key's attempt to create
 * a server or to change a server's connection. A server's address, command and
 * credentials are declared in the reviewed servers file and applied by the
 * configuration sync (sync scope); the operator scope keeps rename and
 * description (the metadata-only update variant). Fixed sentences, naming no
 * server and no value.
 */
export const OPERATOR_SERVER_REFUSALS = {
  operator_server_create: {
    code: "FORBIDDEN",
    message:
      "An operator-scope admin-plane API key cannot create an MCP server. A server is declared in the reviewed servers file and registered by the configuration sync.",
  },
  operator_server_connection_change: {
    code: "FORBIDDEN",
    message:
      "An operator-scope admin-plane API key can only rename a server or change its description. Send the metadata-only update (metadata_only true, with a name and/or a description). A server's address and connection are declared in the reviewed servers file and applied by the configuration sync.",
  },
} as const;

/**
 * Refuse an operator-scope admin-plane key the named rule, before any write:
 * one `denied` audit row naming the rule (awaited, so the read-back sees it),
 * then the coded error. The scope is the verified one on the actor (anything
 * but the literal `operator` reads as the sync scope, which keeps both
 * powers). Called before each method's `try`, whose catch would otherwise
 * turn the refusal into `success: false` inside an HTTP 200. Nothing is read
 * from the row: the answer depends on who asks and which variant they sent.
 */
async function refuseOperatorScope(
  actor: AuditActor | undefined,
  rule: keyof typeof OPERATOR_SERVER_REFUSALS,
  action: "mcpserver.create" | "mcpserver.update",
  targetId?: string,
): Promise<void> {
  if (actor?.admin_plane?.scope !== "operator") return;
  await recordDenialAfterRollback(actor, {
    action,
    target_type: "mcp_server",
    ...(targetId !== undefined ? { target_id: targetId } : {}),
    outcome: "denied",
    detail: { rule },
  });
  const { code, message } = OPERATOR_SERVER_REFUSALS[rule];
  throw new TRPCError({ code, message });
}

/**
 * Run a server write inside `withAdminAudit` and turn the repository's refusal
 * of a taken name (ServerNameTakenError, thrown after the name's lock is held
 * and nothing is written) into the coded CONFLICT every caller gets. For an
 * admin-plane key the refusal is thrown inside the audited transaction, which
 * rolls back, records one `denied` row naming the rule and answers with the
 * coded error; a person's write has no audited transaction, so the caller's
 * catch (`codedRefusalOf`) turns it into the same coded error without a row.
 * Fixed sentence, naming no server and no owner.
 */
async function refusingTakenName<T>(
  action: "mcpserver.create" | "mcpserver.update",
  targetId: string | undefined,
  write: () => Promise<T>,
): Promise<T> {
  try {
    return await write();
  } catch (error) {
    if (!(error instanceof ServerNameTakenError)) throw error;
    throw new AdminRuleRefusal("CONFLICT", SERVER_NAME_TAKEN_MESSAGE, {
      action,
      target_type: "mcp_server",
      ...(targetId !== undefined ? { target_id: targetId } : {}),
      detail: { rule: "server_name_taken" },
    });
  }
}

/**
 * The coded error a refusal that reached a person's write (no audited
 * transaction to convert it) stands for, or undefined for any other error.
 */
function codedRefusalOf(error: unknown): TRPCError | undefined {
  return error instanceof AdminRuleRefusal
    ? new TRPCError({ code: error.code, message: error.message })
    : undefined;
}

type MetadataUpdateRequest = z.infer<
  typeof UpdateMcpServerMetadataRequestSchema
>;

/** The strict metadata-only variant (the schema requires the marker). */
function isMetadataOnly(
  input: z.infer<typeof UpdateMcpServerAnyRequestSchema>,
): input is MetadataUpdateRequest {
  return (input as { metadata_only?: unknown }).metadata_only === true;
}

/** The audit event of a server update, either variant. */
function serverUpdateEvent(written: {
  server: DatabaseMcpServer;
  previous: DatabaseMcpServer;
}) {
  return {
    action: "mcpserver.update" as const,
    target_type: "mcp_server" as const,
    target_id: written.server.uuid,
    detail: {
      name: written.server.name,
      type: written.server.type,
      // Which fields this write changed and the previous and new value of
      // each that cannot hold a credential. The connection fields (command,
      // args, url, env, bearer token, headers) are named when changed and
      // never recorded by value.
      ...describeUpdate(
        written.previous,
        written.server,
        MCP_SERVER_UPDATE_FIELDS,
      ),
    },
  };
}

export const mcpServersImplementations = {
  // removalImpact and remove: the leaf-only removal (topology-removal.impl).
  ...topologyRemovalImplementations("mcp_server"),
  create: async (
    input: z.infer<typeof CreateMcpServerRequestSchema>,
    userId: string,
    actor?: AuditActor,
  ): Promise<z.infer<typeof CreateMcpServerResponseSchema>> => {
    // First, and whatever the request says: an operator-scope key does not
    // create servers (the sync scope does, from the reviewed declaration).
    await refuseOperatorScope(
      actor,
      "operator_server_create",
      "mcpserver.create",
    );
    refuseStdioServerUnlessAllowed(input.type);
    refuseStoredIdentityHeaders(input.headers);
    try {
      // Determine user ownership based on input.user_id or default to current user
      const effectiveUserId =
        input.user_id !== undefined ? input.user_id : null;

      // SECRETS. An MCP server row carries the VENDOR credentials this
      // gateway uses to reach a third party: `bearerToken`, `env`, and
      // `headers` (which is where an API key lives for an HTTP backend). None
      // of the three appears in the audit event, and none may be added:
      // `audit_log` is append-only and un-clearable by design, so a credential
      // written into it cannot be taken back out. Identity and transport only.
      //
      // For an admin-plane key the row and its audit row are one transaction
      // (an audit failure fails the create); for everyone else the event is
      // emitted best-effort right after the write.
      const createdServer = await withAdminAudit(
        actor,
        (...tx) =>
          refusingTakenName("mcpserver.create", undefined, () =>
            mcpServersRepository.create(
              {
                ...input,
                user_id: effectiveUserId,
              },
              ...tx,
            ),
          ),
        (created) =>
          created
            ? {
                action: "mcpserver.create",
                target_type: "mcp_server",
                target_id: created.uuid,
                detail: {
                  name: created.name,
                  type: created.type,
                  owner_user_id: effectiveUserId,
                },
              }
            : null,
      );

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

      return {
        success: true as const,
        // create is adminProcedure, so the caller is an administrator by
        // construction: a person's dialog echoes the values it just submitted;
        // an admin-plane key gets the names only (replyDetailFor).
        data: McpServersSerializer.serializeMcpServer(
          createdServer,
          replyDetailFor(actor),
        ),
        message: "MCP server created successfully",
      };
    } catch (error) {
      // A coded refusal (the change budget, a rule) reaches the caller as
      // itself, never as `success: false` inside an HTTP 200.
      if (error instanceof TRPCError) throw error;
      const refusal = codedRefusalOf(error);
      if (refusal) throw refusal;
      logger.error("Error creating MCP server:", describeDbError(error));
      return {
        success: false as const,
        message:
          error instanceof Error ? error.message : "Internal server error",
      };
    }
  },

  list: async (
    userId: string,
    detail: ServerDetailLevel,
  ): Promise<z.infer<typeof ListMcpServersResponseSchema>> => {
    try {
      // Find servers accessible to user (public + user's own)
      const servers =
        await mcpServersRepository.findAllAccessibleToUser(userId);

      return {
        success: true as const,
        // protectedProcedure: members reach this. Redaction, not an RBAC
        // gate — the member dashboard still lists every server it could
        // before, minus the connection URL and credential material. The
        // level is the router's decision from the verified caller.
        data: McpServersSerializer.serializeMcpServerList(servers, detail),
        message: "MCP servers retrieved successfully",
      };
    } catch (error) {
      logger.error("Error fetching MCP servers:", describeDbError(error));
      return {
        success: false as const,
        data: [],
        message: "Failed to fetch MCP servers",
      };
    }
  },

  // Every server, whoever owns it. Inventory visibility does not grant
  // another owner's private connection credentials: those rows use the
  // existing redacted view. Public and owned rows keep the admin view they
  // already have through `list`, whose public-plus-own filter is unchanged.
  listAll: async (
    userId: string,
    detail: ServerDetailLevel,
  ): Promise<z.infer<typeof ListMcpServersResponseSchema>> => {
    try {
      const servers = await mcpServersRepository.findAll();

      return {
        success: true as const,
        // Another owner's private row is redacted whatever the caller's level.
        data: servers.map((server) =>
          McpServersSerializer.serializeMcpServer(
            server,
            server.user_id === null || server.user_id === userId
              ? detail
              : "redacted",
          ),
        ),
        message: "MCP servers retrieved successfully",
      };
    } catch (error) {
      logger.error("Error fetching all MCP servers:", describeDbError(error));
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
    refuseStdioBulkImportUnlessAllowed(input.mcpServers);
    refuseStoredIdentityHeadersInBulkImport(input.mcpServers);
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
                describeDbError(error),
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
      logger.error("Error bulk importing MCP servers:", describeDbError(error));
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
    detail: ServerDetailLevel,
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
        data: McpServersSerializer.serializeMcpServer(server, detail),
        message: "MCP server retrieved successfully",
      };
    } catch (error) {
      logger.error("Error fetching MCP server:", describeDbError(error));
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

      // The row is gone, so the Inspector sessions opened from it (and any
      // still opening on it) end now, before the other post-delete work.
      // This never throws, so it cannot turn the delete into a failure.
      await closeInspectorSessionsForServer(deletedServer.uuid);

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
      logger.error("Error deleting MCP server:", describeDbError(error));
      return {
        success: false as const,
        message:
          error instanceof Error ? error.message : "Internal server error",
      };
    }
  },

  update: async (
    input: z.infer<typeof UpdateMcpServerAnyRequestSchema>,
    userId: string,
    actor?: AuditActor,
  ): Promise<z.infer<typeof UpdateMcpServerResponseSchema>> => {
    // Before the existence and ownership reads as well as the write: the
    // answer does not depend on the row. An operator-scope key may send only
    // the metadata-only variant; the full variant (the one that carries a
    // connection) is refused whatever it holds. The stdio and identity-header
    // gates apply to the full variant, the only one with those fields.
    if (!isMetadataOnly(input)) {
      await refuseOperatorScope(
        actor,
        "operator_server_connection_change",
        "mcpserver.update",
        input.uuid,
      );
      // An existing stdio row can still be switched to Streamable HTTP or
      // SSE, and deleted, with the flag off.
      refuseStdioServerUnlessAllowed(input.type);
      refuseStoredIdentityHeaders(input.headers);
    }
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

      let result: Awaited<
        ReturnType<typeof mcpServersRepository.updateReportingChange>
      >;
      if (isMetadataOnly(input)) {
        // The rename path: only the name and the description are written, and
        // the owner rule is judged again on the row the write locks. No
        // connection field is read or written, so none of the destination and
        // credential bookkeeping below applies (it is reported as unchanged).
        const written = await withAdminAudit(
          actor,
          (...tx) =>
            refusingTakenName("mcpserver.update", input.uuid, () =>
              mcpServersRepository.updateMetadataReportingChange(
                {
                  uuid: input.uuid,
                  name: input.name,
                  description: input.description,
                },
                userId,
                ...tx,
              ),
            ),
          (outcome) =>
            outcome.kind === "updated" ? serverUpdateEvent(outcome) : null,
        );
        if (written.kind === "not_found") {
          return {
            success: false as const,
            message: "MCP server not found",
          };
        }
        if (written.kind === "not_owner") {
          return {
            success: false as const,
            message: "Access denied: You can only update servers you own",
          };
        }
        result = {
          server: written.server,
          previous: written.previous,
          destinationOrCredentialChanged: false,
          ownershipChanged: false,
        };
      } else {
        // Determine user ownership based on input.user_id or keep existing ownership
        const effectiveUserId =
          input.user_id !== undefined ? input.user_id : server.user_id;

        // The repository judges the update against the row it locks, and
        // refuses a URL change that does not decide what happens to the stored
        // bearer token and headers (planServerUpdate in mcp-servers.repo.ts).
        // A refusal writes nothing.
        try {
          // Same credential ban as `create` above: an update is the call that
          // ROTATES a vendor token, so it is the likeliest place for one to
          // leak into a log. For an admin-plane key the row and its audit row
          // are one transaction.
          result = await withAdminAudit(
            actor,
            (...tx) =>
              refusingTakenName("mcpserver.update", input.uuid, () =>
                mcpServersRepository.updateReportingChange(
                  {
                    ...input,
                    user_id: effectiveUserId,
                  },
                  ...tx,
                ),
              ),
            (written) => (written ? serverUpdateEvent(written) : null),
          );
        } catch (error) {
          if (error instanceof ServerCredentialRetentionError) {
            logger.info(
              `Refused an update of MCP server ${server.uuid}: it changes the URL without replacing or clearing the stored credentials`,
            );
            return { success: false as const, message: error.message };
          }
          throw error;
        }
      }

      if (!result) {
        return {
          success: false as const,
          message: "MCP server not found",
        };
      }
      const updatedServer = result.server;
      // A metadata-only write cannot change a stdio connection or recover its
      // error gate. Only a full update keeps the stdio recovery side effects;
      // a rename or description must leave error status and Inspector sessions
      // alone, just as it does for an HTTP server.
      const fullStdioUpdate =
        !isMetadataOnly(input) &&
        updatedServer.type === McpServerTypeEnum.enum.STDIO;

      // Inspector sessions opened from this row (and any still opening on it)
      // hold a transport built from the row as it was. Close them, first and
      // whatever the pooled invalidation below does, when the write changed
      // where the gateway connects or what it presents there; when a full
      // update writes a stdio row, whose command, args and env that report
      // does not cover;
      // or when the locked write changed the owner, who decides who may see
      // the row. A re-save that changed none of this (the sync's routine one,
      // made for every row on every run) leaves them open, as the pool does.
      // This never throws, so it cannot turn the committed write into a
      // failure.
      if (
        result.destinationOrCredentialChanged ||
        fullStdioUpdate ||
        result.ownershipChanged
      ) {
        await closeInspectorSessionsForServer(updatedServer.uuid);
      }

      // A changed URL, type, bearer or headers: retire every pooled
      // connection still built from the old values (active and idle, all
      // sessions), as `reconnect` does, before this returns. Without it a
      // live connection keeps presenting a cleared or replaced credential, or
      // keeps talking to the old address, until it happens to be recycled.
      // An edit that changes none of these (the sync's routine re-save)
      // leaves live connections alone.
      if (result.destinationOrCredentialChanged) {
        await mcpServerPool.invalidateServerConnection(
          "<update-trigger>",
          updatedServer.uuid,
        );
      }

      // Reset error status for full stdio updates only.
      if (fullStdioUpdate) {
        try {
          await serverErrorTracker.resetServerErrorState(updatedServer.uuid);
          logger.info(
            `Reset error status for updated stdio server: ${updatedServer.name} (${updatedServer.uuid})`,
          );
        } catch (error) {
          logger.error(
            `Error resetting error status for updated stdio server ${updatedServer.name} (${updatedServer.uuid}):`,
            describeDbError(error),
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

      return {
        success: true as const,
        // update is adminProcedure: see the note on `create`.
        data: McpServersSerializer.serializeMcpServer(
          updatedServer,
          replyDetailFor(actor),
        ),
        message: "MCP server updated successfully",
      };
    } catch (error) {
      // A coded refusal (the change budget, a rule) reaches the caller as
      // itself, never as `success: false` inside an HTTP 200.
      if (error instanceof TRPCError) throw error;
      const refusal = codedRefusalOf(error);
      if (refusal) throw refusal;
      logger.error("Error updating MCP server:", describeDbError(error));
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
    isAdmin: boolean,
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

      // Only the server owner can reconnect their own server, and only an
      // admin can reconnect a PUBLIC one. The public half is the half the
      // ownership test cannot make: `user_id` is NULL on a public server, so
      // the check below is vacuously true for every caller and each of them
      // reached the cascade underneath — which tears down every active and
      // idle pooled connection for that server and forces every downstream
      // consumer to re-list. On the shared servers this gateway exists to
      // serve, that is any member being able to interrupt everyone's traffic
      // on demand. The role arrives from `ctx.user.role` at the router
      // (packages/trpc/src/routers/frontend/mcp-servers.ts) rather than being
      // re-derived here, so it is the same session role `adminProcedure`
      // gates on. Ordered public-first because it is the broader denial.
      if (!server.user_id && !isAdmin) {
        return {
          success: false as const,
          message:
            "Access denied: Only an administrator can reconnect a public server",
        };
      }

      // Someone else's PRIVATE server, unchanged: not admin-exempt either,
      // because an admin who needs to act on a member's own server has the
      // admin-gated update/delete paths for it and does not need a second
      // route into it here.
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
            describeDbError(error),
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
      logger.error("Error reconnecting MCP server:", describeDbError(error));
      // Members receive this as response data, outside tRPC's error masking.
      // The same try reaches repositories as well as the connection pool.
      return {
        success: false as const,
        message: "Failed to reconnect MCP server",
      };
    }
  },

  /**
   * `mcpServers.resetErrors`: the implementation the cookie-only REST reset
   * route shares (lib/metamcp/reset-server-errors). Coded errors reach the
   * caller as themselves (NOT_FOUND, the change budget, a rule); an audit
   * write failure is the fixed sentence every audited change answers with;
   * anything else propagates and is masked by the error formatter. Never
   * `success: false` inside a 200.
   */
  resetErrors: async (
    input: z.infer<typeof ResetMcpServerErrorsRequestSchema>,
    actor?: AuditActor,
  ): Promise<z.infer<typeof ResetMcpServerErrorsResponseSchema>> => {
    try {
      return await resetServerErrors(input, actor);
    } catch (error) {
      if (error instanceof AdminAuditWriteError) {
        throw new TRPCError({
          code: "INTERNAL_SERVER_ERROR",
          message: ADMIN_AUDIT_WRITE_FAILED_MESSAGE,
        });
      }
      if (!(error instanceof TRPCError)) {
        logger.error(
          "Error resetting MCP server error state:",
          describeDbError(error),
        );
      }
      throw error;
    }
  },
};
