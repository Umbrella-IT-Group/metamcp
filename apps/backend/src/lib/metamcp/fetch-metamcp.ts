import {
  McpServerErrorStatusEnum,
  McpServerStatusEnum,
  ServerParameters,
} from "@repo/zod-types";
import { and, eq } from "drizzle-orm";

import logger from "@/utils/logger";

import { db } from "../../db/index";
import { oauthSessionsRepository } from "../../db/repositories/index";
import { mcpServersTable, namespaceServerMappingsTable } from "../../db/schema";
import { getDefaultEnvironment } from "./utils";

// Define IOType for stderr handling
export type IOType = "overlapped" | "pipe" | "ignore" | "inherit";

/** One server mounted in a namespace, whatever its mount status and error gate. */
export interface NamespaceServerState {
  uuid: string;
  name: string;
  /** namespace_server_mappings.status: ACTIVE or INACTIVE. */
  mountStatus: string;
  /** mcp_servers.error_status: NONE, or ERROR when the server is error-gated. */
  errorStatus: string;
}

/**
 * Every server mounted in the namespace, INCLUDING the error-gated ones
 * `getMcpServers` leaves out, with each one's mount status and error gate.
 *
 * tools/call routing uses it only after a miss, to tell a name whose server is
 * mounted but error-gated (a transient "backend unavailable") from a name no
 * mounted server carries ("Unknown tool"); see tool-call-routing.ts.
 *
 * Unlike `getMcpServers`, a database error is NOT caught: it must stay
 * distinguishable from "no such server", so the caller can refuse to call a
 * real tool unknown just because the lookup failed.
 */
export async function getNamespaceServerStates(
  namespaceUuid: string,
): Promise<NamespaceServerState[]> {
  return await db
    .select({
      uuid: mcpServersTable.uuid,
      name: mcpServersTable.name,
      mountStatus: namespaceServerMappingsTable.status,
      errorStatus: mcpServersTable.error_status,
    })
    .from(mcpServersTable)
    .innerJoin(
      namespaceServerMappingsTable,
      eq(mcpServersTable.uuid, namespaceServerMappingsTable.mcp_server_uuid),
    )
    .where(eq(namespaceServerMappingsTable.namespace_uuid, namespaceUuid));
}

export async function getMcpServers(
  namespaceUuid: string,
  includeInactiveServers: boolean = false,
): Promise<Record<string, ServerParameters>> {
  try {
    // Build the where conditions based on includeInactiveServers flag
    const whereConditions = [
      eq(namespaceServerMappingsTable.namespace_uuid, namespaceUuid),
    ];

    // Only filter by ACTIVE status if includeInactiveServers is false
    if (!includeInactiveServers) {
      whereConditions.push(
        eq(
          namespaceServerMappingsTable.status,
          McpServerStatusEnum.enum.ACTIVE,
        ),
      );
    }

    // Always exclude servers with ERROR status (these are crashed servers)
    whereConditions.push(
      eq(mcpServersTable.error_status, McpServerErrorStatusEnum.enum.NONE),
    );

    // Fetch MCP servers for the specific namespace using a join query
    const servers = await db
      .select({
        uuid: mcpServersTable.uuid,
        name: mcpServersTable.name,
        description: mcpServersTable.description,
        type: mcpServersTable.type,
        command: mcpServersTable.command,
        args: mcpServersTable.args,
        env: mcpServersTable.env,
        url: mcpServersTable.url,
        created_at: mcpServersTable.created_at,
        bearerToken: mcpServersTable.bearerToken,
        headers: mcpServersTable.headers,
        status: namespaceServerMappingsTable.status,
        error_status: mcpServersTable.error_status,
      })
      .from(mcpServersTable)
      .innerJoin(
        namespaceServerMappingsTable,
        eq(mcpServersTable.uuid, namespaceServerMappingsTable.mcp_server_uuid),
      )
      .where(and(...whereConditions));

    const serverDict: Record<string, ServerParameters> = {};
    for (const server of servers) {
      // Fetch OAuth tokens from OAuth sessions table
      const oauthSession = await oauthSessionsRepository.findByMcpServerUuid(
        server.uuid,
      );
      let oauthTokens = null;

      if (oauthSession && oauthSession.tokens) {
        oauthTokens = {
          access_token: oauthSession.tokens.access_token,
          token_type: oauthSession.tokens.token_type,
          expires_in: oauthSession.tokens.expires_in,
          scope: oauthSession.tokens.scope,
          refresh_token: oauthSession.tokens.refresh_token,
        };
      }

      const params: ServerParameters = {
        uuid: server.uuid,
        name: server.name,
        description: server.description || "",
        type: server.type || "STDIO",
        command: server.command,
        args: server.args || [],
        env: server.env || {},
        url: server.url,
        headers: server.headers || {},
        created_at:
          server.created_at?.toISOString() || new Date().toISOString(),
        status: server.status.toLowerCase(),
        error_status: server.error_status?.toLowerCase(),
        stderr: "inherit" as IOType,
        oauth_tokens: oauthTokens,
        bearerToken: server.bearerToken,
      };

      // Process based on server type
      if (params.type === "STDIO") {
        if ("args" in params && !params.args) {
          params.args = undefined;
        }

        params.env = {
          ...getDefaultEnvironment(),
          ...(params.env || {}),
        };
      } else if (params.type === "SSE" || params.type === "STREAMABLE_HTTP") {
        // For SSE or STREAMABLE_HTTP servers, ensure url is present
        if (!params.url) {
          logger.warn(
            `${params.type} server ${params.uuid} is missing url field, skipping`,
          );
          continue;
        }
      }

      serverDict[server.uuid] = params;
    }

    return serverDict;
  } catch (error) {
    logger.error("Error fetching active MCP servers from database:", error);
    return {};
  }
}
