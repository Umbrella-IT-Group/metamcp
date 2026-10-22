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

/**
 * The servers one tools/list covers. `routable` is exactly the set
 * `getMcpServers` answers; `errorGated` holds the servers mounted the same way
 * (ACTIVE unless inactive mounts are included) whose error gate is set.
 */
export interface NamespaceListingServers {
  routable: Record<string, ServerParameters>;
  /**
   * Mounted, but mcp_servers.error_status is ERROR. The listing does not
   * connect to them; it counts them as unreachable, so a namespace whose
   * only server is gated answers a retryable error rather than an empty
   * list, and the session is owed a re-notify once the gate is reset.
   */
  errorGated: Record<string, ServerParameters>;
}

/**
 * The tools/list read of what a namespace mounts.
 *
 * WHY NOT `getMcpServers`. It leaves error-gated servers out and answers `{}`
 * on a database error, and the listing read either as "this namespace mounts
 * nothing": a successful empty tools/list, which a client that re-lists on
 * list_changed takes as its new tool set, and every re-notify the session
 * was owed cancelled as if its server had left the namespace. Here the
 * gated servers are kept (apart from the routable ones) and a database error
 * propagates, so the listing can answer a retryable error instead.
 */
export async function getNamespaceListingServers(
  namespaceUuid: string,
  includeInactiveServers: boolean = false,
): Promise<NamespaceListingServers> {
  const listing: NamespaceListingServers = { routable: {}, errorGated: {} };
  const servers = await readNamespaceServers(
    namespaceUuid,
    includeInactiveServers,
    true,
  );
  for (const { params, errorGated } of servers) {
    (errorGated ? listing.errorGated : listing.routable)[params.uuid] = params;
  }
  return listing;
}

/**
 * The routable servers of a namespace: mounted, ACTIVE unless
 * `includeInactiveServers`, and not error-gated. A database error is logged
 * and answered as `{}`; tools/list reads `getNamespaceListingServers`
 * instead, which does not hide either.
 */
export async function getMcpServers(
  namespaceUuid: string,
  includeInactiveServers: boolean = false,
): Promise<Record<string, ServerParameters>> {
  try {
    const serverDict: Record<string, ServerParameters> = {};
    const servers = await readNamespaceServers(
      namespaceUuid,
      includeInactiveServers,
      false,
    );
    for (const { params } of servers) {
      serverDict[params.uuid] = params;
    }
    return serverDict;
  } catch (error) {
    logger.error("Error fetching active MCP servers from database:", error);
    return {};
  }
}

/**
 * One query for both reads above, and the parameters built from each row.
 * Throws on a database error; each caller decides what that means.
 */
async function readNamespaceServers(
  namespaceUuid: string,
  includeInactiveServers: boolean,
  includeErrorGated: boolean,
): Promise<Array<{ params: ServerParameters; errorGated: boolean }>> {
  // Build the where conditions based on includeInactiveServers flag
  const whereConditions = [
    eq(namespaceServerMappingsTable.namespace_uuid, namespaceUuid),
  ];

  // Only filter by ACTIVE status if includeInactiveServers is false
  if (!includeInactiveServers) {
    whereConditions.push(
      eq(namespaceServerMappingsTable.status, McpServerStatusEnum.enum.ACTIVE),
    );
  }

  // Exclude servers with ERROR status (these are crashed servers), unless
  // the caller keeps them apart itself (getNamespaceListingServers).
  if (!includeErrorGated) {
    whereConditions.push(
      eq(mcpServersTable.error_status, McpServerErrorStatusEnum.enum.NONE),
    );
  }

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

  const result: Array<{ params: ServerParameters; errorGated: boolean }> = [];
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
      created_at: server.created_at?.toISOString() || new Date().toISOString(),
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

    result.push({
      params,
      // error_status is NOT NULL, so this split matches the query filter
      // getMcpServers applies (`error_status = 'NONE'`) row for row.
      errorGated: server.error_status !== McpServerErrorStatusEnum.enum.NONE,
    });
  }
  return result;
}
