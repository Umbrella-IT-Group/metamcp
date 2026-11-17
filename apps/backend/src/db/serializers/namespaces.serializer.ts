import type { ServerDetailLevel } from "@repo/trpc";
import {
  DatabaseNamespace,
  DatabaseNamespaceTool,
  DatabaseNamespaceWithServers,
  Namespace,
  NamespaceTool,
  NamespaceWithServers,
} from "@repo/zod-types";

import { serverConnectionView } from "./server-connection-view";

export class NamespacesSerializer {
  static serializeNamespace(dbNamespace: DatabaseNamespace): Namespace {
    return {
      uuid: dbNamespace.uuid,
      name: dbNamespace.name,
      description: dbNamespace.description,
      created_at: dbNamespace.created_at.toISOString(),
      updated_at: dbNamespace.updated_at.toISOString(),
      user_id: dbNamespace.user_id,
      tool_policy: dbNamespace.tool_policy,
    };
  }

  static serializeNamespaceList(
    dbNamespaces: DatabaseNamespace[],
  ): Namespace[] {
    return dbNamespaces.map(this.serializeNamespace);
  }

  /**
   * `detail` carries the same contract as
   * McpServersSerializer.serializeMcpServer — required, no default — because
   * the embedded server objects are the SAME disclosure surface by another
   * route. `namespaces.get` is protectedProcedure, so redacting only the
   * mcpServers router would have left `env`, `bearerToken`, `headers`,
   * `command`, `args` and the internal `url` reachable to any member who
   * asked for the namespace that contains the server, and to an admin-plane
   * key that asked for the connection it was never to be shown.
   *
   * The embed is hand-rolled here (rather than delegating to
   * McpServersSerializer) because NamespaceServer adds the per-namespace
   * `status` field and coalesces nullable columns; that predates this change
   * and is left alone. The connection fields come from the one shared
   * function (serverConnectionView), so the redaction set is identical to the
   * sibling serializer's by construction.
   */
  static serializeNamespaceWithServers(
    dbNamespace: DatabaseNamespaceWithServers,
    detail: ServerDetailLevel,
  ): NamespaceWithServers {
    return {
      uuid: dbNamespace.uuid,
      name: dbNamespace.name,
      description: dbNamespace.description,
      created_at: dbNamespace.created_at.toISOString(),
      updated_at: dbNamespace.updated_at.toISOString(),
      user_id: dbNamespace.user_id,
      tool_policy: dbNamespace.tool_policy,
      servers: dbNamespace.servers.map((server) => ({
        uuid: server.uuid,
        name: server.name,
        description: server.description,
        type: server.type,
        ...serverConnectionView(server, detail),
        // NEVER returned: the stored value is an
        // `enc:v1:` ciphertext read only server-side to build the upstream
        // header, so no response echoes it, same posture as
        // McpServersSerializer.
        bearerToken: null,
        error_status: server.error_status,
        created_at: server.created_at.toISOString(),
        user_id: server.user_id,
        status: server.status,
      })),
    };
  }

  static serializeNamespaceTool(dbTool: DatabaseNamespaceTool): NamespaceTool {
    return {
      uuid: dbTool.uuid,
      name: dbTool.name,
      description: dbTool.description,
      toolSchema: dbTool.toolSchema,
      created_at: dbTool.created_at.toISOString(),
      updated_at: dbTool.updated_at.toISOString(),
      mcp_server_uuid: dbTool.mcp_server_uuid,
      status: dbTool.status,
      serverName: dbTool.serverName,
      serverUuid: dbTool.serverUuid,
      overrideName: dbTool.overrideName,
      overrideTitle: dbTool.overrideTitle,
      overrideDescription: dbTool.overrideDescription,
      overrideAnnotations: dbTool.overrideAnnotations,
    };
  }

  static serializeNamespaceTools(
    dbTools: DatabaseNamespaceTool[],
  ): NamespaceTool[] {
    return dbTools.map(this.serializeNamespaceTool);
  }
}
