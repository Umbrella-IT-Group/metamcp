import {
  DatabaseNamespace,
  DatabaseNamespaceTool,
  DatabaseNamespaceWithServers,
  Namespace,
  NamespaceTool,
  NamespaceWithServers,
} from "@repo/zod-types";

export class NamespacesSerializer {
  static serializeNamespace(dbNamespace: DatabaseNamespace): Namespace {
    return {
      uuid: dbNamespace.uuid,
      name: dbNamespace.name,
      description: dbNamespace.description,
      created_at: dbNamespace.created_at.toISOString(),
      updated_at: dbNamespace.updated_at.toISOString(),
      user_id: dbNamespace.user_id,
    };
  }

  static serializeNamespaceList(
    dbNamespaces: DatabaseNamespace[],
  ): Namespace[] {
    return dbNamespaces.map(this.serializeNamespace);
  }

  /**
   * `includeSecrets` carries the same contract as
   * McpServersSerializer.serializeMcpServer — required, no default — because
   * the embedded server objects are the SAME disclosure surface by another
   * route. `namespaces.get` is protectedProcedure, so redacting only the
   * mcpServers router would have left `env`, `bearerToken`, `headers`,
   * `command`, `args` and the internal `url` reachable to any member who
   * asked for the namespace that contains the server.
   *
   * The embed is hand-rolled here (rather than delegating to
   * McpServersSerializer) because NamespaceServer adds the per-namespace
   * `status` field and coalesces nullable columns; that predates this change
   * and is left alone. The redaction set is kept identical to the sibling
   * serializer's on purpose — if one grows a field, so must the other.
   */
  static serializeNamespaceWithServers(
    dbNamespace: DatabaseNamespaceWithServers,
    includeSecrets: boolean,
  ): NamespaceWithServers {
    return {
      uuid: dbNamespace.uuid,
      name: dbNamespace.name,
      description: dbNamespace.description,
      created_at: dbNamespace.created_at.toISOString(),
      updated_at: dbNamespace.updated_at.toISOString(),
      user_id: dbNamespace.user_id,
      servers: dbNamespace.servers.map((server) => ({
        uuid: server.uuid,
        name: server.name,
        description: server.description,
        type: server.type,
        command: includeSecrets ? server.command : null,
        args: includeSecrets ? server.args || [] : [],
        url: includeSecrets ? server.url : null,
        env: includeSecrets ? server.env || {} : {},
        bearerToken: includeSecrets ? server.bearerToken : null,
        headers: includeSecrets ? server.headers || {} : {},
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
