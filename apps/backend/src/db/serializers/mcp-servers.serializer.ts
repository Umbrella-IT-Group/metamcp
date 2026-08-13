import { DatabaseMcpServer, McpServer } from "@repo/zod-types";

// `env`, `bearerToken` and `headers` hold the credentials THIS gateway
// presents to a backend MCP server (upstream API keys, static bearer tokens,
// custom auth headers). Handing them to a member would let any self-registered
// user impersonate the gateway against every vendor backend it fronts, so the
// member-facing read paths (mcpServers.list / mcpServers.get, both
// protectedProcedure) get them blanked. Mirrors the api-keys serializer's
// admin/member split.
//
// Blanked rather than omitted on purpose: `McpServerSchema` marks all three
// required, so dropping the keys would fail tRPC output validation and force
// them optional across every consumer of the `McpServer` type. Blanking cannot
// round-trip into a wipe either — every write procedure (create / update /
// bulkImport / delete) is already adminProcedure, so a member has no path to
// save the redacted values back over the real ones.
export interface McpServerSerializeOptions {
  // True only for callers the RBAC layer has confirmed are admins.
  includeSecrets: boolean;
}

export class McpServersSerializer {
  static serializeMcpServer(
    dbServer: DatabaseMcpServer,
    options: McpServerSerializeOptions,
  ): McpServer {
    return {
      uuid: dbServer.uuid,
      name: dbServer.name,
      description: dbServer.description,
      type: dbServer.type,
      command: dbServer.command,
      args: dbServer.args,
      env: options.includeSecrets ? dbServer.env : {},
      url: dbServer.url,
      error_status: dbServer.error_status,
      created_at: dbServer.created_at.toISOString(),
      bearerToken: options.includeSecrets ? dbServer.bearerToken : null,
      headers: options.includeSecrets ? dbServer.headers : {},
      user_id: dbServer.user_id,
    };
  }

  static serializeMcpServerList(
    dbServers: DatabaseMcpServer[],
    options: McpServerSerializeOptions,
  ): McpServer[] {
    // Explicit arrow, not `.map(this.serializeMcpServer)` — `map` passes the
    // element index as the second argument, which would land in `options`.
    return dbServers.map((dbServer) =>
      McpServersSerializer.serializeMcpServer(dbServer, options),
    );
  }
}
