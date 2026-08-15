import { DatabaseMcpServer, McpServer } from "@repo/zod-types";

/**
 * `includeSecrets` is a REQUIRED parameter, not an option with a default.
 *
 * Every call site has to state which side of the RBAC line it is on, and a
 * new one cannot inherit "full passthrough" by omission — which is how the
 * disclosure being fixed here arose in the first place: `mcpServers.list` and
 * `.get` are `protectedProcedure` (members legitimately see the server
 * inventory), and they were handing every member the connection URL of each
 * backend MCP (`http://some-backend:3000` and friends — an internal Docker
 * network map) alongside `env`, `bearerToken`, `headers`, `command` and
 * `args`, which routinely carry API credentials.
 *
 * Members keep the fields the dashboard is built on — uuid, name,
 * description, type, error_status, created_at, user_id — so nothing in the
 * member-facing UI loses its identity; only the reachability and credential
 * material goes.
 */
export class McpServersSerializer {
  static serializeMcpServer(
    dbServer: DatabaseMcpServer,
    includeSecrets: boolean,
  ): McpServer {
    return {
      uuid: dbServer.uuid,
      name: dbServer.name,
      description: dbServer.description,
      type: dbServer.type,
      // Redacted to the schema's own empty/null values rather than to a
      // "REDACTED" sentinel: McpServerSchema already allows null command/url
      // and empty env/headers, so a member client parses the response
      // unchanged instead of rendering a fake credential.
      command: includeSecrets ? dbServer.command : null,
      args: includeSecrets ? dbServer.args : [],
      env: includeSecrets ? dbServer.env : {},
      url: includeSecrets ? dbServer.url : null,
      error_status: dbServer.error_status,
      created_at: dbServer.created_at.toISOString(),
      bearerToken: includeSecrets ? dbServer.bearerToken : null,
      headers: includeSecrets ? dbServer.headers : {},
      user_id: dbServer.user_id,
    };
  }

  static serializeMcpServerList(
    dbServers: DatabaseMcpServer[],
    includeSecrets: boolean,
  ): McpServer[] {
    // Explicit arrow, NOT `.map(this.serializeMcpServer)`: Array.map passes
    // the element INDEX as the second argument, which would have made
    // includeSecrets false for the first server and truthy for every one
    // after it — a redaction that silently applies to exactly one row.
    return dbServers.map((dbServer) =>
      this.serializeMcpServer(dbServer, includeSecrets),
    );
  }
}
