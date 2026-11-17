import type { ServerDetailLevel } from "@repo/trpc";
import { DatabaseMcpServer, McpServer } from "@repo/zod-types";

import { serverConnectionView } from "./server-connection-view";

/**
 * `detail` is a REQUIRED parameter, not an option with a default.
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
 * The level has three values (see ServerDetailLevel in @repo/trpc): `full`
 * for a person signed in as an administrator, `names_only` for an admin-plane
 * API key (the `env` and `headers` names with empty values, no command,
 * arguments or URL), and `redacted` for everyone else. The router decides it
 * from the verified request context.
 *
 * Members keep the fields the dashboard is built on — uuid, name,
 * description, type, error_status, created_at, user_id — so nothing in the
 * member-facing UI loses its identity; only the reachability and credential
 * material goes.
 */
export class McpServersSerializer {
  static serializeMcpServer(
    dbServer: DatabaseMcpServer,
    detail: ServerDetailLevel,
  ): McpServer {
    return {
      uuid: dbServer.uuid,
      name: dbServer.name,
      description: dbServer.description,
      type: dbServer.type,
      // The connection fields are redacted to the schema's own empty/null
      // values rather than to a "REDACTED" sentinel: McpServerSchema already
      // allows null command/url and empty env/headers, so a client parses the
      // response unchanged instead of rendering a fake credential.
      ...serverConnectionView(dbServer, detail),
      error_status: dbServer.error_status,
      created_at: dbServer.created_at.toISOString(),
      // NEVER returned, on either side of the RBAC line.
      // The value at rest is now an `enc:v1:` ciphertext, useless to a client,
      // and even the plaintext was a gateway credential that no response needs
      // to echo, it is only ever read server-side to build the upstream
      // header. Same posture as api_keys and the OAuth token views: presence is
      // not exposed here, the value is simply gone.
      bearerToken: null,
      user_id: dbServer.user_id,
    };
  }

  static serializeMcpServerList(
    dbServers: DatabaseMcpServer[],
    detail: ServerDetailLevel,
  ): McpServer[] {
    // Explicit arrow, NOT `.map(this.serializeMcpServer)`: Array.map passes
    // the element INDEX as the second argument, which a level that is read
    // loosely would take for a value, so one row would be treated differently
    // from the rest.
    return dbServers.map((dbServer) =>
      this.serializeMcpServer(dbServer, detail),
    );
  }
}
