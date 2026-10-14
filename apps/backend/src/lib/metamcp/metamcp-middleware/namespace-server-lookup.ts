import { and, eq } from "drizzle-orm";

import { db } from "../../../db/index";
import {
  mcpServersTable,
  namespaceServerMappingsTable,
} from "../../../db/schema";

/**
 * Resolve a tool name's server prefix to the server(s) MOUNTED in this
 * namespace under that name.
 *
 * WHY NAMESPACE-SCOPED (upstream metatool-ai/metamcp#364). Server names are
 * unique per owner, not globally: `mcp_servers_name_user_unique_idx` covers
 * (name, user_id), so two users can each own a `github`, and Postgres treats
 * NULL owners as distinct, so even two public servers can share a name at the
 * database level. The tool filter and the override middleware used to resolve
 * the prefix with `WHERE name = ?` alone, no ORDER BY, so which row came back
 * was heap order: a call in namespace A could be judged against a same-named
 * server mounted only in namespace B, find no mapping row there, and read that
 * as "no row, allowed" while A's own row for the tool said INACTIVE. Only the
 * servers mounted in the namespace can serve its tools, so only they are
 * candidates. A prefix that matches no mounted server resolves to nothing and
 * the caller fails closed.
 *
 * Mount status (ACTIVE/INACTIVE in namespace_server_mappings) is deliberately
 * not filtered here: whether an inactive server is routed at all is
 * getMcpServers' decision (`includeInactiveServers`), and this lookup only
 * answers which servers a name can mean in this namespace.
 *
 * Returns every match. Two mounted servers sharing a name is possible (a
 * public `github` and the namespace owner's own `github`), and the routing
 * maps already treat that as a collision; each caller decides how to read an
 * ambiguous answer. A database error is NOT caught: it must stay
 * distinguishable from "no such server", so it propagates and the caller fails
 * closed.
 */
export async function findNamespaceServerUuidsByName(
  namespaceUuid: string,
  serverName: string,
): Promise<string[]> {
  const rows = await db
    .select({ uuid: mcpServersTable.uuid })
    .from(mcpServersTable)
    .innerJoin(
      namespaceServerMappingsTable,
      eq(mcpServersTable.uuid, namespaceServerMappingsTable.mcp_server_uuid),
    )
    .where(
      and(
        eq(namespaceServerMappingsTable.namespace_uuid, namespaceUuid),
        eq(mcpServersTable.name, serverName),
      ),
    );

  return rows.map((row) => row.uuid);
}
