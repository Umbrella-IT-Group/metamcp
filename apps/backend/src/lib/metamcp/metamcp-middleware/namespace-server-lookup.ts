import { McpServerStatusEnum } from "@repo/zod-types";
import { and, eq } from "drizzle-orm";

import { db } from "../../../db/index";
import {
  mcpServersTable,
  namespaceServerMappingsTable,
} from "../../../db/schema";

/**
 * Which mounts a lookup may answer with.
 *
 * `active`: only mounts whose namespace_server_mappings.status is ACTIVE. The
 * tool filter uses this on every public tools/list and tools/call, so a mount
 * switched to INACTIVE stops serving at once, including a live session that
 * still holds a route to the server from an earlier listing.
 *
 * `any`: every mount, whatever its status. The admin Inspector's explicit
 * include-inactive mode uses it (its listing shows inactive servers, so its
 * filter must judge them), and so does override-name resolution, which only
 * maps an alias to its original tool and authorizes nothing.
 */
export type NamespaceMountScope = "active" | "any";

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
 * WHY THE MOUNT STATUS IS READ HERE. The call path reuses a live session's
 * cached route (metamcp-proxy.ts) and only consults the routable-server read
 * (getMcpServers, which filters ACTIVE) when it has no route. The filter's
 * verdict is the one check every call passes, so the mount status has to be
 * part of it: under `active` an INACTIVE mount is not a candidate, the filter
 * refuses the call, and the proxy drops a route that points at it. This is an
 * uncached read on every call, so a status change takes effect for the next
 * call with no cache to invalidate. See NamespaceMountScope.
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
  mountScope: NamespaceMountScope,
): Promise<string[]> {
  const conditions = [
    eq(namespaceServerMappingsTable.namespace_uuid, namespaceUuid),
    eq(mcpServersTable.name, serverName),
  ];
  if (mountScope === "active") {
    conditions.push(
      eq(namespaceServerMappingsTable.status, McpServerStatusEnum.enum.ACTIVE),
    );
  }

  const rows = await db
    .select({ uuid: mcpServersTable.uuid })
    .from(mcpServersTable)
    .innerJoin(
      namespaceServerMappingsTable,
      eq(mcpServersTable.uuid, namespaceServerMappingsTable.mcp_server_uuid),
    )
    .where(and(...conditions));

  return rows.map((row) => row.uuid);
}
