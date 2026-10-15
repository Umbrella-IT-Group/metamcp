import {
  DatabaseNamespace,
  DatabaseNamespaceTool,
  DatabaseNamespaceWithServers,
  NamespaceCreateInput,
  NamespaceToolPolicy,
  NamespaceUpdateInput,
} from "@repo/zod-types";
import { and, desc, eq, inArray, isNull, notInArray, or } from "drizzle-orm";

import { db } from "../index";
import {
  mcpServersTable,
  namespaceServerMappingsTable,
  namespacesTable,
  namespaceToolMappingsTable,
  toolsTable,
} from "../schema";

export class NamespacesRepository {
  async create(input: NamespaceCreateInput): Promise<DatabaseNamespace> {
    return await db.transaction(async (tx) => {
      // Create the namespace
      const [createdNamespace] = await tx
        .insert(namespacesTable)
        .values({
          name: input.name,
          description: input.description,
          user_id: input.user_id,
        })
        .returning();

      if (!createdNamespace) {
        throw new Error("Failed to create namespace");
      }

      // If mcp server UUIDs are provided, create the mappings with default ACTIVE status
      if (input.mcpServerUuids && input.mcpServerUuids.length > 0) {
        const mappings = input.mcpServerUuids.map((serverUuid) => ({
          namespace_uuid: createdNamespace.uuid,
          mcp_server_uuid: serverUuid,
          status: "ACTIVE" as const,
        }));

        await tx.insert(namespaceServerMappingsTable).values(mappings);

        // Also create namespace-tool mappings for all tools of the selected servers
        const serverTools = await tx
          .select({
            uuid: toolsTable.uuid,
            mcp_server_uuid: toolsTable.mcp_server_uuid,
          })
          .from(toolsTable)
          .where(inArray(toolsTable.mcp_server_uuid, input.mcpServerUuids));

        if (serverTools.length > 0) {
          const toolMappings = serverTools.map((tool) => ({
            namespace_uuid: createdNamespace.uuid,
            tool_uuid: tool.uuid,
            mcp_server_uuid: tool.mcp_server_uuid,
            status: "ACTIVE" as const,
          }));

          await tx.insert(namespaceToolMappingsTable).values(toolMappings);
        }
      }

      return createdNamespace;
    });
  }

  async findAll(): Promise<DatabaseNamespace[]> {
    return await db
      .select({
        uuid: namespacesTable.uuid,
        name: namespacesTable.name,
        description: namespacesTable.description,
        created_at: namespacesTable.created_at,
        updated_at: namespacesTable.updated_at,
        user_id: namespacesTable.user_id,
        tool_policy: namespacesTable.tool_policy,
      })
      .from(namespacesTable)
      .orderBy(desc(namespacesTable.created_at));
  }

  // Find namespaces accessible to a specific user (public + user's own namespaces)
  async findAllAccessibleToUser(userId: string): Promise<DatabaseNamespace[]> {
    return await db
      .select({
        uuid: namespacesTable.uuid,
        name: namespacesTable.name,
        description: namespacesTable.description,
        created_at: namespacesTable.created_at,
        updated_at: namespacesTable.updated_at,
        user_id: namespacesTable.user_id,
        tool_policy: namespacesTable.tool_policy,
      })
      .from(namespacesTable)
      .where(
        or(
          isNull(namespacesTable.user_id), // Public namespaces
          eq(namespacesTable.user_id, userId), // User's own namespaces
        ),
      )
      .orderBy(desc(namespacesTable.created_at));
  }

  // Find only public namespaces (no user ownership)
  async findPublicNamespaces(): Promise<DatabaseNamespace[]> {
    return await db
      .select({
        uuid: namespacesTable.uuid,
        name: namespacesTable.name,
        description: namespacesTable.description,
        created_at: namespacesTable.created_at,
        updated_at: namespacesTable.updated_at,
        user_id: namespacesTable.user_id,
        tool_policy: namespacesTable.tool_policy,
      })
      .from(namespacesTable)
      .where(isNull(namespacesTable.user_id))
      .orderBy(desc(namespacesTable.created_at));
  }

  // Find namespaces owned by a specific user
  async findByUserId(userId: string): Promise<DatabaseNamespace[]> {
    return await db
      .select({
        uuid: namespacesTable.uuid,
        name: namespacesTable.name,
        description: namespacesTable.description,
        created_at: namespacesTable.created_at,
        updated_at: namespacesTable.updated_at,
        user_id: namespacesTable.user_id,
        tool_policy: namespacesTable.tool_policy,
      })
      .from(namespacesTable)
      .where(eq(namespacesTable.user_id, userId))
      .orderBy(desc(namespacesTable.created_at));
  }

  async findByUuid(uuid: string): Promise<DatabaseNamespace | undefined> {
    const [namespace] = await db
      .select({
        uuid: namespacesTable.uuid,
        name: namespacesTable.name,
        description: namespacesTable.description,
        created_at: namespacesTable.created_at,
        updated_at: namespacesTable.updated_at,
        user_id: namespacesTable.user_id,
        tool_policy: namespacesTable.tool_policy,
      })
      .from(namespacesTable)
      .where(eq(namespacesTable.uuid, uuid));

    return namespace;
  }

  // Find namespace by name within user scope (for uniqueness checks)
  async findByNameAndUserId(
    name: string,
    userId: string | null,
  ): Promise<DatabaseNamespace | undefined> {
    const [namespace] = await db
      .select({
        uuid: namespacesTable.uuid,
        name: namespacesTable.name,
        description: namespacesTable.description,
        created_at: namespacesTable.created_at,
        updated_at: namespacesTable.updated_at,
        user_id: namespacesTable.user_id,
        tool_policy: namespacesTable.tool_policy,
      })
      .from(namespacesTable)
      .where(
        and(
          eq(namespacesTable.name, name),
          userId
            ? eq(namespacesTable.user_id, userId)
            : isNull(namespacesTable.user_id),
        ),
      )
      .limit(1);

    return namespace;
  }

  async findByUuidWithServers(
    uuid: string,
  ): Promise<DatabaseNamespaceWithServers | null> {
    // First, get the namespace
    const namespace = await this.findByUuid(uuid);

    if (!namespace) {
      return null;
    }

    // Then, get servers associated with this namespace
    const serversData = await db
      .select({
        uuid: mcpServersTable.uuid,
        name: mcpServersTable.name,
        description: mcpServersTable.description,
        type: mcpServersTable.type,
        command: mcpServersTable.command,
        args: mcpServersTable.args,
        url: mcpServersTable.url,
        env: mcpServersTable.env,
        bearerToken: mcpServersTable.bearerToken,
        headers: mcpServersTable.headers,
        error_status: mcpServersTable.error_status,
        created_at: mcpServersTable.created_at,
        user_id: mcpServersTable.user_id,
        status: namespaceServerMappingsTable.status,
      })
      .from(mcpServersTable)
      .innerJoin(
        namespaceServerMappingsTable,
        eq(mcpServersTable.uuid, namespaceServerMappingsTable.mcp_server_uuid),
      )
      .where(eq(namespaceServerMappingsTable.namespace_uuid, uuid));

    // Format the servers without date conversion
    const servers = serversData.map((server) => ({
      uuid: server.uuid,
      name: server.name,
      description: server.description,
      type: server.type,
      command: server.command,
      args: server.args || [],
      url: server.url,
      env: server.env || {},
      bearerToken: server.bearerToken,
      headers: server.headers || {},
      error_status: server.error_status,
      created_at: server.created_at,
      user_id: server.user_id,
      status: server.status,
    }));

    return {
      ...namespace,
      servers,
    };
  }

  async findToolsByNamespaceUuid(
    namespaceUuid: string,
  ): Promise<DatabaseNamespaceTool[]> {
    const toolsData = await db
      .select({
        // Tool fields
        uuid: toolsTable.uuid,
        name: toolsTable.name,
        description: toolsTable.description,
        toolSchema: toolsTable.toolSchema,
        created_at: toolsTable.created_at,
        updated_at: toolsTable.updated_at,
        mcp_server_uuid: toolsTable.mcp_server_uuid,
        // Server fields
        serverName: mcpServersTable.name,
        serverUuid: mcpServersTable.uuid,
        // Namespace mapping fields
        status: namespaceToolMappingsTable.status,
        overrideName: namespaceToolMappingsTable.override_name,
        overrideTitle: namespaceToolMappingsTable.override_title,
        overrideDescription: namespaceToolMappingsTable.override_description,
        overrideAnnotations: namespaceToolMappingsTable.override_annotations,
      })
      .from(toolsTable)
      .innerJoin(
        namespaceToolMappingsTable,
        eq(toolsTable.uuid, namespaceToolMappingsTable.tool_uuid),
      )
      .innerJoin(
        mcpServersTable,
        eq(toolsTable.mcp_server_uuid, mcpServersTable.uuid),
      )
      .where(eq(namespaceToolMappingsTable.namespace_uuid, namespaceUuid))
      .orderBy(desc(toolsTable.created_at));

    return toolsData;
  }

  /**
   * Last-known-good routing for the tools/call reconnect-window fix
   * (see metamcp-proxy.ts / openapi/handlers.ts originalCallToolHandler).
   * Looks up which server(s) the DB currently associates a tool name
   * with inside a namespace, using the rows written by the last
   * successful tools/list sync — independent of whether a live pooled
   * session exists right now. Returns every match rather than one row:
   * the same original tool name can legitimately exist on more than one
   * backend server in a namespace, disambiguated only by the
   * server-name prefix on the call side, so callers must filter by
   * `sanitizeName(serverName) === serverPrefix` themselves.
   *
   * ACTIVE rows only. This fallback picks the server it routes to from these
   * rows, AFTER the filter middleware judged the call by name, so a row it
   * returns has to be one the filter would serve on its own: an ACTIVE row is
   * served under both tool policies (allow_all and allowlist), an INACTIVE row
   * under neither. Returning INACTIVE rows (as this did before the per-
   * namespace tool policy) meant the fallback could warm and route a server
   * whose row for this tool is switched off, relying entirely on the filter
   * having refused first. A tool with no row was never found here (the join
   * requires a row), which is unchanged.
   */
  async findServersForNamespaceToolName(
    namespaceUuid: string,
    toolName: string,
  ): Promise<Array<{ serverUuid: string; serverName: string | null }>> {
    const rows = await db
      .select({
        serverUuid: toolsTable.mcp_server_uuid,
        serverName: mcpServersTable.name,
      })
      .from(toolsTable)
      .innerJoin(
        namespaceToolMappingsTable,
        eq(toolsTable.uuid, namespaceToolMappingsTable.tool_uuid),
      )
      .innerJoin(
        mcpServersTable,
        eq(toolsTable.mcp_server_uuid, mcpServersTable.uuid),
      )
      .where(
        and(
          eq(namespaceToolMappingsTable.namespace_uuid, namespaceUuid),
          eq(toolsTable.name, toolName),
          eq(namespaceToolMappingsTable.status, "ACTIVE"),
        ),
      );

    return rows;
  }

  /**
   * Set the namespace's tool policy and report the value it replaced, for the
   * audit row. The read locks the row (FOR UPDATE) so the previous value is the
   * one this write actually replaced, not one a concurrent call already
   * overwrote. The UPDATE also conflicts with the FOR SHARE lock the mapping
   * writers take on this row (namespace-mappings.repo), so a refresh runs
   * entirely before or entirely after a flip, never with a policy that changed
   * underneath it.
   *
   * @returns undefined when no namespace has this uuid
   */
  async setToolPolicy(
    uuid: string,
    toolPolicy: NamespaceToolPolicy,
  ): Promise<
    { previous: NamespaceToolPolicy; namespace: DatabaseNamespace } | undefined
  > {
    return await db.transaction(async (tx) => {
      const [current] = await tx
        .select({ tool_policy: namespacesTable.tool_policy })
        .from(namespacesTable)
        .where(eq(namespacesTable.uuid, uuid))
        .for("update");

      if (!current) {
        return undefined;
      }

      const [updated] = await tx
        .update(namespacesTable)
        .set({ tool_policy: toolPolicy, updated_at: new Date() })
        .where(eq(namespacesTable.uuid, uuid))
        .returning();

      if (!updated) {
        return undefined;
      }

      return { previous: current.tool_policy, namespace: updated };
    });
  }

  async deleteByUuid(uuid: string): Promise<DatabaseNamespace | undefined> {
    const [deletedNamespace] = await db
      .delete(namespacesTable)
      .where(eq(namespacesTable.uuid, uuid))
      .returning();

    return deletedNamespace;
  }

  /**
   * Update a namespace and, when `mcpServerUuids` is given, make its server set
   * that list.
   *
   * Rows are reconciled, not rebuilt: only the rows of servers that left the
   * list are deleted, and a row for a server or tool the namespace has no row
   * for yet is inserted with ON CONFLICT DO NOTHING. A retained row is never
   * touched, so everything an administrator set on it since it was created
   * (a tool's status and its four override columns, a server's status) survives
   * the save, and a change another administrator commits meanwhile
   * (updateToolStatus, updateToolOverrides, updateServerStatus) is never
   * overwritten with a value read earlier. The same path serves both tool
   * policies; they differ only in the status a NEW tool row starts with: ACTIVE
   * under allow_all (a tool with no row is served there anyway), INACTIVE under
   * allowlist (an unreviewed tool must not be served because the server list
   * was saved again).
   *
   * The namespace row's UPDATE below holds that row's lock until commit, so two
   * saves, a save and a refresh (bulkUpsertNamespaceToolMappings, FOR SHARE) and
   * a save and a policy flip (setToolPolicy, FOR UPDATE) each run entirely
   * before or after the other, and the policy read from RETURNING is the one in
   * force for the whole write.
   */
  async update(input: NamespaceUpdateInput): Promise<DatabaseNamespace> {
    return await db.transaction(async (tx) => {
      // Update the namespace
      const [updatedNamespace] = await tx
        .update(namespacesTable)
        .set({
          name: input.name,
          description: input.description,
          user_id: input.user_id,
          updated_at: new Date(),
        })
        .where(eq(namespacesTable.uuid, input.uuid))
        .returning();

      if (!updatedNamespace) {
        throw new Error("Namespace not found");
      }

      // If mcpServerUuids are provided, reconcile the mappings with them
      if (input.mcpServerUuids) {
        const serverUuids = [...new Set(input.mcpServerUuids)];
        // Only the rows of servers no longer in the list go. An empty list
        // removes every row, which is the wipe the admin CLI's docs warn about.
        const removedTools =
          serverUuids.length > 0
            ? notInArray(
                namespaceToolMappingsTable.mcp_server_uuid,
                serverUuids,
              )
            : undefined;
        const removedServers =
          serverUuids.length > 0
            ? notInArray(
                namespaceServerMappingsTable.mcp_server_uuid,
                serverUuids,
              )
            : undefined;

        await tx
          .delete(namespaceToolMappingsTable)
          .where(
            and(
              eq(namespaceToolMappingsTable.namespace_uuid, input.uuid),
              removedTools,
            ),
          );
        await tx
          .delete(namespaceServerMappingsTable)
          .where(
            and(
              eq(namespaceServerMappingsTable.namespace_uuid, input.uuid),
              removedServers,
            ),
          );

        if (serverUuids.length > 0) {
          // A server new to the namespace starts ACTIVE; a retained one keeps
          // the status it has (DO NOTHING).
          await tx
            .insert(namespaceServerMappingsTable)
            .values(
              serverUuids.map((serverUuid) => ({
                namespace_uuid: input.uuid,
                mcp_server_uuid: serverUuid,
                status: "ACTIVE" as const,
              })),
            )
            .onConflictDoNothing({
              target: [
                namespaceServerMappingsTable.namespace_uuid,
                namespaceServerMappingsTable.mcp_server_uuid,
              ],
            });

          const serverTools = await tx
            .select({
              uuid: toolsTable.uuid,
              mcp_server_uuid: toolsTable.mcp_server_uuid,
            })
            .from(toolsTable)
            .where(inArray(toolsTable.mcp_server_uuid, serverUuids));

          if (serverTools.length > 0) {
            // A tool with no row is a tool nobody has reviewed for this
            // namespace. The policy is read from the row this transaction just
            // updated (see above), so a concurrent setToolPolicy cannot change
            // it in between.
            const newRowStatus: "ACTIVE" | "INACTIVE" =
              updatedNamespace.tool_policy === "allow_all"
                ? "ACTIVE"
                : "INACTIVE";

            await tx
              .insert(namespaceToolMappingsTable)
              .values(
                serverTools.map((tool) => ({
                  namespace_uuid: input.uuid,
                  tool_uuid: tool.uuid,
                  mcp_server_uuid: tool.mcp_server_uuid,
                  status: newRowStatus,
                })),
              )
              .onConflictDoNothing({
                target: [
                  namespaceToolMappingsTable.namespace_uuid,
                  namespaceToolMappingsTable.tool_uuid,
                ],
              });
          }
        }
      }

      return updatedNamespace;
    });
  }
}

export const namespacesRepository = new NamespacesRepository();
