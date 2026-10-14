import {
  DatabaseNamespace,
  DatabaseNamespaceTool,
  DatabaseNamespaceWithServers,
  NamespaceCreateInput,
  NamespaceToolPolicy,
  NamespaceUpdateInput,
} from "@repo/zod-types";
import { and, desc, eq, inArray, isNull, or } from "drizzle-orm";

import { db } from "../index";
import {
  mcpServersTable,
  namespaceServerMappingsTable,
  namespacesTable,
  namespaceToolMappingsTable,
  toolsTable,
} from "../schema";
import { namespaceMappingsRepository } from "./namespace-mappings.repo";

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

      // If mcpServerUuids are provided, update the mappings
      if (input.mcpServerUuids) {
        // Get existing tool mappings to preserve their status
        const existingToolMappings =
          await namespaceMappingsRepository.findToolMappingsByNamespace(
            input.uuid,
          );
        const existingToolStatusMap = new Map<string, "ACTIVE" | "INACTIVE">();

        // Create a map of existing tool statuses by tool_uuid
        existingToolMappings.forEach((mapping) => {
          existingToolStatusMap.set(mapping.tool_uuid, mapping.status);
        });

        // Delete existing server mappings
        await tx
          .delete(namespaceServerMappingsTable)
          .where(eq(namespaceServerMappingsTable.namespace_uuid, input.uuid));

        // Delete existing tool mappings
        await tx
          .delete(namespaceToolMappingsTable)
          .where(eq(namespaceToolMappingsTable.namespace_uuid, input.uuid));

        // Create new server mappings if any servers are specified
        if (input.mcpServerUuids.length > 0) {
          const serverMappings = input.mcpServerUuids.map((serverUuid) => ({
            namespace_uuid: input.uuid,
            mcp_server_uuid: serverUuid,
            status: "ACTIVE" as const,
          }));

          await tx.insert(namespaceServerMappingsTable).values(serverMappings);

          // Also create namespace-tool mappings for all tools of the selected servers
          const serverTools = await tx
            .select({
              uuid: toolsTable.uuid,
              mcp_server_uuid: toolsTable.mcp_server_uuid,
            })
            .from(toolsTable)
            .where(inArray(toolsTable.mcp_server_uuid, input.mcpServerUuids));

          if (serverTools.length > 0) {
            // A tool with no previous row is a tool nobody has reviewed for
            // this namespace. Under `allowlist` it must not come back ACTIVE
            // just because the server list was saved again, so it starts
            // INACTIVE there; under `allow_all` it starts ACTIVE, as it always
            // has (no row and an ACTIVE row serve the same). The policy is
            // read from the row this transaction just updated, which also
            // holds that row's lock until commit, so a concurrent
            // setToolPolicy cannot change it in between.
            const newRowStatus: "ACTIVE" | "INACTIVE" =
              updatedNamespace.tool_policy === "allow_all"
                ? "ACTIVE"
                : "INACTIVE";
            const toolMappings = serverTools.map((tool) => ({
              namespace_uuid: input.uuid,
              tool_uuid: tool.uuid,
              mcp_server_uuid: tool.mcp_server_uuid,
              // Preserve existing status if tool was previously mapped,
              // otherwise the policy's default for a new row (above).
              status: existingToolStatusMap.get(tool.uuid) || newRowStatus,
            }));

            await tx.insert(namespaceToolMappingsTable).values(toolMappings);
          }
        }
      }

      return updatedNamespace;
    });
  }
}

export const namespacesRepository = new NamespacesRepository();
