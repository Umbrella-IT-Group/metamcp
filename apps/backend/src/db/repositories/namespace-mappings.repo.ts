import {
  NamespaceServerStatusUpdate,
  NamespaceToolOverridesUpdate,
  NamespaceToolPolicy,
  NamespaceToolStatusUpdate,
} from "@repo/zod-types";
import { and, eq, sql } from "drizzle-orm";

import { db } from "../index";
import {
  namespaceServerMappingsTable,
  namespacesTable,
  namespaceToolMappingsTable,
} from "../schema";

export class NamespaceMappingsRepository {
  async updateServerStatus(input: NamespaceServerStatusUpdate) {
    const [updatedMapping] = await db
      .update(namespaceServerMappingsTable)
      .set({
        status: input.status,
      })
      .where(
        and(
          eq(namespaceServerMappingsTable.namespace_uuid, input.namespaceUuid),
          eq(namespaceServerMappingsTable.mcp_server_uuid, input.serverUuid),
        ),
      )
      .returning();

    return updatedMapping;
  }

  async updateToolStatus(input: NamespaceToolStatusUpdate) {
    const [updatedMapping] = await db
      .update(namespaceToolMappingsTable)
      .set({
        status: input.status,
      })
      .where(
        and(
          eq(namespaceToolMappingsTable.namespace_uuid, input.namespaceUuid),
          eq(namespaceToolMappingsTable.tool_uuid, input.toolUuid),
          eq(namespaceToolMappingsTable.mcp_server_uuid, input.serverUuid),
        ),
      )
      .returning();

    return updatedMapping;
  }

  async updateToolOverrides(input: NamespaceToolOverridesUpdate) {
    const [updatedMapping] = await db
      .update(namespaceToolMappingsTable)
      .set({
        override_name: input.overrideName,
        override_title: input.overrideTitle,
        override_description: input.overrideDescription,
        override_annotations: input.overrideAnnotations,
      })
      .where(
        and(
          eq(namespaceToolMappingsTable.namespace_uuid, input.namespaceUuid),
          eq(namespaceToolMappingsTable.tool_uuid, input.toolUuid),
          eq(namespaceToolMappingsTable.mcp_server_uuid, input.serverUuid),
        ),
      )
      .returning();

    return updatedMapping;
  }

  async findServerMapping(namespaceUuid: string, serverUuid: string) {
    const [mapping] = await db
      .select()
      .from(namespaceServerMappingsTable)
      .where(
        and(
          eq(namespaceServerMappingsTable.namespace_uuid, namespaceUuid),
          eq(namespaceServerMappingsTable.mcp_server_uuid, serverUuid),
        ),
      );

    return mapping;
  }

  /**
   * Find all namespace UUIDs that use a specific MCP server
   */
  async findNamespacesByServerUuid(serverUuid: string): Promise<string[]> {
    const mappings = await db
      .select({
        namespace_uuid: namespaceServerMappingsTable.namespace_uuid,
      })
      .from(namespaceServerMappingsTable)
      .where(eq(namespaceServerMappingsTable.mcp_server_uuid, serverUuid));

    return mappings.map((mapping) => mapping.namespace_uuid);
  }

  /**
   * Get all existing tool mappings for a namespace
   */
  async findToolMappingsByNamespace(namespaceUuid: string) {
    const mappings = await db
      .select()
      .from(namespaceToolMappingsTable)
      .where(eq(namespaceToolMappingsTable.namespace_uuid, namespaceUuid));

    return mappings;
  }

  async findToolMapping(
    namespaceUuid: string,
    toolUuid: string,
    serverUuid: string,
  ) {
    const [mapping] = await db
      .select()
      .from(namespaceToolMappingsTable)
      .where(
        and(
          eq(namespaceToolMappingsTable.namespace_uuid, namespaceUuid),
          eq(namespaceToolMappingsTable.tool_uuid, toolUuid),
          eq(namespaceToolMappingsTable.mcp_server_uuid, serverUuid),
        ),
      );

    return mapping;
  }

  /**
   * Bulk upsert namespace tool mappings for a namespace
   * Used when refreshing tools from MetaMCP connection
   *
   * What a write may do depends on the namespace's tool policy (migration
   * 0040), because the caller (refreshTools) sends every tool it saw as ACTIVE:
   *
   *   allow_all   unchanged: a new row takes the requested status (ACTIVE by
   *               default) and an existing row is set to it, so a refresh
   *               still switches an INACTIVE row back on. Kept as it was so
   *               the policy's arrival changes nothing for existing
   *               namespaces; a tool with no row is served there anyway.
   *   allowlist   a new row is created INACTIVE whatever status was asked
   *               for, and an existing row keeps its status. A refresh only
   *               records which tools exist; it never decides which are
   *               served. Without this, the provisioning refresh the
   *               platform's admin CLI runs would allowlist every tool it was
   *               sent, which is the default-allow behaviour the policy exists
   *               to remove. A tool joins the allowlist through
   *               updateToolStatus, an admin-gated, audited act.
   *
   * The policy is read FOR SHARE inside the same transaction as the write, and
   * setToolPolicy's UPDATE conflicts with that lock, so a flip and a refresh
   * serialize: the write never applies one policy's rule after the other
   * policy has taken effect.
   *
   * @returns the upserted rows and the policy the write followed (undefined
   *   when nothing was written)
   */
  async bulkUpsertNamespaceToolMappings(input: {
    namespaceUuid: string;
    toolMappings: Array<{
      toolUuid: string;
      serverUuid: string;
      status?: "ACTIVE" | "INACTIVE";
    }>;
  }): Promise<{
    mappings: Array<typeof namespaceToolMappingsTable.$inferSelect>;
    toolPolicy: NamespaceToolPolicy | undefined;
  }> {
    if (!input.toolMappings || input.toolMappings.length === 0) {
      return { mappings: [], toolPolicy: undefined };
    }

    return await db.transaction(async (tx) => {
      const [namespace] = await tx
        .select({ tool_policy: namespacesTable.tool_policy })
        .from(namespacesTable)
        .where(eq(namespacesTable.uuid, input.namespaceUuid))
        .for("share");

      if (!namespace) {
        throw new Error(`Namespace ${input.namespaceUuid} not found`);
      }

      // Anything other than 'allow_all' is treated as an allowlist, the
      // stricter reading, matching the filter middleware.
      const allowAll = namespace.tool_policy === "allow_all";

      const mappingsToInsert = input.toolMappings.map((mapping) => ({
        namespace_uuid: input.namespaceUuid,
        tool_uuid: mapping.toolUuid,
        mcp_server_uuid: mapping.serverUuid,
        status: allowAll
          ? ((mapping.status || "ACTIVE") as "ACTIVE" | "INACTIVE")
          : ("INACTIVE" as const),
      }));

      // Upsert the mappings: insert new ones; on an existing row, update the
      // status only under allow_all (see the policy table above).
      const mappings = await tx
        .insert(namespaceToolMappingsTable)
        .values(mappingsToInsert)
        .onConflictDoUpdate({
          target: [
            namespaceToolMappingsTable.namespace_uuid,
            namespaceToolMappingsTable.tool_uuid,
          ],
          set: allowAll
            ? {
                status: sql`excluded.status`,
                mcp_server_uuid: sql`excluded.mcp_server_uuid`,
              }
            : { mcp_server_uuid: sql`excluded.mcp_server_uuid` },
        })
        .returning();

      return { mappings, toolPolicy: namespace.tool_policy };
    });
  }
}

export const namespaceMappingsRepository = new NamespaceMappingsRepository();
