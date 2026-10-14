import {
  DatabaseTool,
  ToolCreateInput,
  ToolUpsertInput,
} from "@repo/zod-types";
import { and, eq, inArray, notExists, notInArray, sql } from "drizzle-orm";

import { db } from "../index";
import { namespaceToolMappingsTable, toolsTable } from "../schema";

/** The rows an upsert writes, one per listed tool. */
function toolRows(input: ToolUpsertInput) {
  return input.tools.map((tool) => ({
    name: tool.name,
    description: tool.description || "",
    toolSchema: {
      type: "object" as const,
      ...tool.inputSchema,
    },
    mcp_server_uuid: input.mcpServerUuid,
  }));
}

/**
 * What an upsert changes on a tool that already exists. The row keeps its
 * uuid, so every namespace mapping row that references it stays attached.
 */
function upsertOnConflict() {
  return {
    target: [toolsTable.mcp_server_uuid, toolsTable.name],
    set: {
      description: sql`excluded.description`,
      toolSchema: sql`excluded.tool_schema`,
      updated_at: new Date(),
    },
  };
}

export class ToolsRepository {
  async findByMcpServerUuid(mcpServerUuid: string): Promise<DatabaseTool[]> {
    return await db
      .select()
      .from(toolsTable)
      .where(eq(toolsTable.mcp_server_uuid, mcpServerUuid))
      .orderBy(toolsTable.name);
  }

  async create(input: ToolCreateInput): Promise<DatabaseTool> {
    const [createdTool] = await db.insert(toolsTable).values(input).returning();

    return createdTool;
  }

  async bulkUpsert(input: ToolUpsertInput): Promise<DatabaseTool[]> {
    if (!input.tools || input.tools.length === 0) {
      return [];
    }

    // Batch insert all tools with upsert
    return await db
      .insert(toolsTable)
      .values(toolRows(input))
      .onConflictDoUpdate(upsertOnConflict())
      .returning();
  }

  async findByUuid(uuid: string): Promise<DatabaseTool | undefined> {
    const [tool] = await db
      .select()
      .from(toolsTable)
      .where(eq(toolsTable.uuid, uuid))
      .limit(1);

    return tool;
  }

  async deleteByUuid(uuid: string): Promise<DatabaseTool | undefined> {
    const [deletedTool] = await db
      .delete(toolsTable)
      .where(eq(toolsTable.uuid, uuid))
      .returning();

    return deletedTool;
  }

  /**
   * Sync a server's catalog to the tool list it just reported: upsert every
   * listed tool, then remove the tools it no longer lists, EXCEPT any tool that
   * a namespace has a mapping row for.
   *
   * WHY MAPPED TOOLS ARE NEVER REMOVED HERE. `namespace_tool_mappings.tool_uuid`
   * references `tools.uuid` ON DELETE CASCADE, and namespace curation is stored
   * as those rows, INACTIVE ones included: a namespace that must expose one
   * tool of a server holds an INACTIVE row for every other one. Deleting a tool
   * row cascades its rows away, and when the tool is listed again it is
   * inserted under a new uuid with no row at all, which the tool filter treats
   * as ACTIVE ("no mapping exists or tool is active"). A server that lists
   * fewer tools for a moment (a restart, a degraded partial list, a tool
   * registered only when configured) would therefore silently re-enable every
   * tool a curator had switched off. An obsolete tool that NO namespace maps
   * carries no curation, so removing it loses nothing and keeps the catalog
   * honest. A retired tool that is still mapped stays until its rows are
   * removed deliberately; the next catalog write after that prunes it.
   *
   * WHY THE LOCK. The candidates are locked FOR UPDATE before the NOT EXISTS
   * check runs. A concurrent mapping insert takes a FOR KEY SHARE lock on the
   * tool row (the foreign-key check) and holds it until it commits. Without
   * our lock, a delete whose snapshot predates that commit would still pass
   * NOT EXISTS, wait for the insert, then delete the tool, and the cascade
   * would take the brand-new row with it. With it, an insert already in flight
   * commits before we read, so its row is seen and the tool kept; one that
   * starts after we lock waits for our commit, and if we deleted that tool its
   * foreign-key check then fails loudly instead of the row being erased.
   *
   * An empty list removes nothing: an empty answer is far more often a
   * degraded listing than a server that really dropped every tool, and a stale
   * catalog costs less than an emptied one. (This method used to delete every
   * tool of the server on an empty list; no caller passes one.)
   *
   * @returns the upserted rows and the rows actually deleted
   */
  async syncTools(input: ToolUpsertInput): Promise<{
    upserted: DatabaseTool[];
    deleted: DatabaseTool[];
  }> {
    if (!input.tools || input.tools.length === 0) {
      return { upserted: [], deleted: [] };
    }

    const currentToolNames = input.tools.map((tool) => tool.name);

    return await db.transaction(async (tx) => {
      const obsolete = await tx
        .select({ uuid: toolsTable.uuid })
        .from(toolsTable)
        .where(
          and(
            eq(toolsTable.mcp_server_uuid, input.mcpServerUuid),
            notInArray(toolsTable.name, currentToolNames),
          ),
        )
        .for("update");

      let deleted: DatabaseTool[] = [];
      if (obsolete.length > 0) {
        deleted = await tx
          .delete(toolsTable)
          .where(
            and(
              inArray(
                toolsTable.uuid,
                obsolete.map((row) => row.uuid),
              ),
              notExists(
                tx
                  .select({ one: sql`1` })
                  .from(namespaceToolMappingsTable)
                  .where(
                    eq(namespaceToolMappingsTable.tool_uuid, toolsTable.uuid),
                  ),
              ),
            ),
          )
          .returning();
      }

      const upserted = await tx
        .insert(toolsTable)
        .values(toolRows(input))
        .onConflictDoUpdate(upsertOnConflict())
        .returning();

      return { upserted, deleted };
    });
  }
}

export const toolsRepository = new ToolsRepository();
