import { eq, inArray, sql } from "drizzle-orm";

import { db } from "../index";
import { configTable } from "../schema";

export const configRepo = {
  async getConfig(
    id: string,
  ): Promise<
    { id: string; value: string; description?: string | null } | undefined
  > {
    const result = await db
      .select()
      .from(configTable)
      .where(eq(configTable.id, id));
    return result[0];
  },

  async setConfig(
    id: string,
    value: string,
    description?: string,
  ): Promise<void> {
    await db
      .insert(configTable)
      .values({
        id,
        value,
        description,
      })
      .onConflictDoUpdate({
        target: configTable.id,
        set: {
          value,
          description,
          updated_at: new Date(),
        },
      });
  },

  /**
   * Read several rows in ONE query. Used by the API-key IP policy, which needs
   * two rows on the hot authentication path and must not pay two round trips
   * for them. Missing rows are simply absent from the result.
   */
  async getConfigs(
    ids: string[],
  ): Promise<Array<{ id: string; value: string }>> {
    if (ids.length === 0) return [];
    return await db
      .select({ id: configTable.id, value: configTable.value })
      .from(configTable)
      .where(inArray(configTable.id, ids));
  },

  /**
   * Upsert several rows in ONE transaction, so a reader never sees half of a
   * setting that spans two rows (the API-key IP policy's mode and its list:
   * a new mode over the old list could refuse callers the new list admits).
   * Return the before/after snapshots under the same locks: reads outside the
   * transaction can attribute another writer's values to this mutation.
   */
  async setConfigs(
    entries: Array<{ id: string; value: string; description?: string }>,
  ): Promise<{
    before: Array<{ id: string; value: string }>;
    after: Array<{ id: string; value: string }>;
  }> {
    if (entries.length === 0) return { before: [], after: [] };
    const ids = [...new Set(entries.map((entry) => entry.id))].sort();
    return await db.transaction(async (tx) => {
      // Row locks alone cannot serialize the first write, when neither row
      // exists. Transaction-scoped advisory locks cover that case too. Take
      // them in ID order so overlapping multi-row settings cannot deadlock.
      for (const id of ids) {
        await tx.execute(
          sql`SELECT pg_advisory_xact_lock(hashtext('metamcp.config'), hashtext(${id}))`,
        );
      }
      const before = await tx
        .select({ id: configTable.id, value: configTable.value })
        .from(configTable)
        .where(inArray(configTable.id, ids))
        .for("update");
      for (const entry of entries) {
        await tx
          .insert(configTable)
          .values({
            id: entry.id,
            value: entry.value,
            description: entry.description,
          })
          .onConflictDoUpdate({
            target: configTable.id,
            set: {
              value: entry.value,
              description: entry.description,
              updated_at: new Date(),
            },
          });
      }
      const after = await tx
        .select({ id: configTable.id, value: configTable.value })
        .from(configTable)
        .where(inArray(configTable.id, ids));
      return { before, after };
    });
  },

  async getAllConfigs(): Promise<
    Array<{ id: string; value: string; description?: string | null }>
  > {
    return await db.select().from(configTable);
  },

  async deleteConfig(id: string): Promise<void> {
    await db.delete(configTable).where(eq(configTable.id, id));
  },
};
