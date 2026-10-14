import { eq, inArray } from "drizzle-orm";

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
   */
  async setConfigs(
    entries: Array<{ id: string; value: string; description?: string }>,
  ): Promise<void> {
    await db.transaction(async (tx) => {
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
