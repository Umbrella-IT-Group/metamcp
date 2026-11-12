import { eq, inArray, sql } from "drizzle-orm";

import { db } from "../index";
import { configTable } from "../schema";
import type { DbExecutor, DbTransaction } from "./db-executor";

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
    // The caller's transaction when it holds one (an admin-plane write records
    // its audit row in the same transaction); the inner transaction is then a
    // savepoint of it, and the advisory locks taken inside it are held until
    // the outer transaction ends.
    executor?: DbExecutor,
  ): Promise<{
    before: Array<{ id: string; value: string }>;
    after: Array<{ id: string; value: string }>;
  }> {
    if (entries.length === 0) return { before: [], after: [] };
    const ids = [...new Set(entries.map((entry) => entry.id))].sort();
    return await (executor ?? db).transaction(async (tx) => {
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

  /**
   * Read several rows inside the caller's transaction, after taking the same
   * per-setting advisory locks `setConfigs` takes, SHARED. A concurrent
   * `setConfigs` of any of these settings therefore finishes first or waits for
   * this transaction, so what is read here is what will be in force when the
   * transaction commits. Used by the self-lockout rail, which must judge a
   * write against the global IP policy as it will be, not as it was.
   *
   * Locks are taken in id order, like `setConfigs`, so the two cannot deadlock
   * on each other.
   */
  async getConfigsShared(
    tx: DbTransaction,
    ids: string[],
  ): Promise<Array<{ id: string; value: string }>> {
    const ordered = [...new Set(ids)].sort();
    for (const id of ordered) {
      await tx.execute(
        sql`SELECT pg_advisory_xact_lock_shared(hashtext('metamcp.config'), hashtext(${id}))`,
      );
    }
    if (ordered.length === 0) return [];
    return await tx
      .select({ id: configTable.id, value: configTable.value })
      .from(configTable)
      .where(inArray(configTable.id, ordered));
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
