import { and, eq, isNotNull, ne, or, sql } from "drizzle-orm";

import { UNRESTRICT_ROLLBACK_WINDOW_HOURS } from "../../lib/endpoint-namespace-gate";
import { endpointsTable } from "../schema";
import { lockEndpointNamespaces } from "./admin-plane-locks";
import type { DbTransaction } from "./db-executor";

/** An endpoint row as the gate judges it, read under its row lock. */
export interface GateEndpoint {
  uuid: string;
  name: string;
  namespace_uuid: string;
  user_id: string | null;
  restricted: boolean;
  restricted_by_api_key_uuid: string | null;
  /** restricted_at is set and less than the rollback window old. */
  restriction_recent: boolean;
  /**
   * The whole row as locked, for the before-state of the update's audit row
   * (lib/audit/before-state).
   */
  row: typeof endpointsTable.$inferSelect;
}

/**
 * The database half of the endpoint namespace gate
 * (lib/endpoint-namespace-gate). Every method takes the caller's transaction:
 * the namespace lock, the locked re-read, the sibling question and the write
 * must all run in the one transaction the judgement belongs to, in the lock
 * order of db/repositories/admin-plane-locks (namespace locks, then endpoint
 * rows).
 */
export const endpointGateRepository = {
  /** Lock the namespaces (sorted, deduplicated) for the rest of `tx`. */
  async lockNamespaces(
    tx: DbTransaction,
    namespaceUuids: readonly string[],
  ): Promise<void> {
    await lockEndpointNamespaces(tx, namespaceUuids);
  },

  /**
   * Re-read one endpoint FOR UPDATE, after its namespace lock. The rollback
   * window is judged by the database clock (`clock_timestamp()`), the clock
   * that wrote `restricted_at`.
   */
  async lockEndpoint(
    tx: DbTransaction,
    uuid: string,
  ): Promise<GateEndpoint | null> {
    const [found] = await tx
      .select({
        row: endpointsTable,
        restriction_recent: sql<boolean>`coalesce(${endpointsTable.restricted_at} > clock_timestamp() - make_interval(hours => ${UNRESTRICT_ROLLBACK_WINDOW_HOURS}), false)`,
      })
      .from(endpointsTable)
      .where(eq(endpointsTable.uuid, uuid))
      .for("update");
    if (!found) return null;
    const { row, restriction_recent } = found;
    return {
      uuid: row.uuid,
      name: row.name,
      namespace_uuid: row.namespace_uuid,
      user_id: row.user_id,
      restricted: row.restricted,
      restricted_by_api_key_uuid: row.restricted_by_api_key_uuid,
      restriction_recent,
      row,
    };
  },

  /** Is another endpoint over the namespace restricted? */
  async restrictedSiblingExists(
    tx: DbTransaction,
    namespaceUuid: string,
    exceptUuid?: string,
  ): Promise<boolean> {
    const [row] = await tx
      .select({ uuid: endpointsTable.uuid })
      .from(endpointsTable)
      .where(
        and(
          eq(endpointsTable.namespace_uuid, namespaceUuid),
          eq(endpointsTable.restricted, true),
          exceptUuid !== undefined
            ? ne(endpointsTable.uuid, exceptUuid)
            : undefined,
        ),
      )
      .limit(1);
    return row !== undefined;
  },

  /**
   * Is another endpoint over the namespace restricted or private? The
   * admin-plane publish rule's question, now asked under the namespace lock.
   */
  async gatedSiblingExists(
    tx: DbTransaction,
    namespaceUuid: string,
    exceptUuid?: string,
  ): Promise<boolean> {
    const [row] = await tx
      .select({ uuid: endpointsTable.uuid })
      .from(endpointsTable)
      .where(
        and(
          eq(endpointsTable.namespace_uuid, namespaceUuid),
          or(
            eq(endpointsTable.restricted, true),
            isNotNull(endpointsTable.user_id),
          ),
          exceptUuid !== undefined
            ? ne(endpointsTable.uuid, exceptUuid)
            : undefined,
        ),
      )
      .limit(1);
    return row !== undefined;
  },

  /**
   * Set `restricted`, keeping the provenance marker (migration 0047) true to
   * the CURRENT restriction, in one statement over the locked row (the SET
   * expressions read the row as it was):
   *  - an actual false-to-true transition stamps the time and the acting
   *    admin-plane key (NULL for a human);
   *  - true on a row already restricted keeps the marker only when the same
   *    key repeats it, and otherwise clears the key, so a no-op can neither
   *    create rollback eligibility nor take over a human's restriction;
   *  - false clears both.
   * Returns the row after the write, or undefined when it does not exist.
   */
  async setRestricted(
    tx: DbTransaction,
    uuid: string,
    restricted: boolean,
    actorKeyUuid: string | null,
  ): Promise<
    | {
        uuid: string;
        name: string;
        restricted: boolean;
        require_scoped_api_key: boolean;
      }
    | undefined
  > {
    const key = actorKeyUuid === null ? null : actorKeyUuid.toLowerCase();
    const [updated] = await tx
      .update(endpointsTable)
      .set({
        restricted,
        restricted_at: restricted
          ? sql`CASE WHEN ${endpointsTable.restricted} THEN ${endpointsTable.restricted_at} ELSE clock_timestamp() END`
          : null,
        restricted_by_api_key_uuid: restricted
          ? sql`CASE
                  WHEN NOT ${endpointsTable.restricted} THEN ${key}::uuid
                  WHEN ${endpointsTable.restricted_by_api_key_uuid} = ${key}::uuid THEN ${endpointsTable.restricted_by_api_key_uuid}
                  ELSE NULL
                END`
          : null,
        updated_at: new Date(),
      })
      .where(eq(endpointsTable.uuid, uuid))
      .returning({
        uuid: endpointsTable.uuid,
        name: endpointsTable.name,
        restricted: endpointsTable.restricted,
        require_scoped_api_key: endpointsTable.require_scoped_api_key,
      });
    return updated;
  },

  /**
   * Clear the key half of the restriction marker after the endpoint moved to
   * another namespace: a restriction made over the old namespace is not one a
   * key may roll back over the new one.
   */
  async clearRestrictionKey(tx: DbTransaction, uuid: string): Promise<void> {
    await tx
      .update(endpointsTable)
      .set({ restricted_by_api_key_uuid: null })
      .where(eq(endpointsTable.uuid, uuid));
  },
};
