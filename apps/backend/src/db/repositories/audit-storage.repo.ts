import { sql } from "drizzle-orm";

import { gatewayEventsDb } from "../gateway-events-db";

/**
 * Storage statistics for the three audit tables, for the growth tripwire in
 * `lib/audit-storage/tripwire`.
 *
 * WHY AN ESTIMATE RATHER THAN A COUNT, and it is the whole reason this file
 * exists instead of three `SELECT count(*)`. Two of these tables carry a
 * 30-day immutability window (migrations 0031 and 0032), so the worst case
 * this monitor exists to catch is tens of millions of rows a day that no
 * application path can reclaim early. `count(*)` on such a table is a
 * sequential scan of exactly the thing that got too big: the monitor's cost
 * would grow with the problem, and the first place it would stall is the
 * five-minute sweep it rides. `pg_class.reltuples` is a catalog column the
 * planner already maintains and `pg_total_relation_size` is a stat of the
 * relation's files, so this stays a fixed-cost read no matter how large the
 * tables get.
 *
 * ONE QUERY, THREE ROWS, ALWAYS THREE. The table names are a VALUES list on
 * the LEFT of the join, so a table that does not resolve still comes back as a
 * row with null figures rather than silently dropping out of the result. A
 * monitor that reports two tables when it was asked about three has lost the
 * one that mattered without saying so.
 *
 * WHICH POOL, AND WHY IT IS NOT THE MAIN ONE. This runs on `gatewayEventsDb`,
 * the bounded two-connection pool with a 1s checkout
 * timeout (`../gateway-events-db`). The main pool sets no
 * `connectionTimeoutMillis`, so a checkout there queues indefinitely; a stats
 * read awaited inside the cleanup interval could then hold the sweep open for
 * as long as the database stayed saturated, which turns a monitor into an
 * outage amplifier. Failing fast and logging is the correct behaviour for a
 * diagnostic: a missed hourly reading costs an hour of visibility, a stalled
 * sweep costs retention.
 *
 * NOT the audit pool, for the reason `../audit-db` spells out at length:
 * `audit_log` is the security record, it has no prune path, and a write that
 * never happens can never be recovered. An hourly diagnostic has no business
 * competing for the two connections that record a refused credential.
 *
 * Note the contrast with `gateway-events.repo`, which deliberately keeps its
 * prune and its admin reads OFF this pool. Those are unbounded work whose
 * duration scales with the table (a DELETE across millions of rows, a page of
 * history with a substring filter), and either could occupy a connection long
 * enough to matter to the writer that depends on it. This is a three-row
 * catalog lookup once an hour that gives up after a second. The rule that
 * pool's comment is really stating is "nothing that can hold a connection",
 * and this cannot.
 */

/** One table's storage figures. Both numbers are nullable, deliberately. */
export interface AuditTableStats {
  table: string;
  /**
   * Planner row estimate, or null when there is no estimate to give.
   *
   * `reltuples` is -1 on PostgreSQL 14+ for a relation that has never been
   * vacuumed or analyzed, which is a different fact from "empty" and must not
   * be reported as zero rows. Null is carried through to the log line as
   * `unknown` so a fresh deployment reads as one.
   */
  est_rows: number | null;
  /** Table + indexes + TOAST in bytes, or null when the table does not exist. */
  total_bytes: number | null;
}

/** The tables the tripwire watches, in the order the query returns them. */
export const AUDIT_STORAGE_TABLES = [
  "audit_log",
  "gateway_events",
  "tool_call_audit",
] as const;

/**
 * `pg` hands bigint back as a string to avoid a lossy implicit conversion.
 * Number is exact to 2^53, which is nine petabytes of bytes and nine
 * quadrillion rows, so the conversion is safe for both columns by a margin
 * nothing here will ever approach.
 */
function toNullableNumber(value: unknown): number | null {
  if (value === null || value === undefined) return null;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : null;
}

export class AuditStorageRepository {
  /**
   * Estimated rows and on-disk size for each audit table.
   *
   * Names are resolved with `to_regclass`, which follows the connection's
   * search_path, the same resolution every unqualified table reference in
   * this application already uses. Measuring what the gateway actually writes
   * to matters more here than pinning a schema name a deployment is free to
   * change.
   */
  async tableStats(): Promise<AuditTableStats[]> {
    const result = await gatewayEventsDb.execute(sql`
      SELECT
        t.table_name AS table_name,
        c.reltuples::bigint AS est_rows,
        pg_total_relation_size(c.oid)::bigint AS total_bytes
      FROM (VALUES ('audit_log'), ('gateway_events'), ('tool_call_audit'))
        AS t(table_name)
      LEFT JOIN pg_catalog.pg_class c ON c.oid = to_regclass(t.table_name)
      ORDER BY t.table_name
    `);

    const rows = result.rows as {
      table_name: string;
      est_rows: string | null;
      total_bytes: string | null;
    }[];

    return rows.map((row) => {
      const estimate = toNullableNumber(row.est_rows);
      return {
        table: row.table_name,
        // Negative means "never analyzed" rather than a row count, so it is
        // reported as no-estimate rather than passed on as a nonsense number.
        est_rows: estimate === null || estimate < 0 ? null : estimate,
        total_bytes: toNullableNumber(row.total_bytes),
      };
    });
  }
}

export const auditStorageRepository = new AuditStorageRepository();
