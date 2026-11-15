import { type SQL, sql } from "drizzle-orm";

/** The filters and page `audit.list` reads with; all exact matches. */
export interface AuditLogReadQuery {
  limit: number;
  cursor?: { occurred_at: string; uuid: string };
  actor_id?: string;
  actor_type?: string;
  action?: string;
  target_type?: string;
  target_id?: string;
  outcome?: string;
  since?: string;
  until?: string;
}

/** One row as read: fixed columns, detail still raw (the caller reduces it). */
export interface AuditLogReadRow {
  uuid: string;
  occurred_at: string;
  actor_type: string;
  actor_id: string | null;
  actor_label: string | null;
  actor_ip: string | null;
  action: string;
  target_type: string | null;
  target_id: string | null;
  outcome: string;
  request_id: string | null;
  http_status: number | null;
  detail: unknown;
}

/**
 * Read one page of `audit_log`, newest first, ordered by (occurred_at, uuid)
 * so a cursor is stable while rows arrive. The timestamp is returned and
 * compared at full (microsecond) precision as text: a JavaScript Date keeps
 * only milliseconds, and a cursor rounded to them would skip or repeat rows
 * written within the same millisecond.
 *
 * Read through the main pool, which holds SELECT on audit_log; nothing here
 * can write to it.
 */
export async function readAuditLogPage(
  query: AuditLogReadQuery,
): Promise<AuditLogReadRow[]> {
  const conditions: SQL[] = [];
  if (query.actor_id !== undefined) {
    conditions.push(sql`actor_id = ${query.actor_id}`);
  }
  if (query.actor_type !== undefined) {
    conditions.push(sql`actor_type = ${query.actor_type}`);
  }
  if (query.action !== undefined) {
    conditions.push(sql`action = ${query.action}`);
  }
  if (query.target_type !== undefined) {
    conditions.push(sql`target_type = ${query.target_type}`);
  }
  if (query.target_id !== undefined) {
    conditions.push(sql`target_id = ${query.target_id}`);
  }
  if (query.outcome !== undefined) {
    conditions.push(sql`outcome = ${query.outcome}`);
  }
  if (query.since !== undefined) {
    conditions.push(sql`occurred_at >= ${query.since}::timestamptz`);
  }
  if (query.until !== undefined) {
    conditions.push(sql`occurred_at < ${query.until}::timestamptz`);
  }
  if (query.cursor !== undefined) {
    conditions.push(
      sql`(occurred_at, uuid) < (${query.cursor.occurred_at}::timestamptz, ${query.cursor.uuid}::uuid)`,
    );
  }
  const where =
    conditions.length > 0
      ? sql`WHERE ${sql.join(conditions, sql` AND `)}`
      : sql``;
  // Lazy, like the other db-backed seams the tRPC layer reaches, so a suite
  // that imports the implementation needs no DATABASE_URL.
  const { db } = await import("../index");
  const result = await db.execute(sql`
    SELECT uuid::text AS uuid,
           to_char(occurred_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS occurred_at,
           actor_type, actor_id, actor_label, actor_ip, action, target_type,
           target_id, outcome, request_id, http_status, detail
      FROM audit_log
      ${where}
     ORDER BY occurred_at DESC, uuid DESC
     LIMIT ${query.limit}`);
  return (result as unknown as { rows: AuditLogReadRow[] }).rows;
}
