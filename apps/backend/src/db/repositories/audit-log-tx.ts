import type { AuditEvent } from "../../lib/audit/audit-emitter";
import { auditLogTable } from "../schema";
import type { DbTransaction } from "./db-executor";

/**
 * The `audit_log` row an event becomes. The one mapping the transactional
 * writer below uses; it mirrors `AuditLogRepository.record`, which the
 * best-effort emitter uses, so a row reads the same whichever path wrote it.
 */
export function toAuditLogRow(event: AuditEvent) {
  return {
    actor_type: event.actor_type,
    actor_id: event.actor_id ?? null,
    actor_label: event.actor_label ?? null,
    actor_ip: event.actor_ip ?? null,
    actor_user_agent: event.actor_user_agent ?? null,
    action: event.action,
    target_type: event.target_type ?? null,
    target_id: event.target_id ?? null,
    outcome: event.outcome,
    request_id: event.request_id ?? null,
    http_status: event.http_status ?? null,
    detail: event.detail ?? {},
  };
}

/**
 * Insert an audit row through the caller's transaction, AWAITED.
 *
 * This is the opposite of `emit()` in lib/audit/audit-emitter.ts, on purpose.
 * `emit` is detached and swallows every failure so that an audit outage can
 * never fail the request it describes. The writes that use THIS function are
 * the ones where the record is part of the change: the insert runs on the same
 * transaction as the write, a failure propagates, and the transaction rolls
 * back, so a change an administrator or a key made either has its audit row or
 * did not happen. It deliberately does not go through `auditDb`: a second
 * connection could not join the transaction, and the point is atomicity, not
 * flood isolation (a mutation reaches here once per authenticated admin call,
 * not once per refused request).
 *
 * Writes through the runtime connection, which holds INSERT on `audit_log`
 * (the optional role split grants it); the append-only triggers from migration
 * 0028 still apply to it.
 */
export async function recordAuditInTransaction(
  tx: DbTransaction,
  event: AuditEvent,
): Promise<void> {
  await tx.insert(auditLogTable).values(toAuditLogRow(event));
}
