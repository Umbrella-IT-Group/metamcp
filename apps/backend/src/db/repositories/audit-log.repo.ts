import { auditDb } from "../audit-db";
import { auditLogTable } from "../schema";

export interface AuditLogEntry {
  occurred_at?: Date;
  actor_type: string;
  actor_id?: string | null;
  actor_label?: string | null;
  actor_ip?: string | null;
  actor_user_agent?: string | null;
  action: string;
  target_type?: string | null;
  target_id?: string | null;
  outcome: string;
  request_id?: string | null;
  http_status?: number | null;
  detail?: Record<string, unknown>;
}

/**
 * Persistence for the control-plane security audit log (migration 0028).
 *
 * INSERT-only, and that is the whole design. There is deliberately no
 * `pruneOlderThan` here — unlike its sibling `tool-call-audit.repo.ts`, which
 * hard-DELETEs on a timer. The operator requirement here is an archive with
 * no application or admin path that empties it,
 * so the method simply does not exist to be called, mis-wired into a cleanup
 * interval, or exposed through a tRPC procedure later. Retention past the
 * WORM-export horizon is an ops-only partition drop (Phase 2), not code.
 *
 * The database enforces the same rule from underneath: 0028 installs BEFORE
 * UPDATE / DELETE / TRUNCATE triggers that RAISE, so even a hand-typed psql
 * mutation is refused. Both halves are needed — the missing method stops the
 * accident, the trigger stops the deliberate act.
 *
 * Writes come fire-and-forget from `lib/audit/audit-emitter.ts`, which
 * imports this module LAZILY to keep its own module graph DB-free for unit
 * tests (same doctrine as `tool-call-audit.repo.ts` and
 * `consumer-identity-resolver.ts`).
 *
 * CONNECTION ISOLATION: this is the one repository that does NOT use the
 * shared `db` from `../index`. It writes through `auditDb`, a two-connection
 * pool with a 1s checkout timeout, so that an unauthenticated request flood —
 * which emits one INSERT per refused request by design — cannot exhaust the
 * connections the AUTH path needs to refuse it. Read `../audit-db` before
 * changing this import back; the failure mode it prevents is "logging the
 * attack starves the code that stops the attack".
 */
export class AuditLogRepository {
  async record(entry: AuditLogEntry): Promise<void> {
    await auditDb.insert(auditLogTable).values(entry);
  }
}

export const auditLogRepository = new AuditLogRepository();
