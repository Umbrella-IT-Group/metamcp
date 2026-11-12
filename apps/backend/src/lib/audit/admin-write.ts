import type { AuditActor } from "@repo/trpc";

import logger from "@/utils/logger";

import { recordAuditInTransaction } from "../../db/repositories/audit-log-tx";
import type { DbTransaction } from "../../db/repositories/db-executor";
import {
  type AdminEventInput,
  buildAdminAuditEvent,
  emitAdminEvent,
} from "./admin-event";

/**
 * Admin writes whose audit row is part of the change.
 *
 * `emitAdminEvent` is the best-effort record: detached, swallowing every
 * failure, so an audit outage can never fail the request it describes. That is
 * the right trade for a person using the admin UI. It is the wrong one for a
 * credential with no person in front of it. A key held by a pipeline or an
 * agent changes the gateway with nobody watching, so "who changed what" has to
 * be a property of the change itself: either the audit row is written in the
 * same transaction as the write, or the write did not happen.
 *
 * `withAdminAudit` is the one place that choice is made. For a request that
 * authenticated with an admin-plane key (the actor carries `admin_plane`, set
 * only from the verified key), the write and its audit row share one
 * transaction and an audit failure rolls the write back. For every other actor
 * the behaviour is exactly what it was: the write runs, then the best-effort
 * event is emitted. Widening the transactional behaviour to human sessions is
 * a one-line change to `requiresTransactionalAudit`, and was left out because
 * it would make an audit-sink outage fail the admin UI, which is a separate
 * decision.
 */

/** Fixed, so an audit failure never echoes a driver message or a row. */
export const ADMIN_AUDIT_WRITE_FAILED_MESSAGE =
  "The change was not applied because its audit record could not be written.";

/** Thrown when the audit row could not be written; the write is rolled back. */
export class AdminAuditWriteError extends Error {
  constructor() {
    super(ADMIN_AUDIT_WRITE_FAILED_MESSAGE);
    this.name = "AdminAuditWriteError";
  }
}

/**
 * Does this request need its audit row in the change's own transaction? True
 * for a request authenticated by an admin-plane key. Read from the verified
 * actor bundle (`auditActor(ctx)`), never from a caller field.
 */
export function requiresTransactionalAudit(
  actor: AuditActor | undefined | null,
): boolean {
  return Boolean(actor?.admin_plane);
}

/** The postgres error code if the failure has one, for a log line that names no row. */
function failureCode(error: unknown): string {
  const candidate = error as { code?: unknown; cause?: { code?: unknown } };
  const code = candidate?.code ?? candidate?.cause?.code;
  return typeof code === "string" ? code : "unknown";
}

/**
 * Run `write` and record its audit event, both on ONE transaction, and fail
 * the change if the record cannot be written. The transactional half of
 * `withAdminAudit`, exported for writes that must always be audited this way
 * whoever calls them (a key lifecycle write is one).
 *
 * `write` gets the transaction handle to pass to the repository calls it
 * makes. `eventFor` builds the event from what the write returned and returns
 * null when nothing was written (a not-found, an already-inactive key): no row
 * then, and nothing to roll back. A failure of `write` rolls back and
 * propagates unchanged; a failure to build or insert the audit row rolls back
 * and throws `AdminAuditWriteError`, whose message is fixed.
 */
export async function runAuditedTransaction<T>(
  actor: AuditActor | undefined | null,
  write: (tx: DbTransaction) => Promise<T>,
  eventFor: (written: T) => AdminEventInput | null,
): Promise<T> {
  // Lazy, like the other db-backed seams the tRPC layer reaches: importing the
  // pool at module load would make every suite that imports an implementation
  // need a DATABASE_URL.
  const { db } = await import("../../db/index");
  return await db.transaction(async (tx) => {
    const written = await write(tx);
    try {
      const event = eventFor(written);
      if (event) {
        await recordAuditInTransaction(tx, buildAdminAuditEvent(actor, event));
      }
    } catch (error) {
      logger.error(
        `Admin audit row could not be written; rolling the change back (code ${failureCode(error)})`,
      );
      throw new AdminAuditWriteError();
    }
    return written;
  });
}

/**
 * `runAuditedTransaction` for a request authenticated by an admin-plane key,
 * and the unchanged best-effort behaviour for every other actor.
 *
 * `write` receives the transaction handle to pass to the repository calls it
 * makes, spread as `...tx`: it is EMPTY for a non-admin-plane actor, so a
 * repository method is called with exactly the arguments it had before, and one
 * handle for an admin-plane actor. For the non-admin-plane actor the write runs
 * and the event is emitted best-effort right after it.
 */
export async function withAdminAudit<T>(
  actor: AuditActor | undefined | null,
  write: (...tx: [] | [DbTransaction]) => Promise<T>,
  eventFor: (written: T) => AdminEventInput | null,
): Promise<T> {
  if (requiresTransactionalAudit(actor)) {
    return await runAuditedTransaction(actor, (tx) => write(tx), eventFor);
  }
  const written = await write();
  try {
    const event = eventFor(written);
    if (event) emitAdminEvent(actor, event);
  } catch {
    // The write happened; a throwing event builder must not turn a completed
    // change into a failure. Same contract as emitAdminEvent.
  }
  return written;
}
