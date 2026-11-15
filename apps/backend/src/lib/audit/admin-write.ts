import type { AuditActor } from "@repo/trpc";
import { TRPCError } from "@trpc/server";

import logger from "@/utils/logger";

import { recordAuditInTransaction } from "../../db/repositories/audit-log-tx";
import type { DbTransaction } from "../../db/repositories/db-executor";
import {
  ADMIN_PLANE_BUDGET_REFUSAL,
  AdminPlaneBudgetExceeded,
  budgetClassOf,
  judgeBudgetClass,
  openBudget,
} from "../admin-plane-budget";
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
 * A rule refused the change. Thrown from inside a change's `write`; the helpers
 * below roll the transaction back, then record `denial` as a `denied` audit
 * row AFTER the rollback (awaited, outside the rolled-back transaction, so the
 * record of the refusal is not lost with the change), then answer the caller
 * with a TRPCError of `code` and the fixed `message`. Never return a refusal
 * as `success: false`: a caller's tooling reads a coded 4xx as "refused before
 * it ran" and an HTTP 200 as an unknown outcome.
 */
export class AdminRuleRefusal extends Error {
  readonly code: TRPCError["code"];
  readonly denial: AdminEventInput;

  constructor(
    code: TRPCError["code"],
    message: string,
    denial: AdminEventInput,
  ) {
    super(message);
    this.name = "AdminRuleRefusal";
    this.code = code;
    this.denial = denial;
  }
}

/**
 * Record a refused change as a `denied` row, awaited, through the audit
 * writer's own connection, after the change's transaction has rolled back. A
 * failure to write it is logged by code and does not change the refusal the
 * caller gets: the change did not happen either way.
 */
export async function recordDenialAfterRollback(
  actor: AuditActor | undefined | null,
  denial: AdminEventInput,
): Promise<void> {
  try {
    const event = buildAdminAuditEvent(actor, { ...denial, outcome: "denied" });
    const { auditLogRepository } = await import(
      "../../db/repositories/audit-log.repo"
    );
    await auditLogRepository.record({
      actor_type: event.actor_type,
      actor_id: event.actor_id ?? null,
      actor_label: event.actor_label ?? null,
      actor_ip: event.actor_ip ?? null,
      actor_user_agent: event.actor_user_agent ?? null,
      action: event.action,
      target_type: event.target_type ?? null,
      target_id: event.target_id ?? null,
      outcome: "denied",
      request_id: event.request_id ?? null,
      http_status: event.http_status ?? null,
      detail: event.detail ?? {},
    });
  } catch (error) {
    logger.error(
      `A refused change's denied audit row could not be written (code ${failureCode(error)})`,
    );
  }
}

/**
 * Turn a refusal thrown inside a change transaction (now rolled back) into the
 * coded error the caller sees, recording its denied row first. Anything else
 * is returned unchanged for the caller to rethrow.
 */
async function refusalAfterRollback(
  actor: AuditActor | undefined | null,
  error: unknown,
): Promise<unknown> {
  if (error instanceof AdminPlaneBudgetExceeded) {
    await recordDenialAfterRollback(actor, {
      action: "admin_plane.budget.exceeded",
      target_type: "api_key",
      target_id: actor?.admin_plane?.key_uuid.toLowerCase() ?? null,
      detail: {
        rule: "change_budget",
        budget_class: error.budgetClass,
        limit: error.limit,
        window_seconds: error.windowSeconds,
      },
    });
    return new TRPCError({
      code: "TOO_MANY_REQUESTS",
      message: ADMIN_PLANE_BUDGET_REFUSAL,
    });
  }
  if (error instanceof AdminRuleRefusal) {
    await recordDenialAfterRollback(actor, error.denial);
    return new TRPCError({ code: error.code, message: error.message });
  }
  return error;
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
 *
 * For an admin-plane actor the change is also charged to the key's change
 * budget (lib/admin-plane-budget), inside this transaction: the budget lock
 * and the total are judged first, before `write` runs; the change's class,
 * which its own event names, is judged before its audit row is written; and
 * the row carries `detail.budget_class`, which is what the next count reads.
 * Over budget, and any `AdminRuleRefusal` the write throws, rolls back, leaves
 * a `denied` row written after the rollback, and reaches the caller as a coded
 * TRPCError (TOO_MANY_REQUESTS for the budget).
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
  try {
    return await db.transaction(async (tx) => {
      const opened = await openBudget(tx, actor);
      const written = await write(tx);
      let event: AdminEventInput | null;
      try {
        event = eventFor(written);
      } catch (error) {
        logger.error(
          `Admin audit row could not be built; rolling the change back (code ${failureCode(error)})`,
        );
        throw new AdminAuditWriteError();
      }
      if (event) {
        if (opened && actor) {
          const budgetClass = budgetClassOf(event.action, event.detail);
          // Outside the try below: an over-budget change is a refusal, not
          // an audit failure.
          judgeBudgetClass(actor, opened, budgetClass);
          event = {
            ...event,
            detail: { ...(event.detail ?? {}), budget_class: budgetClass },
          };
        }
        try {
          await recordAuditInTransaction(
            tx,
            buildAdminAuditEvent(actor, event),
          );
        } catch (error) {
          logger.error(
            `Admin audit row could not be written; rolling the change back (code ${failureCode(error)})`,
          );
          throw new AdminAuditWriteError();
        }
      }
      return written;
    });
  } catch (error) {
    throw await refusalAfterRollback(actor, error);
  }
}

/**
 * Run a change in ONE transaction for every actor. For an admin-plane actor
 * this is `runAuditedTransaction` (audit row and budget in the transaction).
 * For any other actor the write still gets a real transaction (a rule that
 * locks and re-reads rows before it writes needs one, whoever calls) and the
 * event is emitted best-effort after it commits, as `withAdminAudit` does.
 * Refusals behave as in `runAuditedTransaction` for both.
 */
export async function withAdminAuditTx<T>(
  actor: AuditActor | undefined | null,
  write: (tx: DbTransaction) => Promise<T>,
  eventFor: (written: T) => AdminEventInput | null,
): Promise<T> {
  if (requiresTransactionalAudit(actor)) {
    return await runAuditedTransaction(actor, write, eventFor);
  }
  const { db } = await import("../../db/index");
  let written: T;
  try {
    written = await db.transaction(async (tx) => write(tx));
  } catch (error) {
    throw await refusalAfterRollback(actor, error);
  }
  try {
    const event = eventFor(written);
    if (event) emitAdminEvent(actor, event);
  } catch {
    // The write committed; a throwing event builder must not turn a completed
    // change into a failure. Same contract as emitAdminEvent.
  }
  return written;
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
