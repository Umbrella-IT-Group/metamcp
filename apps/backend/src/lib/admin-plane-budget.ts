import type { AuditActor } from "@repo/trpc";
import { sql } from "drizzle-orm";

import logger from "@/utils/logger";

import { lockAdminPlaneBudget } from "../db/repositories/admin-plane-locks";
import type { DbTransaction } from "../db/repositories/db-executor";

/**
 * The per-key change budget of an admin-plane API key.
 *
 * WHY. An admin-plane key is a standing credential with no person in front of
 * it, and its holder chooses the request rate. The per-IP request cap bounds
 * load, not damage: inside it a key could make thousands of changes an hour.
 * The budget bounds how many changes one key can make in a sliding window, and
 * bounds the two classes that matter most (changes that widen access, and
 * deletions) more tightly, so a mistake or a misused key is stopped after a
 * bounded number of changes instead of after it has finished.
 *
 * WHAT COUNTS. A change's own audit row: every admin-plane change writes one
 * row in its own transaction (lib/audit/admin-write), carrying
 * `detail.budget_class`. The count reads those rows for the key in the window,
 * so it survives a restart and is shared by every gateway replica. Reads,
 * authentication rows, denied rows and no-op calls (which write no row) cost
 * nothing, and one change is one row, so one slot.
 *
 * SERIALIZED. The count, the judgment, the change and its audit row all run in
 * one transaction holding the key's budget lock (position 1 of the lock order
 * in db/repositories/admin-plane-locks), so two concurrent requests cannot each
 * spend the last slot: the second counts the first's committed row.
 *
 * NOT RESETTABLE. The numbers come from the deploy environment only. Nothing a
 * caller sends changes them, nothing in memory holds them, and a key's
 * identity for the budget is its uuid (rotation, when it exists, must carry
 * the predecessor's budget identity forward).
 */

/** How a change is counted. Every class counts toward the total. */
export type BudgetClass = "tighten" | "change" | "loosen" | "destroy";

/** The limits of one scope, per window. */
export interface ScopeBudget {
  total: number;
  loosen: number;
  destroy: number;
}

export interface AdminPlaneBudgetConfig {
  windowSeconds: number;
  operator: ScopeBudget;
  sync: ScopeBudget;
}

/**
 * The defaults: three times the peak measured on a production deployment for
 * each key and class, so ordinary bulk work fits and a runaway loop or a
 * hijacked key is stopped within an hour. Changing them is a reviewed change
 * to the deploy environment, not a request field.
 *
 *  - operator total: a bulk access-group rollout is many changes in one run,
 *    and several runs can land in one hour.
 *  - operator loosen: the grants of such a rollout (members added, endpoints
 *    mapped) and the keys created for it.
 *  - operator destroy: deletions are rare and leaf-only. None was measured, so
 *    the peak is taken as one and the limit is three times that; a limit of
 *    zero would make a leaf deletion impossible for an agent. A group delete
 *    and a key removal (apiKeys.remove) share it.
 *  - sync total: the configuration sync re-saves every registered server on
 *    each run, and several runs can land in one hour.
 *  - sync loosen and destroy 0: the sync scope has no procedure in either
 *    class.
 */
export const DEFAULT_ADMIN_PLANE_BUDGET: AdminPlaneBudgetConfig = {
  windowSeconds: 3600,
  operator: { total: 318, loosen: 33, destroy: 3 },
  sync: { total: 1056, loosen: 0, destroy: 0 },
};

/** Bounds an environment value must fall in; outside them the default holds. */
const BOUNDS = {
  windowSeconds: { min: 60, max: 86_400 },
  total: { min: 1, max: 100_000 },
  classLimit: { min: 0, max: 100_000 },
} as const;

/**
 * The environment variables, one per number. Read on every call (cheap), so a
 * test can set them; the deployed process reads what compose gave it.
 */
export const ADMIN_PLANE_BUDGET_ENV = {
  windowSeconds: "ADMIN_PLANE_BUDGET_WINDOW_SECONDS",
  operatorTotal: "ADMIN_PLANE_BUDGET_OPERATOR_TOTAL",
  operatorLoosen: "ADMIN_PLANE_BUDGET_OPERATOR_LOOSEN",
  operatorDestroy: "ADMIN_PLANE_BUDGET_OPERATOR_DESTROY",
  syncTotal: "ADMIN_PLANE_BUDGET_SYNC_TOTAL",
  syncLoosen: "ADMIN_PLANE_BUDGET_SYNC_LOOSEN",
  syncDestroy: "ADMIN_PLANE_BUDGET_SYNC_DESTROY",
} as const;

const warnedInvalid = new Set<string>();

/**
 * One environment number: a plain non-negative integer inside its bounds, or
 * the default. An unreadable or out-of-bounds value is not guessed at: the
 * reviewed default holds and the variable is named once in a warning.
 */
function envNumber(
  name: string,
  fallback: number,
  bounds: { min: number; max: number },
): number {
  const raw = process.env[name];
  if (raw === undefined || raw === "") return fallback;
  const value = /^\d{1,9}$/.test(raw.trim()) ? Number(raw.trim()) : NaN;
  if (Number.isInteger(value) && value >= bounds.min && value <= bounds.max) {
    return value;
  }
  if (!warnedInvalid.has(name)) {
    warnedInvalid.add(name);
    logger.warn(
      `${name} is not an integer from ${bounds.min} to ${bounds.max}; the default ${fallback} applies`,
    );
  }
  return fallback;
}

function scopeBudget(
  totalName: string,
  loosenName: string,
  destroyName: string,
  fallback: ScopeBudget,
): ScopeBudget {
  const total = envNumber(totalName, fallback.total, BOUNDS.total);
  // A class limit above the total could never bind; it is held to the total.
  const loosen = Math.min(
    envNumber(loosenName, fallback.loosen, BOUNDS.classLimit),
    total,
  );
  const destroy = Math.min(
    envNumber(destroyName, fallback.destroy, BOUNDS.classLimit),
    total,
  );
  return { total, loosen, destroy };
}

/** The budget in force, from the environment within its bounds. */
export function adminPlaneBudgetConfig(): AdminPlaneBudgetConfig {
  return {
    windowSeconds: envNumber(
      ADMIN_PLANE_BUDGET_ENV.windowSeconds,
      DEFAULT_ADMIN_PLANE_BUDGET.windowSeconds,
      BOUNDS.windowSeconds,
    ),
    operator: scopeBudget(
      ADMIN_PLANE_BUDGET_ENV.operatorTotal,
      ADMIN_PLANE_BUDGET_ENV.operatorLoosen,
      ADMIN_PLANE_BUDGET_ENV.operatorDestroy,
      DEFAULT_ADMIN_PLANE_BUDGET.operator,
    ),
    sync: scopeBudget(
      ADMIN_PLANE_BUDGET_ENV.syncTotal,
      ADMIN_PLANE_BUDGET_ENV.syncLoosen,
      ADMIN_PLANE_BUDGET_ENV.syncDestroy,
      DEFAULT_ADMIN_PLANE_BUDGET.sync,
    ),
  };
}

/** Test seam: forget which invalid variables were already reported. */
export function __resetAdminPlaneBudgetWarningsForTesting(): void {
  warnedInvalid.clear();
}

/**
 * The class of every audit action an admin-plane change can write. An action
 * not listed is counted as `destroy`, the strictest class, so a change added
 * later without a decision is held tightly rather than not at all; the
 * classification test lists the actions each admin-plane mutation writes and
 * fails when one is missing here.
 */
const ACTION_CLASSES: Readonly<
  Record<
    string,
    BudgetClass | ((detail: Record<string, unknown>) => BudgetClass)
  >
> = {
  "mcpserver.create": "change",
  "mcpserver.update": "change",
  "namespace.create": "change",
  "namespace.update": "change",
  "namespace.refresh_tools": "change",
  "namespace.tool_status": "change",
  // allow_all serves every tool without a row; allowlist serves only listed
  // ones. Switching to allow_all widens what callers reach.
  "namespace.tool_policy": (detail) =>
    detail.tool_policy === "allow_all" ? "loosen" : "tighten",
  "endpoint.create": "change",
  "endpoint.update": "change",
  // Turning the gate off opens the endpoint to every caller of its auth mode.
  "endpoint.restricted.set": (detail) =>
    detail.restricted === false ? "loosen" : "tighten",
  "group.create": "change",
  "group.update": "change",
  "group.delete": "destroy",
  "group.member.add": "loosen",
  "group.member.remove": "tighten",
  "group.endpoint.add": "loosen",
  "group.endpoint.remove": "tighten",
  // A new credential is new access, and so is one taken back into use.
  "apikey.create": "loosen",
  "apikey.reactivate": "loosen",
  "apikey.revoke": "tighten",
  // A rename (apiKeys.rename) changes no access.
  "apikey.update": "change",
  // A removal (apiKeys.remove, leaf-only) cannot be undone.
  "apikey.delete": "destroy",
  // Clearing a server's ERROR status lets the gateway connect to it again;
  // it grants no caller anything.
  "mcpserver.errors.reset": "change",
  "apikey.ip_policy.set": "change",
  "config.api_key_ip_policy.set": "change",
};

/** The audit actions the table above classifies, for the classification test. */
export const BUDGETED_ACTIONS: readonly string[] = Object.keys(ACTION_CLASSES);

/** The class one change's audit event is counted in. */
export function budgetClassOf(
  action: string,
  detail: Record<string, unknown> | undefined,
): BudgetClass {
  const entry = ACTION_CLASSES[action];
  if (entry === undefined) return "destroy";
  return typeof entry === "function" ? entry(detail ?? {}) : entry;
}

/** The fixed refusal sentence; it names no count, key or class value. */
export const ADMIN_PLANE_BUDGET_REFUSAL =
  "This admin-plane API key has made as many changes as its change budget allows in the current window. Nothing was changed. Wait for the window to move, or ask an administrator.";

/** Thrown inside the change transaction; the caller rolls back and refuses. */
export class AdminPlaneBudgetExceeded extends Error {
  readonly budgetClass: BudgetClass | "total";
  readonly limit: number;
  readonly windowSeconds: number;

  constructor(
    budgetClass: BudgetClass | "total",
    limit: number,
    windowSeconds: number,
  ) {
    super(ADMIN_PLANE_BUDGET_REFUSAL);
    this.name = "AdminPlaneBudgetExceeded";
    this.budgetClass = budgetClass;
    this.limit = limit;
    this.windowSeconds = windowSeconds;
  }
}

interface SpentCounts {
  total: number;
  loosen: number;
  destroy: number;
}

/**
 * The key's changes in the window, read through the change's transaction.
 * `clock_timestamp()`, not `now()`: the transaction may have waited for the
 * budget lock, and `now()` is fixed at its start.
 */
async function spent(
  tx: DbTransaction,
  keyUuid: string,
  windowSeconds: number,
): Promise<SpentCounts> {
  const result = await tx.execute(sql`
    SELECT count(*)::int AS total,
           count(*) FILTER (WHERE detail->>'budget_class' = 'loosen')::int AS loosen,
           count(*) FILTER (WHERE detail->>'budget_class' = 'destroy')::int AS destroy
      FROM audit_log
     WHERE actor_type = 'api_key'
       AND actor_id = ${keyUuid.toLowerCase()}
       AND outcome = 'success'
       AND detail ? 'budget_class'
       AND occurred_at > clock_timestamp() - make_interval(secs => ${windowSeconds})`);
  const row = (result as unknown as { rows: Array<Record<string, unknown>> })
    .rows[0];
  return {
    total: Number(row?.total ?? 0),
    loosen: Number(row?.loosen ?? 0),
    destroy: Number(row?.destroy ?? 0),
  };
}

/** The limits that apply to this actor's scope. */
function limitsFor(
  actor: AuditActor,
  config: AdminPlaneBudgetConfig,
): ScopeBudget {
  return actor.admin_plane?.scope === "operator"
    ? config.operator
    : config.sync;
}

/**
 * The first half of the charge, before the change runs: take the key's budget
 * lock and refuse when the total is already spent. Returns what the second
 * half needs. For an actor without admin-plane provenance it does nothing.
 */
export async function openBudget(
  tx: DbTransaction,
  actor: AuditActor | undefined | null,
): Promise<{ counts: SpentCounts; config: AdminPlaneBudgetConfig } | null> {
  const keyUuid = actor?.admin_plane?.key_uuid;
  if (!actor || !keyUuid) return null;
  const config = adminPlaneBudgetConfig();
  await lockAdminPlaneBudget(tx, keyUuid);
  const counts = await spent(tx, keyUuid, config.windowSeconds);
  const limits = limitsFor(actor, config);
  if (counts.total >= limits.total) {
    throw new AdminPlaneBudgetExceeded(
      "total",
      limits.total,
      config.windowSeconds,
    );
  }
  return { counts, config };
}

/**
 * The second half, once the change has said what it is (its audit event) and
 * before its row is written and the transaction commits: refuse when the
 * change's class is already spent. Still under the lock `openBudget` took.
 */
export function judgeBudgetClass(
  actor: AuditActor,
  opened: { counts: SpentCounts; config: AdminPlaneBudgetConfig },
  budgetClass: BudgetClass,
): void {
  const limits = limitsFor(actor, opened.config);
  if (budgetClass === "loosen" && opened.counts.loosen >= limits.loosen) {
    throw new AdminPlaneBudgetExceeded(
      "loosen",
      limits.loosen,
      opened.config.windowSeconds,
    );
  }
  if (budgetClass === "destroy" && opened.counts.destroy >= limits.destroy) {
    throw new AdminPlaneBudgetExceeded(
      "destroy",
      limits.destroy,
      opened.config.windowSeconds,
    );
  }
}
