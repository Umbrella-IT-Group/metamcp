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
 * bounded number of changes instead of after it has finished. Inside the
 * widening class a smaller limit bounds the changes that grant access to a
 * key, a person or an endpoint, so the room the class needs for topology
 * writes is not also room for grants.
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

/**
 * The limits of one scope, per window. `grant` is a sub-limit inside `loosen`:
 * a change that grants access (see GRANT_ACTIONS) counts against both.
 */
export interface ScopeBudget {
  total: number;
  loosen: number;
  grant: number;
  destroy: number;
}

export interface AdminPlaneBudgetConfig {
  windowSeconds: number;
  operator: ScopeBudget;
  sync: ScopeBudget;
}

/**
 * The defaults: set from observed usage, each at three times the per-class
 * peak for that key, so ordinary bulk work fits and a runaway loop or a
 * misused key is stopped within an hour. Changing them is a reviewed change
 * to the deploy environment, not a request field.
 *
 * Peaks are taken over any sliding window of the budget's own 3600 seconds,
 * per key, counting each change in the class below:
 *
 *  - operator total 318: a bulk access-group rollout is many changes in one
 *    run.
 *  - operator loosen 102: the access grants, namespace creations, mounts, tool
 *    activations and open endpoint creations such a rollout makes. A namespace
 *    update that records no evidence of whether it added a mount counts as
 *    loosening, as the code counts a write with no evidence.
 *  - operator grant 33: the access grants (keys minted or re-activated, IP
 *    policies widened, group members and endpoint mappings added, endpoints
 *    un-restricted, namespaces switched to allow_all) of such a rollout. It is
 *    the limit the loosening class had before topology writes joined it, so
 *    the larger loosen limit does not enlarge how many grants a key can make.
 *  - operator destroy 3: deletions are rare and leaf-only. The limit has a
 *    floor of 1 so it stays usable; 0 would make a leaf deletion impossible
 *    for an agent (a group delete and a key removal share it).
 *  - sync total 1089: the configuration sync re-saves every registered server
 *    on each run.
 *  - sync loosen 48: a server the sync creates is a loosening change. An
 *    ordinary run creates none, and a declaration that grows by many servers
 *    still registers in one run.
 *  - sync grant 0: the sync scope grants no access.
 *  - sync destroy 0: the sync scope has no procedure in that class.
 *
 * Namespace creation, mounting, tool activation and an open endpoint count as
 * the loosening changes they are, which is why the operator's loosen limit is
 * higher than the access grants alone need; the sync scope has a loosen
 * allowance of its own because creating a declared server spends it.
 */
export const DEFAULT_ADMIN_PLANE_BUDGET: AdminPlaneBudgetConfig = {
  windowSeconds: 3600,
  operator: { total: 318, loosen: 102, grant: 33, destroy: 3 },
  sync: { total: 1089, loosen: 48, grant: 0, destroy: 0 },
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
  operatorGrant: "ADMIN_PLANE_BUDGET_OPERATOR_GRANT",
  operatorDestroy: "ADMIN_PLANE_BUDGET_OPERATOR_DESTROY",
  syncTotal: "ADMIN_PLANE_BUDGET_SYNC_TOTAL",
  syncLoosen: "ADMIN_PLANE_BUDGET_SYNC_LOOSEN",
  syncGrant: "ADMIN_PLANE_BUDGET_SYNC_GRANT",
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
  names: { total: string; loosen: string; grant: string; destroy: string },
  fallback: ScopeBudget,
): ScopeBudget {
  const total = envNumber(names.total, fallback.total, BOUNDS.total);
  // A class limit above the total could never bind; it is held to the total.
  const loosen = Math.min(
    envNumber(names.loosen, fallback.loosen, BOUNDS.classLimit),
    total,
  );
  // Every grant is also a loosening change, so a grant limit above the loosen
  // limit could never bind either; it is held to the loosen limit.
  const grant = Math.min(
    envNumber(names.grant, fallback.grant, BOUNDS.classLimit),
    loosen,
  );
  const destroy = Math.min(
    envNumber(names.destroy, fallback.destroy, BOUNDS.classLimit),
    total,
  );
  return { total, loosen, grant, destroy };
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
      {
        total: ADMIN_PLANE_BUDGET_ENV.operatorTotal,
        loosen: ADMIN_PLANE_BUDGET_ENV.operatorLoosen,
        grant: ADMIN_PLANE_BUDGET_ENV.operatorGrant,
        destroy: ADMIN_PLANE_BUDGET_ENV.operatorDestroy,
      },
      DEFAULT_ADMIN_PLANE_BUDGET.operator,
    ),
    sync: scopeBudget(
      {
        total: ADMIN_PLANE_BUDGET_ENV.syncTotal,
        loosen: ADMIN_PLANE_BUDGET_ENV.syncLoosen,
        grant: ADMIN_PLANE_BUDGET_ENV.syncGrant,
        destroy: ADMIN_PLANE_BUDGET_ENV.syncDestroy,
      },
      DEFAULT_ADMIN_PLANE_BUDGET.sync,
    ),
  };
}

/** Test seam: forget which invalid variables were already reported. */
export function __resetAdminPlaneBudgetWarningsForTesting(): void {
  warnedInvalid.clear();
}

/** A finite number in an audit detail, or null when it is missing or not one. */
function countIn(detail: Record<string, unknown>, key: string): number | null {
  const value = detail[key];
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

/**
 * The class of every audit action an admin-plane change can write. An action
 * not listed is counted as `destroy`, the strictest class, so a change added
 * later without a decision is held tightly rather than not at all; the
 * classification test lists the actions each admin-plane mutation writes and
 * fails when one is missing here.
 *
 * `loosen` is any change that can put a tool in front of callers it was not
 * in front of, with no status write to say so: a tool row is born ACTIVE under
 * `allow_all`, so creating a namespace over a server, mounting a server, or
 * opening an endpoint reaches every caller of the endpoint at once. The
 * detail-keyed entries read the evidence the write put in its own audit
 * event; evidence that is missing is never read as the lesser class.
 */
const ACTION_CLASSES: Readonly<
  Record<
    string,
    BudgetClass | ((detail: Record<string, unknown>) => BudgetClass)
  >
> = {
  // A server row is the target of every mount, and the sync key creates the
  // servers its declaration lists; a new row can be mounted and served.
  "mcpserver.create": "loosen",
  "mcpserver.update": "change",
  // A namespace created over servers mounts them with ACTIVE tool rows.
  "namespace.create": "loosen",
  // Adding a mount (a server the namespace did not have) serves that server's
  // tools through the namespace; a rename or an unmount does not.
  "namespace.update": (detail) =>
    countIn(detail, "mounts_added") === 0 ? "change" : "loosen",
  // A refresh that inserted an ACTIVE row gave a tool a row it did not have;
  // one that wrote none, or only INACTIVE ones, changed nothing served.
  "namespace.refresh_tools": (detail) =>
    countIn(detail, "active_rows_written") === 0 ? "change" : "loosen",
  // Switching a tool on is new access; switching one off takes it away.
  "namespace.tool_status": (detail) =>
    detail.status === "INACTIVE" ? "tighten" : "loosen",
  // allow_all serves every tool without a row; allowlist serves only listed
  // ones. Switching to allow_all widens what callers reach.
  "namespace.tool_policy": (detail) =>
    detail.tool_policy === "allow_all" ? "loosen" : "tighten",
  // An open endpoint serves its namespace to every caller its auth mode
  // accepts; a restricted one serves administrators and mapped groups only.
  "endpoint.create": (detail) =>
    detail.restricted === true ? "change" : "loosen",
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
  // The caller compares the effective policies under the config and key
  // locks. Any newly admitted address is new access, even within the mint's
  // prefix bound. Missing evidence cannot grant the less restrictive class.
  "apikey.ip_policy.set": (detail) =>
    detail.policy_widened === false ? "change" : "loosen",
  "config.api_key_ip_policy.set": "change",
};

/** The audit actions the table above classifies, for the classification test. */
export const BUDGETED_ACTIONS: readonly string[] = Object.keys(ACTION_CLASSES);

/**
 * The audit actions that grant access to a key, a person, an endpoint or the
 * tools of a namespace: a new or re-activated key, a widened IP policy, a group
 * member, an endpoint added to a group, an endpoint un-restricted, a namespace
 * switched to `allow_all` (one write that serves every tool without a row to
 * every caller). A change of one of these actions that is counted `loosen` is a
 * grant, and counts against the grant limit as well as the loosen one; the same
 * change narrowed (an IP policy that admits no new address, an endpoint
 * restricted, a namespace switched to `allowlist`) is not. The count reads the
 * key's own audit rows by action and class, so a row written before the grant
 * limit existed counts too.
 */
export const GRANT_ACTIONS: ReadonlySet<string> = new Set([
  "apikey.create",
  "apikey.reactivate",
  "apikey.ip_policy.set",
  "group.member.add",
  "group.endpoint.add",
  "endpoint.restricted.set",
  "namespace.tool_policy",
]);

/** Does a change of this action, counted in this class, spend a grant? */
export function isGrantChange(
  action: string,
  budgetClass: BudgetClass,
): boolean {
  return budgetClass === "loosen" && GRANT_ACTIONS.has(action);
}

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

/**
 * The fixed refusal sentence when the grant limit is the one that refused: it
 * names the grant limit, and no count or key.
 */
export const ADMIN_PLANE_GRANT_REFUSAL =
  "This admin-plane API key has made as many access-granting changes as its grant limit allows in the current window. Nothing was changed. Wait for the window to move, or ask an administrator.";

/** Thrown inside the change transaction; the caller rolls back and refuses. */
export class AdminPlaneBudgetExceeded extends Error {
  readonly budgetClass: BudgetClass | "total" | "grant";
  readonly limit: number;
  readonly windowSeconds: number;

  constructor(
    budgetClass: BudgetClass | "total" | "grant",
    limit: number,
    windowSeconds: number,
  ) {
    super(
      budgetClass === "grant"
        ? ADMIN_PLANE_GRANT_REFUSAL
        : ADMIN_PLANE_BUDGET_REFUSAL,
    );
    this.name = "AdminPlaneBudgetExceeded";
    this.budgetClass = budgetClass;
    this.limit = limit;
    this.windowSeconds = windowSeconds;
  }
}

interface SpentCounts {
  total: number;
  loosen: number;
  grant: number;
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
           count(*) FILTER (WHERE detail->>'budget_class' = 'loosen'
                              AND action IN (${sql.join(
                                [...GRANT_ACTIONS].map(
                                  (action) => sql`${action}`,
                                ),
                                sql`, `,
                              )}))::int AS grant,
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
    grant: Number(row?.grant ?? 0),
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
 * change's class is already spent, or, for a grant, when the grant limit is.
 * The loosen limit is judged first, so a refusal names the grant limit only
 * when the loosen limit had room. Still under the lock `openBudget` took.
 *
 * `grant` is `isGrantChange(action, class)` for the change, passed by every
 * caller and with no default, so a caller cannot skip the grant judgment by
 * leaving it out.
 */
export function judgeBudgetClass(
  actor: AuditActor,
  opened: { counts: SpentCounts; config: AdminPlaneBudgetConfig },
  budgetClass: BudgetClass,
  grant: boolean,
): void {
  const limits = limitsFor(actor, opened.config);
  if (budgetClass === "loosen" && opened.counts.loosen >= limits.loosen) {
    throw new AdminPlaneBudgetExceeded(
      "loosen",
      limits.loosen,
      opened.config.windowSeconds,
    );
  }
  if (grant && opened.counts.grant >= limits.grant) {
    throw new AdminPlaneBudgetExceeded(
      "grant",
      limits.grant,
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
