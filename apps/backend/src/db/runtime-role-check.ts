import type { Pool } from "pg";

import { emit } from "@/lib/audit/audit-emitter";
import logger from "@/utils/logger";

import { auditPool } from "./audit-db";
import { pool } from "./index";
import type { RuntimeConnection } from "./runtime-connection";
import { resolveRuntimeConnection } from "./runtime-connection";

/**
 * Proves at boot what privilege the gateway is actually holding.
 *
 * "The variable is set" and "the pool authenticated as a NOSUPERUSER role" are
 * different claims, and only the second one is worth anything: a typo in the
 * derived credentials, a role that was hand-promoted to SUPERUSER later, or an
 * operator who set RUNTIME_DATABASE_URL to the owner string by mistake all
 * produce a deployment that reads as hardened and is not. So this asks the
 * server, over the same pools the request path uses, rather than re-reading
 * the environment and believing it.
 *
 * Both pools are checked. They resolve the connection independently (see
 * ./audit-db), and the audit pool is the one whose privilege the whole feature
 * is about — a check that covered only the main pool would miss exactly the
 * regression that matters.
 */

interface RoleFacts {
  currentUser: string;
  isSuperuser: boolean;
}

async function readRoleFacts(target: Pool): Promise<RoleFacts> {
  const { rows } = await target.query<{
    current_user: string;
    is_superuser: boolean;
  }>(
    "SELECT current_user, (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) AS is_superuser",
  );
  return {
    currentUser: rows[0].current_user,
    isSuperuser: rows[0].is_superuser,
  };
}

/**
 * The action recorded when a configured split turns out not to be in force.
 *
 * A boot-log WARN is only seen by whoever is watching that container at that
 * minute. This is the same finding written to the durable archive, so "was the
 * split ever actually effective?" is a query over `audit_log` rather than an
 * archaeology exercise in retained stdout — and so it can be alerted on.
 */
export const RUNTIME_SPLIT_INEFFECTIVE_ACTION = "db.runtime_split.ineffective";

async function checkPool(
  label: string,
  target: Pool,
  connection: RuntimeConnection,
): Promise<void> {
  const facts = await readRoleFacts(target);

  // Evaluated BEFORE the superuser branch returns. These are independent
  // failures and the superuser case is the one most likely to have both: an
  // operator who pointed the runtime at the owner string gets a superuser AND
  // a role that is not the one the entrypoint granted. Reporting only the
  // first would hide half of what went wrong.
  const roleMismatch = Boolean(
    connection.expectedRole && facts.currentUser !== connection.expectedRole,
  );

  if (roleMismatch) {
    // Not fatal, but it means the grant/revoke work the entrypoint did landed
    // on a different role than the one serving traffic.
    logger.warn(
      `Runtime DB role check (${label}): expected role "${connection.expectedRole}" ` +
        `but authenticated as "${facts.currentUser}".`,
    );
    emit({
      actor_type: "system",
      action: RUNTIME_SPLIT_INEFFECTIVE_ACTION,
      outcome: "failure",
      target_type: "database_role",
      target_id: facts.currentUser,
      detail: {
        reason: "role_mismatch",
        pool: label,
        expected_role: connection.expectedRole,
        connection_mode: connection.mode,
      },
    });
  }

  if (facts.isSuperuser) {
    // WARN, not a hard exit: the gateway still works, and refusing to boot
    // would turn a privilege regression into an outage. But it is never
    // silent — an operator who configured the split has to be able to see
    // from the boot log that it did not take, and the audit row above/below
    // survives the log.
    logger.warn(
      `Runtime DB role check (${label}): connected as "${facts.currentUser}", rolsuper=true — ` +
        `the append-only triggers on the audit tables remain bypassable by this credential ` +
        `(runtime connection mode: ${connection.mode}).`,
    );
    emit({
      actor_type: "system",
      action: RUNTIME_SPLIT_INEFFECTIVE_ACTION,
      outcome: "failure",
      target_type: "database_role",
      target_id: facts.currentUser,
      detail: {
        reason: "superuser",
        pool: label,
        connection_mode: connection.mode,
      },
    });
    return;
  }

  // `console.log`, not `logger.info`, for the same reason the port banner in
  // ../index.ts uses it: LOG_LEVEL defaults to `errors-only`, which mirrors
  // only WARN and above to stdout. An operator following the documented
  // cutover ("recreate, then check the boot log") would find nothing there,
  // and a confirmation line you cannot see is not a confirmation.
  console.log(
    `Runtime DB role check (${label}): connected as "${facts.currentUser}", rolsuper=false ` +
      `(runtime connection mode: ${connection.mode}).`,
  );
}

export async function verifyRuntimeDatabaseRole(): Promise<void> {
  const connection = resolveRuntimeConnection();

  if (connection.mode === "unsplit") {
    // Logged rather than skipped quietly: "no line in the log" is
    // indistinguishable from "the check crashed", and this is the state most
    // deployments are in.
    console.log(
      "Runtime DB role check: no runtime role configured (METAMCP_RUNTIME_DB_PASSWORD / " +
        "RUNTIME_DATABASE_URL unset) — the gateway connects with the same credential as migrations.",
    );
    return;
  }

  // `allSettled`, not `all`. Under `all` the first rejection discards the
  // other pool's result, and the pool most likely to fail its query is the
  // audit pool (`max: 2`, 1s checkout timeout) — so a transient timeout there
  // would suppress the main pool's answer too and the boot log would carry one
  // generic error instead of the privilege facts it exists to report.
  const checks: [string, Pool][] = [
    ["main pool", pool],
    ["audit pool", auditPool],
  ];
  const results = await Promise.allSettled(
    checks.map(([label, target]) => checkPool(label, target, connection)),
  );

  results.forEach((result, index) => {
    if (result.status === "rejected") {
      logger.error(
        `Runtime DB role check (${checks[index][0]}) failed:`,
        result.reason,
      );
    }
  });
}
