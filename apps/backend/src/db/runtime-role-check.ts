import type { Pool } from "pg";

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

async function checkPool(
  label: string,
  target: Pool,
  connection: RuntimeConnection,
): Promise<void> {
  const facts = await readRoleFacts(target);

  if (facts.isSuperuser) {
    // WARN, not a hard exit: the gateway still works, and refusing to boot
    // would turn a privilege regression into an outage. But it is never
    // silent — an operator who configured the split has to be able to see
    // from the boot log that it did not take.
    logger.warn(
      `Runtime DB role check (${label}): connected as "${facts.currentUser}", which IS a SUPERUSER — ` +
        `the append-only triggers on the audit tables remain bypassable by this credential ` +
        `(runtime connection mode: ${connection.mode}).`,
    );
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

  if (
    connection.expectedRole &&
    facts.currentUser !== connection.expectedRole
  ) {
    // Not fatal, but it means the grant/revoke work the entrypoint did landed
    // on a different role than the one serving traffic.
    logger.warn(
      `Runtime DB role check (${label}): expected role "${connection.expectedRole}" ` +
        `but authenticated as "${facts.currentUser}".`,
    );
  }
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

  await Promise.all([
    checkPool("main pool", pool, connection),
    checkPool("audit pool", auditPool, connection),
  ]);
}
