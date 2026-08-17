/**
 * `scripts/ensure-runtime-role.sh` against a REAL Postgres.
 *
 * The claim under test is the one the whole role split exists to make: after
 * this script runs, the credential the gateway serves traffic with CANNOT
 * rewrite the audit trail. A migration file that says `CREATE TRIGGER` and a
 * connection that is actually refused an UPDATE are different claims, and only
 * the second one survives contact with an incident.
 *
 * Three things are asserted that nothing else can assert:
 *   1. the role comes out NOSUPERUSER — without that, every REVOKE below is
 *      decorative, because superusers bypass grants outright;
 *   2. the grants land as the matrix says (append yes, rewrite no, prune only
 *      where a pruner exists);
 *   3. running it twice is the same as running it once — it runs on EVERY
 *      container start, not once.
 *
 * GATING: opt-in via TEST_DATABASE_URL, deliberately not DATABASE_URL. This
 * suite CREATEs and ALTERs a role and rewrites grants; pointing it at a live
 * database would change that deployment's privileges. It also needs the
 * TEST_DATABASE_URL role to be a superuser (it creates roles), which is true
 * of a throwaway `postgres:16-alpine` container and should not be true of
 * anything else.
 *
 *   docker run -d --name metamcp-role-test -e POSTGRES_PASSWORD=test \
 *     -e POSTGRES_USER=test -e POSTGRES_DB=metamcp_test \
 *     -p 127.0.0.1:55434:5432 postgres:16-alpine
 *   cd apps/backend
 *   DATABASE_URL=postgres://test:test@127.0.0.1:55434/metamcp_test \
 *     npx drizzle-kit migrate
 *   TEST_DATABASE_URL=postgres://test:test@127.0.0.1:55434/metamcp_test \
 *     npx vitest run src/db/ensure-runtime-role.integration.test.ts
 */

import { execFile } from "node:child_process";
import path from "node:path";
import { promisify } from "node:util";

import { Client } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { INTEGRATION_DB_LOCK_KEY } from "./repositories/integration-db-lock";
import { resolveRuntimeConnection } from "./runtime-connection";

const execFileAsync = promisify(execFile);

const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL as string;

// `describe.skipIf` rather than an early return: a skipped suite is visible in
// the vitest output, so "the grant test didn't run" can never be read as "the
// grant test passed".
const describeIfDb = describe.skipIf(!TEST_DATABASE_URL);

const SCRIPT_PATH = path.resolve(
  __dirname,
  "../../../../scripts/ensure-runtime-role.sh",
);

// Suffixed so a rerun against a database that still holds the previous run's
// role exercises the CREATE path rather than only the ALTER path.
const ROLE = `metamcp_rt_itest_${Date.now()}`;
const PASSWORD = "itest-Str0ng!p@ss%41word";

async function runEnsureScript(): Promise<string> {
  const { stdout, stderr } = await execFileAsync("sh", [SCRIPT_PATH], {
    env: {
      ...process.env,
      DATABASE_URL: TEST_DATABASE_URL,
      METAMCP_RUNTIME_DB_ROLE: ROLE,
      METAMCP_RUNTIME_DB_PASSWORD: PASSWORD,
    },
  });
  return `${stdout}\n${stderr}`;
}

describeIfDb("ensure-runtime-role.sh against a REAL postgres", () => {
  let owner: Client;
  let firstRun: string;
  let secondRun: string;

  beforeAll(async () => {
    owner = new Client({ connectionString: TEST_DATABASE_URL });
    await owner.connect();

    // Same advisory lock the repository integration suites take. vitest runs
    // test FILES in parallel processes against one database, and GRANT/REVOKE
    // takes an ACCESS EXCLUSIVE lock on every table it touches — interleaving
    // that with another suite's TRUNCATE turns a passing run into a blocked
    // one. See ./repositories/integration-db-lock.
    await owner.query(`SELECT pg_advisory_lock(${INTEGRATION_DB_LOCK_KEY})`);

    firstRun = await runEnsureScript();
    // Second pass immediately: the script runs on every container start, so
    // "idempotent" is a boot-time requirement, not a nicety.
    secondRun = await runEnsureScript();
  }, 60_000);

  afterAll(async () => {
    if (!owner) return;
    // `DROP OWNED BY` first, or DROP ROLE fails with "cannot be dropped
    // because some objects depend on it": it is what clears the table grants,
    // the DATABASE-level CONNECT grant and the default-privilege entries the
    // script created. The role owns nothing — it cannot create anything — so
    // this drops privileges only.
    await owner.query(`DROP OWNED BY "${ROLE}"`);
    await owner.query(`DROP ROLE IF EXISTS "${ROLE}"`);
    await owner.query(`SELECT pg_advisory_unlock(${INTEGRATION_DB_LOCK_KEY})`);
    await owner.end();
  });

  it("reports success on both runs", () => {
    expect(firstRun).toContain(`role '${ROLE}' converged`);
    expect(secondRun).toContain(`role '${ROLE}' converged`);
  });

  it("creates the role NOSUPERUSER — the precondition every REVOKE depends on", async () => {
    const { rows } = await owner.query<{
      rolsuper: boolean;
      rolcanlogin: boolean;
      rolcreatedb: boolean;
      rolcreaterole: boolean;
      rolbypassrls: boolean;
    }>(
      "SELECT rolsuper, rolcanlogin, rolcreatedb, rolcreaterole, rolbypassrls FROM pg_roles WHERE rolname = $1",
      [ROLE],
    );

    expect(rows).toHaveLength(1);
    expect(rows[0].rolsuper).toBe(false);
    expect(rows[0].rolcanlogin).toBe(true);
    expect(rows[0].rolcreatedb).toBe(false);
    expect(rows[0].rolcreaterole).toBe(false);
    expect(rows[0].rolbypassrls).toBe(false);
  });

  it("converges a role that was promoted to SUPERUSER behind its back", async () => {
    // The failure this catches is an operator (or a restored dump) leaving the
    // runtime role with superuser rights: the app would connect, everything
    // would work, and the audit triggers would be bypassable with nothing in
    // any log to say so.
    await owner.query(`ALTER ROLE "${ROLE}" SUPERUSER`);
    await runEnsureScript();

    const { rows } = await owner.query<{ rolsuper: boolean }>(
      "SELECT rolsuper FROM pg_roles WHERE rolname = $1",
      [ROLE],
    );
    expect(rows[0].rolsuper).toBe(false);
  });

  it("grants the standard DML on an ordinary application table", async () => {
    for (const privilege of ["SELECT", "INSERT", "UPDATE", "DELETE"]) {
      const { rows } = await owner.query<{ ok: boolean }>(
        "SELECT has_table_privilege($1, 'public.mcp_servers', $2) AS ok",
        [ROLE, privilege],
      );
      expect(rows[0].ok, `mcp_servers ${privilege}`).toBe(true);
    }
  });

  it.each([
    ["audit_log", ["SELECT", "INSERT"], ["UPDATE", "DELETE", "TRUNCATE"]],
    ["tool_call_audit", ["SELECT", "INSERT", "DELETE"], ["UPDATE", "TRUNCATE"]],
  ])("%s: keeps %j, refuses %j", async (table, allowed, denied) => {
    for (const privilege of allowed as string[]) {
      const { rows } = await owner.query<{ ok: boolean }>(
        "SELECT has_table_privilege($1, $2, $3) AS ok",
        [ROLE, `public.${table}`, privilege],
      );
      expect(rows[0].ok, `${table} ${privilege} should be granted`).toBe(true);
    }
    for (const privilege of denied as string[]) {
      const { rows } = await owner.query<{ ok: boolean }>(
        "SELECT has_table_privilege($1, $2, $3) AS ok",
        [ROLE, `public.${table}`, privilege],
      );
      expect(rows[0].ok, `${table} ${privilege} should be revoked`).toBe(false);
    }
  });

  describe("as the runtime role itself", () => {
    let runtime: Client;
    const marker = `role-split-itest-${Date.now()}`;

    beforeAll(async () => {
      // Built by the SAME resolver the application uses, not by hand: the
      // point is to prove the string the app will dial works, including the
      // percent-encoding of a password containing `@` and `%`.
      const resolved = resolveRuntimeConnection({
        DATABASE_URL: TEST_DATABASE_URL,
        METAMCP_RUNTIME_DB_ROLE: ROLE,
        METAMCP_RUNTIME_DB_PASSWORD: PASSWORD,
      });
      expect(resolved.mode).toBe("derived");

      runtime = new Client({ connectionString: resolved.connectionString });
      await runtime.connect();
    });

    afterAll(async () => {
      if (runtime) await runtime.end();
    });

    it("authenticates as the expected role and is not a superuser", async () => {
      const { rows } = await runtime.query<{
        current_user: string;
        rolsuper: boolean;
      }>(
        "SELECT current_user, (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) AS rolsuper",
      );
      expect(rows[0].current_user).toBe(ROLE);
      expect(rows[0].rolsuper).toBe(false);
    });

    it("can append to audit_log", async () => {
      await runtime.query(
        "INSERT INTO audit_log (actor_type, actor_id, action, outcome) VALUES ('api_key', $1, 'mcp.auth.denied', 'denied')",
        [marker],
      );
      const { rows } = await runtime.query(
        "SELECT 1 FROM audit_log WHERE actor_id = $1",
        [marker],
      );
      expect(rows).toHaveLength(1);
    });

    it("is REFUSED an UPDATE on audit_log by privilege, not only by trigger", async () => {
      // "permission denied" rather than the trigger's "append-only" message is
      // the whole result: the statement is stopped before the trigger is even
      // reached, which is what a role that cannot `SET session_replication_role`
      // buys.
      await expect(
        runtime.query(
          "UPDATE audit_log SET outcome = 'success' WHERE actor_id = $1",
          [marker],
        ),
      ).rejects.toThrow(/permission denied/i);
    });

    it("is REFUSED a DELETE and a TRUNCATE on audit_log", async () => {
      await expect(
        runtime.query("DELETE FROM audit_log WHERE actor_id = $1", [marker]),
      ).rejects.toThrow(/permission denied/i);
      await expect(runtime.query("TRUNCATE TABLE audit_log")).rejects.toThrow(
        /permission denied/i,
      );
    });

    it("cannot disable the trigger the way a superuser can", async () => {
      // `SET session_replication_role = 'replica'` is the one-line superuser
      // bypass named in migration 0028's header. A NOSUPERUSER role is refused
      // the SET itself.
      await expect(
        runtime.query("SET session_replication_role = 'replica'"),
      ).rejects.toThrow(/permission denied|must be superuser/i);
    });

    it("cannot drop the trigger either", async () => {
      await expect(
        runtime.query("DROP TRIGGER audit_log_no_update ON audit_log"),
      ).rejects.toThrow(/must be (owner|table owner)|permission denied/i);
    });

    it("keeps DELETE on tool_call_audit so the retention pruner still works", async () => {
      // Revoking DELETE here would break TOOL_AUDIT_RETENTION_DAYS silently —
      // the pruner swallows nothing, but an unbounded audit table is its own
      // outage. In-window immutability on this table is the triggers' job.
      await expect(
        runtime.query(
          "DELETE FROM tool_call_audit WHERE called_at < now() - interval '3650 days'",
        ),
      ).resolves.toBeDefined();
    });

    it("cannot read the migration bookkeeping schema", async () => {
      // Not granted, and deliberately: drizzle's journal is DDL state. A
      // runtime role that can edit it can make a migration appear applied.
      await expect(
        runtime.query("SELECT 1 FROM drizzle.__drizzle_migrations"),
      ).rejects.toThrow(/permission denied/i);
    });
  });
});
