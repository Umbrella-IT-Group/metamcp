#!/bin/sh
#
# Create/converge the NOSUPERUSER database role the gateway runs as.
#
# WHY THIS EXISTS. On the stock compose stack the application connects as the
# cluster bootstrap role of the `postgres:16-alpine` image, which is a
# SUPERUSER, and one DATABASE_URL serves both `drizzle-kit migrate` and the
# running app. Superusers bypass GRANTs outright, and they can disable a
# trigger for their own session (`SET session_replication_role = 'replica'`)
# or simply drop it. So the append-only triggers on the audit tables — the
# thing that makes the audit trail worth anything the morning after an
# incident — are bypassable by the very credential the app holds. Splitting
# DDL (migrate, superuser/owner) from DML (runtime, NOSUPERUSER) is what turns
# those triggers from a speed bump into an enforced property.
#
# OPT-IN, AND SILENT WHEN OFF. With METAMCP_RUNTIME_DB_PASSWORD unset this
# script is never invoked by docker-entrypoint.sh and the deployment behaves
# exactly as it did before it existed. Nothing here runs on an upgrade until
# an operator sets the variable.
#
# IDEMPOTENT BY CONSTRUCTION. Every statement is a create-if-absent, an ALTER
# that converges attributes, or a GRANT/REVOKE — all repeatable. Running it
# twice produces the same end state, which matters because it runs on EVERY
# container start, not once.
#
# Required environment:
#   DATABASE_URL                  owner/superuser connection (same one
#                                 drizzle-kit migrate uses)
#   METAMCP_RUNTIME_DB_PASSWORD   password to set on the runtime role
# Optional:
#   METAMCP_RUNTIME_DB_ROLE       role name (default: metamcp_runtime)

set -eu

# Blank means UNSET, matching `db/runtime-connection.ts` exactly.
#
# The two must agree or they disagree in a dangerous direction. The TS resolver
# treats a whitespace-only value as unset (so the app keeps DATABASE_URL); if
# this script instead accepted those spaces as a real password it would report
# a converged role while the app served every request as the superuser — and
# the reverse, a whitespace-only role name, creates a role literally named with
# spaces that nothing ever connects as. Both were reachable before this gate.
is_blank() {
    case "$1" in
        *[![:space:]]*) return 1 ;;
        *) return 0 ;;
    esac
}

if [ -z "${DATABASE_URL:-}" ] || is_blank "${DATABASE_URL:-}"; then
    echo "ensure-runtime-role: DATABASE_URL is not set" >&2
    exit 1
fi

if [ -z "${METAMCP_RUNTIME_DB_PASSWORD:-}" ] || is_blank "${METAMCP_RUNTIME_DB_PASSWORD:-}"; then
    echo "ensure-runtime-role: METAMCP_RUNTIME_DB_PASSWORD is not set" >&2
    exit 1
fi

# Blank role name falls back to the default rather than erroring: that is what
# the resolver does with the same input, and the two have to agree on which
# role the app will dial.
if is_blank "${METAMCP_RUNTIME_DB_ROLE:-}"; then
    RUNTIME_ROLE="metamcp_runtime"
else
    RUNTIME_ROLE="$METAMCP_RUNTIME_DB_ROLE"
fi

echo "ensure-runtime-role: converging role '${RUNTIME_ROLE}'..."

# Values reach psql through -v rather than through a generated `\set` heredoc
# because -v takes them VERBATIM: no shell-side escaping layer to get subtly
# wrong for a password containing a quote or a backslash. psql then re-quotes
# them safely at each use site (:'x' -> SQL literal, and format(%I/%L) inside
# the generated statements). The password is briefly visible in this process's
# argv, which is not an additional exposure: anything that could read it can
# already read DATABASE_URL — the SUPERUSER credential — out of the same
# container's environment, and this process has exited before any MCP server
# child is spawned.
psql "$DATABASE_URL" \
    --no-psqlrc \
    --quiet \
    -v ON_ERROR_STOP=1 \
    -v runtime_role="$RUNTIME_ROLE" \
    -v runtime_password="$METAMCP_RUNTIME_DB_PASSWORD" \
    <<'SQL'
-- FIRST statement, and it has to be first.
--
-- The CREATE below is a check-then-act: `WHERE NOT EXISTS (SELECT 1 FROM
-- pg_roles ...)` is evaluated, and only then is CREATE ROLE executed. Two
-- containers booting at once — a rolling restart, a replica set, a compose
-- stack coming up after a host reboot — both see "absent" and both run the
-- CREATE; the loser gets `role already exists`, ON_ERROR_STOP turns that into
-- a non-zero exit, and docker-entrypoint.sh treats a non-zero exit as fatal.
-- So the race does not corrupt anything, it just refuses to start a container
-- for a reason that has nothing to do with that container. Reproduced.
--
-- A session-level advisory lock serialises the whole script instead. It is
-- released when psql disconnects, including on a crash, so there is no stuck
-- lock to clean up. `hashtext` of a fixed string keeps the key derived from
-- something readable rather than a magic integer.
SELECT pg_advisory_lock(hashtext('metamcp.ensure_runtime_role'))
\gset _lock_

-- `\gexec` rather than a DO block for every statement that needs a psql
-- variable: psql does NOT interpolate :vars inside dollar-quoted strings, so
-- `DO $$ ... :'runtime_role' ... $$` would send the literal text `:'runtime_role'`
-- to the server. Building the statement in a SELECT and executing it with
-- \gexec keeps interpolation in the one place psql actually performs it.

-- Postgres has no CREATE ROLE IF NOT EXISTS. The WHERE NOT EXISTS makes the
-- SELECT return zero rows when the role is already there, and \gexec on zero
-- rows executes nothing.
SELECT format(
    'CREATE ROLE %I WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD %L',
    :'runtime_role', :'runtime_password')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'runtime_role')
\gexec

-- Unconditional ALTER so an existing role CONVERGES rather than being trusted.
-- A role that was hand-created as SUPERUSER (or later promoted) silently
-- defeats the entire point of this script; re-asserting the attributes on
-- every boot is what makes that state unreachable while this runs.
SELECT format(
    'ALTER ROLE %I WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD %L',
    :'runtime_role', :'runtime_password')
\gexec

-- ---------------------------------------------------------------------------
-- Baseline grants: ordinary application DML on everything in `public`.
-- ---------------------------------------------------------------------------
SELECT format('GRANT CONNECT ON DATABASE %I TO %I', current_database(), :'runtime_role')
\gexec

SELECT format('GRANT USAGE ON SCHEMA public TO %I', :'runtime_role')
\gexec

SELECT format('GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO %I', :'runtime_role')
\gexec

-- No table in the schema uses a sequence today. Granted anyway because the
-- failure mode of forgetting is an INSERT that fails at runtime on the first
-- table that adds one, long after this script was last read.
SELECT format('GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO %I', :'runtime_role')
\gexec

-- Future migrations create tables as the role running THIS script (the same
-- owner drizzle-kit migrates as), so a default-privilege grant with the
-- default grantor covers them without another pass here.
SELECT format(
    'ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO %I',
    :'runtime_role')
\gexec

SELECT format(
    'ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO %I',
    :'runtime_role')
\gexec

-- ---------------------------------------------------------------------------
-- Audit-table revokes — the half that makes "immutable" true.
--
-- !!! A NEW AUDIT TABLE MUST BE ADDED TO THE LIST BELOW. !!!
-- The ALTER DEFAULT PRIVILEGES above deliberately grants full DML on every
-- table a future migration creates, so an audit table added later starts out
-- UPDATE-able and DELETE-able by the runtime role unless it is named here.
-- There is no way to detect "this is an audit table" automatically, and
-- guessing from the name would fail closed on the wrong tables; an explicit
-- list that a reviewer can read is the trade.
--
-- Per-table policy:
--   audit_log        INSERT + SELECT only. Nothing prunes it in-app — its
--                    retention is an ops-level act performed deliberately as
--                    the owner, not something the gateway credential can do.
--   tool_call_audit  INSERT + SELECT + DELETE. Its in-app pruner hard-deletes
--                    rows past TOOL_AUDIT_RETENTION_DAYS, so DELETE has to
--                    stay.
--
--                    BE CLEAR ABOUT WHAT THE GRANT ALONE DOES. A granted
--                    DELETE cannot distinguish "prune the aged tail" from
--                    "empty the table", so the revokes here are not what
--                    bounds it. Migration 0032 is: BEFORE UPDATE / TRUNCATE
--                    triggers that raise at any row age, plus a BEFORE DELETE
--                    trigger that raises for any row whose called_at is
--                    younger than 30 days. Revoking UPDATE and TRUNCATE here
--                    is still worth doing, because a grant stops the
--                    statement before the trigger has to, but the 30-day
--                    window is what makes DELETE mean "prune".
--   gateway_events   INSERT + SELECT + DELETE, the same grant shape as
--                    tool_call_audit and, since 0032, the same exposure.
--                    Migration 0031 gives this table the identical trigger
--                    set: UPDATE and TRUNCATE raise at any row age, and
--                    DELETE raises for anything younger than 30 days. So the
--                    DELETE left standing here reaches only the aged tail,
--                    and a statement spanning the boundary rolls back whole
--                    rather than partially succeeding. That is exactly the
--                    grant its retention sweeper needs and nothing beyond it.
--
--                    `to_regclass IS NOT NULL` below remains the guard for a
--                    database that has not run 0031 yet: an absent table is
--                    skipped, not an error.
--
-- TRUNCATE is revoked even though it was never granted above. It is the third
-- wipe verb, it does not fire row-level triggers, and an operator who ran an
-- extra GRANT by hand should still be converged back by the next boot.
-- ---------------------------------------------------------------------------
SELECT format('REVOKE %s ON TABLE %s FROM %I', t.revoked, t.tbl, :'runtime_role')
FROM (VALUES
    ('public.audit_log',       'UPDATE, DELETE, TRUNCATE'),
    ('public.tool_call_audit', 'UPDATE, TRUNCATE'),
    ('public.gateway_events',  'UPDATE, TRUNCATE')
) AS t(tbl, revoked)
WHERE to_regclass(t.tbl) IS NOT NULL
\gexec

-- ---------------------------------------------------------------------------
-- Self-check. A GRANT/REVOKE script that reports success without asserting the
-- end state is how a deployment ends up believing in an immutability it does
-- not have. ON_ERROR_STOP=1 turns any RAISE below into a non-zero exit, which
-- docker-entrypoint.sh treats as fatal.
--
-- The role name travels into the DO block through a session GUC because psql
-- will not interpolate into the dollar-quoted body. Only the name — never the
-- password — needs to make that trip.
-- ---------------------------------------------------------------------------
-- `\gset` rather than a bare semicolon so the assignment does not print a
-- result row into the entrypoint log.
SELECT set_config('metamcp.ensure_runtime_role', :'runtime_role', false)
\gset _ensure_

DO $verify$
DECLARE
    v_role text := current_setting('metamcp.ensure_runtime_role');
    v_super boolean;
    v_login boolean;
BEGIN
    SELECT rolsuper, rolcanlogin INTO v_super, v_login
    FROM pg_roles WHERE rolname = v_role;

    IF v_super IS NULL THEN
        RAISE EXCEPTION 'runtime role % does not exist after ensure', v_role;
    END IF;
    IF v_super THEN
        RAISE EXCEPTION 'runtime role % is a SUPERUSER; audit triggers would stay bypassable', v_role;
    END IF;
    IF NOT v_login THEN
        RAISE EXCEPTION 'runtime role % cannot LOGIN', v_role;
    END IF;

    -- Checked explicitly so the failure names the cause. Without it,
    -- has_table_privilege() below raises a bare "relation does not exist" —
    -- true, but it buries the actual problem, which is that this script ran
    -- against a database the migrations have not been applied to.
    IF to_regclass('public.audit_log') IS NULL THEN
        RAISE EXCEPTION 'audit_log does not exist — run the migrations before ensuring the runtime role';
    END IF;

    -- Asserted against has_table_privilege rather than against the GRANT
    -- statements above: the question worth answering is what the catalog says
    -- the role can do, not what this file asked for.
    IF has_table_privilege(v_role, 'public.audit_log', 'UPDATE')
        OR has_table_privilege(v_role, 'public.audit_log', 'DELETE')
        OR has_table_privilege(v_role, 'public.audit_log', 'TRUNCATE') THEN
        RAISE EXCEPTION 'runtime role % can still mutate audit_log', v_role;
    END IF;
    IF NOT has_table_privilege(v_role, 'public.audit_log', 'INSERT')
        OR NOT has_table_privilege(v_role, 'public.audit_log', 'SELECT') THEN
        RAISE EXCEPTION 'runtime role % cannot append to audit_log', v_role;
    END IF;

    IF to_regclass('public.tool_call_audit') IS NOT NULL THEN
        IF has_table_privilege(v_role, 'public.tool_call_audit', 'UPDATE')
            OR has_table_privilege(v_role, 'public.tool_call_audit', 'TRUNCATE') THEN
            RAISE EXCEPTION 'runtime role % can still rewrite tool_call_audit', v_role;
        END IF;
        IF NOT has_table_privilege(v_role, 'public.tool_call_audit', 'DELETE') THEN
            RAISE EXCEPTION 'runtime role % cannot prune tool_call_audit', v_role;
        END IF;
    END IF;

    -- gateway_events (migration 0031) carries the same trigger set as
    -- tool_call_audit, so the runtime role's grant matrix on it must match:
    -- INSERT + SELECT + DELETE held, UPDATE + TRUNCATE refused. Guarded by
    -- to_regclass so a database that has not run 0031 yet converges rather than
    -- erroring. The unconditional REVOKE above already re-runs every boot; this
    -- block is what makes the SCRIPT fail loudly if that end state is ever not
    -- reached (a hand-run GRANT on a boot where the REVOKE was edited away, a
    -- REVOKE that silently no-oped), the way the two blocks above do for the
    -- other audit tables.
    IF to_regclass('public.gateway_events') IS NOT NULL THEN
        IF has_table_privilege(v_role, 'public.gateway_events', 'UPDATE')
            OR has_table_privilege(v_role, 'public.gateway_events', 'TRUNCATE') THEN
            RAISE EXCEPTION 'runtime role % can still rewrite gateway_events', v_role;
        END IF;
        -- DELETE is held on purpose: the in-app retention sweeper prunes the
        -- aged tail, and migration 0031's age-gated DELETE trigger is what
        -- bounds that grant to rows past the 30-day window. SELECT and INSERT
        -- are the history read and the record() append. Asserted positively so
        -- a REVOKE that reached too far fails the boot rather than silently
        -- breaking the write path or the sweeper.
        IF NOT has_table_privilege(v_role, 'public.gateway_events', 'INSERT')
            OR NOT has_table_privilege(v_role, 'public.gateway_events', 'SELECT')
            OR NOT has_table_privilege(v_role, 'public.gateway_events', 'DELETE') THEN
            RAISE EXCEPTION 'runtime role % cannot append to or prune gateway_events', v_role;
        END IF;
    END IF;

    RAISE NOTICE 'runtime role % converged: NOSUPERUSER, LOGIN, audit_log append-only', v_role;
END
$verify$;
SQL

echo "ensure-runtime-role: role '${RUNTIME_ROLE}' converged."
