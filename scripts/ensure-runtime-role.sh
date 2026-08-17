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

RUNTIME_ROLE="${METAMCP_RUNTIME_DB_ROLE:-metamcp_runtime}"

if [ -z "${DATABASE_URL:-}" ]; then
    echo "ensure-runtime-role: DATABASE_URL is not set" >&2
    exit 1
fi

if [ -z "${METAMCP_RUNTIME_DB_PASSWORD:-}" ]; then
    echo "ensure-runtime-role: METAMCP_RUNTIME_DB_PASSWORD is not set" >&2
    exit 1
fi

if [ -z "$RUNTIME_ROLE" ]; then
    echo "ensure-runtime-role: METAMCP_RUNTIME_DB_ROLE is empty" >&2
    exit 1
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
--                    stay. In-window immutability is carried by UPDATE being
--                    revoked plus the table's own triggers — which a
--                    NOSUPERUSER role can no longer bypass, and that is the
--                    entire point of this script.
--   gateway_events   Same shape as tool_call_audit, listed ahead of the
--                    migration that creates it. `to_regclass IS NOT NULL`
--                    below is the guard: an absent table is skipped, not an
--                    error, so this script is correct both before and after
--                    that migration lands.
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

    RAISE NOTICE 'runtime role % converged: NOSUPERUSER, LOGIN, audit_log append-only', v_role;
END
$verify$;
SQL

echo "ensure-runtime-role: role '${RUNTIME_ROLE}' converged."
