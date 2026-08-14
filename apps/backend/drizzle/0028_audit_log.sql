-- Control-plane security audit log — the durable, un-wipeable record the
-- 2026-08-13 incident proved this gateway did not have.
--
-- Before this table the only durable stores were `tool_call_audit` (data
-- plane, actively hard-DELETE pruned) and the in-memory Live Logs ring
-- buffer (2000 entries, gone on restart, and clearable from the admin UI).
-- Neither captured a single control-plane security event: not one RBAC
-- denial, not one refused bearer credential. The stolen-key detector was
-- silent for the entire incident because nothing wrote those events down.
--
-- Column set is the common envelope every emitter fills (who / from where /
-- what / against what / outcome / which request). `detail` carries the
-- event-specific extras. Raw secrets are NEVER stored — the emitter puts a
-- sha256 + last-4 fingerprint in `detail`, the same discipline migration
-- 0019 applied to tool-call params.
--
-- Deliberately NOT here: `seq` / `prev_hash` / `row_hash`. Hash-chained
-- tamper evidence is Phase 2 and needs an off-DB HMAC secret plus a single
-- ordered writer; shipping the columns before the chain would leave three
-- always-NULL columns that read as "verified" to anyone glancing at the
-- schema.
--
-- Idempotent (IF NOT EXISTS / CREATE OR REPLACE / DROP TRIGGER IF EXISTS)
-- per fork convention. Journal "when" (1786838400000) deliberately exceeds
-- 0027's (1786752000000): drizzle only applies entries whose "when" is above
-- the max already applied — see UMBRELLA_FORK.md's migration-ordering note.
CREATE TABLE IF NOT EXISTS "audit_log" (
	"uuid" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"occurred_at" timestamp with time zone DEFAULT now() NOT NULL,
	"actor_type" text NOT NULL,
	"actor_id" text,
	"actor_label" text,
	"actor_ip" text,
	"actor_user_agent" text,
	"action" text NOT NULL,
	"target_type" text,
	"target_id" text,
	"outcome" text NOT NULL,
	"request_id" text,
	"http_status" integer,
	"detail" jsonb DEFAULT '{}'::jsonb NOT NULL
);
--> statement-breakpoint
-- The four query shapes an incident responder actually types: "what happened
-- in this window", "show me every denial of class X", "everything this actor
-- did", "everything that was refused".
CREATE INDEX IF NOT EXISTS "audit_log_occurred_at_idx" ON "audit_log" ("occurred_at");
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "audit_log_action_idx" ON "audit_log" ("action");
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "audit_log_actor_id_idx" ON "audit_log" ("actor_id");
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "audit_log_outcome_idx" ON "audit_log" ("outcome");
--> statement-breakpoint
-- DB-level immutability stopgap.
--
-- The application connects as `metamcp_user`, which on the official
-- postgres:16-alpine image is the cluster bootstrap SUPERUSER — one
-- DATABASE_URL serves both drizzle-kit migrate and the runtime, and nothing
-- in this repo ever creates a second role. A `REVOKE UPDATE, DELETE` is
-- therefore a no-op here: superusers bypass grants. A trigger is not
-- bypassed by privilege, so it is what actually blocks the app (and a
-- careless psql session) from rewriting history today.
--
-- What this does NOT stop: a superuser who deliberately runs
-- `SET session_replication_role = 'replica'` or drops the trigger. Closing
-- that needs the Phase-2 NOSUPERUSER runtime role plus the hash chain; this
-- is the interim, and it is honest about being one.
CREATE OR REPLACE FUNCTION audit_log_block_mutation() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'audit_log is append-only; % is not permitted', TG_OP;
END; $$ LANGUAGE plpgsql;
--> statement-breakpoint
DROP TRIGGER IF EXISTS audit_log_no_update ON "audit_log";
--> statement-breakpoint
CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON "audit_log"
  FOR EACH ROW EXECUTE FUNCTION audit_log_block_mutation();
--> statement-breakpoint
DROP TRIGGER IF EXISTS audit_log_no_delete ON "audit_log";
--> statement-breakpoint
CREATE TRIGGER audit_log_no_delete BEFORE DELETE ON "audit_log"
  FOR EACH ROW EXECUTE FUNCTION audit_log_block_mutation();
--> statement-breakpoint
-- TRUNCATE is the third wipe verb and row-level triggers do not fire for it,
-- so blocking UPDATE and DELETE alone would leave `TRUNCATE audit_log` as a
-- one-statement path to exactly the outcome this table exists to prevent.
-- Statement-level, because TRUNCATE has no rows to fire per.
DROP TRIGGER IF EXISTS audit_log_no_truncate ON "audit_log";
--> statement-breakpoint
CREATE TRIGGER audit_log_no_truncate BEFORE TRUNCATE ON "audit_log"
  FOR EACH STATEMENT EXECUTE FUNCTION audit_log_block_mutation();
