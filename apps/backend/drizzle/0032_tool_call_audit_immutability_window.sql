-- tool_call_audit: a 30-day immutability window, matching the one 0031 puts on
-- gateway_events and the unconditional block 0028 puts on audit_log.
--
-- WHY THIS TABLE IS LAST. The requirement behind all three is at least 30 days
-- of in-platform log history that cannot be rewritten or quietly trimmed,
-- because the value of a log during an investigation is exactly the part
-- nobody could have edited afterwards. `audit_log` has held that since 0028
-- and `gateway_events` since 0031. `tool_call_audit` (migration 0019) held
-- nothing: no trigger constrained it, so the DELETE its retention pruner needs
-- was an unrestricted DELETE. The credential the gateway serves requests with
-- could empty the table, not merely prune its aged tail, and a rewritten or
-- emptied tool-call history is the single most useful thing to remove after
-- misusing a credential. Migration 0030 made these rows attributable; without
-- this migration they were attributable and erasable at the same time.
--
-- WINDOW SEMANTICS, stated once and enforced below:
--
--   UPDATE    refused at every age, unconditionally. Nothing in the
--             application updates an audit row it has already written, so
--             there is no legitimate caller to accommodate. The repository
--             (db/repositories/tool-call-audit.repo.ts) exposes exactly two
--             methods, `record` and `pruneOlderThan`, and neither updates.
--   TRUNCATE  refused at every age, unconditionally. It is a one-statement
--             path to precisely the outcome this migration exists to prevent,
--             and row-level triggers do not fire for it, so it needs a
--             statement-level trigger of its own.
--   DELETE    refused while `called_at` is inside the last 30 days, permitted
--             once the row is older. This is the single opening, and it exists
--             only because retention needs it.
--
-- THE PRUNER, and why 30 days does not collide with it. Retention is
-- `ToolCallAuditRepository.pruneOlderThan(days)`, called from the five-minute
-- cleanup interval in `routers/oauth/index.ts` with TOOL_AUDIT_RETENTION_DAYS
-- (default 90, values <= 0 disable pruning entirely). Its comparison is
-- `lt(called_at, cutoff)` with `cutoff = now - days`: it deletes rows STRICTLY
-- OLDER than the cutoff and never touches anything newer. At the default 90 it
-- therefore only ever asks to delete rows already 90 days old, which are 60
-- days past the boundary this trigger draws. The two cannot disagree.
--
-- That 60-day gap is also what makes the clock-source difference safe. 0031's
-- sweeper computes its cutoff in SQL so it evaluates at the same instant as
-- the trigger's `now()`; this pruner computes its cutoff in JavaScript from
-- the application's clock instead. For the two to disagree the application
-- clock would have to run more than 60 days AHEAD of the database, which is
-- not a skew, it is a broken host. Narrowing the gap is what would make the
-- clock source matter.
--
-- CONFIGURING TOOL_AUDIT_RETENTION_DAYS BELOW 30 is prevented in the
-- application rather than merely surviving it, and the reason is that the
-- failure mode is worse than "retention is shorter than the floor". The
-- pruner issues ONE statement covering everything older than its cutoff. With
-- retention between 1 and 29 that statement spans this boundary, the trigger
-- raises on the first in-window row, and the raise rolls the WHOLE statement
-- back, so the aged rows the sweep existed to reclaim are not deleted either.
-- Pruning stops altogether behind an error logged every five minutes while the
-- table grows without bound. `lib/tool-audit-retention` therefore clamps 1-29
-- up to 30 at boot with a WARN, so the application never asks for a range the
-- database will refuse. `<= 0` keeps its long-standing meaning of retain
-- forever and is left alone: the floor exists to stop retention going BELOW 30,
-- and forever is not below 30.
--
-- WHAT A TRIGGER BUYS THAT A GRANT DOES NOT. `scripts/ensure-runtime-role.sh`
-- (migration-era change #124) already revokes UPDATE and TRUNCATE from the
-- runtime role. Grants alone are not enough for two reasons: DELETE has to
-- stay granted for the pruner, so the wipe verb that matters most is the one
-- a grant cannot restrict here; and a superuser bypasses grants outright,
-- while nothing bypasses a trigger by privilege. The trigger is what turns
-- "DELETE is granted" into "DELETE means prune".
--
-- THE PRIVILEGE LAYER IS WHAT MAKES IT UNBYPASSABLE. A trigger is not
-- absolute on its own. `ALTER TABLE tool_call_audit DISABLE TRIGGER ...`
-- requires table ownership, and `SET session_replication_role = 'replica'`
-- requires SUPERUSER, so either one is available to whoever holds the
-- bootstrap credential. That is the BREAK GLASS path, and it is deliberately
-- left open: an operator with a legal hold or a corrupted row needs a way in.
-- Using it is itself an event worth recording, because it is indistinguishable
-- at the database level from the tampering this migration is here to stop.
-- What closes the gap for ordinary operation is the runtime role split: with
-- METAMCP_RUNTIME_DB_PASSWORD set, the gateway serves traffic as a
-- NOSUPERUSER role that does not own this table, so it can reach neither
-- lever. Without that split the application still holds the bootstrap
-- superuser and the trigger is a speed bump rather than an enforced property.
-- README's "Separating the runtime credential from the migration credential"
-- section carries the cutover.
--
-- Idempotent (CREATE OR REPLACE FUNCTION / DROP TRIGGER IF EXISTS) per fork
-- convention: a re-run must not crash-loop a deployer. Journal "when"
-- (1787184000000) deliberately exceeds every earlier entry, because drizzle
-- applies only entries whose "when" is above the max already applied and a
-- misordered one is SILENTLY SKIPPED, leaving the triggers simply absent in
-- production with nothing failing loudly. See UMBRELLA_FORK.md's
-- migration-ordering note.
CREATE OR REPLACE FUNCTION tool_call_audit_block_mutation() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'tool_call_audit is append-only; % is not permitted', TG_OP;
END; $$ LANGUAGE plpgsql;
--> statement-breakpoint
-- Age-gated DELETE. `now()` is transaction start time, evaluated inside the
-- deleting transaction, so every row of one multi-row DELETE is judged against
-- one instant rather than against a clock advancing mid-statement.
--
-- The column is `called_at`, not `occurred_at`: this table predates the naming
-- 0028 and 0031 use, and renaming it here would break every reader for a
-- cosmetic gain.
CREATE OR REPLACE FUNCTION tool_call_audit_block_recent_delete() RETURNS trigger AS $$
BEGIN
  IF OLD.called_at >= now() - interval '30 days' THEN
    RAISE EXCEPTION 'tool_call_audit rows are immutable for 30 days; this row is not yet prunable';
  END IF;
  RETURN OLD;
END; $$ LANGUAGE plpgsql;
--> statement-breakpoint
DROP TRIGGER IF EXISTS tool_call_audit_no_update ON "tool_call_audit";
--> statement-breakpoint
CREATE TRIGGER tool_call_audit_no_update BEFORE UPDATE ON "tool_call_audit"
  FOR EACH ROW EXECUTE FUNCTION tool_call_audit_block_mutation();
--> statement-breakpoint
DROP TRIGGER IF EXISTS tool_call_audit_no_recent_delete ON "tool_call_audit";
--> statement-breakpoint
CREATE TRIGGER tool_call_audit_no_recent_delete BEFORE DELETE ON "tool_call_audit"
  FOR EACH ROW EXECUTE FUNCTION tool_call_audit_block_recent_delete();
--> statement-breakpoint
-- Row-level triggers do not fire for TRUNCATE, so without a statement-level
-- one `TRUNCATE tool_call_audit` would stay a single statement that empties
-- the whole history regardless of row age.
DROP TRIGGER IF EXISTS tool_call_audit_no_truncate ON "tool_call_audit";
--> statement-breakpoint
CREATE TRIGGER tool_call_audit_no_truncate BEFORE TRUNCATE ON "tool_call_audit"
  FOR EACH STATEMENT EXECUTE FUNCTION tool_call_audit_block_mutation();
