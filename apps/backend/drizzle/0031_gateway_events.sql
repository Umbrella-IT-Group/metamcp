-- Gateway activity history — the durable record behind the Live Logs page.
--
-- Until this table the Live Logs view rendered ONE source: an in-memory ring
-- buffer of 2000 entries (`lib/metamcp/log-store.ts`) that is gone the moment
-- the process restarts. Connection attempts, client sessions, backend stderr
-- and gateway lifecycle events had no durable home anywhere in the product, so
-- the two questions the page exists to answer — "was this failing yesterday
-- too?" and "who was connected when it broke?" — could not be answered at all
-- once the buffer rolled or the container was replaced.
--
-- SCOPE, and why `tool_call` is missing from the category list. Tool calls are
-- already persisted, per call, by migration 0019's `tool_call_audit`. Mirroring
-- them here would double the write rate on the busiest event class in the
-- gateway to store a strictly poorer copy (no params hash, no latency, no
-- namespace). The writer filters that category out; this table covers the
-- ACTIVITY events that had no durable home, not the ones that already do.
--
-- RELATIONSHIP TO `audit_log` (migration 0028). Deliberately a third table
-- rather than more rows in that one. `audit_log` is the control-plane SECURITY
-- record: who authenticated, what was refused, which credential was presented,
-- and it is append-only forever with no prune path at all. This table is
-- OPERATIONAL history: connection churn, session opens, backend output. It is
-- high-volume, it is mostly `info`, and it is meant to age out. Merging them
-- would either force security rows to inherit a retention policy or force
-- reconnect noise to be kept forever, and the first of those is the one that
-- ends badly.
--
-- Idempotent (IF NOT EXISTS / CREATE OR REPLACE / DROP TRIGGER IF EXISTS) per
-- fork convention. Journal "when" (1787097600000) deliberately exceeds every
-- earlier entry: drizzle applies only entries whose "when" is above the max
-- already applied, and a misordered one is SILENTLY SKIPPED — the table would
-- simply never exist in production and nothing would fail loudly. See
-- UMBRELLA_FORK.md's migration-ordering note.
CREATE TABLE IF NOT EXISTS "gateway_events" (
	"uuid" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	-- MILLISECOND precision, deliberately, and it is the pagination cursor that
	-- makes it load-bearing rather than a storage nicety. The history is paged
	-- with a keyset on (occurred_at, uuid): a client receives the last row's
	-- timestamp and hands it back to fetch the next page. That value round-trips
	-- through a JavaScript Date, which cannot represent anything finer than a
	-- millisecond. At the default microsecond precision the returned cursor is
	-- therefore slightly EARLIER than the row it came from, so the next page's
	-- `<` comparison excludes every row sharing that millisecond — silently
	-- skipping rows, which is the exact failure keyset pagination exists to
	-- prevent. Storing what the contract can express removes the mismatch
	-- instead of papering over it in the query.
	"occurred_at" timestamp (3) with time zone DEFAULT now() NOT NULL,
	-- connection | client | server | system. Text rather than an enum for the
	-- same reason `audit_log.actor_type` is text: a new event class must never
	-- be able to make this INSERT fail, and a failed INSERT is a silently
	-- missing record.
	"category" text NOT NULL,
	"level" text,
	"server_uuid" uuid,
	"server_name" text,
	"client_name" text,
	"session_id" text,
	"message" text NOT NULL,
	"metadata" jsonb
);
--> statement-breakpoint
-- The two query shapes the history view issues: "what happened in this window"
-- (every page load) and "what happened in this window, of this class" (every
-- category filter). DESC matches the newest-first ordering the keyset
-- pagination uses, so the index answers the ORDER BY as well as the range.
CREATE INDEX IF NOT EXISTS "gateway_events_occurred_at_idx" ON "gateway_events" ("occurred_at" DESC);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "gateway_events_category_occurred_at_idx" ON "gateway_events" ("category", "occurred_at" DESC);
--> statement-breakpoint
-- IMMUTABILITY WINDOW: 30 days, and the number is the requirement rather than
-- a tuning knob.
--
-- The operator requirement is at least 30 days of history that cannot be
-- rewritten or quietly trimmed, because the value of an activity log during an
-- investigation is exactly the part nobody could have edited afterwards. But
-- unlike `audit_log`, this table is high-volume operational noise and MUST age
-- out or it grows without bound, so "append-only forever" is not available
-- here.
--
-- The window is how both hold at once. Inside 30 days a row cannot be changed
-- or removed by anything — application, admin gesture, or hand-typed psql.
-- Outside 30 days a DELETE is permitted, which is the single opening the
-- retention sweeper uses.
--
-- UPDATE and TRUNCATE are refused unconditionally at every age. There is no
-- legitimate caller for either: nothing in the application updates a row it has
-- already written, and TRUNCATE is a one-statement path to exactly the outcome
-- this table exists to prevent. Only DELETE is age-gated, and only because
-- retention needs it.
--
-- The application half of the coupling lives in
-- `apps/backend/src/lib/gateway-events/retention.ts`, which floor-clamps
-- GATEWAY_EVENTS_RETENTION_DAYS to 30. If that floor is ever lowered below the
-- interval below, the sweeper's DELETE starts raising instead of pruning — the
-- failure is loud and the record survives, which is the correct direction for
-- the two to disagree in.
--
-- What this does NOT stop, stated as plainly as 0028 states it: a superuser who
-- runs `SET session_replication_role = 'replica'` or drops the trigger. The
-- application connects as the cluster bootstrap superuser today, so a
-- `REVOKE UPDATE, DELETE` would be a no-op (superusers bypass grants) while a
-- trigger is not bypassed by privilege. Closing the remaining gap needs a
-- NOSUPERUSER runtime role; this is the interim and it is honest about it.
CREATE OR REPLACE FUNCTION gateway_events_block_mutation() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'gateway_events is append-only; % is not permitted', TG_OP;
END; $$ LANGUAGE plpgsql;
--> statement-breakpoint
-- Age-gated DELETE. `now()` here is transaction start time, which is the SAME
-- instant the sweeper's own `now() - make_interval(...)` cutoff is evaluated
-- at — the sweeper computes its cutoff in SQL rather than in the application
-- precisely so the two predicates cannot disagree by clock skew at the
-- boundary. A cutoff computed in the application from a clock running ahead of
-- the database would select rows this trigger then refuses, turning routine
-- pruning into a recurring exception.
CREATE OR REPLACE FUNCTION gateway_events_block_recent_delete() RETURNS trigger AS $$
BEGIN
  IF OLD.occurred_at >= now() - interval '30 days' THEN
    RAISE EXCEPTION 'gateway_events rows are immutable for 30 days; this row is not yet prunable';
  END IF;
  RETURN OLD;
END; $$ LANGUAGE plpgsql;
--> statement-breakpoint
DROP TRIGGER IF EXISTS gateway_events_no_update ON "gateway_events";
--> statement-breakpoint
CREATE TRIGGER gateway_events_no_update BEFORE UPDATE ON "gateway_events"
  FOR EACH ROW EXECUTE FUNCTION gateway_events_block_mutation();
--> statement-breakpoint
DROP TRIGGER IF EXISTS gateway_events_no_recent_delete ON "gateway_events";
--> statement-breakpoint
CREATE TRIGGER gateway_events_no_recent_delete BEFORE DELETE ON "gateway_events"
  FOR EACH ROW EXECUTE FUNCTION gateway_events_block_recent_delete();
--> statement-breakpoint
-- Row-level triggers do not fire for TRUNCATE, so without a statement-level one
-- `TRUNCATE gateway_events` would stay a single statement that empties the
-- whole history regardless of row age.
DROP TRIGGER IF EXISTS gateway_events_no_truncate ON "gateway_events";
--> statement-breakpoint
CREATE TRIGGER gateway_events_no_truncate BEFORE TRUNCATE ON "gateway_events"
  FOR EACH STATEMENT EXECUTE FUNCTION gateway_events_block_mutation();
