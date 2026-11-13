-- Per-endpoint presentation: what a client is told when it connects to an
-- endpoint, and how its tool list is shaped.
--
--   title                a display title sent as serverInfo.title at initialize
--   instructions         a short paragraph sent as the initialize result's
--                        instructions (model-visible guidance for the endpoint)
--   tool_listing         'full' (today's behaviour) or 'lean'
--   omit_output_schemas  leave outputSchema out of tools/list results
--
-- A SEPARATE 1:1 TABLE, not columns on endpoints. (1) The endpoint row is
-- selected by name on every data-plane request, before authentication, from a
-- column list that is repeated in many places in the repository layer and the
-- shared types; four more columns there would add bytes to the hottest read and
-- touch every one of those lists, while a new table is read once per new
-- session and touches none of them. (2) Text that reaches models is a human
-- administrator's act, the same class as tool overrides. The endpoint update
-- procedure can be called by an admin-plane key; a procedure for this table is
-- in neither admin-plane procedure set, so authorship is human-only by default
-- instead of by a field stripped inside a shared procedure.
--
-- NO ROW MEANS TODAY'S BEHAVIOUR. The table ships empty, and the application
-- keeps a row only while at least one setting is non-default (setting
-- everything back to default deletes it), so a missing row is provably the
-- behaviour every endpoint has always had and a deploy changes nothing for any
-- existing caller. The row is read at initialize and pinned for the session
-- (mcp_sessions.init_params), so editing it never changes a live session.
--
-- tool_listing is text plus a CHECK rather than a pgEnum, as in 0040 and 0043:
-- a CHECK is DO-guardable, refuses any other value from a row written outside
-- the app, and a later value is one constraint swap instead of an ALTER TYPE.
-- The CHECK already allows 'lean' although the first release that uses this
-- table serves only 'full': the release that serves lean then needs no
-- migration, and the application reads (and clears) a stored 'lean' row
-- whichever release wrote it.
--
-- The length bounds mirror the application's (80 for the title, 1500 for the
-- instructions); the application is the stricter layer, counting UTF-16 code
-- units where Postgres counts code points and also refusing Unicode format and
-- C1 control characters (Postgres regular expressions have no \p classes), so
-- the CHECKs are a backstop against rows written outside the app. A title is a
-- single line; instructions may hold TAB and LF. 1500 leaves room for the
-- paragraph the lean listing prepends (327 characters plus a blank line)
-- under 2048 characters.
--
-- ON DELETE CASCADE: deleting an endpoint deletes its presentation, so an
-- endpoint recreated under the same name starts at the defaults (this includes
-- the endpoints a BOOTSTRAP_RECREATE_USER recreate cascades away).
--
-- No extra index: the primary key is the lookup.
--
-- Idempotent (CREATE TABLE IF NOT EXISTS / DO-guarded constraints) per fork
-- convention. Journal "when" (1788220800000) deliberately exceeds 0043's
-- (1788134400000): drizzle only applies entries whose "when" is above the max
-- already applied, so an entry with a stale "when" is SILENTLY skipped; see the
-- migration-ordering note in UMBRELLA_FORK.md. Mirrored in schema.ts, so a
-- fresh `drizzle-kit generate` produces no diff.
--
-- An image from before this migration ignores the table (and the init_params
-- pin), so rolling the image back needs no down-migration. Prefer a forward
-- fix.
CREATE TABLE IF NOT EXISTS "endpoint_presentation" (
	"endpoint_uuid" uuid PRIMARY KEY NOT NULL,
	"title" text,
	"instructions" text,
	"tool_listing" text DEFAULT 'full' NOT NULL,
	"omit_output_schemas" boolean DEFAULT false NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
-- Postgres has no ADD CONSTRAINT IF NOT EXISTS, so each constraint is guarded
-- the same way 0033, 0040 and 0043 guard theirs.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'endpoint_presentation_endpoint_uuid_fk'
      AND conrelid = '"endpoint_presentation"'::regclass
  ) THEN
    ALTER TABLE "endpoint_presentation"
      ADD CONSTRAINT "endpoint_presentation_endpoint_uuid_fk"
      FOREIGN KEY ("endpoint_uuid") REFERENCES "endpoints"("uuid") ON DELETE CASCADE;
  END IF;
END $$;
--> statement-breakpoint
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'endpoint_presentation_tool_listing_check'
      AND conrelid = '"endpoint_presentation"'::regclass
  ) THEN
    ALTER TABLE "endpoint_presentation"
      ADD CONSTRAINT "endpoint_presentation_tool_listing_check"
      CHECK ("tool_listing" IN ('full', 'lean'));
  END IF;
END $$;
--> statement-breakpoint
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'endpoint_presentation_title_check'
      AND conrelid = '"endpoint_presentation"'::regclass
  ) THEN
    ALTER TABLE "endpoint_presentation"
      ADD CONSTRAINT "endpoint_presentation_title_check"
      CHECK ("title" IS NULL OR (char_length("title") BETWEEN 1 AND 80 AND "title" !~ '[\r\n]'));
  END IF;
END $$;
--> statement-breakpoint
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'endpoint_presentation_instructions_check'
      AND conrelid = '"endpoint_presentation"'::regclass
  ) THEN
    ALTER TABLE "endpoint_presentation"
      ADD CONSTRAINT "endpoint_presentation_instructions_check"
      CHECK ("instructions" IS NULL OR (char_length("instructions") BETWEEN 1 AND 1500 AND "instructions" !~ '[\u0001-\u0008\u000B\u000C\u000E-\u001F\u007F]'));
  END IF;
END $$;
