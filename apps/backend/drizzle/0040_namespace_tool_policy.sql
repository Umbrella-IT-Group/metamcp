-- Per-namespace tool policy: how a namespace treats a tool that has NO row in
-- namespace_tool_mappings.
--
--   allow_all   the behaviour every namespace has always had: a tool with no
--               row is served, an INACTIVE row hides it, an ACTIVE row serves
--               it. Curation is a denylist, so a tool added to a server after
--               the namespace was curated is served there with no review.
--   allowlist   no row means INACTIVE: only a tool with an ACTIVE row is listed
--               (tools/list) or callable (tools/call). Curation is an
--               allowlist, so a new tool stays hidden until an administrator
--               switches its row on.
--
-- The filter middleware (lib/metamcp/metamcp-middleware/filter-tools) reads
-- this column on both the list path and the call path. The writers that create
-- mapping rows (refreshTools' bulk upsert and the namespace update that
-- re-mounts servers) create NEW rows INACTIVE in an allowlist namespace and
-- never change an existing row's status there, so a refresh cannot silently
-- allowlist what it sees. Setting the column is the admin-only
-- `namespaces.setToolPolicy` procedure, audited as `namespace.tool_policy`.
--
-- DEFAULT 'allow_all' backfills every existing namespace with today's
-- behaviour, so the deploy is inert: nothing changes until an administrator
-- flips a namespace. Rolling a namespace back is setting it to 'allow_all'
-- again, one call. NOT NULL for the reason acts-as (0024) and admin_plane
-- (0038) chose their shapes: a null policy would be a silently ambiguous gate.
--
-- text plus a CHECK rather than a pgEnum: the CHECK refuses any other value at
-- write time exactly as an enum would, a row written outside the app (psql,
-- admin_cli) included, and a later value is one DO-guarded constraint swap
-- instead of an ALTER TYPE that cannot run inside a transaction on older
-- servers. The filter still reads any value other than 'allow_all' as
-- 'allowlist', so even a row that somehow bypassed the CHECK fails toward the
-- stricter policy.
--
-- Idempotent (ADD COLUMN IF NOT EXISTS / DO-guarded CHECK) per fork
-- convention. Journal "when" deliberately exceeds 0039's (1787788800000):
-- drizzle only applies entries whose "when" is above the max already applied,
-- so a stale "when" is SILENTLY skipped -- see the migration-ordering note in
-- UMBRELLA_FORK.md. Mirrored in schema.ts via text().notNull().default() plus a
-- check() clause so a fresh `drizzle-kit generate` produces no diff.
--
-- No index: the filter reads the column by primary key (namespaces.uuid).
ALTER TABLE "namespaces" ADD COLUMN IF NOT EXISTS "tool_policy" text NOT NULL DEFAULT 'allow_all';
--> statement-breakpoint
-- Postgres has no ADD CONSTRAINT IF NOT EXISTS, so the CHECK is guarded the
-- same way 0024 and 0038 guard theirs.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'namespaces_tool_policy_check'
      AND conrelid = '"namespaces"'::regclass
  ) THEN
    ALTER TABLE "namespaces" ADD CONSTRAINT "namespaces_tool_policy_check"
      CHECK ("tool_policy" IN ('allow_all', 'allowlist'));
  END IF;
END $$;
