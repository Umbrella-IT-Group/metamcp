-- Admin-plane API key scope. api_keys.admin_plane_scope splits the admin-plane
-- (control-plane, migration 0038) key population in two:
--
--   sync      what a CI credential needs: the configuration-sync procedures
--             and nothing else. This is the value of EVERY existing row, and
--             the default of every new one, so a deploy only ever removes
--             reach: no key gains a procedure it did not hold before.
--   operator  the sync procedures plus the operator's tooling (key and policy
--             inventory, containment, provisioning, and the narrow data-plane
--             key mint). Only a human administrator can create one, from the
--             admin UI: no procedure an admin-plane key can call writes this
--             column, and the CHECKs below keep it off every data-plane key.
--
-- The set of procedures each scope may call lives in packages/trpc/src/trpc.ts
-- (ADMIN_PLANE_SYNC_PROCEDURES, ADMIN_PLANE_OPERATOR_PROCEDURES). The column
-- is read only on the admin-plane bearer path (validateAdminPlaneApiKey); the
-- data-plane authentication read does not select it.
--
-- Creation-only and immutable through the app: it is absent from every update
-- schema and repository setter, the same rule acts-as bindings follow
-- (migration 0024). A promotion path is exactly what a stolen key would want.
--
-- Text plus CHECKs rather than a pgEnum, matching migrations 0020, 0038 and
-- 0041: a CHECK is DO-guardable, and it makes a row written outside the app
-- (psql, admin tooling) unable to carry a scope the gateway does not know.
-- The second CHECK keeps the scope meaningful only where it can apply: a
-- data-plane key is always `sync`, so "operator" can never be read off a row
-- that is not an admin-plane key.
--
-- No index: the column is read from the row the key_hash lookup already
-- fetches (the unique constraint from migration 0034 is the btree that lookup
-- uses), the same reasoning migration 0038 gives for admin_plane.
--
-- Idempotent (ADD COLUMN IF NOT EXISTS / DO-guarded CHECKs) per fork
-- convention. Journal "when" deliberately exceeds 0042's (1788048000000):
-- drizzle only applies entries whose "when" is above the max already applied,
-- so an entry with a stale "when" is SILENTLY skipped -- see the
-- migration-ordering note in UMBRELLA_FORK.md. Mirrored in schema.ts so a
-- fresh `drizzle-kit generate` produces no diff.
--
-- An image from before this migration ignores the column and applies its own
-- single procedure list to every admin-plane key, so rolling the image back
-- needs no down-migration. Prefer a forward fix.
ALTER TABLE "api_keys" ADD COLUMN IF NOT EXISTS "admin_plane_scope" text NOT NULL DEFAULT 'sync';
--> statement-breakpoint
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'api_keys_admin_plane_scope_valid'
      AND conrelid = '"api_keys"'::regclass
  ) THEN
    ALTER TABLE "api_keys" ADD CONSTRAINT "api_keys_admin_plane_scope_valid"
      CHECK ("admin_plane_scope" IN ('sync', 'operator'));
  END IF;
END $$;
--> statement-breakpoint
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'api_keys_admin_plane_scope_requires_admin_plane'
      AND conrelid = '"api_keys"'::regclass
  ) THEN
    ALTER TABLE "api_keys" ADD CONSTRAINT "api_keys_admin_plane_scope_requires_admin_plane"
      CHECK ("admin_plane" = true OR "admin_plane_scope" = 'sync');
  END IF;
END $$;
