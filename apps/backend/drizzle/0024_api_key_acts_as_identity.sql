-- API-key-bound identity (acts-as). api_keys.acts_as_user_id names the ONE
-- better-auth user whose delegated m365 identity requests authenticated by
-- this key exercise. NULL (the default, and the state of every existing key)
-- means NO identity: the m365 injected fetch keeps fail-closing for api-key
-- consumers exactly as before this migration. Non-NULL is an EXPLICIT,
-- admin-set, creation-time binding — the tRPC create path (not this
-- migration) enforces that it is admin-only, immutable through the app, and
-- REQUIRES a non-null endpoint scope (migration 0023): an identity-bound key
-- must be usable on exactly one endpoint, never gateway-wide. `text`, not
-- `uuid`: better-auth users.id is text, matching the existing
-- api_keys.user_id FK. ON DELETE CASCADE: a key bound to a deleted user
-- exercises an identity that no longer exists and dies with it.
--
-- Idempotent (ADD COLUMN IF NOT EXISTS / CREATE INDEX IF NOT EXISTS) per
-- fork convention. Journal "when" deliberately exceeds 0023's
-- (1785196800000): drizzle only applies entries whose "when" is above the
-- max already applied — see UMBRELLA_FORK.md's migration-ordering note.
ALTER TABLE "api_keys" ADD COLUMN IF NOT EXISTS "acts_as_user_id" text REFERENCES "users"("id") ON DELETE CASCADE;
CREATE INDEX IF NOT EXISTS "api_keys_acts_as_user_id_idx" ON "api_keys" ("acts_as_user_id");

-- Structural pairing invariant: an identity binding REQUIRES a single-
-- endpoint scope (migration 0023's endpoint_uuid). The app layer already
-- rejects the combination three times over (zod superRefines, the impl
-- guard, and the middleware's runtime stamp gate), but none of those reach
-- rows written OUTSIDE the app — psql / admin_cli is a routine ops path
-- here. This CHECK makes an unscoped-but-bound row impossible to write at
-- all, so the containment argument (identity is confined to exactly one
-- endpoint) is structural, not policy. Mirrored in schema.ts via drizzle's
-- check(). Guarded with a DO block for idempotency (postgres has no
-- ADD CONSTRAINT IF NOT EXISTS), matching the file's IF-NOT-EXISTS
-- convention in spirit.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'api_keys_acts_as_requires_scope'
      AND conrelid = '"api_keys"'::regclass
  ) THEN
    ALTER TABLE "api_keys" ADD CONSTRAINT "api_keys_acts_as_requires_scope"
      CHECK ("acts_as_user_id" IS NULL OR "endpoint_uuid" IS NOT NULL);
  END IF;
END $$;
