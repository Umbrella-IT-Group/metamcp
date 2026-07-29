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
