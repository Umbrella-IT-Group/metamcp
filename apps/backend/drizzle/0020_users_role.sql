-- RBAC: add users.role, the column that gates administrative tRPC mutations
-- (MCP-server / namespace / endpoint create-update-delete + all API-key
-- administration) through adminProcedure. NOT NULL default 'member' so every
-- pre-existing account is backfilled least-privilege and stays that way until
-- explicitly promoted. Idempotent (ADD COLUMN IF NOT EXISTS) per fork
-- convention so a re-run against an already-migrated database is a no-op
-- instead of a hash-mismatch crash-loop.
ALTER TABLE "users" ADD COLUMN IF NOT EXISTS "role" text DEFAULT 'member' NOT NULL;
--> statement-breakpoint
-- Seed the operator as the first admin. Idempotent by email (users.email is
-- UNIQUE, so this touches at most one row) — re-running only re-asserts the
-- role. This account already exists in prod, so the UPDATE promotes it on the
-- first apply. On a fresh database where the row does not exist yet it affects
-- zero rows (the account is later created as the 'member' default and must be
-- promoted by re-running this or a manual UPDATE) — an intentional no-op, not
-- a failure.
UPDATE "users" SET "role" = 'admin' WHERE "email" = 'alex@umbrellaitgroup.com';
