-- Account disable — the incident-response primitive that sits between
-- revoke and delete.
--
-- Revoking access severs live sessions/tokens/keys but the account can sign
-- straight back in, and deleting the account destroys the authoritative
-- record of who it was (and cascades into other users' endpoints and keys —
-- see the Access dashboard's delete preview). Neither is what an operator
-- wants at 2am against a self-registered account they are still
-- investigating. `disabled` locks the account out while preserving it
-- whole.
--
-- NOT NULL DEFAULT false so every pre-existing and future account is
-- enabled until someone explicitly locks it — the same least-privilege
-- shape migration 0020 used for `role`. Deliberately NOT surfaced through
-- better-auth `additionalFields` with `input: true`: nothing a client sends
-- may set this. Enforcement lives in two places, both required — a
-- `session.create.before` database hook (blocks NEW logins) and the tRPC
-- context (rejects the sessions a user ALREADY holds, without waiting for
-- the 30-day expiry). See apps/backend/src/auth.ts and src/trpc.ts.
--
-- disabled_at / disabled_by are the audit trail: an account that is locked
-- out with no record of who did it or when is a support ticket nobody can
-- answer. disabled_by is ON DELETE SET NULL rather than CASCADE — deleting
-- the administrator who performed the action must never quietly re-enable
-- (or erase the record of) an account they locked.
--
-- Idempotent (ADD COLUMN IF NOT EXISTS / CREATE INDEX IF NOT EXISTS) per
-- fork convention. Journal "when" deliberately exceeds 0026's
-- (1786665600000): drizzle only applies entries whose "when" is above the
-- max already applied — see UMBRELLA_FORK.md's migration-ordering note.
ALTER TABLE "users" ADD COLUMN IF NOT EXISTS "disabled" boolean DEFAULT false NOT NULL;
ALTER TABLE "users" ADD COLUMN IF NOT EXISTS "disabled_at" timestamp with time zone;
ALTER TABLE "users" ADD COLUMN IF NOT EXISTS "disabled_by" text REFERENCES "users"("id") ON DELETE SET NULL;

-- Partial index: the enforcement paths ask "is THIS user disabled" by
-- primary key, so the only scan that benefits from an index is the admin
-- listing's "show me the locked accounts", and disabled accounts are the
-- rare case. Indexing just those rows keeps the index tiny.
CREATE INDEX IF NOT EXISTS "users_disabled_idx" ON "users" ("disabled") WHERE "disabled" = true;
