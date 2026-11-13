-- oauth_clients.registration_source: admit 'cimd', a client whose identity is
-- a client metadata document.
--
-- A client metadata document (CIMD) client uses an https URL as its
-- client_id, and the document published at that URL is the registration. The
-- gateway fetches it only for a URL an operator listed in
-- OAUTH_CIMD_ALLOWED_CLIENTS (refused before any network call otherwise) and
-- stores what it read in an oauth_clients row so the authorize, consent and
-- token endpoints keep working from the table, as they do for every other
-- client. This migration only widens the set of values the provenance column
-- accepts; it adds no column, no table and no index.
--
-- Why a 'cimd' row is its own provenance and not 'dcr' or 'admin':
--   - It is a CACHE of a published document, rewritten from that document on
--     refresh. The DCR retention sweep matches registration_source = 'dcr'
--     exactly, so a cimd row is never swept by it, and the approval decision
--     (migration 0042) never applies: the allowlist entry IS the approval. The
--     row is written 'approved' with no approving person recorded, which the
--     approval-fields CHECK from 0042 already allows.
--   - A row left behind after its allowlist entry is removed is refused at
--     the authorize, consent, decision and token endpoints (the gate keys on
--     this value), so clearing the allowlist stops new authorizations and
--     refreshes without deleting anything. Access tokens already issued live
--     until they expire; an operator who wants a hard stop deletes the cimd
--     clients, which cascades their tokens and codes.
--   - Rows of this source are swept by their own rule (unused for 30 days,
--     with no token, code or rotated marker), never by the DCR sweep.
--
-- Rollback. The migration is additive and harmless to leave applied. An image
-- from before it does not know the value: its OAuth Clients list schema
-- rejects a 'cimd' row, which breaks the OAuth Clients and Access pages while
-- any such row exists, and it has no allowlist gate. Before rolling the image
-- back below the one that introduced this, clear OAUTH_CIMD_ALLOWED_CLIENTS and
-- delete the cimd rows (DELETE FROM oauth_clients WHERE registration_source =
-- 'cimd'), which also revokes the tokens issued to them. Prefer a forward fix.
--
-- Idempotent, per fork convention: the DO block replaces the constraint only
-- when its stored definition does not yet name 'cimd', so a re-run changes
-- nothing. Postgres has no ALTER CONSTRAINT for a CHECK expression, hence the
-- drop and re-add, which run in the one implicit transaction of the block.
--
-- Journal "when" deliberately exceeds the migrations before it in this
-- sequence: drizzle only applies entries whose "when" is above the maximum
-- already applied, so an entry with a stale "when" is SILENTLY skipped (see
-- the migration-ordering note in UMBRELLA_FORK.md). Number order, "when"
-- order and merge order must agree.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'oauth_clients_registration_source_valid'
      AND conrelid = '"oauth_clients"'::regclass
      AND pg_get_constraintdef(oid) LIKE '%''cimd''%'
  ) THEN
    ALTER TABLE "oauth_clients"
      DROP CONSTRAINT IF EXISTS "oauth_clients_registration_source_valid";
    ALTER TABLE "oauth_clients"
      ADD CONSTRAINT "oauth_clients_registration_source_valid"
      CHECK ("registration_source" IS NULL
             OR "registration_source" IN ('dcr', 'admin', 'cimd'));
  END IF;
END $$;
