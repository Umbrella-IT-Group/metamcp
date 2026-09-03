-- OAuth refresh-token families: detect reuse of a rotated-out refresh token
-- and revoke the whole lineage, instead of silently rejecting the stolen copy.
--
-- THE GAP THIS CLOSES. Refresh tokens rotate on every use (the refresh grant
-- issues a new pair and deletes the old row), so a stolen refresh token that
-- an attacker rotates leaves the legitimate client holding a copy that no
-- longer resolves. Until now a presented refresh token that is NOT found was
-- simply rejected with invalid_grant: no signal, and the family the attacker
-- rotated INTO keeps working. That is the classic OAuth 2.1 replay: the theft
-- is invisible and the live chain survives. Family lineage turns that silent
-- miss into a detected event that revokes every live token in the chain.
--
-- TWO PIECES.
--
--   family_id on oauth_access_tokens ties a refresh chain together. The
--   initial authorization_code grant starts a new family; every refresh
--   rotation inherits the same id (see routers/oauth/token.ts issueTokenPair).
--   Revoking a family is one DELETE keyed on this column. A uuid, generated in
--   the app with randomUUID and unguessable, so it is never a value a caller
--   can present or predict.
--
--   oauth_rotated_refresh_tokens records each refresh token that has been
--   rotated OUT, keyed on the SAME sha256 hash the live table stores (migration
--   0036 hashed refresh tokens at rest, so the lineage keys on the stored
--   digest, never the plaintext). When a presented refresh token is not a live
--   token but IS found here, that is a reuse: the refresh grant revokes the
--   whole family and returns invalid_grant. client_id and user_id travel on
--   the record so the reuse audit event can attribute the compromise even after
--   the family's live rows are gone; both cascade-delete with their parent, the
--   same posture oauth_access_tokens already takes, so removing a client or a
--   user does not leave orphan markers behind.
--
-- WHY A SEPARATE TABLE RATHER THAN A STATUS COLUMN. Keeping the rotated row in
-- oauth_access_tokens with a "rotated" status would leave its access token and
-- its refresh token in the live table, where getAccessToken and
-- getByRefreshToken would still resolve them unless every lookup grew a status
-- filter, and listActiveAccessTokens (which keys off expiry, not status) would
-- surface a rotated row as a live session. The rotation path already DELETES
-- the old row precisely to kill the old access token immediately; a status
-- column would undo that. A narrow side table holds only what reuse detection
-- needs (the hash, the family, the owner, an expiry) and touches none of the
-- live-token read paths.
--
-- REAPER. A rotated marker expires WITH the family: expires_at is the rotated
-- refresh token's own expiry, so cleanupExpired collects it exactly when that
-- credential would have lapsed anyway, and a family that is never reused
-- dissolves on its own. A family that IS reused is collapsed at detection time
-- (the refresh grant deletes the family's live rows AND its markers), so a
-- replay after revocation takes the plain unknown-token path and writes no
-- further audit rows: one reuse row per family compromise, not one per replay.
--
-- gen_random_uuid() is a PostgreSQL core builtin (since 13), the same call the
-- schema already uses for uuid defaults, so no extension is required and the
-- migration cannot fail mid-startup on a role that cannot CREATE EXTENSION.
--
-- IDEMPOTENT AND SELF-HEALING, per fork convention (see 0014, 0034, 0035,
-- 0036), so a re-run after a partial apply is a no-op rather than a crash-loop:
--   * family_id is added nullable with a gen_random_uuid() default (so the
--     previously deployed image, which inserts without the column, still
--     works if rolled back), backfilled under a `family_id IS NULL` guard (one
--     fresh family per existing row, since past lineage cannot be
--     reconstructed), then set NOT NULL. A re-run adds nothing, backfills no
--     rows, and SET NOT NULL on an already-NOT NULL column is a no-op.
--   * every CREATE uses IF NOT EXISTS.
-- Journal "when" (1787616000000) deliberately exceeds 0036's (1787529600000):
-- drizzle only applies entries whose "when" is above the max already applied,
-- see UMBRELLA_FORK.md's migration-ordering note.

-- ===== oauth_access_tokens: family_id ties a refresh chain together =====
-- DEFAULT gen_random_uuid() is rollback insurance, not app behaviour: the
-- application always supplies family_id explicitly (see issueTokenPair), so the
-- default only fires for an INSERT that omits the column, which is exactly what
-- the image deployed BEFORE this migration does. Without it, rolling that image
-- back after 0037 has run would fail every token issue on the NOT NULL below;
-- with it, each such insert becomes a family of one, the same shape the
-- backfill gives pre-existing rows.
ALTER TABLE "oauth_access_tokens" ADD COLUMN IF NOT EXISTS "family_id" uuid DEFAULT gen_random_uuid();
--> statement-breakpoint
-- Backfill one fresh family per existing row. Past lineage is unknowable, so
-- each live row becomes its own family of one; a subsequent refresh of any of
-- them inherits the id and grows the family from there. Guarded on IS NULL so a
-- re-run after this committed backfills nothing.
UPDATE "oauth_access_tokens"
  SET "family_id" = gen_random_uuid()
  WHERE "family_id" IS NULL;
--> statement-breakpoint
-- NOT NULL only after the backfill: a null here would be a row the backfill
-- never reached, so fail loudly rather than leave a familyless token.
ALTER TABLE "oauth_access_tokens" ALTER COLUMN "family_id" SET NOT NULL;
--> statement-breakpoint
-- Revocation is a DELETE keyed on family_id, so it needs the index.
CREATE INDEX IF NOT EXISTS "oauth_access_tokens_family_id_idx"
  ON "oauth_access_tokens" ("family_id");
--> statement-breakpoint

-- ===== oauth_rotated_refresh_tokens: the reuse-detection surface =====
-- refresh_token_hash is the sha256 the live table stores (migration 0036), so
-- detection hashes the presented token and matches the digest, never the
-- plaintext. client_id and user_id cascade with their parent so a deleted
-- client or user leaves no orphan markers. expires_at is the rotated token's
-- own expiry, so cleanupExpired reaps the marker with the family.
CREATE TABLE IF NOT EXISTS "oauth_rotated_refresh_tokens" (
  "refresh_token_hash" text PRIMARY KEY NOT NULL,
  "family_id" uuid NOT NULL,
  "client_id" text NOT NULL REFERENCES "oauth_clients" ("client_id") ON DELETE CASCADE,
  "user_id" text NOT NULL REFERENCES "users" ("id") ON DELETE CASCADE,
  "expires_at" timestamp with time zone NOT NULL
);
--> statement-breakpoint
-- Revocation deletes every marker for a family; reuse detection never needs the
-- reverse direction, so family_id is the only lookup index besides the PK.
CREATE INDEX IF NOT EXISTS "oauth_rotated_refresh_tokens_family_id_idx"
  ON "oauth_rotated_refresh_tokens" ("family_id");
--> statement-breakpoint
-- The reaper sweeps on expiry.
CREATE INDEX IF NOT EXISTS "oauth_rotated_refresh_tokens_expires_at_idx"
  ON "oauth_rotated_refresh_tokens" ("expires_at");
