-- OAuth access tokens: a refresh token and its expiry must be present together.
--
-- THE SHAPE THIS FORBIDS. A row in `oauth_access_tokens` with a
-- `refresh_token` but a NULL `refresh_token_expires_at` is both never-expiring
-- and never-reaped. The refresh grant treats a NULL expiry as "not expired"
-- (it only compares when a value is present), so such a token would be honored
-- forever; and `cleanupExpired` sweeps only rows whose refresh expiry is in the
-- past OR whose refresh token is NULL, so a row with a refresh token and no
-- expiry matches no reaper predicate and is never removed. Combined, that is an
-- immortal credential that no maintenance path ever collects.
--
-- WHY A CHECK RATHER THAN APP CODE ALONE. The one production write path
-- (issueTokenPair -> setAccessToken) now takes the refresh token and its expiry
-- as a single pair, so it cannot express the bad shape. A CHECK closes the gap
-- that app-layer pairing cannot reach: `oauth_access_tokens` is writable from
-- psql and any future insert path, and this table holds bearer credentials, so
-- the invariant has to hold of the DATA and not only of the code that usually
-- writes it. The refresh grant also treats a NULL expiry as expired now, as
-- defense in depth for any legacy row written before this constraint.
--
-- BOTH-OR-NEITHER, written as an equality of two NULL tests:
-- `(refresh_token IS NULL) = (refresh_token_expires_at IS NULL)`. This admits
-- the two legitimate shapes — both set (a token that can be refreshed) and both
-- NULL (a token with no refresh capability) — and rejects the two mixed shapes.
-- The mirror shape (an expiry with no refresh token) is meaningless too, so the
-- symmetric form is the honest constraint rather than a one-sided guard.
--
-- PRE-DEPLOY: this migration will FAIL if any existing row already violates the
-- constraint. The last census (2026-08-19) found zero such rows and the sole
-- production insert path always set both, so it is expected to add cleanly.
-- Confirm the violating-row count is 0 before applying (the query is in the PR
-- description). Written idempotently (DO-block guard on pg_constraint) per fork
-- convention so a re-run after a partial apply is a no-op rather than an error.
-- Journal "when" (1787443200000) deliberately exceeds 0034's (1787356800000):
-- drizzle only applies entries whose "when" is above the max already applied —
-- see UMBRELLA_FORK.md's migration-ordering note.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'oauth_access_tokens_refresh_pairing'
      AND conrelid = '"oauth_access_tokens"'::regclass
  ) THEN
    ALTER TABLE "oauth_access_tokens"
      ADD CONSTRAINT "oauth_access_tokens_refresh_pairing"
      CHECK (("refresh_token" IS NULL) = ("refresh_token_expires_at" IS NULL));
  END IF;
END $$;
