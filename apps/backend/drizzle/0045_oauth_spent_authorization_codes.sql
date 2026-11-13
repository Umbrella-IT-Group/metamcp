-- Spent authorization codes: remember which token family a redeemed code
-- produced, so a second redemption of that code can be recognised and acted on
-- instead of vanishing into a bare invalid_grant.
--
-- THE GAP THIS CLOSES. RFC 6749 section 4.1.2: "If an authorization code is
-- used more than once, the authorization server MUST deny the request and
-- SHOULD revoke (when possible) all tokens previously issued based on that
-- authorization code." The token endpoint already denies: consuming a code is
-- a DELETE ... RETURNING on its hash, so the second redemption finds no row
-- and gets invalid_grant. But that delete also destroys the only record that
-- the code ever existed, so nothing can say which tokens it produced, and
-- nothing is logged. A code that was redeemed by an interceptor first, and then
-- by the legitimate client, leaves the interceptor's session alive and
-- unrecorded. Refresh-token families (migration 0037) closed the same hole for
-- refresh tokens; this closes it for the code that starts the family.
--
-- WHAT IS STORED. One row per redeemed code, written in the SAME transaction
-- as the token pair it produced (so the row exists exactly when the pair does):
--
--   code_hash       the sha256 the live codes table keys on (migration 0036),
--                   never the code. Primary key: the single-use gate for a
--                   REPLAY is a DELETE ... RETURNING on this key, so exactly
--                   one replay acts and later ones find nothing.
--   family_id       the refresh-token family the redemption started
--                   (migration 0037). Revoking it is one delete on the
--                   existing family index.
--   client_id,      what the code was bound to. A replay is acted on only when
--   redirect_uri,   it presents the SAME client, redirect and a code_verifier
--   code_challenge  whose S256 digest equals the stored challenge (RFC 6749
--                   section 4.1.3 bindings, RFC 7636 section 4.6). A caller
--                   holding only a leaked code (codes travel in redirect
--                   URLs) therefore cannot use this table to revoke anyone's
--                   session. The challenge is a public value (it was in the
--                   authorize URL), not a secret.
--   user_id         owner, for the per-user credential lock the revoke runs
--                   under.
--   expires_at      the redeemed code's own expiry plus a fixed margin (see
--                   routers/oauth/token.ts), after which a replay is no longer
--                   acted on and the row is reaped.
--
-- WHY A SIDE TABLE rather than a "consumed" state on oauth_authorization_codes.
-- Keeping the redeemed row in the live table would leave every reader of that
-- table (and the DELETE ... RETURNING single-use gate itself) needing to learn
-- a status filter, and a missed filter would make a spent code redeemable
-- again. The redemption keeps deleting the live row exactly as before; this
-- table holds only what replay handling needs. Same reasoning as 0037's
-- rotated-token table.
--
-- RETENTION. A row lives for about fifteen minutes (a code lives at most ten,
-- plus the margin), so the table holds a handful of rows. cleanupExpired reaps
-- expired rows; both foreign keys cascade, so deleting a client or a user
-- leaves no orphan. No user_id index: at this size a cascade scan is cheap.
--
-- ADDITIVE AND SWITCHABLE. Nothing existing is altered. OAUTH_CODE_REPLAY=off
-- makes the application read and write nothing here, so the feature can be
-- disabled without touching the table; an image that predates this migration
-- ignores the table and does not reap it (a few rows accumulate, one per
-- login, until `DELETE FROM oauth_spent_authorization_codes WHERE expires_at
-- < now()`), so rolling the application back needs no schema change.
--
-- No GRANT: new tables inherit the runtime role's default privileges, as
-- 0037's did.
--
-- Idempotent (IF NOT EXISTS on every CREATE) per fork convention, so a re-run
-- after a partial apply is a no-op. Journal "when" (1788307200000) deliberately
-- exceeds 0043's (1788134400000): drizzle only applies entries whose "when" is
-- above the max already applied, so an entry with a stale "when" is SILENTLY
-- skipped (see UMBRELLA_FORK.md's migration-ordering note). Number order,
-- "when" order and merge order must agree; apps/backend/src/db/
-- migrations-journal.test.ts guards the journal itself.
CREATE TABLE IF NOT EXISTS "oauth_spent_authorization_codes" (
  "code_hash" text PRIMARY KEY NOT NULL,
  "family_id" uuid NOT NULL,
  "client_id" text NOT NULL REFERENCES "oauth_clients" ("client_id") ON DELETE CASCADE,
  "user_id" text NOT NULL REFERENCES "users" ("id") ON DELETE CASCADE,
  "redirect_uri" text NOT NULL,
  "code_challenge" text NOT NULL,
  "expires_at" timestamp with time zone NOT NULL,
  "created_at" timestamp with time zone NOT NULL DEFAULT now()
);
--> statement-breakpoint
-- The reaper sweeps on expiry.
CREATE INDEX IF NOT EXISTS "oauth_spent_authorization_codes_expires_at_idx"
  ON "oauth_spent_authorization_codes" ("expires_at");
