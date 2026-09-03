-- OAuth credentials at rest: hash access tokens, refresh tokens, authorization
-- codes and client secrets instead of storing them in the clear.
--
-- THE GAP THIS CLOSES. `api_keys` stopped holding a usable credential at
-- migration 0034, but the OAuth tables one door over did not move with it.
-- `oauth_access_tokens.access_token` and `.refresh_token`,
-- `oauth_authorization_codes.code` and `oauth_clients.client_secret` were all
-- plaintext, so any read of the database that 0034 made harmless for API keys
--, a backup, a replica, a `psql` session, a stray `SELECT *` in a log, or the
-- NOSUPERUSER runtime role which still holds SELECT, still yielded directly
-- usable machine-plane bearer and refresh tokens plus client secrets. These
-- are the mcp_token consumer bearers minted for 30 days (access) and 365 days
-- (refresh) as deployed, so the exposure was live, not latent. This migration
-- extends the exact posture 0034 gave `api_keys` to the OAuth tables.
--
-- TWO HASHING SHAPES, on purpose.
--
--   Tokens and codes (access_token, refresh_token, code) are 256-bit random
--   values, so an UNSALTED sha256 is correct: there is no dictionary to
--   precompute against a value that random, and lookup is already an
--   exact-value match, so hashing the presented value and matching digests
--   keeps every existing token and code working with no re-auth. The encoding
--   is byte-identical to lib/api-key-hash.ts's hashApiKey() (utf8 bytes in,
--   lowercase hex out) so the application's hash-on-lookup agrees with what the
--   backfill writes, and so a stored access-token hash equals the audit log's
--   credentialFingerprint of the same token, the same join 0034 preserved.
--
--   client_secret is a user-visible secret handed to a confidential client, so
--   it is SALTED (sha256 of secret||salt) to match the already-written
--   hashClientSecret/verifyClientSecret in routers/oauth/utils.ts. The salt is
--   stored in a new client_secret_salt column. The backfill derives a
--   per-row salt as md5(client_id || client_secret) so both SET expressions in
--   one UPDATE compute the identical value from the row's OLD tuple (Postgres
--   evaluates every SET right-hand side against the pre-update row), and it is
--   unique per row because client_id is unique, no CTE or per-row loop
--   needed. verifyClientSecret does not care how the salt was produced, only
--   that the stored salt is the one the stored hash was computed with, so a
--   backfilled row verifies against the operator's existing secret and no
--   client re-registers.
--
-- THE ACCESS-TOKEN PRIMARY KEY BECOMES THE HASH, in place. `access_token` is
-- the primary key of oauth_access_tokens and nothing references it by foreign
-- key (the child references are oauth_access_tokens.client_id -> oauth_clients,
-- never the token column), so rewriting the column value to its own sha256 is
-- safe: the key stays unique because distinct 256-bit tokens have distinct
-- digests, and the reaper (cleanupExpired) and the admin listing
-- (listActiveAccessTokens) both key off expiry and metadata columns, never off
-- the token value. `code` is likewise the primary key of
-- oauth_authorization_codes and is rewritten to its hash the same way.
--
-- LAST4 FOR THE ADMIN VIEW. access_token_last4 keeps the last four characters
-- of the token, the one part safe to display, the same tail the audit log
-- already records as access_token_last4, so the Access dashboard can show a
-- token's tail and an operator can correlate a listed token against an audit
-- row without either surface holding a usable credential. Codes and client
-- secrets get no last4: codes are single-use and never displayed, and the
-- client-secret admin view shows presence only (has_client_secret).
--
-- LIVE CREDENTIALS SURVIVE. Every backfill hashes what is already stored, so
-- the authentication lookups (rewritten to hash the presented value and match
-- digests) match exactly the rows the old exact-value `WHERE` matched. No
-- re-auth, no downtime, no coordination with token or key holders.
--
-- sha256() is a PostgreSQL core builtin (since 11), so pgcrypto is deliberately
-- NOT required, requiring an extension would make this migration fail on a
-- database whose role cannot CREATE EXTENSION, mid-startup. md5() is likewise a
-- core builtin. convert_to("col", 'UTF8') rather than `"col"::bytea` is the
-- load-bearing half of the encoding agreement, for the reason spelled out in
-- 0034: a text-to-bytea cast is an I/O conversion through byteain that treats a
-- backslash as an escape introducer, so it would either abort the migration or
-- silently produce a digest no application code path can reproduce; convert_to
-- returns the column's characters as UTF-8 bytes, which is what
-- createHash().update(string) hashes. Today the generators emit base64url only
-- (mcp_token_/mcp_refresh_/mcp_code_/mcp_secret_ + randomBytes(32).base64url),
-- so nothing in the wild hits the backslash case, but the correct call costs
-- nothing.
--
-- IDEMPOTENT AND SELF-HEALING, per fork convention (see 0014, 0034, 0035), so a
-- re-run after a partial apply is a no-op rather than a crash-loop:
--   * The access-token backfill is guarded on access_token_last4 IS NULL. That
--     column is added NULL for every row, and the single UPDATE that hashes the
--     token also sets last4 atomically, so a row is either fully converted
--     (last4 set, token hashed) or untouched, a re-run skips the converted
--     rows and the NOT NULL that follows is a no-op once it holds.
--   * The code and client_secret backfills are guarded on the plaintext prefix
--     ('mcp_%') and, for client_secret, on client_secret_salt IS NULL: a
--     sha256 hex digest never starts with 'mcp_', so a converted row is never
--     re-hashed.
-- Journal "when" (1787529600000) deliberately exceeds 0035's (1787443200000):
-- drizzle only applies entries whose "when" is above the max already applied,
-- see UMBRELLA_FORK.md's migration-ordering note.

-- ===== oauth_access_tokens: hash access_token + refresh_token, keep last4 =====
ALTER TABLE "oauth_access_tokens" ADD COLUMN IF NOT EXISTS "access_token_last4" text;
--> statement-breakpoint
-- One UPDATE rewrites the token to its hash, records its tail, and hashes the
-- refresh token when present. Every right-hand side reads the OLD row, so last4
-- is the tail of the plaintext (not of the hash it is being replaced by) and
-- the guard below sees the pre-update NULL. Guarded on last4 IS NULL so a
-- re-run after this statement committed is a no-op.
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = current_schema()
      AND table_name = 'oauth_access_tokens'
      AND column_name = 'access_token_last4'
  ) THEN
    EXECUTE $backfill$
      UPDATE "oauth_access_tokens"
      SET "access_token" = encode(sha256(convert_to("access_token", 'UTF8')), 'hex'),
          "access_token_last4" = right("access_token", 4),
          "refresh_token" = CASE
            WHEN "refresh_token" IS NOT NULL
              THEN encode(sha256(convert_to("refresh_token", 'UTF8')), 'hex')
            ELSE NULL
          END
      WHERE "access_token_last4" IS NULL
    $backfill$;
  END IF;
END $$;
--> statement-breakpoint
-- NOT NULL only after the backfill: a row without a last4 would be one the
-- backfill never reached, so allow it to fail loudly here rather than exist as
-- a half-converted row.
ALTER TABLE "oauth_access_tokens" ALTER COLUMN "access_token_last4" SET NOT NULL;
--> statement-breakpoint

-- ===== oauth_authorization_codes: hash the code (primary key) in place =====
-- Codes are single-use and expire in ten minutes, so no last4 and no display
-- concern; the lookup hashes the presented code and matches the digest. The
-- 'mcp_%' guard makes a re-run a no-op (a hashed code is 64 hex chars).
UPDATE "oauth_authorization_codes"
  SET "code" = encode(sha256(convert_to("code", 'UTF8')), 'hex')
  WHERE "code" LIKE 'mcp\_%';
--> statement-breakpoint

-- ===== oauth_clients: salted-hash client_secret, store the salt =====
ALTER TABLE "oauth_clients" ADD COLUMN IF NOT EXISTS "client_secret_salt" text;
--> statement-breakpoint
-- Salt = md5(client_id || client_secret): deterministic from the OLD row so
-- both SET right-hand sides compute the same value, unique per row via the
-- unique client_id. Guarded on the plaintext prefix and on the salt still
-- being NULL so a re-run never re-hashes an already-hashed secret. NULL secrets
-- (PKCE / public clients) are left untouched.
UPDATE "oauth_clients"
  SET "client_secret" = encode(
        sha256(convert_to("client_secret" || md5("client_id" || "client_secret"), 'UTF8')),
        'hex'
      ),
      "client_secret_salt" = md5("client_id" || "client_secret")
  WHERE "client_secret" IS NOT NULL
    AND "client_secret_salt" IS NULL
    AND "client_secret" LIKE 'mcp\_%';
