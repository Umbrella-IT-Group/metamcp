-- API keys at rest: SHA-256 + last4 instead of the key itself.
--
-- THE GAP THIS CLOSES. `api_keys.key` held every gateway credential in
-- plaintext. Anything that could read one row of that table — a database
-- backup, a `psql` session, a replica, an accidental `SELECT *` in a log or
-- a support export, or any future read path added by someone who did not
-- know the column was secret — obtained working credentials for every
-- integration on the gateway, with no further step. Redaction at the API
-- boundary (the serializer emits a prefix, the tRPC `.output()` schemas
-- strip `key`) already stopped keys leaving through the application, but
-- redaction only guards the paths that go through the application. Storage
-- was still the raw secret, so the blast radius of read access to the
-- database was "all credentials", not "the row you were looking at".
--
-- After this migration the table holds a one-way hash and four display
-- characters. A key is now a bearer secret in the strict sense: it exists in
-- readable form exactly once, in the mint-time response, and if it is not
-- copied then it is gone and must be re-minted. That is the same posture the
-- product already documents to users ("the API key is only shown once") —
-- storage simply now matches the promise.
--
-- WHAT THIS COSTS, stated plainly so nobody rediscovers it as a bug: no
-- surface can ever recover an existing key again. The endpoint-creation
-- convenience that used to embed an EXISTING key as the auto-generated MCP
-- server's bearer token is removed in the same change for exactly this
-- reason (it now always mints a fresh endpoint-scoped key), and the
-- recreate-user preservation path now carries the hash/last4 PAIR so
-- preserved keys keep authenticating across a `BOOTSTRAP_RECREATE_USER`.
--
-- LIVE KEYS SURVIVE. The backfill hashes what is already stored, so every
-- key currently in use keeps working — the authentication lookup is rewritten
-- to hash the presented value and compare hashes, which matches the same rows
-- the old `WHERE key = $1` matched. No re-mint, no downtime, no coordination
-- with key holders. This is why the backfill runs BEFORE the NOT NULL and the
-- DROP: a hash computed from the plaintext in the same statement cannot
-- disagree with it.
--
-- sha256() is a PostgreSQL core builtin (since 11) — pgcrypto is deliberately
-- NOT required, because requiring an extension would make this migration fail
-- on a database whose role cannot CREATE EXTENSION, in the middle of a
-- startup sequence that has already deleted nothing and can only halt. The
-- encoding (utf8 bytes in, lowercase hex out, unsalted) is byte-identical to
-- the application's hashApiKey() in lib/api-key-hash.ts and to the audit
-- log's credentialFingerprint(), and `encode(..., 'hex')` is lowercase. All
-- three must agree or a key hashed by one is invisible to the others.
--
-- convert_to("key", 'UTF8') rather than `"key"::bytea` is the load-bearing
-- half of that agreement. A `text`-to-`bytea` CAST is not a byte
-- reinterpretation: it is an I/O conversion through byteain, which reads the
-- text as bytea INPUT SYNTAX — so a backslash in a stored key is an escape
-- introducer, not a byte, and the cast then fails one of two ways depending
-- on what follows it. Measured on 16.14: a key holding `sk_mt_a\b` has no
-- valid escape after the backslash, so `"key"::bytea` raises `invalid input
-- syntax for type bytea` and ABORTS this migration — a startup halted
-- mid-schema-change, with no digest produced at all. A key holding
-- `sk_mt_a\\b` does have a valid escape, which is the quieter failure:
-- byteain collapses the pair to a single byte, so the cast digests 9 bytes
-- to 97a132e4… while convert_to digests the 10 stored characters to
-- f0d3dd0e…. The cast's digest is one no application code path can ever
-- reproduce for that key, so it would silently 401 forever. convert_to() has
-- neither failure mode: it returns the column's characters encoded as UTF-8
-- bytes, which is what Node's createHash().update(string) hashes — Node
-- digests `sk_mt_a\\b` to f0d3dd0e… too, so the hash written by the backfill
-- and the hash computed at login agree. Today both key generators emit
-- [0-9A-Za-z] only (api-keys.repo.ts, bootstrap.service.ts) so nothing in the
-- wild hits it, but an operator-supplied BOOTSTRAP_API_KEYS key is not so
-- constrained.
--
-- Idempotent (ADD COLUMN IF NOT EXISTS / DO-block guards, and the backfill is
-- restricted to rows still missing a hash) per fork convention — see
-- 0014_oauth_refresh_token for why a re-run must not crash-loop a deployer.
-- Journal "when" (1787356800000) deliberately exceeds 0033's
-- (1787270400000): drizzle only applies entries whose "when" is above the max
-- already applied — see UMBRELLA_FORK.md's migration-ordering note.
ALTER TABLE "api_keys" ADD COLUMN IF NOT EXISTS "key_hash" text;
--> statement-breakpoint
ALTER TABLE "api_keys" ADD COLUMN IF NOT EXISTS "last4" text;
--> statement-breakpoint
-- Backfill from the plaintext while it is still there. Guarded on the column
-- still existing so a re-run after the DROP below is a no-op rather than an
-- error: a partially-applied migration must be resumable, not fatal. The
-- guard is schema-qualified to current_schema(): information_schema.columns
-- spans every schema this role can see, so an unrelated same-named table
-- elsewhere would make the guard true after the search-path table has
-- already dropped "key" — turning the resumability guard into exactly the
-- error it exists to prevent.
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = current_schema()
      AND table_name = 'api_keys'
      AND column_name = 'key'
  ) THEN
    EXECUTE $backfill$
      UPDATE "api_keys"
      SET "key_hash" = encode(sha256(convert_to("key", 'UTF8')), 'hex'),
          "last4" = right("key", 4)
      WHERE "key_hash" IS NULL OR "last4" IS NULL
    $backfill$;
  END IF;
END $$;
--> statement-breakpoint
-- NOT NULL only after the backfill: a row without a hash can never
-- authenticate, so allowing one would be a silently dead credential rather
-- than a loud failure at write time.
ALTER TABLE "api_keys" ALTER COLUMN "key_hash" SET NOT NULL;
--> statement-breakpoint
ALTER TABLE "api_keys" ALTER COLUMN "last4" SET NOT NULL;
--> statement-breakpoint
-- Uniqueness moves to the hash, preserving what `api_keys_key_unique` gave
-- us: two rows cannot share a credential, so a lookup can never be ambiguous
-- about which key (and therefore which scope and which acts-as identity)
-- authenticated a request. The unique constraint also builds the btree the
-- authentication lookup needs, which is why no separate index replaces the
-- old `api_keys_key_idx` — that index was already redundant with
-- `api_keys_key_unique` and its replacement would be redundant with this.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'api_keys_key_hash_unique'
      AND conrelid = '"api_keys"'::regclass
  ) THEN
    ALTER TABLE "api_keys" ADD CONSTRAINT "api_keys_key_hash_unique" UNIQUE("key_hash");
  END IF;
END $$;
--> statement-breakpoint
-- The point of the whole migration. Dropping the column takes
-- `api_keys_key_unique` and `api_keys_key_idx` with it; both are replaced by
-- `api_keys_key_hash_unique` above. IF EXISTS so a re-run is a no-op.
ALTER TABLE "api_keys" DROP COLUMN IF EXISTS "key";
