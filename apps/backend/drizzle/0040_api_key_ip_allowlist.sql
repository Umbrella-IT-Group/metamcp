-- API-key IP allowlists. Three columns on api_keys:
--
--   allowed_cidrs   text[] NULL. NULL means "this key has no list of its own":
--                   the GLOBAL policy (config rows API_KEY_IP_ALLOWED_CIDRS +
--                   API_KEY_IP_POLICY_MODE) applies to it. A non-NULL array,
--                   even an empty one, is the key's own list, and the key's own
--                   ip_policy_mode then applies instead of the global mode.
--                   The any-IP exemption (for callers with rotating source
--                   addresses, such as CI runners) is a list holding BOTH
--                   0.0.0.0/0 and ::/0.
--   ip_policy_mode  text NOT NULL DEFAULT 'off', one of off | audit | enforce.
--                   off: no evaluation. audit: the request is served and a
--                   would-deny audit row is written. enforce: the request is
--                   refused with 403. Read only when allowed_cidrs is non-NULL.
--   last_used_ip    text NULL. The CF-Connecting-IP of the last request this
--                   key authenticated, written in the same throttled
--                   fire-and-forget update as last_used_at (migration 0021),
--                   so an operator can build a key's allowlist from what the
--                   key really uses.
--
-- INERT ON DEPLOY, which is the property everything else depends on: every
-- existing row backfills to allowed_cidrs NULL (follow the global policy) and
-- the global mode is unset, which reads as off, so no key changes behaviour
-- until an administrator sets a policy. last_used_ip starts NULL and fills in
-- as keys are used.
--
-- Text plus a CHECK rather than a pgEnum, matching users.role (migration 0020)
-- and the plane CHECKs in migration 0038: a CHECK is DO-guardable and makes a
-- row written outside the app (psql, admin tooling) unable to carry a mode the
-- evaluator does not know. CIDR syntax is NOT checked in SQL: Postgres has a
-- cidr type, but the evaluator uses node:net BlockList, and two parsers that
-- disagree about an edge case would let the database accept a list the gateway
-- reads differently. The admin write path validates every entry; the evaluator
-- ignores (and logs) an entry it cannot parse, which only ever narrows a list.
--
-- No index on any of the three: they are read from the row the key_hash lookup
-- already fetches (the unique constraint from migration 0034 is the btree that
-- lookup uses), the same reasoning migration 0038 gives for admin_plane.
--
-- Idempotent (ADD COLUMN IF NOT EXISTS / DO-guarded CHECK) per fork
-- convention. Journal "when" deliberately exceeds 0039's (1787788800000):
-- drizzle only applies entries whose "when" is above the max already applied,
-- so an entry with a stale "when" is SILENTLY skipped -- see the
-- migration-ordering note in UMBRELLA_FORK.md. Mirrored in schema.ts so a
-- fresh `drizzle-kit generate` produces no diff.
ALTER TABLE "api_keys" ADD COLUMN IF NOT EXISTS "allowed_cidrs" text[];
--> statement-breakpoint
ALTER TABLE "api_keys" ADD COLUMN IF NOT EXISTS "ip_policy_mode" text NOT NULL DEFAULT 'off';
--> statement-breakpoint
ALTER TABLE "api_keys" ADD COLUMN IF NOT EXISTS "last_used_ip" text;
--> statement-breakpoint
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'api_keys_ip_policy_mode_valid'
      AND conrelid = '"api_keys"'::regclass
  ) THEN
    ALTER TABLE "api_keys" ADD CONSTRAINT "api_keys_ip_policy_mode_valid"
      CHECK ("ip_policy_mode" IN ('off', 'audit', 'enforce'));
  END IF;
END $$;
