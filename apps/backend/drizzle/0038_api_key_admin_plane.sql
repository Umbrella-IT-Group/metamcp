-- Admin-plane (control-plane) API keys. api_keys.admin_plane splits the key
-- population into two NON-OVERLAPPING planes. admin_plane = false (the default,
-- and the state of every existing key) is the DATA plane: the key authenticates
-- on /metamcp and /mcp-proxy exactly as before, and is refused if presented as a
-- tRPC bearer. admin_plane = true is the CONTROL plane: the key authenticates
-- AS its owning user on /trpc via Authorization: Bearer, and is refused on the
-- data plane. The mutual exclusion is the containment story: a leaked
-- control-plane key cannot pull MCP tool data or exercise the m365 delegated
-- injection, and a data-plane key gains no control-plane reach.
--
-- Default false backfills every existing row into the data plane, so NO live key
-- changes behaviour on deploy: the bearer path resolves nothing until a key is
-- deliberately minted admin_plane, and the data-plane refusal never fires. NOT
-- NULL for the same reason acts-as (migration 0024) chose its shape: a null
-- plane flag would be a silently ambiguous key.
--
-- Idempotent (ADD COLUMN IF NOT EXISTS / DO-guarded CHECKs) per fork
-- convention. Journal "when" deliberately exceeds 0037's (1787616000000):
-- drizzle only applies entries whose "when" is above the max already applied,
-- so a mechanical rename with a stale "when" is SILENTLY skipped -- see the
-- migration-ordering note in UMBRELLA_FORK.md. Mirrored in schema.ts via
-- drizzle's boolean().notNull().default(false) + three check() clauses so a
-- fresh `drizzle-kit generate` produces no diff.
--
-- No index on admin_plane: the authentication lookup keys on key_hash (the
-- unique constraint from migration 0034 builds that btree) and admin_plane is
-- read from the same row the lookup already fetches, so an index would be dead
-- weight -- matching the "No index on key_hash" note in schema.ts.
ALTER TABLE "api_keys" ADD COLUMN IF NOT EXISTS "admin_plane" boolean NOT NULL DEFAULT false;

-- Three DO-block-guarded CHECK constraints (postgres has no
-- ADD CONSTRAINT IF NOT EXISTS). Each makes an unsafe row impossible to write
-- at all, so plane separation is STRUCTURAL, not policy -- a row written outside
-- the app (psql / admin_cli, a routine ops path in this fork) cannot straddle
-- the planes.

-- A control-plane key authenticates AS a user. A public ('everyone') key
-- (user_id NULL) has no user to become and no role to resolve, so it can never
-- be admin-plane.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'api_keys_admin_plane_requires_owner'
      AND conrelid = '"api_keys"'::regclass
  ) THEN
    ALTER TABLE "api_keys" ADD CONSTRAINT "api_keys_admin_plane_requires_owner"
      CHECK ("admin_plane" = false OR "user_id" IS NOT NULL);
  END IF;
END $$;

-- Endpoint scope is a DATA-plane concept (checkApiKeyAccess). A control-plane
-- key is not bound to an endpoint, so it stores endpoint_uuid NULL -- which is
-- exactly why the data plane MUST refuse admin-plane keys explicitly: a NULL
-- scope reads as "legacy gateway-wide" on the data plane, so the runtime
-- refusal is what stops an admin-plane key acting as a gateway-wide data-plane
-- key.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'api_keys_admin_plane_no_endpoint_scope'
      AND conrelid = '"api_keys"'::regclass
  ) THEN
    ALTER TABLE "api_keys" ADD CONSTRAINT "api_keys_admin_plane_no_endpoint_scope"
      CHECK ("admin_plane" = false OR "endpoint_uuid" IS NULL);
  END IF;
END $$;

-- Acts-as is the data-plane m365 delegated-identity injection (migration 0024).
-- A control-plane key carries none. Implied by the no-endpoint-scope check above
-- plus the existing api_keys_acts_as_requires_scope, but stated explicitly so
-- the invariant survives even if the acts-as check is ever changed.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'api_keys_admin_plane_no_acts_as'
      AND conrelid = '"api_keys"'::regclass
  ) THEN
    ALTER TABLE "api_keys" ADD CONSTRAINT "api_keys_admin_plane_no_acts_as"
      CHECK ("admin_plane" = false OR "acts_as_user_id" IS NULL);
  END IF;
END $$;
