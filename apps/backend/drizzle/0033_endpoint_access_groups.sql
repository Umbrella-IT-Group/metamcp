-- Named access groups: which OAuth users may reach which endpoints.
--
-- THE GAP THIS CLOSES. Until now, any account that completed an OAuth flow
-- against this gateway could reach EVERY public endpoint on it. `checkOAuthAccess`
-- gates only on ownership — a private endpoint admits its owner, and a public
-- endpoint admits every authenticated user — so an estate that publishes one
-- connector per business system published all of them to everyone who could log
-- in once. API keys have had per-endpoint scoping since 0023; OAuth users had
-- nothing equivalent.
--
-- The model is deliberately the same shape as namespaces: a named group is a
-- reusable set, users join it, and endpoints are mapped to it. An endpoint that
-- opts in (`restricted = true`) admits an OAuth caller only when that caller is
-- an administrator or belongs to at least one group mapped to it.
--
-- SHIPS INERT, and that is a requirement rather than a convenience. Nothing is
-- seeded and nothing is flagged, so immediately after this migration
-- `restricted` is false on every row, no group exists, and the enforcement
-- predicate is never consulted. Behaviour is byte-identical to the previous
-- release for every existing caller — there is no window in which a live
-- connector is locked out while the groups are still being drawn up.
--
-- API KEYS ARE OUT OF SCOPE BY DESIGN, and the reason is that they are a
-- different trust class: a key is minted by an administrator, already carries
-- per-endpoint scoping (0023 `endpoint_uuid`, `require_scoped_api_key`), and is
-- held by a machine rather than by a person who logs in. Making an
-- admin-minted, endpoint-scoped key ALSO depend on the group membership of
-- whoever happens to own it would break every server-to-server integration on
-- the gateway to solve a problem those keys do not have. Mirrored in
-- `checkOAuthAccess`'s sibling comment and in the README.
--
-- Idempotent (IF NOT EXISTS / DO-block constraint guard) per fork convention —
-- see 0014_oauth_refresh_token for why a re-run must not crash-loop a deployer.
-- Journal "when" (1787270400000) deliberately exceeds 0032's (1787184000000):
-- drizzle only applies entries whose "when" is above the max already applied.
CREATE TABLE IF NOT EXISTS "access_groups" (
	"uuid" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"name" text NOT NULL,
	"description" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "access_groups_name_unique" UNIQUE("name")
);
--> statement-breakpoint
-- Membership. Composite primary key rather than a surrogate uuid plus a unique
-- index: the pair IS the identity of the row, there is nothing else to say
-- about it, and a PK that is exactly the uniqueness constraint makes a
-- double-add a no-op-able conflict target instead of a second row that silently
-- grants the same access twice.
--
-- Both sides CASCADE. Deleting a group must not leave orphan grants behind that
-- a later group reusing the uuid would inherit, and deleting a USER must revoke
-- their access rather than leaving a row pointing at an id that no longer
-- resolves — a dangling grant is the failure mode where "the account was
-- deleted" and "the account still has access" are both true.
CREATE TABLE IF NOT EXISTS "access_group_members" (
	"group_uuid" uuid NOT NULL,
	"user_id" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "access_group_members_pkey" PRIMARY KEY("group_uuid","user_id")
);
--> statement-breakpoint
-- Which endpoints a group opens. Same composite-PK and same CASCADE reasoning
-- as membership above: an endpoint that is deleted takes its grants with it, so
-- recreating an endpoint under the same name never resurrects an old mapping.
CREATE TABLE IF NOT EXISTS "access_group_endpoints" (
	"group_uuid" uuid NOT NULL,
	"endpoint_uuid" uuid NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "access_group_endpoints_pkey" PRIMARY KEY("group_uuid","endpoint_uuid")
);
--> statement-breakpoint
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'access_group_members_group_uuid_fk'
      AND conrelid = '"access_group_members"'::regclass
  ) THEN
    ALTER TABLE "access_group_members"
      ADD CONSTRAINT "access_group_members_group_uuid_fk"
      FOREIGN KEY ("group_uuid") REFERENCES "access_groups"("uuid") ON DELETE CASCADE;
  END IF;
END $$;
--> statement-breakpoint
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'access_group_members_user_id_fk'
      AND conrelid = '"access_group_members"'::regclass
  ) THEN
    ALTER TABLE "access_group_members"
      ADD CONSTRAINT "access_group_members_user_id_fk"
      FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE;
  END IF;
END $$;
--> statement-breakpoint
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'access_group_endpoints_group_uuid_fk'
      AND conrelid = '"access_group_endpoints"'::regclass
  ) THEN
    ALTER TABLE "access_group_endpoints"
      ADD CONSTRAINT "access_group_endpoints_group_uuid_fk"
      FOREIGN KEY ("group_uuid") REFERENCES "access_groups"("uuid") ON DELETE CASCADE;
  END IF;
END $$;
--> statement-breakpoint
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'access_group_endpoints_endpoint_uuid_fk'
      AND conrelid = '"access_group_endpoints"'::regclass
  ) THEN
    ALTER TABLE "access_group_endpoints"
      ADD CONSTRAINT "access_group_endpoints_endpoint_uuid_fk"
      FOREIGN KEY ("endpoint_uuid") REFERENCES "endpoints"("uuid") ON DELETE CASCADE;
  END IF;
END $$;
--> statement-breakpoint
-- The grant lookup on the authentication hot path is
--   WHERE m.user_id = $1 AND e.endpoint_uuid = $2
-- joined on group_uuid, so each side needs the index its own predicate uses.
-- The composite primary keys above already cover a group_uuid-leading scan
-- (listing one group's members / endpoints, which is the admin UI's query), but
-- neither can serve a lookup that starts from the user or from the endpoint —
-- the leading column is wrong. Without these two, every cache miss on a
-- restricted endpoint is a sequential scan of the whole grant table.
CREATE INDEX IF NOT EXISTS "access_group_members_user_id_idx" ON "access_group_members" ("user_id");
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "access_group_endpoints_endpoint_uuid_idx" ON "access_group_endpoints" ("endpoint_uuid");
--> statement-breakpoint
-- The per-endpoint opt-in.
--
-- NOT NULL DEFAULT false is what makes this migration inert: every existing row
-- takes the default in the same statement, so no endpoint changes behaviour
-- when this lands, and an insert path that forgets the column fails OPEN in the
-- only direction that is safe to fail — unchanged from today, rather than
-- locking out a live connector because a new field was missed.
--
-- Turning it on is therefore always a deliberate, attributable act (the
-- `endpoint.restricted.set` audit event), and turning it off is the one-switch
-- rollback if a group mapping is drawn up wrong.
ALTER TABLE "endpoints" ADD COLUMN IF NOT EXISTS "restricted" boolean DEFAULT false NOT NULL;
