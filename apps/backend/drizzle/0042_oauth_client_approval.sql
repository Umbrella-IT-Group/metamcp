-- oauth_clients approval state: self-registered clients wait for an
-- administrator before anyone can authorize them.
--
-- POST /oauth/register is anonymous (RFC 7591), so until now any caller could
-- create a client, give it any name, and have a signed-in person reach the
-- consent screen for it. From this migration on only a client whose
-- approval_status is exactly 'approved' can be authorized or exchange a code or
-- refresh token. Self-registration writes 'pending'; the admin create dialog
-- writes 'approved'; an administrator approves or rejects pending rows from the
-- OAuth Clients page.
--
--   approval_status  text NOT NULL DEFAULT 'pending', one of approved | pending
--                    | rejected. The DEFAULT is 'pending' on purpose: an insert
--                    path that forgets the column must produce a client nobody
--                    can use, not one that is quietly usable.
--   approved_by      text NULL. users.id of the administrator who approved a
--                    self-registered client, from the authenticated session.
--                    No foreign key: deleting that account must not erase who
--                    approved. NULL for every grandfathered and admin-created
--                    row; no approving person is invented for them.
--   approved_at      timestamptz NULL. When that approval happened.
--   rejected_at      timestamptz NULL. When an administrator rejected the
--                    client; the retention sweep removes a rejected
--                    self-registration one day after this.
--
-- GRANDFATHERING, applied exactly once (only rows whose new column is still
-- NULL, i.e. the rows that existed when the column was added). A row becomes
-- 'approved' when it was not self-registered (registration_source is 'admin',
-- or NULL for rows that predate migration 0029 and whose provenance was never
-- recorded), or when it has EVER been used: any authorization code, any access
-- or refresh token row, or any rotated-out refresh token marker for it. Every
-- other row, a self-registration nobody has completed an authorization with,
-- becomes 'pending' and waits for an administrator like a new registration.
-- oauth_clients has no last-used column, so those three child tables are the
-- complete record of use.
--
-- RE-RUN SAFETY. The UPDATE only touches rows whose approval_status IS NULL,
-- and the column is NOT NULL once this file finishes, so a second run changes
-- nothing: a client that is pending or rejected afterwards stays that way. No
-- client id, secret hash, salt, callback, code, token or registration_source
-- is touched.
--
-- Text plus a CHECK rather than a pgEnum, matching registration_source
-- (migration 0029) and api_keys.ip_policy_mode (migration 0041): a CHECK is
-- DO-guardable and stops a row written by hand from carrying a status the
-- gates do not know. A second CHECK keeps the decision fields consistent with
-- the status, and makes a rejected row always carry the time the sweep counts
-- from.
--
-- Additive only. An image that predates this migration ignores the columns,
-- so rolling the application back restores the old (unapproved) behaviour;
-- keep this migration and roll forward instead (see UMBRELLA_FORK.md).
--
-- Idempotent (ADD COLUMN IF NOT EXISTS / DO-guarded CHECKs) per fork
-- convention. Journal "when" deliberately exceeds 0041's (1787961600000):
-- drizzle only applies entries whose "when" is above the max already applied,
-- so an entry with a stale "when" is SILENTLY skipped -- see the
-- migration-ordering note in UMBRELLA_FORK.md. Mirrored in schema.ts so a
-- fresh `drizzle-kit generate` produces no diff.
ALTER TABLE "oauth_clients" ADD COLUMN IF NOT EXISTS "approval_status" text;
--> statement-breakpoint
UPDATE "oauth_clients" AS c
SET "approval_status" = CASE
  WHEN c."registration_source" IS DISTINCT FROM 'dcr' THEN 'approved'
  WHEN EXISTS (
    SELECT 1 FROM "oauth_authorization_codes" AS x
    WHERE x."client_id" = c."client_id"
  ) THEN 'approved'
  WHEN EXISTS (
    SELECT 1 FROM "oauth_access_tokens" AS x
    WHERE x."client_id" = c."client_id"
  ) THEN 'approved'
  WHEN EXISTS (
    SELECT 1 FROM "oauth_rotated_refresh_tokens" AS x
    WHERE x."client_id" = c."client_id"
  ) THEN 'approved'
  ELSE 'pending'
END
WHERE c."approval_status" IS NULL;
--> statement-breakpoint
ALTER TABLE "oauth_clients" ALTER COLUMN "approval_status" SET DEFAULT 'pending';
--> statement-breakpoint
ALTER TABLE "oauth_clients" ALTER COLUMN "approval_status" SET NOT NULL;
--> statement-breakpoint
ALTER TABLE "oauth_clients" ADD COLUMN IF NOT EXISTS "approved_by" text;
--> statement-breakpoint
ALTER TABLE "oauth_clients" ADD COLUMN IF NOT EXISTS "approved_at" timestamp with time zone;
--> statement-breakpoint
ALTER TABLE "oauth_clients" ADD COLUMN IF NOT EXISTS "rejected_at" timestamp with time zone;
--> statement-breakpoint
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'oauth_clients_approval_status_valid'
      AND conrelid = '"oauth_clients"'::regclass
  ) THEN
    ALTER TABLE "oauth_clients" ADD CONSTRAINT "oauth_clients_approval_status_valid"
      CHECK ("approval_status" IN ('approved', 'pending', 'rejected'));
  END IF;
END $$;
--> statement-breakpoint
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'oauth_clients_approval_fields_consistent'
      AND conrelid = '"oauth_clients"'::regclass
  ) THEN
    ALTER TABLE "oauth_clients" ADD CONSTRAINT "oauth_clients_approval_fields_consistent"
      CHECK (
        ("approved_by" IS NULL OR "approval_status" = 'approved')
        AND ("approved_at" IS NULL OR "approval_status" = 'approved')
        AND (("rejected_at" IS NOT NULL) = ("approval_status" = 'rejected'))
      );
  END IF;
END $$;
