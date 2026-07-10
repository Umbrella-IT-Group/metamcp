-- M365 delegated-token broker: per-user Entra refresh-token custody.
-- Refresh tokens are stored as AES-256-GCM envelopes only (KEK lives in
-- the SOPS-vaulted env file, never in this database). Idempotent
-- (IF NOT EXISTS) per fork convention so a re-run against an
-- already-migrated database is a no-op instead of a crash-loop.
CREATE TABLE IF NOT EXISTS "m365_user_tokens" (
	"uuid" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"user_id" text NOT NULL,
	"entra_oid" text NOT NULL,
	"tenant_id" text NOT NULL,
	"entra_upn" text,
	"rt_ciphertext" text NOT NULL,
	"kek_id" text NOT NULL,
	"scopes_granted" text NOT NULL,
	"status" text DEFAULT 'active' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"rotated_at" timestamp with time zone,
	"last_used_at" timestamp with time zone,
	CONSTRAINT "m365_user_tokens_user_id_unique" UNIQUE("user_id")
);
--> statement-breakpoint
DO $$ BEGIN
 ALTER TABLE "m365_user_tokens" ADD CONSTRAINT "m365_user_tokens_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "m365_user_tokens_status_idx" ON "m365_user_tokens" USING btree ("status");
