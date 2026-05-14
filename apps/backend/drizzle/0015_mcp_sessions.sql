CREATE TABLE IF NOT EXISTS "mcp_sessions" (
	"session_id" text PRIMARY KEY NOT NULL,
	"namespace_uuid" uuid NOT NULL,
	"endpoint_name" text NOT NULL,
	"auth_principal" text NOT NULL,
	"auth_method" text NOT NULL,
	"init_params" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"last_seen_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "mcp_sessions_last_seen_at_idx" ON "mcp_sessions" USING btree ("last_seen_at");
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "mcp_sessions_namespace_uuid_idx" ON "mcp_sessions" USING btree ("namespace_uuid");
