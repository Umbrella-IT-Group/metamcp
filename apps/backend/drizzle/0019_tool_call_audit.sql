-- Tool-call audit log: one row per proxied tools/call so "who called what
-- when" is SQL-queryable instead of a Loki grep (Umbrella-MCP-Server
-- TASKLIST "Tool-call audit logging" SPEC). Raw params are NEVER stored —
-- only a sha256 of the JSON-serialized arguments (too easy to log a
-- password otherwise). Rows are pruned after TOOL_AUDIT_RETENTION_DAYS
-- (default 90) by the existing oauth cleanup interval. Idempotent
-- (IF NOT EXISTS) per fork convention.
CREATE TABLE IF NOT EXISTS "tool_call_audit" (
	"uuid" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"called_at" timestamp with time zone DEFAULT now() NOT NULL,
	"client_name" text,
	"namespace_uuid" text,
	"session_id" text,
	"server_name" text NOT NULL,
	"tool_name" text NOT NULL,
	"params_hash" text,
	"success" boolean NOT NULL,
	"error_code" text,
	"latency_ms" integer
);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "tool_call_audit_called_at_idx" ON "tool_call_audit" ("called_at");
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "tool_call_audit_tool_name_idx" ON "tool_call_audit" ("tool_name");
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS "tool_call_audit_client_name_idx" ON "tool_call_audit" ("client_name");
