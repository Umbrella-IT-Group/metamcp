-- PR #23: Capability-hash column. Used alongside gateway_boot_id (PR #22)
-- so lazy recovery refuses only when capabilities actually changed across
-- a restart, not on every restart. Capabilities are deterministic per
-- code version; a same-image redeploy keeps the hash stable.
ALTER TABLE "mcp_sessions" ADD COLUMN IF NOT EXISTS "capability_hash" text;
