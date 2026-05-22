-- PR #22: Stamp the gateway process UUID at session init. Used by lazy
-- recovery to refuse recovering sessions that crossed a gateway restart,
-- because the client's cached server-capability set may be stale post
-- restart (initialize negotiates once per session). Nullable for
-- backwards-compatibility with sessions persisted by prior versions.
ALTER TABLE "mcp_sessions" ADD COLUMN IF NOT EXISTS "gateway_boot_id" uuid;
