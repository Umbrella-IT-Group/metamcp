-- API-key governance: add api_keys.last_used_at. Written fire-and-forget and
-- throttled by validateApiKey (only when NULL or >=15 min stale) so the hot
-- auth path never pays a write per request and a failed timestamp write can
-- never fail the request. Nullable — a key that has never authenticated reads
-- NULL. Ordering-safe relative to 0020 (independent table, no shared object).
-- Idempotent (ADD COLUMN IF NOT EXISTS) per fork convention.
ALTER TABLE "api_keys" ADD COLUMN IF NOT EXISTS "last_used_at" timestamp with time zone;
