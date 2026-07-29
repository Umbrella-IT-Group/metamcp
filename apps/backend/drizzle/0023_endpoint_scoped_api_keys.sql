-- Endpoint-scoped API keys. api_keys.endpoint_uuid binds a key to exactly ONE
-- endpoint; checkApiKeyAccess denies a scoped key everywhere else. NULL means
-- legacy/unscoped (grandfathered): the key keeps reaching every endpoint with
-- enable_api_key_auth, exactly as before this migration — existing keys are
-- deliberately NOT migrated. New keys must pick an endpoint or pass an
-- explicit all_endpoints escape hatch at mint time (enforced in the create
-- path, not here). ON DELETE CASCADE: a key bound to a deleted endpoint is
-- useless and revoking it on endpoint deletion is the safe default.
--
-- endpoints.require_scoped_api_key lets a sensitive endpoint opt OUT of the
-- grandfathered gateway-wide keys: when true, checkApiKeyAccess rejects any
-- unscoped (endpoint_uuid IS NULL) key on that endpoint. Default false =
-- zero behavior change for every existing endpoint.
--
-- Idempotent (ADD COLUMN IF NOT EXISTS / CREATE INDEX IF NOT EXISTS) per
-- fork convention. Ordering-safe relative to 0022 (no shared object).
ALTER TABLE "api_keys" ADD COLUMN IF NOT EXISTS "endpoint_uuid" uuid REFERENCES "endpoints"("uuid") ON DELETE CASCADE;
CREATE INDEX IF NOT EXISTS "api_keys_endpoint_uuid_idx" ON "api_keys" ("endpoint_uuid");
ALTER TABLE "endpoints" ADD COLUMN IF NOT EXISTS "require_scoped_api_key" boolean NOT NULL DEFAULT false;
