-- Seed for the MCP conformance job: one fixture backend, one namespace, one
-- mapping, in a THROWAWAY database, before the gateway boots.
--
-- Why SQL and not the gateway's environment bootstrap: that bootstrap covers
-- users, API keys, namespaces and endpoints but has no path for MCP servers or
-- namespace mappings. Seeding the namespace here means its uuid exists before
-- boot, so bootstrap finds it by name and creates the endpoint and key against
-- it. (The admin API was rejected: it needs a bootstrap admin and a minted
-- admin-plane key first.)
--
-- Idempotent: each insert is guarded, so a second run changes nothing.
-- Throwaway databases only: the guard below refuses any other database, because
-- the gateway's bootstrap and idle warmup also write to whatever they boot on.

DO $guard$
BEGIN
  IF current_database() !~ '(_test$|^conformance)'
     AND coalesce(current_setting('conformance.allow_db', true), '') <> '1' THEN
    RAISE EXCEPTION 'seed.sql refuses to run in database "%": not a throwaway database', current_database();
  END IF;
END
$guard$;

INSERT INTO mcp_servers (name, type, url, user_id)
SELECT 'Fixture', 'STREAMABLE_HTTP'::mcp_server_type, 'http://127.0.0.1:3901/mcp', NULL
WHERE NOT EXISTS (SELECT 1 FROM mcp_servers WHERE name = 'Fixture' AND user_id IS NULL);

INSERT INTO namespaces (name, user_id)
SELECT 'conformance', NULL
WHERE NOT EXISTS (SELECT 1 FROM namespaces WHERE name = 'conformance' AND user_id IS NULL);

INSERT INTO namespace_server_mappings (namespace_uuid, mcp_server_uuid, status)
SELECT n.uuid, s.uuid, 'ACTIVE'::mcp_server_status
FROM namespaces n, mcp_servers s
WHERE n.name = 'conformance' AND n.user_id IS NULL
  AND s.name = 'Fixture' AND s.user_id IS NULL
ON CONFLICT (namespace_uuid, mcp_server_uuid) DO NOTHING;
