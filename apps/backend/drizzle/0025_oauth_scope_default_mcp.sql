-- OAuth scope: stop recording "admin" for callers who were never admins.
--
-- The code half of this shipped already: every issue path (dynamic client
-- registration, the authorization code, the token grant, the WWW-Authenticate
-- challenge) now writes GRANTED_OAUTH_SCOPE = 'mcp', the one scope this
-- server ever grants. The three tables kept DEFAULT 'admin' underneath, so a
-- row written without an explicit scope still landed as "admin", and every
-- legacy row still reads that way.
--
-- Scope carries NO privilege in this fork: checkOAuthAccess
-- (api-key-oauth.middleware) authorizes on the token's user id plus endpoint
-- ownership and never inspects the scope string, and the real privilege gate
-- is the better-auth session role. So this is honest labelling plus
-- defense-in-depth, not an access change — no live token loses or gains
-- anything. It matters anyway because handleRefreshTokenGrant copies the
-- STORED scope forward on every refresh: without rewriting the rows, an
-- 'admin'-labelled grant renews itself indefinitely, and any future code
-- (or auditor) that starts reading the string inherits the lie.
--
-- Idempotent: ALTER COLUMN SET DEFAULT is naturally so, and the UPDATEs are
-- scoped to 'admin' exactly, leaving any other legacy scope value alone (none
-- of them are privilege-bearing either, and rewriting them would destroy
-- history for no security gain). Journal "when" deliberately exceeds 0024's
-- (1785283200000): drizzle only applies entries whose "when" is above the max
-- already applied — see UMBRELLA_FORK.md's migration-ordering note.
ALTER TABLE "oauth_clients" ALTER COLUMN "scope" SET DEFAULT 'mcp';
ALTER TABLE "oauth_authorization_codes" ALTER COLUMN "scope" SET DEFAULT 'mcp';
ALTER TABLE "oauth_access_tokens" ALTER COLUMN "scope" SET DEFAULT 'mcp';

UPDATE "oauth_clients" SET "scope" = 'mcp' WHERE "scope" = 'admin';
UPDATE "oauth_authorization_codes" SET "scope" = 'mcp' WHERE "scope" = 'admin';
UPDATE "oauth_access_tokens" SET "scope" = 'mcp' WHERE "scope" = 'admin';
