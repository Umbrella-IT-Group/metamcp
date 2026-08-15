-- oauth_clients.registration_source: tell the two mint paths apart.
--
-- The retention sweep added alongside this column deletes never-used OAuth
-- clients older than DCR_CLIENT_RETENTION_DAYS. It is aimed at the anonymous
-- RFC 7591 endpoint, POST /oauth/register, which needs no credential and had
-- grown 45 junk rows that nothing could prune. But the admin UI's "create
-- OAuth client" dialog writes to the SAME table through the SAME
-- buildClientRegistration core and therefore the same generateSecureClientId,
-- so an admin-minted client is byte-indistinguishable from a DCR one: both
-- read mcp_client_<random>. A prefix match is not a discriminator here.
--
-- That matters because an unused admin-minted row is often unused ON PURPOSE.
-- Pre-provisioning a partner's client and handing over the credentials days
-- before they pair is the normal way that dialog gets used, and the sweep
-- would have deleted the client out from under them.
--
-- NULL IS DELIBERATE for every row that already exists. Provenance was not
-- recorded before this migration, so it cannot be reconstructed, and the sweep
-- matches registration_source = 'dcr' exactly — meaning legacy rows are never
-- touched. The known backlog of junk registrations therefore survives this
-- change and stays deletable from the admin UI one row at a time, which is
-- where it was already. The sweep's job is to bound FUTURE growth on an
-- endpoint anyone can POST to; a fixed, finite set of old rows is not the
-- unbounded problem, and deleting an admin's pre-provisioned client to reach
-- them would be a worse trade.
--
-- No DEFAULT for the same reason: an insert path that forgets to set this must
-- fail safe (land as NULL, never swept) rather than fail open (inherit 'dcr',
-- swept). @repo/zod-types makes the field required on the create input so the
-- compiler catches that first, but the column's own shape is the backstop.
--
-- Idempotent (ADD COLUMN IF NOT EXISTS) for the reason recorded on
-- 0014_oauth_refresh_token: a re-run must not crash-loop a deployer.
-- Journal "when" deliberately exceeds 0028's (1786838400000): drizzle only
-- applies entries whose "when" is above the max already applied -- see
-- UMBRELLA_FORK.md's migration-ordering note.
ALTER TABLE "oauth_clients" ADD COLUMN IF NOT EXISTS "registration_source" text;

-- The column's domain, enforced by the database rather than by the two callers
-- that happen to write it today. psql and admin_cli are routine ops paths here,
-- so a typo'd third value ('DCR', 'dynamic') is reachable — and its failure
-- mode is the quiet one: the sweep matches 'dcr' exactly, so a mistyped row
-- would simply never be swept and nobody would find out. This also makes the
-- $type<OAuthClientRegistrationSource>() narrowing in schema.ts true of the
-- data and not just of the code. Mirrored there via drizzle's check().
--
-- NULL stays legal: it is the honest value for every row that predates this
-- migration, and the sweep already treats it as not-DCR.
--
-- DO block for idempotency (postgres has no ADD CONSTRAINT IF NOT EXISTS),
-- matching the convention 0024_api_key_acts_as_identity established.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'oauth_clients_registration_source_valid'
      AND conrelid = '"oauth_clients"'::regclass
  ) THEN
    ALTER TABLE "oauth_clients"
      ADD CONSTRAINT "oauth_clients_registration_source_valid"
      CHECK ("registration_source" IS NULL
             OR "registration_source" IN ('dcr', 'admin'));
  END IF;
END $$;
