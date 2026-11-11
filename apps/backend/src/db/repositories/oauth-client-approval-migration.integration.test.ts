/**
 * Migration 0042 (oauth_clients approval state) against a populated
 * pre-change table, applied twice, on a REAL Postgres.
 *
 * The migration file itself is executed, statement by statement, inside a
 * scratch schema whose four OAuth tables are cloned from the migrated public
 * ones (`CREATE TABLE ... (LIKE ... INCLUDING ALL)`) with the 0042 columns
 * then dropped, which is exactly the pre-0042 shape. The public tables other
 * suites use are never altered, and the scratch schema is dropped afterwards.
 *
 * Pinned: the one-time grandfathering (admin-created and NULL-provenance
 * rows, and any row with a code, token or rotated-token record, approved;
 * never-used self-registrations pending), byte-for-byte preservation of
 * every existing column and child row, a re-run that changes no decision, the
 * pending default for a later insert, and the CHECKs.
 *
 * Opt-in via TEST_DATABASE_URL, pointed at a disposable, migrated database.
 */

import { readFileSync } from "node:fs";
import path from "node:path";

import { Client } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { INTEGRATION_DB_LOCK_KEY } from "./integration-db-lock";

const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL;
const describeIfDb = describe.skipIf(!TEST_DATABASE_URL);

const SCHEMA = `mig0042_${Date.now().toString(36)}`;
const MIGRATION = readFileSync(
  path.join(
    __dirname,
    "..",
    "..",
    "..",
    "drizzle",
    "0042_oauth_client_approval.sql",
  ),
  "utf8",
);
const STATEMENTS = MIGRATION.split("--> statement-breakpoint")
  .map((statement) => statement.trim())
  .filter((statement) => statement.length > 0);

const EXPECTED: Record<string, string> = {
  c_admin_hosted: "approved",
  c_legacy_null: "approved",
  c_dcr_used_token: "approved",
  c_dcr_used_code: "approved",
  c_dcr_used_rotated: "approved",
  c_dcr_unused: "pending",
  c_dcr_hosted_unused: "pending",
};

describeIfDb("migration 0042 on a populated pre-change schema", () => {
  let client: Client;

  const statuses = async () => {
    const res = await client.query(
      "SELECT client_id, approval_status FROM oauth_clients ORDER BY client_id",
    );
    return Object.fromEntries(
      res.rows.map((r: { client_id: string; approval_status: string }) => [
        r.client_id,
        r.approval_status,
      ]),
    );
  };

  const fingerprint = async () => {
    const parts: string[] = [];
    for (const [table, key, columns] of [
      [
        "oauth_clients",
        "client_id",
        "client_id, client_secret, client_secret_salt, client_name, redirect_uris, grant_types, response_types, token_endpoint_auth_method, scope, registration_source, created_at, updated_at",
      ],
      ["oauth_access_tokens", "access_token", "*"],
      ["oauth_authorization_codes", "code", "*"],
      ["oauth_rotated_refresh_tokens", "refresh_token_hash", "*"],
    ]) {
      const res = await client.query(
        `SELECT md5(coalesce(string_agg(row_to_json(t)::text, '|' ORDER BY ${key}), '')) AS h
         FROM (SELECT ${columns} FROM ${table}) t`,
      );
      parts.push(`${table}:${res.rows[0].h}`);
    }
    return parts.join(",");
  };

  const migrate = async () => {
    for (const statement of STATEMENTS) {
      await client.query(statement);
    }
  };

  let before = "";

  beforeAll(async () => {
    client = new Client({ connectionString: TEST_DATABASE_URL });
    await client.connect();
    await client.query(`SELECT pg_advisory_lock(${INTEGRATION_DB_LOCK_KEY})`);
    await client.query(`CREATE SCHEMA ${SCHEMA}`);
    await client.query(`SET search_path TO ${SCHEMA}`);
    for (const table of [
      "oauth_clients",
      "oauth_authorization_codes",
      "oauth_access_tokens",
      "oauth_rotated_refresh_tokens",
    ]) {
      await client.query(
        `CREATE TABLE ${table} (LIKE public.${table} INCLUDING ALL)`,
      );
    }
    // Back to the pre-0042 shape. Dropping a column drops the CHECKs on it.
    await client.query(
      `ALTER TABLE oauth_clients DROP COLUMN approval_status, DROP COLUMN approved_by,
         DROP COLUMN approved_at, DROP COLUMN rejected_at`,
    );

    await client.query(`
      INSERT INTO oauth_clients (client_id, client_secret, client_secret_salt, client_name, redirect_uris, token_endpoint_auth_method, registration_source, created_at) VALUES
       ('c_admin_hosted', 'hash-admin', 'salt-admin', 'Hosted (org)', '{https://claude.ai/api/mcp/auth_callback}', 'client_secret_post', 'admin', now() - interval '90 days'),
       ('c_legacy_null', NULL, NULL, 'Pre-0029 row', '{http://localhost:3334/callback}', 'none', NULL, now() - interval '200 days'),
       ('c_dcr_used_token', NULL, NULL, 'Used, token', '{http://localhost:53682/callback}', 'none', 'dcr', now() - interval '30 days'),
       ('c_dcr_used_code', NULL, NULL, 'Used, code', '{http://127.0.0.1:41000/callback}', 'none', 'dcr', now() - interval '1 hour'),
       ('c_dcr_used_rotated', NULL, NULL, 'Used, rotated', '{http://localhost:1455/auth/callback}', 'none', 'dcr', now() - interval '20 days'),
       ('c_dcr_unused', NULL, NULL, 'Never used', '{http://localhost:1455/auth/callback}', 'none', 'dcr', now() - interval '3 days'),
       ('c_dcr_hosted_unused', 'hash-hosted', 'salt-hosted', 'Hosted, never used', '{https://claude.ai/api/mcp/auth_callback}', 'client_secret_post', 'dcr', now() - interval '1 day')`);
    await client.query(`
      INSERT INTO oauth_access_tokens (access_token, access_token_last4, client_id, user_id, scope, expires_at, refresh_token, refresh_token_expires_at, family_id) VALUES
       ('tokhash-1', 'ok-1', 'c_dcr_used_token', 'u1', 'mcp', now() - interval '1 day', 'refhash-1', now() + interval '300 days', 'aaaaaaaa-0000-0000-0000-000000000001')`);
    await client.query(`
      INSERT INTO oauth_authorization_codes (code, client_id, redirect_uri, scope, user_id, code_challenge, code_challenge_method, expires_at) VALUES
       ('codehash-1', 'c_dcr_used_code', 'http://127.0.0.1:41000/callback', 'mcp', 'u1', 'chal', 'S256', now() + interval '5 minutes')`);
    await client.query(`
      INSERT INTO oauth_rotated_refresh_tokens (refresh_token_hash, family_id, client_id, user_id, expires_at) VALUES
       ('rothash-1', 'aaaaaaaa-0000-0000-0000-000000000003', 'c_dcr_used_rotated', 'u1', now() + interval '100 days')`);

    before = await fingerprint();
    await migrate();
  });

  afterAll(async () => {
    if (!client) return;
    await client.query(`DROP SCHEMA IF EXISTS ${SCHEMA} CASCADE`);
    await client.query(`SELECT pg_advisory_unlock(${INTEGRATION_DB_LOCK_KEY})`);
    await client.end();
  });

  it("grandfathers admin, legacy and ever-used rows as approved and never-used self-registrations as pending", async () => {
    expect(await statuses()).toEqual(EXPECTED);
    const res = await client.query(
      "SELECT count(*)::int AS n FROM oauth_clients WHERE approved_by IS NOT NULL OR approved_at IS NOT NULL OR rejected_at IS NOT NULL",
    );
    expect(res.rows[0].n).toBe(0);
  });

  it("preserves every existing column and child row byte for byte", async () => {
    expect(await fingerprint()).toBe(before);
  });

  it("changes no decision when the migration runs again", async () => {
    await client.query(
      "UPDATE oauth_clients SET approval_status = 'rejected', rejected_at = now() WHERE client_id = 'c_dcr_hosted_unused'",
    );
    const decided = await statuses();
    const fingerprintBefore = await fingerprint();
    await migrate();
    expect(await statuses()).toEqual(decided);
    expect(decided.c_dcr_hosted_unused).toBe("rejected");
    expect(decided.c_dcr_unused).toBe("pending");
    expect(await fingerprint()).toBe(fingerprintBefore);
  });

  it("defaults a later insert that names no status to pending", async () => {
    await client.query(
      "INSERT INTO oauth_clients (client_id, client_name, registration_source) VALUES ('c_new', 'x', 'dcr')",
    );
    const res = await client.query(
      "SELECT approval_status FROM oauth_clients WHERE client_id = 'c_new'",
    );
    expect(res.rows[0].approval_status).toBe("pending");
  });

  it.each([
    [
      "an unknown status",
      "INSERT INTO oauth_clients (client_id, client_name, approval_status) VALUES ('c_bad', 'x', 'Approved')",
      "oauth_clients_approval_status_valid",
    ],
    [
      "a rejected row without its time",
      "INSERT INTO oauth_clients (client_id, client_name, approval_status) VALUES ('c_bad', 'x', 'rejected')",
      "oauth_clients_approval_fields_consistent",
    ],
    [
      "an approver on a pending row",
      "INSERT INTO oauth_clients (client_id, client_name, approval_status, approved_by) VALUES ('c_bad', 'x', 'pending', 'someone')",
      "oauth_clients_approval_fields_consistent",
    ],
    [
      "a NULL status",
      "UPDATE oauth_clients SET approval_status = NULL WHERE client_id = 'c_dcr_unused'",
      "approval_status",
    ],
  ])("refuses %s", async (_label, statement, mention) => {
    await expect(client.query(statement)).rejects.toThrow(mention);
  });
});
