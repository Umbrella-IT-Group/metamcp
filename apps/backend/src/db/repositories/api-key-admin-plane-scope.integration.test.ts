/**
 * Migration 0043: api_keys.admin_plane_scope.
 *
 * Layer 1 (always runs): the migration SQL, the drizzle journal and the
 * schema.ts mirror are asserted directly. A journal entry whose `when` does not
 * out-rank the previous max is SILENTLY skipped by drizzle, so ordering is a
 * test, not a review item.
 *
 * Layer 2 (opt-in via TEST_DATABASE_URL): the migration's own statements run
 * against a scratch table holding rows from before the column existed, and the
 * real Drizzle migrator runs the whole journal on a fresh database twice. What
 * is pinned: every existing row, admin-plane or not, becomes `sync` (the deploy
 * only ever removes reach); both CHECKs refuse a bad row; a second run changes
 * nothing; and the columns an image from before this migration reads are all
 * still there.
 *
 *   cd apps/backend
 *   DATABASE_URL=<url> npx drizzle-kit migrate
 *   TEST_DATABASE_URL=<url> npx vitest run \
 *     src/db/repositories/api-key-admin-plane-scope.integration.test.ts
 */

import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";

import { Client } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { INTEGRATION_DB_LOCK_KEY } from "./integration-db-lock";

const MIGRATION_PATH = path.resolve(
  __dirname,
  "../../../drizzle/0043_api_key_admin_plane_scope.sql",
);
const MIGRATIONS_FOLDER = path.resolve(__dirname, "../../../drizzle");
const JOURNAL_PATH = path.resolve(MIGRATIONS_FOLDER, "meta/_journal.json");
const SCHEMA_PATH = path.resolve(__dirname, "../schema.ts");

const raw = readFileSync(MIGRATION_PATH, "utf8");
// Assert against the STATEMENTS, not the file: the header comment names the
// scopes and would otherwise be read as schema.
const statementsSql = raw
  .split("\n")
  .filter((line) => !line.trimStart().startsWith("--"))
  .join("\n");

describe("migration 0043: the DDL", () => {
  it("adds the column idempotently, NOT NULL default sync", () => {
    expect(statementsSql).toContain(
      `ALTER TABLE "api_keys" ADD COLUMN IF NOT EXISTS "admin_plane_scope" text NOT NULL DEFAULT 'sync';`,
    );
  });

  it("guards both CHECKs with a DO block (idempotent)", () => {
    for (const name of [
      "api_keys_admin_plane_scope_valid",
      "api_keys_admin_plane_scope_requires_admin_plane",
    ]) {
      expect(statementsSql).toContain(`conname = '${name}'`);
      expect(statementsSql).toContain(`ADD CONSTRAINT "${name}"`);
    }
    expect((statementsSql.match(/DO \$\$/g) ?? []).length).toBe(2);
  });

  it("encodes the scope values and the admin-plane-only rule", () => {
    expect(statementsSql).toContain(
      `CHECK ("admin_plane_scope" IN ('sync', 'operator'))`,
    );
    expect(statementsSql).toContain(
      `CHECK ("admin_plane" = true OR "admin_plane_scope" = 'sync')`,
    );
  });

  it("adds no index, no setter and no data change", () => {
    expect(statementsSql).not.toMatch(/CREATE\s+(UNIQUE\s+)?INDEX/i);
    expect(statementsSql).not.toMatch(/\bUPDATE\b/i);
    expect(statementsSql).not.toMatch(/\bINSERT\b/i);
    expect(statementsSql).not.toMatch(/\bDROP\b/i);
  });
});

describe("drizzle journal for 0043", () => {
  const journal = JSON.parse(readFileSync(JOURNAL_PATH, "utf8")) as {
    entries: { idx: number; when: number; tag: string }[];
  };

  it("registers 0043 with a `when` strictly above every EARLIER entry", () => {
    const entry = journal.entries.find(
      (e) => e.tag === "0043_api_key_admin_plane_scope",
    );
    expect(entry).toBeDefined();
    expect(entry?.idx).toBe(43);
    const earlier = journal.entries.filter((e) => e.idx < (entry?.idx ?? 0));
    expect(entry?.when).toBeGreaterThan(
      Math.max(...earlier.map((e) => e.when)),
    );
    // 0042's `when`; get this wrong and 0043 is skipped WITHOUT an error.
    expect(entry?.when).toBeGreaterThan(1788048000000);
  });

  it("has a migration file for every journal entry and no unregistered one", () => {
    const files = readdirSync(MIGRATIONS_FOLDER)
      .filter((name) => name.endsWith(".sql"))
      .map((name) => name.replace(/\.sql$/, ""))
      .sort();
    expect(journal.entries.map((e) => e.tag).sort()).toEqual(files);
  });
});

describe("schema.ts mirror: so `drizzle-kit generate` re-adds nothing", () => {
  const schema = readFileSync(SCHEMA_PATH, "utf8");

  it("declares the column and both CHECKs", () => {
    expect(schema).toContain(
      'admin_plane_scope: text("admin_plane_scope").notNull().default("sync")',
    );
    expect(schema).toContain('"api_keys_admin_plane_scope_valid"');
    expect(schema).toContain(
      '"api_keys_admin_plane_scope_requires_admin_plane"',
    );
  });
});

const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL;
const describeIfDb = describe.skipIf(!TEST_DATABASE_URL);

describeIfDb("migration 0043 against a REAL postgres", () => {
  let admin: Client;
  const scratchDb = `itest_mig_${Date.now().toString(36)}`;

  /** The migration's statements, aimed at a scratch table instead of api_keys. */
  const scratchMigration = (table: string) =>
    statementsSql.replaceAll('"api_keys"', `"${table}"`);

  async function applyMigration(client: Client, table: string) {
    // drizzle splits on the statement-breakpoint marker; so does this.
    for (const statement of scratchMigration(table).split(
      "--> statement-breakpoint",
    )) {
      if (statement.trim()) await client.query(statement);
    }
  }

  const urlFor = (database: string) => {
    const url = new URL(TEST_DATABASE_URL as string);
    url.pathname = `/${database}`;
    return url.toString();
  };

  beforeAll(async () => {
    admin = new Client({ connectionString: TEST_DATABASE_URL });
    await admin.connect();
    await admin.query(`SELECT pg_advisory_lock(${INTEGRATION_DB_LOCK_KEY})`);
  });

  afterAll(async () => {
    if (!admin) return;
    await admin.query(`DROP TABLE IF EXISTS scratch_keys`);
    await admin.query(`DROP DATABASE IF EXISTS ${scratchDb} WITH (FORCE)`);
    await admin.query(`SELECT pg_advisory_unlock(${INTEGRATION_DB_LOCK_KEY})`);
    await admin.end();
  });

  describe("the statements on rows from before the column existed", () => {
    beforeAll(async () => {
      await admin.query(`DROP TABLE IF EXISTS scratch_keys`);
      // The columns the migration's CHECKs mention, as they were after 0041.
      await admin.query(`
        CREATE TABLE scratch_keys (
          uuid uuid PRIMARY KEY DEFAULT gen_random_uuid(),
          name text NOT NULL,
          user_id text,
          admin_plane boolean NOT NULL DEFAULT false
        )`);
      await admin.query(
        `INSERT INTO scratch_keys (name, user_id, admin_plane) VALUES
           ('old data plane', 'u1', false),
           ('old public data plane', NULL, false),
           ('old admin plane', 'u1', true),
           ('old second admin plane', 'u2', true)`,
      );
      await applyMigration(admin, "scratch_keys");
    });

    it("turns every existing row into sync, admin-plane or not", async () => {
      const { rows } = await admin.query(
        `SELECT name, admin_plane, admin_plane_scope FROM scratch_keys ORDER BY name`,
      );
      expect(rows).toHaveLength(4);
      for (const row of rows) expect(row.admin_plane_scope).toBe("sync");
    });

    it("refuses a scope outside the two known ones", async () => {
      for (const scope of ["", "admin", "Operator", "SYNC", "root"]) {
        await expect(
          admin.query(
            `INSERT INTO scratch_keys (name, user_id, admin_plane, admin_plane_scope)
             VALUES ('bad scope', 'u1', true, $1)`,
            [scope],
          ),
        ).rejects.toThrow(/admin_plane_scope_valid/);
      }
    });

    it("refuses operator on a data-plane key, on insert and by update", async () => {
      await expect(
        admin.query(
          `INSERT INTO scratch_keys (name, user_id, admin_plane, admin_plane_scope)
           VALUES ('data plane operator', 'u1', false, 'operator')`,
        ),
      ).rejects.toThrow(/requires_admin_plane/);
      await expect(
        admin.query(
          `UPDATE scratch_keys SET admin_plane_scope = 'operator'
            WHERE name = 'old data plane'`,
        ),
      ).rejects.toThrow(/requires_admin_plane/);
    });

    it("accepts operator on an admin-plane key, and sync on either kind", async () => {
      await admin.query(
        `INSERT INTO scratch_keys (name, user_id, admin_plane, admin_plane_scope)
         VALUES ('new operator', 'u1', true, 'operator'),
                ('new sync admin', 'u1', true, 'sync'),
                ('new sync data', 'u1', false, 'sync')`,
      );
      const { rows } = await admin.query(
        `SELECT admin_plane_scope FROM scratch_keys WHERE name = 'new operator'`,
      );
      expect(rows[0].admin_plane_scope).toBe("operator");
    });

    it("changes nothing when run a second time", async () => {
      const before = await admin.query(
        `SELECT name, admin_plane_scope FROM scratch_keys ORDER BY name`,
      );
      const constraintsBefore = await admin.query(
        `SELECT conname FROM pg_constraint
          WHERE conrelid = 'scratch_keys'::regclass ORDER BY conname`,
      );

      await applyMigration(admin, "scratch_keys");

      expect(
        (
          await admin.query(
            `SELECT name, admin_plane_scope FROM scratch_keys ORDER BY name`,
          )
        ).rows,
      ).toEqual(before.rows);
      expect(
        (
          await admin.query(
            `SELECT conname FROM pg_constraint
              WHERE conrelid = 'scratch_keys'::regclass ORDER BY conname`,
          )
        ).rows,
      ).toEqual(constraintsBefore.rows);
    });
  });

  describe("the real Drizzle migrator over the whole journal", () => {
    it("discovers 0043 on a fresh database, and a second run changes nothing", async () => {
      await admin.query(`CREATE DATABASE ${scratchDb}`);
      const fresh = new Client({ connectionString: urlFor(scratchDb) });
      await fresh.connect();
      try {
        const { drizzle } = await import("drizzle-orm/node-postgres");
        const { migrate } = await import("drizzle-orm/node-postgres/migrator");
        const migrator = drizzle(fresh);

        await migrate(migrator, { migrationsFolder: MIGRATIONS_FOLDER });

        const journal = JSON.parse(readFileSync(JOURNAL_PATH, "utf8")) as {
          entries: unknown[];
        };
        const applied = await fresh.query(
          `SELECT count(*)::int AS n FROM drizzle.__drizzle_migrations`,
        );
        expect(applied.rows[0].n).toBe(journal.entries.length);

        const column = await fresh.query(
          `SELECT is_nullable, column_default FROM information_schema.columns
            WHERE table_name = 'api_keys' AND column_name = 'admin_plane_scope'`,
        );
        expect(column.rows).toEqual([
          { is_nullable: "NO", column_default: "'sync'::text" },
        ]);
        const checks = await fresh.query(
          `SELECT conname FROM pg_constraint
            WHERE conrelid = 'api_keys'::regclass AND conname LIKE 'api_keys_admin_plane_scope_%'
            ORDER BY conname`,
        );
        expect(checks.rows.map((r) => r.conname)).toEqual([
          "api_keys_admin_plane_scope_requires_admin_plane",
          "api_keys_admin_plane_scope_valid",
        ]);

        // A row written the way the previous image wrote it (no scope column in
        // its INSERT) reads `sync`, and that image's own column list still
        // reads cleanly.
        await fresh.query(
          `INSERT INTO users (id, name, email, role) VALUES ('mig-u', 'mig', 'mig@example.test', 'admin')`,
        );
        await fresh.query(
          `INSERT INTO api_keys (name, key_hash, last4, user_id, admin_plane)
           VALUES ('prev image key', 'hash-prev-image', 'wxyz', 'mig-u', true)`,
        );
        const prev = await fresh.query(
          `SELECT uuid, name, key_hash, last4, user_id, endpoint_uuid,
                  acts_as_user_id, created_at, is_active, last_used_at,
                  admin_plane, allowed_cidrs, ip_policy_mode, last_used_ip
             FROM api_keys WHERE name = 'prev image key'`,
        );
        expect(prev.rows).toHaveLength(1);
        const scope = await fresh.query(
          `SELECT admin_plane_scope FROM api_keys WHERE name = 'prev image key'`,
        );
        expect(scope.rows[0].admin_plane_scope).toBe("sync");

        await migrate(migrator, { migrationsFolder: MIGRATIONS_FOLDER });

        const again = await fresh.query(
          `SELECT count(*)::int AS n FROM drizzle.__drizzle_migrations`,
        );
        expect(again.rows[0].n).toBe(journal.entries.length);
        expect(
          (
            await fresh.query(
              `SELECT admin_plane_scope FROM api_keys WHERE name = 'prev image key'`,
            )
          ).rows[0].admin_plane_scope,
        ).toBe("sync");
      } finally {
        await fresh.end();
      }
    }, 120_000);
  });
});
