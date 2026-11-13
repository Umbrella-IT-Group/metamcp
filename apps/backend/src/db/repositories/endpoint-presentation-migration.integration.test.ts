/**
 * Migration 0044: the endpoint_presentation table.
 *
 * Layer 1 (always runs): the migration SQL, the drizzle journal entry and the
 * schema.ts mirror are asserted directly. A journal entry whose `when` does not
 * out-rank the previous max is SILENTLY skipped by drizzle, and the gateway's
 * resolver fails open to "no presentation", so a skipped migration would show
 * up as a feature that quietly does nothing: ordering is a test, not a review
 * item.
 *
 * Layer 2 (opt-in via TEST_DATABASE_URL): the real Drizzle migrator runs the
 * whole journal on a fresh database, twice; the migration's own statements are
 * then applied again to the migrated database (the migrator skips an applied
 * entry, so that re-run is what proves the statements are idempotent); and the
 * constraints are exercised with rows: the length bounds and control-character
 * rules at their boundaries, the mode values, the primary key, and the
 * cascading foreign key.
 *
 * Oracles: the bounds are the design's (title 1 to 80 characters on one line;
 * instructions 1 to 1500 characters with no C0 control other than TAB, LF and
 * CR); `char_length` counts code points, which is why an 80-code-point title of
 * astral characters (160 UTF-16 units) passes the CHECK and the application
 * refuses it, the application being the stricter layer.
 *
 *   cd apps/backend
 *   DATABASE_URL=<url> npx drizzle-kit migrate
 *   TEST_DATABASE_URL=<url> npx vitest run \
 *     src/db/repositories/endpoint-presentation-migration.integration.test.ts
 */

import { readFileSync } from "node:fs";
import path from "node:path";

import { Client } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { INTEGRATION_DB_LOCK_KEY } from "./integration-db-lock";

const MIGRATION_PATH = path.resolve(
  __dirname,
  "../../../drizzle/0044_endpoint_presentation.sql",
);
const MIGRATIONS_FOLDER = path.resolve(__dirname, "../../../drizzle");
const JOURNAL_PATH = path.resolve(MIGRATIONS_FOLDER, "meta/_journal.json");
const SCHEMA_PATH = path.resolve(__dirname, "../schema.ts");

const raw = readFileSync(MIGRATION_PATH, "utf8");
// Assert against the STATEMENTS, not the file: the header comment names the
// columns and the modes and would otherwise be read as schema.
const statementsSql = raw
  .split("\n")
  .filter((line) => !line.trimStart().startsWith("--"))
  .join("\n");

describe("migration 0044: the DDL", () => {
  it("creates the table idempotently, with the primary key and the defaults", () => {
    expect(statementsSql).toContain(
      'CREATE TABLE IF NOT EXISTS "endpoint_presentation"',
    );
    expect(statementsSql).toContain(
      '"endpoint_uuid" uuid PRIMARY KEY NOT NULL',
    );
    expect(statementsSql).toContain(
      `"tool_listing" text DEFAULT 'full' NOT NULL`,
    );
    expect(statementsSql).toContain(
      '"omit_output_schemas" boolean DEFAULT false NOT NULL',
    );
    expect(statementsSql).toContain(
      '"updated_at" timestamp with time zone DEFAULT now() NOT NULL',
    );
  });

  it("guards every constraint with a DO block (idempotent) and names the four", () => {
    for (const name of [
      "endpoint_presentation_endpoint_uuid_fk",
      "endpoint_presentation_tool_listing_check",
      "endpoint_presentation_title_check",
      "endpoint_presentation_instructions_check",
    ]) {
      expect(statementsSql).toContain(`conname = '${name}'`);
      expect(statementsSql).toContain(`ADD CONSTRAINT "${name}"`);
    }
    expect((statementsSql.match(/DO \$\$/g) ?? []).length).toBe(4);
  });

  it("cascades with the endpoint and allows both listing modes", () => {
    expect(statementsSql).toContain(
      'FOREIGN KEY ("endpoint_uuid") REFERENCES "endpoints"("uuid") ON DELETE CASCADE',
    );
    expect(statementsSql).toContain(
      `CHECK ("tool_listing" IN ('full', 'lean'))`,
    );
  });

  it("encodes the text bounds", () => {
    expect(statementsSql).toContain(
      `char_length("title") BETWEEN 1 AND 80 AND "title" !~ '[\\r\\n]'`,
    );
    expect(statementsSql).toContain(
      `char_length("instructions") BETWEEN 1 AND 1500 AND "instructions" !~ '[\\u0001-\\u0008\\u000B\\u000C\\u000E-\\u001F\\u007F]'`,
    );
  });

  it("adds no index, no data change and nothing destructive", () => {
    expect(statementsSql).not.toMatch(/CREATE\s+(UNIQUE\s+)?INDEX/i);
    expect(statementsSql).not.toMatch(/\bUPDATE\b/i);
    expect(statementsSql).not.toMatch(/\bINSERT\b/i);
    expect(statementsSql).not.toMatch(/\bDROP\b/i);
    expect(statementsSql).not.toMatch(/\bALTER\s+TABLE\s+"endpoints"/i);
  });
});

describe("drizzle journal for 0044", () => {
  const journal = JSON.parse(readFileSync(JOURNAL_PATH, "utf8")) as {
    entries: { idx: number; when: number; tag: string }[];
  };

  it("registers 0044 with the reserved idx, tag and `when`", () => {
    const entry = journal.entries.find(
      (e) => e.tag === "0044_endpoint_presentation",
    );
    expect(entry).toBeDefined();
    expect(entry?.idx).toBe(44);
    expect(entry?.when).toBe(1788220800000);
  });

  it("gives 0044 a `when` strictly above every EARLIER entry, or it is skipped without an error", () => {
    const entry = journal.entries.find(
      (e) => e.tag === "0044_endpoint_presentation",
    );
    const earlier = journal.entries.filter((e) => e.idx < (entry?.idx ?? 0));
    expect(earlier.length).toBeGreaterThan(0);
    expect(entry?.when).toBeGreaterThan(
      Math.max(...earlier.map((e) => e.when)),
    );
    // 0043's `when`.
    expect(entry?.when).toBeGreaterThan(1788134400000);
  });
});

describe("schema.ts mirror: so `drizzle-kit generate` re-adds nothing", () => {
  const schema = readFileSync(SCHEMA_PATH, "utf8");

  it("declares the table, its columns and the three CHECKs", () => {
    expect(schema).toContain('"endpoint_presentation"');
    expect(schema).toContain(
      'tool_listing: text("tool_listing")\n      .$type<ToolListingMode>()\n      .notNull()\n      .default("full")',
    );
    for (const name of [
      "endpoint_presentation_tool_listing_check",
      "endpoint_presentation_title_check",
      "endpoint_presentation_instructions_check",
    ]) {
      expect(schema).toContain(`"${name}"`);
    }
  });

  it("references the endpoint with ON DELETE CASCADE", () => {
    expect(schema).toMatch(
      /endpoint_uuid: uuid\("endpoint_uuid"\)\s+\.primaryKey\(\)\s+\.references\(\(\) => endpointsTable\.uuid, \{ onDelete: "cascade" \}\)/,
    );
  });
});

const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL;
const describeIfDb = describe.skipIf(!TEST_DATABASE_URL);

describeIfDb("migration 0044 against a REAL postgres", () => {
  let admin: Client;
  let fresh: Client;
  const scratchDb = `itest_mig44_${Date.now().toString(36)}`;
  let counter = 0;

  const urlFor = (database: string) => {
    // A socket-path URL keeps its `host` query parameter, so only the database
    // name is replaced.
    const url = new URL(TEST_DATABASE_URL as string);
    url.pathname = `/${database}`;
    return url.toString();
  };

  /** A namespace and an endpoint in it; returns the endpoint uuid. */
  async function endpoint(): Promise<string> {
    counter += 1;
    const ns = await fresh.query(
      `INSERT INTO namespaces (name) VALUES ($1) RETURNING uuid`,
      [`ns-${counter}`],
    );
    const ep = await fresh.query(
      `INSERT INTO endpoints (name, namespace_uuid) VALUES ($1, $2) RETURNING uuid`,
      [`ep-${counter}`, ns.rows[0].uuid],
    );
    return ep.rows[0].uuid;
  }

  const insert = (
    endpointUuid: string,
    columns: {
      title?: string | null;
      instructions?: string | null;
      mode?: string;
    },
  ) =>
    fresh.query(
      `INSERT INTO endpoint_presentation (endpoint_uuid, title, instructions, tool_listing)
       VALUES ($1, $2, $3, $4)`,
      [
        endpointUuid,
        columns.title ?? null,
        columns.instructions ?? null,
        columns.mode ?? "full",
      ],
    );

  /** One row per call: a fresh endpoint each time keeps cases independent. */
  const accepted = async (columns: Parameters<typeof insert>[1]) => {
    await expect(insert(await endpoint(), columns)).resolves.toBeDefined();
  };
  const refused = async (
    columns: Parameters<typeof insert>[1],
    constraint: RegExp,
  ) => {
    await expect(insert(await endpoint(), columns)).rejects.toThrow(constraint);
  };

  beforeAll(async () => {
    admin = new Client({ connectionString: TEST_DATABASE_URL });
    await admin.connect();
    await admin.query(`SELECT pg_advisory_lock(${INTEGRATION_DB_LOCK_KEY})`);
    await admin.query(`CREATE DATABASE ${scratchDb}`);
    fresh = new Client({ connectionString: urlFor(scratchDb) });
    await fresh.connect();
  }, 120_000);

  afterAll(async () => {
    await fresh?.end();
    if (!admin) return;
    await admin.query(`DROP DATABASE IF EXISTS ${scratchDb} WITH (FORCE)`);
    await admin.query(`SELECT pg_advisory_unlock(${INTEGRATION_DB_LOCK_KEY})`);
    await admin.end();
  });

  describe("the real Drizzle migrator over the whole journal", () => {
    it("discovers 0044 on a fresh database, and a second run changes nothing", async () => {
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

      const columns = await fresh.query(
        `SELECT column_name, is_nullable, column_default
           FROM information_schema.columns
          WHERE table_name = 'endpoint_presentation' ORDER BY ordinal_position`,
      );
      expect(columns.rows).toEqual([
        {
          column_name: "endpoint_uuid",
          is_nullable: "NO",
          column_default: null,
        },
        { column_name: "title", is_nullable: "YES", column_default: null },
        {
          column_name: "instructions",
          is_nullable: "YES",
          column_default: null,
        },
        {
          column_name: "tool_listing",
          is_nullable: "NO",
          column_default: "'full'::text",
        },
        {
          column_name: "omit_output_schemas",
          is_nullable: "NO",
          column_default: "false",
        },
        {
          column_name: "updated_at",
          is_nullable: "NO",
          column_default: "now()",
        },
      ]);

      await migrate(migrator, { migrationsFolder: MIGRATIONS_FOLDER });
      const again = await fresh.query(
        `SELECT count(*)::int AS n FROM drizzle.__drizzle_migrations`,
      );
      expect(again.rows[0].n).toBe(journal.entries.length);
    }, 120_000);
  });

  describe("the migration's own statements, applied again", () => {
    const constraints = async () =>
      (
        await fresh.query(
          `SELECT conname, pg_get_constraintdef(oid) AS def FROM pg_constraint
            WHERE conrelid = 'endpoint_presentation'::regclass ORDER BY conname`,
        )
      ).rows;

    it("run without error and change nothing, rows included", async () => {
      const uuid = await endpoint();
      await insert(uuid, { title: "Desk", instructions: "Be brief." });
      const before = await constraints();
      expect(before.map((row) => row.conname)).toEqual([
        "endpoint_presentation_endpoint_uuid_fk",
        "endpoint_presentation_instructions_check",
        "endpoint_presentation_pkey",
        "endpoint_presentation_title_check",
        "endpoint_presentation_tool_listing_check",
      ]);

      // drizzle splits on the statement-breakpoint marker; so does this.
      for (const statement of statementsSql.split("--> statement-breakpoint")) {
        if (statement.trim()) await fresh.query(statement);
      }

      expect(await constraints()).toEqual(before);
      const row = await fresh.query(
        `SELECT title, instructions FROM endpoint_presentation WHERE endpoint_uuid = $1`,
        [uuid],
      );
      expect(row.rows).toEqual([{ title: "Desk", instructions: "Be brief." }]);
    });
  });

  describe("defaults", () => {
    it("a row holding only the endpoint is the full listing with no text and no trim", async () => {
      const uuid = await endpoint();
      await fresh.query(
        `INSERT INTO endpoint_presentation (endpoint_uuid) VALUES ($1)`,
        [uuid],
      );
      const { rows } = await fresh.query(
        `SELECT title, instructions, tool_listing, omit_output_schemas,
                updated_at IS NOT NULL AS has_time
           FROM endpoint_presentation WHERE endpoint_uuid = $1`,
        [uuid],
      );
      expect(rows).toEqual([
        {
          title: null,
          instructions: null,
          tool_listing: "full",
          omit_output_schemas: false,
          has_time: true,
        },
      ]);
    });
  });

  describe("the tool listing CHECK", () => {
    it("accepts full and lean and refuses anything else", async () => {
      await accepted({ mode: "full" });
      await accepted({ mode: "lean" });
      for (const mode of ["x", "", "FULL", "Lean", "full "]) {
        await refused({ mode }, /endpoint_presentation_tool_listing_check/);
      }
    });
  });

  describe("the title CHECK", () => {
    it("accepts 1 to 80 characters and refuses 0 and 81", async () => {
      await accepted({ title: "t" });
      await accepted({ title: "t".repeat(80) });
      await refused({ title: "" }, /endpoint_presentation_title_check/);
      await refused(
        { title: "t".repeat(81) },
        /endpoint_presentation_title_check/,
      );
    });

    it("counts code points, so the application, which counts UTF-16 units, is the stricter layer", async () => {
      // 80 astral characters: 80 code points (accepted here) and 160 UTF-16
      // units (refused by the application's own 80-unit bound).
      await accepted({ title: "\u{1F600}".repeat(80) });
      await refused(
        { title: "\u{1F600}".repeat(81) },
        /endpoint_presentation_title_check/,
      );
    });

    it("is one line: LF and CR are refused", async () => {
      await refused({ title: "a\nb" }, /endpoint_presentation_title_check/);
      await refused({ title: "a\rb" }, /endpoint_presentation_title_check/);
    });
  });

  describe("the instructions CHECK", () => {
    it("accepts 1 to 1500 characters and refuses 0 and 1501", async () => {
      await accepted({ instructions: "i" });
      await accepted({ instructions: "i".repeat(1500) });
      await refused(
        { instructions: "" },
        /endpoint_presentation_instructions_check/,
      );
      await refused(
        { instructions: "i".repeat(1501) },
        /endpoint_presentation_instructions_check/,
      );
    });

    it("accepts TAB and LF, which a multi-line text needs", async () => {
      await accepted({ instructions: "step one\n\tstep two\nstep three" });
    });

    it.each([
      ["SOH", "\u0001"],
      ["BEL", "\u0007"],
      ["BS", "\u0008"],
      ["VT", "\u000B"],
      ["FF", "\u000C"],
      ["SO", "\u000E"],
      ["ESC", "\u001B"],
      ["US", "\u001F"],
      ["DEL", "\u007F"],
    ])("refuses the control character %s", async (_name, char) => {
      await refused(
        { instructions: `ab${char}cd` },
        /endpoint_presentation_instructions_check/,
      );
    });
  });

  describe("keys", () => {
    it("allows one row per endpoint", async () => {
      const uuid = await endpoint();
      await insert(uuid, { title: "first" });
      await expect(insert(uuid, { title: "second" })).rejects.toThrow(
        /endpoint_presentation_pkey/,
      );
    });

    it("refuses a row for an endpoint that does not exist", async () => {
      await expect(
        insert("00000000-0000-4000-8000-000000000000", { title: "orphan" }),
      ).rejects.toThrow(/endpoint_presentation_endpoint_uuid_fk/);
    });

    it("is deleted with its endpoint, and with the namespace that endpoint is deleted by", async () => {
      const uuid = await endpoint();
      await insert(uuid, { title: "gone with the endpoint" });
      await fresh.query(`DELETE FROM endpoints WHERE uuid = $1`, [uuid]);
      expect(
        (
          await fresh.query(
            `SELECT 1 FROM endpoint_presentation WHERE endpoint_uuid = $1`,
            [uuid],
          )
        ).rows,
      ).toEqual([]);

      const viaNamespace = await endpoint();
      await insert(viaNamespace, { title: "gone with the namespace" });
      await fresh.query(
        `DELETE FROM namespaces WHERE uuid =
           (SELECT namespace_uuid FROM endpoints WHERE uuid = $1)`,
        [viaNamespace],
      );
      expect(
        (
          await fresh.query(
            `SELECT 1 FROM endpoint_presentation WHERE endpoint_uuid = $1`,
            [viaNamespace],
          )
        ).rows,
      ).toEqual([]);
    });
  });
});
