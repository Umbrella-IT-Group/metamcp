/**
 * Migration 0040, the per-namespace tool policy, proven two ways.
 *
 * Layer 1 (always runs): the migration SQL, the drizzle journal, and the
 * schema.ts mirror are asserted directly. A migration whose journal entry does
 * not out-rank the previous max is SILENTLY SKIPPED by drizzle (the column
 * would never exist in production, and the filter's policy read would fail
 * closed on every namespace), so the ordering is a test, not a review item.
 *
 * Layer 2 (opt-in via TEST_DATABASE_URL): the properties that live in the
 * DATABASE, against a real Postgres:
 *   - the column defaults to `allow_all` (the deploy is inert) and the CHECK
 *     refuses any other value;
 *   - setToolPolicy reports the value it replaced;
 *   - the mapping writers follow the policy: under `allowlist` a refresh's
 *     bulk upsert creates new rows INACTIVE and never changes an existing
 *     row's status, and re-saving a namespace's server list creates rows for
 *     unreviewed tools INACTIVE; under `allow_all` both behave as before;
 *   - a refresh and a policy flip serialize on the namespace row lock;
 *   - the reconnect-window fallback query returns ACTIVE rows only;
 *   - the REAL filter middleware, on the real database, resolves a server
 *     prefix among the namespace's mounted servers (upstream
 *     metatool-ai/metamcp#364) and applies the policy on both paths.
 *
 * GATING: opt-in via TEST_DATABASE_URL, never DATABASE_URL, because this suite
 * TRUNCATEs. Run it against a throwaway database:
 *
 *   cd apps/backend
 *   DATABASE_URL=postgres://.../metamcp_test npx drizzle-kit migrate
 *   TEST_DATABASE_URL=postgres://.../metamcp_test \
 *     npx vitest run src/db/repositories/namespace-tool-policy.integration.test.ts
 */

import { readFileSync } from "node:fs";
import path from "node:path";

import { and, eq } from "drizzle-orm";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

import { INTEGRATION_DB_LOCK_KEY } from "./integration-db-lock";

const MIGRATION_TAG = "0040_namespace_tool_policy";
const MIGRATION_PATH = path.resolve(
  __dirname,
  `../../../drizzle/${MIGRATION_TAG}.sql`,
);
const JOURNAL_PATH = path.resolve(
  __dirname,
  "../../../drizzle/meta/_journal.json",
);
const SCHEMA_PATH = path.resolve(__dirname, "../schema.ts");

/** 0039's journal `when`; 0040 must be strictly above it. */
const PRIOR_MAX_WHEN = 1787788800000;

describe("migration 0040: the DDL that adds the tool policy", () => {
  const raw = readFileSync(MIGRATION_PATH, "utf8");
  // Assert against the STATEMENTS, not the file: the header comment names the
  // policies and would otherwise be read as schema.
  const sql = raw
    .split("\n")
    .filter((line) => !line.trimStart().startsWith("--"))
    .join("\n");

  it("adds the column idempotently, NOT NULL default 'allow_all' (deploy is inert)", () => {
    expect(sql).toContain(
      `ALTER TABLE "namespaces" ADD COLUMN IF NOT EXISTS "tool_policy" text NOT NULL DEFAULT 'allow_all'`,
    );
  });

  it("guards the CHECK with a DO block and allows exactly the two policies", () => {
    expect(sql).toContain("conname = 'namespaces_tool_policy_check'");
    expect(sql).toContain('ADD CONSTRAINT "namespaces_tool_policy_check"');
    expect(sql).toContain(
      `CHECK ("tool_policy" IN ('allow_all', 'allowlist'))`,
    );
    expect((sql.match(/DO \$\$/g) ?? []).length).toBe(1);
  });
});

describe("drizzle journal ordering for 0040", () => {
  const journal = JSON.parse(readFileSync(JOURNAL_PATH, "utf8")) as {
    entries: { idx: number; when: number; tag: string }[];
  };

  it("registers 0040 as idx 40 with the migration's file name as its tag", () => {
    const entry = journal.entries.find((e) => e.tag === MIGRATION_TAG);
    expect(entry).toBeDefined();
    expect(entry?.idx).toBe(40);
  });

  it("has a `when` STRICTLY GREATER than every earlier entry", () => {
    const entry = journal.entries.find((e) => e.tag === MIGRATION_TAG);
    const when = entry?.when ?? Number.NEGATIVE_INFINITY;
    const earlier = journal.entries.filter(
      (e) => entry !== undefined && e.idx < entry.idx,
    );
    // drizzle applies only entries whose `when` exceeds the max already
    // applied. Get this wrong and 0040 is skipped in production WITHOUT an
    // error, and the filter's policy read fails closed on every namespace.
    expect(when).toBeGreaterThan(Math.max(...earlier.map((e) => e.when)));
    expect(when).toBeGreaterThan(PRIOR_MAX_WHEN);
  });

  it("keeps idx and when monotonically increasing and unique across the journal", () => {
    const idxs = journal.entries.map((e) => e.idx);
    const whens = journal.entries.map((e) => e.when);
    expect(idxs).toEqual([...idxs].sort((a, b) => a - b));
    expect(whens).toEqual([...whens].sort((a, b) => a - b));
    expect(new Set(whens).size).toBe(whens.length);
  });
});

describe("schema.ts mirror, so `drizzle-kit generate` re-adds nothing", () => {
  const schema = readFileSync(SCHEMA_PATH, "utf8");

  it("declares the column NOT NULL default 'allow_all'", () => {
    expect(schema).toMatch(
      /tool_policy: text\("tool_policy"\)\s*\.\$type<NamespaceToolPolicy>\(\)\s*\.notNull\(\)\s*\.default\("allow_all"\)/,
    );
  });

  it("mirrors the CHECK by name", () => {
    expect(schema).toContain('"namespaces_tool_policy_check"');
  });
});

const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL;
// `describe.skipIf` rather than a silent early return: a skipped suite is
// visible in the vitest output.
const describeIfDb = describe.skipIf(!TEST_DATABASE_URL);

type Db = Awaited<typeof import("../index")>["db"];
type Pool = Awaited<typeof import("../index")>["pool"];
type Schema = typeof import("../schema");
type Middleware =
  typeof import("../../lib/metamcp/metamcp-middleware/filter-tools.functional");

let db: Db;
let pool: Pool;
let schema: Schema;
let namespacesRepository: (typeof import("./namespaces.repo"))["namespacesRepository"];
let namespaceMappingsRepository: (typeof import("./namespace-mappings.repo"))["namespaceMappingsRepository"];
let filter: Middleware;

const USER_A = "policy-user-a";
const USER_B = "policy-user-b";
const NS_A = "70000000-0000-4000-8000-00000000000a";
const NS_B = "70000000-0000-4000-8000-00000000000b";
// Two servers named "github", one per owner, as mcp_servers_name_user_unique_idx
// allows. B's is inserted FIRST so a lookup by name alone, with no ORDER BY,
// tends to land on it.
const GITHUB_B = "80000000-0000-4000-8000-00000000000b";
const GITHUB_A = "80000000-0000-4000-8000-00000000000a";

beforeAll(async () => {
  if (!TEST_DATABASE_URL) return;
  // db/index reads DATABASE_URL at import time, so set it before importing.
  process.env.DATABASE_URL = TEST_DATABASE_URL;
  ({ db, pool } = await import("../index"));
  schema = await import("../schema");
  ({ namespacesRepository } = await import("./namespaces.repo"));
  ({ namespaceMappingsRepository } = await import("./namespace-mappings.repo"));
  filter = await import(
    "../../lib/metamcp/metamcp-middleware/filter-tools.functional"
  );
  await db.execute(
    `SELECT pg_advisory_lock(${INTEGRATION_DB_LOCK_KEY})` as never,
  );
});

afterAll(async () => {
  if (!TEST_DATABASE_URL || !db) return;
  await truncate();
  await db.execute(
    `SELECT pg_advisory_unlock(${INTEGRATION_DB_LOCK_KEY})` as never,
  );
  await pool.end();
});

async function truncate() {
  await db.execute(
    `TRUNCATE TABLE namespace_tool_mappings, namespace_server_mappings, tools, namespaces, mcp_servers, users RESTART IDENTITY CASCADE` as never,
  );
}

/** Insert tools for a server; returns name -> uuid. */
async function addTools(serverUuid: string, ...names: string[]) {
  const rows = await db
    .insert(schema.toolsTable)
    .values(
      names.map((name) => ({
        name,
        description: `${name} description`,
        toolSchema: { type: "object" as const, properties: {} },
        mcp_server_uuid: serverUuid,
      })),
    )
    .returning({ uuid: schema.toolsTable.uuid, name: schema.toolsTable.name });
  return new Map(rows.map((row) => [row.name, row.uuid]));
}

async function mapTool(
  namespaceUuid: string,
  serverUuid: string,
  toolUuid: string,
  status: "ACTIVE" | "INACTIVE",
) {
  await db.insert(schema.namespaceToolMappingsTable).values({
    namespace_uuid: namespaceUuid,
    mcp_server_uuid: serverUuid,
    tool_uuid: toolUuid,
    status,
  });
}

/** tool name -> status for one namespace. */
async function statuses(namespaceUuid: string) {
  const rows = await db
    .select({
      name: schema.toolsTable.name,
      status: schema.namespaceToolMappingsTable.status,
    })
    .from(schema.namespaceToolMappingsTable)
    .innerJoin(
      schema.toolsTable,
      eq(schema.toolsTable.uuid, schema.namespaceToolMappingsTable.tool_uuid),
    )
    .where(eq(schema.namespaceToolMappingsTable.namespace_uuid, namespaceUuid));
  return Object.fromEntries(rows.map((row) => [row.name, row.status]));
}

async function setPolicyDirect(
  namespaceUuid: string,
  policy: "allow_all" | "allowlist",
) {
  await db
    .update(schema.namespacesTable)
    .set({ tool_policy: policy })
    .where(eq(schema.namespacesTable.uuid, namespaceUuid));
}

/**
 * Return a raw client whose transaction may still be open (an assertion failed
 * before its COMMIT). ROLLBACK first: released as-is, the open transaction
 * would keep its lock on the namespace row and every later test in the file
 * would fail behind it instead of the one that broke. After a COMMIT the
 * ROLLBACK is a no-op (postgres only warns).
 */
async function endTransaction(client: {
  query: (sql: string) => Promise<unknown>;
  release: () => void;
}) {
  try {
    await client.query("ROLLBACK");
  } finally {
    client.release();
  }
}

/** Wait until some backend is blocked waiting on another's row lock. */
async function waitForRowLockWaiter() {
  const deadline = Date.now() + 5_000;
  for (;;) {
    const waiting = await db.execute(
      `SELECT count(*)::int AS n FROM pg_locks
        WHERE NOT granted AND locktype IN ('transactionid', 'tuple')` as never,
    );
    const n = (waiting as unknown as { rows: Array<{ n: number }> }).rows[0].n;
    if (n > 0) return;
    if (Date.now() > deadline) {
      throw new Error("no backend ever blocked on the namespace row lock");
    }
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
}

let toolsA: Map<string, string>;

/** A seeded tool's uuid in namespace A's github, failing loudly if absent. */
function toolA(name: string): string {
  const uuid = toolsA.get(name);
  if (!uuid) {
    throw new Error(`no seeded tool "${name}" on GITHUB_A`);
  }
  return uuid;
}

async function seed() {
  await truncate();
  await db.insert(schema.usersTable).values([
    { id: USER_A, name: "A", email: "policy-a@example.invalid" },
    { id: USER_B, name: "B", email: "policy-b@example.invalid" },
  ]);
  await db.insert(schema.mcpServersTable).values([
    {
      uuid: GITHUB_B,
      name: "github",
      type: "STDIO",
      command: "true",
      user_id: USER_B,
    },
    {
      uuid: GITHUB_A,
      name: "github",
      type: "STDIO",
      command: "true",
      user_id: USER_A,
    },
  ]);
  await db.insert(schema.namespacesTable).values([
    { uuid: NS_A, name: "policy-a", user_id: USER_A },
    { uuid: NS_B, name: "policy-b", user_id: USER_B },
  ]);
  await db.insert(schema.namespaceServerMappingsTable).values([
    { namespace_uuid: NS_A, mcp_server_uuid: GITHUB_A },
    { namespace_uuid: NS_B, mcp_server_uuid: GITHUB_B },
  ]);
  toolsA = await addTools(GITHUB_A, "read", "delete_repo", "brand_new");
  await addTools(GITHUB_B, "read", "delete_repo");
  // Namespace A curated its github: `read` on, `delete_repo` off. No row for
  // `brand_new`, a tool that arrived after the curation.
  await mapTool(NS_A, GITHUB_A, toolA("read"), "ACTIVE");
  await mapTool(NS_A, GITHUB_A, toolA("delete_repo"), "INACTIVE");
  filter.clearFilterCache();
}

describeIfDb("namespaces.tool_policy against a REAL postgres", () => {
  beforeEach(seed);

  it("defaults a namespace inserted without a policy to allow_all", async () => {
    const [row] = await db
      .select({ tool_policy: schema.namespacesTable.tool_policy })
      .from(schema.namespacesTable)
      .where(eq(schema.namespacesTable.uuid, NS_A));
    expect(row.tool_policy).toBe("allow_all");
  });

  it("the CHECK refuses a value outside the two policies", async () => {
    const err = (await db
      .update(schema.namespacesTable)
      .set({ tool_policy: "deny_all" as never })
      .where(eq(schema.namespacesTable.uuid, NS_A))
      .then(
        () => null,
        (e) => e,
      )) as (Error & { cause?: { constraint?: string } }) | null;
    expect(err).not.toBeNull();
    expect(
      [err?.message, err?.cause?.constraint].filter(Boolean).join(" | "),
    ).toContain("namespaces_tool_policy_check");
  });

  it("setToolPolicy returns the value it replaced and the updated row", async () => {
    const first = await namespacesRepository.setToolPolicy(NS_A, "allowlist");
    expect(first?.previous).toBe("allow_all");
    expect(first?.namespace.tool_policy).toBe("allowlist");

    const back = await namespacesRepository.setToolPolicy(NS_A, "allow_all");
    expect(back?.previous).toBe("allowlist");
    expect(back?.namespace.tool_policy).toBe("allow_all");

    expect(
      await namespacesRepository.setToolPolicy(
        "70000000-0000-4000-8000-0000000000ff",
        "allowlist",
      ),
    ).toBeUndefined();
  });

  it("every namespace read carries the policy", async () => {
    await setPolicyDirect(NS_A, "allowlist");
    expect((await namespacesRepository.findByUuid(NS_A))?.tool_policy).toBe(
      "allowlist",
    );
    expect(
      (await namespacesRepository.findByUuidWithServers(NS_A))?.tool_policy,
    ).toBe("allowlist");
    const all = await namespacesRepository.findAll();
    expect(Object.fromEntries(all.map((n) => [n.uuid, n.tool_policy]))).toEqual(
      { [NS_A]: "allowlist", [NS_B]: "allow_all" },
    );
  });

  describe("refresh (bulkUpsertNamespaceToolMappings)", () => {
    const refreshA = () =>
      namespaceMappingsRepository.bulkUpsertNamespaceToolMappings({
        namespaceUuid: NS_A,
        // What refreshTools sends: every tool it saw, asked ACTIVE.
        toolMappings: ["read", "delete_repo", "brand_new"].map((name) => ({
          toolUuid: toolA(name),
          serverUuid: GITHUB_A,
          status: "ACTIVE" as const,
        })),
      });

    it("allow_all: unchanged, new rows ACTIVE and an INACTIVE row switched back on", async () => {
      const result = await refreshA();

      expect(result.toolPolicy).toBe("allow_all");
      expect(await statuses(NS_A)).toEqual({
        read: "ACTIVE",
        delete_repo: "ACTIVE",
        brand_new: "ACTIVE",
      });
    });

    it("allowlist: a new row is INACTIVE and existing statuses are kept", async () => {
      await setPolicyDirect(NS_A, "allowlist");

      const result = await refreshA();

      expect(result.toolPolicy).toBe("allowlist");
      expect(result.mappings).toHaveLength(3);
      expect(await statuses(NS_A)).toEqual({
        read: "ACTIVE",
        delete_repo: "INACTIVE",
        brand_new: "INACTIVE",
      });
    });

    it("waits for an uncommitted policy flip and then follows the NEW policy", async () => {
      const flipper = await pool.connect();
      try {
        await flipper.query("BEGIN");
        await flipper.query(
          `UPDATE namespaces SET tool_policy = 'allowlist' WHERE uuid = $1`,
          [NS_A],
        );

        const refresh = refreshA();
        await waitForRowLockWaiter();
        await flipper.query("COMMIT");

        expect((await refresh).toolPolicy).toBe("allowlist");
      } finally {
        await endTransaction(flipper);
      }

      expect(await statuses(NS_A)).toEqual({
        read: "ACTIVE",
        delete_repo: "INACTIVE",
        brand_new: "INACTIVE",
      });
    });

    it("a policy flip waits for an in-flight refresh's share lock", async () => {
      const refresher = await pool.connect();
      let flipped = false;
      try {
        await refresher.query("BEGIN");
        await refresher.query(
          `SELECT tool_policy FROM namespaces WHERE uuid = $1 FOR SHARE`,
          [NS_A],
        );

        const flip = namespacesRepository
          .setToolPolicy(NS_A, "allowlist")
          .then((result) => {
            flipped = true;
            return result;
          });
        await waitForRowLockWaiter();
        expect(flipped).toBe(false);

        await refresher.query("COMMIT");
        expect((await flip)?.namespace.tool_policy).toBe("allowlist");
      } finally {
        await endTransaction(refresher);
      }
    });
  });

  describe("re-saving a namespace's servers (namespacesRepository.update)", () => {
    const resave = () =>
      namespacesRepository.update({
        uuid: NS_A,
        name: "policy-a",
        user_id: USER_A,
        mcpServerUuids: [GITHUB_A],
      });

    it("allow_all: unchanged, an unreviewed tool gets an ACTIVE row", async () => {
      await resave();
      expect(await statuses(NS_A)).toEqual({
        read: "ACTIVE",
        delete_repo: "INACTIVE",
        brand_new: "ACTIVE",
      });
    });

    it("allowlist: an unreviewed tool gets an INACTIVE row, reviewed ones keep theirs", async () => {
      await setPolicyDirect(NS_A, "allowlist");
      await resave();
      expect(await statuses(NS_A)).toEqual({
        read: "ACTIVE",
        delete_repo: "INACTIVE",
        brand_new: "INACTIVE",
      });
    });
  });

  it("the reconnect-window fallback query returns ACTIVE rows only", async () => {
    expect(
      await namespacesRepository.findServersForNamespaceToolName(NS_A, "read"),
    ).toEqual([{ serverUuid: GITHUB_A, serverName: "github" }]);
    // INACTIVE row: not a routing candidate.
    expect(
      await namespacesRepository.findServersForNamespaceToolName(
        NS_A,
        "delete_repo",
      ),
    ).toEqual([]);
    // No row: never was one (the join requires a row).
    expect(
      await namespacesRepository.findServersForNamespaceToolName(
        NS_A,
        "brand_new",
      ),
    ).toEqual([]);
  });

  describe("the REAL filter middleware on the real database", () => {
    const call = async (namespaceUuid: string, name: string) => {
      let ran = false;
      const result = await filter.createFilterCallToolMiddleware({
        cacheEnabled: false,
      })(async () => {
        ran = true;
        return { content: [{ type: "text" as const, text: "ok" }] };
      })(
        { method: "tools/call", params: { name, arguments: {} } },
        { namespaceUuid, sessionId: "integration" },
      );
      return { ran, result };
    };

    const list = async (namespaceUuid: string, names: string[]) => {
      const { tools } = await filter.createFilterListToolsMiddleware({
        cacheEnabled: false,
      })(async () => ({
        tools: names.map((name) => ({
          name,
          inputSchema: { type: "object" as const },
        })),
      }))(
        { method: "tools/list", params: {} },
        { namespaceUuid, sessionId: "integration" },
      );
      return tools.map((tool) => tool.name).sort();
    };

    const ALL = ["github__read", "github__delete_repo", "github__brand_new"];

    it("#364: namespace A's INACTIVE row decides, not B's same-named server", async () => {
      // B's github has no row in A, and was inserted first. Resolved by name
      // alone, the call could be judged against it and allowed.
      const { ran, result } = await call(NS_A, "github__delete_repo");
      expect(ran).toBe(false);
      expect(result.isError).toBe(true);

      // B's own namespace (allow_all, no rows) still serves its tool.
      expect((await call(NS_B, "github__delete_repo")).ran).toBe(true);
    });

    it("allow_all lists every tool without an INACTIVE row", async () => {
      expect(await list(NS_A, ALL)).toEqual([
        "github__brand_new",
        "github__read",
      ]);
      expect((await call(NS_A, "github__brand_new")).ran).toBe(true);
    });

    it("allowlist lists and runs only ACTIVE rows", async () => {
      await setPolicyDirect(NS_A, "allowlist");

      expect(await list(NS_A, ALL)).toEqual(["github__read"]);
      expect((await call(NS_A, "github__read")).ran).toBe(true);
      expect((await call(NS_A, "github__brand_new")).ran).toBe(false);
      expect((await call(NS_A, "github__delete_repo")).ran).toBe(false);

      // Namespace B is untouched by A's flip.
      expect(await list(NS_B, ["github__read", "github__delete_repo"])).toEqual(
        ["github__delete_repo", "github__read"],
      );
    });

    it("a server mounted only in another namespace does not resolve", async () => {
      await db
        .delete(schema.namespaceServerMappingsTable)
        .where(
          and(
            eq(schema.namespaceServerMappingsTable.namespace_uuid, NS_A),
            eq(schema.namespaceServerMappingsTable.mcp_server_uuid, GITHUB_A),
          ),
        );

      const { ran, result } = await call(NS_A, "github__read");
      expect(ran).toBe(false);
      expect(JSON.stringify(result.content)).toContain(
        "server could not be resolved",
      );
    });
  });
});
