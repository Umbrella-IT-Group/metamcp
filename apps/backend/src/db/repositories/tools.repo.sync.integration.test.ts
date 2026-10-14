/**
 * REAL-POSTGRES integration test for `ToolsRepository.syncTools`, the write
 * behind both the gateway's tools/list catalog sync and the UI's tools.sync.
 *
 * Why this file exists: the property that matters is a property of the
 * DATABASE. `namespace_tool_mappings.tool_uuid` references `tools.uuid` ON
 * DELETE CASCADE, and namespace curation lives in those rows, INACTIVE ones
 * included. A sync that deleted a tool missing from one listing would cascade
 * the curator's INACTIVE row away, and the tool would come back unmapped, which
 * the gateway serves as ACTIVE. Only a real driver proves the NOT EXISTS
 * predicate keeps that row, that the cascade never fires for it, and that the
 * row lock closes the window in which a mapping committed mid-sync could still
 * be erased. A mock returns whatever its author imagined.
 *
 * GATING: opt-in via TEST_DATABASE_URL, and deliberately NOT via DATABASE_URL —
 * this suite TRUNCATEs. See the note at the top of
 * `access-queries.integration.test.ts` for the full reasoning, and run it the
 * same way (a throwaway postgres, `drizzle-kit migrate`, then vitest with
 * TEST_DATABASE_URL set).
 */

import { and, eq } from "drizzle-orm";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

import { INTEGRATION_DB_LOCK_KEY } from "./integration-db-lock";

const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL;

// `describe.skipIf` rather than a silent early return: a skipped suite is
// visible in the vitest output, so "the integration test didn't run" can never
// be mistaken for "the integration test passed".
const describeIfDb = describe.skipIf(!TEST_DATABASE_URL);

const SERVER_A = "30000000-0000-4000-8000-00000000000a";
const SERVER_B = "30000000-0000-4000-8000-00000000000b";
const CURATED_NS = "40000000-0000-4000-8000-000000000001";
const OTHER_NS = "40000000-0000-4000-8000-000000000002";

type Db = Awaited<typeof import("../index")>["db"];
type Pool = Awaited<typeof import("../index")>["pool"];
type Schema = typeof import("../schema");

let db: Db;
let pool: Pool;
let schema: Schema;
let repo: (typeof import("./tools.repo"))["toolsRepository"];

beforeAll(async () => {
  if (!TEST_DATABASE_URL) return;

  // db/index reads DATABASE_URL at import time, so it has to be set BEFORE the
  // first dynamic import below.
  process.env.DATABASE_URL = TEST_DATABASE_URL;

  ({ db, pool } = await import("../index"));
  schema = await import("../schema");
  ({ toolsRepository: repo } = await import("./tools.repo"));

  // Serialize against every other TEST_DATABASE_URL suite before touching a
  // shared table; same advisory lock key as the other integration suites.
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
    `TRUNCATE TABLE namespace_tool_mappings, tools, namespaces, mcp_servers RESTART IDENTITY CASCADE` as never,
  );
}

const listed = (...names: string[]) =>
  names.map((name) => ({
    name,
    description: `${name} description`,
    inputSchema: { properties: {} },
  }));

/** Every tool of a server, by name, with its uuid. */
async function catalog(serverUuid: string) {
  const rows = await db
    .select({ uuid: schema.toolsTable.uuid, name: schema.toolsTable.name })
    .from(schema.toolsTable)
    .where(eq(schema.toolsTable.mcp_server_uuid, serverUuid));
  return new Map(rows.map((row) => [row.name, row.uuid]));
}

/** One tool's uuid, failing loudly if the catalog does not hold it. */
async function toolUuid(serverUuid: string, name: string): Promise<string> {
  const uuid = (await catalog(serverUuid)).get(name);
  if (!uuid) {
    throw new Error(`no tool "${name}" in the catalog of ${serverUuid}`);
  }
  return uuid;
}

async function mappingsFor(uuid: string) {
  return db
    .select()
    .from(schema.namespaceToolMappingsTable)
    .where(eq(schema.namespaceToolMappingsTable.tool_uuid, uuid));
}

async function map(
  namespaceUuid: string,
  serverUuid: string,
  uuid: string,
  status: "ACTIVE" | "INACTIVE",
) {
  await db.insert(schema.namespaceToolMappingsTable).values({
    namespace_uuid: namespaceUuid,
    mcp_server_uuid: serverUuid,
    tool_uuid: uuid,
    status,
    override_description: `${status} by a curator`,
  });
}

async function seed() {
  await truncate();
  await db.insert(schema.mcpServersTable).values([
    { uuid: SERVER_A, name: "toolsync-a", type: "STDIO", command: "true" },
    { uuid: SERVER_B, name: "toolsync-b", type: "STDIO", command: "true" },
  ]);
  await db.insert(schema.namespacesTable).values([
    { uuid: CURATED_NS, name: "toolsync-curated", user_id: null },
    { uuid: OTHER_NS, name: "toolsync-other", user_id: null },
  ]);
  // Server A lists three tools; the curated namespace switched one off.
  await repo.syncTools({
    mcpServerUuid: SERVER_A,
    tools: listed("kept", "switched_off", "unmapped"),
  });
  await repo.syncTools({ mcpServerUuid: SERVER_B, tools: listed("other") });
  await map(
    CURATED_NS,
    SERVER_A,
    await toolUuid(SERVER_A, "switched_off"),
    "INACTIVE",
  );
  await map(CURATED_NS, SERVER_A, await toolUuid(SERVER_A, "kept"), "ACTIVE");
}

describeIfDb("syncTools never removes a tool a namespace maps", () => {
  beforeEach(seed);

  it("keeps a tool with an INACTIVE row when a listing omits it, row intact", async () => {
    const switchedOff = await toolUuid(SERVER_A, "switched_off");
    const [rowBefore] = await mappingsFor(switchedOff);

    // A momentarily short listing: the curated-off tool is missing from it.
    const { deleted } = await repo.syncTools({
      mcpServerUuid: SERVER_A,
      tools: listed("kept"),
    });

    const after = await catalog(SERVER_A);
    expect(after.get("switched_off")).toBe(switchedOff);
    const rowsAfter = await mappingsFor(switchedOff);
    expect(rowsAfter).toHaveLength(1);
    expect(rowsAfter[0]).toEqual(rowBefore);
    expect(rowsAfter[0].status).toBe("INACTIVE");
    expect(deleted.map((row) => row.name)).toEqual(["unmapped"]);
  });

  it("serves the returning tool with the SAME row, so it is still switched off", async () => {
    const switchedOff = await toolUuid(SERVER_A, "switched_off");

    await repo.syncTools({ mcpServerUuid: SERVER_A, tools: listed("kept") });
    await repo.syncTools({
      mcpServerUuid: SERVER_A,
      tools: listed("kept", "switched_off"),
    });

    expect((await catalog(SERVER_A)).get("switched_off")).toBe(switchedOff);
    const [row] = await mappingsFor(switchedOff);
    expect(row.status).toBe("INACTIVE");
  });

  it("removes an obsolete tool that no namespace maps", async () => {
    await repo.syncTools({ mcpServerUuid: SERVER_A, tools: listed("kept") });

    expect([...(await catalog(SERVER_A)).keys()].sort()).toEqual([
      "kept",
      "switched_off",
    ]);
  });

  it("updates a listed tool in place: same uuid, new definition, mapping kept", async () => {
    const kept = await toolUuid(SERVER_A, "kept");

    await repo.syncTools({
      mcpServerUuid: SERVER_A,
      tools: [{ name: "kept", description: "reworded", inputSchema: {} }],
    });

    const [row] = await db
      .select()
      .from(schema.toolsTable)
      .where(eq(schema.toolsTable.uuid, kept));
    expect(row.description).toBe("reworded");
    expect(await mappingsFor(kept)).toHaveLength(1);
  });

  it("removes nothing on an empty listing", async () => {
    const { upserted, deleted } = await repo.syncTools({
      mcpServerUuid: SERVER_A,
      tools: [],
    });

    expect(upserted).toEqual([]);
    expect(deleted).toEqual([]);
    expect((await catalog(SERVER_A)).size).toBe(3);
  });

  it("touches only the listed server's tools", async () => {
    await repo.syncTools({ mcpServerUuid: SERVER_A, tools: listed("kept") });

    expect([...(await catalog(SERVER_B)).keys()]).toEqual(["other"]);
  });

  it("keeps a mapping committed while the sync waits on its lock, instead of cascading it away", async () => {
    const unmapped = await toolUuid(SERVER_A, "unmapped");

    // A curator's mapping insert, in flight: its foreign-key check holds a
    // FOR KEY SHARE lock on the tool row until it commits.
    const curator = await pool.connect();
    try {
      await curator.query("BEGIN");
      await curator.query(
        `INSERT INTO namespace_tool_mappings
           (namespace_uuid, mcp_server_uuid, tool_uuid, status)
         VALUES ($1, $2, $3, 'INACTIVE')`,
        [OTHER_NS, SERVER_A, unmapped],
      );

      // The sync starts while that insert is uncommitted, so any snapshot it
      // takes now does not see the new row.
      const sync = repo.syncTools({
        mcpServerUuid: SERVER_A,
        tools: listed("kept"),
      });

      // Wait until the sync is actually blocked on the curator's row lock, so
      // the commit below lands while it waits rather than before it starts. A
      // backend waiting for a row lock waits on the holder's transaction id;
      // the other integration suites wait on the advisory lock instead, so
      // they cannot satisfy this.
      const deadline = Date.now() + 5_000;
      for (;;) {
        const waiting = await db.execute(
          `SELECT count(*)::int AS n FROM pg_locks
            WHERE NOT granted AND locktype = 'transactionid'` as never,
        );
        const n = (waiting as unknown as { rows: Array<{ n: number }> }).rows[0]
          .n;
        if (n > 0) break;
        if (Date.now() > deadline) {
          throw new Error("the sync never blocked on the tool row's lock");
        }
        await new Promise((resolve) => setTimeout(resolve, 20));
      }

      await curator.query("COMMIT");
      const { deleted } = await sync;

      expect(deleted.map((row) => row.name)).toEqual([]);
    } finally {
      curator.release();
    }

    expect((await catalog(SERVER_A)).get("unmapped")).toBe(unmapped);
    const rows = await db
      .select()
      .from(schema.namespaceToolMappingsTable)
      .where(
        and(
          eq(schema.namespaceToolMappingsTable.tool_uuid, unmapped),
          eq(schema.namespaceToolMappingsTable.namespace_uuid, OTHER_NS),
        ),
      );
    expect(rows).toHaveLength(1);
    expect(rows[0].status).toBe("INACTIVE");
  });
});
