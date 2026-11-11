/**
 * A server update that changes the URL must replace or clear the stored
 * bearer token and send the stored headers again, judged against the row as
 * it is when the write happens (planServerUpdate, mcp-servers.repo.ts
 * `updateReportingChange`). Against a real Postgres:
 *   - a same-URL save with a blank bearer keeps the stored token and headers;
 *   - a URL change with no decision is refused and leaves the WHOLE row as it
 *     was, other fields included;
 *   - a replacement or a clear is accepted and written;
 *   - the decision is atomic: an editor whose form still shows the old URL,
 *     racing an update that moved the server and set a new token, is judged
 *     against the committed URL and refused, instead of moving the server
 *     back with the new token still attached;
 *   - the change report the tRPC layer uses to retire pooled connections.
 *
 * GATING: opt-in via TEST_DATABASE_URL, never DATABASE_URL, because this suite
 * TRUNCATEs. Run it against a throwaway database:
 *
 *   cd apps/backend
 *   DATABASE_URL=postgres://.../metamcp_test npx drizzle-kit migrate
 *   TEST_DATABASE_URL=postgres://.../metamcp_test \
 *     npx vitest run src/db/repositories/mcp-servers.credential-retention.integration.test.ts
 */
import { randomBytes } from "node:crypto";

import { eq } from "drizzle-orm";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

import { INTEGRATION_DB_LOCK_KEY } from "./integration-db-lock";

const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL;
const describeIfDb = describe.skipIf(!TEST_DATABASE_URL);

type Db = Awaited<typeof import("../index")>["db"];
type Pool = Awaited<typeof import("../index")>["pool"];
type Schema = typeof import("../schema");
type Repo = (typeof import("./mcp-servers.repo"))["mcpServersRepository"];
type Plan = typeof import("./mcp-server-update-plan");
type Crypto = typeof import("../../lib/metamcp/server-bearer-crypto");

let db: Db;
let pool: Pool;
let schema: Schema;
let repo: Repo;
let plan: Plan;
let crypto: Crypto;

const OLD_URL = "http://mcp-vendor:3000/mcp";
const NEW_URL = "http://mcp-vendor-next:3000/mcp";
const STORED_HEADERS = { "x-api-key": "stored-header-value" };

beforeAll(async () => {
  if (!TEST_DATABASE_URL) return;
  process.env.DATABASE_URL = TEST_DATABASE_URL;
  process.env.M365_TOKEN_KEK = randomBytes(32).toString("base64");
  delete process.env.M365_KEK_ID;
  ({ db, pool } = await import("../index"));
  schema = await import("../schema");
  ({ mcpServersRepository: repo } = await import("./mcp-servers.repo"));
  plan = await import("./mcp-server-update-plan");
  crypto = await import("../../lib/metamcp/server-bearer-crypto");
  await db.execute(
    `SELECT pg_advisory_lock(${INTEGRATION_DB_LOCK_KEY})` as never,
  );
});

afterAll(async () => {
  if (!TEST_DATABASE_URL || !db) return;
  await db.execute(`TRUNCATE TABLE mcp_servers CASCADE` as never);
  await db.execute(
    `SELECT pg_advisory_unlock(${INTEGRATION_DB_LOCK_KEY})` as never,
  );
  await pool.end();
});

beforeEach(async () => {
  if (!TEST_DATABASE_URL) return;
  await db.execute(`TRUNCATE TABLE mcp_servers CASCADE` as never);
});

async function seed() {
  return await repo.create({
    name: "vendor",
    description: "Vendor tools",
    type: "STREAMABLE_HTTP",
    url: OLD_URL,
    bearerToken: "stored-bearer-value",
    headers: STORED_HEADERS,
    user_id: null,
  });
}

async function read(uuid: string) {
  const [row] = await db
    .select()
    .from(schema.mcpServersTable)
    .where(eq(schema.mcpServersTable.uuid, uuid));
  return row;
}

/** The refusal an update produced, or a failure if it was accepted. */
async function refusalOf(run: () => Promise<unknown>): Promise<string> {
  try {
    await run();
  } catch (error) {
    expect(error).toBeInstanceOf(plan.ServerCredentialRetentionError);
    return (error as Error).message;
  }
  throw new Error("expected the update to be refused");
}

/** Resolve once some backend is waiting on a row lock in this database. */
async function untilSomeoneWaitsOnALock() {
  const deadline = Date.now() + 10_000;
  while (Date.now() < deadline) {
    const result = await pool.query(
      `SELECT count(*)::int AS waiting FROM pg_stat_activity
         WHERE datname = current_database() AND wait_event_type = 'Lock'`,
    );
    if (result.rows[0].waiting > 0) return;
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  throw new Error("no backend started waiting on the row lock");
}

describeIfDb("server update and stored credentials (Postgres)", () => {
  it("a same-URL save with a blank bearer keeps the stored token and headers", async () => {
    const seeded = await seed();
    const result = await repo.updateReportingChange({
      uuid: seeded.uuid,
      name: "vendor",
      type: "STREAMABLE_HTTP",
      url: OLD_URL,
      bearerToken: "",
      description: "Vendor tools, renamed",
    });
    const after = await read(seeded.uuid);
    expect(after.bearerToken).toBe(seeded.bearerToken);
    expect(after.headers).toEqual(STORED_HEADERS);
    expect(after.description).toBe("Vendor tools, renamed");
    expect(result?.destinationOrCredentialChanged).toBe(false);
  });

  it("a URL change with no decision is refused and the whole row is unchanged", async () => {
    const seeded = await seed();
    const before = await read(seeded.uuid);
    const message = await refusalOf(() =>
      repo.updateReportingChange({
        uuid: seeded.uuid,
        name: "vendor-renamed",
        description: "should not be written",
        type: "STREAMABLE_HTTP",
        url: NEW_URL,
        bearerToken: "",
        headers: {},
      }),
    );
    expect(message).toBe(plan.URL_CHANGE_NEEDS_BEARER_DECISION);
    expect(await read(seeded.uuid)).toEqual(before);
  });

  it("a URL change that omits stored headers is refused and the row is unchanged", async () => {
    const seeded = await seed();
    const before = await read(seeded.uuid);
    expect(
      await refusalOf(() =>
        repo.update({
          uuid: seeded.uuid,
          url: NEW_URL,
          bearerToken: "bearer-for-the-new-address",
        }),
      ),
    ).toBe(plan.URL_CHANGE_NEEDS_HEADERS_DECISION);
    expect(await read(seeded.uuid)).toEqual(before);
  });

  it("a URL change with a replacement bearer is written, encrypted", async () => {
    const seeded = await seed();
    const result = await repo.updateReportingChange({
      uuid: seeded.uuid,
      url: NEW_URL,
      bearerToken: "bearer-for-the-new-address",
      headers: {},
    });
    const after = await read(seeded.uuid);
    expect(after.url).toBe(NEW_URL);
    expect(after.bearerToken?.startsWith(crypto.BEARER_ENVELOPE_PREFIX)).toBe(
      true,
    );
    expect(crypto.resolveServerBearerToken(after.bearerToken)).toBe(
      "bearer-for-the-new-address",
    );
    expect(after.headers).toEqual({});
    expect(result?.destinationOrCredentialChanged).toBe(true);
  });

  it("a URL change with clearBearerToken removes the bearer", async () => {
    const seeded = await seed();
    await repo.update({
      uuid: seeded.uuid,
      url: NEW_URL,
      clearBearerToken: true,
      headers: STORED_HEADERS,
    });
    const after = await read(seeded.uuid);
    expect(after.url).toBe(NEW_URL);
    expect(after.bearerToken).toBeNull();
    expect(after.headers).toEqual(STORED_HEADERS);
  });

  it("an editor still holding the old URL is judged against the committed one", async () => {
    const seeded = await seed();

    // Connection 1: the first update, holding the row while it moves the
    // server and sets a token for the new address.
    const first = await pool.connect();
    try {
      await first.query("BEGIN");
      await first.query(
        "SELECT uuid FROM mcp_servers WHERE uuid = $1 FOR UPDATE",
        [seeded.uuid],
      );
      await first.query(
        "UPDATE mcp_servers SET url = $2, bearer_token = $3 WHERE uuid = $1",
        [
          seeded.uuid,
          NEW_URL,
          crypto.encryptServerBearerToken("bearer-for-the-new-address"),
        ],
      );

      // Connection 2 (the repository's own pool connection): an editor whose
      // form still shows the old URL re-saves it with a blank bearer. It has
      // to wait for the row.
      const second = repo
        .updateReportingChange({
          uuid: seeded.uuid,
          name: "vendor",
          type: "STREAMABLE_HTTP",
          url: OLD_URL,
          bearerToken: "",
          headers: STORED_HEADERS,
        })
        .then(
          () => "accepted",
          (error: unknown) =>
            error instanceof plan.ServerCredentialRetentionError
              ? error.message
              : `failed: ${String(error)}`,
        );
      await untilSomeoneWaitsOnALock();
      await first.query("COMMIT");

      // Judged against NEW_URL, the re-save is a URL change back to OLD_URL
      // that neither replaces nor clears the new token: refused.
      expect(await second).toBe(plan.URL_CHANGE_NEEDS_BEARER_DECISION);
    } finally {
      first.release();
    }

    const after = await read(seeded.uuid);
    expect(after.url).toBe(NEW_URL);
    expect(crypto.resolveServerBearerToken(after.bearerToken)).toBe(
      "bearer-for-the-new-address",
    );
  });

  it("the change report: a credential replacement on the same URL counts, a description edit does not", async () => {
    const seeded = await seed();
    expect(
      (
        await repo.updateReportingChange({
          uuid: seeded.uuid,
          description: "edited",
        })
      )?.destinationOrCredentialChanged,
    ).toBe(false);
    expect(
      (
        await repo.updateReportingChange({
          uuid: seeded.uuid,
          bearerToken: "rotated-bearer",
        })
      )?.destinationOrCredentialChanged,
    ).toBe(true);
    expect(
      (
        await repo.updateReportingChange({
          uuid: seeded.uuid,
          headers: { "x-api-key": "rotated-header" },
        })
      )?.destinationOrCredentialChanged,
    ).toBe(true);
    expect(
      (
        await repo.updateReportingChange({
          uuid: seeded.uuid,
          headers: { "x-api-key": "rotated-header" },
        })
      )?.destinationOrCredentialChanged,
    ).toBe(false);
  });

  it("an unknown server answers undefined and writes nothing", async () => {
    expect(
      await repo.updateReportingChange({
        uuid: "99999999-9999-4999-8999-999999999999",
        url: NEW_URL,
      }),
    ).toBeUndefined();
  });
});
