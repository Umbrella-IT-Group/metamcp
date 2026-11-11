/**
 * REAL-POSTGRES integration test for the self-registration retention sweep,
 * `oauthRepository.pruneUnapprovedDcrClients` (migration 0042).
 *
 * WHY THIS FILE EXISTS. The sweep is the only DELETE in this codebase that
 * runs unattended, on a timer, against rows a customer integration depends on.
 * Its entire correctness is in one WHERE clause (provenance, status and two
 * cutoffs), and the unit suite (../../routers/oauth/client-retention.test.ts)
 * replaces the repository with `vi.fn()`: it pins the window resolution and
 * the never-throws contract, but cannot tell you whether the statement
 * deletes the right rows. Reversing a cutoff, dropping the provenance check
 * or matching approved rows would all leave it green.
 *
 * What is asserted here is one table of cases against one real statement:
 * which rows survive a sweep, and which do not. The rule since migration 0042:
 * delete self-registrations still PENDING past the window (by created_at) and
 * self-registrations REJECTED more than a day ago (by rejected_at); never an
 * approved row, an admin-created row or a row with NULL provenance.
 *
 * GATING: opt-in via TEST_DATABASE_URL, and deliberately NOT via DATABASE_URL,
 * for the reason spelled out at the top of ./access-queries.integration.test.ts
 * — this suite deletes rows, and pointing it at a database has to be an
 * explicit act rather than a side effect of having a connection string
 * exported. Same setup:
 *
 *   docker run -d --name metamcp-access-test -e POSTGRES_PASSWORD=test \
 *     -e POSTGRES_USER=test -e POSTGRES_DB=metamcp_test \
 *     -p 127.0.0.1:55432:5432 postgres:16-alpine
 *   cd apps/backend
 *   DATABASE_URL=postgres://test:test@127.0.0.1:55432/metamcp_test \
 *     npx drizzle-kit migrate
 *   TEST_DATABASE_URL=postgres://test:test@127.0.0.1:55432/metamcp_test \
 *     npx vitest run src/db/repositories/client-retention.integration.test.ts
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { INTEGRATION_DB_LOCK_KEY } from "./integration-db-lock";

const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL;

// `describe.skipIf` rather than a silent early return: a skipped suite is
// visible in the vitest output, so "the integration test didn't run" can never
// be mistaken for "the integration test passed".
const describeIfDb = describe.skipIf(!TEST_DATABASE_URL);

const HOUR = 60 * 60 * 1000;
const DAY = 24 * HOUR;
const NOW = new Date();
const past = (ms: number) => new Date(NOW.getTime() - ms);
const future = (ms: number) => new Date(NOW.getTime() + ms);

/** The pending window every case below is positioned against. */
const RETENTION_DAYS = 7;
/** The rejected window the production wrapper passes. */
const REJECTED_MS = DAY;

const USER_ID = "retention-itest-user";
const CALLBACK = "http://localhost:53682/callback";

/**
 * One row per rule the WHERE clause enforces, named for what it proves. Each
 * survivor survives for exactly one reason, so a broken predicate can only
 * take down the case that tests it.
 */
const PENDING_OLD = "mcp_client_retention_pending_old";
const PENDING_JUST_OUTSIDE = "mcp_client_retention_pending_just_outside";
const PENDING_JUST_INSIDE = "mcp_client_retention_pending_just_inside";
const REJECTED_OLD = "mcp_client_retention_rejected_old";
const REJECTED_RECENT = "mcp_client_retention_rejected_recent";
const REJECTED_TODAY_REGISTERED_LONG_AGO =
  "mcp_client_retention_rejected_today_old_registration";
const APPROVED_DCR_UNUSED_OLD = "mcp_client_retention_approved_unused";
const APPROVED_DCR_WITH_TOKEN = "mcp_client_retention_approved_with_token";
const ADMIN_OLD = "mcp_client_retention_admin_old";
const ADMIN_PENDING_BY_HAND = "mcp_client_retention_admin_pending";
const LEGACY_NULL_OLD = "mcp_client_retention_legacy_old";
const LEGACY_NULL_PENDING_BY_HAND = "mcp_client_retention_legacy_pending";
const RACE = "mcp_client_retention_race";

const ALL_CLIENT_IDS = [
  PENDING_OLD,
  PENDING_JUST_OUTSIDE,
  PENDING_JUST_INSIDE,
  REJECTED_OLD,
  REJECTED_RECENT,
  REJECTED_TODAY_REGISTERED_LONG_AGO,
  APPROVED_DCR_UNUSED_OLD,
  APPROVED_DCR_WITH_TOKEN,
  ADMIN_OLD,
  ADMIN_PENDING_BY_HAND,
  LEGACY_NULL_OLD,
  LEGACY_NULL_PENDING_BY_HAND,
  RACE,
];

type Db = Awaited<typeof import("../index")>["db"];
type Pool = Awaited<typeof import("../index")>["pool"];
type Schema = typeof import("../schema");

let db: Db;
let pool: Pool;
let schema: Schema;
let oauthRepository: (typeof import("./oauth.repo"))["oauthRepository"];
let inArray: (typeof import("drizzle-orm"))["inArray"];

beforeAll(async () => {
  if (!TEST_DATABASE_URL) return;

  // db/index reads DATABASE_URL at import time, so it has to be set BEFORE the
  // first dynamic import below — hence the lazy module graph.
  process.env.DATABASE_URL = TEST_DATABASE_URL;

  ({ db, pool } = await import("../index"));
  schema = await import("../schema");
  ({ oauthRepository } = await import("./oauth.repo"));
  ({ inArray } = await import("drizzle-orm"));

  // See ./integration-db-lock: other integration suites TRUNCATE the same
  // tables from parallel vitest workers.
  await db.execute(
    `SELECT pg_advisory_lock(${INTEGRATION_DB_LOCK_KEY})` as never,
  );

  await seed();
});

afterAll(async () => {
  if (!TEST_DATABASE_URL || !db) return;
  await cleanup();
  await db.execute(
    `SELECT pg_advisory_unlock(${INTEGRATION_DB_LOCK_KEY})` as never,
  );
  await pool.end();
});

async function cleanup() {
  // Scoped deletes rather than a TRUNCATE. The client rows cascade to their
  // own codes and tokens, and the user row is this file's own.
  await db
    .delete(schema.oauthClientsTable)
    .where(inArray(schema.oauthClientsTable.client_id, ALL_CLIENT_IDS));
  await db
    .delete(schema.usersTable)
    .where(inArray(schema.usersTable.id, [USER_ID]));
}

type ClientSeed = {
  client_id: string;
  source: "dcr" | "admin" | null;
  status: "approved" | "pending" | "rejected";
  created: Date;
  rejected?: Date;
};

function clientRow(seed: ClientSeed) {
  return {
    client_id: seed.client_id,
    client_name: seed.client_id,
    redirect_uris: [CALLBACK],
    registration_source: seed.source,
    approval_status: seed.status,
    rejected_at: seed.status === "rejected" ? (seed.rejected ?? null) : null,
    created_at: seed.created,
  };
}

async function seed() {
  await cleanup();

  // Access tokens carry a NOT NULL user_id FK.
  await db.insert(schema.usersTable).values({
    id: USER_ID,
    name: "Retention Integration User",
    email: "retention-itest@example.invalid",
    emailVerified: true,
    role: "member",
    createdAt: past(30 * DAY),
    updatedAt: past(30 * DAY),
  });

  const seeds: ClientSeed[] = [
    // The row the sweep exists for: self-registered, never approved, old.
    {
      client_id: PENDING_OLD,
      source: "dcr",
      status: "pending",
      created: past(30 * DAY),
    },
    // Either side of the pending cutoff, so the comparison's direction and
    // its unit (days) are both pinned.
    {
      client_id: PENDING_JUST_OUTSIDE,
      source: "dcr",
      status: "pending",
      created: past(7 * DAY + HOUR),
    },
    {
      client_id: PENDING_JUST_INSIDE,
      source: "dcr",
      status: "pending",
      created: past(7 * DAY - HOUR),
    },
    // Rejected two days ago: past the one-day window.
    {
      client_id: REJECTED_OLD,
      source: "dcr",
      status: "rejected",
      created: past(3 * DAY),
      rejected: past(2 * DAY),
    },
    // Rejected an hour ago: still visible to administrators.
    {
      client_id: REJECTED_RECENT,
      source: "dcr",
      status: "rejected",
      created: past(2 * HOUR),
      rejected: past(HOUR),
    },
    // Registered long ago, rejected an hour ago. Counting from created_at
    // would delete it at once; the window starts at the rejection.
    {
      client_id: REJECTED_TODAY_REGISTERED_LONG_AGO,
      source: "dcr",
      status: "rejected",
      created: past(30 * DAY),
      rejected: past(HOUR),
    },
    // Approved and never used: the previous rule ("no code or token rows")
    // would have deleted this. Approval protects it however old it is.
    {
      client_id: APPROVED_DCR_UNUSED_OLD,
      source: "dcr",
      status: "approved",
      created: past(30 * DAY),
    },
    {
      client_id: APPROVED_DCR_WITH_TOKEN,
      source: "dcr",
      status: "approved",
      created: past(30 * DAY),
    },
    // Admin-created and legacy rows are never swept, whatever their status
    // says (a pending one could only have been written by hand).
    {
      client_id: ADMIN_OLD,
      source: "admin",
      status: "approved",
      created: past(30 * DAY),
    },
    {
      client_id: ADMIN_PENDING_BY_HAND,
      source: "admin",
      status: "pending",
      created: past(30 * DAY),
    },
    {
      client_id: LEGACY_NULL_OLD,
      source: null,
      status: "approved",
      created: past(30 * DAY),
    },
    {
      client_id: LEGACY_NULL_PENDING_BY_HAND,
      source: null,
      status: "pending",
      created: past(30 * DAY),
    },
  ];
  await db.insert(schema.oauthClientsTable).values(seeds.map(clientRow));

  await db.insert(schema.oauthAccessTokensTable).values({
    access_token: "retention-itest-access",
    access_token_last4: "cess",
    client_id: APPROVED_DCR_WITH_TOKEN,
    user_id: USER_ID,
    scope: "mcp",
    expires_at: past(2 * DAY),
    refresh_token: "retention-itest-refresh",
    refresh_token_expires_at: future(300 * DAY),
    family_id: "bbbbbbbb-0000-0000-0000-000000000001",
    created_at: past(30 * DAY),
  });
}

async function survivingClientIds(): Promise<string[]> {
  const rows = await db
    .select({ client_id: schema.oauthClientsTable.client_id })
    .from(schema.oauthClientsTable)
    .where(inArray(schema.oauthClientsTable.client_id, ALL_CLIENT_IDS));
  return rows.map((row) => row.client_id).sort();
}

describeIfDb("pruneUnapprovedDcrClients against real postgres", () => {
  // One sweep, then assertions about its result. Running it per-test would
  // make every case after the first operate on an already-swept table, which
  // is a different question than the one being asked.
  let removed: number;
  let survivors: string[];

  beforeAll(async () => {
    removed = await oauthRepository.pruneUnapprovedDcrClients(
      RETENTION_DAYS,
      REJECTED_MS,
    );
    survivors = await survivingClientIds();
  });

  it("deletes a pending self-registration past the window", () => {
    expect(survivors).not.toContain(PENDING_OLD);
    expect(survivors).not.toContain(PENDING_JUST_OUTSIDE);
  });

  it("keeps a pending self-registration inside the window", () => {
    expect(survivors).toContain(PENDING_JUST_INSIDE);
  });

  it("deletes a self-registration rejected more than a day ago", () => {
    expect(survivors).not.toContain(REJECTED_OLD);
  });

  it("keeps a recent rejection, counting from rejection rather than registration", () => {
    expect(survivors).toContain(REJECTED_RECENT);
    expect(survivors).toContain(REJECTED_TODAY_REGISTERED_LONG_AGO);
  });

  it("keeps approved self-registrations, used or not", () => {
    expect(survivors).toContain(APPROVED_DCR_UNUSED_OLD);
    expect(survivors).toContain(APPROVED_DCR_WITH_TOKEN);
  });

  it("keeps admin-created and NULL-provenance rows whatever their status", () => {
    expect(survivors).toContain(ADMIN_OLD);
    expect(survivors).toContain(ADMIN_PENDING_BY_HAND);
    expect(survivors).toContain(LEGACY_NULL_OLD);
    expect(survivors).toContain(LEGACY_NULL_PENDING_BY_HAND);
  });

  it("removes exactly the three expected rows and reports that count", () => {
    // Scoped to this fixture's ids, so an unrelated row left in a developer's
    // database cannot make it flap.
    expect(survivors).toEqual(
      [
        PENDING_JUST_INSIDE,
        REJECTED_RECENT,
        REJECTED_TODAY_REGISTERED_LONG_AGO,
        APPROVED_DCR_UNUSED_OLD,
        APPROVED_DCR_WITH_TOKEN,
        ADMIN_OLD,
        ADMIN_PENDING_BY_HAND,
        LEGACY_NULL_OLD,
        LEGACY_NULL_PENDING_BY_HAND,
      ].sort(),
    );
    expect(removed).toBe(3);
  });

  it("is a no-op on a second run", () => {
    // Idempotence matters because this runs every five minutes forever.
    return expect(
      oauthRepository.pruneUnapprovedDcrClients(RETENTION_DAYS, REJECTED_MS),
    ).resolves.toBe(0);
  });

  it("deletes nothing when the window is disabled", async () => {
    // `<= 0` is the documented off switch for the whole sweep. It must not be
    // read as "cutoff is now", which would delete every pending client.
    await expect(
      oauthRepository.pruneUnapprovedDcrClients(0, REJECTED_MS),
    ).resolves.toBe(0);
    await expect(
      oauthRepository.pruneUnapprovedDcrClients(-1, REJECTED_MS),
    ).resolves.toBe(0);
    expect(await survivingClientIds()).toHaveLength(9);
  });

  it("does not delete a row an administrator approves while the sweep runs", async () => {
    // A pending row past the window, approved by a transaction that holds the
    // row lock while the sweep's DELETE is already waiting for it. The DELETE
    // re-checks its WHERE clause on the committed (approved) row and skips it,
    // which is why the status predicates live in the DELETE itself.
    await db.insert(schema.oauthClientsTable).values(
      clientRow({
        client_id: RACE,
        source: "dcr",
        status: "pending",
        created: past(30 * DAY),
      }),
    );

    const approver = await pool.connect();
    try {
      await approver.query("BEGIN");
      await approver.query(
        `UPDATE oauth_clients SET approval_status = 'approved', approved_by = 'race-admin', approved_at = now() WHERE client_id = $1`,
        [RACE],
      );

      const sweep = oauthRepository.pruneUnapprovedDcrClients(
        RETENTION_DAYS,
        REJECTED_MS,
      );

      // Wait until the sweep is actually blocked on the row lock, so the
      // commit below lands while the DELETE is in flight, not before it. Any
      // other session in this database waiting on a row lock is the sweep:
      // the suites share an advisory lock (an `advisory` wait, excluded), and
      // query text is not used because a parameterized statement can show
      // an empty `query` here. Polled through the pool (autocommit), not the
      // approver: pg_stat_activity is snapshotted for the rest of a
      // transaction on first read, so the approver would never see the change.
      let waiting = 0;
      for (let attempt = 0; attempt < 100 && waiting === 0; attempt++) {
        const res = await pool.query(
          `SELECT count(*)::int AS n FROM pg_stat_activity
           WHERE datname = current_database()
             AND pid <> pg_backend_pid()
             AND wait_event_type = 'Lock'
             AND wait_event IN ('transactionid', 'tuple')`,
        );
        waiting = res.rows[0].n;
        if (waiting === 0) await new Promise((r) => setTimeout(r, 20));
      }
      expect(waiting).toBe(1);

      await approver.query("COMMIT");
      await expect(sweep).resolves.toBe(0);
    } finally {
      approver.release();
    }

    expect(await survivingClientIds()).toContain(RACE);
  });
});
