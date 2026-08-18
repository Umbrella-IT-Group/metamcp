/**
 * REAL-POSTGRES integration test for the access-group grant model (0033).
 *
 * Why this file exists: the three properties this feature leans on are all
 * properties of the DATABASE, and none of them can be proved by a mock.
 *
 *   1. The GRANT QUERY. `hasEndpointGrant` is a two-table join that the
 *      middleware turns straight into "serve or refuse". A mock returns
 *      whatever the test author imagined; only a real driver proves the join
 *      predicate is the one that was meant, and that a user granted through one
 *      group is not accidentally granted through every group.
 *   2. The CASCADES. Deleting a group, a user, or an endpoint must take its
 *      grants with it. A dangling grant is the failure mode where "the account
 *      was deleted" and "the account still has access" are both true, and the
 *      only thing that enforces it is the four ON DELETE CASCADE clauses in the
 *      migration — not any line of TypeScript.
 *   3. The COMPOSITE PRIMARY KEYS, which is what makes `onConflictDoNothing`
 *      an idempotent add rather than a second row silently granting the same
 *      access twice.
 *
 * GATING: opt-in via TEST_DATABASE_URL, and deliberately NOT via DATABASE_URL —
 * this suite TRUNCATEs. See the note at the top of
 * `access-queries.integration.test.ts` for the full reasoning.
 *
 *   docker run -d --name metamcp-agroups-test -e POSTGRES_PASSWORD=test \
 *     -e POSTGRES_USER=test -e POSTGRES_DB=metamcp_test \
 *     -p 127.0.0.1:55541:5432 postgres:16-alpine
 *   cd apps/backend
 *   DATABASE_URL=postgres://test:test@127.0.0.1:55541/metamcp_test \
 *     npx drizzle-kit migrate
 *   TEST_DATABASE_URL=postgres://test:test@127.0.0.1:55541/metamcp_test \
 *     npx vitest run src/db/repositories/access-groups.integration.test.ts
 */

import { eq } from "drizzle-orm";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

import { INTEGRATION_DB_LOCK_KEY } from "./integration-db-lock";

const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL;

// `describe.skipIf` rather than a silent early return: a skipped suite is
// visible in the vitest output, so "the integration test didn't run" can never
// be mistaken for "the integration test passed".
const describeIfDb = describe.skipIf(!TEST_DATABASE_URL);

const ADMIN_ID = "agroups-admin";
const MEMBER_ID = "agroups-member";
const STRANGER_ID = "agroups-stranger";

const NAMESPACE_UUID = "10000000-0000-4000-8000-000000000001";
const ENDPOINT_A = "20000000-0000-4000-8000-00000000000a";
const ENDPOINT_B = "20000000-0000-4000-8000-00000000000b";

type Db = Awaited<typeof import("../index")>["db"];
type Schema = typeof import("../schema");

let db: Db;
let schema: Schema;
let repo: (typeof import("./access-groups.repo"))["accessGroupsRepository"];

beforeAll(async () => {
  if (!TEST_DATABASE_URL) return;

  // db/index reads DATABASE_URL at import time, so it has to be set BEFORE the
  // first dynamic import below.
  process.env.DATABASE_URL = TEST_DATABASE_URL;

  ({ db } = await import("../index"));
  schema = await import("../schema");
  ({ accessGroupsRepository: repo } = await import("./access-groups.repo"));

  // Serialize against every other TEST_DATABASE_URL suite before touching a
  // shared table — vitest runs test FILES in parallel workers and this one
  // TRUNCATEs. Same advisory lock key as the other integration suites.
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
  const { pool } = await import("../index");
  await pool.end();
});

async function truncate() {
  // CASCADE in one statement: the FK graph makes any per-table delete order
  // fragile, and `access_groups` is reached from two directions.
  await db.execute(
    `TRUNCATE TABLE users, endpoints, namespaces, access_groups RESTART IDENTITY CASCADE` as never,
  );
}

async function seed() {
  await truncate();

  await db.insert(schema.usersTable).values([
    {
      id: ADMIN_ID,
      name: "Groups Admin",
      email: "agroups-admin@example.invalid",
      role: "admin",
    },
    {
      id: MEMBER_ID,
      name: "Groups Member",
      email: "agroups-member@example.invalid",
      role: "member",
    },
    {
      id: STRANGER_ID,
      name: "Groups Stranger",
      email: "agroups-stranger@example.invalid",
      role: "member",
    },
  ]);

  await db
    .insert(schema.namespacesTable)
    .values({ uuid: NAMESPACE_UUID, name: "agroups-ns", user_id: null });

  await db.insert(schema.endpointsTable).values([
    {
      uuid: ENDPOINT_A,
      name: "agroups-alpha",
      namespace_uuid: NAMESPACE_UUID,
      user_id: null,
    },
    {
      uuid: ENDPOINT_B,
      name: "agroups-beta",
      namespace_uuid: NAMESPACE_UUID,
      user_id: null,
    },
  ]);
}

describeIfDb("migration 0033 shape", () => {
  beforeEach(seed);

  it("endpoints.restricted lands NOT NULL DEFAULT false, so an existing row is untouched", async () => {
    // The inserts above never mention `restricted`. If the column had shipped
    // nullable, or with any other default, this feature would not be inert at
    // cutover — which is the requirement it had to meet.
    const rows = await db
      .select({
        uuid: schema.endpointsTable.uuid,
        restricted: schema.endpointsTable.restricted,
      })
      .from(schema.endpointsTable);

    expect(rows).toHaveLength(2);
    expect(rows.every((r) => r.restricted === false)).toBe(true);
  });

  it("group names are globally unique", async () => {
    await repo.create({ name: "helpdesk" });
    await expect(repo.create({ name: "helpdesk" })).rejects.toThrow();
  });
});

describeIfDb(
  "hasEndpointGrant — the query the middleware turns into an answer",
  () => {
    beforeEach(seed);

    it("false for everyone when no group exists", async () => {
      await expect(repo.hasEndpointGrant(MEMBER_ID, ENDPOINT_A)).resolves.toBe(
        false,
      );
      await expect(repo.hasEndpointGrant(ADMIN_ID, ENDPOINT_A)).resolves.toBe(
        false,
      );
    });

    it("true only for a member of a group mapped to THAT endpoint", async () => {
      const group = await repo.create({ name: "helpdesk" });
      await repo.addMember(group.uuid, MEMBER_ID);
      await repo.addEndpoint(group.uuid, ENDPOINT_A);

      await expect(repo.hasEndpointGrant(MEMBER_ID, ENDPOINT_A)).resolves.toBe(
        true,
      );
      // Same user, different endpoint — the join must not leak across the
      // mapping table.
      await expect(repo.hasEndpointGrant(MEMBER_ID, ENDPOINT_B)).resolves.toBe(
        false,
      );
      // Same endpoint, different user.
      await expect(
        repo.hasEndpointGrant(STRANGER_ID, ENDPOINT_A),
      ).resolves.toBe(false);
    });

    it("a member of group X is NOT granted group Y's endpoint", async () => {
      // The cross-product bug this join could have: matching any member row
      // against any endpoint row rather than pairing them through group_uuid.
      const x = await repo.create({ name: "group-x" });
      const y = await repo.create({ name: "group-y" });
      await repo.addMember(x.uuid, MEMBER_ID);
      await repo.addEndpoint(x.uuid, ENDPOINT_A);
      await repo.addMember(y.uuid, STRANGER_ID);
      await repo.addEndpoint(y.uuid, ENDPOINT_B);

      await expect(repo.hasEndpointGrant(MEMBER_ID, ENDPOINT_B)).resolves.toBe(
        false,
      );
      await expect(
        repo.hasEndpointGrant(STRANGER_ID, ENDPOINT_A),
      ).resolves.toBe(false);
    });

    it("stays true while ANY one of several groups still grants it", async () => {
      const x = await repo.create({ name: "group-x" });
      const y = await repo.create({ name: "group-y" });
      for (const g of [x, y]) {
        await repo.addMember(g.uuid, MEMBER_ID);
        await repo.addEndpoint(g.uuid, ENDPOINT_A);
      }

      await repo.removeMember(x.uuid, MEMBER_ID);

      // Removal from one group is not revocation while a second still grants it.
      await expect(repo.hasEndpointGrant(MEMBER_ID, ENDPOINT_A)).resolves.toBe(
        true,
      );

      await repo.removeMember(y.uuid, MEMBER_ID);
      await expect(repo.hasEndpointGrant(MEMBER_ID, ENDPOINT_A)).resolves.toBe(
        false,
      );
    });
  },
);

describeIfDb("idempotent adds", () => {
  beforeEach(seed);

  it("adding the same member twice inserts once and reports the repeat", async () => {
    const group = await repo.create({ name: "helpdesk" });

    await expect(repo.addMember(group.uuid, MEMBER_ID)).resolves.toBe(true);
    await expect(repo.addMember(group.uuid, MEMBER_ID)).resolves.toBe(false);

    const detail = await repo.findDetailByUuid(group.uuid);
    expect(detail?.members).toHaveLength(1);
  });

  it("mapping the same endpoint twice maps once", async () => {
    const group = await repo.create({ name: "helpdesk" });

    await expect(repo.addEndpoint(group.uuid, ENDPOINT_A)).resolves.toBe(true);
    await expect(repo.addEndpoint(group.uuid, ENDPOINT_A)).resolves.toBe(false);

    const detail = await repo.findDetailByUuid(group.uuid);
    expect(detail?.endpoints).toHaveLength(1);
  });
});

describeIfDb("cascades — no grant may outlive what it points at", () => {
  beforeEach(seed);

  it("deleting the GROUP revokes its grants", async () => {
    const group = await repo.create({ name: "helpdesk" });
    await repo.addMember(group.uuid, MEMBER_ID);
    await repo.addEndpoint(group.uuid, ENDPOINT_A);
    expect(await repo.hasEndpointGrant(MEMBER_ID, ENDPOINT_A)).toBe(true);

    await repo.deleteByUuid(group.uuid);

    await expect(repo.hasEndpointGrant(MEMBER_ID, ENDPOINT_A)).resolves.toBe(
      false,
    );
  });

  it("deleting the USER revokes their membership", async () => {
    const group = await repo.create({ name: "helpdesk" });
    await repo.addMember(group.uuid, MEMBER_ID);
    await repo.addEndpoint(group.uuid, ENDPOINT_A);

    await db.execute(`DELETE FROM users WHERE id = '${MEMBER_ID}'` as never);

    await expect(repo.hasEndpointGrant(MEMBER_ID, ENDPOINT_A)).resolves.toBe(
      false,
    );
    // The group itself survives — deleting a person must not delete the team.
    expect(await repo.findByUuid(group.uuid)).toBeDefined();
  });

  it("deleting the ENDPOINT drops its mappings, so recreating the name grants nothing", async () => {
    const group = await repo.create({ name: "helpdesk" });
    await repo.addMember(group.uuid, MEMBER_ID);
    await repo.addEndpoint(group.uuid, ENDPOINT_A);

    await db.execute(
      `DELETE FROM endpoints WHERE uuid = '${ENDPOINT_A}'` as never,
    );

    const detail = await repo.findDetailByUuid(group.uuid);
    expect(detail?.endpoints).toHaveLength(0);
  });
});

describeIfDb("read shapes the admin UI depends on", () => {
  beforeEach(seed);

  it("listWithCounts decodes counts as NUMBERS, not driver strings", async () => {
    // The failure this pins: a raw `count(*)` in a drizzle projection comes
    // back as a STRING from node-postgres, and the router's `.output()` schema
    // then rejects the whole response with `invalid_type: expected number`.
    // Nothing in the type system catches it — see the note at the top of
    // access-queries.integration.test.ts.
    const group = await repo.create({ name: "helpdesk" });
    await repo.addMember(group.uuid, MEMBER_ID);
    await repo.addMember(group.uuid, ADMIN_ID);
    await repo.addEndpoint(group.uuid, ENDPOINT_A);

    const [row] = await repo.listWithCounts();

    expect(typeof row.member_count).toBe("number");
    expect(typeof row.endpoint_count).toBe("number");
    expect(row.member_count).toBe(2);
    expect(row.endpoint_count).toBe(1);
    expect(row.created_at).toBeInstanceOf(Date);
  });

  it("a group with nothing in it counts zero rather than going missing", async () => {
    await repo.create({ name: "empty" });

    const [row] = await repo.listWithCounts();

    expect(row.name).toBe("empty");
    expect(row.member_count).toBe(0);
    expect(row.endpoint_count).toBe(0);
  });

  it("findDetailByUuid carries the auth toggles the badge reads", async () => {
    // `restricted` alone cannot say whether a mapping does anything: the gate
    // is OAuth-only, so it is inert with `enable_oauth` off and partial when
    // API keys are also accepted. These two columns are what let the group
    // screen distinguish those states instead of labelling all three
    // "Enforcing".
    await db.execute(
      `UPDATE endpoints SET restricted = true, enable_oauth = false, enable_api_key_auth = true WHERE uuid = '${ENDPOINT_A}'` as never,
    );
    const group = await repo.create({ name: "helpdesk" });
    await repo.addEndpoint(group.uuid, ENDPOINT_A);

    const detail = await repo.findDetailByUuid(group.uuid);

    expect(detail?.endpoints).toEqual([
      {
        endpoint_uuid: ENDPOINT_A,
        name: "agroups-alpha",
        restricted: true,
        enable_oauth: false,
        enable_api_key_auth: true,
      },
    ]);
  });

  it("findGroupsForEndpoint returns the groups that gate one endpoint", async () => {
    const gating = await repo.create({ name: "gating" });
    const elsewhere = await repo.create({ name: "elsewhere" });
    await repo.addMember(gating.uuid, MEMBER_ID);
    await repo.addEndpoint(gating.uuid, ENDPOINT_A);
    await repo.addEndpoint(elsewhere.uuid, ENDPOINT_B);

    const groups = await repo.findGroupsForEndpoint(ENDPOINT_A);

    expect(groups).toEqual([
      { uuid: gating.uuid, name: "gating", member_count: 1 },
    ]);
  });

  it("setEndpointRestricted flips the gate and reports the new state", async () => {
    const updated = await repo.setEndpointRestricted(ENDPOINT_A, true);
    expect(updated?.restricted).toBe(true);

    const [row] = await db
      .select({ restricted: schema.endpointsTable.restricted })
      .from(schema.endpointsTable)
      .where(eq(schema.endpointsTable.uuid, ENDPOINT_A));
    expect(row.restricted).toBe(true);

    // And the sibling endpoint was not swept along with it.
    const untouched = await db
      .select({
        uuid: schema.endpointsTable.uuid,
        restricted: schema.endpointsTable.restricted,
      })
      .from(schema.endpointsTable);
    expect(untouched.find((r) => r.uuid === ENDPOINT_B)?.restricted).toBe(
      false,
    );
  });

  it("setEndpointRestricted on an unknown endpoint returns undefined", async () => {
    await expect(
      repo.setEndpointRestricted("30000000-0000-4000-8000-000000000099", true),
    ).resolves.toBeUndefined();
  });
});
