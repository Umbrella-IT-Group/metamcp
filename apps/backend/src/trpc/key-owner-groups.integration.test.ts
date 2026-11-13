/**
 * An operator-scope admin-plane key managing access groups, and the access-group
 * owner rule on API keys, on the real /trpc stack and the real data-plane
 * middleware against a REAL Postgres: the real router, bearer resolver,
 * createContext, implementations, repositories, decision cache and audit
 * writer. Only the MCP connection pools are stubbed.
 *
 * What is pinned, and why each needs a database:
 *
 *  - The ten procedures the operator scope gained (nine accessGroups
 *    procedures and namespaces.setToolPolicy) each reach their implementation
 *    with a real bearer, change the real rows, and leave exactly one audit row
 *    that names the KEY and its scope. A sync key, a demoted owner and a
 *    disabled owner reach none of them, and a batch is judged per procedure.
 *  - Each change and its audit row are one transaction: with the audit insert
 *    made to fail at the database, nothing changed (a group delete's cascade
 *    included); with the change itself made to fail, no audit row exists; and
 *    in both cases the decision cache was not dropped, because it drops only
 *    after a commit. Mocks could prove only the mock.
 *  - The owner rule, end to end: groups built through the operator procedures
 *    admit a member's gateway-wide and endpoint-scoped keys and an
 *    administrator's, refuse a non-member's and a public key's, on both
 *    API-key branches, and a membership change takes effect on the next
 *    request. Restricting an endpoint does not turn on the scoped-key
 *    requirement.
 *  - Restricting every endpoint cannot cut an operator key off: its routes are
 *    on /trpc and depend on no MCP endpoint.
 *
 * Opt-in via TEST_DATABASE_URL, pointed at a disposable, migrated database:
 *
 *   cd apps/backend
 *   DATABASE_URL=<url> npx drizzle-kit migrate
 *   TEST_DATABASE_URL=<url> npx vitest run \
 *     src/trpc/key-owner-groups.integration.test.ts
 *
 * Addresses are RFC 5737 documentation ranges, emails use .test, ids and names
 * are synthetic.
 */

import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

import { createFixture, type Fixture } from "./admin-plane-integration-fixture";

const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL;
const describeIfDb = describe.skipIf(!TEST_DATABASE_URL);

const quiet = { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() };
vi.mock("@/utils/logger", () => ({ default: quiet }));
vi.mock("../lib/metamcp/mcp-server-pool", () => ({
  mcpServerPool: {
    ensureIdleSessionForNewServer: vi.fn().mockResolvedValue(undefined),
    cleanupIdleSession: vi.fn().mockResolvedValue(undefined),
    invalidateIdleSession: vi.fn().mockResolvedValue(undefined),
    invalidateServerConnection: vi.fn().mockResolvedValue(undefined),
  },
}));
vi.mock("../lib/metamcp/metamcp-server-pool", () => ({
  metaMcpServerPool: {
    ensureIdleServerForNewNamespace: vi.fn().mockResolvedValue(undefined),
    cleanupIdleServer: vi.fn().mockResolvedValue(undefined),
    invalidateIdleServers: vi.fn().mockResolvedValue(undefined),
    invalidateOpenApiSessions: vi.fn().mockResolvedValue(undefined),
  },
}));

const STANDING_REFUSAL =
  "This procedure is not available to an admin-plane API key.";
const AUDIT_FAILED =
  "The change was not applied because its audit record could not be written.";
const ENDPOINT_REFUSAL =
  "Permission denied, this connector is not available for you. Please reach out to your administrator.";

type Result = { success: boolean; message?: string; data?: unknown };

describeIfDb("operator access-group writes and the key owner rule", () => {
  let fx: Fixture;
  let counter = 0;

  // Public endpoints with API-key auth only, and with OAuth on too (the two
  // API-key branches of the middleware).
  let epKeys = "";
  let epKeysOauth = "";
  let epUnmapped = "";

  const name = (stem: string) => `${stem}-${++counter}`;
  const operator = (
    procedure: string,
    input: unknown,
    kind: "query" | "mutation" = "mutation",
  ) => fx.trpc(`frontend.${procedure}`, input, kind);
  const result = (reply: { data: unknown }) => reply.data as Result;

  async function cacheModule() {
    return await import("../lib/endpoint-access-control");
  }

  // Fault injection at the database. A trigger that raises on a marked
  // statement is a real failure inside the transaction, which is what the
  // atomicity claims are about; the rules live in a table because the app's
  // connection is not the test's.
  const FAULT_TABLES = [
    "access_groups",
    "access_group_members",
    "access_group_endpoints",
    "endpoints",
    "namespaces",
  ];
  async function installDmlFaults() {
    await fx.suiteLock.query(
      `CREATE TABLE IF NOT EXISTS itest_fail_dml_rules (
         tbl text NOT NULL, op text NOT NULL, PRIMARY KEY (tbl, op))`,
    );
    await fx.suiteLock.query(`
      CREATE OR REPLACE FUNCTION itest_fail_dml() RETURNS trigger AS $$
      BEGIN
        IF EXISTS (SELECT 1 FROM itest_fail_dml_rules
                    WHERE tbl = TG_TABLE_NAME AND op = TG_OP) THEN
          RAISE EXCEPTION 'itest: % on % refused', TG_OP, TG_TABLE_NAME;
        END IF;
        IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
        RETURN NEW;
      END $$ LANGUAGE plpgsql`);
    for (const table of FAULT_TABLES) {
      await fx.suiteLock.query(
        `DROP TRIGGER IF EXISTS itest_fail_dml_trg ON ${table}`,
      );
      await fx.suiteLock.query(
        `CREATE TRIGGER itest_fail_dml_trg
           BEFORE INSERT OR UPDATE OR DELETE ON ${table}
           FOR EACH ROW EXECUTE FUNCTION itest_fail_dml()`,
      );
    }
  }
  async function removeDmlFaults() {
    for (const table of FAULT_TABLES) {
      await fx.suiteLock.query(
        `DROP TRIGGER IF EXISTS itest_fail_dml_trg ON ${table}`,
      );
    }
    await fx.suiteLock.query(`DROP TABLE IF EXISTS itest_fail_dml_rules`);
    await fx.suiteLock.query(`DROP FUNCTION IF EXISTS itest_fail_dml()`);
  }
  async function failDml(table: string, op: "INSERT" | "UPDATE" | "DELETE") {
    await fx.suiteLock.query(
      `INSERT INTO itest_fail_dml_rules (tbl, op) VALUES ($1, $2)
         ON CONFLICT DO NOTHING`,
      [table, op],
    );
  }
  async function clearDml() {
    await fx.suiteLock.query(`DELETE FROM itest_fail_dml_rules`);
  }

  const one = async (sql: string, params: unknown[] = []) => {
    const { rows } = await fx.suiteLock.query(sql, params);
    return rows;
  };
  const auditCount = async (action: string, targetId: string) =>
    (
      await one(
        `SELECT count(*)::int AS n FROM audit_log
          WHERE action = $1 AND target_id = $2`,
        [action, targetId],
      )
    )[0].n as number;
  const groupRow = async (uuid: string) =>
    (await one(`SELECT name FROM access_groups WHERE uuid = $1`, [uuid]))[0];
  const memberCount = async (groupUuid: string) =>
    (
      await one(
        `SELECT count(*)::int AS n FROM access_group_members WHERE group_uuid = $1`,
        [groupUuid],
      )
    )[0].n as number;
  const mappingCount = async (groupUuid: string) =>
    (
      await one(
        `SELECT count(*)::int AS n FROM access_group_endpoints WHERE group_uuid = $1`,
        [groupUuid],
      )
    )[0].n as number;
  const endpointFlags = async (uuid: string) =>
    (
      await one(
        `SELECT restricted, require_scoped_api_key FROM endpoints WHERE uuid = $1`,
        [uuid],
      )
    )[0] as { restricted: boolean; require_scoped_api_key: boolean };
  const policyOf = async (uuid: string) =>
    (await one(`SELECT tool_policy FROM namespaces WHERE uuid = $1`, [uuid]))[0]
      .tool_policy as string;

  /** A group made through the operator procedure, with a member and a mapping. */
  // Groups the cases below create through the operator procedure are removed
  // when the suite ends, whether or not the case that made them got that far:
  // a group left mapped to an endpoint would admit its members there and
  // corrupt every later case.
  const madeGroups: string[] = [];
  async function operatorGroup(over: {
    members?: string[];
    endpoints?: string[];
  }) {
    const created = await operator("accessGroups.create", {
      name: `${name("grp")}-${fx.run}`,
    });
    expect(created.status).toBe(200);
    const uuid = (result(created).data as { uuid: string }).uuid;
    madeGroups.push(uuid);
    for (const userId of over.members ?? []) {
      expect(
        result(
          await operator("accessGroups.addMember", {
            group_uuid: uuid,
            user_id: userId,
          }),
        ).success,
      ).toBe(true);
    }
    for (const endpointUuid of over.endpoints ?? []) {
      expect(
        result(
          await operator("accessGroups.addEndpoint", {
            group_uuid: uuid,
            endpoint_uuid: endpointUuid,
          }),
        ).success,
      ).toBe(true);
    }
    return uuid;
  }

  beforeAll(async () => {
    fx = await createFixture(TEST_DATABASE_URL as string, "kog");
    epKeys = await fx.endpoint({ name: "ep-keys" });
    epKeysOauth = await fx.endpoint({ name: "ep-keys-oauth", oauth: true });
    epUnmapped = await fx.endpoint({ name: "ep-unmapped" });
    await installDmlFaults();
  }, 90_000);

  afterAll(async () => {
    await removeDmlFaults();
    for (const uuid of madeGroups) {
      await fx.db
        .delete(fx.schema.accessGroupsTable)
        .where(fx.eq(fx.schema.accessGroupsTable.uuid, uuid));
    }
    await fx?.close();
  });

  // ---------------------------------------------------------------------------
  describe("each of the ten procedures, with a real operator bearer", () => {
    it("creates, renames, populates, maps, restricts and deletes a group, one audit row per change naming the key and its scope", async () => {
      const key = fx.operator;
      const owner = {
        key_uuid: key.uuid,
        owner_user_id: fx.ownerId,
        scope: "operator",
      };
      const groupName = `${name("helpdesk")}-${fx.run}`;

      const created = await operator("accessGroups.create", {
        name: groupName,
        description: "synthetic",
      });
      expect(created.status).toBe(200);
      expect(result(created).success).toBe(true);
      const uuid = (result(created).data as { uuid: string }).uuid;
      expect((await groupRow(uuid)).name).toBe(groupName);

      const renamed = `${groupName}-renamed`;
      expect(
        result(await operator("accessGroups.update", { uuid, name: renamed }))
          .success,
      ).toBe(true);
      expect((await groupRow(uuid)).name).toBe(renamed);

      expect(
        result(
          await operator("accessGroups.addMember", {
            group_uuid: uuid,
            user_id: fx.memberId,
          }),
        ).success,
      ).toBe(true);
      expect(await memberCount(uuid)).toBe(1);

      // The read-back answers for an endpoint with no mapping at all, and shows
      // the switch and both auth toggles, which list and group-detail cannot.
      const unmapped = await operator(
        "accessGroups.getEndpointAccess",
        { endpoint_uuid: epUnmapped },
        "query",
      );
      expect(unmapped.status).toBe(200);
      expect(result(unmapped).data).toMatchObject({
        endpoint_uuid: epUnmapped,
        restricted: false,
        enable_api_key_auth: true,
        require_scoped_api_key: false,
        groups: [],
      });

      expect(
        result(
          await operator("accessGroups.addEndpoint", {
            group_uuid: uuid,
            endpoint_uuid: epUnmapped,
          }),
        ).success,
      ).toBe(true);
      expect(await mappingCount(uuid)).toBe(1);

      expect(
        result(
          await operator("accessGroups.setEndpointRestricted", {
            endpoint_uuid: epUnmapped,
            restricted: true,
          }),
        ).success,
      ).toBe(true);
      // Restricting did not turn the scoped-key requirement on.
      expect(await endpointFlags(epUnmapped)).toEqual({
        restricted: true,
        require_scoped_api_key: false,
      });
      const readBack = await operator(
        "accessGroups.getEndpointAccess",
        { endpoint_uuid: epUnmapped },
        "query",
      );
      expect(result(readBack).data).toMatchObject({
        restricted: true,
        require_scoped_api_key: false,
        groups: [{ uuid, name: renamed, member_count: 1 }],
      });

      // Turned off again, then the membership, the mapping and the group go.
      expect(
        result(
          await operator("accessGroups.setEndpointRestricted", {
            endpoint_uuid: epUnmapped,
            restricted: false,
          }),
        ).success,
      ).toBe(true);
      expect(
        result(
          await operator("accessGroups.removeMember", {
            group_uuid: uuid,
            user_id: fx.memberId,
          }),
        ).success,
      ).toBe(true);
      expect(
        result(
          await operator("accessGroups.removeEndpoint", {
            group_uuid: uuid,
            endpoint_uuid: epUnmapped,
          }),
        ).success,
      ).toBe(true);
      expect(
        result(await operator("accessGroups.delete", { uuid })).success,
      ).toBe(true);
      expect(await groupRow(uuid)).toBeUndefined();

      // One audit row per change, written in the change's transaction (so
      // visible at once), the KEY as the actor and the owner and scope beside.
      const rows = await fx.auditNow(
        `actor_id = $1 AND action = ANY($2) AND (target_id = $3 OR target_id = $4)
           AND occurred_at >= now() - interval '5 minutes'`,
        [
          key.uuid,
          [
            "group.create",
            "group.update",
            "group.member.add",
            "group.member.remove",
            "group.endpoint.add",
            "group.endpoint.remove",
            "group.delete",
            "endpoint.restricted.set",
          ],
          uuid,
          epUnmapped,
        ],
      );
      const byAction = (action: string) =>
        rows.filter((r) => r.action === action);
      for (const action of [
        "group.create",
        "group.update",
        "group.member.add",
        "group.member.remove",
        "group.endpoint.add",
        "group.endpoint.remove",
        "group.delete",
      ]) {
        expect({ action, n: byAction(action).length }).toEqual({
          action,
          n: 1,
        });
      }
      expect(byAction("endpoint.restricted.set")).toHaveLength(2);
      for (const row of rows) {
        expect(row).toMatchObject({
          actor_type: "api_key",
          outcome: "success",
        });
        expect((row.detail as { admin_plane: unknown }).admin_plane).toEqual(
          owner,
        );
      }
      expect(
        byAction("endpoint.restricted.set").map((r) => ({
          previous: (r.detail as { previous: boolean }).previous,
          restricted: (r.detail as { restricted: boolean }).restricted,
        })),
      ).toEqual([
        { previous: false, restricted: true },
        { previous: true, restricted: false },
      ]);
    });

    it("sets a namespace's tool policy and records the value it replaced under the key", async () => {
      const ns = fx.publicNamespaceUuid;
      expect(await policyOf(ns)).toBe("allow_all");

      const set = await operator("namespaces.setToolPolicy", {
        namespaceUuid: ns,
        toolPolicy: "allowlist",
      });
      expect(set.status).toBe(200);
      expect(result(set).success).toBe(true);
      expect(await policyOf(ns)).toBe("allowlist");

      const rows = await fx.auditNow(
        `action = 'namespace.tool_policy' AND target_id = $1 AND actor_id = $2`,
        [ns, fx.operator.uuid],
      );
      expect(rows).toHaveLength(1);
      expect(rows[0]).toMatchObject({
        actor_type: "api_key",
        outcome: "success",
      });
      expect(rows[0].detail).toMatchObject({
        previous: "allow_all",
        tool_policy: "allowlist",
        admin_plane: {
          key_uuid: fx.operator.uuid,
          owner_user_id: fx.ownerId,
          scope: "operator",
        },
      });

      expect(
        result(
          await operator("namespaces.setToolPolicy", {
            namespaceUuid: ns,
            toolPolicy: "allow_all",
          }),
        ).success,
      ).toBe(true);
      expect(await policyOf(ns)).toBe("allow_all");
    });

    it("keeps the owner's namespace check: a private namespace of another user is refused, with no change and no row", async () => {
      const [privateNs] = await fx.db
        .insert(fx.schema.namespacesTable)
        .values({ name: `kog-private-${fx.run}`, user_id: fx.memberId })
        .returning({ uuid: fx.schema.namespacesTable.uuid });
      try {
        const reply = await operator("namespaces.setToolPolicy", {
          namespaceUuid: privateNs.uuid,
          toolPolicy: "allowlist",
        });
        expect(reply.status).toBe(200);
        expect(result(reply).success).toBe(false);
        expect(result(reply).message).toContain("Access denied");
        expect(await policyOf(privateNs.uuid)).toBe("allow_all");
        expect(await auditCount("namespace.tool_policy", privateNs.uuid)).toBe(
          0,
        );
      } finally {
        await fx.db
          .delete(fx.schema.namespacesTable)
          .where(fx.eq(fx.schema.namespacesTable.uuid, privateNs.uuid));
      }
    });

    it("leaves a human administrator's session as it was: the change commits and a best-effort row names the user", async () => {
      const created = await fx.trpc(
        "frontend.accessGroups.create",
        { name: `${name("human")}-${fx.run}` },
        "mutation",
        { cookie: fx.ownerCookie },
      );
      expect(created.status).toBe(200);
      const uuid = (result(created).data as { uuid: string }).uuid;

      const rows = await fx.auditEventually(
        `action = 'group.create' AND target_id = $1`,
        [uuid],
      );
      expect(rows).toHaveLength(1);
      expect(rows[0]).toMatchObject({
        actor_type: "user",
        actor_id: fx.ownerId,
      });
      expect(
        (rows[0].detail as { admin_plane?: unknown }).admin_plane,
      ).toBeUndefined();
    });
  });

  // ---------------------------------------------------------------------------
  describe("a sync key, a demoted owner, a disabled owner and a mixed batch", () => {
    const TEN: Array<[string, () => unknown, "query" | "mutation"]> = [
      ["accessGroups.create", () => ({ name: "x" }), "mutation"],
      ["accessGroups.update", () => ({ uuid: epKeys, name: "x" }), "mutation"],
      ["accessGroups.delete", () => ({ uuid: epKeys }), "mutation"],
      [
        "accessGroups.addMember",
        () => ({ group_uuid: epKeys, user_id: fx.memberId }),
        "mutation",
      ],
      [
        "accessGroups.removeMember",
        () => ({ group_uuid: epKeys, user_id: fx.memberId }),
        "mutation",
      ],
      [
        "accessGroups.addEndpoint",
        () => ({ group_uuid: epKeys, endpoint_uuid: epKeys }),
        "mutation",
      ],
      [
        "accessGroups.removeEndpoint",
        () => ({ group_uuid: epKeys, endpoint_uuid: epKeys }),
        "mutation",
      ],
      [
        "accessGroups.setEndpointRestricted",
        () => ({ endpoint_uuid: epKeys, restricted: true }),
        "mutation",
      ],
      [
        "accessGroups.getEndpointAccess",
        () => ({ endpoint_uuid: epKeys }),
        "query",
      ],
      [
        "namespaces.setToolPolicy",
        () => ({
          namespaceUuid: fx.publicNamespaceUuid,
          toolPolicy: "allowlist",
        }),
        "mutation",
      ],
    ];

    it.each(TEN)(
      "refuses a sync-scope key %s with the standing sentence, before the implementation",
      async (procedure, input, kind) => {
        const reply = await fx.trpc(`frontend.${procedure}`, input(), kind, {
          key: fx.sync.key,
        });
        expect(reply.status).toBe(403);
        expect(reply.code).toBe("FORBIDDEN");
        expect(reply.message).toBe(STANDING_REFUSAL);
        // Nothing the refused calls could have written exists.
        expect((await endpointFlags(epKeys)).restricted).toBe(false);
        expect(await policyOf(fx.publicNamespaceUuid)).toBe("allow_all");
      },
    );

    it("refuses an operator key whose owner was demoted to a member, and writes nothing", async () => {
      await fx.setRole(fx.ownerId, "member");
      try {
        const before = await one(
          `SELECT count(*)::int AS n FROM access_groups`,
        );
        for (const [procedure, input, kind] of TEN) {
          const reply = await operator(procedure, input(), kind);
          expect({ procedure, code: reply.code }).toEqual({
            procedure,
            code: "FORBIDDEN",
          });
        }
        expect(
          await one(`SELECT count(*)::int AS n FROM access_groups`),
        ).toEqual(before);
        expect((await endpointFlags(epKeys)).restricted).toBe(false);
        expect(await policyOf(fx.publicNamespaceUuid)).toBe("allow_all");
      } finally {
        await fx.setRole(fx.ownerId, "admin");
      }
    });

    it("refuses an operator key whose owner is disabled, and writes nothing", async () => {
      await fx.db
        .update(fx.schema.usersTable)
        .set({ disabled: true })
        .where(fx.eq(fx.schema.usersTable.id, fx.ownerId));
      try {
        for (const [procedure, input, kind] of TEN) {
          const reply = await operator(procedure, input(), kind);
          expect({ procedure, code: reply.code }).toEqual({
            procedure,
            code: "UNAUTHORIZED",
          });
        }
        expect((await endpointFlags(epKeys)).restricted).toBe(false);
      } finally {
        await fx.db
          .update(fx.schema.usersTable)
          .set({ disabled: false })
          .where(fx.eq(fx.schema.usersTable.id, fx.ownerId));
      }
    });

    it("judges a batch per procedure: the group write lands and the user disable beside it is refused, leaving the user enabled", async () => {
      const res = await fetch(
        `${fx.base}/trpc/frontend/frontend.accessGroups.setEndpointRestricted,frontend.users.setDisabled?batch=1`,
        {
          method: "POST",
          headers: {
            "content-type": "application/json",
            authorization: `Bearer ${fx.operator.key}`,
            "cf-connecting-ip": "198.51.100.77",
          },
          body: JSON.stringify({
            "0": { endpoint_uuid: epKeys, restricted: true },
            "1": { user_id: fx.memberId, disabled: true },
          }),
        },
      );
      const body = (await res.json()) as Array<{
        result?: { data?: Result };
        error?: { data?: { code?: string }; message?: string };
      }>;
      expect(body).toHaveLength(2);
      expect(body[0].result?.data?.success).toBe(true);
      expect(body[1].error?.data?.code).toBe("FORBIDDEN");
      expect(body[1].error?.message).toBe(STANDING_REFUSAL);
      expect((await endpointFlags(epKeys)).restricted).toBe(true);
      const [member] = await one(`SELECT disabled FROM users WHERE id = $1`, [
        fx.memberId,
      ]);
      expect(member.disabled).toBe(false);

      // Put the endpoint back for the cases that follow.
      await operator("accessGroups.setEndpointRestricted", {
        endpoint_uuid: epKeys,
        restricted: false,
      });
    });

    it.each([
      ["users.setDisabled", { user_id: "someone", disabled: true }],
      ["users.delete", { user_id: "someone" }],
      ["users.revokeAccess", { user_id: "someone" }],
      ["oauthClients.approve", { client_id: "someone" }],
      ["oauthClients.reject", { client_id: "someone" }],
    ])(
      "keeps %s out of the operator scope: refused with the standing sentence",
      async (procedure, input) => {
        const reply = await operator(procedure, input);
        expect(reply.status).toBe(403);
        expect(reply.message).toBe(STANDING_REFUSAL);
      },
    );
  });

  // ---------------------------------------------------------------------------
  describe("a change and its audit row are one transaction", () => {
    it("rolls back every mutation when its audit row cannot be written, emits nothing twice, and leaves the decision cache alone", async () => {
      const { __endpointAccessCacheSizeForTesting, isUserAllowedOnEndpoint } =
        await cacheModule();
      const prime = async () => {
        // A restricted answer in the cache, to see whether a write drops it.
        await isUserAllowedOnEndpoint(fx.memberId, {
          uuid: epKeys,
          restricted: true,
        });
        expect(__endpointAccessCacheSizeForTesting()).toBeGreaterThan(0);
      };

      // A group with one member and one mapping to act on.
      const target = await operatorGroup({
        members: [fx.memberId],
        endpoints: [epKeys],
      });
      const spare = await fx.group({ name: name("spare") });
      const spareName = (await groupRow(spare)).name as string;

      const cases: Array<{
        action: string;
        targetId: string;
        call: () => Promise<{ data: unknown }>;
        unchanged: () => Promise<void>;
      }> = [
        {
          action: "group.create",
          targetId: "",
          call: () =>
            operator("accessGroups.create", {
              name: `audit-fault-${fx.run}`,
            }),
          unchanged: async () => {
            expect(
              await one(`SELECT 1 FROM access_groups WHERE name = $1`, [
                `audit-fault-${fx.run}`,
              ]),
            ).toHaveLength(0);
          },
        },
        {
          action: "group.update",
          targetId: spare,
          call: () =>
            operator("accessGroups.update", {
              uuid: spare,
              name: `renamed-${fx.run}`,
            }),
          unchanged: async () => {
            expect((await groupRow(spare)).name).toBe(spareName);
          },
        },
        {
          action: "group.member.add",
          targetId: spare,
          call: () =>
            operator("accessGroups.addMember", {
              group_uuid: spare,
              user_id: fx.otherMemberId,
            }),
          unchanged: async () => {
            expect(await memberCount(spare)).toBe(0);
          },
        },
        {
          action: "group.member.remove",
          targetId: target,
          call: () =>
            operator("accessGroups.removeMember", {
              group_uuid: target,
              user_id: fx.memberId,
            }),
          unchanged: async () => {
            expect(await memberCount(target)).toBe(1);
          },
        },
        {
          action: "group.endpoint.add",
          targetId: spare,
          call: () =>
            operator("accessGroups.addEndpoint", {
              group_uuid: spare,
              endpoint_uuid: epKeysOauth,
            }),
          unchanged: async () => {
            expect(await mappingCount(spare)).toBe(0);
          },
        },
        {
          action: "group.endpoint.remove",
          targetId: target,
          call: () =>
            operator("accessGroups.removeEndpoint", {
              group_uuid: target,
              endpoint_uuid: epKeys,
            }),
          unchanged: async () => {
            expect(await mappingCount(target)).toBe(1);
          },
        },
        {
          action: "endpoint.restricted.set",
          targetId: epKeys,
          call: () =>
            operator("accessGroups.setEndpointRestricted", {
              endpoint_uuid: epKeys,
              restricted: true,
            }),
          unchanged: async () => {
            expect((await endpointFlags(epKeys)).restricted).toBe(false);
          },
        },
        {
          // The cascade into the memberships and mappings runs inside the
          // delete, so a failed audit row must bring all three back.
          action: "group.delete",
          targetId: target,
          call: () => operator("accessGroups.delete", { uuid: target }),
          unchanged: async () => {
            expect(await groupRow(target)).toBeDefined();
            expect(await memberCount(target)).toBe(1);
            expect(await mappingCount(target)).toBe(1);
          },
        },
        {
          action: "namespace.tool_policy",
          targetId: fx.publicNamespaceUuid,
          call: () =>
            operator("namespaces.setToolPolicy", {
              namespaceUuid: fx.publicNamespaceUuid,
              toolPolicy: "allowlist",
            }),
          unchanged: async () => {
            expect(await policyOf(fx.publicNamespaceUuid)).toBe("allow_all");
          },
        },
      ];

      for (const c of cases) {
        await fx.failAuditFor(c.action);
        await prime();
        const sizeBefore = __endpointAccessCacheSizeForTesting();
        const rowsBefore = c.targetId
          ? await auditCount(c.action, c.targetId)
          : 0;
        try {
          const reply = await c.call();
          const outcome = reply.data as Result;
          expect({ action: c.action, success: outcome.success }).toEqual({
            action: c.action,
            success: false,
          });
          expect(outcome.message).toBe(AUDIT_FAILED);
          await c.unchanged();
          // Dropped only after a commit, and nothing committed.
          expect(__endpointAccessCacheSizeForTesting()).toBe(sizeBefore);
          if (c.targetId) {
            expect(await auditCount(c.action, c.targetId)).toBe(rowsBefore);
          }
        } finally {
          await fx.clearAuditFault(c.action);
        }
      }

      // With the fault gone each call commits once, writes exactly one row and
      // drops the cache.
      const { __resetEndpointAccessCacheForTesting } = await cacheModule();
      __resetEndpointAccessCacheForTesting();
      await prime();
      const ok = await operator("accessGroups.removeMember", {
        group_uuid: target,
        user_id: fx.memberId,
      });
      expect(result(ok).success).toBe(true);
      expect(__endpointAccessCacheSizeForTesting()).toBe(0);
      expect(await auditCount("group.member.remove", target)).toBe(1);
      await operator("accessGroups.delete", { uuid: target });
    });

    it("writes no audit row and drops no cache entry when the change itself fails, for each write, a group delete's cascade included", async () => {
      const { __endpointAccessCacheSizeForTesting, isUserAllowedOnEndpoint } =
        await cacheModule();
      const target = await operatorGroup({
        members: [fx.memberId],
        endpoints: [epKeys],
      });
      const spare = await fx.group({ name: name("spare") });

      const cases: Array<{
        table: string;
        op: "INSERT" | "UPDATE" | "DELETE";
        action: string;
        targetId: string;
        call: () => Promise<{ data: unknown }>;
      }> = [
        {
          table: "access_groups",
          op: "INSERT",
          action: "group.create",
          targetId: "",
          call: () =>
            operator("accessGroups.create", { name: `write-fault-${fx.run}` }),
        },
        {
          table: "access_groups",
          op: "UPDATE",
          action: "group.update",
          targetId: spare,
          call: () =>
            operator("accessGroups.update", { uuid: spare, name: "nope" }),
        },
        {
          table: "access_group_members",
          op: "INSERT",
          action: "group.member.add",
          targetId: spare,
          call: () =>
            operator("accessGroups.addMember", {
              group_uuid: spare,
              user_id: fx.otherMemberId,
            }),
        },
        {
          table: "access_group_members",
          op: "DELETE",
          action: "group.member.remove",
          targetId: target,
          call: () =>
            operator("accessGroups.removeMember", {
              group_uuid: target,
              user_id: fx.memberId,
            }),
        },
        {
          table: "access_group_endpoints",
          op: "INSERT",
          action: "group.endpoint.add",
          targetId: spare,
          call: () =>
            operator("accessGroups.addEndpoint", {
              group_uuid: spare,
              endpoint_uuid: epKeysOauth,
            }),
        },
        {
          table: "access_group_endpoints",
          op: "DELETE",
          action: "group.endpoint.remove",
          targetId: target,
          call: () =>
            operator("accessGroups.removeEndpoint", {
              group_uuid: target,
              endpoint_uuid: epKeys,
            }),
        },
        {
          table: "endpoints",
          op: "UPDATE",
          action: "endpoint.restricted.set",
          targetId: epKeys,
          call: () =>
            operator("accessGroups.setEndpointRestricted", {
              endpoint_uuid: epKeys,
              restricted: true,
            }),
        },
        {
          // The cascade fails inside the delete: the group goes with nothing.
          table: "access_group_endpoints",
          op: "DELETE",
          action: "group.delete",
          targetId: target,
          call: () => operator("accessGroups.delete", { uuid: target }),
        },
        {
          table: "access_group_members",
          op: "DELETE",
          action: "group.delete",
          targetId: target,
          call: () => operator("accessGroups.delete", { uuid: target }),
        },
        {
          table: "namespaces",
          op: "UPDATE",
          action: "namespace.tool_policy",
          targetId: fx.publicNamespaceUuid,
          call: () =>
            operator("namespaces.setToolPolicy", {
              namespaceUuid: fx.publicNamespaceUuid,
              toolPolicy: "allowlist",
            }),
        },
      ];

      for (const c of cases) {
        await clearDml();
        await failDml(c.table, c.op);
        await isUserAllowedOnEndpoint(fx.memberId, {
          uuid: epKeys,
          restricted: true,
        });
        const sizeBefore = __endpointAccessCacheSizeForTesting();
        expect(sizeBefore).toBeGreaterThan(0);
        const label = `${c.action} (${c.op} on ${c.table})`;
        const rowsBefore = c.targetId
          ? await auditCount(c.action, c.targetId)
          : 0;

        const reply = await c.call();
        expect({ label, success: (reply.data as Result).success }).toEqual({
          label,
          success: false,
        });
        expect(__endpointAccessCacheSizeForTesting()).toBe(sizeBefore);
        if (c.targetId) {
          expect({
            label,
            rows: await auditCount(c.action, c.targetId),
          }).toEqual({ label, rows: rowsBefore });
        }
      }
      await clearDml();

      // The failed deletes left the group, its member and its mapping intact.
      expect(await groupRow(target)).toBeDefined();
      expect(await memberCount(target)).toBe(1);
      expect(await mappingCount(target)).toBe(1);
      expect((await endpointFlags(epKeys)).restricted).toBe(false);
      expect(await policyOf(fx.publicNamespaceUuid)).toBe("allow_all");
      await operator("accessGroups.delete", { uuid: target });
    });

    it("runs the same transaction through a direct implementation call, and keeps the best-effort path for an actor with no admin-plane origin", async () => {
      const { accessGroupsImplementations } = await import(
        "./access-groups.impl"
      );
      const { auditActor } = await import("@repo/trpc");
      const adminPlaneActor = auditActor({
        user: { id: fx.ownerId, email: "owner@example.test" },
        session: { id: "synthetic" },
        authOrigin: {
          kind: "admin_plane",
          key_uuid: fx.operator.uuid,
          owner_user_id: fx.ownerId,
          scope: "operator",
        },
      } as never);
      const humanActor = auditActor({
        user: { id: fx.ownerId, email: "owner@example.test" },
        session: { id: "synthetic" },
      } as never);
      expect(adminPlaneActor.admin_plane?.scope).toBe("operator");
      expect(humanActor.admin_plane).toBeUndefined();

      // An admin-plane actor: the row is in the transaction, so a failing audit
      // insert leaves no group.
      const groupName = `direct-${fx.run}`;
      await fx.failAuditFor("group.create");
      try {
        const failed = await accessGroupsImplementations.create(
          { name: groupName },
          adminPlaneActor,
        );
        expect(failed.success).toBe(false);
        expect(
          await one(`SELECT 1 FROM access_groups WHERE name = $1`, [groupName]),
        ).toHaveLength(0);
      } finally {
        await fx.clearAuditFault("group.create");
      }
      const made = await accessGroupsImplementations.create(
        { name: groupName },
        adminPlaneActor,
      );
      expect(made.success).toBe(true);
      const uuid = (made as { data: { uuid: string } }).data.uuid;
      expect(await auditCount("group.create", uuid)).toBe(1);

      // A human actor: the write commits whatever the audit sink does.
      await fx.failAuditFor("group.update");
      try {
        const renamed = await accessGroupsImplementations.update(
          { uuid, name: `${groupName}-human` },
          humanActor,
        );
        expect(renamed.success).toBe(true);
        expect((await groupRow(uuid)).name).toBe(`${groupName}-human`);
      } finally {
        await fx.clearAuditFault("group.update");
      }
      await accessGroupsImplementations.delete({ uuid }, adminPlaneActor);
    });

    it("refuses a direct setToolPolicy call from an admin-plane actor when the audit row cannot be written", async () => {
      const { namespacesImplementations } = await import("./namespaces.impl");
      const { auditActor } = await import("@repo/trpc");
      const actor = auditActor({
        user: { id: fx.ownerId },
        session: { id: "synthetic" },
        authOrigin: {
          kind: "admin_plane",
          key_uuid: fx.operator.uuid,
          owner_user_id: fx.ownerId,
          scope: "operator",
        },
      } as never);
      await fx.failAuditFor("namespace.tool_policy");
      try {
        const failed = await namespacesImplementations.setToolPolicy(
          {
            namespaceUuid: fx.publicNamespaceUuid,
            toolPolicy: "allowlist",
          },
          fx.ownerId,
          actor,
        );
        expect(failed.success).toBe(false);
        expect(await policyOf(fx.publicNamespaceUuid)).toBe("allow_all");
      } finally {
        await fx.clearAuditFault("namespace.tool_policy");
      }
    });
  });

  // ---------------------------------------------------------------------------
  describe("the owner rule, end to end, on both API-key branches", () => {
    const ENDPOINTS = [
      ["API-key-only (CONDITION 2)", () => epKeys],
      ["OAuth-enabled (CONDITION 3)", () => epKeysOauth],
    ] as const;

    it.each(ENDPOINTS)(
      "on the %s endpoint: groups built by the operator key admit the right keys and refuse the others, and a membership change lands on the next request",
      async (_label, endpointOf) => {
        const endpointUuid = endpointOf();
        const ip = "203.0.113.9";
        const memberGateway = await fx.dataKey({
          name: name("member-gw"),
          ownerId: fx.memberId,
        });
        const memberScoped = await fx.dataKey({
          name: name("member-sc"),
          ownerId: fx.memberId,
          endpointUuid,
        });
        const outsiderGateway = await fx.dataKey({
          name: name("other-gw"),
          ownerId: fx.otherMemberId,
        });
        const outsiderScoped = await fx.dataKey({
          name: name("other-sc"),
          ownerId: fx.otherMemberId,
          endpointUuid,
        });
        const adminGateway = await fx.dataKey({
          name: name("admin-gw"),
          ownerId: fx.ownerId,
        });
        const publicGateway = await fx.dataKey({
          name: name("public-gw"),
          ownerId: null,
        });
        const serves = async (key: { key: string }) =>
          (await fx.authenticateKey({ endpointUuid, token: key.key, ip })).next;
        const status = async (key: { key: string }) =>
          (await fx.authenticateKey({ endpointUuid, token: key.key, ip }))
            .status;

        // Unrestricted: every key passes, the public one included.
        for (const k of [
          memberGateway,
          memberScoped,
          outsiderGateway,
          outsiderScoped,
          adminGateway,
          publicGateway,
        ]) {
          expect(await serves(k)).toBe(true);
        }

        const group = await operatorGroup({
          members: [fx.memberId],
          endpoints: [endpointUuid],
        });
        expect(
          result(
            await operator("accessGroups.setEndpointRestricted", {
              endpoint_uuid: endpointUuid,
              restricted: true,
            }),
          ).success,
        ).toBe(true);
        // Restricting did not require scoped keys, so gateway-wide keys are
        // still accepted here and the owner rule decides.
        expect((await endpointFlags(endpointUuid)).require_scoped_api_key).toBe(
          false,
        );

        expect(await serves(memberGateway)).toBe(true);
        expect(await serves(memberScoped)).toBe(true);
        expect(await serves(adminGateway)).toBe(true);
        for (const k of [outsiderGateway, outsiderScoped, publicGateway]) {
          expect(await status(k)).toBe(403);
          const refused = await fx.authenticateKey({
            endpointUuid,
            token: k.key,
            ip,
          });
          expect((refused.body as { message: string }).message).toBe(
            ENDPOINT_REFUSAL,
          );
        }

        // Removing the member takes effect on the very next request.
        expect(
          result(
            await operator("accessGroups.removeMember", {
              group_uuid: group,
              user_id: fx.memberId,
            }),
          ).success,
        ).toBe(true);
        expect(await status(memberGateway)).toBe(403);
        expect(await status(memberScoped)).toBe(403);
        expect(await serves(adminGateway)).toBe(true);

        // Adding them back, and mapping the outsider's group, takes effect too.
        await operator("accessGroups.addMember", {
          group_uuid: group,
          user_id: fx.memberId,
        });
        expect(await serves(memberGateway)).toBe(true);

        // Unmapping the endpoint locks the member out again; deleting the group
        // does the same through the cascade.
        await operator("accessGroups.removeEndpoint", {
          group_uuid: group,
          endpoint_uuid: endpointUuid,
        });
        expect(await status(memberGateway)).toBe(403);
        await operator("accessGroups.addEndpoint", {
          group_uuid: group,
          endpoint_uuid: endpointUuid,
        });
        expect(await serves(memberGateway)).toBe(true);
        await operator("accessGroups.delete", { uuid: group });
        expect(await status(memberGateway)).toBe(403);

        // Switched off, the endpoint is open to every key again.
        expect(
          result(
            await operator("accessGroups.setEndpointRestricted", {
              endpoint_uuid: endpointUuid,
              restricted: false,
            }),
          ).success,
        ).toBe(true);
        for (const k of [outsiderGateway, outsiderScoped, publicGateway]) {
          expect(await serves(k)).toBe(true);
        }
      },
    );

    it("keeps require_scoped_api_key as its own switch: turned on, a restricted endpoint refuses a gateway-wide key before any group question", async () => {
      const endpointUuid = epKeys;
      await fx.db
        .update(fx.schema.endpointsTable)
        .set({ restricted: true, require_scoped_api_key: true })
        .where(fx.eq(fx.schema.endpointsTable.uuid, endpointUuid));
      const { invalidateEndpointAccessCache } = await cacheModule();
      invalidateEndpointAccessCache();
      try {
        const group = await fx.group({
          name: name("scoped-req"),
          members: [fx.memberId],
          endpoints: [endpointUuid],
        });
        invalidateEndpointAccessCache();
        const gateway = await fx.dataKey({
          name: name("scoped-gw"),
          ownerId: fx.memberId,
        });
        const scoped = await fx.dataKey({
          name: name("scoped-sc"),
          ownerId: fx.memberId,
          endpointUuid,
        });
        const refused = await fx.authenticateKey({
          endpointUuid,
          token: gateway.key,
          ip: "203.0.113.9",
        });
        expect(refused.next).toBe(false);
        expect((refused.body as { message: string }).message).toContain(
          "requires an endpoint-scoped API key",
        );
        expect(
          (
            await fx.authenticateKey({
              endpointUuid,
              token: scoped.key,
              ip: "203.0.113.9",
            })
          ).next,
        ).toBe(true);
        await fx.db
          .delete(fx.schema.accessGroupsTable)
          .where(fx.eq(fx.schema.accessGroupsTable.uuid, group));
      } finally {
        await fx.db
          .update(fx.schema.endpointsTable)
          .set({ restricted: false, require_scoped_api_key: false })
          .where(fx.eq(fx.schema.endpointsTable.uuid, endpointUuid));
        invalidateEndpointAccessCache();
      }
    });

    it("answers a refused key with its own audit row in audit_log, naming the key and its owner", async () => {
      const endpointUuid = epKeysOauth;
      const key = await fx.dataKey({
        name: name("audited"),
        ownerId: fx.otherMemberId,
      });
      expect(
        result(
          await operator("accessGroups.setEndpointRestricted", {
            endpoint_uuid: endpointUuid,
            restricted: true,
          }),
        ).success,
      ).toBe(true);
      try {
        const refused = await fx.authenticateKey({
          endpointUuid,
          token: key.key,
          ip: "203.0.113.9",
        });
        expect(refused.next).toBe(false);

        const rows = await fx.auditEventually(
          `action = 'endpoint.access.denied' AND actor_id = $1`,
          [key.uuid],
        );
        expect(rows).toHaveLength(1);
        expect(rows[0]).toMatchObject({
          actor_type: "api_key",
          target_id: endpointUuid,
          outcome: "denied",
        });
        expect(rows[0].detail).toMatchObject({
          reason: "access_group_denied",
          auth_method: "api_key",
          owner_user_id: fx.otherMemberId,
          key_scope: "gateway",
        });
        expect(JSON.stringify(rows[0])).not.toContain(key.key);
      } finally {
        await operator("accessGroups.setEndpointRestricted", {
          endpoint_uuid: endpointUuid,
          restricted: false,
        });
      }
    });
  });

  // ---------------------------------------------------------------------------
  describe("a group restriction cannot cut an operator key off", () => {
    it("still reaches every operator procedure, the read-back and the switch, with every endpoint restricted, no group mapped and its owner in no group", async () => {
      const endpoints = [epKeys, epKeysOauth, epUnmapped];
      for (const endpoint_uuid of endpoints) {
        expect(
          result(
            await operator("accessGroups.setEndpointRestricted", {
              endpoint_uuid,
              restricted: true,
            }),
          ).success,
        ).toBe(true);
      }
      try {
        // Nothing admits anyone on the data plane but administrators' keys...
        const memberKey = await fx.dataKey({
          name: name("locked-out"),
          ownerId: fx.memberId,
        });
        for (const endpointUuid of endpoints) {
          const refused = await fx.authenticateKey({
            endpointUuid,
            token: memberKey.key,
            ip: "203.0.113.9",
          });
          expect(refused.next).toBe(false);
        }

        // ...and the operator key still answers on /trpc, which depends on no
        // MCP endpoint.
        for (const endpoint_uuid of endpoints) {
          const readBack = await operator(
            "accessGroups.getEndpointAccess",
            { endpoint_uuid },
            "query",
          );
          expect(readBack.status).toBe(200);
          expect(result(readBack).data).toMatchObject({
            restricted: true,
            groups: [],
          });
        }
        const listed = await operator("accessGroups.list", undefined, "query");
        expect(listed.status).toBe(200);
        const keys = await operator("apiKeys.listAll", undefined, "query");
        expect(keys.status).toBe(200);
      } finally {
        for (const endpoint_uuid of endpoints) {
          const undone = await operator("accessGroups.setEndpointRestricted", {
            endpoint_uuid,
            restricted: false,
          });
          expect(result(undone).success).toBe(true);
          expect((await endpointFlags(endpoint_uuid)).restricted).toBe(false);
        }
      }
    });
  });
});
