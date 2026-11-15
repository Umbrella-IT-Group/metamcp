/**
 * The operator-scope key powers against a real Postgres, through the real
 * /trpc stack:
 *
 *  - apiKeys.reactivate: a data-plane key only, the owner and the mint's
 *    eligibility rules re-run against rows locked in the write transaction,
 *    the key's own policy already a narrow enforce list, never an admin-plane
 *    key; the owner re-check ordered against a person disabling the owner;
 *  - apiKeys.rename: a data-plane key only, a valid name unique for its owner,
 *    the old and new names in the audit row;
 *  - apiKeys.removalImpact and apiKeys.remove: leaf-only (an inactive
 *    data-plane key), confirmed by name and by the impact fingerprint read
 *    beforehand, with a credential-free snapshot in the audit row;
 *  - mcpServers.resetErrors: the error status and the audit row commit
 *    together, connection recovery starts only after the commit and reports
 *    on its own, and the REST route it shares an implementation with stays
 *    reachable by a browser session only;
 *  - logs.history for an operator key, with credential-shaped text redacted;
 *  - the operator contract (apiKeys.operatorCapabilities) and the audit read
 *    of the new rows.
 *
 * Every refusal of a rule is coded and leaves a denied row; every change rolls
 * back when its audit row cannot be written (a database trigger refuses the
 * insert, a real statement failure inside the transaction).
 */
import type { AddressInfo } from "node:net";

import express from "express";
import { Client } from "pg";
import {
  afterAll,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";

import {
  createFixture,
  DEFAULT_REASON,
  type Fixture,
} from "./admin-plane-integration-fixture";

const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL;
const describeIfDb = describe.skipIf(!TEST_DATABASE_URL);

const pool = vi.hoisted(() => ({
  ensureIdleSessionForNewServer: vi.fn(),
  getPoolStatus: vi.fn(),
  ensureIdleServers: vi.fn(),
}));

const quiet = { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() };
vi.mock("@/utils/logger", () => ({ default: quiet }));
vi.mock("../lib/metamcp/mcp-server-pool", () => ({
  mcpServerPool: {
    ensureIdleSessionForNewServer: pool.ensureIdleSessionForNewServer,
    getPoolStatus: pool.getPoolStatus,
    cleanupIdleSession: vi.fn().mockResolvedValue(undefined),
    invalidateIdleSession: vi.fn().mockResolvedValue(undefined),
    invalidateServerConnection: vi.fn().mockResolvedValue(undefined),
  },
}));
vi.mock("../lib/metamcp/metamcp-server-pool", () => ({
  metaMcpServerPool: {
    ensureIdleServers: pool.ensureIdleServers,
    ensureIdleServerForNewNamespace: vi.fn().mockResolvedValue(undefined),
    cleanupIdleServer: vi.fn().mockResolvedValue(undefined),
    invalidateIdleServers: vi.fn().mockResolvedValue(undefined),
    invalidateOpenApiSessions: vi.fn().mockResolvedValue(undefined),
  },
}));

type Reply = Awaited<ReturnType<Fixture["trpc"]>>;

describeIfDb("admin-plane key powers (real Postgres)", () => {
  let fx: Fixture;
  let barrier: Client;
  let counter = 0;
  const uniq = (stem: string) => `${stem}-${++counter}-${fx.run}`;

  const one = async (sql: string, params: unknown[] = []) =>
    (await fx.suiteLock.query(sql, params)).rows;
  const operator = (procedure: string, input: unknown, key?: string) =>
    fx.trpc(`frontend.${procedure}`, input, "mutation", key ? { key } : {});
  const operatorRead = (procedure: string, input: unknown, key?: string) =>
    fx.trpc(`frontend.${procedure}`, input, "query", key ? { key } : {});
  const human = (procedure: string, input: unknown) =>
    fx.trpc(`frontend.${procedure}`, input, "mutation", {
      cookie: fx.ownerCookie,
    });

  const keyRow = async (uuid: string) =>
    (
      await one(
        `SELECT uuid, name, is_active, allowed_cidrs, ip_policy_mode FROM api_keys WHERE uuid = $1`,
        [uuid],
      )
    )[0] as
      | {
          uuid: string;
          name: string;
          is_active: boolean;
          allowed_cidrs: string[] | null;
          ip_policy_mode: string;
        }
      | undefined;

  /** Rows of audit_log for one target, newest last. */
  const rowsFor = (targetId: string, action: string, outcome = "success") =>
    fx.auditNow(`target_id = $1 AND action = $2 AND outcome = $3`, [
      targetId,
      action,
      outcome,
    ]);

  /** Rows of audit_log the change transaction wrote for this target. */
  const changeRows = (targetId: string, action: string) =>
    rowsFor(targetId, action, "success");

  /** Denied rows recorded after the rollback, read once they have landed. */
  const deniedRows = (targetId: string, action: string) =>
    fx.auditNow(
      `target_id = $1 AND action = $2 AND outcome = 'denied' AND actor_type = 'api_key'`,
      [targetId, action],
    );

  /**
   * The answer to a change whose audit row could not be written: HTTP 500 with
   * the fixed sentence (or the error formatter's mask of it), never the
   * driver's text.
   */
  const expectFixedAuditFailure = (reply: Reply) => {
    expect([
      "The change was not applied because its audit record could not be written.",
      "Internal server error",
    ]).toContain(reply.message);
    expect(reply.message).not.toContain("itest");
  };

  /** A data-plane key as an administrator's UI creates it, then shaped. */
  async function dataKey(over: {
    stem: string;
    ownerId?: string | null;
    endpointUuid?: string | null;
    active?: boolean;
    cidrs?: string[] | null;
    mode?: "off" | "audit" | "enforce";
  }) {
    const created = await fx.dataKey({
      name: uniq(over.stem),
      ownerId: over.ownerId === undefined ? fx.memberId : over.ownerId,
      endpointUuid: over.endpointUuid ?? null,
    });
    const cidrs = over.cidrs === undefined ? ["203.0.113.0/24"] : over.cidrs;
    await one(
      `UPDATE api_keys SET is_active = $2, allowed_cidrs = $3, ip_policy_mode = $4 WHERE uuid = $1`,
      [
        created.uuid,
        over.active ?? false,
        cidrs,
        over.mode ?? (cidrs === null ? "off" : "enforce"),
      ],
    );
    return created.uuid;
  }

  /** An admin-plane key of the fixture's administrator, written directly. */
  async function adminPlaneKey(stem: string, active: boolean) {
    const { ApiKeysRepository } = await import(
      "../db/repositories/api-keys.repo"
    );
    const created = await new ApiKeysRepository().create({
      name: uniq(stem),
      user_id: fx.ownerId,
      admin_plane: true,
      is_active: true,
    });
    if (!active) {
      await one(`UPDATE api_keys SET is_active = false WHERE uuid = $1`, [
        created.uuid,
      ]);
    }
    return created.uuid;
  }

  /** Another operator-scope key (its own change budget) of the same owner. */
  async function freshOperatorKey() {
    const { ApiKeysRepository } = await import(
      "../db/repositories/api-keys.repo"
    );
    const created = await new ApiKeysRepository().create({
      name: uniq("operator-key"),
      user_id: fx.ownerId,
      admin_plane: true,
      admin_plane_scope: "operator",
      is_active: true,
    });
    return { key: created.key, uuid: created.uuid };
  }

  /** Resolve once `n` backends of this database are waiting on a lock. */
  async function waitForLockWaiters(n: number) {
    const deadline = Date.now() + 10_000;
    for (;;) {
      const [{ waiting }] = await one(
        `SELECT count(*)::int AS waiting FROM pg_stat_activity
          WHERE datname = current_database() AND wait_event_type = 'Lock'`,
      );
      if (waiting >= n) return;
      if (Date.now() > deadline) {
        throw new Error(`only ${waiting} of ${n} requests queued on the lock`);
      }
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
  }

  /**
   * Hold `lock` on the barrier connection while `first` and then `second` are
   * sent, each queued behind it before the next is sent; then release and
   * return both replies in sending order.
   */
  async function raceBehind(
    lock: string,
    unlock: string,
    first: () => Promise<Reply>,
    second: () => Promise<Reply>,
  ): Promise<[Reply, Reply]> {
    await barrier.query(lock);
    try {
      const a = first();
      await waitForLockWaiters(1);
      const b = second();
      await waitForLockWaiters(2);
      await barrier.query(unlock);
      return [await a, await b];
    } catch (error) {
      await barrier.query(unlock).catch(() => undefined);
      throw error;
    }
  }

  beforeAll(async () => {
    fx = await createFixture(TEST_DATABASE_URL as string, "powers");
    barrier = new Client({ connectionString: TEST_DATABASE_URL });
    await barrier.connect();
  });

  afterAll(async () => {
    await barrier?.end();
    await fx?.close();
  });

  beforeEach(() => {
    pool.ensureIdleSessionForNewServer.mockReset();
    pool.ensureIdleSessionForNewServer.mockResolvedValue(undefined);
    pool.getPoolStatus.mockReset();
    pool.getPoolStatus.mockReturnValue({
      idleServerUuids: [],
      perServerCounts: {},
    });
    pool.ensureIdleServers.mockReset();
    pool.ensureIdleServers.mockResolvedValue(undefined);
  });

  // ---------------------------------------------------------------------------
  describe("apiKeys.create names", () => {
    it.each([true, false])(
      "refuses an admin-plane key's name even for another owner (active: %s)",
      async (active) => {
        const target = await adminPlaneKey("mint-lookalike", active);
        const name = (await keyRow(target))?.name as string;
        const reply = await operator("apiKeys.create", {
          name,
          user_id: fx.memberId,
          all_endpoints: true,
          ip_policy: {
            mode: "enforce",
            allowed_cidrs: ["203.0.113.0/24"],
          },
        });
        expect({ status: reply.status, code: reply.code }).toEqual({
          status: 400,
          code: "BAD_REQUEST",
        });
        expect(
          await one(`SELECT uuid FROM api_keys WHERE name = $1`, [name]),
        ).toEqual([{ uuid: target }]);
        const denied = await fx.auditEventually(
          `action = 'apikey.create' AND outcome = 'denied' AND actor_id = $1 AND detail->>'rule' = 'name_admin_plane'`,
          [fx.operator.uuid],
        );
        expect(denied.length).toBeGreaterThan(0);
      },
    );
  });

  // ---------------------------------------------------------------------------
  describe("apiKeys.reactivate", () => {
    const reactivate = (uuid: string, key?: string) =>
      operator("apiKeys.reactivate", { uuid }, key);

    it("reactivates an inactive data-plane key locked to a narrow list, in one transaction with its audit row", async () => {
      const ep = await fx.endpoint({ name: uniq("react-ep") });
      const uuid = await dataKey({ stem: "react", endpointUuid: ep });

      const reply = await reactivate(uuid);

      expect(reply.status).toBe(200);
      expect(reply.data).toMatchObject({
        uuid,
        is_active: true,
        changed: true,
      });
      expect(await keyRow(uuid)).toMatchObject({
        is_active: true,
        allowed_cidrs: ["203.0.113.0/24"],
        ip_policy_mode: "enforce",
      });
      const rows = await changeRows(uuid, "apikey.reactivate");
      expect(rows).toHaveLength(1);
      expect(rows[0]).toMatchObject({
        actor_type: "api_key",
        actor_id: fx.operator.uuid,
        target_type: "api_key",
      });
      expect(rows[0].detail).toMatchObject({
        via: "reactivate",
        is_active: true,
        owner_user_id: fx.memberId,
        endpoint_uuid: ep,
        reason: DEFAULT_REASON,
        budget_class: "loosen",
        ip_policy: { mode: "enforce", allowed_cidrs: ["203.0.113.0/24"] },
      });
    });

    it("answers an already-active key with changed false and writes no row", async () => {
      const uuid = await dataKey({ stem: "react-live", active: true });
      const reply = await reactivate(uuid);
      expect(reply.status).toBe(200);
      expect(reply.data).toMatchObject({ is_active: true, changed: false });
      expect(await changeRows(uuid, "apikey.reactivate")).toHaveLength(0);
    });

    it("answers an unknown key with NOT_FOUND", async () => {
      const reply = await reactivate("0f0e0d0c-0b0a-4908-8706-050403020100");
      expect(reply.code).toBe("NOT_FOUND");
    });

    it("never reactivates an admin-plane key, the calling key included, and leaves a denied row", async () => {
      const ci = await adminPlaneKey("react-ci", false);
      for (const target of [ci, fx.operator.uuid]) {
        const reply = await reactivate(target);
        expect({ target, code: reply.code }).toEqual({
          target,
          code: "FORBIDDEN",
        });
      }
      expect((await keyRow(ci))?.is_active).toBe(false);
      const denied = await deniedRows(ci, "apikey.reactivate");
      expect(denied).toHaveLength(1);
      expect(denied[0].detail).toMatchObject({ rule: "target_admin_plane" });
    });

    it("refuses a key that acts as a user, a public key and a key of a disabled owner", async () => {
      const { ApiKeysRepository } = await import(
        "../db/repositories/api-keys.repo"
      );
      const ep = await fx.endpoint({ name: uniq("react-actsas-ep") });
      const actsAs = await new ApiKeysRepository().create({
        name: uniq("react-actsas"),
        user_id: fx.memberId,
        endpoint_uuid: ep,
        acts_as_user_id: fx.memberId,
        is_active: true,
      });
      await one(
        `UPDATE api_keys SET is_active = false, allowed_cidrs = ARRAY['203.0.113.0/24'], ip_policy_mode = 'enforce' WHERE uuid = $1`,
        [actsAs.uuid],
      );
      const publicKey = await dataKey({ stem: "react-public", ownerId: null });
      const disabledOwnerKey = await dataKey({
        stem: "react-disabled",
        ownerId: fx.otherMemberId,
      });
      await one(`UPDATE users SET disabled = true WHERE id = $1`, [
        fx.otherMemberId,
      ]);
      try {
        const cases: Array<[string, string]> = [
          [actsAs.uuid, "target_acts_as"],
          [publicKey, "owner_ineligible"],
          [disabledOwnerKey, "owner_ineligible"],
        ];
        for (const [uuid, rule] of cases) {
          const reply = await reactivate(uuid);
          expect({ rule, code: reply.code }).toEqual({
            rule,
            code: "FORBIDDEN",
          });
          expect((await keyRow(uuid))?.is_active).toBe(false);
          const denied = await deniedRows(uuid, "apikey.reactivate");
          expect(
            denied.map((row) => (row.detail as { rule?: unknown }).rule),
          ).toEqual([rule]);
        }
      } finally {
        await one(`UPDATE users SET disabled = false WHERE id = $1`, [
          fx.otherMemberId,
        ]);
      }
    });

    it("refuses a key whose own policy is not a narrow enforce list", async () => {
      const cases: Array<{
        stem: string;
        cidrs: string[] | null;
        mode?: "off" | "audit" | "enforce";
      }> = [
        { stem: "react-global", cidrs: null },
        { stem: "react-audit", cidrs: ["203.0.113.0/24"], mode: "audit" },
        { stem: "react-wide", cidrs: ["10.0.0.0/16"] },
        { stem: "react-anyip", cidrs: ["0.0.0.0/0", "::/0"] },
        {
          stem: "react-many",
          cidrs: Array.from({ length: 9 }, (_v, i) => `198.51.${i}.0/24`),
        },
      ];
      for (const shape of cases) {
        const uuid = await dataKey({ ...shape });
        const reply = await reactivate(uuid);
        expect({ stem: shape.stem, code: reply.code }).toEqual({
          stem: shape.stem,
          code: "FORBIDDEN",
        });
        expect((await keyRow(uuid))?.is_active).toBe(false);
        const denied = await deniedRows(uuid, "apikey.reactivate");
        expect(
          denied.map((row) => (row.detail as { rule?: unknown }).rule),
        ).toEqual(["ip_policy_not_narrow"]);
      }
    });

    it("re-runs the mint's endpoint rules against the locked rows", async () => {
      const privateEp = await fx.endpoint({
        name: uniq("react-private"),
        userId: fx.memberId,
      });
      const guardedNs = await fx.namespace(uniq("react-guarded"));
      const guarded = await fx.endpoint({
        name: uniq("react-guarded-ep"),
        restricted: true,
        namespaceUuid: guardedNs,
      });
      const onPrivate = await dataKey({
        stem: "react-on-private",
        endpointUuid: privateEp,
      });
      const onGuardedNonMember = await dataKey({
        stem: "react-on-guarded",
        endpointUuid: guarded,
      });
      const adminGatewayWide = await dataKey({
        stem: "react-admin-wide",
        ownerId: fx.ownerId,
      });
      const cases: Array<[string, string]> = [
        [onPrivate, "endpoint_not_eligible"],
        [onGuardedNonMember, "endpoint_not_eligible"],
        [adminGatewayWide, "gateway_wide_admin_owner"],
      ];
      for (const [uuid, rule] of cases) {
        const reply = await reactivate(uuid);
        expect({ rule, code: reply.code }).toEqual({ rule, code: "FORBIDDEN" });
        expect((await keyRow(uuid))?.is_active).toBe(false);
        expect(
          (await deniedRows(uuid, "apikey.reactivate")).map(
            (row) => (row.detail as { rule?: unknown }).rule,
          ),
        ).toEqual([rule]);
      }

      // The same restricted endpoint, once the owner is an explicit member of a
      // group mapped to it.
      await fx.group({
        name: uniq("react-grant"),
        members: [fx.memberId],
        endpoints: [guarded],
      });
      const granted = await reactivate(onGuardedNonMember);
      expect(granted.status).toBe(200);
      expect((await keyRow(onGuardedNonMember))?.is_active).toBe(true);
    });

    it("refuses while the IP-policy kill switch is on", async () => {
      const uuid = await dataKey({ stem: "react-killswitch" });
      process.env.API_KEY_IP_POLICY_DISABLED = "true";
      try {
        const reply = await reactivate(uuid);
        expect(reply.code).toBe("FORBIDDEN");
      } finally {
        delete process.env.API_KEY_IP_POLICY_DISABLED;
      }
      expect((await keyRow(uuid))?.is_active).toBe(false);
      expect(
        (await deniedRows(uuid, "apikey.reactivate")).map(
          (row) => (row.detail as { rule?: unknown }).rule,
        ),
      ).toEqual(["ip_policy_disabled"]);
    });

    it("rolls the reactivation back when its audit row cannot be written", async () => {
      const uuid = await dataKey({ stem: "react-fault" });
      await fx.failAuditFor("apikey.reactivate");
      try {
        const reply = await reactivate(uuid);
        expect(reply.status).toBe(500);
        expectFixedAuditFailure(reply);
      } finally {
        await fx.clearAuditFault("apikey.reactivate");
      }
      expect((await keyRow(uuid))?.is_active).toBe(false);
    });

    it("re-checks the owner under its row lock, in both orders against a person disabling the owner", async () => {
      const disable = (disabled: boolean) =>
        human("users.setDisabled", {
          user_id: fx.otherMemberId,
          disabled,
        });
      const lockOwner = `BEGIN; SELECT 1 FROM users WHERE id = '${fx.otherMemberId}' FOR UPDATE`;
      try {
        // Reactivation queued first: it is judged before the disable lands.
        const first = await dataKey({
          stem: "react-race-a",
          ownerId: fx.otherMemberId,
        });
        const [kept, disabledA] = await raceBehind(
          lockOwner,
          "COMMIT",
          () => reactivate(first),
          () => disable(true),
        );
        expect([kept.status, disabledA.status]).toEqual([200, 200]);
        expect((await keyRow(first))?.is_active).toBe(true);
        expect((await disable(false)).status).toBe(200);

        // Disable queued first: the reactivation reads the owner as the
        // disable left it, and is refused.
        const second = await dataKey({
          stem: "react-race-b",
          ownerId: fx.otherMemberId,
        });
        const [disabledB, refused] = await raceBehind(
          lockOwner,
          "COMMIT",
          () => disable(true),
          () => reactivate(second),
        );
        expect([disabledB.status, refused.code]).toEqual([200, "FORBIDDEN"]);
        expect((await keyRow(second))?.is_active).toBe(false);
      } finally {
        await one(`UPDATE users SET disabled = false WHERE id = $1`, [
          fx.otherMemberId,
        ]);
      }
    });
  });

  // ---------------------------------------------------------------------------
  describe("apiKeys.rename", () => {
    const rename = (uuid: string, name: string, key?: string) =>
      operator("apiKeys.rename", { uuid, name }, key);

    it("renames a data-plane key and records the old and new names in its audit row", async () => {
      const uuid = await dataKey({ stem: "ren", active: true });
      const before = (await keyRow(uuid))?.name;
      const next = uniq("ren-new");

      const reply = await rename(uuid, next);

      expect(reply.status).toBe(200);
      expect(reply.data).toMatchObject({
        uuid,
        name: next,
        previous_name: before,
        changed: true,
      });
      expect((await keyRow(uuid))?.name).toBe(next);
      const rows = await changeRows(uuid, "apikey.update");
      expect(rows).toHaveLength(1);
      expect(rows[0].detail).toMatchObject({
        via: "rename",
        name: next,
        previous_name: before,
        budget_class: "change",
        reason: DEFAULT_REASON,
      });
    });

    it("refuses a name the owner already uses, inactive keys included, and a name of the wrong shape", async () => {
      const taken = await dataKey({ stem: "ren-taken", active: false });
      const takenName = (await keyRow(taken))?.name as string;
      const uuid = await dataKey({ stem: "ren-target", active: true });
      const before = (await keyRow(uuid))?.name;

      const clash = await rename(uuid, takenName);
      expect(clash.code).toBe("BAD_REQUEST");
      const badShape = await rename(uuid, "semi;colon");
      expect(badShape.code).toBe("BAD_REQUEST");

      expect((await keyRow(uuid))?.name).toBe(before);
      expect(
        (await deniedRows(uuid, "apikey.update")).map(
          (row) => (row.detail as { rule?: unknown }).rule,
        ),
      ).toEqual(["name_taken", "name_invalid"]);
    });

    it("does not judge a name against another owner's keys", async () => {
      const others = await dataKey({
        stem: "ren-other",
        ownerId: fx.otherMemberId,
        active: true,
      });
      const othersName = (await keyRow(others))?.name as string;
      const uuid = await dataKey({ stem: "ren-mine", active: true });
      const reply = await rename(uuid, othersName);
      expect(reply.status).toBe(200);
      expect((await keyRow(uuid))?.name).toBe(othersName);
    });

    it.each([
      ["a newline", "line1\nline2"],
      ["a tab", "tab\there"],
      ["a no-break space", "no-break\u00a0space"],
      ["a line separator", "line\u2028separator"],
    ])("refuses a name with %s and changes nothing", async (_label, name) => {
      const uuid = await dataKey({ stem: "ren-ws", active: true });
      const before = (await keyRow(uuid))?.name;
      const reply = await rename(uuid, name);
      expect({ status: reply.status, code: reply.code }).toEqual({
        status: 400,
        code: "BAD_REQUEST",
      });
      expect((await keyRow(uuid))?.name).toBe(before);
      expect(
        (await deniedRows(uuid, "apikey.update")).map(
          (row) => (row.detail as { rule?: unknown }).rule,
        ),
      ).toContain("name_invalid");
    });

    it("refuses a name that is an admin-plane key's, whoever owns either, and says so with a denied row", async () => {
      const adminPlane = await adminPlaneKey("ren-op", true);
      const inactiveAdminPlane = await adminPlaneKey("ren-op-off", false);
      const uuid = await dataKey({
        stem: "ren-lookalike",
        ownerId: fx.otherMemberId,
        active: true,
      });
      const before = (await keyRow(uuid))?.name;
      for (const target of [adminPlane, inactiveAdminPlane]) {
        const name = (await keyRow(target))?.name as string;
        const reply = await rename(uuid, name);
        expect({ status: reply.status, code: reply.code }).toEqual({
          status: 400,
          code: "BAD_REQUEST",
        });
      }
      expect((await keyRow(uuid))?.name).toBe(before);
      expect(
        (await deniedRows(uuid, "apikey.update")).map(
          (row) => (row.detail as { rule?: unknown }).rule,
        ),
      ).toEqual(["name_admin_plane", "name_admin_plane"]);
    });

    it("lets exactly one of two callers rename two public keys to one name at the same moment", async () => {
      // The database's per-owner unique rule does not cover public keys (a
      // NULL owner is distinct to it), so two renames that both read the name
      // as free would both commit. A test-only trigger holds each rename just
      // before its write until the barrier opens, so both have made their
      // check by then if nothing orders them; the name lock orders them.
      const first = await freshOperatorKey();
      const second = await freshOperatorKey();
      const a = await dataKey({ stem: "ren-pub-a", ownerId: null });
      const b = await dataKey({ stem: "ren-pub-b", ownerId: null });
      const name = uniq("ren-pub-same");
      const barrierKey = "hashtext('itest.rename.barrier')";
      await one(`CREATE OR REPLACE FUNCTION itest_rename_barrier() RETURNS trigger AS $$
        BEGIN PERFORM pg_advisory_xact_lock(${barrierKey}); RETURN NEW; END $$ LANGUAGE plpgsql`);
      await one(`DROP TRIGGER IF EXISTS itest_rename_barrier_trg ON api_keys`);
      await one(`CREATE TRIGGER itest_rename_barrier_trg
        BEFORE UPDATE OF name ON api_keys
        FOR EACH ROW EXECUTE FUNCTION itest_rename_barrier()`);
      try {
        const [one1, two] = await raceBehind(
          `SELECT pg_advisory_lock(${barrierKey})`,
          `SELECT pg_advisory_unlock(${barrierKey})`,
          () => rename(a, name, first.key),
          () => rename(b, name, second.key),
        );
        expect([one1.status, two.status].sort()).toEqual([200, 400]);
        expect(
          await one(
            `SELECT count(*)::int AS n FROM api_keys WHERE user_id IS NULL AND name = $1`,
            [name],
          ),
        ).toEqual([{ n: 1 }]);
      } finally {
        await one(
          `DROP TRIGGER IF EXISTS itest_rename_barrier_trg ON api_keys`,
        );
        await one(`DROP FUNCTION IF EXISTS itest_rename_barrier()`);
      }
    });

    it("never renames an admin-plane key", async () => {
      const ci = await adminPlaneKey("ren-ci", true);
      const before = (await keyRow(ci))?.name;
      const reply = await rename(ci, uniq("ren-ci-new"));
      expect(reply.code).toBe("FORBIDDEN");
      expect((await keyRow(ci))?.name).toBe(before);
      expect(
        (await deniedRows(ci, "apikey.update")).map(
          (row) => (row.detail as { rule?: unknown }).rule,
        ),
      ).toEqual(["target_admin_plane"]);
    });

    it("answers the current name with changed false and writes no row", async () => {
      const uuid = await dataKey({ stem: "ren-same", active: true });
      const name = (await keyRow(uuid))?.name as string;
      const reply = await rename(uuid, name);
      expect(reply.status).toBe(200);
      expect(reply.data).toMatchObject({ name, changed: false });
      expect(await changeRows(uuid, "apikey.update")).toHaveLength(0);
    });

    it("rolls the rename back when its audit row cannot be written", async () => {
      const uuid = await dataKey({ stem: "ren-fault", active: true });
      const before = (await keyRow(uuid))?.name;
      await fx.failAuditFor("apikey.update");
      try {
        const reply = await rename(uuid, uniq("ren-fault-new"));
        expect(reply.status).toBe(500);
        expectFixedAuditFailure(reply);
      } finally {
        await fx.clearAuditFault("apikey.update");
      }
      expect((await keyRow(uuid))?.name).toBe(before);
    });
  });

  // ---------------------------------------------------------------------------
  describe("apiKeys.remove", () => {
    type Impact = {
      uuid: string;
      name: string;
      removable: boolean;
      blocked_by: string | null;
      impact_fingerprint: string;
      snapshot: Record<string, unknown>;
    };
    const impactOf = async (uuid: string, key?: string) => {
      const reply = await operatorRead("apiKeys.removalImpact", { uuid }, key);
      return { reply, impact: reply.data as Impact };
    };
    const remove = (
      uuid: string,
      confirmName: string,
      fingerprint: string,
      key?: string,
    ) =>
      operator(
        "apiKeys.remove",
        { uuid, confirm_name: confirmName, impact_fingerprint: fingerprint },
        key,
      );

    it("removes an inactive data-plane key confirmed by name and current fingerprint, with a credential-free snapshot in its audit row", async () => {
      const ep = await fx.endpoint({ name: uniq("rm-ep") });
      const created = await fx.dataKey({
        name: uniq("rm"),
        ownerId: fx.memberId,
        endpointUuid: ep,
      });
      await one(`UPDATE api_keys SET is_active = false WHERE uuid = $1`, [
        created.uuid,
      ]);
      const [{ key_hash: keyHash }] = await one(
        `SELECT key_hash FROM api_keys WHERE uuid = $1`,
        [created.uuid],
      );
      const { reply: read, impact } = await impactOf(created.uuid);
      expect(read.status).toBe(200);
      expect(impact).toMatchObject({
        uuid: created.uuid,
        removable: true,
        blocked_by: null,
      });
      expect(impact.impact_fingerprint).toMatch(/^sha256:[0-9a-f]{64}$/);

      const reply = await remove(
        created.uuid,
        impact.name,
        impact.impact_fingerprint,
      );

      expect(reply.status).toBe(200);
      expect(reply.data).toMatchObject({
        uuid: created.uuid,
        name: impact.name,
        removed: true,
      });
      expect(await keyRow(created.uuid)).toBeUndefined();
      const rows = await changeRows(created.uuid, "apikey.delete");
      expect(rows).toHaveLength(1);
      expect(rows[0].detail).toMatchObject({
        via: "remove",
        name: impact.name,
        impact_fingerprint: impact.impact_fingerprint,
        budget_class: "destroy",
        snapshot: {
          name: impact.name,
          owner_user_id: fx.memberId,
          endpoint_uuid: ep,
          is_active: false,
          key_prefix: `sk_mt_…${created.key.slice(-4)}`,
        },
      });
      const written = JSON.stringify(rows[0].detail);
      expect(written).not.toContain(created.key);
      expect(written).not.toContain(keyHash);
      expect(written).not.toContain("key_hash");
    });

    it("refuses an active key as a conflict, says so in the impact read, and leaves a denied row", async () => {
      const uuid = await dataKey({ stem: "rm-live", active: true });
      const { impact } = await impactOf(uuid);
      expect(impact).toMatchObject({
        removable: false,
        blocked_by: "key_active",
      });
      const reply = await remove(uuid, impact.name, impact.impact_fingerprint);
      expect(reply.code).toBe("CONFLICT");
      expect(await keyRow(uuid)).toBeDefined();
      expect(
        (await deniedRows(uuid, "apikey.delete")).map(
          (row) => (row.detail as { rule?: unknown }).rule,
        ),
      ).toEqual(["key_active"]);
    });

    it("refuses a confirm_name that is not the key's current name", async () => {
      const uuid = await dataKey({ stem: "rm-confirm" });
      const { impact } = await impactOf(uuid);
      const reply = await remove(
        uuid,
        `${impact.name}-typo`,
        impact.impact_fingerprint,
      );
      expect(reply.code).toBe("BAD_REQUEST");
      expect(await keyRow(uuid)).toBeDefined();
      expect(
        (await deniedRows(uuid, "apikey.delete")).map(
          (row) => (row.detail as { rule?: unknown }).rule,
        ),
      ).toEqual(["confirm_name_mismatch"]);
    });

    it("refuses a fingerprint read before the key last changed, as a retryable conflict", async () => {
      const uuid = await dataKey({ stem: "rm-stale" });
      const { impact: before } = await impactOf(uuid);
      // A person narrows the key's policy after the impact was read.
      expect(
        (
          await human("apiKeys.setIpPolicy", {
            uuid,
            allowed_cidrs: ["203.0.113.128/25"],
            ip_policy_mode: "enforce",
          })
        ).status,
      ).toBe(200);
      const stale = await remove(uuid, before.name, before.impact_fingerprint);
      expect(stale.code).toBe("CONFLICT");
      expect(await keyRow(uuid)).toBeDefined();

      const { impact: after } = await impactOf(uuid);
      expect(after.impact_fingerprint).not.toBe(before.impact_fingerprint);
      expect(
        (await remove(uuid, after.name, after.impact_fingerprint)).status,
      ).toBe(200);
      expect(await keyRow(uuid)).toBeUndefined();
      expect(
        (await deniedRows(uuid, "apikey.delete")).map(
          (row) => (row.detail as { rule?: unknown }).rule,
        ),
      ).toEqual(["impact_changed"]);
    });

    it("orders a removal and a reactivation of one key by its row lock, in both orders, across two callers", async () => {
      // Two operator keys (each with its own change budget) so nothing but
      // the key row orders them. Whichever goes first is held at its own audit
      // write, after its change and before its commit, so it still holds the
      // key row; the second is then sent. With the row lock the second waits
      // for the first and judges the key as the first left it; without it the
      // second reads the row as it was and removes a key the first has just
      // made active (or reactivates a key the first has just removed).
      const reactivator = await freshOperatorKey();
      const remover = await freshOperatorKey();
      const prepare = async (stem: string) => {
        const ep = await fx.endpoint({ name: uniq(`${stem}-ep`) });
        const uuid = await dataKey({ stem, endpointUuid: ep });
        const impact = (await operatorRead("apiKeys.removalImpact", { uuid }))
          .data as { name: string; impact_fingerprint: string };
        return { uuid, impact };
      };
      const reactivate = (uuid: string) =>
        operator("apiKeys.reactivate", { uuid }, reactivator.key);
      const removeKey = (target: Awaited<ReturnType<typeof prepare>>) =>
        operator(
          "apiKeys.remove",
          {
            uuid: target.uuid,
            confirm_name: target.impact.name,
            impact_fingerprint: target.impact.impact_fingerprint,
          },
          remover.key,
        );
      // Only these two success rows wait; the request-acceptance rows and
      // every other audit write pass, so what is waiting is the change's own
      // audit write inside its transaction.
      const gate = "hashtext('itest.key.lifecycle.audit')";
      await one(`CREATE OR REPLACE FUNCTION itest_hold_key_audit() RETURNS trigger AS $$
        BEGIN
          IF NEW.outcome = 'success'
             AND NEW.action IN ('apikey.reactivate', 'apikey.delete') THEN
            PERFORM pg_advisory_lock_shared(${gate});
            PERFORM pg_advisory_unlock_shared(${gate});
          END IF;
          RETURN NEW;
        END $$ LANGUAGE plpgsql`);
      await one(`DROP TRIGGER IF EXISTS itest_hold_key_audit_trg ON audit_log`);
      await one(`CREATE TRIGGER itest_hold_key_audit_trg BEFORE INSERT ON audit_log
        FOR EACH ROW EXECUTE FUNCTION itest_hold_key_audit()`);
      const hold = (
        first: () => Promise<Reply>,
        second: () => Promise<Reply>,
      ) =>
        raceBehind(
          `SELECT pg_advisory_lock(${gate})`,
          `SELECT pg_advisory_unlock(${gate})`,
          first,
          second,
        );
      try {
        // The reactivation first: the key is active when the removal looks, so
        // the removal is refused and the key stays.
        const a = await prepare("race-react-first");
        const [reactivated, refused] = await hold(
          () => reactivate(a.uuid),
          () => removeKey(a),
        );
        expect([reactivated.status, refused.code]).toEqual([200, "CONFLICT"]);
        expect((await keyRow(a.uuid))?.is_active).toBe(true);

        // The removal first: the reactivation finds no key.
        const b = await prepare("race-remove-first");
        const [removed, gone] = await hold(
          () => removeKey(b),
          () => reactivate(b.uuid),
        );
        expect([removed.status, gone.code]).toEqual([200, "NOT_FOUND"]);
        expect(await keyRow(b.uuid)).toBeUndefined();
      } finally {
        await one(
          `DROP TRIGGER IF EXISTS itest_hold_key_audit_trg ON audit_log`,
        );
        await one(`DROP FUNCTION IF EXISTS itest_hold_key_audit()`);
      }
    });

    it("never removes an admin-plane key, even an inactive one", async () => {
      const ci = await adminPlaneKey("rm-ci", false);
      const { impact } = await impactOf(ci);
      expect(impact).toMatchObject({
        removable: false,
        blocked_by: "target_admin_plane",
      });
      const reply = await remove(ci, impact.name, impact.impact_fingerprint);
      expect(reply.code).toBe("FORBIDDEN");
      expect(await keyRow(ci)).toBeDefined();
      expect(
        (await deniedRows(ci, "apikey.delete")).map(
          (row) => (row.detail as { rule?: unknown }).rule,
        ),
      ).toEqual(["target_admin_plane"]);
    });

    it("rolls the removal back when its audit row cannot be written", async () => {
      const uuid = await dataKey({ stem: "rm-fault" });
      const { impact } = await impactOf(uuid);
      await fx.failAuditFor("apikey.delete");
      try {
        const reply = await remove(
          uuid,
          impact.name,
          impact.impact_fingerprint,
        );
        expect(reply.status).toBe(500);
        expectFixedAuditFailure(reply);
      } finally {
        await fx.clearAuditFault("apikey.delete");
      }
      expect(await keyRow(uuid)).toBeDefined();
    });

    it("keeps the broad update and delete procedures out of an operator key's reach", async () => {
      const uuid = await dataKey({ stem: "rm-broad", active: true });
      for (const [procedure, input] of [
        ["apiKeys.update", { uuid, is_active: false }],
        ["apiKeys.delete", { uuid }],
      ] as const) {
        const reply = await operator(procedure, input);
        expect({ procedure, code: reply.code }).toEqual({
          procedure,
          code: "FORBIDDEN",
        });
      }
      expect(await keyRow(uuid)).toMatchObject({ is_active: true });
    });
  });

  // ---------------------------------------------------------------------------
  describe("mcpServers.resetErrors", () => {
    const server = async (stem: string, status: "ERROR" | "NONE") => {
      const name = uniq(stem).replace(/[^A-Za-z0-9_-]/g, "_");
      const [row] = await one(
        `INSERT INTO mcp_servers (name, type, url, error_status)
         VALUES ($1, 'STREAMABLE_HTTP', 'http://backend.internal:8000/mcp', $2)
         RETURNING uuid`,
        [name, status],
      );
      return { uuid: row.uuid as string, name };
    };
    const statusOf = async (uuid: string) =>
      (
        await one(`SELECT error_status FROM mcp_servers WHERE uuid = $1`, [
          uuid,
        ])
      )[0]?.error_status;
    const resetErrors = (input: unknown, key?: string) =>
      operator("mcpServers.resetErrors", input, key);
    type ResetReply = {
      reset: Array<{ uuid: string; name: string }>;
      recovery: {
        status: string;
        servers: Array<{ uuid: string; name: string; status: string }>;
      };
    };

    afterAll(async () => {
      await one(`DELETE FROM mcp_servers WHERE name LIKE $1`, [`%${fx.run}`]);
    });

    it("clears one server's error status with its audit row in one transaction, then starts recovery after the commit", async () => {
      const s = await server("reset-one", "ERROR");
      // Another server in ERROR, which a reset of the first must not touch.
      const bystander = await server("reset-one-bystander", "ERROR");
      const seenAtRecovery: Array<{ status: unknown; rows: number }> = [];
      pool.ensureIdleSessionForNewServer.mockImplementation(async (uuid) => {
        // Read on the test's own connection: what is committed.
        seenAtRecovery.push({
          status: await statusOf(uuid),
          rows: (await changeRows(uuid, "mcpserver.errors.reset")).length,
        });
      });
      pool.getPoolStatus.mockReturnValue({
        idleServerUuids: [s.uuid],
        perServerCounts: { [s.uuid]: 1 },
      });

      const reply = await resetErrors({ serverUuid: s.uuid });

      expect(reply.status).toBe(200);
      const data = reply.data as ResetReply;
      expect(data.reset).toEqual([{ uuid: s.uuid, name: s.name }]);
      expect(data.recovery).toEqual({
        status: "succeeded",
        servers: [{ uuid: s.uuid, name: s.name, status: "connected" }],
      });
      expect(await statusOf(s.uuid)).toBe("NONE");
      expect(await statusOf(bystander.uuid)).toBe("ERROR");
      expect(seenAtRecovery).toEqual([{ status: "NONE", rows: 1 }]);
      const rows = await changeRows(s.uuid, "mcpserver.errors.reset");
      expect(rows).toHaveLength(1);
      expect(rows[0]).toMatchObject({
        actor_type: "api_key",
        actor_id: fx.operator.uuid,
        target_type: "mcp_server",
      });
      expect(rows[0].detail).toMatchObject({
        selection: "one",
        server_uuids: [s.uuid],
        reset_count: 1,
        budget_class: "change",
        reason: DEFAULT_REASON,
      });
    });

    it("answers an unknown server with NOT_FOUND and starts nothing", async () => {
      const reply = await resetErrors({
        serverUuid: "0f0e0d0c-0b0a-4908-8706-050403020101",
      });
      expect(reply.code).toBe("NOT_FOUND");
      expect(pool.ensureIdleSessionForNewServer).not.toHaveBeenCalled();
    });

    it("answers a server that is not in error with an empty reset, no row and no recovery", async () => {
      const s = await server("reset-healthy", "NONE");
      const reply = await resetErrors({ serverUuid: s.uuid });
      expect(reply.status).toBe(200);
      expect(reply.data).toEqual({
        reset: [],
        recovery: { status: "not_needed", servers: [] },
      });
      expect(await changeRows(s.uuid, "mcpserver.errors.reset")).toHaveLength(
        0,
      );
      expect(pool.ensureIdleSessionForNewServer).not.toHaveBeenCalled();
    });

    it("resets every server in error when none is named, as one audited change", async () => {
      const a = await server("reset-all-a", "ERROR");
      const b = await server("reset-all-b", "ERROR");
      const healthy = await server("reset-all-ok", "NONE");

      const reply = await resetErrors({});

      expect(reply.status).toBe(200);
      const data = reply.data as ResetReply;
      const resetUuids = data.reset.map((s) => s.uuid);
      expect(resetUuids).toEqual(expect.arrayContaining([a.uuid, b.uuid]));
      expect(resetUuids).not.toContain(healthy.uuid);
      expect(await statusOf(a.uuid)).toBe("NONE");
      expect(await statusOf(b.uuid)).toBe("NONE");
      const rows = await fx.auditNow(
        `action = 'mcpserver.errors.reset' AND actor_id = $1 AND detail->>'selection' = 'all_in_error' AND detail->'server_uuids' ? $2`,
        [fx.operator.uuid, a.uuid],
      );
      expect(rows).toHaveLength(1);
      expect(
        (rows[0].detail as { server_uuids?: unknown }).server_uuids,
      ).toEqual(expect.arrayContaining([a.uuid, b.uuid]));
    });

    it("rolls the reset back when its audit row cannot be written, leaving the server in error and recovering nothing", async () => {
      const s = await server("reset-fault", "ERROR");
      await fx.failAuditFor("mcpserver.errors.reset");
      try {
        const reply = await resetErrors({ serverUuid: s.uuid });
        expect(reply.status).toBe(500);
        expectFixedAuditFailure(reply);
      } finally {
        await fx.clearAuditFault("mcpserver.errors.reset");
      }
      expect(await statusOf(s.uuid)).toBe("ERROR");
      expect(pool.ensureIdleSessionForNewServer).not.toHaveBeenCalled();
    });

    it("reports a failed recovery as such, without undoing the committed reset", async () => {
      const s = await server("reset-recover-fail", "ERROR");
      pool.ensureIdleSessionForNewServer.mockRejectedValue(
        new Error("upstream unreachable"),
      );
      const reply = await resetErrors({ serverUuid: s.uuid });
      expect(reply.status).toBe(200);
      expect(reply.data).toEqual({
        reset: [{ uuid: s.uuid, name: s.name }],
        recovery: {
          status: "failed",
          servers: [{ uuid: s.uuid, name: s.name, status: "failed" }],
        },
      });
      expect(await statusOf(s.uuid)).toBe("NONE");
      expect(await changeRows(s.uuid, "mcpserver.errors.reset")).toHaveLength(
        1,
      );
      expect(pool.ensureIdleSessionForNewServer).toHaveBeenCalledTimes(1);
    });

    it("is not available to a sync-scope key", async () => {
      const s = await server("reset-sync", "ERROR");
      const reply = await resetErrors({ serverUuid: s.uuid }, fx.sync.key);
      expect(reply.code).toBe("FORBIDDEN");
      expect(await statusOf(s.uuid)).toBe("ERROR");
    });

    it("shares its implementation with the REST route, which stays reachable by a browser session only", async () => {
      const { default: adminRouter } = await import(
        "../routers/public-metamcp/admin"
      );
      const { auditContextMiddleware } = await import(
        "../middleware/audit-context.middleware"
      );
      const ep = await fx.endpoint({ name: uniq("reset-rest-ep") });
      const [{ name: endpointName }] = await one(
        `SELECT name FROM endpoints WHERE uuid = $1`,
        [ep],
      );
      const app = express();
      app.use(auditContextMiddleware);
      app.use("/metamcp", adminRouter);
      let restServer!: import("node:http").Server;
      await new Promise<void>((resolve) => {
        restServer = app.listen(0, "127.0.0.1", resolve);
      });
      const url = `http://127.0.0.1:${(restServer.address() as AddressInfo).port}/metamcp/${endpointName}/admin/reset-errors`;
      try {
        const s = await server("reset-rest", "ERROR");

        // An admin-plane key's bearer is not a session: refused, nothing reset.
        const bearer = await fetch(url, {
          method: "POST",
          headers: {
            "content-type": "application/json",
            authorization: `Bearer ${fx.operator.key}`,
          },
          body: JSON.stringify({ serverUuid: s.uuid }),
        });
        expect(bearer.status).toBe(401);
        expect(await statusOf(s.uuid)).toBe("ERROR");

        // An unknown server is a 404 there too, not a reported reset.
        const unknown = await fetch(url, {
          method: "POST",
          headers: {
            "content-type": "application/json",
            cookie: fx.ownerCookie,
          },
          body: JSON.stringify({
            serverUuid: "0f0e0d0c-0b0a-4908-8706-050403020102",
          }),
        });
        expect(unknown.status).toBe(404);

        // The administrator's session resets it through the same code, which
        // writes the same audit action, attributed to the person.
        const session = await fetch(url, {
          method: "POST",
          headers: {
            "content-type": "application/json",
            cookie: fx.ownerCookie,
          },
          body: JSON.stringify({ serverUuid: s.uuid }),
        });
        expect(session.status).toBe(200);
        expect(await session.json()).toMatchObject({
          success: true,
          reset: 1,
          servers: [s.name],
        });
        expect(await statusOf(s.uuid)).toBe("NONE");
        const rows = await fx.auditEventually(
          `target_id = $1 AND action = 'mcpserver.errors.reset'`,
          [s.uuid],
        );
        expect(rows).toHaveLength(1);
        expect(rows[0]).toMatchObject({
          actor_type: "user",
          actor_id: fx.ownerId,
        });
      } finally {
        await new Promise((resolve) => restServer.close(resolve));
      }
    });
  });

  // ---------------------------------------------------------------------------
  describe("logs.history for an operator key", () => {
    it("reads the bounded history with credential-shaped text redacted and session ids left out", async () => {
      const serverName = uniq("diag").replace(/[^A-Za-z0-9_-]/g, "_");
      const token = "sk_mt_abcdefghijklmnopqrstuvwxyz0123456789ABCD";
      await one(
        `INSERT INTO gateway_events (category, level, server_name, session_id, message, metadata)
         VALUES ('connection', 'error', $1, 'session-abc', $2, $3::jsonb)`,
        [
          serverName,
          `connect failed for https://agent:hunter2@vendor.example/mcp?api_key=s3cr3t&x=1 with Bearer ${token}`,
          JSON.stringify({
            error: "upstream said password=letmein",
            other: "dropped",
          }),
        ],
      );

      const reply = await operatorRead("logs.history", { serverName });

      expect(reply.status).toBe(200);
      const rows = (
        reply.data as {
          data: Array<{
            message: string;
            sessionId: string | null;
            metadata: Record<string, unknown> | null;
            serverName: string;
          }>;
        }
      ).data;
      expect(rows).toHaveLength(1);
      expect(rows[0].serverName).toBe(serverName);
      expect(rows[0].sessionId).toBeNull();
      const text = JSON.stringify(rows[0]);
      for (const secret of ["hunter2", "s3cr3t", token, "letmein", "dropped"]) {
        expect({ secret, present: text.includes(secret) }).toEqual({
          secret,
          present: false,
        });
      }
      expect(rows[0].message).toContain("vendor.example/mcp");

      // A person in the admin UI reads the history as stored.
      const asPerson = await fx.trpc(
        "frontend.logs.history",
        { serverName },
        "query",
        { cookie: fx.ownerCookie },
      );
      expect(JSON.stringify(asPerson.data)).toContain("hunter2");
    });

    it("refuses a search term, which would match the unredacted text a character at a time, and still lets a person search", async () => {
      const serverName = uniq("diag-search").replace(/[^A-Za-z0-9_-]/g, "_");
      await one(
        `INSERT INTO gateway_events (category, level, server_name, message)
         VALUES ('connection', 'error', $1, 'connect failed token=ZxQ-secret-9981-tail')`,
        [serverName],
      );

      // The redacted page does not show the value, and a search for a prefix
      // of it would still tell a caller whether the prefix is there.
      for (const search of ["ZxQ-secret-99", "ZxQ-secret-98"]) {
        const reply = await operatorRead("logs.history", {
          serverName,
          search,
        });
        expect({ search, status: reply.status, code: reply.code }).toEqual({
          search,
          status: 400,
          code: "BAD_REQUEST",
        });
        expect(reply.message ?? "").not.toContain("ZxQ");
      }
      // Without a search the row is read, redacted.
      const page = await operatorRead("logs.history", { serverName });
      expect(page.status).toBe(200);
      expect(JSON.stringify(page.data)).not.toContain("ZxQ-secret");

      // A person's session searches as before.
      const asPerson = await fx.trpc(
        "frontend.logs.history",
        { serverName, search: "ZxQ-secret-99" },
        "query",
        { cookie: fx.ownerCookie },
      );
      expect(asPerson.status).toBe(200);
      expect((asPerson.data as { data: unknown[] }).data).toHaveLength(1);
    });

    it("is not available to a sync-scope key", async () => {
      const reply = await operatorRead("logs.history", {}, fx.sync.key);
      expect(reply.code).toBe("FORBIDDEN");
    });
  });

  // ---------------------------------------------------------------------------
  describe("the operator contract", () => {
    it("reports contract 3, the procedure set and the confirmations remove needs", async () => {
      const reply = await operatorRead(
        "apiKeys.operatorCapabilities",
        undefined,
      );
      expect(reply.status).toBe(200);
      const caps = reply.data as {
        contract_version: number;
        procedures: string[];
        mutations: string[];
        confirmations: Record<string, string[]>;
      };
      expect(caps.contract_version).toBe(3);
      expect(caps.procedures).toEqual(
        expect.arrayContaining([
          "frontend.apiKeys.reactivate",
          "frontend.apiKeys.rename",
          "frontend.apiKeys.remove",
          "frontend.apiKeys.removalImpact",
          "frontend.mcpServers.resetErrors",
          "frontend.logs.history",
        ]),
      );
      expect(caps.procedures).toHaveLength(44);
      expect(caps.mutations).toHaveLength(25);
      expect(caps.mutations).not.toContain("frontend.apiKeys.removalImpact");
      expect(caps.confirmations).toEqual({
        "frontend.apiKeys.remove": ["confirm_name", "impact_fingerprint"],
      });
    });

    it("reads a removal's snapshot and fingerprint back through audit.list", async () => {
      const uuid = await dataKey({ stem: "rm-read" });
      const impact = (await operatorRead("apiKeys.removalImpact", { uuid }))
        .data as { name: string; impact_fingerprint: string };
      expect(
        (
          await operator("apiKeys.remove", {
            uuid,
            confirm_name: impact.name,
            impact_fingerprint: impact.impact_fingerprint,
          })
        ).status,
      ).toBe(200);
      const read = await operatorRead("audit.list", {
        action: "apikey.delete",
        target_id: uuid,
      });
      expect(read.status).toBe(200);
      const [row] = (
        read.data as {
          rows: Array<{
            detail: Record<string, unknown>;
            detail_omitted: number;
          }>;
        }
      ).rows;
      expect(row.detail).toMatchObject({
        via: "remove",
        impact_fingerprint: impact.impact_fingerprint,
        snapshot: { name: impact.name, is_active: false },
      });
      expect(row.detail_omitted).toBe(0);
    });
  });
});
