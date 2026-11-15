/**
 * The admin-plane rails against a real Postgres, through the real /trpc stack
 * (and, for the bootstrap and the account rails, the real implementations):
 *
 *  - the IP rail: an admin-plane key may only narrow an admin-plane key's
 *    policy and may not weaken the global one; two concurrent narrowings of
 *    one key are judged one after the other against the locked row;
 *  - the endpoint namespace gate for every writer, its admin-plane un-restrict
 *    rail and the provenance marker, the bootstrap, and the race between an
 *    open alias and a restriction in both orders;
 *  - the per-key change budget: totals and classes, a refusal written after
 *    the rollback, reads and no-ops free, and two requests contending for the
 *    last slot from separate connections;
 *  - leaf-only group delete for an admin-plane key;
 *  - the account rails: admin targets, admin-plane key owners, and the last
 *    enabled administrator under two concurrent disables;
 *  - audit.list and apiKeys.operatorCapabilities.
 *
 * Races use deterministic barriers: the test holds the lock the writers need
 * on a separate connection, waits until both requests are queued behind it,
 * then lets go. Postgres grants a queued lock in arrival order, so the first
 * request sent is the first served.
 */
import { randomBytes } from "node:crypto";

import { Client } from "pg";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

import {
  createFixture,
  DEFAULT_REASON,
  type Fixture,
} from "./admin-plane-integration-fixture";

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
    invalidateIdleServer: vi.fn().mockResolvedValue(undefined),
    invalidateIdleServers: vi.fn().mockResolvedValue(undefined),
    invalidateOpenApiSessions: vi.fn().mockResolvedValue(undefined),
  },
}));

type Reply = Awaited<ReturnType<Fixture["trpc"]>>;

describeIfDb("admin-plane rails (real Postgres)", () => {
  let fx: Fixture;
  let barrier: Client;
  let counter = 0;
  const uniq = (stem: string) => `${stem}-${++counter}-${fx.run}`;

  const one = async (sql: string, params: unknown[] = []) =>
    (await fx.suiteLock.query(sql, params)).rows;
  const operator = (procedure: string, input: unknown, key?: string) =>
    fx.trpc(`frontend.${procedure}`, input, "mutation", key ? { key } : {});
  const human = (procedure: string, input: unknown) =>
    fx.trpc(`frontend.${procedure}`, input, "mutation", {
      cookie: fx.ownerCookie,
    });
  const ok = (reply: Reply) =>
    reply.status === 200 &&
    (reply.data as { success?: boolean } | undefined)?.success !== false;

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
   * Hold `lock` (a statement run on the barrier connection) while `first` and
   * then `second` are sent, each queued behind it before the next is sent;
   * then release and return both replies in sending order.
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
    fx = await createFixture(TEST_DATABASE_URL as string, "rails");
    barrier = new Client({ connectionString: TEST_DATABASE_URL });
    await barrier.connect();
  });

  afterAll(async () => {
    await barrier?.end();
    await fx?.close();
  });

  // ---------------------------------------------------------------------------
  describe("the IP rail", () => {
    const policyOf = async (uuid: string) =>
      (
        await one(
          `SELECT allowed_cidrs, ip_policy_mode FROM api_keys WHERE uuid = $1`,
          [uuid],
        )
      )[0];
    const setCi = (allowed: string[] | null, mode: string) =>
      operator("apiKeys.setIpPolicy", {
        uuid: fx.sync.uuid,
        allowed_cidrs: allowed,
        ip_policy_mode: mode,
      });
    const resetCi = () =>
      one(
        `UPDATE api_keys SET allowed_cidrs = NULL, ip_policy_mode = 'off' WHERE uuid = $1`,
        [fx.sync.uuid],
      );

    it("lets an operator key narrow an admin-plane key and refuses every loosening, leaving a denied row and no change", async () => {
      try {
        expect((await setCi(["10.0.0.0/8"], "enforce")).status).toBe(200);
        for (const [allowed, mode] of [
          [["10.0.0.0/7"], "enforce"],
          [["10.0.0.0/8", "198.51.100.0/24"], "enforce"],
          [["0.0.0.0/0", "::/0"], "enforce"],
          [["10.0.0.0/8"], "audit"],
          [["10.0.0.0/8"], "off"],
          [null, "off"],
        ] as const) {
          const reply = await setCi(allowed ? [...allowed] : null, mode);
          expect({ allowed, mode, code: reply.code }).toEqual({
            allowed,
            mode,
            code: "FORBIDDEN",
          });
        }
        expect(await policyOf(fx.sync.uuid)).toEqual({
          allowed_cidrs: ["10.0.0.0/8"],
          ip_policy_mode: "enforce",
        });
        // Each refusal wrote its denied row after the rollback, awaited, so
        // it is there as soon as the reply is.
        const denied = await fx.auditNow(
          `action = 'apikey.ip_policy.set' AND outcome = 'denied' AND target_id = $1`,
          [fx.sync.uuid],
        );
        expect(denied.length).toBeGreaterThanOrEqual(6);
        expect(denied[0].detail).toMatchObject({
          reason: DEFAULT_REASON,
          admin_plane: { key_uuid: fx.operator.uuid },
        });
        // A human administrator is not held to the rail.
        expect(
          (
            await human("apiKeys.setIpPolicy", {
              uuid: fx.sync.uuid,
              allowed_cidrs: null,
              ip_policy_mode: "off",
            })
          ).status,
        ).toBe(200);
      } finally {
        await resetCi();
      }
    });

    it("judges two concurrent narrowings one after the other against the locked row", async () => {
      await one(
        `UPDATE api_keys SET allowed_cidrs = ARRAY['10.0.0.0/8'], ip_policy_mode = 'enforce' WHERE uuid = $1`,
        [fx.sync.uuid],
      );
      try {
        const [a, b] = await raceBehind(
          `BEGIN; SELECT 1 FROM api_keys WHERE uuid = '${fx.sync.uuid}' FOR UPDATE`,
          `COMMIT`,
          () => setCi(["10.0.0.0/9"], "enforce"),
          () => setCi(["10.128.0.0/9"], "enforce"),
        );
        // The first narrowed from the /8; the second was then judged against
        // the first's /9, which its other half is not inside.
        expect([a.status, b.code]).toEqual([200, "FORBIDDEN"]);
        expect(await policyOf(fx.sync.uuid)).toEqual({
          allowed_cidrs: ["10.0.0.0/9"],
          ip_policy_mode: "enforce",
        });
      } finally {
        await resetCi();
      }
    });

    it("refuses an operator key any weakening of the global policy, even with a list of its own", async () => {
      const restore = () =>
        one(
          `DELETE FROM config WHERE id IN ('API_KEY_IP_POLICY_MODE', 'API_KEY_IP_ALLOWED_CIDRS')`,
        );
      // The operator key gets a list of its own covering every test address.
      await one(
        `UPDATE api_keys SET allowed_cidrs = ARRAY['198.51.100.0/24','192.0.2.0/24','203.0.113.0/24'], ip_policy_mode = 'enforce' WHERE uuid = $1`,
        [fx.operator.uuid],
      );
      const global = (mode: string, cidrs: string[]) =>
        operator("apiKeys.setGlobalIpPolicy", { mode, allowed_cidrs: cidrs });
      try {
        expect((await global("enforce", ["203.0.113.0/24"])).status).toBe(200);
        for (const [mode, cidrs] of [
          ["enforce", ["203.0.112.0/23"]],
          ["enforce", ["0.0.0.0/0", "::/0"]],
          ["audit", ["203.0.113.0/24"]],
          ["off", []],
        ] as const) {
          const reply = await global(mode, [...cidrs]);
          expect({ mode, cidrs, code: reply.code }).toEqual({
            mode,
            cidrs,
            code: "FORBIDDEN",
          });
        }
        const [stored] = await one(
          `SELECT value FROM config WHERE id = 'API_KEY_IP_POLICY_MODE'`,
        );
        expect(stored.value).toBe("enforce");
        expect((await global("enforce", ["203.0.113.0/25"])).status).toBe(200);
        // A person's session may weaken it.
        expect(
          (
            await human("apiKeys.setGlobalIpPolicy", {
              mode: "off",
              allowed_cidrs: [],
            })
          ).status,
        ).toBe(200);
      } finally {
        await restore();
        await one(
          `UPDATE api_keys SET allowed_cidrs = NULL, ip_policy_mode = 'off' WHERE uuid = $1`,
          [fx.operator.uuid],
        );
      }
    });
  });

  // ---------------------------------------------------------------------------
  describe("the endpoint namespace gate", () => {
    const create = (
      who: "operator" | "human",
      name: string,
      namespaceUuid: string,
      over: Record<string, unknown> = {},
    ) =>
      (who === "operator" ? operator : human)("endpoints.create", {
        name,
        namespaceUuid,
        enableApiKeyAuth: true,
        enableMaxRate: false,
        enableClientMaxRate: false,
        enableOauth: false,
        user_id: null,
        createMcpServer: false,
        ...over,
      });
    const nameOf = async (uuid: string) =>
      (await one(`SELECT name FROM endpoints WHERE uuid = $1`, [uuid]))[0]
        .name as string;
    const move = async (
      who: "operator" | "human",
      uuid: string,
      namespaceUuid: string,
      name?: string,
    ) =>
      (who === "operator" ? operator : human)("endpoints.update", {
        uuid,
        name: name ?? (await nameOf(uuid)),
        namespaceUuid,
        enableApiKeyAuth: true,
        requireScopedApiKey: false,
        enableMaxRate: false,
        enableClientMaxRate: false,
        enableOauth: false,
      });
    const restrict = (
      who: "operator" | "human",
      endpoint_uuid: string,
      restricted: boolean,
    ) =>
      (who === "operator" ? operator : human)(
        "accessGroups.setEndpointRestricted",
        { endpoint_uuid, restricted },
      );
    const row = async (uuid: string) =>
      (
        await one(
          `SELECT name, namespace_uuid, restricted, restricted_by_api_key_uuid,
                  restricted_at IS NOT NULL AS stamped
             FROM endpoints WHERE uuid = $1`,
          [uuid],
        )
      )[0];
    const byName = async (name: string) =>
      (await one(`SELECT uuid FROM endpoints WHERE name = $1`, [name]))[0] as
        | { uuid: string }
        | undefined;
    const uuidOf = async (name: string) => {
      const found = await byName(name);
      if (!found) throw new Error(`no endpoint named ${name}`);
      return found.uuid;
    };

    it("refuses every writer an open endpoint over a guarded namespace, and allows a restricted one", async () => {
      const ns = await fx.namespace(uniq("guarded"));
      await fx.endpoint({
        name: uniq("guard"),
        restricted: true,
        namespaceUuid: ns,
      });

      for (const who of ["human", "operator"] as const) {
        const open = uniq(`open-${who}`);
        const reply = await create(who, open, ns);
        expect({ who, status: reply.status, code: reply.code }).toEqual({
          who,
          status: 409,
          code: "CONFLICT",
        });
        expect(await byName(open)).toBeUndefined();
        // A private endpoint is a route too.
        expect(
          (
            await create(who, uniq(`private-${who}`), ns, {
              user_id: undefined,
            })
          ).code,
        ).toBe("CONFLICT");
        const guarded = uniq(`restricted-${who}`);
        expect(ok(await create(who, guarded, ns, { restricted: true }))).toBe(
          true,
        );
        // Created restricted: stamped, but no key may roll it back.
        expect(await row(await uuidOf(guarded))).toMatchObject({
          restricted: true,
          restricted_by_api_key_uuid: null,
          stamped: true,
        });
      }
      const denied = await fx.auditNow(
        `action = 'endpoint.create' AND outcome = 'denied' AND actor_id = $1`,
        [fx.operator.uuid],
      );
      expect(denied.at(-1)?.detail).toMatchObject({
        rule: "namespace_restricted_create_open",
      });
    });

    it("refuses moving any endpoint, a restricted one included, onto a guarded namespace", async () => {
      const guardedNs = await fx.namespace(uniq("guarded-move"));
      await fx.endpoint({
        name: uniq("guard"),
        restricted: true,
        namespaceUuid: guardedNs,
      });
      const otherNs = await fx.namespace(uniq("other"));
      const mover = await fx.endpoint({
        name: uniq("mover"),
        restricted: true,
        namespaceUuid: otherNs,
      });
      for (const who of ["human", "operator"] as const) {
        const reply = await move(who, mover, guardedNs);
        expect({ who, code: reply.code }).toEqual({ who, code: "CONFLICT" });
      }
      expect((await row(mover)).namespace_uuid).toBe(otherNs);
    });

    it("judges an operator key's move of a restricted endpoint out of its namespace as opening that namespace", async () => {
      // The guard of a namespace moved out is the same loss of protection as
      // un-restricting it: afterwards an open create over the namespace would
      // be allowed. Refused unless another restricted endpoint stays behind or
      // the key's own recent restriction applies, exactly as for the literal
      // un-restrict.
      const source = await fx.namespace(uniq("move-out"));
      const target = await fx.namespace(uniq("move-out-target"));
      const guard = await fx.endpoint({
        name: uniq("guard"),
        restricted: true,
        namespaceUuid: source,
      });
      const refused = await move("operator", guard, target);
      expect({ status: refused.status, code: refused.code }).toEqual({
        status: 403,
        code: "FORBIDDEN",
      });
      expect(refused.message).toBe(
        "An admin-plane API key can open an endpoint only to roll back a restriction it made itself in the last 24 hours. Do this in the admin UI.",
      );
      expect((await row(guard)).namespace_uuid).toBe(source);
      const denied = await fx.auditNow(
        `action = 'endpoint.update' AND outcome = 'denied' AND target_id = $1`,
        [guard],
      );
      expect(denied.at(-1)?.detail).toMatchObject({
        rule: "admin_plane_unrestrict",
      });
      // The namespace is still guarded, so the follow-up open create over it
      // stays refused for the key and for a person.
      for (const who of ["operator", "human"] as const) {
        const open = uniq(`follow-up-${who}`);
        expect((await create(who, open, source)).code).toBe("CONFLICT");
        expect(await byName(open)).toBeUndefined();
      }
    });

    it("lets an operator key move a restricted endpoint out while another restricted endpoint keeps the namespace guarded", async () => {
      const source = await fx.namespace(uniq("move-out-pair"));
      const target = await fx.namespace(uniq("move-out-pair-target"));
      const stays = await fx.endpoint({
        name: uniq("stays"),
        restricted: true,
        namespaceUuid: source,
      });
      const leaves = await fx.endpoint({
        name: uniq("leaves"),
        restricted: true,
        namespaceUuid: source,
      });
      expect(ok(await move("operator", leaves, target))).toBe(true);
      expect((await row(leaves)).namespace_uuid).toBe(target);
      expect((await row(stays)).namespace_uuid).toBe(source);
      const open = uniq("follow-up");
      expect((await create("operator", open, source)).code).toBe("CONFLICT");
      expect(await byName(open)).toBeUndefined();
      // Now `stays` is the only guard left: it may not leave.
      const elsewhere = await fx.namespace(uniq("move-out-pair-elsewhere"));
      expect((await move("operator", stays, elsewhere)).code).toBe("FORBIDDEN");
      expect((await row(stays)).namespace_uuid).toBe(source);
    });

    it("lets an operator key move an open endpoint out of a namespace, and a person move any endpoint out", async () => {
      const source = await fx.namespace(uniq("move-out-open"));
      const target = await fx.namespace(uniq("move-out-open-target"));
      const open = await fx.endpoint({
        name: uniq("open"),
        namespaceUuid: source,
      });
      expect(ok(await move("operator", open, target))).toBe(true);
      expect((await row(open)).namespace_uuid).toBe(target);

      const guarded = await fx.namespace(uniq("move-out-person"));
      const away = await fx.namespace(uniq("move-out-person-target"));
      const guard = await fx.endpoint({
        name: uniq("guard"),
        restricted: true,
        namespaceUuid: guarded,
      });
      expect(ok(await move("human", guard, away))).toBe(true);
      expect((await row(guard)).namespace_uuid).toBe(away);
    });

    it("applies the key's own 24-hour provenance to a move out exactly as to un-restricting", async () => {
      const restrictedByKey = async (stem: string) => {
        const ns = await fx.namespace(uniq(stem));
        const ep = await fx.endpoint({ name: uniq(stem), namespaceUuid: ns });
        expect(ok(await restrict("operator", ep, true))).toBe(true);
        return { ns, ep };
      };

      // Its own fresh restriction: the move out is allowed and the marker goes
      // with it, so the key cannot roll the endpoint back over the new place.
      const fresh = await restrictedByKey("prov-fresh");
      const freshTarget = await fx.namespace(uniq("prov-fresh-target"));
      expect(ok(await move("operator", fresh.ep, freshTarget))).toBe(true);
      expect(await row(fresh.ep)).toMatchObject({
        namespace_uuid: freshTarget,
        restricted: true,
        restricted_by_api_key_uuid: null,
      });

      // Older than 24 hours: refused.
      const old = await restrictedByKey("prov-old");
      await one(
        `UPDATE endpoints SET restricted_at = now() - interval '25 hours' WHERE uuid = $1`,
        [old.ep],
      );
      const oldTarget = await fx.namespace(uniq("prov-old-target"));
      expect((await move("operator", old.ep, oldTarget)).code).toBe(
        "FORBIDDEN",
      );
      expect((await row(old.ep)).namespace_uuid).toBe(old.ns);

      // The key's restriction repeated by a person is the person's: refused.
      const taken = await restrictedByKey("prov-taken");
      expect(ok(await restrict("human", taken.ep, true))).toBe(true);
      const takenTarget = await fx.namespace(uniq("prov-taken-target"));
      expect((await move("operator", taken.ep, takenTarget)).code).toBe(
        "FORBIDDEN",
      );
      expect((await row(taken.ep)).namespace_uuid).toBe(taken.ns);
    });

    it("judges a move out against the source namespace as a person's concurrent move left it", async () => {
      // Two guards over one namespace, one moved out by a person while the
      // key moves the other: whichever commits first decides what the second
      // sees under the namespace lock.
      const source = await fx.namespace(uniq("move-race"));
      const targetA = await fx.namespace(uniq("move-race-a"));
      const targetB = await fx.namespace(uniq("move-race-b"));
      const personsGuard = await fx.endpoint({
        name: uniq("persons"),
        restricted: true,
        namespaceUuid: source,
      });
      const keysGuard = await fx.endpoint({
        name: uniq("keys"),
        restricted: true,
        namespaceUuid: source,
      });
      const lock = `SELECT pg_advisory_lock(hashtext('metamcp.endpoint.namespace'), hashtext('${source}'))`;
      const unlock = `SELECT pg_advisory_unlock(hashtext('metamcp.endpoint.namespace'), hashtext('${source}'))`;
      const [persons, keys] = await raceBehind(
        lock,
        unlock,
        () => move("human", personsGuard, targetA),
        () => move("operator", keysGuard, targetB),
      );
      expect(ok(persons)).toBe(true);
      expect(keys.code).toBe("FORBIDDEN");
      expect((await row(keysGuard)).namespace_uuid).toBe(source);
      expect((await row(personsGuard)).namespace_uuid).toBe(targetA);
    });

    it("refuses opening an endpoint while a sibling stays restricted, and lets a person open the last one", async () => {
      const ns = await fx.namespace(uniq("pair"));
      const a = await fx.endpoint({
        name: uniq("a"),
        restricted: true,
        namespaceUuid: ns,
      });
      const b = await fx.endpoint({
        name: uniq("b"),
        restricted: true,
        namespaceUuid: ns,
      });
      expect((await restrict("human", a, false)).code).toBe("CONFLICT");
      expect((await row(a)).restricted).toBe(true);
      await one(`DELETE FROM endpoints WHERE uuid = $1`, [b]);
      expect(ok(await restrict("human", a, false))).toBe(true);
      expect(await row(a)).toMatchObject({
        restricted: false,
        restricted_by_api_key_uuid: null,
        stamped: false,
      });
    });

    it("lets an operator key roll back only its own current restriction, within 24 hours", async () => {
      const ns = await fx.namespace(uniq("rollback"));
      const ep = await fx.endpoint({ name: uniq("ep"), namespaceUuid: ns });

      // Its own fresh transition: may be rolled back.
      expect(ok(await restrict("operator", ep, true))).toBe(true);
      expect(await row(ep)).toMatchObject({
        restricted_by_api_key_uuid: fx.operator.uuid,
        stamped: true,
      });
      expect(ok(await restrict("operator", ep, false))).toBe(true);

      // A person's restriction: refused, with a denied row.
      expect(ok(await restrict("human", ep, true))).toBe(true);
      const refused = await restrict("operator", ep, false);
      expect({ status: refused.status, code: refused.code }).toEqual({
        status: 403,
        code: "FORBIDDEN",
      });
      expect((await row(ep)).restricted).toBe(true);
      const denied = await fx.auditNow(
        `action = 'endpoint.restricted.set' AND outcome = 'denied' AND target_id = $1`,
        [ep],
      );
      expect(denied.at(-1)?.detail).toMatchObject({
        rule: "admin_plane_unrestrict",
      });
      await restrict("human", ep, false);

      // The key's restriction, repeated by a person: the marker is cleared and
      // the key's rollback is refused. Repeated by the key itself, nothing
      // changes and the rollback stays allowed.
      await restrict("operator", ep, true);
      await restrict("operator", ep, true);
      expect((await row(ep)).restricted_by_api_key_uuid).toBe(fx.operator.uuid);
      await restrict("human", ep, true);
      expect((await row(ep)).restricted_by_api_key_uuid).toBeNull();
      expect((await restrict("operator", ep, false)).code).toBe("FORBIDDEN");
      await restrict("human", ep, false);

      // Older than 24 hours: refused.
      await restrict("operator", ep, true);
      await one(
        `UPDATE endpoints SET restricted_at = now() - interval '25 hours' WHERE uuid = $1`,
        [ep],
      );
      expect((await restrict("operator", ep, false)).code).toBe("FORBIDDEN");
      await restrict("human", ep, false);

      // Moved to another namespace after the key restricted it: refused.
      await restrict("operator", ep, true);
      const elsewhere = await fx.namespace(uniq("elsewhere"));
      expect(ok(await move("operator", ep, elsewhere))).toBe(true);
      expect((await row(ep)).restricted_by_api_key_uuid).toBeNull();
      expect((await restrict("operator", ep, false)).code).toBe("FORBIDDEN");
    });

    it("refuses a move from a stale read as a retryable conflict", async () => {
      // Not raceable over HTTP without a hook, so the stale read is staged:
      // the endpoint is moved behind the pre-read by holding its namespace lock
      // while a second move queues, then the first commits a different move.
      const nsA = await fx.namespace(uniq("stale-a"));
      const nsB = await fx.namespace(uniq("stale-b"));
      const nsC = await fx.namespace(uniq("stale-c"));
      const ep = await fx.endpoint({ name: uniq("stale"), namespaceUuid: nsA });
      const epName = await nameOf(ep);
      const [first, second] = await raceBehind(
        `SELECT pg_advisory_lock(hashtext('metamcp.endpoint.namespace'), hashtext('${nsA}'))`,
        `SELECT pg_advisory_unlock(hashtext('metamcp.endpoint.namespace'), hashtext('${nsA}'))`,
        () => move("human", ep, nsB, epName),
        () => move("human", ep, nsC, epName),
      );
      expect(ok(first)).toBe(true);
      expect(second.code).toBe("CONFLICT");
      expect(second.message).toBe(
        "The endpoint changed while this request was applied. Read it again and retry.",
      );
      expect((await row(ep)).namespace_uuid).toBe(nsB);
    });

    it("orders a restriction and an open alias by the namespace lock, in both orders", async () => {
      const lockSql = (ns: string) =>
        `SELECT pg_advisory_lock(hashtext('metamcp.endpoint.namespace'), hashtext('${ns}'))`;
      const unlockSql = (ns: string) =>
        `SELECT pg_advisory_unlock(hashtext('metamcp.endpoint.namespace'), hashtext('${ns}'))`;

      // Restriction first: the alias that queued behind it is refused.
      const ns1 = await fx.namespace(uniq("race-1"));
      const e1 = await fx.endpoint({ name: uniq("e1"), namespaceUuid: ns1 });
      const alias1 = uniq("alias1");
      const [restricted1, alias1Reply] = await raceBehind(
        lockSql(ns1),
        unlockSql(ns1),
        () => restrict("human", e1, true),
        () => create("human", alias1, ns1),
      );
      expect(ok(restricted1)).toBe(true);
      expect(alias1Reply.code).toBe("CONFLICT");
      expect(await byName(alias1)).toBeUndefined();

      // Alias first: it is created, and the restriction (a tightening) is
      // still allowed. The gate is one-sided: it never repairs an open alias
      // that already exists, which is the caller's census to find.
      const ns2 = await fx.namespace(uniq("race-2"));
      const e2 = await fx.endpoint({ name: uniq("e2"), namespaceUuid: ns2 });
      const alias2 = uniq("alias2");
      const [alias2Reply, restricted2] = await raceBehind(
        lockSql(ns2),
        unlockSql(ns2),
        () => create("human", alias2, ns2),
        () => restrict("human", e2, true),
      );
      expect(ok(alias2Reply)).toBe(true);
      expect(ok(restricted2)).toBe(true);
    });

    it("keeps apply-groups' sequence: create restricted with no mapping, then map, and only members reach it", async () => {
      const ns = await fx.namespace(uniq("apply"));
      await fx.endpoint({
        name: uniq("guard"),
        restricted: true,
        namespaceUuid: ns,
      });
      const name = uniq("namesake");
      expect(ok(await create("operator", name, ns, { restricted: true }))).toBe(
        true,
      );
      const ep = await uuidOf(name);
      expect(
        await one(
          `SELECT count(*)::int AS n FROM access_group_endpoints WHERE endpoint_uuid = $1`,
          [ep],
        ),
      ).toEqual([{ n: 0 }]);
      const group = await fx.group({
        name: uniq("apply-g"),
        members: [fx.memberId],
      });
      expect(
        ok(
          await operator("accessGroups.addEndpoint", {
            group_uuid: group,
            endpoint_uuid: ep,
          }),
        ),
      ).toBe(true);
      const memberKey = await fx.dataKey({
        name: uniq("m"),
        ownerId: fx.memberId,
      });
      const outsiderKey = await fx.dataKey({
        name: uniq("o"),
        ownerId: fx.otherMemberId,
      });
      const adminKey = await fx.dataKey({
        name: uniq("a"),
        ownerId: fx.ownerId,
      });
      const serves = async (token: string) =>
        (
          await fx.authenticateKey({
            endpointUuid: ep,
            token,
            ip: "203.0.113.9",
          })
        ).next;
      expect(await serves(memberKey.key)).toBe(true);
      expect(await serves(adminKey.key)).toBe(true);
      expect(await serves(outsiderKey.key)).toBe(false);
    });

    it("holds the bootstrap to the gate in its own transaction, reporting a refused entry and writing nothing", async () => {
      const { applyBootstrapEndpoint } = await import(
        "../lib/bootstrap-endpoint-gate"
      );
      const guardedNs = await fx.namespace(uniq("boot-guarded"));
      await fx.endpoint({
        name: uniq("guard"),
        restricted: true,
        namespaceUuid: guardedNs,
      });
      const freeNs = await fx.namespace(uniq("boot-free"));
      const values = (name: string, namespace_uuid: string) => ({
        name,
        description: null,
        namespace_uuid,
        enable_api_key_auth: true,
        use_query_param_auth: false,
        enable_oauth: false,
        user_id: null,
        updated_at: new Date(),
      });
      const refusedName = uniq("boot-open");
      expect(
        await applyBootstrapEndpoint(values(refusedName, guardedNs), null),
      ).toEqual({
        status: "refused",
        rule: "namespace_restricted_create_open",
      });
      expect(await byName(refusedName)).toBeUndefined();

      const createdName = uniq("boot-free-ep");
      expect(
        await applyBootstrapEndpoint(values(createdName, freeNs), null),
      ).toEqual({ status: "created" });
      const created = await uuidOf(createdName);
      expect(
        await applyBootstrapEndpoint(values(createdName, guardedNs), created),
      ).toEqual({ status: "refused", rule: "namespace_restricted_move" });
      expect((await row(created)).namespace_uuid).toBe(freeNs);
    });
  });

  // ---------------------------------------------------------------------------
  describe("the per-key change budget", () => {
    const envNames = [
      "ADMIN_PLANE_BUDGET_OPERATOR_TOTAL",
      "ADMIN_PLANE_BUDGET_OPERATOR_LOOSEN",
      "ADMIN_PLANE_BUDGET_OPERATOR_DESTROY",
    ];
    const setBudget = (total: number, loosen: number, destroy: number) => {
      process.env.ADMIN_PLANE_BUDGET_OPERATOR_TOTAL = String(total);
      process.env.ADMIN_PLANE_BUDGET_OPERATOR_LOOSEN = String(loosen);
      process.env.ADMIN_PLANE_BUDGET_OPERATOR_DESTROY = String(destroy);
    };
    afterAll(() => {
      for (const name of envNames) process.env[name] = "100000";
    });

    async function freshOperatorKey() {
      const { ApiKeysRepository } = await import(
        "../db/repositories/api-keys.repo"
      );
      const created = await new ApiKeysRepository().create({
        name: uniq("budget-key"),
        user_id: fx.ownerId,
        admin_plane: true,
        admin_plane_scope: "operator",
        is_active: true,
      });
      return { key: created.key, uuid: created.uuid };
    }
    const spent = async (uuid: string) =>
      (
        await one(
          `SELECT count(*)::int AS n FROM audit_log
            WHERE actor_id = $1 AND outcome = 'success' AND detail ? 'budget_class'`,
          [uuid],
        )
      )[0].n as number;

    it("counts changes per key and class, refuses over budget before any change with a denied row, and charges nothing for reads, no-ops or refusals", async () => {
      setBudget(4, 1, 1);
      const k = await freshOperatorKey();
      const group = await fx.group({ name: uniq("budget-g") });

      // Loosen: one slot.
      expect(
        ok(
          await operator(
            "accessGroups.addMember",
            { group_uuid: group, user_id: fx.memberId },
            k.key,
          ),
        ),
      ).toBe(true);
      const loosened = await operator(
        "accessGroups.addMember",
        { group_uuid: group, user_id: fx.otherMemberId },
        k.key,
      );
      expect({ status: loosened.status, code: loosened.code }).toEqual({
        status: 429,
        code: "TOO_MANY_REQUESTS",
      });
      expect(
        await one(
          `SELECT count(*)::int AS n FROM access_group_members WHERE group_uuid = $1`,
          [group],
        ),
      ).toEqual([{ n: 1 }]);
      const denied = await fx.auditNow(
        `action = 'admin_plane.budget.exceeded' AND actor_id = $1`,
        [k.uuid],
      );
      expect(denied).toHaveLength(1);
      expect(denied[0]).toMatchObject({ outcome: "denied", target_id: k.uuid });
      expect(denied[0].detail).toMatchObject({
        budget_class: "loosen",
        limit: 1,
        reason: DEFAULT_REASON,
      });

      // A no-op (already a member) writes no row and costs nothing; a read
      // costs nothing; a refusal cost nothing.
      expect(
        ok(
          await operator(
            "accessGroups.addMember",
            { group_uuid: group, user_id: fx.memberId },
            k.key,
          ),
        ),
      ).toBe(true);
      expect(
        (
          await fx.trpc("frontend.accessGroups.list", undefined, "query", {
            key: k.key,
          })
        ).status,
      ).toBe(200);
      expect(await spent(k.uuid)).toBe(1);

      // A tighten and a change still fit the total.
      expect(
        ok(
          await operator(
            "accessGroups.removeMember",
            { group_uuid: group, user_id: fx.memberId },
            k.key,
          ),
        ),
      ).toBe(true);
      const made = await operator(
        "accessGroups.create",
        { name: uniq("budget-made") },
        k.key,
      );
      expect(ok(made)).toBe(true);
      const madeUuid = (made.data as { data: { uuid: string } }).data.uuid;
      // A destroy: one slot, and the fourth change in all.
      expect(
        ok(await operator("accessGroups.delete", { uuid: madeUuid }, k.key)),
      ).toBe(true);
      expect(await spent(k.uuid)).toBe(4);

      // The total is spent: refused before anything is written.
      const another = uniq("budget-over");
      const over = await operator(
        "accessGroups.create",
        { name: another },
        k.key,
      );
      expect(over.code).toBe("TOO_MANY_REQUESTS");
      expect(
        await one(`SELECT 1 FROM access_groups WHERE name = $1`, [another]),
      ).toHaveLength(0);
      expect(await spent(k.uuid)).toBe(4);
    });

    it("charges nothing for a change whose audit row could not be written", async () => {
      setBudget(4, 4, 4);
      const k = await freshOperatorKey();
      await fx.failAuditFor("group.create");
      try {
        const reply = await operator(
          "accessGroups.create",
          { name: uniq("fault") },
          k.key,
        );
        expect((reply.data as { success: boolean }).success).toBe(false);
      } finally {
        await fx.clearAuditFault("group.create");
      }
      expect(await spent(k.uuid)).toBe(0);
    });

    it("lets exactly one of two requests from separate connections spend the last slot", async () => {
      setBudget(1, 1, 1);
      const k = await freshOperatorKey();
      const a = uniq("slot-a");
      const b = uniq("slot-b");
      const [first, second] = await raceBehind(
        `SELECT pg_advisory_lock(hashtext('metamcp.admin_plane.budget'), hashtext('${k.uuid}'))`,
        `SELECT pg_advisory_unlock(hashtext('metamcp.admin_plane.budget'), hashtext('${k.uuid}'))`,
        () => operator("accessGroups.create", { name: a }, k.key),
        () => operator("accessGroups.create", { name: b }, k.key),
      );
      expect([ok(first), second.code]).toEqual([true, "TOO_MANY_REQUESTS"]);
      expect(
        await one(`SELECT 1 FROM access_groups WHERE name = $1`, [b]),
      ).toHaveLength(0);
      expect(await spent(k.uuid)).toBe(1);
    });
  });

  // ---------------------------------------------------------------------------
  describe("group delete", () => {
    it("is leaf-only for an operator key: refused while the group has a member or a mapping, with a denied row", async () => {
      const ep = await fx.endpoint({
        name: uniq("leaf-ep"),
        namespaceUuid: await fx.namespace(uniq("leaf")),
      });
      const withMember = await fx.group({
        name: uniq("with-member"),
        members: [fx.memberId],
      });
      const withMapping = await fx.group({
        name: uniq("with-mapping"),
        endpoints: [ep],
      });
      for (const uuid of [withMember, withMapping]) {
        const reply = await operator("accessGroups.delete", { uuid });
        expect({ status: reply.status, code: reply.code }).toEqual({
          status: 409,
          code: "CONFLICT",
        });
        expect(
          await one(`SELECT 1 FROM access_groups WHERE uuid = $1`, [uuid]),
        ).toHaveLength(1);
      }
      const denied = await fx.auditNow(
        `action = 'group.delete' AND outcome = 'denied' AND target_id = $1`,
        [withMember],
      );
      expect(denied[0].detail).toMatchObject({
        rule: "group_not_empty",
        members: 1,
        mappings: 0,
      });
      // A person's delete keeps its cascade.
      expect(
        ok(await human("accessGroups.delete", { uuid: withMapping })),
      ).toBe(true);
      expect(
        await one(
          `SELECT 1 FROM access_group_endpoints WHERE endpoint_uuid = $1`,
          [ep],
        ),
      ).toHaveLength(0);
    });
  });

  // ---------------------------------------------------------------------------
  describe("group delete against a grant being added", () => {
    it("waits for a member or mapping insert in flight, then refuses the delete with the group and the new row intact", async () => {
      // The delete counts what it would cascade to under a row lock on the
      // group: an insert whose foreign key check is already holding the group
      // row waits the delete out, so the delete sees the committed row. Without
      // that lock the count is read as it was before the insert committed, the
      // delete statement then waits for it and cascades it away, and the key's
      // delete succeeds over a grant it never saw.
      const ep = await fx.endpoint({
        name: uniq("barrier-ep"),
        namespaceUuid: await fx.namespace(uniq("barrier")),
      });
      const inserts = [
        {
          label: "member",
          insert: `INSERT INTO access_group_members (group_uuid, user_id) VALUES ($1, $2)`,
          other: fx.memberId,
          present: `SELECT 1 FROM access_group_members WHERE group_uuid = $1`,
        },
        {
          label: "mapping",
          insert: `INSERT INTO access_group_endpoints (group_uuid, endpoint_uuid) VALUES ($1, $2)`,
          other: ep,
          present: `SELECT 1 FROM access_group_endpoints WHERE group_uuid = $1`,
        },
      ];
      for (const step of inserts) {
        const group = await fx.group({ name: uniq(`barrier-${step.label}`) });
        const writer = new Client({ connectionString: TEST_DATABASE_URL });
        await writer.connect();
        let pending: Promise<Reply>;
        try {
          await writer.query("BEGIN");
          await writer.query(step.insert, [group, step.other]);
          pending = operator("accessGroups.delete", { uuid: group });
          await waitForLockWaiters(1);
          await writer.query("COMMIT");
        } catch (error) {
          await writer.query("ROLLBACK").catch(() => undefined);
          throw error;
        } finally {
          await writer.end();
        }
        const reply = await pending;
        expect({
          step: step.label,
          status: reply.status,
          code: reply.code,
        }).toEqual({ step: step.label, status: 409, code: "CONFLICT" });
        expect(
          await one(`SELECT 1 FROM access_groups WHERE uuid = $1`, [group]),
        ).toHaveLength(1);
        expect(await one(step.present, [group])).toHaveLength(1);
      }
    });
  });

  // ---------------------------------------------------------------------------
  describe("the before-state of an update", () => {
    const CREDENTIALS = {
      envOld: "SENTINEL-ENV-OLD-6e1b",
      envNew: "SENTINEL-ENV-NEW-41c8",
      headerOld: "SENTINEL-HDR-OLD-93ac",
      headerNew: "SENTINEL-HDR-NEW-5d07",
      bearerOld: "SENTINEL-BEARER-OLD-2d70",
      bearerNew: "SENTINEL-BEARER-NEW-8b3f",
      argOld: "SENTINEL-ARG-OLD-b514",
      argNew: "SENTINEL-ARG-NEW-17e9",
      urlOld: "sentinel-old-7c0e.example.test",
      urlNew: "sentinel-new-a3f6.example.test",
    };
    const serverUuids: string[] = [];
    let priorKek: string | undefined;

    beforeAll(() => {
      // The server's bearer token is encrypted at rest under this key.
      priorKek = process.env.M365_TOKEN_KEK;
      process.env.M365_TOKEN_KEK = randomBytes(32).toString("base64");
    });
    afterAll(async () => {
      if (priorKek === undefined) delete process.env.M365_TOKEN_KEK;
      else process.env.M365_TOKEN_KEK = priorKek;
      for (const uuid of serverUuids) {
        await one(`DELETE FROM mcp_servers WHERE uuid = $1`, [uuid]);
      }
    });

    const newServer = async () => {
      const name = uniq("bs-server");
      const [row] = await one(
        `INSERT INTO mcp_servers (name, type, url, args, env, headers, bearer_token)
         VALUES ($1, 'STREAMABLE_HTTP', $2, $3, $4::jsonb, $5::jsonb, $6)
         RETURNING uuid`,
        [
          name,
          `https://${CREDENTIALS.urlOld}/mcp`,
          [CREDENTIALS.argOld],
          JSON.stringify({ TOKEN: CREDENTIALS.envOld }),
          JSON.stringify({ Authorization: `Bearer ${CREDENTIALS.headerOld}` }),
          CREDENTIALS.bearerOld,
        ],
      );
      serverUuids.push(row.uuid as string);
      return { uuid: row.uuid as string, name };
    };

    /** The one success row of an action on a target, read through audit.list. */
    const rowThroughAuditList = async (action: string, targetId: string) => {
      const reply = await fx.trpc(
        "frontend.audit.list",
        { action, target_id: targetId, outcome: "success" },
        "query",
      );
      expect(reply.status).toBe(200);
      const rows = (
        reply.data as {
          rows: Array<{ detail: Record<string, unknown> }>;
        }
      ).rows;
      expect(rows).toHaveLength(1);
      return rows[0].detail;
    };

    it("records the previous value of each changed field of an endpoint update, a move included", async () => {
      const from = await fx.namespace(uniq("bs-from"));
      const to = await fx.namespace(uniq("bs-to"));
      const ep = await fx.endpoint({
        name: uniq("bs-ep"),
        namespaceUuid: from,
      });
      const name = await (async () =>
        (await one(`SELECT name FROM endpoints WHERE uuid = $1`, [ep]))[0]
          .name as string)();
      const reply = await operator("endpoints.update", {
        uuid: ep,
        name,
        description: "a described endpoint",
        namespaceUuid: to,
        enableApiKeyAuth: true,
        requireScopedApiKey: true,
        enableMaxRate: false,
        enableClientMaxRate: false,
        enableOauth: false,
      });
      expect(ok(reply)).toBe(true);
      const detail = await rowThroughAuditList("endpoint.update", ep);
      expect(detail).toMatchObject({
        changed_fields: [
          "description",
          "namespace_uuid",
          "require_scoped_api_key",
        ],
        old_value: {
          description: null,
          namespace_uuid: from,
          require_scoped_api_key: false,
        },
        new_value: {
          description: "a described endpoint",
          namespace_uuid: to,
          require_scoped_api_key: true,
        },
      });
      // A field the write left alone is not in the pair.
      expect(
        (detail.old_value as Record<string, unknown>).enable_oauth,
      ).toBeUndefined();
    });

    it("records the previous name, description and server list of a namespace update, the list compared as a set", async () => {
      const [a, b] = [await newServer(), await newServer()];
      const ns = await fx.namespace(uniq("bs-ns"));
      await one(
        `INSERT INTO namespace_server_mappings (namespace_uuid, mcp_server_uuid, status) VALUES ($1, $2, 'ACTIVE')`,
        [ns, a.uuid],
      );
      const before = (
        await one(`SELECT name FROM namespaces WHERE uuid = $1`, [ns])
      )[0].name as string;
      const renamed = uniq("bs-ns-renamed");
      expect(
        ok(
          await operator("namespaces.update", {
            uuid: ns,
            name: renamed,
            description: "now described",
            mcpServerUuids: [b.uuid, a.uuid],
          }),
        ),
      ).toBe(true);
      const detail = await rowThroughAuditList("namespace.update", ns);
      expect(detail).toMatchObject({
        changed_fields: ["description", "name", "server_uuids"],
        old_value: {
          name: before,
          description: null,
          server_uuids: [a.uuid],
        },
        new_value: {
          name: renamed,
          description: "now described",
          server_uuids: [a.uuid, b.uuid].sort(),
        },
      });

      // The same list in another order, and a list left out, change nothing.
      expect(
        ok(
          await operator("namespaces.update", {
            uuid: ns,
            name: renamed,
            description: "now described",
            mcpServerUuids: [a.uuid, b.uuid],
          }),
        ),
      ).toBe(true);
      expect(
        ok(
          await operator("namespaces.update", {
            uuid: ns,
            name: renamed,
            description: "now described",
          }),
        ),
      ).toBe(true);
      const rows = (
        await fx.trpc(
          "frontend.audit.list",
          { action: "namespace.update", target_id: ns, outcome: "success" },
          "query",
        )
      ).data as { rows: Array<{ detail: Record<string, unknown> }> };
      const noops = rows.rows.filter(
        (row) => (row.detail.changed_fields as string[]).length === 0,
      );
      expect(noops).toHaveLength(2);
    });

    it("records the previous name and description of an access group update", async () => {
      const group = await fx.group({ name: uniq("bs-group") });
      const before = (
        await one(`SELECT name FROM access_groups WHERE uuid = $1`, [group])
      )[0].name as string;
      const renamed = uniq("bs-group-renamed");
      expect(
        ok(
          await operator("accessGroups.update", {
            uuid: group,
            name: renamed,
            description: "who may read the books",
          }),
        ),
      ).toBe(true);
      expect(await rowThroughAuditList("group.update", group)).toMatchObject({
        changed_fields: ["description", "name"],
        old_value: { name: before, description: null },
        new_value: { name: renamed, description: "who may read the books" },
      });
    });

    it("records the previous status of a tool a namespace update turned off", async () => {
      const server = await newServer();
      const ns = await fx.namespace(uniq("bs-tool-ns"));
      const [tool] = await one(
        `INSERT INTO tools (name, mcp_server_uuid, tool_schema) VALUES ($1, $2, '{"type":"object"}'::jsonb) RETURNING uuid`,
        [uniq("bs-tool"), server.uuid],
      );
      await one(
        `INSERT INTO namespace_tool_mappings (namespace_uuid, tool_uuid, mcp_server_uuid, status) VALUES ($1, $2, $3, 'ACTIVE')`,
        [ns, tool.uuid, server.uuid],
      );
      expect(
        ok(
          await operator("namespaces.updateToolStatus", {
            namespaceUuid: ns,
            toolUuid: tool.uuid,
            serverUuid: server.uuid,
            status: "INACTIVE",
          }),
        ),
      ).toBe(true);
      expect(
        await rowThroughAuditList("namespace.tool_status", ns),
      ).toMatchObject({
        changed_fields: ["status"],
        old_value: { status: "ACTIVE" },
        new_value: { status: "INACTIVE" },
      });
    });

    it("names a changed server credential field and stores no credential value, old or new, in the row or its read-back", async () => {
      const server = await newServer();
      const reply = await operator("mcpServers.update", {
        uuid: server.uuid,
        name: server.name,
        description: "a described server",
        type: "STREAMABLE_HTTP",
        url: `https://${CREDENTIALS.urlNew}/mcp`,
        args: [CREDENTIALS.argNew],
        env: { TOKEN: CREDENTIALS.envNew },
        headers: { Authorization: `Bearer ${CREDENTIALS.headerNew}` },
        bearerToken: CREDENTIALS.bearerNew,
      });
      expect(ok(reply)).toBe(true);

      const detail = await rowThroughAuditList("mcpserver.update", server.uuid);
      expect(detail).toMatchObject({
        changed_fields: [
          "args",
          "bearer_token",
          "description",
          "env",
          "headers",
          "url",
        ],
        old_value: { description: null },
        new_value: { description: "a described server" },
      });
      // Only the plain field is a value; no credential field is in the pair.
      for (const pair of ["old_value", "new_value"] as const) {
        expect(Object.keys(detail[pair] as object)).toEqual(["description"]);
      }

      // The stored row, in full, and the read-back both hold no value.
      const [stored] = await one(
        `SELECT detail::text AS text FROM audit_log
          WHERE action = 'mcpserver.update' AND target_id = $1`,
        [server.uuid],
      );
      for (const value of Object.values(CREDENTIALS)) {
        expect(stored.text).not.toContain(value);
        expect(JSON.stringify(detail)).not.toContain(value);
      }
      // The ciphertext the bearer token is stored as is not recorded either.
      expect(stored.text).not.toContain("enc:v1");
    });

    it("records a credential field cleared as changed and an untouched credential as not", async () => {
      const server = await newServer();
      const reply = await operator("mcpServers.update", {
        uuid: server.uuid,
        name: server.name,
        type: "STREAMABLE_HTTP",
        url: `https://${CREDENTIALS.urlOld}/mcp`,
        clearBearerToken: true,
      });
      expect(ok(reply)).toBe(true);
      const detail = await rowThroughAuditList("mcpserver.update", server.uuid);
      expect(detail.changed_fields).toEqual(["bearer_token"]);
      expect(JSON.stringify(detail)).not.toContain(CREDENTIALS.bearerOld);
    });
  });

  // ---------------------------------------------------------------------------
  describe("the account rails", () => {
    const actorOf = async (adminPlane: boolean) => {
      const { auditActor } = await import("@repo/trpc");
      return auditActor({
        user: { id: fx.ownerId, email: "owner@example.test" },
        session: { id: "s" },
        ...(adminPlane
          ? {
              authOrigin: {
                kind: "admin_plane",
                key_uuid: fx.operator.uuid,
                owner_user_id: fx.ownerId,
                scope: "operator",
              },
            }
          : {}),
      } as never);
    };
    const addUser = async (role: "admin" | "member") => {
      const id = uniq(`user-${role}`);
      await fx.db.insert(fx.schema.usersTable).values({
        id,
        name: "itest",
        email: `${id}@example.test`,
        role,
      });
      return id;
    };

    it("refuses an admin-plane caller an administrator or an admin-plane key owner, and allows an ordinary member", async () => {
      const { usersImplementations } = await import("./users.impl");
      const key = await actorOf(true);
      const admin = await addUser("admin");
      const keyOwner = await addUser("member");
      await one(
        `INSERT INTO api_keys (name, key_hash, last4, user_id, admin_plane, admin_plane_scope, is_active)
         VALUES ($1, $2, 'abcd', $3, true, 'sync', true)`,
        [uniq("owned"), `itest-hash-${uniq("h")}`, keyOwner],
      );
      const plain = await addUser("member");
      try {
        for (const target of [admin, keyOwner]) {
          for (const call of [
            () =>
              usersImplementations.setDisabled(
                { user_id: target, disabled: true },
                fx.ownerId,
                key,
              ),
            () =>
              usersImplementations.revokeAccess(
                { user_id: target },
                fx.ownerId,
                key,
              ),
            () =>
              usersImplementations.delete({ user_id: target }, fx.ownerId, key),
          ]) {
            await expect(call()).rejects.toMatchObject({ code: "FORBIDDEN" });
          }
        }
        expect(
          await one(`SELECT disabled FROM users WHERE id = ANY($1)`, [
            [admin, keyOwner],
          ]),
        ).toEqual([{ disabled: false }, { disabled: false }]);
        expect(
          (
            await usersImplementations.setDisabled(
              { user_id: plain, disabled: true },
              fx.ownerId,
              key,
            )
          ).success,
        ).toBe(true);
      } finally {
        await one(`DELETE FROM users WHERE id = ANY($1)`, [
          [admin, keyOwner, plain],
        ]);
      }
    });

    it("never disables the last enabled administrator, even with two disables racing for the last two", async () => {
      const { usersImplementations } = await import("./users.impl");
      const person = await actorOf(false);
      const second = await addUser("admin");
      // Only the fixture's owner and `second` are enabled administrators for
      // the length of this case; any other left in the database by an earlier
      // run is set aside and restored.
      const others = (
        await one(
          `UPDATE users SET disabled = true
            WHERE role = 'admin' AND disabled = false AND id <> ALL($1) RETURNING id`,
          [[fx.ownerId, second]],
        )
      ).map((r) => r.id as string);
      try {
        await barrier.query(
          `BEGIN; SELECT 1 FROM users WHERE id = '${fx.ownerId}' FOR UPDATE`,
        );
        const a = usersImplementations
          .setDisabled({ user_id: second, disabled: true }, fx.ownerId, person)
          .then(
            (r) => r,
            (e) => e,
          );
        await waitForLockWaiters(1);
        const b = usersImplementations
          .setDisabled({ user_id: fx.ownerId, disabled: true }, second, person)
          .then(
            (r) => r,
            (e) => e,
          );
        await waitForLockWaiters(2);
        await barrier.query("COMMIT");
        const results = [await a, await b];
        const refused = results.filter(
          (r) => (r as { code?: string }).code === "CONFLICT",
        );
        expect(refused).toHaveLength(1);
        const enabled = await one(
          `SELECT id FROM users WHERE role = 'admin' AND disabled = false AND id = ANY($1)`,
          [[fx.ownerId, second]],
        );
        expect(enabled).toHaveLength(1);
        // Deleting the one left is refused too.
        const left = enabled[0].id as string;
        const actorId = left === fx.ownerId ? second : fx.ownerId;
        await expect(
          usersImplementations.delete({ user_id: left }, actorId, person),
        ).rejects.toMatchObject({ code: "CONFLICT" });
      } finally {
        await one(`UPDATE users SET disabled = false WHERE id = $1`, [
          fx.ownerId,
        ]);
        await one(`UPDATE users SET disabled = false WHERE id = ANY($1)`, [
          others,
        ]);
        await one(`DELETE FROM users WHERE id = $1`, [second]);
      }
    });

    it("re-checks a new admin-plane key's owner under its row lock: a disabled administrator gets none", async () => {
      const admin = await addUser("admin");
      await one(`UPDATE users SET disabled = true WHERE id = $1`, [admin]);
      try {
        const reply = await human("apiKeys.create", {
          name: uniq("owner-check"),
          admin_plane: true,
          user_id: admin,
        });
        expect(reply.code).toBe("FORBIDDEN");
        expect(
          await one(`SELECT 1 FROM api_keys WHERE user_id = $1`, [admin]),
        ).toHaveLength(0);
      } finally {
        await one(`DELETE FROM users WHERE id = $1`, [admin]);
      }
    });

    it("refuses the broad key procedures to an admin-plane caller even if one reached them", async () => {
      const { apiKeysImplementations } = await import("./api-keys.impl");
      const key = await actorOf(true);
      await expect(
        apiKeysImplementations.update(
          { uuid: fx.sync.uuid, is_active: true } as never,
          fx.ownerId,
          true,
          key,
        ),
      ).rejects.toMatchObject({ code: "FORBIDDEN" });
      await expect(
        apiKeysImplementations.delete(
          { uuid: fx.sync.uuid } as never,
          fx.ownerId,
          true,
          key,
        ),
      ).rejects.toMatchObject({ code: "FORBIDDEN" });
    });
  });

  // ---------------------------------------------------------------------------
  describe("the operator's verification reads", () => {
    it("reads its own audit rows through audit.list, paged with a stable cursor and whitelisted detail", async () => {
      await one(
        `INSERT INTO audit_log (actor_type, actor_id, action, outcome, detail)
         VALUES ('api_key', $1, 'itest.read', 'success', $2::jsonb)`,
        [
          fx.operator.uuid,
          JSON.stringify({ reason: "r", secret_value: "never" }),
        ],
      );
      for (let i = 0; i < 3; i += 1) {
        await one(
          `INSERT INTO audit_log (actor_type, actor_id, action, outcome) VALUES ('api_key', $1, 'itest.page', 'success')`,
          [fx.operator.uuid],
        );
      }
      const read = (input: unknown) =>
        fx.trpc("frontend.audit.list", input, "query");
      const first = await read({
        actor_id: fx.operator.uuid,
        action: "itest.page",
        limit: 2,
      });
      expect(first.status).toBe(200);
      const page1 = first.data as {
        rows: Array<{ uuid: string }>;
        next_cursor: unknown;
      };
      expect(page1.rows).toHaveLength(2);
      const second = await read({
        actor_id: fx.operator.uuid,
        action: "itest.page",
        limit: 2,
        cursor: page1.next_cursor,
      });
      const page2 = second.data as {
        rows: Array<{ uuid: string }>;
        next_cursor: unknown;
      };
      expect(page2.rows).toHaveLength(1);
      expect(page2.next_cursor).toBeNull();
      expect(
        new Set([...page1.rows, ...page2.rows].map((r) => r.uuid)).size,
      ).toBe(3);

      const detailed = await read({
        action: "itest.read",
        actor_id: fx.operator.uuid,
      });
      const row = (detailed.data as { rows: Array<Record<string, unknown>> })
        .rows[0];
      expect(row.detail).toEqual({ reason: "r" });
      expect(row.detail_omitted).toBe(1);
      expect(JSON.stringify(detailed.data)).not.toContain("never");

      // Not the sync scope's.
      expect(
        (
          await fx.trpc("frontend.audit.list", {}, "query", {
            key: fx.sync.key,
          })
        ).code,
      ).toBe("FORBIDDEN");
    });

    it("reports the operator contract from the gateway's own scope sets", async () => {
      const reply = await fx.trpc(
        "frontend.apiKeys.operatorCapabilities",
        undefined,
        "query",
      );
      expect(reply.status).toBe(200);
      const caps = reply.data as {
        contract_version: number;
        caller_scope: string;
        procedures: string[];
        mutations: string[];
        reason: { required_for_operator_scope: boolean };
      };
      // TEST-EDIT (key powers): the key powers raise the contract to 3 and the
      // operator set from 38 procedures (21 mutations) to 44 (25).
      expect(caps.contract_version).toBe(3);
      expect(caps.caller_scope).toBe("operator");
      expect(caps.procedures).toHaveLength(44);
      expect(caps.mutations).toHaveLength(25);
      expect(caps.reason.required_for_operator_scope).toBe(true);
      expect(
        (
          await fx.trpc(
            "frontend.apiKeys.operatorCapabilities",
            undefined,
            "query",
            { key: fx.sync.key },
          )
        ).code,
      ).toBe("FORBIDDEN");
    });

    it("refuses an operator change without a reason, and records the reason of one that has it", async () => {
      const name = uniq("reasonless");
      const refused = await fx.trpc(
        "frontend.accessGroups.create",
        { name },
        "mutation",
        { reason: null },
      );
      expect({ status: refused.status, code: refused.code }).toEqual({
        status: 400,
        code: "BAD_REQUEST",
      });
      expect(
        await one(`SELECT 1 FROM access_groups WHERE name = $1`, [name]),
      ).toHaveLength(0);
      const named = uniq("reasoned");
      const made = await fx.trpc(
        "frontend.accessGroups.create",
        { name: named, run_id: "itest-run-1" },
        "mutation",
        { reason: "standing up the reviewers group" },
      );
      const uuid = (made.data as { data: { uuid: string } }).data.uuid;
      const [row] = await fx.auditNow(
        `action = 'group.create' AND target_id = $1`,
        [uuid],
      );
      expect(row.detail).toMatchObject({
        reason: "standing up the reviewers group",
        run_id: "itest-run-1",
        budget_class: "change",
      });
      // The CI sync key may still change without one.
      expect(
        (
          await fx.trpc(
            "frontend.mcpServers.create",
            {
              name: uniq("sync-srv"),
              type: "STREAMABLE_HTTP",
              url: "http://backend.internal:8000/mcp",
              user_id: null,
            },
            "mutation",
            { key: fx.sync.key, reason: null },
          )
        ).status,
      ).toBe(200);
    });
  });
});
