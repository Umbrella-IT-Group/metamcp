/**
 * An operator-scope admin-plane key creating data-plane keys, on the real
 * /trpc stack against a REAL Postgres: the real router, bearer resolver,
 * createContext, implementations, repositories and audit writer. Only the MCP
 * connection pools are stubbed.
 *
 * The mint is a credential boundary, so the cases are the ways it could fail:
 *  - a refusal of any rule leaves no key and no success row, with one fixed
 *    sentence;
 *  - the key, its IP-policy columns and its single audit row are written in
 *    ONE transaction: a key insert that fails, or an audit insert that fails,
 *    leaves neither; concurrent creates of one name make one key and one row;
 *    an owner disable that races a create is serialized by the owner row lock;
 *  - a key created this way, driven through BOTH API-key authentication
 *    branches of the real middleware (API-key-only and OAuth-enabled
 *    endpoints), is admitted only from its list, only on its endpoint, and
 *    never reaches an endpoint its owner cannot reach through OAuth;
 *  - the raw value is stored as a hash, returned once, and appears in no audit
 *    row, no log line and no error.
 * The self-lockout rails and `apiKeys.deactivate` are exercised over the same
 * stack at the end, because they share its fixtures.
 *
 * Opt-in via TEST_DATABASE_URL, pointed at a disposable, migrated database:
 *
 *   cd apps/backend
 *   DATABASE_URL=<url> npx drizzle-kit migrate
 *   TEST_DATABASE_URL=<url> npx vitest run \
 *     src/trpc/api-key-mint.integration.test.ts
 *
 * The race cases wait for the database to report a blocked statement
 * (pg_stat_activity), never for a fixed time.
 */

import { createHash } from "node:crypto";

import type express from "express";
import { Client } from "pg";
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

type KeyView = {
  uuid: string;
  name: string;
  user_id: string | null;
  endpoint_uuid: string | null;
  acts_as_user_id: string | null;
  admin_plane: boolean;
  admin_plane_scope: string;
  is_active: boolean;
  allowed_cidrs: string[] | null;
  ip_policy_mode: string;
};

describeIfDb(
  "operator-scope key creating data-plane keys (real Postgres)",
  () => {
    let fx: Fixture;
    let mintCounter = 0;
    const mintedValues: string[] = [];
    const failureBodies: string[] = [];

    // Endpoints: public with API-key auth only, public with OAuth enabled too,
    // private to each member, and a restricted public one (which accepts
    // gateway-wide keys: `restricted` does not require scoped keys, so the
    // owner's groups decide what a key reaches there).
    let epPublic = "";
    let epPublicOauth = "";
    let epPrivateMember = "";
    let epPrivateOther = "";
    let epRestricted = "";

    const POLICY = { mode: "enforce", allowed_cidrs: ["203.0.113.0/24"] };
    const ALLOWED_IP = "203.0.113.9";
    const OUTSIDE_IP = "198.51.100.200";

    const nextName = () => `mint-${++mintCounter}-${fx.run}`;

    const mint = (
      over: Record<string, unknown> = {},
      options: { key?: string; cookie?: string } = {},
    ) =>
      fx.trpc(
        "frontend.apiKeys.create",
        {
          name: nextName(),
          user_id: fx.memberId,
          endpoint_uuid: epPublic,
          ip_policy: { ...POLICY },
          ...over,
        },
        "mutation",
        options,
      );

    async function listAllKeys(): Promise<KeyView[]> {
      const reply = await fx.trpc(
        "frontend.apiKeys.listAll",
        undefined,
        "query",
      );
      expect(reply.status).toBe(200);
      return (reply.data as { apiKeys: KeyView[] }).apiKeys;
    }

    async function count(table: "api_keys" | "audit_create") {
      const { rows } =
        table === "api_keys"
          ? await fx.suiteLock.query(`SELECT count(*)::int AS n FROM api_keys`)
          : await fx.suiteLock.query(
              `SELECT count(*)::int AS n FROM audit_log WHERE action = 'apikey.create' AND outcome = 'success'`,
            );
      return rows[0].n as number;
    }

    /** The key's value out of a successful mint, remembered for the leak check. */
    function valueOf(reply: { data: unknown }): string {
      const key = (reply.data as { key: string }).key;
      mintedValues.push(key);
      return key;
    }

    /** Assert a refusal: status, code, the sentence, and nothing written. */
    async function expectRefused(
      reply: Awaited<ReturnType<typeof mint>>,
      expected: { status: number; code: string; message?: string | RegExp },
    ) {
      failureBodies.push(JSON.stringify(reply));
      expect(reply.status).toBe(expected.status);
      expect(reply.code).toBe(expected.code);
      if (typeof expected.message === "string") {
        expect(reply.message).toBe(expected.message);
      } else if (expected.message) {
        expect(reply.message).toMatch(expected.message);
      }
    }

    type AuthResult = { next: boolean; status: number; body: unknown };

    async function authenticate(options: {
      endpointUuid: string;
      token: string;
      via?: "bearer" | "x-api-key";
      ip?: string | null;
    }): Promise<AuthResult> {
      const { authenticateApiKey } = await import(
        "../middleware/api-key-oauth.middleware"
      );
      const { endpointsRepository } = await import("../db/repositories");
      const endpoint = await endpointsRepository.findByUuid(
        options.endpointUuid,
      );
      const headers: Record<string, string> = {};
      if (options.via === "x-api-key") headers["x-api-key"] = options.token;
      else headers.authorization = `Bearer ${options.token}`;
      if (options.ip) headers["cf-connecting-ip"] = options.ip;
      const req = {
        headers,
        query: {},
        ip: "127.0.0.1",
        endpoint,
        protocol: "http",
        originalUrl: "/metamcp/x/mcp",
        path: "/mcp",
        method: "POST",
        get: () => undefined,
      } as unknown as express.Request;
      const result: AuthResult = { next: false, status: 0, body: undefined };
      const res = {
        status(code: number) {
          result.status = code;
          return res;
        },
        json(body: unknown) {
          result.body = body;
          return res;
        },
        send(body: unknown) {
          result.body = body;
          return res;
        },
        set: () => res,
        setHeader: () => res,
        header: () => res,
        end: () => res,
      } as unknown as express.Response;
      await authenticateApiKey(req, res, () => {
        result.next = true;
      });
      return result;
    }

    async function newKey(over: Record<string, unknown>): Promise<{
      key: string;
      uuid: string;
    }> {
      const reply = await mint(over);
      expect(reply.status).toBe(200);
      const key = valueOf(reply);
      return { key, uuid: (reply.data as { uuid: string }).uuid };
    }

    const GENERIC_403 =
      "This credential is not currently permitted to access this gateway.";

    /** Run a refused call and prove it wrote no key and no create row. */
    async function expectNothingWritten(call: () => Promise<void>) {
      const keysBefore = await count("api_keys");
      const auditBefore = await count("audit_create");
      await call();
      expect(await count("api_keys")).toBe(keysBefore);
      expect(await count("audit_create")).toBe(auditBefore);
    }

    beforeAll(async () => {
      fx = await createFixture(TEST_DATABASE_URL as string, "mint");
      epPublic = await fx.endpoint({ name: "ep-public" });
      epPublicOauth = await fx.endpoint({
        name: "ep-public-oauth",
        oauth: true,
      });
      epPrivateMember = await fx.endpoint({
        name: "ep-private-member",
        userId: fx.memberId,
      });
      epPrivateOther = await fx.endpoint({
        name: "ep-private-other",
        userId: fx.otherMemberId,
      });
      epRestricted = await fx.endpoint({
        name: "ep-restricted",
        restricted: true,
      });
    }, 90_000);

    afterAll(async () => {
      await fx?.close();
    });

    // -------------------------------------------------------------------------
    describe("a valid mint", () => {
      it("creates a locked, scoped, data-plane key that reads exactly as submitted", async () => {
        const name = nextName();
        const reply = await mint({
          name,
          ip_policy: {
            mode: "enforce",
            allowed_cidrs: ["203.0.113.0/24", "203.0.113.9", "2001:db8:1::/48"],
          },
        });

        expect(reply.status).toBe(200);
        const created = reply.data as {
          uuid: string;
          name: string;
          key: string;
          created_at: string;
        };
        expect(Object.keys(created).sort()).toEqual([
          "created_at",
          "key",
          "name",
          "uuid",
        ]);
        expect(created.key).toMatch(/^sk_mt_[A-Za-z0-9]{64}$/);
        valueOf(reply);

        const item = (await listAllKeys()).find((k) => k.uuid === created.uuid);
        expect(item).toMatchObject({
          name,
          user_id: fx.memberId,
          endpoint_uuid: epPublic,
          acts_as_user_id: null,
          admin_plane: false,
          admin_plane_scope: "sync",
          is_active: true,
          ip_policy_mode: "enforce",
          // Canonical, in the order submitted.
          allowed_cidrs: [
            "203.0.113.0/24",
            "203.0.113.9/32",
            "2001:db8:1::/48",
          ],
        });
      });

      it("stores the hash and the tail, never the value", async () => {
        const reply = await mint();
        expect(reply.status).toBe(200);
        const key = valueOf(reply);
        const uuid = (reply.data as { uuid: string }).uuid;

        const { rows } = await fx.suiteLock.query(
          `SELECT * FROM api_keys WHERE uuid = $1`,
          [uuid],
        );
        expect(rows).toHaveLength(1);
        expect(rows[0].key_hash).toBe(
          createHash("sha256").update(key).digest("hex"),
        );
        expect(rows[0].last4).toBe(key.slice(-4));
        expect(JSON.stringify(rows[0])).not.toContain(key);
      });

      it("writes the key's policy columns with the key and exactly one correctly attributed audit row, visible as soon as the call returns", async () => {
        const name = nextName();
        const reply = await mint({ name });
        const uuid = (reply.data as { uuid: string }).uuid;
        valueOf(reply);

        // No polling: the row was awaited inside the transaction.
        const rows = await fx.auditNow(
          `action = 'apikey.create' AND target_id = $1`,
          [uuid],
        );
        expect(rows).toHaveLength(1);
        expect(rows[0]).toMatchObject({
          actor_type: "api_key",
          actor_id: fx.operator.uuid,
          target_type: "api_key",
          outcome: "success",
        });
        expect(rows[0].detail).toEqual({
          name,
          owner_user_id: fx.memberId,
          endpoint_uuid: epPublic,
          all_endpoints: false,
          acts_as_user_id: null,
          key_admin_plane: false,
          key_admin_plane_scope: "sync",
          ip_policy: { mode: "enforce", allowed_cidrs: ["203.0.113.0/24"] },
          admin_plane: {
            key_uuid: fx.operator.uuid,
            owner_user_id: fx.ownerId,
            scope: "operator",
          },
        });

        const { rows: keyRows } = await fx.suiteLock.query(
          `SELECT allowed_cidrs, ip_policy_mode FROM api_keys WHERE uuid = $1`,
          [uuid],
        );
        expect(keyRows[0]).toEqual({
          allowed_cidrs: ["203.0.113.0/24"],
          ip_policy_mode: "enforce",
        });
      });

      it("creates a gateway-wide key with all_endpoints: true", async () => {
        const reply = await mint({
          endpoint_uuid: undefined,
          all_endpoints: true,
        });
        expect(reply.status).toBe(200);
        valueOf(reply);

        const item = (await listAllKeys()).find(
          (k) => k.uuid === (reply.data as { uuid: string }).uuid,
        );
        expect(item).toMatchObject({
          endpoint_uuid: null,
          admin_plane: false,
          admin_plane_scope: "sync",
          ip_policy_mode: "enforce",
        });
        // Deactivated again so the later pairing case sees a clean slate.
        await fx.trpc(
          "frontend.apiKeys.deactivate",
          { uuid: (reply.data as { uuid: string }).uuid },
          "mutation",
        );
      });

      it("lets the key's owner be the administrator whose key is asking, when named explicitly", async () => {
        const reply = await mint({ user_id: fx.ownerId });
        expect(reply.status).toBe(200);
        valueOf(reply);

        const item = (await listAllKeys()).find(
          (k) => k.uuid === (reply.data as { uuid: string }).uuid,
        );
        expect(item).toMatchObject({ user_id: fx.ownerId, admin_plane: false });
      });

      it("accepts IPv4 /24 and /32 and native IPv6 /48 and /128, and a mapped /120 and /128", async () => {
        for (const cidr of [
          "203.0.113.0/24",
          "203.0.113.7/32",
          "2001:db8:1::/48",
          "2001:db8:1::5/128",
          "::ffff:203.0.113.0/120",
          "::ffff:203.0.113.5/128",
        ]) {
          const reply = await mint({
            ip_policy: { mode: "enforce", allowed_cidrs: [cidr] },
          });
          expect({ cidr, status: reply.status }).toEqual({ cidr, status: 200 });
          valueOf(reply);
        }
      });
    });

    // -------------------------------------------------------------------------
    describe("every refusal leaves no key and no success row", () => {
      it("refuses a sync-scope key, and a missing key, with the standing sentence", async () => {
        await expectNothingWritten(async () => {
          await expectRefused(await mint({}, { key: fx.sync.key }), {
            status: 403,
            code: "FORBIDDEN",
            message: STANDING_REFUSAL,
          });
        });
      });

      it("refuses an operator whose owner has been demoted to a member", async () => {
        await fx.db
          .update(fx.schema.usersTable)
          .set({ role: "member" })
          .where(fx.eq(fx.schema.usersTable.id, fx.ownerId));
        try {
          await expectNothingWritten(async () => {
            const reply = await mint();
            // The admin gate or the impl's own check: either way, FORBIDDEN and
            // nothing written.
            expect(reply.status).toBe(403);
            expect(reply.code).toBe("FORBIDDEN");
          });
        } finally {
          await fx.db
            .update(fx.schema.usersTable)
            .set({ role: "admin" })
            .where(fx.eq(fx.schema.usersTable.id, fx.ownerId));
        }
      });

      const REFUSALS: Array<
        [string, () => Record<string, unknown>, number, string]
      > = [
        // With an endpoint beside it the input schema refuses first; without one
        // the request reaches the implementation, which refuses it as well. The
        // caller gets the rule's own code and sentence either way.
        ["admin_plane true", () => ({ admin_plane: true }), 403, "FORBIDDEN"],
        [
          "admin_plane true with nothing else to refuse it",
          () => ({ admin_plane: true, endpoint_uuid: undefined }),
          403,
          "FORBIDDEN",
        ],
        [
          "admin_plane true with an operator scope",
          () => ({ admin_plane: true, admin_plane_scope: "operator" }),
          403,
          "FORBIDDEN",
        ],
        [
          "a scope without admin_plane",
          () => ({ admin_plane_scope: "sync" }),
          403,
          "FORBIDDEN",
        ],
        [
          "an acts-as identity",
          () => ({ acts_as_user_id: fx.memberId }),
          403,
          "FORBIDDEN",
        ],
        [
          "an acts-as identity that is null",
          () => ({ acts_as_user_id: null }),
          403,
          "FORBIDDEN",
        ],
        [
          "an acts-as identity that is empty",
          () => ({ acts_as_user_id: "" }),
          403,
          "FORBIDDEN",
        ],
        [
          "a public (null) owner",
          () => ({ user_id: null }),
          400,
          "BAD_REQUEST",
        ],
        [
          "an omitted owner, which would default to the caller",
          () => ({ user_id: undefined }),
          400,
          "BAD_REQUEST",
        ],
        ["an empty owner", () => ({ user_id: "" }), 400, "BAD_REQUEST"],
        [
          "an owner that does not exist",
          () => ({ user_id: "no-such-user-id" }),
          400,
          "BAD_REQUEST",
        ],
        [
          "neither endpoint nor all_endpoints",
          () => ({ endpoint_uuid: undefined }),
          400,
          "BAD_REQUEST",
        ],
        [
          "both an endpoint and all_endpoints",
          () => ({ all_endpoints: true }),
          400,
          "BAD_REQUEST",
        ],
        [
          "an endpoint that does not exist",
          () => ({ endpoint_uuid: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" }),
          400,
          "BAD_REQUEST",
        ],
        [
          "a private endpoint (the owner's own)",
          () => ({ endpoint_uuid: epPrivateMember }),
          403,
          "FORBIDDEN",
        ],
        [
          "another user's private endpoint",
          () => ({ endpoint_uuid: epPrivateOther }),
          403,
          "FORBIDDEN",
        ],
        [
          // The owner is an ordinary member in no group mapped to it.
          "a restricted endpoint whose owner is in no mapped group",
          () => ({ endpoint_uuid: epRestricted }),
          403,
          "FORBIDDEN",
        ],
        ["an invalid name", () => ({ name: "bad/name" }), 400, "BAD_REQUEST"],
        ["no IP policy", () => ({ ip_policy: undefined }), 400, "BAD_REQUEST"],
        [
          "a policy in audit mode",
          () => ({
            ip_policy: { mode: "audit", allowed_cidrs: ["203.0.113.0/24"] },
          }),
          400,
          "BAD_REQUEST",
        ],
        [
          "a policy in off mode",
          () => ({
            ip_policy: { mode: "off", allowed_cidrs: ["203.0.113.0/24"] },
          }),
          400,
          "BAD_REQUEST",
        ],
        [
          "a policy that follows the global one (no list)",
          () => ({ ip_policy: { mode: "enforce" } }),
          400,
          "BAD_REQUEST",
        ],
        [
          "an empty list",
          () => ({ ip_policy: { mode: "enforce", allowed_cidrs: [] } }),
          400,
          "BAD_REQUEST",
        ],
        [
          "nine entries",
          () => ({
            ip_policy: {
              mode: "enforce",
              allowed_cidrs: Array.from(
                { length: 9 },
                (_v, i) => `203.0.113.${i}`,
              ),
            },
          }),
          400,
          "BAD_REQUEST",
        ],
        [
          "host bits set",
          () => ({
            ip_policy: { mode: "enforce", allowed_cidrs: ["203.0.113.5/24"] },
          }),
          400,
          "BAD_REQUEST",
        ],
        [
          "an IPv4 /23",
          () => ({
            ip_policy: { mode: "enforce", allowed_cidrs: ["203.0.112.0/23"] },
          }),
          400,
          "BAD_REQUEST",
        ],
        [
          "an IPv6 /47",
          () => ({
            ip_policy: { mode: "enforce", allowed_cidrs: ["2001:db8::/47"] },
          }),
          400,
          "BAD_REQUEST",
        ],
        [
          "0.0.0.0/0",
          () => ({
            ip_policy: { mode: "enforce", allowed_cidrs: ["0.0.0.0/0"] },
          }),
          400,
          "BAD_REQUEST",
        ],
        [
          "::/48, which contains the whole mapped range",
          () => ({ ip_policy: { mode: "enforce", allowed_cidrs: ["::/48"] } }),
          400,
          "BAD_REQUEST",
        ],
        [
          "::ffff:0:0/96",
          () => ({
            ip_policy: { mode: "enforce", allowed_cidrs: ["::ffff:0:0/96"] },
          }),
          400,
          "BAD_REQUEST",
        ],
        [
          "a mapped /119",
          () => ({
            ip_policy: {
              mode: "enforce",
              allowed_cidrs: ["::ffff:203.0.112.0/119"],
            },
          }),
          400,
          "BAD_REQUEST",
        ],
      ];

      it.each(REFUSALS)("refuses %s", async (_label, over, status, code) => {
        await expectNothingWritten(async () => {
          const reply = await mint(over());
          await expectRefused(reply, { status, code });
          // One fixed sentence, not the schema's JSON dump of its issues, and
          // nothing of the request is echoed back.
          expect(() => JSON.parse(reply.message ?? "")).toThrow();
          const text = JSON.stringify(reply);
          expect(text).not.toContain(fx.memberId);
          expect(text).not.toContain("no-such-user-id");
          expect(text).not.toContain("203.0.113.5/24");
        });
      });

      it("refuses with each rule's own fixed sentence, whatever the offending value", async () => {
        const a = await mint({ user_id: "owner-probe-alpha" });
        const b = await mint({ user_id: "owner-probe-beta" });

        expect(a.message).toBe(b.message);
        expect(a.message).not.toContain("alpha");
      });

      it("refuses a disabled owner, with the same sentence as a nonexistent one", async () => {
        await fx.db
          .update(fx.schema.usersTable)
          .set({ disabled: true })
          .where(fx.eq(fx.schema.usersTable.id, fx.otherMemberId));
        try {
          await expectNothingWritten(async () => {
            const disabled = await mint({ user_id: fx.otherMemberId });
            const missing = await mint({ user_id: "no-such-user-id" });
            await expectRefused(disabled, { status: 400, code: "BAD_REQUEST" });
            expect(disabled.message).toBe(missing.message);
          });
        } finally {
          await fx.db
            .update(fx.schema.usersTable)
            .set({ disabled: false })
            .where(fx.eq(fx.schema.usersTable.id, fx.otherMemberId));
        }
      });

      it("refuses while the global IP-policy kill switch is on, creating nothing", async () => {
        process.env.API_KEY_IP_POLICY_DISABLED = "true";
        try {
          await expectNothingWritten(async () => {
            const reply = await mint();
            await expectRefused(reply, { status: 403, code: "FORBIDDEN" });
          });
        } finally {
          delete process.env.API_KEY_IP_POLICY_DISABLED;
        }
      });

      it("allows a gateway-wide key for a member owner while endpoints are restricted, paired or not", async () => {
        // Oracle: reach is decided per request by the owner's groups, so the
        // pairing no longer blocks a gateway-wide mint; only an
        // administrator-role owner does (next test).
        const unpaired = await fx.endpoint({
          name: "ep-unpaired",
          restricted: true,
          requireScoped: false,
        });
        const paired = await fx.endpoint({
          name: "ep-paired",
          restricted: true,
          requireScoped: true,
        });
        try {
          for (const _ of [unpaired, paired]) {
            const accepted = await mint({
              endpoint_uuid: undefined,
              all_endpoints: true,
            });
            expect(accepted.status).toBe(200);
            valueOf(accepted);
            await fx.trpc(
              "frontend.apiKeys.deactivate",
              { uuid: (accepted.data as { uuid: string }).uuid },
              "mutation",
            );
          }
        } finally {
          for (const uuid of [unpaired, paired]) {
            await fx.db
              .delete(fx.schema.endpointsTable)
              .where(fx.eq(fx.schema.endpointsTable.uuid, uuid));
          }
        }
      });

      it("refuses a gateway-wide key for an administrator-role owner, with its own sentence, and creates nothing", async () => {
        await expectNothingWritten(async () => {
          const reply = await mint({
            user_id: fx.ownerId,
            endpoint_uuid: undefined,
            all_endpoints: true,
          });
          await expectRefused(reply, {
            status: 403,
            code: "FORBIDDEN",
            message:
              "A gateway-wide key cannot be created for an administrator, because it would reach every restricted endpoint. Scope the key to one endpoint, or create it in the admin UI.",
          });
        });
      });

      it("still allows an endpoint-scoped key for an administrator owner on an unrestricted endpoint", async () => {
        const reply = await mint({
          user_id: fx.ownerId,
          endpoint_uuid: epPublic,
        });
        expect(reply.status).toBe(200);
        valueOf(reply);
        await fx.trpc(
          "frontend.apiKeys.deactivate",
          { uuid: (reply.data as { uuid: string }).uuid },
          "mutation",
        );
      });

      it("refuses a name an owner's key already uses, an inactive key's name included, but not another owner's", async () => {
        const name = nextName();
        const first = await mint({ name });
        expect(first.status).toBe(200);
        valueOf(first);

        await expectNothingWritten(async () => {
          await expectRefused(await mint({ name }), {
            status: 400,
            code: "BAD_REQUEST",
          });
        });

        // Deactivated, the name is still taken: it is never reused.
        const deactivated = await fx.trpc(
          "frontend.apiKeys.deactivate",
          { uuid: (first.data as { uuid: string }).uuid },
          "mutation",
        );
        expect(deactivated.status).toBe(200);
        await expectNothingWritten(async () => {
          await expectRefused(await mint({ name }), {
            status: 400,
            code: "BAD_REQUEST",
          });
        });

        // Another owner may use it (the constraint is per owner).
        const other = await mint({ name, user_id: fx.otherMemberId });
        expect(other.status).toBe(200);
        valueOf(other);
      });

      it("does not let a member session create a key, with or without a policy", async () => {
        await expectNothingWritten(async () => {
          const reply = await mint({}, { cookie: fx.memberCookie });
          expect(reply.status).toBe(403);
          const bare = await fx.trpc(
            "frontend.apiKeys.create",
            { name: nextName(), all_endpoints: true },
            "mutation",
            { cookie: fx.memberCookie },
          );
          expect(bare.status).toBe(403);
        });
      });
    });

    // -------------------------------------------------------------------------
    describe("the human session's create is unchanged except for the optional policy and scope", () => {
      it("creates a data-plane key without a policy, following the global one", async () => {
        const name = nextName();
        const reply = await fx.trpc(
          "frontend.apiKeys.create",
          { name, all_endpoints: true },
          "mutation",
          { cookie: fx.ownerCookie },
        );
        expect(reply.status).toBe(200);
        valueOf(reply);

        const item = (await listAllKeys()).find((k) => k.name === name);
        expect(item).toMatchObject({
          admin_plane: false,
          admin_plane_scope: "sync",
          allowed_cidrs: null,
          ip_policy_mode: "off",
        });
        const rows = await fx.auditNow(
          `action = 'apikey.create' AND target_id = $1`,
          [(reply.data as { uuid: string }).uuid],
        );
        // The human path keeps the best-effort row (`emit`), so poll for it.
        expect(
          rows.length === 1 ||
            (
              await fx.auditEventually(
                `action = 'apikey.create' AND target_id = $1`,
                [(reply.data as { uuid: string }).uuid],
              )
            ).length === 1,
        ).toBe(true);
      });

      it.each(["sync", "operator"] as const)(
        "creates an admin-plane key of scope %s",
        async (scope) => {
          const name = nextName();
          const reply = await fx.trpc(
            "frontend.apiKeys.create",
            { name, admin_plane: true, admin_plane_scope: scope },
            "mutation",
            { cookie: fx.ownerCookie },
          );
          expect(reply.status).toBe(200);
          valueOf(reply);

          expect(
            (await listAllKeys()).find((k) => k.name === name),
          ).toMatchObject({
            admin_plane: true,
            admin_plane_scope: scope,
          });
        },
      );

      it("defaults an admin-plane key to sync when no scope is chosen", async () => {
        const name = nextName();
        const reply = await fx.trpc(
          "frontend.apiKeys.create",
          { name, admin_plane: true },
          "mutation",
          { cookie: fx.ownerCookie },
        );
        expect(reply.status).toBe(200);
        valueOf(reply);

        expect(
          (await listAllKeys()).find((k) => k.name === name),
        ).toMatchObject({
          admin_plane: true,
          admin_plane_scope: "sync",
        });
      });

      it("accepts the optional policy and stores it with the key", async () => {
        const name = nextName();
        const reply = await fx.trpc(
          "frontend.apiKeys.create",
          {
            name,
            all_endpoints: true,
            ip_policy: { mode: "enforce", allowed_cidrs: ["10.0.0.0/8"] },
          },
          "mutation",
          { cookie: fx.ownerCookie },
        );
        expect(reply.status).toBe(200);
        valueOf(reply);

        expect(
          (await listAllKeys()).find((k) => k.name === name),
        ).toMatchObject({
          allowed_cidrs: ["10.0.0.0/8"],
          ip_policy_mode: "enforce",
        });
      });
    });

    // -------------------------------------------------------------------------
    describe("the transaction", () => {
      it("leaves neither a key nor an audit row when the key INSERT fails", async () => {
        const name = nextName();
        await fx.failKeyInsertFor(name);
        try {
          const reply = await mint({ name });
          failureBodies.push(JSON.stringify(reply));

          expect(reply.status).toBe(500);
          expect(reply.message).toBe("Internal server error");
        } finally {
          await fx.clearKeyInsertFault();
        }

        const { rows } = await fx.suiteLock.query(
          `SELECT count(*)::int AS n FROM api_keys WHERE name = $1`,
          [name],
        );
        expect(rows[0].n).toBe(0);
        expect(
          await fx.auditNow(
            `action = 'apikey.create' AND detail->>'name' = $1`,
            [name],
          ),
        ).toHaveLength(0);
      });

      it("leaves neither a key nor an audit row when the audit INSERT fails", async () => {
        const name = nextName();
        await fx.failAuditFor("apikey.create");
        try {
          const reply = await mint({ name });
          failureBodies.push(JSON.stringify(reply));

          expect(reply.status).toBe(500);
        } finally {
          await fx.clearAuditFault("apikey.create");
        }

        const { rows } = await fx.suiteLock.query(
          `SELECT count(*)::int AS n FROM api_keys WHERE name = $1`,
          [name],
        );
        expect(rows[0].n).toBe(0);
        expect(
          await fx.auditNow(
            `action = 'apikey.create' AND detail->>'name' = $1`,
            [name],
          ),
        ).toHaveLength(0);

        // And the same request succeeds once the fault is cleared: nothing was
        // reserved, and nothing retried on its own.
        const retry = await mint({ name });
        expect(retry.status).toBe(200);
        valueOf(retry);
      });

      it("makes one key and one create row out of concurrent creates of one name", async () => {
        const name = nextName();
        const replies = await Promise.all(
          Array.from({ length: 6 }, () => mint({ name })),
        );

        const accepted = replies.filter((r) => r.status === 200);
        const refused = replies.filter((r) => r.status !== 200);
        expect(accepted).toHaveLength(1);
        valueOf(accepted[0]);
        for (const reply of refused) {
          // The unique constraint's race is translated into the fixed refusal.
          expect({ status: reply.status, code: reply.code }).toEqual({
            status: 400,
            code: "BAD_REQUEST",
          });
          expect(reply.message).toBe(refused[0].message);
        }
        const { rows } = await fx.suiteLock.query(
          `SELECT count(*)::int AS n FROM api_keys WHERE name = $1`,
          [name],
        );
        expect(rows[0].n).toBe(1);
        expect(
          await fx.auditNow(
            `action = 'apikey.create' AND detail->>'name' = $1`,
            [name],
          ),
        ).toHaveLength(1);
      });

      async function waitForBlocked(fragment: string): Promise<void> {
        const deadline = Date.now() + 10_000;
        for (;;) {
          const { rows } = await fx.suiteLock.query(
            `SELECT 1 FROM pg_stat_activity
            WHERE wait_event_type = 'Lock' AND query ILIKE $1`,
            [`%${fragment}%`],
          );
          if (rows.length > 0) return;
          if (Date.now() > deadline) {
            throw new Error(`no statement blocked on a lock like ${fragment}`);
          }
          await new Promise((resolve) => setTimeout(resolve, 10));
        }
      }

      it("refuses a create whose owner was disabled before the owner row lock was granted", async () => {
        const locker = new Client({ connectionString: TEST_DATABASE_URL });
        await locker.connect();
        try {
          await locker.query("BEGIN");
          await locker.query(`UPDATE users SET disabled = true WHERE id = $1`, [
            fx.otherMemberId,
          ]);
          // The create runs and waits on the owner row, which is locked by the
          // uncommitted disable.
          const pending = mint({ user_id: fx.otherMemberId });
          await waitForBlocked('from "users"');
          await locker.query("COMMIT");

          const reply = await pending;
          await expectRefused(reply, { status: 400, code: "BAD_REQUEST" });
          const { rows } = await fx.suiteLock.query(
            `SELECT count(*)::int AS n FROM api_keys WHERE user_id = $1`,
            [fx.otherMemberId],
          );
          // Only the key from the name-reuse case, none from this create.
          expect(
            (
              await fx.auditNow(
                `action = 'apikey.create' AND detail->>'owner_user_id' = $1 AND outcome = 'success'`,
                [fx.otherMemberId],
              )
            ).length,
          ).toBe(rows[0].n);
        } finally {
          await locker.query("ROLLBACK").catch(() => undefined);
          await locker.end();
          await fx.db
            .update(fx.schema.usersTable)
            .set({ disabled: false })
            .where(fx.eq(fx.schema.usersTable.id, fx.otherMemberId));
        }
      });

      it("holds a concurrent owner disable until the create has committed", async () => {
        const blockEndpoint = new Client({
          connectionString: TEST_DATABASE_URL,
        });
        const disabler = new Client({ connectionString: TEST_DATABASE_URL });
        await blockEndpoint.connect();
        await disabler.connect();
        let disableDone = false;
        try {
          // Hold the endpoint row so the create stalls AFTER it took the owner
          // row lock (the owner is checked first).
          await blockEndpoint.query("BEGIN");
          await blockEndpoint.query(
            `SELECT 1 FROM endpoints WHERE uuid = $1 FOR UPDATE`,
            [epPublic],
          );
          const name = nextName();
          const pendingMint = mint({ name, user_id: fx.otherMemberId });
          await waitForBlocked('from "endpoints"');

          const pendingDisable = disabler
            .query(`UPDATE users SET disabled = true WHERE id = $1`, [
              fx.otherMemberId,
            ])
            .then(() => {
              disableDone = true;
            });
          // The disable is waiting on the create's lock on the owner row.
          await waitForBlocked("update users set disabled");
          expect(disableDone).toBe(false);

          await blockEndpoint.query("COMMIT");
          const reply = await pendingMint;
          await pendingDisable;

          // The create committed against an enabled owner; the disable followed.
          expect(reply.status).toBe(200);
          valueOf(reply);
          const { rows } = await fx.suiteLock.query(
            `SELECT disabled FROM users WHERE id = $1`,
            [fx.otherMemberId],
          );
          expect(rows[0].disabled).toBe(true);
        } finally {
          await blockEndpoint.query("ROLLBACK").catch(() => undefined);
          await blockEndpoint.end();
          await disabler.end();
          await fx.db
            .update(fx.schema.usersTable)
            .set({ disabled: false })
            .where(fx.eq(fx.schema.usersTable.id, fx.otherMemberId));
        }
      });
    });

    // -------------------------------------------------------------------------
    describe("a created key through both API-key authentication branches of the real middleware", () => {
      it.each([
        ["an API-key-only endpoint", "public", "bearer"],
        ["an API-key-only endpoint", "public", "x-api-key"],
        ["an OAuth-enabled endpoint", "oauth", "bearer"],
        ["an OAuth-enabled endpoint", "oauth", "x-api-key"],
      ] as const)(
        "on %s (%s, sent as %s): admitted from the list, refused outside it and with no address",
        async (_label, which, via) => {
          const endpointUuid = which === "public" ? epPublic : epPublicOauth;
          const { key } = await newKey({ endpoint_uuid: endpointUuid });

          const inside = await authenticate({
            endpointUuid,
            token: key,
            via,
            ip: ALLOWED_IP,
          });
          expect(inside.next).toBe(true);

          for (const ip of [OUTSIDE_IP, null]) {
            const refused = await authenticate({
              endpointUuid,
              token: key,
              via,
              ip,
            });
            expect({ ip, next: refused.next, status: refused.status }).toEqual({
              ip,
              next: false,
              status: 403,
            });
            expect((refused.body as { message: string }).message).toBe(
              GENERIC_403,
            );
          }
        },
      );

      it("refuses a scoped key on another endpoint, from an allowed address, on both branches", async () => {
        const { key } = await newKey({ endpoint_uuid: epPublic });

        for (const endpointUuid of [
          epPublicOauth,
          epPrivateMember,
          epRestricted,
        ]) {
          const refused = await authenticate({
            endpointUuid,
            token: key,
            ip: ALLOWED_IP,
          });
          expect({
            endpointUuid,
            next: refused.next,
            status: refused.status,
          }).toEqual({
            endpointUuid,
            next: false,
            status: 403,
          });
        }
      });

      it("never reaches an endpoint its owner cannot reach through OAuth: gateway-wide and scoped keys against every endpoint kind", async () => {
        const gatewayWide = await newKey({
          endpoint_uuid: undefined,
          all_endpoints: true,
        });
        const scoped = await newKey({ endpoint_uuid: epPublic });

        // The owner is an ordinary member in no group. Oracle: OAuth reach is
        // public endpoints for any authenticated user, a private endpoint for its
        // owner only, and a restricted endpoint for administrators and group
        // members only (plan, foreman decision 1).
        const ownerOAuthReach = (e: {
          uuid: string;
          owner: string | null;
          restricted: boolean;
        }) => (e.owner === null ? !e.restricted : e.owner === fx.memberId);
        const endpoints = [
          { uuid: epPublic, owner: null, restricted: false },
          { uuid: epPublicOauth, owner: null, restricted: false },
          { uuid: epPrivateMember, owner: fx.memberId, restricted: false },
          { uuid: epPrivateOther, owner: fx.otherMemberId, restricted: false },
          { uuid: epRestricted, owner: null, restricted: true },
        ];

        const reached: Record<string, string[]> = {
          gatewayWide: [],
          scoped: [],
        };
        for (const e of endpoints) {
          for (const [name, token] of [
            ["gatewayWide", gatewayWide.key],
            ["scoped", scoped.key],
          ] as const) {
            const result = await authenticate({
              endpointUuid: e.uuid,
              token,
              ip: ALLOWED_IP,
            });
            if (result.next) {
              reached[name].push(e.uuid);
              // The invariant: a created key reaches only what its owner can.
              expect({
                name,
                endpoint: e.uuid,
                ownerReaches: ownerOAuthReach(e),
              }).toEqual({ name, endpoint: e.uuid, ownerReaches: true });
            }
          }
        }
        // And the concrete reach: a gateway-wide key reaches the public
        // unrestricted endpoints and the owner's own private one, and not
        // another user's private one nor the restricted one (the owner is in no
        // mapped group, so the owner rule refuses it); a scoped key reaches its
        // one endpoint.
        expect(reached.gatewayWide.sort()).toEqual(
          [epPublic, epPublicOauth, epPrivateMember].sort(),
        );
        expect(reached.scoped).toEqual([epPublic]);
      });

      it("denies a key's subsequent use once its owner is disabled, on both branches", async () => {
        const { key } = await newKey({ endpoint_uuid: epPublic });
        const oauthKey = await newKey({ endpoint_uuid: epPublicOauth });
        expect(
          (
            await authenticate({
              endpointUuid: epPublic,
              token: key,
              ip: ALLOWED_IP,
            })
          ).next,
        ).toBe(true);

        await fx.db
          .update(fx.schema.usersTable)
          .set({ disabled: true })
          .where(fx.eq(fx.schema.usersTable.id, fx.memberId));
        try {
          for (const [endpointUuid, token] of [
            [epPublic, key],
            [epPublicOauth, oauthKey.key],
          ] as const) {
            const refused = await authenticate({
              endpointUuid,
              token,
              ip: ALLOWED_IP,
            });
            expect({
              endpointUuid,
              next: refused.next,
              status: refused.status,
            }).toEqual({
              endpointUuid,
              next: false,
              status: 403,
            });
          }
        } finally {
          await fx.db
            .update(fx.schema.usersTable)
            .set({ disabled: false })
            .where(fx.eq(fx.schema.usersTable.id, fx.memberId));
        }
      });

      it("denies a deactivated key on both branches, and never serves it as an admin-plane credential", async () => {
        const { key, uuid } = await newKey({ endpoint_uuid: epPublic });
        const deactivated = await fx.trpc(
          "frontend.apiKeys.deactivate",
          { uuid },
          "mutation",
        );
        expect(deactivated.status).toBe(200);

        for (const endpointUuid of [epPublic, epPublicOauth]) {
          const refused = await authenticate({
            endpointUuid,
            token: key,
            ip: ALLOWED_IP,
          });
          expect(refused.next).toBe(false);
          expect(refused.status).toBe(401);
        }

        // A created key is a data-plane key: as a /trpc bearer it is refused
        // (401), so it cannot reach any control-plane procedure.
        const active = await newKey({ endpoint_uuid: epPublic });
        const asBearer = await fx.trpc(
          "frontend.mcpServers.list",
          undefined,
          "query",
          {
            key: active.key,
          },
        );
        expect(asBearer.status).toBe(401);
      });
    });

    // -------------------------------------------------------------------------
    describe("apiKeys.deactivate", () => {
      const deactivate = (
        uuid: string,
        options: { key?: string; cookie?: string } = {},
      ) =>
        fx.trpc("frontend.apiKeys.deactivate", { uuid }, "mutation", options);

      async function victim(): Promise<string> {
        const reply = await mint();
        expect(reply.status).toBe(200);
        valueOf(reply);
        return (reply.data as { uuid: string }).uuid;
      }

      it("deactivates another key with one apikey.revoke row carrying the operator scope", async () => {
        const uuid = await victim();

        const reply = await deactivate(uuid);

        expect(reply.status).toBe(200);
        expect(reply.data).toMatchObject({
          uuid,
          is_active: false,
          changed: true,
        });
        const rows = await fx.auditNow(
          `action = 'apikey.revoke' AND target_id = $1`,
          [uuid],
        );
        expect(rows).toHaveLength(1);
        expect(rows[0]).toMatchObject({
          actor_type: "api_key",
          actor_id: fx.operator.uuid,
        });
        expect(rows[0].detail).toMatchObject({
          via: "deactivate",
          is_active: false,
          admin_plane: { key_uuid: fx.operator.uuid, scope: "operator" },
        });
        const { rows: keyRows } = await fx.suiteLock.query(
          `SELECT is_active FROM api_keys WHERE uuid = $1`,
          [uuid],
        );
        expect(keyRows[0].is_active).toBe(false);
      });

      it("refuses the calling key in any spelling and writes nothing", async () => {
        for (const spelling of [
          fx.operator.uuid,
          fx.operator.uuid.toUpperCase(),
        ]) {
          const reply = await deactivate(spelling);
          expect({ status: reply.status, code: reply.code }).toEqual({
            status: 400,
            code: "BAD_REQUEST",
          });
        }
        const { rows } = await fx.suiteLock.query(
          `SELECT is_active FROM api_keys WHERE uuid = $1`,
          [fx.operator.uuid],
        );
        expect(rows[0].is_active).toBe(true);
      });

      it("returns changed: false for an inactive key and records no second row", async () => {
        const uuid = await victim();
        await deactivate(uuid);

        const again = await deactivate(uuid);

        expect(again.status).toBe(200);
        expect(again.data).toMatchObject({ changed: false, is_active: false });
        expect(
          await fx.auditNow(`action = 'apikey.revoke' AND target_id = $1`, [
            uuid,
          ]),
        ).toHaveLength(1);
      });

      it("answers NOT_FOUND for a key that does not exist", async () => {
        const reply = await deactivate("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
        expect({ status: reply.status, code: reply.code }).toEqual({
          status: 404,
          code: "NOT_FOUND",
        });
      });

      it("refuses a sync-scope key and a member session", async () => {
        const uuid = await victim();

        const syncReply = await deactivate(uuid, { key: fx.sync.key });
        expect(syncReply.status).toBe(403);
        expect(syncReply.message).toBe(STANDING_REFUSAL);

        const memberReply = await deactivate(uuid, { cookie: fx.memberCookie });
        expect(memberReply.status).toBe(403);

        const { rows } = await fx.suiteLock.query(
          `SELECT is_active FROM api_keys WHERE uuid = $1`,
          [uuid],
        );
        expect(rows[0].is_active).toBe(true);
      });

      it("makes one state change and one event out of concurrent deactivations", async () => {
        const uuid = await victim();

        const replies = await Promise.all(
          Array.from({ length: 5 }, () => deactivate(uuid)),
        );

        expect(replies.every((r) => r.status === 200)).toBe(true);
        expect(
          replies.filter((r) => (r.data as { changed: boolean }).changed),
        ).toHaveLength(1);
        expect(
          await fx.auditNow(`action = 'apikey.revoke' AND target_id = $1`, [
            uuid,
          ]),
        ).toHaveLength(1);
      });

      it("leaves the key active when the audit row cannot be written", async () => {
        const uuid = await victim();
        await fx.failAuditFor("apikey.revoke");
        try {
          const reply = await deactivate(uuid);
          expect(reply.status).toBe(500);
        } finally {
          await fx.clearAuditFault("apikey.revoke");
        }

        const { rows } = await fx.suiteLock.query(
          `SELECT is_active FROM api_keys WHERE uuid = $1`,
          [uuid],
        );
        expect(rows[0].is_active).toBe(true);
        expect(
          await fx.auditNow(`action = 'apikey.revoke' AND target_id = $1`, [
            uuid,
          ]),
        ).toHaveLength(0);
      });

      it("works for an administrator's session too, in the same transaction", async () => {
        const uuid = await victim();

        const reply = await deactivate(uuid, { cookie: fx.ownerCookie });

        expect(reply.status).toBe(200);
        expect(
          await fx.auditNow(`action = 'apikey.revoke' AND target_id = $1`, [
            uuid,
          ]),
        ).toHaveLength(1);
      });
    });

    // -------------------------------------------------------------------------
    describe("the self-lockout rails on the real stack", () => {
      const CALLER_IP = "203.0.113.9";
      const own = (
        allowed: string[] | null,
        mode: "off" | "audit" | "enforce",
        ip: string | null = CALLER_IP,
      ) =>
        fx.trpc(
          "frontend.apiKeys.setIpPolicy",
          {
            uuid: fx.operator.uuid,
            allowed_cidrs: allowed,
            ip_policy_mode: mode,
          },
          "mutation",
          { ip },
        );
      const policyOf = async () => {
        const { rows } = await fx.suiteLock.query(
          `SELECT allowed_cidrs, ip_policy_mode FROM api_keys WHERE uuid = $1`,
          [fx.operator.uuid],
        );
        return rows[0] as {
          allowed_cidrs: string[] | null;
          ip_policy_mode: string;
        };
      };

      it("refuses an own enforce list that excludes the request's address, then accepts one that includes it, then lets the key restore itself", async () => {
        const refused = await own(["198.51.100.0/24"], "enforce");
        expect({ status: refused.status, code: refused.code }).toEqual({
          status: 400,
          code: "BAD_REQUEST",
        });
        expect(await policyOf()).toEqual({
          allowed_cidrs: null,
          ip_policy_mode: "off",
        });

        try {
          const accepted = await own(["203.0.113.0/24"], "enforce");
          expect(accepted.status).toBe(200);
          expect(await policyOf()).toEqual({
            allowed_cidrs: ["203.0.113.0/24"],
            ip_policy_mode: "enforce",
          });
          // The key keeps working from its address and not from another.
          expect(
            (
              await fx.trpc("frontend.mcpServers.list", undefined, "query", {
                ip: CALLER_IP,
              })
            ).status,
          ).toBe(200);
          expect(
            (
              await fx.trpc("frontend.mcpServers.list", undefined, "query", {
                ip: "198.51.100.77",
              })
            ).status,
          ).toBe(403);
        } finally {
          const restored = await own(null, "off");
          expect(restored.status).toBe(200);
        }
        expect(await policyOf()).toEqual({
          allowed_cidrs: null,
          ip_policy_mode: "off",
        });
      });

      it("fails closed on a request with no trusted address", async () => {
        const refused = await own(["203.0.113.0/24"], "enforce", null);
        expect(refused.status).toBe(400);
        expect(await policyOf()).toEqual({
          allowed_cidrs: null,
          ip_policy_mode: "off",
        });
      });

      it("judges the global policy for a key that follows it, in both directions", async () => {
        const restoreGlobal = async () => {
          await fx.suiteLock.query(
            `DELETE FROM config WHERE id IN ('API_KEY_IP_POLICY_MODE', 'API_KEY_IP_ALLOWED_CIDRS')`,
          );
        };
        const storedBefore = await fx.suiteLock.query(
          `SELECT id, value FROM config
          WHERE id IN ('API_KEY_IP_POLICY_MODE', 'API_KEY_IP_ALLOWED_CIDRS')
          ORDER BY id`,
        );
        try {
          // The operator key follows the global policy. A global enforce list
          // that excludes the caller is refused and changes nothing.
          const refused = await fx.trpc(
            "frontend.apiKeys.setGlobalIpPolicy",
            { mode: "enforce", allowed_cidrs: ["198.51.100.0/24"] },
            "mutation",
            { ip: CALLER_IP },
          );
          expect(refused.status).toBe(400);
          const stored = await fx.suiteLock.query(
            `SELECT id, value FROM config
            WHERE id IN ('API_KEY_IP_POLICY_MODE', 'API_KEY_IP_ALLOWED_CIDRS')
            ORDER BY id`,
          );
          expect(stored.rows).toEqual(storedBefore.rows);

          // One that includes the caller is accepted; it audits like any change.
          const accepted = await fx.trpc(
            "frontend.apiKeys.setGlobalIpPolicy",
            { mode: "enforce", allowed_cidrs: ["203.0.113.0/24"] },
            "mutation",
            { ip: CALLER_IP },
          );
          expect(accepted.status).toBe(200);
          expect(
            await fx.auditNow(
              `action = 'config.api_key_ip_policy.set' AND actor_id = $1`,
              [fx.operator.uuid],
            ),
          ).toHaveLength(1);

          // With that list in force, the key (which follows it) is still
          // admitted from its address, and may be set to follow it explicitly:
          // the rail judges the global policy it would follow, which admits it.
          // (The case where the followed list excludes the caller cannot be
          // staged over HTTP, because the gateway would refuse the call itself;
          // api-keys.impl.rails.test.ts covers it.)
          const follow = await own(null, "off");
          expect(follow.status).toBe(200);
        } finally {
          await restoreGlobal();
        }
      });

      it("does not judge a write to another key", async () => {
        const uuid = (await fx
          .trpc(
            "frontend.apiKeys.create",
            { name: nextName(), all_endpoints: true },
            "mutation",
            { cookie: fx.ownerCookie },
          )
          .then((r) => {
            valueOf(r);
            return (r.data as { uuid: string }).uuid;
          })) as string;

        const reply = await fx.trpc(
          "frontend.apiKeys.setIpPolicy",
          {
            uuid,
            allowed_cidrs: ["198.51.100.0/24"],
            ip_policy_mode: "enforce",
          },
          "mutation",
          { ip: CALLER_IP },
        );

        expect(reply.status).toBe(200);
      });
    });

    // -------------------------------------------------------------------------
    // -------------------------------------------------------------------------
    describe("a refusal leaves one denied row and no success row", () => {
      // The generic accepted-request row carries no procedure name or payload,
      // so without a denial row a key probing for a credential it may not create
      // leaves no distinct signal, while an out-of-scope call is a denial.
      const serverNow = async () =>
        (await fx.suiteLock.query(`SELECT clock_timestamp() AS t`)).rows[0]
          .t as Date;

      const deniedSince = (since: Date) =>
        fx.auditEventually(
          `action = 'apikey.create' AND outcome = 'denied' AND actor_id = $1 AND occurred_at >= $2`,
          [fx.operator.uuid, since],
        );

      const PROBES: Array<
        [string, () => Record<string, unknown>, string, string]
      > = [
        [
          "an admin-plane key",
          () => ({
            admin_plane: true,
            endpoint_uuid: undefined,
            all_endpoints: true,
          }),
          "admin_plane_field",
          "FORBIDDEN",
        ],
        [
          "an acts-as key",
          () => ({ acts_as_user_id: fx.memberId }),
          "acts_as_field",
          "FORBIDDEN",
        ],
        [
          "a public key",
          () => ({ user_id: null }),
          "owner_required",
          "BAD_REQUEST",
        ],
        [
          "an over-wide list",
          () => ({
            ip_policy: { mode: "enforce", allowed_cidrs: ["0.0.0.0/0"] },
          }),
          "ip_policy_too_wide",
          "BAD_REQUEST",
        ],
        [
          "a policy that is not enforce (refused by the input schema)",
          () => ({
            ip_policy: { mode: "off", allowed_cidrs: ["203.0.113.0/24"] },
          }),
          "ip_policy_shape",
          "BAD_REQUEST",
        ],
        [
          "a private endpoint (refused in the transaction)",
          () => ({ endpoint_uuid: epPrivateMember }),
          "endpoint_not_eligible",
          "FORBIDDEN",
        ],
        [
          "a restricted endpoint for an owner in no mapped group",
          () => ({ endpoint_uuid: epRestricted }),
          "endpoint_not_eligible",
          "FORBIDDEN",
        ],
        [
          "a restricted endpoint for an administrator owner who is in no mapped group",
          () => ({ user_id: fx.ownerId, endpoint_uuid: epRestricted }),
          "endpoint_not_eligible",
          "FORBIDDEN",
        ],
        [
          "a gateway-wide key for an administrator owner",
          () => ({
            user_id: fx.ownerId,
            endpoint_uuid: undefined,
            all_endpoints: true,
          }),
          "gateway_wide_admin_owner",
          "FORBIDDEN",
        ],
      ];

      it.each(PROBES)(
        "records one denial naming the rule for %s, and nothing of the request",
        async (_label, over, rule, code) => {
          const since = await serverNow();
          const successBefore = await count("audit_create");

          const reply = await mint(over());
          await expectRefused(reply, {
            status: code === "FORBIDDEN" ? 403 : 400,
            code,
          });

          const rows = await deniedSince(since);
          expect(rows).toHaveLength(1);
          expect(rows[0]).toMatchObject({
            actor_type: "api_key",
            actor_id: fx.operator.uuid,
            target_id: null,
            outcome: "denied",
          });
          expect(rows[0].detail).toEqual({
            rule,
            admin_plane: {
              key_uuid: fx.operator.uuid,
              owner_user_id: fx.ownerId,
              scope: "operator",
            },
          });
          expect(await count("audit_create")).toBe(successBefore);
          // Nothing the request carried reaches the row.
          const text = JSON.stringify(rows);
          for (const value of [fx.memberId, epPrivateMember, "0.0.0.0/0"]) {
            expect(text).not.toContain(value);
          }
        },
      );
    });

    // -------------------------------------------------------------------------
    describe("the endpoint uuid in the audit row is the stored one", () => {
      it("records a lower-case uuid when the request spelled it upper case", async () => {
        const reply = await mint({ endpoint_uuid: epPublic.toUpperCase() });
        expect(reply.status).toBe(200);
        const uuid = (reply.data as { uuid: string }).uuid;
        valueOf(reply);

        const rows = await fx.auditNow(
          `action = 'apikey.create' AND target_id = $1`,
          [uuid],
        );
        expect(rows).toHaveLength(1);
        const stored = (
          await fx.suiteLock.query(
            `SELECT endpoint_uuid::text AS u FROM api_keys WHERE uuid = $1`,
            [uuid],
          )
        ).rows[0].u as string;
        expect(stored).toBe(epPublic);
        expect(
          (rows[0].detail as { endpoint_uuid: string }).endpoint_uuid,
        ).toBe(stored);
      });
    });

    // -------------------------------------------------------------------------
    describe("a created key stays locked and narrow after it is created", () => {
      // Rule 5 holds across calls, not only in one: the key that created a key
      // may not then unlock it or widen it past the bound, with setIpPolicy.
      let minted = "";
      const policyOfMinted = async () =>
        (
          await fx.suiteLock.query(
            `SELECT allowed_cidrs, ip_policy_mode FROM api_keys WHERE uuid = $1`,
            [minted],
          )
        ).rows[0] as { allowed_cidrs: string[] | null; ip_policy_mode: string };
      const setPolicy = (
        cidrs: string[] | null,
        mode: string,
        options: { key?: string; cookie?: string } = {},
      ) =>
        fx.trpc(
          "frontend.apiKeys.setIpPolicy",
          { uuid: minted, allowed_cidrs: cidrs, ip_policy_mode: mode },
          "mutation",
          options,
        );

      beforeAll(async () => {
        const reply = await mint();
        expect(reply.status).toBe(200);
        minted = (reply.data as { uuid: string }).uuid;
        valueOf(reply);
      });

      it.each([
        ["mode off, following the global policy", null, "off"],
        ["mode off with a list", ["203.0.113.0/24"], "off"],
        ["mode audit", ["203.0.113.0/24"], "audit"],
        ["the any-IP exemption", ["0.0.0.0/0", "::/0"], "enforce"],
        ["an IPv4 /8", ["10.0.0.0/8"], "enforce"],
        ["::ffff:0:0/96", ["::ffff:0:0/96"], "enforce"],
        ["::/48", ["::/48"], "enforce"],
        ["a mapped /119", ["::ffff:203.0.112.0/119"], "enforce"],
        [
          "nine entries",
          Array.from({ length: 9 }, (_v, i) => `203.0.113.${i}`),
          "enforce",
        ],
      ] as const)(
        "refuses %s, leaving the policy as it was",
        async (_label, cidrs, mode) => {
          const reply = await setPolicy(cidrs ? [...cidrs] : null, mode, {});
          failureBodies.push(JSON.stringify(reply));

          expect(reply.status).toBe(400);
          expect(reply.code).toBe("BAD_REQUEST");
          expect(() => JSON.parse(reply.message ?? "")).toThrow();
          expect(await policyOfMinted()).toEqual({
            allowed_cidrs: ["203.0.113.0/24"],
            ip_policy_mode: "enforce",
          });
        },
      );

      it("leaves a denied row for a refusal, naming the rule and the key", async () => {
        const since = (
          await fx.suiteLock.query(`SELECT clock_timestamp() AS t`)
        ).rows[0].t as Date;
        await setPolicy(["10.0.0.0/8"], "enforce");

        const rows = await fx.auditEventually(
          `action = 'apikey.ip_policy.set' AND outcome = 'denied' AND target_id = $1 AND occurred_at >= $2`,
          [minted, since],
        );
        expect(rows).toHaveLength(1);
        expect(rows[0]).toMatchObject({
          actor_type: "api_key",
          actor_id: fx.operator.uuid,
        });
        expect((rows[0].detail as { rule: string }).rule).toBe(
          "ip_policy_change_too_wide",
        );
      });

      it("lets the key move it to another narrow list, and records the change", async () => {
        const moved = await setPolicy(
          ["198.51.100.0/24", "2001:db8::/48"],
          "enforce",
        );
        expect(moved.status).toBe(200);
        expect(await policyOfMinted()).toEqual({
          allowed_cidrs: ["198.51.100.0/24", "2001:db8::/48"],
          ip_policy_mode: "enforce",
        });
        const rows = await fx.auditNow(
          `action = 'apikey.ip_policy.set' AND outcome = 'success' AND target_id = $1`,
          [minted],
        );
        expect(rows.length).toBeGreaterThanOrEqual(1);
        // Back to the first list, for the cases after this one.
        expect((await setPolicy(["203.0.113.0/24"], "enforce")).status).toBe(
          200,
        );
      });

      it("does not hold an administrator's session to the bound", async () => {
        const widened = await setPolicy(["10.0.0.0/8"], "enforce", {
          cookie: fx.ownerCookie,
        });
        expect(widened.status).toBe(200);
        expect(await policyOfMinted()).toEqual({
          allowed_cidrs: ["10.0.0.0/8"],
          ip_policy_mode: "enforce",
        });
        const off = await setPolicy(null, "off", { cookie: fx.ownerCookie });
        expect(off.status).toBe(200);
        await setPolicy(["203.0.113.0/24"], "enforce", {
          cookie: fx.ownerCookie,
        });
      });

      it("does not hold the policy of an admin-plane key to the bound", async () => {
        // The CI key is locked to any address on purpose (its runners rotate).
        const ci = await fx.trpc(
          "frontend.apiKeys.setIpPolicy",
          {
            uuid: fx.sync.uuid,
            allowed_cidrs: ["0.0.0.0/0", "::/0"],
            ip_policy_mode: "enforce",
          },
          "mutation",
        );
        expect(ci.status).toBe(200);
        const { rows } = await fx.suiteLock.query(
          `SELECT allowed_cidrs FROM api_keys WHERE uuid = $1`,
          [fx.sync.uuid],
        );
        expect(rows[0].allowed_cidrs).toEqual(["0.0.0.0/0", "::/0"]);
        await fx.trpc(
          "frontend.apiKeys.setIpPolicy",
          { uuid: fx.sync.uuid, allowed_cidrs: null, ip_policy_mode: "off" },
          "mutation",
        );
      });

      it("answers NOT_FOUND for a key that does not exist, whatever the policy", async () => {
        const reply = await fx.trpc(
          "frontend.apiKeys.setIpPolicy",
          {
            uuid: "99999999-9999-4999-8999-999999999999",
            allowed_cidrs: ["10.0.0.0/8"],
            ip_policy_mode: "enforce",
          },
          "mutation",
        );
        expect(reply.code).toBe("NOT_FOUND");
      });
    });

    // -------------------------------------------------------------------------
    describe("an endpoint cannot be used to reach what a restricted endpoint keeps from a key", () => {
      // A key may be created only for a public, unrestricted endpoint. The same
      // key could otherwise create such an endpoint over the namespace a
      // restricted (or private) endpoint serves, and create a key for it.
      const created: string[] = [];
      let freshNamespace = "";

      const createEndpoint = (
        name: string,
        namespaceUuid: string,
        over: Record<string, unknown> = {},
        options: { key?: string; cookie?: string } = {},
      ) =>
        fx.trpc(
          "frontend.endpoints.create",
          {
            name,
            namespaceUuid,
            enableApiKeyAuth: true,
            enableMaxRate: false,
            enableClientMaxRate: false,
            enableOauth: false,
            user_id: null,
            createMcpServer: false,
            ...over,
          },
          "mutation",
          options,
        );

      const endpointRow = async (name: string) =>
        (
          await fx.suiteLock.query(
            `SELECT uuid, namespace_uuid FROM endpoints WHERE name = $1`,
            [name],
          )
        ).rows[0] as { uuid: string; namespace_uuid: string } | undefined;

      beforeAll(async () => {
        const [namespace] = await fx.db
          .insert(fx.schema.namespacesTable)
          .values({ name: `itest-${fx.run}-fresh-ns`, user_id: null })
          .returning();
        freshNamespace = namespace.uuid;
      });

      afterAll(async () => {
        for (const name of created) {
          await fx.suiteLock.query(`DELETE FROM endpoints WHERE name = $1`, [
            name,
          ]);
        }
        await fx.suiteLock.query(`DELETE FROM namespaces WHERE uuid = $1`, [
          freshNamespace,
        ]);
      });

      it("refuses a public endpoint over a namespace a restricted or private endpoint serves, creating nothing", async () => {
        const name = `clone-${fx.run}`;
        const reply = await createEndpoint(name, fx.publicNamespaceUuid);

        // `success: false` inside an HTTP 200, like the rules beside it.
        expect(reply.status).toBe(200);
        const body = reply.data as { success: boolean; message: string };
        expect(body.success).toBe(false);
        expect(body.message).toBe(
          "An admin-plane API key cannot make a namespace public that a restricted or private endpoint already serves. Do this in the admin UI.",
        );
        expect(await endpointRow(name)).toBeUndefined();
      });

      it("creates a public endpoint over a namespace nothing gates", async () => {
        const name = `fresh-${fx.run}`;
        created.push(name);
        const reply = await createEndpoint(name, freshNamespace);

        expect((reply.data as { success: boolean }).success).toBe(true);
        expect((await endpointRow(name))?.namespace_uuid).toBe(freshNamespace);
      });

      it("refuses re-pointing that endpoint at the namespace a restricted endpoint serves, leaving it where it was", async () => {
        const name = `fresh-${fx.run}`;
        const row = await endpointRow(name);
        expect(row).toBeDefined();

        const reply = await fx.trpc(
          "frontend.endpoints.update",
          {
            uuid: row?.uuid,
            name,
            namespaceUuid: fx.publicNamespaceUuid,
            enableApiKeyAuth: true,
            requireScopedApiKey: false,
            enableMaxRate: false,
            enableClientMaxRate: false,
            enableOauth: false,
          },
          "mutation",
        );

        expect((reply.data as { success: boolean }).success).toBe(false);
        expect((await endpointRow(name))?.namespace_uuid).toBe(freshNamespace);
      });

      it("does not hold an administrator's session to the rule", async () => {
        const name = `human-${fx.run}`;
        created.push(name);
        const reply = await createEndpoint(
          name,
          fx.publicNamespaceUuid,
          {},
          { cookie: fx.ownerCookie },
        );

        expect((reply.data as { success: boolean }).success).toBe(true);
      });
    });

    // -------------------------------------------------------------------------
    describe("a key's scope cannot be changed after it is created", () => {
      it("is unchanged by an administrator's update, with the scope in the request or in the repository call", async () => {
        const scopeOf = async (uuid: string) =>
          (
            await fx.suiteLock.query(
              `SELECT admin_plane, admin_plane_scope FROM api_keys WHERE uuid = $1`,
              [uuid],
            )
          ).rows[0];

        // Through the procedure: the request carries a scope the schema drops.
        const viaTrpc = await fx.trpc(
          "frontend.apiKeys.update",
          {
            uuid: fx.sync.uuid,
            is_active: true,
            admin_plane_scope: "operator",
          },
          "mutation",
          { cookie: fx.ownerCookie },
        );
        expect(viaTrpc.status).toBe(200);
        expect(await scopeOf(fx.sync.uuid)).toEqual({
          admin_plane: true,
          admin_plane_scope: "sync",
        });

        // Through the repository, for a caller that skipped the schema.
        const { ApiKeysRepository } = await import(
          "../db/repositories/api-keys.repo"
        );
        const repo = new ApiKeysRepository();
        await repo.updateAsAdmin(fx.sync.uuid, {
          is_active: true,
          admin_plane_scope: "operator",
        } as never);
        await repo.update(fx.sync.uuid, fx.ownerId, {
          is_active: true,
          admin_plane_scope: "operator",
        } as never);
        expect(await scopeOf(fx.sync.uuid)).toEqual({
          admin_plane: true,
          admin_plane_scope: "sync",
        });
      });
    });

    // -------------------------------------------------------------------------
    // The owner rule on a restricted endpoint, and the mint that follows it.
    // Last in the file on purpose: these cases cause many fire-and-forget audit
    // writes (a refusal row per refused request) through the audit pool, which is
    // deliberately small and sheds load (db/audit-db), and the cases above read
    // their own denied rows from the table and must not share a pool with that
    // backlog. Oracle for every expectation: a key reaches a restricted endpoint
    // exactly when its owner is an administrator or belongs to a mapped group,
    // and a mint must never create a key that reaches more than its owner: so
    // an agent mint for a restricted endpoint needs an owner who is an explicit
    // member (an administrator's role alone does not count), and a gateway-wide
    // mint is refused for an administrator owner.
    describe("the owner rule and the mint that follows it", () => {
      const invalidate = async () => {
        const { invalidateEndpointAccessCache } = await import(
          "../lib/endpoint-access-control"
        );
        invalidateEndpointAccessCache();
      };

      /** A group mapping `endpoints`, with `members`, removed afterwards. */
      async function withGroup(
        over: { members: string[]; endpoints: string[] },
        run: (groupUuid: string) => Promise<void>,
      ) {
        const uuid = await fx.group({
          name: `mint-grp-${++mintCounter}`,
          ...over,
        });
        await invalidate();
        try {
          await run(uuid);
        } finally {
          await fx.db
            .delete(fx.schema.accessGroupsTable)
            .where(fx.eq(fx.schema.accessGroupsTable.uuid, uuid));
          await invalidate();
        }
      }

      async function reaches(
        endpointUuid: string,
        token: string,
        via: "bearer" | "x-api-key" = "x-api-key",
      ) {
        const result = await authenticate({
          endpointUuid,
          token,
          via,
          ip: ALLOWED_IP,
        });
        return { next: result.next, status: result.status };
      }

      describe("a mint for a restricted endpoint follows the owner's membership", () => {
        it("refuses an owner in no mapped group, and one whose group maps a different endpoint", async () => {
          await withGroup(
            { members: [fx.memberId], endpoints: [epPublicOauth] },
            async () => {
              await expectNothingWritten(async () => {
                await expectRefused(
                  await mint({ endpoint_uuid: epRestricted }),
                  {
                    status: 403,
                    code: "FORBIDDEN",
                  },
                );
              });
            },
          );
        });

        it("refuses an owner outside the group that is mapped to the endpoint", async () => {
          await withGroup(
            { members: [fx.otherMemberId], endpoints: [epRestricted] },
            async () => {
              await expectNothingWritten(async () => {
                await expectRefused(
                  await mint({ endpoint_uuid: epRestricted }),
                  {
                    status: 403,
                    code: "FORBIDDEN",
                  },
                );
              });
            },
          );
        });

        it("refuses an administrator owner who is not an explicit member: the role alone does not count at mint time", async () => {
          await withGroup(
            { members: [fx.memberId], endpoints: [epRestricted] },
            async () => {
              await expectNothingWritten(async () => {
                await expectRefused(
                  await mint({
                    user_id: fx.ownerId,
                    endpoint_uuid: epRestricted,
                  }),
                  { status: 403, code: "FORBIDDEN" },
                );
              });
            },
          );
        });

        it("allows an explicit member, and the key then reaches the endpoint on both branches only while the membership holds", async () => {
          await withGroup(
            { members: [fx.memberId], endpoints: [epRestricted] },
            async (groupUuid) => {
              const minted = await newKey({ endpoint_uuid: epRestricted });
              // Both transports on the API-key-only endpoint.
              for (const via of ["x-api-key", "bearer"] as const) {
                expect(await reaches(epRestricted, minted.key, via)).toEqual({
                  next: true,
                  status: 0,
                });
              }

              await fx.db
                .delete(fx.schema.accessGroupMembersTable)
                .where(
                  fx.eq(
                    fx.schema.accessGroupMembersTable.group_uuid,
                    groupUuid,
                  ),
                );
              await invalidate();

              const after = await reaches(epRestricted, minted.key);
              expect(after.next).toBe(false);
              expect(after.status).toBe(403);
            },
          );
        });

        it("allows an administrator owner who IS an explicit member", async () => {
          await withGroup(
            { members: [fx.ownerId], endpoints: [epRestricted] },
            async () => {
              const minted = await newKey({
                user_id: fx.ownerId,
                endpoint_uuid: epRestricted,
              });
              expect((await reaches(epRestricted, minted.key)).next).toBe(true);
              await fx.trpc(
                "frontend.apiKeys.deactivate",
                { uuid: minted.uuid },
                "mutation",
              );
            },
          );
        });

        it("reads the membership in the mint's own transaction, not from the request cache", async () => {
          await withGroup(
            { members: [fx.memberId], endpoints: [epRestricted] },
            async (groupUuid) => {
              // A key for the member, used once, so the decision cache holds
              // "allowed" for (member, epRestricted).
              const first = await newKey({ endpoint_uuid: epRestricted });
              expect((await reaches(epRestricted, first.key)).next).toBe(true);

              // The membership is removed behind the cache's back (another
              // replica, or psql): no invalidation in this process.
              await fx.db
                .delete(fx.schema.accessGroupMembersTable)
                .where(
                  fx.eq(
                    fx.schema.accessGroupMembersTable.group_uuid,
                    groupUuid,
                  ),
                );

              // The cache would still answer yes, and the mint must not.
              expect((await reaches(epRestricted, first.key)).next).toBe(true);
              await expectNothingWritten(async () => {
                await expectRefused(
                  await mint({ endpoint_uuid: epRestricted }),
                  {
                    status: 403,
                    code: "FORBIDDEN",
                  },
                );
              });
            },
          );
        });
      });

      describe("a key reaches a restricted endpoint exactly when its owner may, on both branches", () => {
        let epRestrictedOauth = "";
        beforeAll(async () => {
          epRestrictedOauth = await fx.endpoint({
            name: "ep-restricted-oauth",
            restricted: true,
            oauth: true,
          });
        });

        const BRANCH_ENDPOINTS = [
          ["API-key-only", () => epRestricted],
          ["OAuth-enabled", () => epRestrictedOauth],
        ] as const;

        it.each(BRANCH_ENDPOINTS)(
          "on the %s endpoint: a member's gateway-wide and scoped keys pass, a non-member's are refused, a removed member's are refused",
          async (_branch, endpointOf) => {
            const endpointUuid = endpointOf();
            const memberGateway = await newKey({
              endpoint_uuid: undefined,
              all_endpoints: true,
            });
            const memberScoped = await fx.dataKey({
              name: `scoped-${++mintCounter}`,
              ownerId: fx.memberId,
              endpointUuid,
            });
            const outsiderGateway = await newKey({
              user_id: fx.otherMemberId,
              endpoint_uuid: undefined,
              all_endpoints: true,
            });
            const outsiderScoped = await fx.dataKey({
              name: `scoped-${++mintCounter}`,
              ownerId: fx.otherMemberId,
              endpointUuid,
            });

            await withGroup(
              { members: [fx.memberId], endpoints: [endpointUuid] },
              async (groupUuid) => {
                for (const key of [memberGateway.key, memberScoped.key]) {
                  expect((await reaches(endpointUuid, key)).next).toBe(true);
                }
                for (const key of [outsiderGateway.key, outsiderScoped.key]) {
                  const refused = await reaches(endpointUuid, key);
                  expect(refused).toEqual({ next: false, status: 403 });
                }

                await fx.db
                  .delete(fx.schema.accessGroupMembersTable)
                  .where(
                    fx.eq(
                      fx.schema.accessGroupMembersTable.group_uuid,
                      groupUuid,
                    ),
                  );
                await invalidate();
                for (const key of [memberGateway.key, memberScoped.key]) {
                  expect(await reaches(endpointUuid, key)).toEqual({
                    next: false,
                    status: 403,
                  });
                }
              },
            );
          },
        );

        it.each(BRANCH_ENDPOINTS)(
          "on the %s endpoint: an administrator-owned key and a public key",
          async (_branch, endpointOf) => {
            const endpointUuid = endpointOf();
            // Created the way an administrator in the UI creates one: an admin
            // owned gateway-wide key, and a public key (no owner).
            const adminKey = await fx.dataKey({
              name: `admin-gw-${++mintCounter}`,
              ownerId: fx.ownerId,
            });
            const publicKey = await fx.dataKey({
              name: `public-gw-${++mintCounter}`,
              ownerId: null,
            });
            const publicScoped = await fx.dataKey({
              name: `public-sc-${++mintCounter}`,
              ownerId: null,
              endpointUuid,
            });

            expect((await reaches(endpointUuid, adminKey.key)).next).toBe(true);
            // No owner: refused even though no group could ever admit it, and
            // an unrestricted endpoint stays open to it.
            for (const key of [publicKey.key, publicScoped.key]) {
              expect(await reaches(endpointUuid, key)).toEqual({
                next: false,
                status: 403,
              });
            }
            expect((await reaches(epPublic, publicKey.key)).next).toBe(true);
          },
        );

        it("refuses a key once its owner is disabled, with the account refusal and not the group one", async () => {
          const key = await fx.dataKey({
            name: `disabled-${++mintCounter}`,
            ownerId: fx.memberId,
          });
          await withGroup(
            { members: [fx.memberId], endpoints: [epRestricted] },
            async () => {
              expect((await reaches(epRestricted, key.key)).next).toBe(true);
              await fx.db
                .update(fx.schema.usersTable)
                .set({ disabled: true })
                .where(fx.eq(fx.schema.usersTable.id, fx.memberId));
              try {
                const refused = await authenticate({
                  endpointUuid: epRestricted,
                  token: key.key,
                  via: "x-api-key",
                  ip: ALLOWED_IP,
                });
                expect(refused.next).toBe(false);
                expect(refused.status).toBe(403);
                expect((refused.body as { message: string }).message).toBe(
                  GENERIC_403,
                );
              } finally {
                await fx.db
                  .update(fx.schema.usersTable)
                  .set({ disabled: false })
                  .where(fx.eq(fx.schema.usersTable.id, fx.memberId));
              }
            },
          );
        });

        it("keeps passing a demoted administrator's key until the 60 second cache bound, and refuses it at once after an invalidation", async () => {
          const key = await fx.dataKey({
            name: `demoted-${++mintCounter}`,
            ownerId: fx.otherMemberId,
          });
          await fx.setRole(fx.otherMemberId, "admin");
          await invalidate();
          try {
            expect((await reaches(epRestricted, key.key)).next).toBe(true);

            await fx.setRole(fx.otherMemberId, "member");
            // Not invalidated: the cached admission is still served.
            expect((await reaches(epRestricted, key.key)).next).toBe(true);

            await invalidate();
            expect(await reaches(epRestricted, key.key)).toEqual({
              next: false,
              status: 403,
            });
          } finally {
            await fx.setRole(fx.otherMemberId, "member");
            await invalidate();
          }
        });

        it("writes the refusal row of a refused key to audit_log, naming the key, its owner and its scope, and no raw key", async () => {
          const key = await fx.dataKey({
            name: `audited-${++mintCounter}`,
            ownerId: fx.otherMemberId,
          });
          const refused = await reaches(epRestrictedOauth, key.key);
          expect(refused.next).toBe(false);

          const rows = await fx.auditEventually(
            `action = 'endpoint.access.denied' AND actor_id = $1`,
            [key.uuid],
          );
          expect(rows).toHaveLength(1);
          expect(rows[0]).toMatchObject({
            actor_type: "api_key",
            actor_id: key.uuid,
            target_id: epRestrictedOauth,
            outcome: "denied",
          });
          expect(rows[0].detail).toMatchObject({
            reason: "access_group_denied",
            auth_method: "api_key",
            owner_user_id: fx.otherMemberId,
            key_scope: "gateway",
          });
          expect(JSON.stringify(rows[0])).not.toContain(key.key);
        });
      });
    });

    it("leaks no created key's value into any audit row, log line or error body", async () => {
      expect(mintedValues.length).toBeGreaterThan(10);
      const { rows } = await fx.suiteLock.query(
        `SELECT row_to_json(a)::text AS text FROM audit_log a`,
      );
      const audit = rows.map((r) => r.text as string).join("\n");
      const logs = JSON.stringify([
        quiet.debug.mock.calls,
        quiet.info.mock.calls,
        quiet.warn.mock.calls,
        quiet.error.mock.calls,
      ]);
      const errors = failureBodies.join("\n");

      for (const value of mintedValues) {
        // The whole value, and its 64-character body without the scheme tag.
        for (const needle of [value, value.slice("sk_mt_".length)]) {
          expect(audit).not.toContain(needle);
          expect(logs).not.toContain(needle);
          expect(errors).not.toContain(needle);
        }
      }
    });
  },
);
