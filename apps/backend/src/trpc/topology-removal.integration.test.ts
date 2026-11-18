/**
 * The leaf-only topology removals against a real Postgres, through the real
 * /trpc stack: `endpoints`, `namespaces` and `mcpServers` `.removalImpact` and
 * `.remove`, called with the operator-scope admin-plane key.
 *
 *  - Each removes one public row nothing depends on, with its own content
 *    (presentation; mounts and tool rows; tool catalog and OAuth session),
 *    and writes one success audit row with the snapshot, in one transaction.
 *  - Each blocker refuses (a key of either state, a group mapping, an
 *    endpoint, a mount of either status, a tool row by either of its two
 *    server references, a private dependant), leaves the rows and a denied
 *    audit row naming the rule.
 *  - The confirmation: a wrong name, a fingerprint read before a rename or an
 *    in-place edit, and the inputs that must NOT change it (an OAuth token
 *    refresh, persisted session churn).
 *  - Concurrency: a child that committed while the removal waited is seen;
 *    a child that waits behind the removal fails its foreign key.
 *  - The audit fault and the destroy budget roll the removal back.
 *  - Scope: the sync key, a member and a reason-less change are refused.
 *
 * Addresses are RFC 5737 documentation ranges, emails use .test, names are
 * synthetic.
 */
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

import { ENDPOINT_NAMESPACE_LOCK_NAMESPACE } from "../db/repositories/admin-plane-locks";
import { createFixture, type Fixture } from "./admin-plane-integration-fixture";

const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL;
const describeIfDb = describe.skipIf(!TEST_DATABASE_URL);

const cleanup = vi.hoisted(() => ({
  cleanupIdleServer: vi.fn(),
  cleanupIdleSession: vi.fn(),
  closeInspector: vi.fn(),
}));

const quiet = { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() };
vi.mock("@/utils/logger", () => ({ default: quiet }));
vi.mock("../lib/metamcp/mcp-server-pool", () => ({
  mcpServerPool: {
    ensureIdleSessionForNewServer: vi.fn().mockResolvedValue(undefined),
    getPoolStatus: vi
      .fn()
      .mockReturnValue({ idleServerUuids: [], perServerCounts: {} }),
    cleanupIdleSession: cleanup.cleanupIdleSession,
    invalidateIdleSession: vi.fn().mockResolvedValue(undefined),
    invalidateServerConnection: vi.fn().mockResolvedValue(undefined),
  },
}));
vi.mock("../lib/metamcp/metamcp-server-pool", () => ({
  metaMcpServerPool: {
    ensureIdleServers: vi.fn().mockResolvedValue(undefined),
    ensureIdleServerForNewNamespace: vi.fn().mockResolvedValue(undefined),
    cleanupIdleServer: cleanup.cleanupIdleServer,
    invalidateIdleServers: vi.fn().mockResolvedValue(undefined),
    invalidateOpenApiSessions: vi.fn().mockResolvedValue(undefined),
  },
}));
vi.mock("../lib/metamcp/inspector-sessions", () => ({
  closeInspectorSessionsForServer: cleanup.closeInspector,
}));

type Kind = "endpoints" | "namespaces" | "mcpServers";
type Impact = {
  kind: string;
  uuid: string;
  name: string;
  removable: boolean;
  blocked_by: string[];
  dependents: Array<{
    rule: string;
    kind: string;
    uuid: string;
    name: string;
    is_active: boolean | null;
  }>;
  hidden_dependents: Array<{ rule: string; count: number }>;
  cascades: Array<{ kind: string; count: number }>;
  live_sessions: number | null;
  impact_fingerprint: string;
  snapshot: Record<string, unknown>;
};

const ACTION: Record<Kind, string> = {
  endpoints: "endpoint.delete",
  namespaces: "namespace.delete",
  mcpServers: "mcpserver.delete",
};

describeIfDb("leaf-only topology removals (real Postgres)", () => {
  let fx: Fixture;
  let barrier: Client;
  let child: Client;
  let counter = 0;
  const uniq = (stem: string) => `${stem}-${++counter}-${fx.run}`;
  const privateNamespaces: string[] = [];

  const one = async (sql: string, params: unknown[] = []) =>
    (await fx.suiteLock.query(sql, params)).rows;

  const impactOf = async (kind: Kind, uuid: string, key?: string) => {
    const reply = await fx.trpc(
      `frontend.${kind}.removalImpact`,
      { uuid },
      "query",
      key ? { key } : {},
    );
    return { reply, impact: reply.data as Impact };
  };
  const remove = (
    kind: Kind,
    uuid: string,
    confirmName: string,
    fingerprint: string,
    options: { key?: string; reason?: string | null; cookie?: string } = {},
  ) =>
    fx.trpc(
      `frontend.${kind}.remove`,
      { uuid, confirm_name: confirmName, impact_fingerprint: fingerprint },
      "mutation",
      options,
    );
  /** Read the impact, then remove with exactly what it returned. */
  const removeAsRead = async (kind: Kind, uuid: string, key?: string) => {
    const { impact } = await impactOf(kind, uuid, key);
    return remove(kind, uuid, impact.name, impact.impact_fingerprint, { key });
  };

  const exists = async (table: string, uuid: string) =>
    (await one(`SELECT 1 FROM ${table} WHERE uuid = $1`, [uuid])).length === 1;
  const successRows = (kind: Kind, uuid: string) =>
    fx.auditNow(`target_id = $1 AND action = $2 AND outcome = 'success'`, [
      uuid,
      ACTION[kind],
    ]);
  const deniedRules = async (kind: Kind, uuid: string) =>
    (
      await fx.auditEventually(
        `target_id = $1 AND action = $2 AND outcome = 'denied'`,
        [uuid, ACTION[kind]],
      )
    ).map((row) => (row.detail as { rule?: unknown }).rule);

  // -- rows written straight to the tables, as a person's UI or the sync would

  async function server(stem: string, ownerId: string | null = null) {
    const [row] = await one(
      `INSERT INTO mcp_servers (name, type, url, user_id)
       VALUES ($1, 'STREAMABLE_HTTP', 'http://192.0.2.10:8080/mcp', $2)
       RETURNING uuid`,
      [uniq(stem), ownerId],
    );
    return row.uuid as string;
  }
  async function tool(serverUuid: string, stem: string) {
    const [row] = await one(
      `INSERT INTO tools (name, tool_schema, mcp_server_uuid)
       VALUES ($1, '{"type":"object"}'::jsonb, $2) RETURNING uuid`,
      [uniq(stem), serverUuid],
    );
    return row.uuid as string;
  }
  async function privateNamespace(stem: string, ownerId: string) {
    const [row] = await one(
      `INSERT INTO namespaces (name, user_id) VALUES ($1, $2) RETURNING uuid`,
      [uniq(stem), ownerId],
    );
    privateNamespaces.push(row.uuid as string);
    return row.uuid as string;
  }
  async function mount(
    namespaceUuid: string,
    serverUuid: string,
    status: "ACTIVE" | "INACTIVE" = "ACTIVE",
  ) {
    await one(
      `INSERT INTO namespace_server_mappings (namespace_uuid, mcp_server_uuid, status)
       VALUES ($1, $2, $3)`,
      [namespaceUuid, serverUuid, status],
    );
  }
  async function toolRow(
    namespaceUuid: string,
    toolUuid: string,
    serverUuid: string,
  ) {
    const [row] = await one(
      `INSERT INTO namespace_tool_mappings (namespace_uuid, tool_uuid, mcp_server_uuid)
       VALUES ($1, $2, $3) RETURNING uuid`,
      [namespaceUuid, toolUuid, serverUuid],
    );
    return row.uuid as string;
  }
  async function scopedKey(endpointUuid: string, active: boolean) {
    const created = await fx.dataKey({
      name: uniq("scoped"),
      ownerId: fx.memberId,
      endpointUuid,
    });
    await one(`UPDATE api_keys SET is_active = $2 WHERE uuid = $1`, [
      created.uuid,
      active,
    ]);
    return created.uuid;
  }
  /** An endpoint over a namespace of its own, so no test shares a gate. */
  async function lonelyEndpoint(stem: string) {
    const ns = await fx.namespace(uniq(`${stem}-ns`));
    const ep = await fx.endpoint({ name: uniq(stem), namespaceUuid: ns });
    return { ns, ep };
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
        throw new Error(`only ${waiting} of ${n} requests queued on a lock`);
      }
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
  }

  beforeAll(async () => {
    fx = await createFixture(TEST_DATABASE_URL as string, "topology");
    barrier = new Client({ connectionString: TEST_DATABASE_URL });
    await barrier.connect();
    child = new Client({ connectionString: TEST_DATABASE_URL });
    await child.connect();
  });

  afterAll(async () => {
    await barrier?.end();
    await child?.end();
    if (fx) {
      await one(`DELETE FROM mcp_servers WHERE name LIKE $1`, [`%${fx.run}`]);
      for (const uuid of privateNamespaces) {
        await one(`DELETE FROM namespaces WHERE uuid = $1`, [uuid]);
      }
      await fx.close();
    }
  });

  beforeEach(() => {
    for (const fn of Object.values(cleanup)) {
      fn.mockReset();
      fn.mockResolvedValue(undefined);
    }
  });

  // ---------------------------------------------------------------------------
  describe("endpoints", () => {
    it("removes a public endpoint nothing depends on, with its presentation row, in one transaction with its audit row", async () => {
      const { ns, ep } = await lonelyEndpoint("ep-ok");
      await one(
        `INSERT INTO endpoint_presentation (endpoint_uuid, title) VALUES ($1, 'A title')`,
        [ep],
      );
      const { reply: read, impact } = await impactOf("endpoints", ep);
      expect(read.status).toBe(200);
      expect(impact).toMatchObject({
        kind: "endpoint",
        uuid: ep,
        removable: true,
        blocked_by: [],
        dependents: [],
        hidden_dependents: [],
        cascades: [{ kind: "endpoint_presentation", count: 1 }],
        live_sessions: 0,
      });
      expect(impact.snapshot).toMatchObject({
        kind: "endpoint",
        name: impact.name,
        owner_user_id: null,
        namespace_uuid: ns,
        restricted: false,
      });
      // No free text of the presentation or the endpoint reaches the snapshot.
      expect(JSON.stringify(impact.snapshot)).not.toContain("A title");

      const reply = await remove(
        "endpoints",
        ep,
        impact.name,
        impact.impact_fingerprint,
      );
      expect(reply.status).toBe(200);
      expect(reply.data).toMatchObject({
        kind: "endpoint",
        uuid: ep,
        name: impact.name,
        removed: true,
        cleanup: "not_needed",
      });
      expect(await exists("endpoints", ep)).toBe(false);
      expect(
        await one(
          `SELECT 1 FROM endpoint_presentation WHERE endpoint_uuid = $1`,
          [ep],
        ),
      ).toHaveLength(0);
      expect(await exists("namespaces", ns)).toBe(true);
      const rows = await successRows("endpoints", ep);
      expect(rows).toHaveLength(1);
      expect(rows[0]).toMatchObject({
        actor_type: "api_key",
        actor_id: fx.operator.uuid,
        target_type: "endpoint",
      });
      expect(rows[0].detail).toMatchObject({
        via: "remove",
        name: impact.name,
        impact_fingerprint: impact.impact_fingerprint,
        snapshot: impact.snapshot,
        budget_class: "destroy",
      });
    });

    it.each([false, true])(
      "refuses while an API key is scoped to it (active: %s), naming the key, and keeps both",
      async (active) => {
        const { ep } = await lonelyEndpoint(`ep-key-${active}`);
        const key = await scopedKey(ep, active);
        const { impact } = await impactOf("endpoints", ep);
        expect(impact.removable).toBe(false);
        expect(impact.blocked_by).toEqual(["endpoint_has_keys"]);
        expect(impact.dependents).toEqual([
          expect.objectContaining({
            rule: "endpoint_has_keys",
            kind: "api_key",
            uuid: key,
            is_active: active,
          }),
        ]);
        const reply = await remove(
          "endpoints",
          ep,
          impact.name,
          impact.impact_fingerprint,
        );
        expect({ status: reply.status, code: reply.code }).toEqual({
          status: 409,
          code: "CONFLICT",
        });
        expect(await exists("endpoints", ep)).toBe(true);
        expect(await exists("api_keys", key)).toBe(true);
        expect(await deniedRules("endpoints", ep)).toEqual([
          "endpoint_has_keys",
        ]);
        expect(await successRows("endpoints", ep)).toHaveLength(0);
      },
    );

    it("refuses while an access group is mapped to it, even an unrestricted one, and reports every blocker at once", async () => {
      const { ep } = await lonelyEndpoint("ep-group");
      const group = await fx.group({ name: uniq("g"), endpoints: [ep] });
      const key = await scopedKey(ep, false);
      const { impact } = await impactOf("endpoints", ep);
      expect(impact.blocked_by).toEqual([
        "endpoint_has_keys",
        "endpoint_has_groups",
      ]);
      expect(impact.dependents.map((d) => [d.rule, d.uuid])).toEqual([
        ["endpoint_has_keys", key],
        ["endpoint_has_groups", group],
      ]);
      await one(`DELETE FROM api_keys WHERE uuid = $1`, [key]);
      const again = await impactOf("endpoints", ep);
      expect(again.impact.blocked_by).toEqual(["endpoint_has_groups"]);
      const reply = await remove(
        "endpoints",
        ep,
        again.impact.name,
        again.impact.impact_fingerprint,
      );
      expect(reply.code).toBe("CONFLICT");
      expect(
        await one(
          `SELECT 1 FROM access_group_endpoints WHERE endpoint_uuid = $1`,
          [ep],
        ),
      ).toHaveLength(1);
      expect(await deniedRules("endpoints", ep)).toEqual([
        "endpoint_has_groups",
      ]);
    });

    it("counts persisted session records without binding the fingerprint to them", async () => {
      const { ep } = await lonelyEndpoint("ep-sessions");
      const before = (await impactOf("endpoints", ep)).impact;
      await one(
        `INSERT INTO mcp_sessions (session_id, namespace_uuid, endpoint_name, auth_principal, auth_method)
         SELECT $1, namespace_uuid, name, 'itest', 'api_key' FROM endpoints WHERE uuid = $2`,
        [uniq("session"), ep],
      );
      const after = (await impactOf("endpoints", ep)).impact;
      expect([before.live_sessions, after.live_sessions]).toEqual([0, 1]);
      expect(after.impact_fingerprint).toBe(before.impact_fingerprint);
      const reply = await remove(
        "endpoints",
        ep,
        before.name,
        before.impact_fingerprint,
      );
      expect(reply.status).toBe(200);
      await one(`DELETE FROM mcp_sessions WHERE session_id LIKE $1`, [
        `%${fx.run}`,
      ]);
    });

    it("preserves the last restricted endpoint when the operator did not set its restriction", async () => {
      const ns = await fx.namespace(uniq("ep-guard-ns"));
      const ep = await fx.endpoint({
        name: uniq("ep-guard"),
        namespaceUuid: ns,
        restricted: true,
      });
      const { impact } = await impactOf("endpoints", ep);
      const reply = await remove(
        "endpoints",
        ep,
        impact.name,
        impact.impact_fingerprint,
      );
      expect(reply.code).toBe("FORBIDDEN");
      expect(impact.removable).toBe(false);
      expect(impact.blocked_by).toEqual(["admin_plane_unrestrict"]);
      expect(await exists("endpoints", ep)).toBe(true);
      expect(await deniedRules("endpoints", ep)).toEqual([
        "admin_plane_unrestrict",
      ]);
    });

    it("lets a key remove a last guard that it restricted within the rollback window", async () => {
      const { ep } = await lonelyEndpoint("ep-guard-owned");
      await one(
        `UPDATE endpoints SET restricted = true, restricted_by_api_key_uuid = $2,
          restricted_at = clock_timestamp() WHERE uuid = $1`,
        [ep, fx.operator.uuid],
      );
      expect((await removeAsRead("endpoints", ep)).status).toBe(200);
      expect(await exists("endpoints", ep)).toBe(false);
    });
  });

  // ---------------------------------------------------------------------------
  describe("namespaces", () => {
    it("removes a namespace with no endpoint, taking its own mounts and tool rows and leaving the servers and their catalogs", async () => {
      const ns = await fx.namespace(uniq("ns-ok"));
      const s = await server("ns-ok-server");
      const t = await tool(s, "ns-ok-tool");
      await mount(ns, s);
      await toolRow(ns, t, s);
      const { impact } = await impactOf("namespaces", ns);
      expect(impact).toMatchObject({
        kind: "namespace",
        removable: true,
        blocked_by: [],
        cascades: [
          { kind: "namespace_server_mapping", count: 1 },
          { kind: "namespace_tool_mapping", count: 1 },
        ],
        live_sessions: 0,
      });
      const reply = await remove(
        "namespaces",
        ns,
        impact.name,
        impact.impact_fingerprint,
      );
      expect(reply.status).toBe(200);
      expect(reply.data).toMatchObject({ removed: true, cleanup: "ok" });
      expect(await exists("namespaces", ns)).toBe(false);
      expect(await exists("mcp_servers", s)).toBe(true);
      expect(await exists("tools", t)).toBe(true);
      expect(cleanup.cleanupIdleServer).toHaveBeenCalledWith(ns);
      expect((await successRows("namespaces", ns))[0].detail).toMatchObject({
        via: "remove",
        snapshot: {
          kind: "namespace",
          cascade_namespace_server_mapping_count: 1,
          cascade_namespace_tool_mapping_count: 1,
        },
      });
    });

    it("refuses while an endpoint serves it, naming a public one and counting another person's private one", async () => {
      const ns = await fx.namespace(uniq("ns-ep"));
      const open = await fx.endpoint({
        name: uniq("ns-ep-open"),
        namespaceUuid: ns,
      });
      await fx.endpoint({
        name: uniq("ns-ep-private"),
        namespaceUuid: ns,
        userId: fx.memberId,
      });
      const { impact } = await impactOf("namespaces", ns);
      expect(impact.blocked_by).toEqual(["namespace_has_endpoints"]);
      expect(impact.dependents.map((d) => d.uuid)).toEqual([open]);
      expect(impact.hidden_dependents).toEqual([
        { rule: "namespace_has_endpoints", count: 1 },
      ]);
      const reply = await remove(
        "namespaces",
        ns,
        impact.name,
        impact.impact_fingerprint,
      );
      expect(reply.code).toBe("CONFLICT");
      expect(await exists("namespaces", ns)).toBe(true);
      expect(await exists("endpoints", open)).toBe(true);
      expect(await deniedRules("namespaces", ns)).toEqual([
        "namespace_has_endpoints",
      ]);
    });
  });

  // ---------------------------------------------------------------------------
  describe("mcpServers", () => {
    it("removes a server no namespace references, with its catalog and OAuth session", async () => {
      const s = await server("srv-ok");
      const t = await tool(s, "srv-ok-tool");
      await one(`INSERT INTO oauth_sessions (mcp_server_uuid) VALUES ($1)`, [
        s,
      ]);
      const { impact } = await impactOf("mcpServers", s);
      expect(impact).toMatchObject({
        kind: "mcp_server",
        removable: true,
        cascades: [
          { kind: "tool", count: 1 },
          { kind: "oauth_session", count: 1 },
        ],
        live_sessions: null,
      });
      // Never a connection setting: the URL, env, headers or bearer token.
      expect(JSON.stringify(impact)).not.toContain("192.0.2.10");
      expect(Object.keys(impact.snapshot).sort()).toEqual(
        [
          "kind",
          "name",
          "owner_user_id",
          "type",
          "error_status",
          "created_at",
          "cascade_tool_count",
          "cascade_oauth_session_count",
        ].sort(),
      );
      const reply = await remove(
        "mcpServers",
        s,
        impact.name,
        impact.impact_fingerprint,
      );
      expect(reply.status).toBe(200);
      expect(reply.data).toMatchObject({ removed: true, cleanup: "ok" });
      expect(await exists("mcp_servers", s)).toBe(false);
      expect(await exists("tools", t)).toBe(false);
      expect(cleanup.cleanupIdleSession).toHaveBeenCalledWith(s);
      expect(cleanup.closeInspector).toHaveBeenCalledWith(s);
    });

    it("refuses while an INACTIVE mount in another person's private namespace holds it, counting it as hidden", async () => {
      const s = await server("srv-mounted");
      const ns = await privateNamespace("srv-mounted-ns", fx.memberId);
      await mount(ns, s, "INACTIVE");
      const { impact } = await impactOf("mcpServers", s);
      expect(impact.blocked_by).toEqual(["server_mounted"]);
      expect(impact.dependents).toEqual([]);
      expect(impact.hidden_dependents).toEqual([
        { rule: "server_mounted", count: 1 },
      ]);
      const reply = await remove(
        "mcpServers",
        s,
        impact.name,
        impact.impact_fingerprint,
      );
      expect(reply.code).toBe("CONFLICT");
      expect(await exists("mcp_servers", s)).toBe(true);
      expect(await deniedRules("mcpServers", s)).toEqual(["server_mounted"]);
    });

    it.each(["names the server", "names one of its tools"] as const)(
      "refuses while a tool row with no mount %s, in either direction of disagreement",
      async (direction) => {
        const s = await server("srv-tools");
        const other = await server("srv-other");
        const mine = await tool(s, "mine");
        const theirs = await tool(other, "theirs");
        const ns = await fx.namespace(uniq("srv-tools-ns"));
        const row =
          direction === "names the server"
            ? await toolRow(ns, theirs, s)
            : await toolRow(ns, mine, other);
        const { impact } = await impactOf("mcpServers", s);
        expect(impact.blocked_by).toEqual(["server_tools_mapped"]);
        expect(impact.dependents).toEqual([
          expect.objectContaining({ rule: "server_tools_mapped", uuid: ns }),
        ]);
        const reply = await remove(
          "mcpServers",
          s,
          impact.name,
          impact.impact_fingerprint,
        );
        expect(reply.code).toBe("CONFLICT");
        expect(await exists("mcp_servers", s)).toBe(true);
        expect(await exists("namespace_tool_mappings", row)).toBe(true);
        expect(await exists("mcp_servers", other)).toBe(true);
      },
    );
  });

  // ---------------------------------------------------------------------------
  describe("the confirmation", () => {
    it("accepts the exact name of a leaf created with a name longer than 100 characters", async () => {
      const { ep } = await lonelyEndpoint(`long-${"a".repeat(101)}`);
      const { impact } = await impactOf("endpoints", ep);
      expect(impact.name.length).toBeGreaterThan(100);
      const reply = await remove(
        "endpoints",
        ep,
        impact.name,
        impact.impact_fingerprint,
      );
      expect(reply.status).toBe(200);
      expect(await exists("endpoints", ep)).toBe(false);
    });

    it("refuses a wrong name with the current fingerprint", async () => {
      const s = await server("cf-name");
      const { impact } = await impactOf("mcpServers", s);
      const reply = await remove(
        "mcpServers",
        s,
        `${impact.name}-x`,
        impact.impact_fingerprint,
      );
      expect({ status: reply.status, code: reply.code }).toEqual({
        status: 400,
        code: "BAD_REQUEST",
      });
      expect(await exists("mcp_servers", s)).toBe(true);
      expect(await deniedRules("mcpServers", s)).toEqual([
        "confirm_name_mismatch",
      ]);
    });

    it("refuses an old fingerprint after a rename, sent with the new name", async () => {
      const { ep } = await lonelyEndpoint("cf-rename");
      const before = (await impactOf("endpoints", ep)).impact;
      const renamed = uniq("cf-renamed");
      await one(`UPDATE endpoints SET name = $2 WHERE uuid = $1`, [
        ep,
        renamed,
      ]);
      const reply = await remove(
        "endpoints",
        ep,
        renamed,
        before.impact_fingerprint,
      );
      expect(reply.code).toBe("CONFLICT");
      expect(await exists("endpoints", ep)).toBe(true);
      expect(await deniedRules("endpoints", ep)).toEqual(["impact_changed"]);
    });

    it("refuses a stale confirmation after a same-name edit of the server or of a tool in its catalog", async () => {
      const s = await server("cf-edit");
      const t = await tool(s, "cf-edit-tool");
      const first = (await impactOf("mcpServers", s)).impact;
      await one(
        `UPDATE mcp_servers SET url = 'http://192.0.2.11:8080/mcp' WHERE uuid = $1`,
        [s],
      );
      const second = (await impactOf("mcpServers", s)).impact;
      expect(second.name).toBe(first.name);
      expect(second.impact_fingerprint).not.toBe(first.impact_fingerprint);
      await one(`UPDATE tools SET description = 'edited' WHERE uuid = $1`, [t]);
      const third = (await impactOf("mcpServers", s)).impact;
      expect(third.impact_fingerprint).not.toBe(second.impact_fingerprint);
      for (const stale of [first, second]) {
        const reply = await remove(
          "mcpServers",
          s,
          stale.name,
          stale.impact_fingerprint,
        );
        expect(reply.code).toBe("CONFLICT");
      }
      expect(await exists("mcp_servers", s)).toBe(true);
    });

    it("keeps the confirmation usable across an OAuth token refresh, and not across a replaced OAuth session", async () => {
      const s = await server("cf-oauth");
      await one(`INSERT INTO oauth_sessions (mcp_server_uuid) VALUES ($1)`, [
        s,
      ]);
      const first = (await impactOf("mcpServers", s)).impact;
      await one(
        `UPDATE oauth_sessions SET tokens = '{"access_token":"refreshed"}'::jsonb, updated_at = now() WHERE mcp_server_uuid = $1`,
        [s],
      );
      const refreshed = (await impactOf("mcpServers", s)).impact;
      expect(refreshed.impact_fingerprint).toBe(first.impact_fingerprint);
      await one(`DELETE FROM oauth_sessions WHERE mcp_server_uuid = $1`, [s]);
      await one(`INSERT INTO oauth_sessions (mcp_server_uuid) VALUES ($1)`, [
        s,
      ]);
      const replaced = (await impactOf("mcpServers", s)).impact;
      expect(replaced.impact_fingerprint).not.toBe(first.impact_fingerprint);
      expect(
        (await remove("mcpServers", s, first.name, first.impact_fingerprint))
          .code,
      ).toBe("CONFLICT");
      expect(
        (
          await remove(
            "mcpServers",
            s,
            replaced.name,
            replaced.impact_fingerprint,
          )
        ).status,
      ).toBe(200);
    });
  });

  // ---------------------------------------------------------------------------
  describe("private rows and scope", () => {
    it("answers NOT_FOUND for another person's private row and removes nothing", async () => {
      const s = await server("pv-other", fx.memberId);
      const { reply } = await impactOf("mcpServers", s);
      expect(reply.code).toBe("NOT_FOUND");
      const removal = await remove(
        "mcpServers",
        s,
        "anything",
        `sha256:${"0".repeat(64)}`,
      );
      expect(removal.code).toBe("NOT_FOUND");
      expect(await exists("mcp_servers", s)).toBe(true);
    });

    it("refuses the caller's own private row as a person's act in the UI", async () => {
      const s = await server("pv-own", fx.ownerId);
      const { impact } = await impactOf("mcpServers", s);
      expect(impact.blocked_by).toEqual(["target_private"]);
      const reply = await remove(
        "mcpServers",
        s,
        impact.name,
        impact.impact_fingerprint,
      );
      expect(reply.code).toBe("FORBIDDEN");
      expect(await exists("mcp_servers", s)).toBe(true);
      expect(await deniedRules("mcpServers", s)).toEqual(["target_private"]);
    });

    it("refuses the sync key, a member's session and an operator change without a reason, removing nothing", async () => {
      const s = await server("scope");
      const { impact } = await impactOf("mcpServers", s);
      for (const kind of ["endpoints", "namespaces", "mcpServers"] as Kind[]) {
        const read = await impactOf(kind, s, fx.sync.key);
        expect({ kind, code: read.reply.code }).toEqual({
          kind,
          code: "FORBIDDEN",
        });
      }
      const bySync = await remove(
        "mcpServers",
        s,
        impact.name,
        impact.impact_fingerprint,
        { key: fx.sync.key },
      );
      expect(bySync.code).toBe("FORBIDDEN");
      const byMember = await remove(
        "mcpServers",
        s,
        impact.name,
        impact.impact_fingerprint,
        { cookie: fx.memberCookie },
      );
      expect(["FORBIDDEN", "UNAUTHORIZED"]).toContain(byMember.code);
      const noReason = await remove(
        "mcpServers",
        s,
        impact.name,
        impact.impact_fingerprint,
        { reason: null },
      );
      expect({ status: noReason.status, code: noReason.code }).toEqual({
        status: 400,
        code: "BAD_REQUEST",
      });
      expect(await exists("mcp_servers", s)).toBe(true);
      expect(await successRows("mcpServers", s)).toHaveLength(0);
    });

    it("keeps the broad deletes out of the operator key's reach", async () => {
      const s = await server("broad");
      const reply = await fx.trpc(
        "frontend.mcpServers.delete",
        { uuid: s },
        "mutation",
      );
      expect(reply.code).toBe("FORBIDDEN");
      expect(await exists("mcp_servers", s)).toBe(true);
    });
  });

  // ---------------------------------------------------------------------------
  describe("rollback", () => {
    it("rolls the removal and its cascades back when its audit row cannot be written", async () => {
      const { ep } = await lonelyEndpoint("rb-audit");
      await one(
        `INSERT INTO endpoint_presentation (endpoint_uuid, title) VALUES ($1, 't')`,
        [ep],
      );
      const { impact } = await impactOf("endpoints", ep);
      await fx.failAuditFor("endpoint.delete");
      try {
        const reply = await remove(
          "endpoints",
          ep,
          impact.name,
          impact.impact_fingerprint,
        );
        expect(reply.status).toBe(500);
      } finally {
        await fx.clearAuditFault("endpoint.delete");
      }
      expect(await exists("endpoints", ep)).toBe(true);
      expect(
        await one(
          `SELECT 1 FROM endpoint_presentation WHERE endpoint_uuid = $1`,
          [ep],
        ),
      ).toHaveLength(1);
    });

    it("refuses a removal past the destroy budget before anything is written", async () => {
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
      const previous = process.env.ADMIN_PLANE_BUDGET_OPERATOR_DESTROY;
      process.env.ADMIN_PLANE_BUDGET_OPERATOR_DESTROY = "1";
      try {
        const a = await server("budget-a");
        const b = await server("budget-b");
        const t = await tool(b, "budget-b-tool");
        expect((await removeAsRead("mcpServers", a, created.key)).status).toBe(
          200,
        );
        const over = await removeAsRead("mcpServers", b, created.key);
        expect(over.code).toBe("TOO_MANY_REQUESTS");
        expect(await exists("mcp_servers", b)).toBe(true);
        expect(await exists("tools", t)).toBe(true);
      } finally {
        process.env.ADMIN_PLANE_BUDGET_OPERATOR_DESTROY = previous;
      }
    });
  });

  // ---------------------------------------------------------------------------
  describe("concurrency", () => {
    it("refuses when a sibling guard was deleted while the endpoint removal waited", async () => {
      const ns = await fx.namespace(uniq("cc-guard-ns"));
      const ep = await fx.endpoint({
        name: uniq("cc-guard"),
        namespaceUuid: ns,
        restricted: true,
      });
      const sibling = await fx.endpoint({
        name: uniq("cc-sibling-guard"),
        namespaceUuid: ns,
        restricted: true,
      });
      const { impact } = await impactOf("endpoints", ep);
      expect(impact.removable).toBe(true);
      await barrier.query("BEGIN");
      let committed = false;
      try {
        await barrier.query("DELETE FROM endpoints WHERE uuid = $1", [sibling]);
        const pending = remove(
          "endpoints",
          ep,
          impact.name,
          impact.impact_fingerprint,
        );
        // A broad delete by a person takes the sibling row lock directly.
        await waitForLockWaiters(1);
        await barrier.query("COMMIT");
        committed = true;
        expect((await pending).code).toBe("FORBIDDEN");
      } finally {
        if (!committed) await barrier.query("ROLLBACK");
      }
      expect(await exists("endpoints", ep)).toBe(true);
      expect(await deniedRules("endpoints", ep)).toEqual([
        "admin_plane_unrestrict",
      ]);
    });

    it("answers NOT_FOUND if a moved endpoint becomes private while removal waits for its gate", async () => {
      const { ns, ep } = await lonelyEndpoint("cc-private-move");
      const destination = await fx.namespace(uniq("cc-destination"));
      const { impact } = await impactOf("endpoints", ep);
      await barrier.query("BEGIN");
      let committed = false;
      try {
        await barrier.query(
          "SELECT pg_advisory_xact_lock(hashtext($1), hashtext($2))",
          [ENDPOINT_NAMESPACE_LOCK_NAMESPACE, ns],
        );
        const pending = remove(
          "endpoints",
          ep,
          impact.name,
          impact.impact_fingerprint,
        );
        await waitForLockWaiters(1);
        await barrier.query(
          "UPDATE endpoints SET namespace_uuid = $2, user_id = $3 WHERE uuid = $1",
          [ep, destination, fx.memberId],
        );
        await barrier.query("COMMIT");
        committed = true;
        expect(await pending).toMatchObject({
          status: 404,
          code: "NOT_FOUND",
          message: "Endpoint not found",
        });
      } finally {
        if (!committed) await barrier.query("ROLLBACK");
      }
      expect(await exists("endpoints", ep)).toBe(true);
      expect(await successRows("endpoints", ep)).toHaveLength(0);
    });

    it("refuses after an OAuth session deletion that commits while the server removal waits", async () => {
      const s = await server("cc-oauth");
      await one(`INSERT INTO oauth_sessions (mcp_server_uuid) VALUES ($1)`, [
        s,
      ]);
      const { impact } = await impactOf("mcpServers", s);
      await barrier.query("BEGIN");
      let committed = false;
      try {
        await barrier.query(
          "DELETE FROM oauth_sessions WHERE mcp_server_uuid = $1",
          [s],
        );
        const pending = remove(
          "mcpServers",
          s,
          impact.name,
          impact.impact_fingerprint,
        );
        await waitForLockWaiters(1);
        await barrier.query("COMMIT");
        committed = true;
        expect((await pending).code).toBe("CONFLICT");
      } finally {
        if (!committed) await barrier.query("ROLLBACK");
      }
      expect(await exists("mcp_servers", s)).toBe(true);
      expect(await deniedRules("mcpServers", s)).toEqual(["impact_changed"]);
    });

    it("sees a key that committed while the removal waited for the endpoint row", async () => {
      const { ep } = await lonelyEndpoint("cc-key-first");
      const { impact } = await impactOf("endpoints", ep);
      await barrier.query("BEGIN");
      let committed = false;
      try {
        // The insert's foreign-key check holds FOR KEY SHARE on the endpoint.
        await barrier.query(
          `INSERT INTO api_keys (name, key_hash, last4, user_id, endpoint_uuid, is_active)
           VALUES ($1, $2, 'abcd', $3, $4, false)`,
          [uniq("cc-key"), `itest-hash-${uniq("h")}`, fx.memberId, ep],
        );
        const pending = remove(
          "endpoints",
          ep,
          impact.name,
          impact.impact_fingerprint,
        );
        await waitForLockWaiters(1);
        await barrier.query("COMMIT");
        committed = true;
        const reply = await pending;
        expect(reply.code).toBe("CONFLICT");
      } finally {
        if (!committed) await barrier.query("ROLLBACK");
      }
      expect(await exists("endpoints", ep)).toBe(true);
      expect(await deniedRules("endpoints", ep)).toEqual(["endpoint_has_keys"]);
    });

    /** Hold the removal at its own audit write, after its delete, before its commit. */
    async function holdingRemovalAudit<T>(
      action: string,
      during: () => Promise<T>,
    ): Promise<T> {
      const gate = "hashtext('itest.topology.removal.audit')";
      await one(`CREATE OR REPLACE FUNCTION itest_hold_topology_audit() RETURNS trigger AS $$
        BEGIN
          IF NEW.outcome = 'success' AND NEW.action = '${action}' THEN
            PERFORM pg_advisory_lock_shared(${gate});
            PERFORM pg_advisory_unlock_shared(${gate});
          END IF;
          RETURN NEW;
        END $$ LANGUAGE plpgsql`);
      await one(
        `DROP TRIGGER IF EXISTS itest_hold_topology_audit_trg ON audit_log`,
      );
      await one(`CREATE TRIGGER itest_hold_topology_audit_trg BEFORE INSERT ON audit_log
        FOR EACH ROW EXECUTE FUNCTION itest_hold_topology_audit()`);
      await barrier.query(`SELECT pg_advisory_lock(${gate})`);
      try {
        return await during();
      } finally {
        await barrier
          .query(`SELECT pg_advisory_unlock(${gate})`)
          .catch(() => undefined);
        await one(
          `DROP TRIGGER IF EXISTS itest_hold_topology_audit_trg ON audit_log`,
        );
        await one(`DROP FUNCTION IF EXISTS itest_hold_topology_audit()`);
      }
    }

    it("fails a key insert that waits behind a removal of its endpoint", async () => {
      const { ep } = await lonelyEndpoint("cc-remove-first");
      const { impact } = await impactOf("endpoints", ep);
      const name = uniq("cc-late-key");
      const [reply, insert] = await holdingRemovalAudit(
        "endpoint.delete",
        async () => {
          const pending = remove(
            "endpoints",
            ep,
            impact.name,
            impact.impact_fingerprint,
          );
          await waitForLockWaiters(1);
          const late = child
            .query(
              `INSERT INTO api_keys (name, key_hash, last4, user_id, endpoint_uuid, is_active)
               VALUES ($1, $2, 'abcd', $3, $4, false)`,
              [name, `itest-hash-${uniq("h")}`, fx.memberId, ep],
            )
            .then(
              () => ({ code: "ok" }),
              (error: { code?: string }) => ({ code: error.code }),
            );
          await waitForLockWaiters(2);
          await barrier.query(
            `SELECT pg_advisory_unlock(hashtext('itest.topology.removal.audit'))`,
          );
          return [await pending, await late] as const;
        },
      );
      expect(reply.status).toBe(200);
      expect(insert.code).toBe("23503");
      expect(await exists("endpoints", ep)).toBe(false);
      expect(
        await one(`SELECT 1 FROM api_keys WHERE name = $1`, [name]),
      ).toHaveLength(0);
    });

    it("fails a tool row attached only through the catalog that waits behind a server removal", async () => {
      const s = await server("cc-catalog");
      const other = await server("cc-catalog-other");
      const t = await tool(s, "cc-catalog-tool");
      const ns = await fx.namespace(uniq("cc-catalog-ns"));
      const { impact } = await impactOf("mcpServers", s);
      const [reply, insert] = await holdingRemovalAudit(
        "mcpserver.delete",
        async () => {
          const pending = remove(
            "mcpServers",
            s,
            impact.name,
            impact.impact_fingerprint,
          );
          await waitForLockWaiters(1);
          const late = child
            .query(
              `INSERT INTO namespace_tool_mappings (namespace_uuid, tool_uuid, mcp_server_uuid)
               VALUES ($1, $2, $3)`,
              [ns, t, other],
            )
            .then(
              () => ({ code: "ok" }),
              (error: { code?: string }) => ({ code: error.code }),
            );
          await waitForLockWaiters(2);
          await barrier.query(
            `SELECT pg_advisory_unlock(hashtext('itest.topology.removal.audit'))`,
          );
          return [await pending, await late] as const;
        },
      );
      expect(reply.status).toBe(200);
      expect(insert.code).toBe("23503");
      expect(await exists("mcp_servers", s)).toBe(false);
      expect(await exists("mcp_servers", other)).toBe(true);
    });

    it("judges an in-place catalog edit that committed while the removal waited", async () => {
      const s = await server("cc-edit");
      const t = await tool(s, "cc-edit-tool");
      const { impact } = await impactOf("mcpServers", s);
      await barrier.query("BEGIN");
      let committed = false;
      try {
        await barrier.query(
          `UPDATE tools SET description = 'edited while waiting' WHERE uuid = $1`,
          [t],
        );
        const pending = remove(
          "mcpServers",
          s,
          impact.name,
          impact.impact_fingerprint,
        );
        await waitForLockWaiters(1);
        await barrier.query("COMMIT");
        committed = true;
        const reply = await pending;
        expect(reply.code).toBe("CONFLICT");
      } finally {
        if (!committed) await barrier.query("ROLLBACK");
      }
      expect(await exists("mcp_servers", s)).toBe(true);
      expect(await deniedRules("mcpServers", s)).toEqual(["impact_changed"]);
    });
  });
});
