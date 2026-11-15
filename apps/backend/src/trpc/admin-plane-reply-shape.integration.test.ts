/**
 * The admin-plane reply shape and the rails that go with it, against a real
 * Postgres, through the real /trpc stack:
 *
 *  - an admin-plane key (operator or sync scope) never receives a stored
 *    connection value: distinct canaries in a server's command, arguments,
 *    environment, headers and in a URL's userinfo, path, query and fragment
 *    are absent from list, the create and update replies, the servers embedded
 *    by `namespaces.get` and the audit read, while a person signed in as an
 *    administrator still sees them and `mcpServers.get` and `listAll` stay
 *    refused to a key;
 *  - an operator-scope key cannot create a server or send the full update (a
 *    coded rule and a `denied` row each), renames through the strict
 *    metadata-only variant and changes nothing else, and the sync scope keeps
 *    create and the full update;
 *  - an admin-plane key's unmount keeps a server's tool rows, so a remount
 *    finds each tool in the state it was left in, and its refresh never
 *    changes an existing row; a person's unmount and refresh are unchanged;
 *  - an admin-plane create or update never leaves both authentication modes
 *    off, a person may;
 *  - the topology writes that can put a tool in front of callers count as
 *    loosening, in both directions of each class, and the sync scope can
 *    create a server within its budget, with a concurrent last slot refused
 *    before the write;
 *  - the capabilities carry the two markers and stay at contract 3.
 */
import { randomBytes } from "node:crypto";

import { Client } from "pg";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

import { SERVER_NAME_TAKEN_MESSAGE } from "../db/repositories/mcp-server-name-rule";
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
    invalidateIdleServer: vi.fn().mockResolvedValue(undefined),
    invalidateIdleServers: vi.fn().mockResolvedValue(undefined),
    invalidateOpenApiSessions: vi.fn().mockResolvedValue(undefined),
  },
}));

type Reply = Awaited<ReturnType<Fixture["trpc"]>>;

/** One value per place a connection can hold a credential, all distinct. */
const CANARY = {
  command: "canary-command-3f2a91",
  arg: "canary-arg-71be04",
  envValue: "canary-env-value-c05d17",
  headerValue: "canary-header-value-9a44e2",
  user: "canary-user-5be8d3",
  pass: "canary-pass-0c7f62",
  path: "canary-path-d1f60b",
  query: "canary-query-47c3aa",
  fragment: "canary-fragment-e82b59",
  bearer: "canary-bearer-b9137e",
};
const CANARY_URL = `https://${CANARY.user}:${CANARY.pass}@vendor.example.test:8443/${CANARY.path}/mcp?k=${CANARY.query}#${CANARY.fragment}`;
/** The same, for the values an update writes. */
const NEXT = {
  command: "canary-command-next-8a1d",
  arg: "canary-arg-next-2f90",
  envValue: "canary-env-next-6b43",
  headerValue: "canary-header-next-d7e5",
  path: "canary-path-next-31c8",
  query: "canary-query-next-a60f",
  fragment: "canary-fragment-next-94be",
  bearer: "canary-bearer-next-0d52",
};
const NEXT_URL = `https://vendor-next.example.test:8443/${NEXT.path}/mcp?k=${NEXT.query}#${NEXT.fragment}`;

const everyCanary = [...Object.values(CANARY), ...Object.values(NEXT)];

const absent = (value: unknown) => {
  const text = JSON.stringify(value);
  for (const canary of everyCanary) expect(text).not.toContain(canary);
};

describeIfDb("admin-plane reply shape and rails (real Postgres)", () => {
  let fx: Fixture;
  let barrier: Client;
  let priorKek: string | undefined;
  let counter = 0;
  const uniq = (stem: string) => `${stem}-${++counter}-${fx.run}`;
  const serverUuids: string[] = [];
  const namespaceUuids: string[] = [];

  const one = async (sql: string, params: unknown[] = []) =>
    (await fx.suiteLock.query(sql, params)).rows;
  const operator = (procedure: string, input: unknown, key?: string) =>
    fx.trpc(`frontend.${procedure}`, input, "mutation", key ? { key } : {});
  const sync = (procedure: string, input: unknown, key?: string) =>
    fx.trpc(`frontend.${procedure}`, input, "mutation", {
      key: key ?? fx.sync.key,
    });
  const human = (procedure: string, input: unknown) =>
    fx.trpc(`frontend.${procedure}`, input, "mutation", {
      cookie: fx.ownerCookie,
    });
  const read = (procedure: string, input: unknown, key?: string) =>
    fx.trpc(`frontend.${procedure}`, input, "query", key ? { key } : {});
  const humanRead = (procedure: string, input: unknown) =>
    fx.trpc(`frontend.${procedure}`, input, "query", {
      cookie: fx.ownerCookie,
    });
  const ok = (reply: Reply) =>
    reply.status === 200 &&
    (reply.data as { success?: boolean } | undefined)?.success !== false;
  const dataOf = <T>(reply: Reply) => (reply.data as { data: T }).data;

  /** A server row written straight to the table, with a canary in every place. */
  async function seedServer(over: { userId?: string | null } = {}) {
    const name = uniq("rs-server");
    const [row] = await one(
      `INSERT INTO mcp_servers (name, type, command, args, env, url, headers, bearer_token, user_id, description)
       VALUES ($1, 'STREAMABLE_HTTP', $2, $3, $4::jsonb, $5, $6::jsonb, $7, $8, 'a seeded description')
       RETURNING uuid`,
      [
        name,
        CANARY.command,
        [CANARY.arg],
        JSON.stringify({ TOKEN: CANARY.envValue }),
        CANARY_URL,
        JSON.stringify({ Authorization: `Bearer ${CANARY.headerValue}` }),
        CANARY.bearer,
        over.userId ?? null,
      ],
    );
    serverUuids.push(row.uuid as string);
    return { uuid: row.uuid as string, name };
  }

  /** The whole stored row, for "nothing else changed". */
  const serverRow = async (uuid: string) =>
    (await one(`SELECT * FROM mcp_servers WHERE uuid = $1`, [uuid]))[0];

  async function seedTool(serverUuid: string, name: string) {
    const [row] = await one(
      `INSERT INTO tools (name, mcp_server_uuid, tool_schema) VALUES ($1, $2, '{"type":"object"}'::jsonb) RETURNING uuid`,
      [name, serverUuid],
    );
    return row.uuid as string;
  }

  async function mount(
    namespaceUuid: string,
    serverUuid: string,
    tools: Array<{ uuid: string; status: "ACTIVE" | "INACTIVE" }>,
  ) {
    await one(
      `INSERT INTO namespace_server_mappings (namespace_uuid, mcp_server_uuid, status) VALUES ($1, $2, 'ACTIVE')`,
      [namespaceUuid, serverUuid],
    );
    for (const tool of tools) {
      await one(
        `INSERT INTO namespace_tool_mappings (namespace_uuid, tool_uuid, mcp_server_uuid, status) VALUES ($1, $2, $3, $4)`,
        [namespaceUuid, tool.uuid, serverUuid, tool.status],
      );
    }
  }

  const toolStatuses = async (namespaceUuid: string, serverUuid: string) =>
    Object.fromEntries(
      (
        await one(
          `SELECT t.name AS name, m.status AS status
             FROM namespace_tool_mappings m JOIN tools t ON t.uuid = m.tool_uuid
            WHERE m.namespace_uuid = $1 AND m.mcp_server_uuid = $2`,
          [namespaceUuid, serverUuid],
        )
      ).map((row) => [row.name as string, row.status as string]),
    );

  /** The same read-back an operator has: namespaces.getTools. */
  const toolStatusesThroughApi = async (namespaceUuid: string) =>
    Object.fromEntries(
      (
        dataOf<Array<{ name: string; status: string }>>(
          await read("namespaces.getTools", { namespaceUuid }),
        ) ?? []
      ).map((tool) => [tool.name, tool.status]),
    );

  const mountStatus = async (namespaceUuid: string, serverUuid: string) =>
    (
      await one(
        `SELECT status FROM namespace_server_mappings WHERE namespace_uuid = $1 AND mcp_server_uuid = $2`,
        [namespaceUuid, serverUuid],
      )
    )[0]?.status as string | undefined;

  const namespaceOf = async (
    stem: string,
    policy: "allow_all" | "allowlist",
  ) => {
    const uuid = await fx.namespace(uniq(stem));
    if (policy === "allowlist") {
      await one(
        `UPDATE namespaces SET tool_policy = 'allowlist' WHERE uuid = $1`,
        [uuid],
      );
    }
    return uuid;
  };

  const classOf = async (action: string, targetId: string) =>
    (
      await fx.auditNow(
        `action = $1 AND target_id = $2 AND outcome = 'success'`,
        [action, targetId],
      )
    ).map((row) => (row.detail as Record<string, unknown>).budget_class);

  const deniedRule = async (action: string, targetId: string | null) =>
    (
      await fx.auditNow(
        `action = $1 AND outcome = 'denied' AND ${
          targetId === null ? "actor_id = $2" : "target_id = $2"
        }`,
        [action, targetId ?? fx.operator.uuid],
      )
    ).map((row) => (row.detail as Record<string, unknown>).rule);

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

  async function freshKey(scope: "operator" | "sync") {
    const { ApiKeysRepository } = await import(
      "../db/repositories/api-keys.repo"
    );
    const created = await new ApiKeysRepository().create({
      name: uniq(`rs-${scope}-key`),
      user_id: fx.ownerId,
      admin_plane: true,
      ...(scope === "operator"
        ? { admin_plane_scope: "operator" as const }
        : {}),
      is_active: true,
    });
    return { key: created.key, uuid: created.uuid };
  }

  beforeAll(async () => {
    // A server's bearer token is encrypted at rest under this key.
    priorKek = process.env.M365_TOKEN_KEK;
    process.env.M365_TOKEN_KEK = randomBytes(32).toString("base64");
    fx = await createFixture(TEST_DATABASE_URL as string, "rshape");
    barrier = new Client({ connectionString: TEST_DATABASE_URL });
    await barrier.connect();
  });

  afterAll(async () => {
    await barrier?.end();
    if (fx) {
      for (const uuid of serverUuids) {
        await one(`DELETE FROM mcp_servers WHERE uuid = $1`, [uuid]);
      }
      await one(`DELETE FROM mcp_servers WHERE name LIKE $1`, [`%${fx.run}`]);
      for (const uuid of namespaceUuids) {
        await one(`DELETE FROM namespaces WHERE uuid = $1`, [uuid]);
      }
      await one(`DELETE FROM endpoints WHERE name LIKE $1`, [`%${fx.run}`]);
    }
    if (priorKek === undefined) delete process.env.M365_TOKEN_KEK;
    else process.env.M365_TOKEN_KEK = priorKek;
    await fx?.close();
  });

  // ---------------------------------------------------------------------------
  describe("what an admin-plane key receives of a server's connection", () => {
    it.each([
      ["operator", undefined],
      ["sync", "sync"],
    ] as const)(
      "withholds every canary from mcpServers.list for a %s-scope key, keeping the names",
      async (_scope, which) => {
        const server = await seedServer();
        const reply = await read(
          "mcpServers.list",
          undefined,
          which === "sync" ? fx.sync.key : undefined,
        );

        expect(reply.status).toBe(200);
        absent(reply.data);
        const row = dataOf<Array<Record<string, unknown>>>(reply).find(
          (entry) => entry.uuid === server.uuid,
        );
        expect(row).toMatchObject({
          name: server.name,
          type: "STREAMABLE_HTTP",
          env: { TOKEN: "" },
          headers: { Authorization: "" },
          command: null,
          args: [],
          url: null,
          bearerToken: null,
        });
      },
    );

    it("shows a person signed in as an administrator the stored connection, and keeps raw get and listAll refused to both key scopes", async () => {
      const server = await seedServer();

      const listed = await humanRead("mcpServers.list", undefined);
      const row = dataOf<Array<Record<string, unknown>>>(listed).find(
        (entry) => entry.uuid === server.uuid,
      );
      expect(row).toMatchObject({
        env: { TOKEN: CANARY.envValue },
        command: CANARY.command,
        args: [CANARY.arg],
        url: CANARY_URL,
        headers: { Authorization: `Bearer ${CANARY.headerValue}` },
        bearerToken: null,
      });
      const got = await humanRead("mcpServers.get", { uuid: server.uuid });
      expect(dataOf<Record<string, unknown>>(got)).toMatchObject({
        url: CANARY_URL,
      });
      const everything = await humanRead("mcpServers.listAll", undefined);
      expect(JSON.stringify(everything.data)).toContain(CANARY.envValue);

      for (const key of [fx.operator.key, fx.sync.key]) {
        for (const [procedure, input] of [
          ["mcpServers.get", { uuid: server.uuid }],
          ["mcpServers.listAll", undefined],
        ] as const) {
          const refused = await read(procedure, input, key);
          expect({
            procedure,
            status: refused.status,
            code: refused.code,
          }).toEqual({ procedure, status: 403, code: "FORBIDDEN" });
          absent(refused);
        }
      }
    });

    it.each([
      ["operator", undefined],
      ["sync", "sync"],
    ] as const)(
      "withholds every canary from the servers namespaces.get embeds for a %s-scope key, and still shows a person",
      async (_scope, which) => {
        const server = await seedServer();
        const ns = await namespaceOf("rs-embed-ns", "allow_all");
        await mount(ns, server.uuid, []);

        const reply = await read(
          "namespaces.get",
          { uuid: ns },
          which === "sync" ? fx.sync.key : undefined,
        );

        expect(reply.status).toBe(200);
        absent(reply.data);
        const embedded = dataOf<{ servers: Array<Record<string, unknown>> }>(
          reply,
        ).servers.find((entry) => entry.uuid === server.uuid);
        expect(embedded).toMatchObject({
          name: server.name,
          status: "ACTIVE",
          env: { TOKEN: "" },
          headers: { Authorization: "" },
          command: null,
          args: [],
          url: null,
          bearerToken: null,
        });

        const personal = await humanRead("namespaces.get", { uuid: ns });
        const seen = dataOf<{ servers: Array<Record<string, unknown>> }>(
          personal,
        ).servers.find((entry) => entry.uuid === server.uuid);
        expect(seen).toMatchObject({
          env: { TOKEN: CANARY.envValue },
          command: CANARY.command,
          url: CANARY_URL,
        });
      },
    );

    it("withholds every canary from a sync key's create and update replies, while the row holds what was written", async () => {
      const name = uniq("rs-create");
      const created = await sync("mcpServers.create", {
        name,
        type: "STREAMABLE_HTTP",
        url: CANARY_URL,
        command: CANARY.command,
        args: [CANARY.arg],
        env: { TOKEN: CANARY.envValue },
        headers: { Authorization: `Bearer ${CANARY.headerValue}` },
        bearerToken: CANARY.bearer,
      });
      expect(ok(created)).toBe(true);
      absent(created.data);
      expect(dataOf<Record<string, unknown>>(created)).toMatchObject({
        name,
        env: { TOKEN: "" },
        headers: { Authorization: "" },
        command: null,
        args: [],
        url: null,
        bearerToken: null,
      });
      const uuid = dataOf<{ uuid: string }>(created).uuid;
      serverUuids.push(uuid);
      expect((await serverRow(uuid)).url).toBe(CANARY_URL);

      const updated = await sync("mcpServers.update", {
        uuid,
        name,
        type: "STREAMABLE_HTTP",
        url: NEXT_URL,
        command: NEXT.command,
        args: [NEXT.arg],
        env: { TOKEN: NEXT.envValue },
        headers: { Authorization: `Bearer ${NEXT.headerValue}` },
        bearerToken: NEXT.bearer,
      });
      expect(ok(updated)).toBe(true);
      absent(updated.data);
      expect(dataOf<Record<string, unknown>>(updated)).toMatchObject({
        env: { TOKEN: "" },
        url: null,
        command: null,
      });
      expect((await serverRow(uuid)).url).toBe(NEXT_URL);
    });

    it("keeps a person's create and update replies as they were", async () => {
      const name = uniq("rs-human");
      const created = await human("mcpServers.create", {
        name,
        type: "STREAMABLE_HTTP",
        url: CANARY_URL,
        env: { TOKEN: CANARY.envValue },
        headers: { Authorization: `Bearer ${CANARY.headerValue}` },
      });
      expect(ok(created)).toBe(true);
      const uuid = dataOf<{ uuid: string }>(created).uuid;
      serverUuids.push(uuid);
      expect(dataOf<Record<string, unknown>>(created)).toMatchObject({
        url: CANARY_URL,
        env: { TOKEN: CANARY.envValue },
        bearerToken: null,
      });
      const updated = await human("mcpServers.update", {
        uuid,
        name,
        type: "STREAMABLE_HTTP",
        url: NEXT_URL,
        env: { TOKEN: NEXT.envValue },
        // A URL change must say what happens to the stored headers.
        headers: { Authorization: `Bearer ${NEXT.headerValue}` },
      });
      expect(ok(updated)).toBe(true);
      expect(dataOf<Record<string, unknown>>(updated)).toMatchObject({
        url: NEXT_URL,
        env: { TOKEN: NEXT.envValue },
      });
    });

    it("carries no canary in the audit read of a write that changed every connection field", async () => {
      const server = await seedServer();
      const reply = await sync("mcpServers.update", {
        uuid: server.uuid,
        name: server.name,
        type: "STREAMABLE_HTTP",
        url: NEXT_URL,
        command: NEXT.command,
        args: [NEXT.arg],
        env: { TOKEN: NEXT.envValue },
        headers: { Authorization: `Bearer ${NEXT.headerValue}` },
        bearerToken: NEXT.bearer,
      });
      expect(ok(reply)).toBe(true);

      const audit = await read("audit.list", {
        action: "mcpserver.update",
        target_id: server.uuid,
      });
      expect(audit.status).toBe(200);
      expect((audit.data as { rows: unknown[] }).rows.length).toBeGreaterThan(
        0,
      );
      absent(audit.data);
      const [stored] = await one(
        `SELECT detail::text AS text FROM audit_log WHERE action = 'mcpserver.update' AND target_id = $1`,
        [server.uuid],
      );
      for (const canary of everyCanary) {
        expect(stored.text).not.toContain(canary);
      }
    });
  });

  // ---------------------------------------------------------------------------
  describe("what an operator-scope key may do to a server", () => {
    it("renames through the metadata-only variant and changes nothing else", async () => {
      const server = await seedServer();
      const before = await serverRow(server.uuid);
      const renamed = uniq("rs-renamed");

      const reply = await operator("mcpServers.update", {
        uuid: server.uuid,
        metadata_only: true,
        name: renamed,
      });

      expect(ok(reply)).toBe(true);
      absent(reply.data);
      expect(dataOf<Record<string, unknown>>(reply)).toMatchObject({
        uuid: server.uuid,
        name: renamed,
        env: { TOKEN: "" },
        url: null,
      });
      const after = await serverRow(server.uuid);
      expect(after).toEqual({ ...before, name: renamed });

      const [row] = await fx.auditNow(
        `action = 'mcpserver.update' AND target_id = $1 AND outcome = 'success'`,
        [server.uuid],
      );
      expect(row).toMatchObject({ actor_type: "api_key" });
      expect(row.detail).toMatchObject({
        budget_class: "change",
        changed_fields: ["name"],
      });
    });

    it("changes only the description when only a description is sent, and both when both are", async () => {
      const server = await seedServer();
      const before = await serverRow(server.uuid);

      expect(
        ok(
          await operator("mcpServers.update", {
            uuid: server.uuid,
            metadata_only: true,
            description: "now described",
          }),
        ),
      ).toBe(true);
      expect(await serverRow(server.uuid)).toEqual({
        ...before,
        description: "now described",
      });

      const renamed = uniq("rs-both");
      expect(
        ok(
          await operator("mcpServers.update", {
            uuid: server.uuid,
            metadata_only: true,
            name: renamed,
            description: "described again",
          }),
        ),
      ).toBe(true);
      expect(await serverRow(server.uuid)).toEqual({
        ...before,
        name: renamed,
        description: "described again",
      });
    });

    it("lets the sync scope rename the same way", async () => {
      const server = await seedServer();
      const renamed = uniq("rs-sync-renamed");

      const reply = await sync("mcpServers.update", {
        uuid: server.uuid,
        metadata_only: true,
        name: renamed,
      });

      expect(ok(reply)).toBe(true);
      expect((await serverRow(server.uuid)).name).toBe(renamed);
    });

    it.each([
      ["a URL", { url: NEXT_URL }],
      ["a type", { type: "SSE" }],
      ["a command", { command: NEXT.command }],
      ["arguments", { args: [NEXT.arg] }],
      ["an environment", { env: { TOKEN: NEXT.envValue } }],
      ["headers", { headers: { Authorization: NEXT.headerValue } }],
      ["a bearer token", { bearerToken: NEXT.bearer }],
      ["an owner", { user_id: fx?.memberId ?? null }],
    ])(
      "rejects a metadata-only update that also carries %s, changing nothing",
      async (_label, extra) => {
        const server = await seedServer();
        const before = await serverRow(server.uuid);

        const reply = await operator("mcpServers.update", {
          uuid: server.uuid,
          metadata_only: true,
          name: uniq("rs-never"),
          ...extra,
        });

        expect({ status: reply.status, code: reply.code }).toEqual({
          status: 400,
          code: "BAD_REQUEST",
        });
        expect(await serverRow(server.uuid)).toEqual(before);
      },
    );

    it("refuses the full variant with its rule and a denied row, and changes nothing", async () => {
      const server = await seedServer();
      const before = await serverRow(server.uuid);

      const reply = await operator("mcpServers.update", {
        uuid: server.uuid,
        name: server.name,
        type: "STREAMABLE_HTTP",
        url: NEXT_URL,
      });

      expect({ status: reply.status, code: reply.code }).toEqual({
        status: 403,
        code: "FORBIDDEN",
      });
      expect(await serverRow(server.uuid)).toEqual(before);
      expect(await deniedRule("mcpserver.update", server.uuid)).toEqual([
        "operator_server_connection_change",
      ]);
      expect(
        await one(
          `SELECT 1 FROM audit_log WHERE action = 'mcpserver.update' AND target_id = $1 AND outcome = 'success'`,
          [server.uuid],
        ),
      ).toHaveLength(0);
    });

    it("refuses a full variant that would change nothing too, and an unknown server the same way", async () => {
      const server = await seedServer();
      const unchanged = await operator("mcpServers.update", {
        uuid: server.uuid,
        name: server.name,
        type: "STREAMABLE_HTTP",
        url: CANARY_URL,
      });
      expect(unchanged.code).toBe("FORBIDDEN");

      const unknown = await operator("mcpServers.update", {
        uuid: "99999999-9999-4999-8999-999999999999",
        name: "ghost",
        type: "STREAMABLE_HTTP",
        url: NEXT_URL,
      });
      expect(unknown.code).toBe("FORBIDDEN");
    });

    it("refuses to create a server with its rule and a denied row, and writes none", async () => {
      const name = uniq("rs-operator-create");

      const reply = await operator("mcpServers.create", {
        name,
        type: "STREAMABLE_HTTP",
        url: NEXT_URL,
      });

      expect({ status: reply.status, code: reply.code }).toEqual({
        status: 403,
        code: "FORBIDDEN",
      });
      expect(
        await one(`SELECT 1 FROM mcp_servers WHERE name = $1`, [name]),
      ).toHaveLength(0);
      const denied = await fx.auditNow(
        `action = 'mcpserver.create' AND outcome = 'denied' AND actor_id = $1`,
        [fx.operator.uuid],
      );
      expect(denied.at(-1)?.detail).toMatchObject({
        rule: "operator_server_create",
      });
    });

    it("leaves the sync scope its create and its full update", async () => {
      const name = uniq("rs-sync-create");
      const created = await sync("mcpServers.create", {
        name,
        type: "STREAMABLE_HTTP",
        url: CANARY_URL,
      });
      expect(ok(created)).toBe(true);
      const uuid = dataOf<{ uuid: string }>(created).uuid;
      serverUuids.push(uuid);
      expect(await classOf("mcpserver.create", uuid)).toEqual(["loosen"]);

      const updated = await sync("mcpServers.update", {
        uuid,
        name,
        type: "STREAMABLE_HTTP",
        url: CANARY_URL,
        description: "synced",
      });
      expect(ok(updated)).toBe(true);
      expect((await serverRow(uuid)).description).toBe("synced");
      expect(await classOf("mcpserver.update", uuid)).toEqual(["change"]);
    });

    // TEST-EDIT (SPEC): a name another server holds is a coded CONFLICT with a
    // denied row now, where it was `success: false` in an HTTP 200 (the rule
    // is in "server names stay unique within an owner scope" below).
    it("refuses a name another server of the owner already has with a coded conflict and a denied row, and changes nothing", async () => {
      // Owned by the key's owner, where the database's own rule also holds.
      const first = await seedServer({ userId: fx.ownerId });
      const second = await seedServer({ userId: fx.ownerId });
      const before = await serverRow(second.uuid);

      const reply = await operator("mcpServers.update", {
        uuid: second.uuid,
        metadata_only: true,
        name: first.name,
      });

      expect({ status: reply.status, code: reply.code }).toEqual({
        status: 409,
        code: "CONFLICT",
      });
      expect(reply.message).toBe(SERVER_NAME_TAKEN_MESSAGE);
      expect(await serverRow(second.uuid)).toEqual(before);
      expect(await classOf("mcpserver.update", second.uuid)).toEqual([]);
      expect(await deniedRule("mcpserver.update", second.uuid)).toEqual([
        "server_name_taken",
      ]);
    });

    it("refuses another owner's private server, judged on the locked row", async () => {
      const foreign = await seedServer({ userId: fx.memberId });
      const before = await serverRow(foreign.uuid);

      const reply = await operator("mcpServers.update", {
        uuid: foreign.uuid,
        metadata_only: true,
        name: uniq("rs-foreign"),
      });

      expect(reply.data).toMatchObject({
        success: false,
        message: "Access denied: You can only update servers you own",
      });
      expect(await serverRow(foreign.uuid)).toEqual(before);
    });

    it("judges the owner rule on the row the write locks, not on the read before it", async () => {
      const server = await seedServer();
      const before = await serverRow(server.uuid);
      // The row is public when the request reads it. A person hands it to
      // someone else while the write waits for its lock; the write then finds
      // the owner it has now and refuses.
      const holder = new Client({ connectionString: TEST_DATABASE_URL });
      await holder.connect();
      let pending: Promise<Reply>;
      try {
        await holder.query("BEGIN");
        await holder.query(
          `SELECT 1 FROM mcp_servers WHERE uuid = $1 FOR UPDATE`,
          [server.uuid],
        );
        pending = operator("mcpServers.update", {
          uuid: server.uuid,
          metadata_only: true,
          name: uniq("rs-late"),
        });
        await waitForLockWaiters(1);
        await holder.query(
          `UPDATE mcp_servers SET user_id = $2 WHERE uuid = $1`,
          [server.uuid, fx.memberId],
        );
        await holder.query("COMMIT");
      } catch (error) {
        await holder.query("ROLLBACK").catch(() => undefined);
        throw error;
      } finally {
        await holder.end();
      }

      const reply = await pending;

      expect(reply.data).toMatchObject({
        success: false,
        message: "Access denied: You can only update servers you own",
      });
      expect(await serverRow(server.uuid)).toEqual({
        ...before,
        user_id: fx.memberId,
      });
    });

    it("rolls a rename back when its audit row cannot be written, and charges nothing", async () => {
      const server = await seedServer();
      const before = await serverRow(server.uuid);
      await fx.failAuditFor("mcpserver.update");
      try {
        const reply = await operator("mcpServers.update", {
          uuid: server.uuid,
          metadata_only: true,
          name: uniq("rs-fault"),
        });
        expect((reply.data as { success: boolean }).success).toBe(false);
      } finally {
        await fx.clearAuditFault("mcpserver.update");
      }
      expect(await serverRow(server.uuid)).toEqual(before);
    });
  });

  // ---------------------------------------------------------------------------
  describe("server names stay unique within an owner scope", () => {
    // The database's unique rule on (name, owner) treats a NULL owner as
    // distinct, so two public servers could share a name. The gateway judges
    // the rule itself for every owner scope, under the name's lock.
    async function lockWaitersReach(n: number) {
      const deadline = Date.now() + 5_000;
      for (;;) {
        const [{ waiting }] = await one(
          `SELECT count(*)::int AS waiting FROM pg_stat_activity
            WHERE datname = current_database() AND wait_event_type = 'Lock'`,
        );
        if (waiting >= n) return true;
        if (Date.now() > deadline) return false;
        await new Promise((resolve) => setTimeout(resolve, 20));
      }
    }
    const refusedAs = (reply: Reply) => ({
      status: reply.status,
      code: reply.code,
      message: reply.message,
    });
    const conflict = {
      status: 409,
      code: "CONFLICT",
      message: SERVER_NAME_TAKEN_MESSAGE,
    };
    const countNamed = async (name: string, userId: string | null = null) =>
      (
        await one(
          `SELECT count(*)::int AS n FROM mcp_servers
            WHERE name = $1 AND user_id IS NOT DISTINCT FROM $2`,
          [name, userId],
        )
      )[0].n as number;
    const deniedFor = async (actorUuid: string, action: string) =>
      (
        await fx.auditNow(
          `action = $1 AND outcome = 'denied' AND actor_id = $2`,
          [action, actorUuid],
        )
      ).map((row) => (row.detail as Record<string, unknown>).rule);

    it("refuses a create that would give a second public server a name, with a coded conflict and a denied row", async () => {
      const k = await freshKey("sync");
      const holder = await seedServer();

      const reply = await sync(
        "mcpServers.create",
        { name: holder.name, type: "STREAMABLE_HTTP", url: NEXT_URL },
        k.key,
      );

      expect(refusedAs(reply)).toEqual(conflict);
      expect(await countNamed(holder.name)).toBe(1);
      expect(await deniedFor(k.uuid, "mcpserver.create")).toEqual([
        "server_name_taken",
      ]);
      expect(
        await fx.auditNow(
          `action = 'mcpserver.create' AND outcome = 'success' AND actor_id = $1`,
          [k.uuid],
        ),
      ).toEqual([]);
    });

    it("refuses a rename onto another public server's name, for the operator scope and for a person, and changes nothing", async () => {
      const holder = await seedServer();
      const operatorSide = await seedServer();
      const personSide = await seedServer();
      const operatorBefore = await serverRow(operatorSide.uuid);
      const personBefore = await serverRow(personSide.uuid);

      const byOperator = await operator("mcpServers.update", {
        uuid: operatorSide.uuid,
        metadata_only: true,
        name: holder.name,
      });
      const byPerson = await human("mcpServers.update", {
        uuid: personSide.uuid,
        metadata_only: true,
        name: holder.name,
      });

      expect(refusedAs(byOperator)).toEqual(conflict);
      expect(refusedAs(byPerson)).toEqual(conflict);
      expect(await serverRow(operatorSide.uuid)).toEqual(operatorBefore);
      expect(await serverRow(personSide.uuid)).toEqual(personBefore);
      expect(await countNamed(holder.name)).toBe(1);
      expect(await deniedRule("mcpserver.update", operatorSide.uuid)).toEqual([
        "server_name_taken",
      ]);
      // A person's refusal has no audited transaction, so no denied row.
      expect(await deniedRule("mcpserver.update", personSide.uuid)).toEqual([]);
    });

    it("refuses the full update that renames onto a taken name, for the sync scope and for a person", async () => {
      const holder = await seedServer();
      const syncSide = await seedServer();
      const personSide = await seedServer();
      const syncBefore = await serverRow(syncSide.uuid);
      const personBefore = await serverRow(personSide.uuid);
      const full = (uuid: string) => ({
        uuid,
        name: holder.name,
        type: "STREAMABLE_HTTP",
        url: CANARY_URL,
      });

      const bySync = await sync("mcpServers.update", full(syncSide.uuid));
      const byPerson = await human("mcpServers.update", full(personSide.uuid));

      expect(refusedAs(bySync)).toEqual(conflict);
      expect(refusedAs(byPerson)).toEqual(conflict);
      expect(await serverRow(syncSide.uuid)).toEqual(syncBefore);
      expect(await serverRow(personSide.uuid)).toEqual(personBefore);
      expect(await deniedRule("mcpserver.update", syncSide.uuid)).toEqual([
        "server_name_taken",
      ]);
    });

    it("refuses a person's create of a second public server with a name, and of a second server of one owner", async () => {
      const holder = await seedServer();
      const ownedHolder = await seedServer({ userId: fx.memberId });

      const publicCreate = await human("mcpServers.create", {
        name: holder.name,
        type: "STREAMABLE_HTTP",
        url: NEXT_URL,
      });
      const ownedCreate = await human("mcpServers.create", {
        name: ownedHolder.name,
        type: "STREAMABLE_HTTP",
        url: NEXT_URL,
        user_id: fx.memberId,
      });

      expect(refusedAs(publicCreate)).toEqual(conflict);
      expect(refusedAs(ownedCreate)).toEqual(conflict);
      expect(await countNamed(holder.name)).toBe(1);
      expect(await countNamed(ownedHolder.name, fx.memberId)).toBe(1);
    });

    it("refuses a full update that moves a server into the public scope under a name another public server holds, and allows the move when the name is free", async () => {
      const holder = await seedServer();
      const owned = await seedServer({ userId: fx.ownerId });
      await one(`UPDATE mcp_servers SET name = $2 WHERE uuid = $1`, [
        owned.uuid,
        holder.name,
      ]);
      const free = await seedServer({ userId: fx.ownerId });
      const move = (uuid: string, name: string) =>
        sync("mcpServers.update", {
          uuid,
          name,
          type: "STREAMABLE_HTTP",
          url: CANARY_URL,
          user_id: null,
        });

      const refused = await move(owned.uuid, holder.name);
      const allowed = await move(free.uuid, free.name);

      expect(refusedAs(refused)).toEqual(conflict);
      expect((await serverRow(owned.uuid)).user_id).toBe(fx.ownerId);
      expect(ok(allowed)).toBe(true);
      expect((await serverRow(free.uuid)).user_id).toBeNull();
    });

    it("allows the same name under another owner scope, a rename to a free name, and a rename to the name the server already has", async () => {
      const holder = await seedServer();
      const k = await freshKey("sync");

      const otherScope = await sync(
        "mcpServers.create",
        {
          name: holder.name,
          type: "STREAMABLE_HTTP",
          url: NEXT_URL,
          user_id: fx.memberId,
        },
        k.key,
      );
      const other = await seedServer();
      const freeName = uniq("rs-free-name");
      const renamed = await operator("mcpServers.update", {
        uuid: other.uuid,
        metadata_only: true,
        name: freeName,
      });
      const same = await operator("mcpServers.update", {
        uuid: other.uuid,
        metadata_only: true,
        name: freeName,
      });

      expect(ok(otherScope)).toBe(true);
      serverUuids.push(dataOf<{ uuid: string }>(otherScope).uuid);
      expect(ok(renamed)).toBe(true);
      expect(ok(same)).toBe(true);
      expect(await countNamed(holder.name)).toBe(1);
      expect(await countNamed(holder.name, fx.memberId)).toBe(1);
      expect(await countNamed(freeName)).toBe(1);
    });

    it("does not repair a duplicate that already exists: either row can still be re-saved, described and left under its name", async () => {
      const first = await seedServer();
      const second = await seedServer();
      await one(`UPDATE mcp_servers SET name = $2 WHERE uuid = $1`, [
        second.uuid,
        first.name,
      ]);
      expect(await countNamed(first.name)).toBe(2);

      const resave = await sync("mcpServers.update", {
        uuid: second.uuid,
        name: first.name,
        type: "STREAMABLE_HTTP",
        url: CANARY_URL,
        description: "re-saved",
      });
      const described = await operator("mcpServers.update", {
        uuid: first.uuid,
        metadata_only: true,
        description: "described",
      });
      const sameName = await operator("mcpServers.update", {
        uuid: first.uuid,
        metadata_only: true,
        name: first.name,
      });

      expect([ok(resave), ok(described), ok(sameName)]).toEqual([
        true,
        true,
        true,
      ]);
      expect(await countNamed(first.name)).toBe(2);
    });

    // The repository's own partial update (no name in the request) is judged
    // under the row's own name when it moves the row to another owner.
    describe("a partial update that only moves a server to another owner", () => {
      const repo = async () =>
        (await import("../db/repositories/mcp-servers.repo"))
          .mcpServersRepository;

      it("refuses the move when the name is taken in the new scope, and allows it when free", async () => {
        const holder = await seedServer();
        const owned = await seedServer({ userId: fx.memberId });
        await one(`UPDATE mcp_servers SET name = $2 WHERE uuid = $1`, [
          owned.uuid,
          holder.name,
        ]);
        const free = await seedServer({ userId: fx.memberId });
        const mcpServers = await repo();

        await expect(
          mcpServers.updateReportingChange({ uuid: owned.uuid, user_id: null }),
        ).rejects.toMatchObject({ message: SERVER_NAME_TAKEN_MESSAGE });
        const moved = await mcpServers.updateReportingChange({
          uuid: free.uuid,
          user_id: null,
        });

        expect((await serverRow(owned.uuid)).user_id).toBe(fx.memberId);
        expect(moved?.server.user_id).toBeNull();
      });

      it("refuses to write when the server was renamed while the write waited for the name's lock", async () => {
        const server = await seedServer();
        const before = await serverRow(server.uuid);
        const mcpServers = await repo();
        const lock = `SELECT pg_advisory_lock(hashtext('metamcp.mcp_server.name'), hashtext('${server.name}'))`;
        const unlock = `SELECT pg_advisory_unlock(hashtext('metamcp.mcp_server.name'), hashtext('${server.name}'))`;
        await barrier.query(lock);
        let pending: Promise<unknown>;
        let queued = false;
        try {
          pending = mcpServers
            .updateReportingChange({ uuid: server.uuid, user_id: fx.memberId })
            .catch((error: unknown) => error);
          queued = await lockWaitersReach(1);
          await one(`UPDATE mcp_servers SET name = $2 WHERE uuid = $1`, [
            server.uuid,
            uniq("rs-renamed-meanwhile"),
          ]);
        } finally {
          await barrier.query(unlock);
        }

        const outcome = await pending;

        expect(queued).toBe(true);
        expect(outcome).toBeInstanceOf(Error);
        expect((await serverRow(server.uuid)).user_id).toBe(before.user_id);
      });
    });

    // Two writers of one name, each on its own key (so only the name's lock
    // can serialize them). The barrier holds that name's lock, both requests
    // queue behind it, and releasing it lets them run together: whichever the
    // database lets in first wins, and the other, judged after the first has
    // committed, is refused.
    describe("two writers of one name", () => {
      async function raceForOneName(
        name: string,
        first: () => Promise<Reply>,
        second: () => Promise<Reply>,
      ) {
        const subject = `hashtext('metamcp.mcp_server.name'), hashtext('${name}')`;
        await barrier.query(`SELECT pg_advisory_lock(${subject})`);
        let a: Promise<Reply> | undefined;
        let b: Promise<Reply> | undefined;
        let queued = false;
        try {
          a = first();
          b = second();
          queued = await lockWaitersReach(2);
        } finally {
          await barrier.query(`SELECT pg_advisory_unlock(${subject})`);
        }
        const replies = await Promise.all([a, b]);
        return { queued, replies };
      }
      const outcomes = (replies: Reply[]) =>
        replies.map((reply) => (ok(reply) ? "ok" : reply.code)).sort();

      it("lets exactly one rename win when two keys rename two servers onto one name", async () => {
        const [k1, k2] = [
          await freshKey("operator"),
          await freshKey("operator"),
        ];
        const a = await seedServer();
        const b = await seedServer();
        const target = uniq("rs-contested-rename");
        const rename = (uuid: string, key: string) => () =>
          operator(
            "mcpServers.update",
            { uuid, metadata_only: true, name: target },
            key,
          );

        const { queued, replies } = await raceForOneName(
          target,
          rename(a.uuid, k1.key),
          rename(b.uuid, k2.key),
        );

        expect(queued).toBe(true);
        expect(outcomes(replies)).toEqual(["CONFLICT", "ok"]);
        expect(await countNamed(target)).toBe(1);
      });

      it("lets exactly one create win when two keys create one name", async () => {
        const [k1, k2] = [await freshKey("sync"), await freshKey("sync")];
        const target = uniq("rs-contested-create");
        const create = (key: string) => () =>
          sync(
            "mcpServers.create",
            { name: target, type: "STREAMABLE_HTTP", url: NEXT_URL },
            key,
          );

        const { queued, replies } = await raceForOneName(
          target,
          create(k1.key),
          create(k2.key),
        );

        expect(queued).toBe(true);
        expect(outcomes(replies)).toEqual(["CONFLICT", "ok"]);
        expect(await countNamed(target)).toBe(1);
      });

      it("lets exactly one full update win when two keys rename two servers onto one name", async () => {
        const [k1, k2] = [await freshKey("sync"), await freshKey("sync")];
        const a = await seedServer();
        const b = await seedServer();
        const target = uniq("rs-contested-full");
        const full = (uuid: string, key: string) => () =>
          sync(
            "mcpServers.update",
            {
              uuid,
              name: target,
              type: "STREAMABLE_HTTP",
              url: CANARY_URL,
            },
            key,
          );

        const { queued, replies } = await raceForOneName(
          target,
          full(a.uuid, k1.key),
          full(b.uuid, k2.key),
        );

        expect(queued).toBe(true);
        expect(outcomes(replies)).toEqual(["CONFLICT", "ok"]);
        expect(await countNamed(target)).toBe(1);
      });
    });
  });

  // ---------------------------------------------------------------------------
  describe("an unmount and a remount by a key", () => {
    async function mountedWithWithheldTools(policy: "allow_all" | "allowlist") {
      const server = await seedServer();
      const ns = await namespaceOf("rs-unmount-ns", policy);
      const open = await seedTool(server.uuid, "open_tool");
      const withheldA = await seedTool(server.uuid, "withheld_a");
      const withheldB = await seedTool(server.uuid, "withheld_b");
      await mount(ns, server.uuid, [
        { uuid: open, status: "ACTIVE" },
        { uuid: withheldA, status: "INACTIVE" },
        { uuid: withheldB, status: "INACTIVE" },
      ]);
      return { server, ns };
    }
    const nameOf = async (ns: string) =>
      (await one(`SELECT name FROM namespaces WHERE uuid = $1`, [ns]))[0]
        .name as string;

    it.each(["allow_all", "allowlist"] as const)(
      "keeps every INACTIVE row INACTIVE through an unmount and a remount (%s)",
      async (policy) => {
        const { server, ns } = await mountedWithWithheldTools(policy);
        const expected = {
          open_tool: "ACTIVE",
          withheld_a: "INACTIVE",
          withheld_b: "INACTIVE",
        };

        const unmounted = await operator("namespaces.update", {
          uuid: ns,
          name: await nameOf(ns),
          mcpServerUuids: [],
        });
        expect(ok(unmounted)).toBe(true);
        expect(await mountStatus(ns, server.uuid)).toBeUndefined();
        expect(await toolStatuses(ns, server.uuid)).toEqual(expected);
        expect(await toolStatusesThroughApi(ns)).toEqual(expected);

        const remounted = await operator("namespaces.update", {
          uuid: ns,
          name: await nameOf(ns),
          mcpServerUuids: [server.uuid],
        });
        expect(ok(remounted)).toBe(true);
        expect(await mountStatus(ns, server.uuid)).toBe("ACTIVE");
        expect(await toolStatuses(ns, server.uuid)).toEqual(expected);
        expect(await toolStatusesThroughApi(ns)).toEqual(expected);
      },
    );

    it("leaves an unmounted server's rows in the namespace for the key, and a tool the server gained since follows the policy", async () => {
      const { server, ns } = await mountedWithWithheldTools("allow_all");
      await operator("namespaces.update", {
        uuid: ns,
        name: await nameOf(ns),
        mcpServerUuids: [],
      });
      await seedTool(server.uuid, "gained_later");

      await operator("namespaces.update", {
        uuid: ns,
        name: await nameOf(ns),
        mcpServerUuids: [server.uuid],
      });

      expect(await toolStatuses(ns, server.uuid)).toEqual({
        open_tool: "ACTIVE",
        withheld_a: "INACTIVE",
        withheld_b: "INACTIVE",
        gained_later: "ACTIVE",
      });
    });

    it("keeps a person's unmount as it was: the rows go, and a remount makes them all ACTIVE", async () => {
      const { server, ns } = await mountedWithWithheldTools("allow_all");

      const unmounted = await human("namespaces.update", {
        uuid: ns,
        name: await nameOf(ns),
        mcpServerUuids: [],
      });
      expect(ok(unmounted)).toBe(true);
      expect(await toolStatuses(ns, server.uuid)).toEqual({});

      await human("namespaces.update", {
        uuid: ns,
        name: await nameOf(ns),
        mcpServerUuids: [server.uuid],
      });
      expect(await toolStatuses(ns, server.uuid)).toEqual({
        open_tool: "ACTIVE",
        withheld_a: "ACTIVE",
        withheld_b: "ACTIVE",
      });
    });

    it("keeps the rows of a server that stays mounted while another is unmounted", async () => {
      const kept = await seedServer();
      const dropped = await seedServer();
      const ns = await namespaceOf("rs-two-ns", "allow_all");
      const keptTool = await seedTool(kept.uuid, "kept_tool");
      const droppedTool = await seedTool(dropped.uuid, "dropped_tool");
      await mount(ns, kept.uuid, [{ uuid: keptTool, status: "INACTIVE" }]);
      await mount(ns, dropped.uuid, [
        { uuid: droppedTool, status: "INACTIVE" },
      ]);

      await operator("namespaces.update", {
        uuid: ns,
        name: await nameOf(ns),
        mcpServerUuids: [kept.uuid],
      });

      expect(await mountStatus(ns, dropped.uuid)).toBeUndefined();
      expect(await toolStatuses(ns, kept.uuid)).toEqual({
        kept_tool: "INACTIVE",
      });
      expect(await toolStatuses(ns, dropped.uuid)).toEqual({
        dropped_tool: "INACTIVE",
      });
    });
  });

  // ---------------------------------------------------------------------------
  describe("a tool refresh by a key", () => {
    const refreshInput = (
      ns: string,
      server: { name: string },
      toolNames: string[],
    ) => ({
      namespaceUuid: ns,
      tools: toolNames.map((name) => ({
        name: `${server.name}__${name}`,
        description: `${name} described`,
        inputSchema: { type: "object" as const },
      })),
    });

    it("keeps an INACTIVE row INACTIVE under allow_all, inserts only the rows that did not exist, and reports exactly those", async () => {
      const server = await seedServer();
      const ns = await namespaceOf("rs-refresh-ns", "allow_all");
      const withheld = await seedTool(server.uuid, "withheld_tool");
      const open = await seedTool(server.uuid, "open_tool");
      await mount(ns, server.uuid, [
        { uuid: withheld, status: "INACTIVE" },
        { uuid: open, status: "ACTIVE" },
      ]);

      const reply = await operator(
        "namespaces.refreshTools",
        refreshInput(ns, server, ["withheld_tool", "open_tool", "brand_new"]),
      );

      expect(ok(reply)).toBe(true);
      expect(reply.data).toMatchObject({ mappingsCreated: 1 });
      const expected = {
        withheld_tool: "INACTIVE",
        open_tool: "ACTIVE",
        brand_new: "ACTIVE",
      };
      expect(await toolStatuses(ns, server.uuid)).toEqual(expected);
      expect(await toolStatusesThroughApi(ns)).toEqual(expected);
    });

    it("leaves an INACTIVE row INACTIVE on a refresh that is all existing rows, and writes no row of that kind", async () => {
      const server = await seedServer();
      const ns = await namespaceOf("rs-refresh-same-ns", "allow_all");
      const withheld = await seedTool(server.uuid, "withheld_tool");
      await mount(ns, server.uuid, [{ uuid: withheld, status: "INACTIVE" }]);

      const reply = await operator(
        "namespaces.refreshTools",
        refreshInput(ns, server, ["withheld_tool"]),
      );

      expect(ok(reply)).toBe(true);
      expect(reply.data).toMatchObject({ mappingsCreated: 0 });
      expect(await toolStatuses(ns, server.uuid)).toEqual({
        withheld_tool: "INACTIVE",
      });
      expect(await classOf("namespace.refresh_tools", ns)).toEqual(["change"]);
    });

    it("gives new rows the allowlist's INACTIVE and keeps existing ones, and is not a loosening", async () => {
      const server = await seedServer();
      const ns = await namespaceOf("rs-refresh-allowlist-ns", "allowlist");
      const listed = await seedTool(server.uuid, "listed_tool");
      await mount(ns, server.uuid, [{ uuid: listed, status: "ACTIVE" }]);

      const reply = await operator(
        "namespaces.refreshTools",
        refreshInput(ns, server, ["listed_tool", "brand_new"]),
      );

      expect(ok(reply)).toBe(true);
      expect(await toolStatuses(ns, server.uuid)).toEqual({
        listed_tool: "ACTIVE",
        brand_new: "INACTIVE",
      });
      expect(await classOf("namespace.refresh_tools", ns)).toEqual(["change"]);
    });

    it("keeps a person's refresh as it was: an INACTIVE row under allow_all is switched back on", async () => {
      const server = await seedServer();
      const ns = await namespaceOf("rs-refresh-human-ns", "allow_all");
      const withheld = await seedTool(server.uuid, "withheld_tool");
      await mount(ns, server.uuid, [{ uuid: withheld, status: "INACTIVE" }]);

      const reply = await human(
        "namespaces.refreshTools",
        refreshInput(ns, server, ["withheld_tool"]),
      );

      expect(ok(reply)).toBe(true);
      expect(await toolStatuses(ns, server.uuid)).toEqual({
        withheld_tool: "ACTIVE",
      });
    });

    it("classes a refresh that inserted an ACTIVE row as loosen, with the evidence in its audit row", async () => {
      const server = await seedServer();
      const ns = await namespaceOf("rs-refresh-class-ns", "allow_all");
      await mount(ns, server.uuid, []);

      await operator(
        "namespaces.refreshTools",
        refreshInput(ns, server, ["fresh_one", "fresh_two"]),
      );

      expect(await classOf("namespace.refresh_tools", ns)).toEqual(["loosen"]);
      const [row] = await fx.auditNow(
        `action = 'namespace.refresh_tools' AND target_id = $1`,
        [ns],
      );
      expect(row.detail).toMatchObject({ active_rows_written: 2 });
    });
  });

  // ---------------------------------------------------------------------------
  describe("the authentication modes of an endpoint", () => {
    const endpointInput = (ns: string, over: Record<string, unknown> = {}) => ({
      name: uniq("rs-ep"),
      namespaceUuid: ns,
      enableClientMaxRate: false,
      enableMaxRate: false,
      ...over,
    });

    it("refuses an operator-scope create that leaves both modes off, with a denied row and no endpoint", async () => {
      const ns = await namespaceOf("rs-auth-ns", "allow_all");
      const input = endpointInput(ns, {
        enableApiKeyAuth: false,
        enableOauth: false,
      });

      const reply = await operator("endpoints.create", input);

      expect({ status: reply.status, code: reply.code }).toEqual({
        status: 403,
        code: "FORBIDDEN",
      });
      expect(
        await one(`SELECT 1 FROM endpoints WHERE name = $1`, [input.name]),
      ).toHaveLength(0);
      const denied = await fx.auditNow(
        `action = 'endpoint.create' AND outcome = 'denied' AND actor_id = $1`,
        [fx.operator.uuid],
      );
      expect(denied.at(-1)?.detail).toMatchObject({
        rule: "admin_plane_auth_off",
      });
    });

    it.each([
      [
        "API-key authentication only",
        { enableApiKeyAuth: true, enableOauth: false },
      ],
      ["OAuth only", { enableApiKeyAuth: false, enableOauth: true }],
    ])("allows an operator-scope create with %s on", async (_label, flags) => {
      const ns = await namespaceOf("rs-auth-one-ns", "allow_all");
      const input = endpointInput(ns, flags);

      const reply = await operator("endpoints.create", input);

      expect(ok(reply)).toBe(true);
      const [row] = await one(
        `SELECT enable_api_key_auth, enable_oauth FROM endpoints WHERE name = $1`,
        [input.name],
      );
      expect(row).toEqual({
        enable_api_key_auth: flags.enableApiKeyAuth,
        enable_oauth: flags.enableOauth,
      });
    });

    it("refuses an operator-scope update that leaves both off, and one that omits them over a row with both off", async () => {
      const ns = await namespaceOf("rs-auth-update-ns", "allow_all");
      const ep = await fx.endpoint({
        name: "rs-auth-upd",
        namespaceUuid: ns,
        apiKeyAuth: true,
        oauth: false,
      });
      const [{ name }] = await one(
        `SELECT name FROM endpoints WHERE uuid = $1`,
        [ep],
      );
      const update = (flags: Record<string, unknown>, uuid = ep) =>
        operator("endpoints.update", {
          uuid,
          name,
          namespaceUuid: ns,
          enableClientMaxRate: false,
          enableMaxRate: false,
          ...flags,
        });

      const refused = await update({
        enableApiKeyAuth: false,
        enableOauth: false,
      });
      expect({ status: refused.status, code: refused.code }).toEqual({
        status: 403,
        code: "FORBIDDEN",
      });
      expect(
        (
          await one(
            `SELECT enable_api_key_auth FROM endpoints WHERE uuid = $1`,
            [ep],
          )
        )[0],
      ).toEqual({ enable_api_key_auth: true });
      expect(await deniedRule("endpoint.update", ep)).toEqual([
        "admin_plane_auth_off",
      ]);

      const bothOff = await fx.endpoint({
        name: "rs-auth-both-off",
        namespaceUuid: ns,
        apiKeyAuth: false,
        oauth: false,
      });
      const [{ name: bothOffName }] = await one(
        `SELECT name FROM endpoints WHERE uuid = $1`,
        [bothOff],
      );
      const omitted = await operator("endpoints.update", {
        uuid: bothOff,
        name: bothOffName,
        namespaceUuid: ns,
        enableClientMaxRate: false,
        enableMaxRate: false,
      });
      expect(omitted.code).toBe("FORBIDDEN");

      const allowed = await operator("endpoints.update", {
        uuid: bothOff,
        name: bothOffName,
        namespaceUuid: ns,
        enableClientMaxRate: false,
        enableMaxRate: false,
        enableApiKeyAuth: true,
      });
      expect(ok(allowed)).toBe(true);
      expect(
        (
          await one(
            `SELECT enable_api_key_auth FROM endpoints WHERE uuid = $1`,
            [bothOff],
          )
        )[0],
      ).toEqual({ enable_api_key_auth: true });
    });

    it("does not hold a person to the rule", async () => {
      const ns = await namespaceOf("rs-auth-human-ns", "allow_all");
      const input = endpointInput(ns, {
        enableApiKeyAuth: false,
        enableOauth: false,
      });

      const created = await human("endpoints.create", input);

      expect(ok(created)).toBe(true);
      const uuid = dataOf<{ uuid: string }>(created).uuid;
      const updated = await human("endpoints.update", {
        uuid,
        name: input.name,
        namespaceUuid: ns,
        enableClientMaxRate: false,
        enableMaxRate: false,
        enableApiKeyAuth: false,
        enableOauth: false,
      });
      expect(ok(updated)).toBe(true);
    });
  });

  // ---------------------------------------------------------------------------
  describe("the budget class of each topology write", () => {
    it("counts each write in the class its own audit row says, in both directions of each", async () => {
      const server = await seedServer();
      const tool = await seedTool(server.uuid, "classed_tool");

      // namespace.create: loosen.
      const createdNs = await operator("namespaces.create", {
        name: uniq("rs-class-ns"),
        mcpServerUuids: [server.uuid],
      });
      expect(ok(createdNs)).toBe(true);
      const ns = dataOf<{ uuid: string }>(createdNs).uuid;
      namespaceUuids.push(ns);
      expect(await classOf("namespace.create", ns)).toEqual(["loosen"]);

      // namespace.update: a mount added is loosen, a rename and an unmount are
      // a change.
      const name = (
        await one(`SELECT name FROM namespaces WHERE uuid = $1`, [ns])
      )[0].name as string;
      const other = await seedServer();
      await operator("namespaces.update", {
        uuid: ns,
        name,
        mcpServerUuids: [server.uuid, other.uuid],
      });
      await operator("namespaces.update", {
        uuid: ns,
        name,
        description: "renamed only",
      });
      await operator("namespaces.update", {
        uuid: ns,
        name,
        mcpServerUuids: [server.uuid],
      });
      expect(await classOf("namespace.update", ns)).toEqual([
        "loosen",
        "change",
        "change",
      ]);

      // namespace.tool_status: ACTIVE is loosen, INACTIVE is tighten.
      await one(
        `INSERT INTO namespace_tool_mappings (namespace_uuid, tool_uuid, mcp_server_uuid, status)
         VALUES ($1, $2, $3, 'INACTIVE') ON CONFLICT DO NOTHING`,
        [ns, tool, server.uuid],
      );
      const status = (value: "ACTIVE" | "INACTIVE") =>
        operator("namespaces.updateToolStatus", {
          namespaceUuid: ns,
          toolUuid: tool,
          serverUuid: server.uuid,
          status: value,
        });
      expect(ok(await status("ACTIVE"))).toBe(true);
      expect(ok(await status("INACTIVE"))).toBe(true);
      expect(await classOf("namespace.tool_status", ns)).toEqual([
        "loosen",
        "tighten",
      ]);

      // endpoint.create: open is loosen, restricted is a change.
      const openName = uniq("rs-class-open");
      const open = await operator("endpoints.create", {
        name: openName,
        namespaceUuid: ns,
        enableClientMaxRate: false,
        enableMaxRate: false,
        user_id: null,
      });
      expect(ok(open)).toBe(true);
      expect(
        await classOf("endpoint.create", dataOf<{ uuid: string }>(open).uuid),
      ).toEqual(["loosen"]);

      const restrictedNs = await namespaceOf(
        "rs-class-restricted-ns",
        "allow_all",
      );
      const restricted = await operator("endpoints.create", {
        name: uniq("rs-class-restricted"),
        namespaceUuid: restrictedNs,
        enableClientMaxRate: false,
        enableMaxRate: false,
        restricted: true,
        user_id: null,
      });
      expect(ok(restricted)).toBe(true);
      expect(
        await classOf(
          "endpoint.create",
          dataOf<{ uuid: string }>(restricted).uuid,
        ),
      ).toEqual(["change"]);
    });

    it("reads the evidence of a mount-adding update back through audit.list", async () => {
      const server = await seedServer();
      const ns = await namespaceOf("rs-evidence-ns", "allow_all");
      const name = (
        await one(`SELECT name FROM namespaces WHERE uuid = $1`, [ns])
      )[0].name as string;
      await operator("namespaces.update", {
        uuid: ns,
        name,
        mcpServerUuids: [server.uuid],
      });

      const audit = await read("audit.list", {
        action: "namespace.update",
        target_id: ns,
        outcome: "success",
      });

      const [row] = (
        audit.data as { rows: Array<{ detail: Record<string, unknown> }> }
      ).rows;
      expect(row.detail).toMatchObject({
        mounts_added: 1,
        budget_class: "loosen",
      });
    });

    it("spends the loosen allowance for a sync key's create, and refuses a concurrent last slot before the write", async () => {
      const k = await freshKey("sync");
      process.env.ADMIN_PLANE_BUDGET_SYNC_LOOSEN = "1";
      try {
        const a = uniq("rs-slot-a");
        const b = uniq("rs-slot-b");
        const create = (name: string) => () =>
          sync(
            "mcpServers.create",
            { name, type: "STREAMABLE_HTTP", url: NEXT_URL },
            k.key,
          );
        const [first, second] = await raceBehind(
          `SELECT pg_advisory_lock(hashtext('metamcp.admin_plane.budget'), hashtext('${k.uuid}'))`,
          `SELECT pg_advisory_unlock(hashtext('metamcp.admin_plane.budget'), hashtext('${k.uuid}'))`,
          create(a),
          create(b),
        );

        expect([ok(first), second.code]).toEqual([true, "TOO_MANY_REQUESTS"]);
        expect(
          await one(`SELECT 1 FROM mcp_servers WHERE name = $1`, [b]),
        ).toHaveLength(0);
        expect(
          await one(`SELECT 1 FROM mcp_servers WHERE name = $1`, [a]),
        ).toHaveLength(1);
        const denied = await fx.auditNow(
          `action = 'admin_plane.budget.exceeded' AND actor_id = $1`,
          [k.uuid],
        );
        expect(denied).toHaveLength(1);
        expect(denied[0].detail).toMatchObject({ budget_class: "loosen" });
      } finally {
        process.env.ADMIN_PLANE_BUDGET_SYNC_LOOSEN = "100000";
      }
    });

    it("answers a sync key's update over its total as a coded refusal, not as success false", async () => {
      const k = await freshKey("sync");
      process.env.ADMIN_PLANE_BUDGET_SYNC_TOTAL = "1";
      try {
        const server = await seedServer();
        const resave = () =>
          sync(
            "mcpServers.update",
            {
              uuid: server.uuid,
              name: server.name,
              type: "STREAMABLE_HTTP",
              url: CANARY_URL,
              description: "re-saved",
            },
            k.key,
          );

        expect(ok(await resave())).toBe(true);
        const over = await resave();

        expect({ status: over.status, code: over.code }).toEqual({
          status: 429,
          code: "TOO_MANY_REQUESTS",
        });
        const denied = await fx.auditNow(
          `action = 'admin_plane.budget.exceeded' AND actor_id = $1`,
          [k.uuid],
        );
        expect(denied).toHaveLength(1);
      } finally {
        process.env.ADMIN_PLANE_BUDGET_SYNC_TOTAL = "100000";
      }
    });

    it("lets a sync key re-save a server within its change allowance once its loosen allowance is spent", async () => {
      const k = await freshKey("sync");
      process.env.ADMIN_PLANE_BUDGET_SYNC_LOOSEN = "1";
      try {
        const name = uniq("rs-resave");
        const created = await sync(
          "mcpServers.create",
          { name, type: "STREAMABLE_HTTP", url: NEXT_URL },
          k.key,
        );
        expect(ok(created)).toBe(true);
        const uuid = dataOf<{ uuid: string }>(created).uuid;
        const resave = await sync(
          "mcpServers.update",
          { uuid, name, type: "STREAMABLE_HTTP", url: NEXT_URL },
          k.key,
        );
        expect(ok(resave)).toBe(true);
      } finally {
        process.env.ADMIN_PLANE_BUDGET_SYNC_LOOSEN = "100000";
      }
    });
  });

  // ---------------------------------------------------------------------------
  describe("a coded refusal leaves every namespace write that spends the loosen allowance", () => {
    // Each procedure answers inside a catch-all that turns an unexpected
    // failure into `success: false` in an HTTP 200. The budget's refusal is a
    // coded 429 and has to leave the procedure as one, with nothing written.
    async function operatorWithOneLooseningChange() {
      const k = await freshKey("operator");
      process.env.ADMIN_PLANE_BUDGET_OPERATOR_LOOSEN = "1";
      const spent = await operator(
        "namespaces.create",
        { name: uniq("rs-spend-ns") },
        k.key,
      );
      expect(ok(spent)).toBe(true);
      namespaceUuids.push(dataOf<{ uuid: string }>(spent).uuid);
      return k;
    }
    const refused = (reply: Reply) => ({
      status: reply.status,
      code: reply.code,
    });
    const tooMany = { status: 429, code: "TOO_MANY_REQUESTS" };

    it.each(["create", "update", "updateToolStatus", "refreshTools"] as const)(
      "namespaces.%s answers a spent loosen allowance as a coded 429 and writes nothing",
      async (procedure) => {
        try {
          const k = await operatorWithOneLooseningChange();
          const server = await seedServer();
          const ns = await namespaceOf("rs-refused-ns", "allow_all");
          const name = (
            await one(`SELECT name FROM namespaces WHERE uuid = $1`, [ns])
          )[0].name as string;

          if (procedure === "create") {
            const refusedName = uniq("rs-refused-create");
            const reply = await operator(
              "namespaces.create",
              { name: refusedName, mcpServerUuids: [server.uuid] },
              k.key,
            );
            expect(refused(reply)).toEqual(tooMany);
            expect(
              await one(`SELECT 1 FROM namespaces WHERE name = $1`, [
                refusedName,
              ]),
            ).toHaveLength(0);
          } else if (procedure === "update") {
            const reply = await operator(
              "namespaces.update",
              { uuid: ns, name, mcpServerUuids: [server.uuid] },
              k.key,
            );
            expect(refused(reply)).toEqual(tooMany);
            expect(await mountStatus(ns, server.uuid)).toBeUndefined();
          } else if (procedure === "updateToolStatus") {
            const tool = await seedTool(server.uuid, "refused_tool");
            await mount(ns, server.uuid, [{ uuid: tool, status: "INACTIVE" }]);
            const reply = await operator(
              "namespaces.updateToolStatus",
              {
                namespaceUuid: ns,
                toolUuid: tool,
                serverUuid: server.uuid,
                status: "ACTIVE",
              },
              k.key,
            );
            expect(refused(reply)).toEqual(tooMany);
            expect(await toolStatuses(ns, server.uuid)).toEqual({
              refused_tool: "INACTIVE",
            });
          } else {
            await mount(ns, server.uuid, []);
            const reply = await operator(
              "namespaces.refreshTools",
              {
                namespaceUuid: ns,
                tools: [
                  {
                    name: `${server.name}__refused_fresh`,
                    description: "refused",
                    inputSchema: { type: "object" as const },
                  },
                ],
              },
              k.key,
            );
            expect(refused(reply)).toEqual(tooMany);
            expect(await toolStatuses(ns, server.uuid)).toEqual({});
          }

          const denied = await fx.auditNow(
            `action = 'admin_plane.budget.exceeded' AND actor_id = $1`,
            [k.uuid],
          );
          expect(denied).toHaveLength(1);
          expect(denied[0].detail).toMatchObject({ budget_class: "loosen" });
        } finally {
          process.env.ADMIN_PLANE_BUDGET_OPERATOR_LOOSEN = "100000";
        }
      },
    );
  });

  // ---------------------------------------------------------------------------
  describe("the grant sub-limit inside the loosen class", () => {
    // The topology writes raised the loosen limit, so the changes that grant
    // access (a group member or endpoint, a key, a widened IP policy, an
    // un-restricted endpoint) are also counted against a smaller grant limit.
    // The count reads the key's own audit rows, under the key's budget lock.
    // Imported when used: the module names the logger the suite mocks above.
    const grantSentence = async () =>
      (await import("../lib/admin-plane-budget")).ADMIN_PLANE_GRANT_REFUSAL;
    const setLimits = (loosen: number, grant: number) => {
      process.env.ADMIN_PLANE_BUDGET_OPERATOR_LOOSEN = String(loosen);
      process.env.ADMIN_PLANE_BUDGET_OPERATOR_GRANT = String(grant);
    };
    const resetLimits = () => {
      process.env.ADMIN_PLANE_BUDGET_OPERATOR_LOOSEN = "100000";
      process.env.ADMIN_PLANE_BUDGET_OPERATOR_GRANT = "100000";
    };
    const addMember = (group: string, userId: string, key: string) =>
      operator(
        "accessGroups.addMember",
        { group_uuid: group, user_id: userId },
        key,
      );
    const members = async (group: string) =>
      (
        await one(
          `SELECT count(*)::int AS n FROM access_group_members WHERE group_uuid = $1`,
          [group],
        )
      )[0].n as number;
    const deniedBudget = async (keyUuid: string) =>
      await fx.auditNow(
        `action = 'admin_plane.budget.exceeded' AND actor_id = $1`,
        [keyUuid],
      );

    it("refuses a grant once the grant limit is spent while loosen has room, and still allows a topology loosen, a tighten and another key's grant", async () => {
      setLimits(100, 2);
      try {
        const k = await freshKey("operator");
        const other = await freshKey("operator");
        const group = await fx.group({ name: uniq("rs-grant-g") });
        const ns = await fx.namespace(uniq("rs-grant-ns"));
        const endpoint = await fx.endpoint({
          name: uniq("rs-grant-ep"),
          restricted: true,
          namespaceUuid: ns,
        });

        // Two different grant actions spend the one limit.
        expect(ok(await addMember(group, fx.memberId, k.key))).toBe(true);
        expect(
          ok(
            await operator(
              "accessGroups.addEndpoint",
              { group_uuid: group, endpoint_uuid: endpoint },
              k.key,
            ),
          ),
        ).toBe(true);

        const refused = await addMember(group, fx.otherMemberId, k.key);

        expect({ status: refused.status, code: refused.code }).toEqual({
          status: 429,
          code: "TOO_MANY_REQUESTS",
        });
        expect(refused.message).toBe(await grantSentence());
        expect(await members(group)).toBe(1);
        const denied = await deniedBudget(k.uuid);
        expect(denied).toHaveLength(1);
        expect(denied[0].detail).toMatchObject({
          budget_class: "grant",
          limit: 2,
        });

        // Loosen has room: a loosening change that grants nothing still passes.
        const created = await operator(
          "namespaces.create",
          { name: uniq("rs-grant-still-ns") },
          k.key,
        );
        expect(ok(created)).toBe(true);
        namespaceUuids.push(dataOf<{ uuid: string }>(created).uuid);
        // A tightening change is not a grant.
        expect(
          ok(
            await operator(
              "accessGroups.removeMember",
              { group_uuid: group, user_id: fx.memberId },
              k.key,
            ),
          ),
        ).toBe(true);
        // The count is the key's own: another key still has its grants.
        expect(ok(await addMember(group, fx.otherMemberId, other.key))).toBe(
          true,
        );
      } finally {
        resetLimits();
      }
    });

    it("refuses a grant by every one of the grant actions once the limit is spent", async () => {
      setLimits(100, 1);
      try {
        const k = await freshKey("operator");
        const group = await fx.group({ name: uniq("rs-grant-each-g") });
        const widened = await fx.dataKey({
          name: uniq("rs-grant-each-key"),
          ownerId: fx.memberId,
        });
        await one(
          `UPDATE api_keys SET allowed_cidrs = $2, ip_policy_mode = 'enforce' WHERE uuid = $1`,
          [widened.uuid, ["203.0.113.1/32"]],
        );
        const ns = await fx.namespace(uniq("rs-grant-each-ns"));
        const open = await fx.endpoint({
          name: uniq("rs-grant-each-ep"),
          namespaceUuid: ns,
        });
        const curated = await fx.namespace(uniq("rs-grant-each-curated"));
        await one(
          `UPDATE namespaces SET tool_policy = 'allowlist' WHERE uuid = $1`,
          [curated],
        );
        // A narrow, locked, inactive data-plane key is what a re-activation
        // accepts.
        const inactive = await fx.dataKey({
          name: uniq("rs-grant-inactive-key"),
          ownerId: fx.memberId,
          endpointUuid: open,
        });
        await one(
          `UPDATE api_keys SET is_active = false, allowed_cidrs = $2, ip_policy_mode = 'enforce' WHERE uuid = $1`,
          [inactive.uuid, ["203.0.113.0/24"]],
        );
        expect(ok(await addMember(group, fx.memberId, k.key))).toBe(true);

        const attempts: Array<[string, () => Promise<Reply>]> = [
          [
            "group.endpoint.add",
            () =>
              operator(
                "accessGroups.addEndpoint",
                { group_uuid: group, endpoint_uuid: open },
                k.key,
              ),
          ],
          [
            "apikey.create",
            () =>
              operator(
                "apiKeys.create",
                {
                  name: uniq("rs-grant-minted"),
                  user_id: fx.memberId,
                  endpoint_uuid: open,
                  ip_policy: {
                    mode: "enforce",
                    allowed_cidrs: ["203.0.113.0/24"],
                  },
                },
                k.key,
              ),
          ],
          [
            "apikey.reactivate",
            () =>
              operator("apiKeys.reactivate", { uuid: inactive.uuid }, k.key),
          ],
          [
            "apikey.ip_policy.set",
            () =>
              operator(
                "apiKeys.setIpPolicy",
                {
                  uuid: widened.uuid,
                  ip_policy_mode: "enforce",
                  allowed_cidrs: ["203.0.113.0/24"],
                },
                k.key,
              ),
          ],
          [
            "endpoint.restricted.set",
            () =>
              operator(
                "accessGroups.setEndpointRestricted",
                { endpoint_uuid: open, restricted: false },
                k.key,
              ),
          ],
          [
            "namespace.tool_policy",
            () =>
              operator(
                "namespaces.setToolPolicy",
                { namespaceUuid: curated, toolPolicy: "allow_all" },
                k.key,
              ),
          ],
        ];
        const outcomes: Record<string, string | undefined> = {};
        for (const [action, attempt] of attempts) {
          const reply = await attempt();
          outcomes[action] = reply.code ?? (ok(reply) ? "ok" : "failed");
        }

        expect(outcomes).toEqual({
          "group.endpoint.add": "TOO_MANY_REQUESTS",
          "apikey.create": "TOO_MANY_REQUESTS",
          "apikey.reactivate": "TOO_MANY_REQUESTS",
          "apikey.ip_policy.set": "TOO_MANY_REQUESTS",
          "endpoint.restricted.set": "TOO_MANY_REQUESTS",
          "namespace.tool_policy": "TOO_MANY_REQUESTS",
        });
        expect(
          (await deniedBudget(k.uuid)).map(
            (row) => (row.detail as Record<string, unknown>).budget_class,
          ),
        ).toEqual(["grant", "grant", "grant", "grant", "grant", "grant"]);
        expect(
          (
            await one(`SELECT tool_policy FROM namespaces WHERE uuid = $1`, [
              curated,
            ])
          )[0].tool_policy,
        ).toBe("allowlist");
      } finally {
        resetLimits();
      }
    });

    it("spends no grant on a narrowing of an action that can grant", async () => {
      setLimits(100, 1);
      try {
        const k = await freshKey("operator");
        const group = await fx.group({ name: uniq("rs-grant-narrow-g") });
        const narrowed = await fx.dataKey({
          name: uniq("rs-grant-narrow-key"),
          ownerId: fx.memberId,
        });
        await one(
          `UPDATE api_keys SET allowed_cidrs = $2, ip_policy_mode = 'enforce' WHERE uuid = $1`,
          [narrowed.uuid, ["203.0.113.0/24"]],
        );
        const ns = await fx.namespace(uniq("rs-grant-narrow-ns"));
        const endpoint = await fx.endpoint({
          name: uniq("rs-grant-narrow-ep"),
          namespaceUuid: ns,
        });
        const open = await fx.namespace(uniq("rs-grant-narrow-open"));

        // A narrower list is a change, and restricting an endpoint is a
        // tightening: neither is a grant, though each is an action that can be.
        const narrow = await operator(
          "apiKeys.setIpPolicy",
          {
            uuid: narrowed.uuid,
            ip_policy_mode: "enforce",
            allowed_cidrs: ["203.0.113.0/28"],
          },
          k.key,
        );
        const restrict = await operator(
          "accessGroups.setEndpointRestricted",
          { endpoint_uuid: endpoint, restricted: true },
          k.key,
        );
        // A switch to allowlist is a tightening too.
        const curate = await operator(
          "namespaces.setToolPolicy",
          { namespaceUuid: open, toolPolicy: "allowlist" },
          k.key,
        );
        expect([ok(narrow), ok(restrict), ok(curate)]).toEqual([
          true,
          true,
          true,
        ]);
        expect(
          (
            await fx.auditNow(
              `actor_id = $1 AND outcome = 'success' AND detail ? 'budget_class'`,
              [k.uuid],
            )
          ).map((row) => (row.detail as Record<string, unknown>).budget_class),
        ).toEqual(["change", "tighten", "tighten"]);

        // The one grant the key has is still unspent.
        expect(ok(await addMember(group, fx.memberId, k.key))).toBe(true);
      } finally {
        resetLimits();
      }
    });

    it("counts a switch of a namespace to allow_all as a grant, and a switch to allowlist as none", async () => {
      setLimits(100, 1);
      try {
        const k = await freshKey("operator");
        const group = await fx.group({ name: uniq("rs-grant-policy-g") });
        const first = await fx.namespace(uniq("rs-grant-policy-a"));
        const second = await fx.namespace(uniq("rs-grant-policy-b"));
        for (const uuid of [first, second]) {
          await one(
            `UPDATE namespaces SET tool_policy = 'allowlist' WHERE uuid = $1`,
            [uuid],
          );
        }
        const setPolicy = (namespaceUuid: string, toolPolicy: string) =>
          operator(
            "namespaces.setToolPolicy",
            { namespaceUuid, toolPolicy },
            k.key,
          );

        // The one grant is spent on a widening of a whole namespace.
        expect(ok(await setPolicy(first, "allow_all"))).toBe(true);
        const refusedMember = await addMember(group, fx.memberId, k.key);
        expect({
          status: refusedMember.status,
          message: refusedMember.message,
        }).toEqual({ status: 429, message: await grantSentence() });
        // Narrowing it again spends none, and a second widening is refused.
        expect(ok(await setPolicy(first, "allowlist"))).toBe(true);
        const refusedPolicy = await setPolicy(second, "allow_all");
        expect({
          status: refusedPolicy.status,
          message: refusedPolicy.message,
        }).toEqual({ status: 429, message: await grantSentence() });
        expect(
          (
            await one(`SELECT tool_policy FROM namespaces WHERE uuid = $1`, [
              second,
            ])
          )[0].tool_policy,
        ).toBe("allowlist");
      } finally {
        resetLimits();
      }
    });

    it("lets exactly one of two concurrent grants take the last slot", async () => {
      setLimits(100, 1);
      try {
        const k = await freshKey("operator");
        const group = await fx.group({ name: uniq("rs-grant-race-g") });

        const [first, second] = await raceBehind(
          `SELECT pg_advisory_lock(hashtext('metamcp.admin_plane.budget'), hashtext('${k.uuid}'))`,
          `SELECT pg_advisory_unlock(hashtext('metamcp.admin_plane.budget'), hashtext('${k.uuid}'))`,
          () => addMember(group, fx.memberId, k.key),
          () => addMember(group, fx.otherMemberId, k.key),
        );

        expect([ok(first), second.code]).toEqual([true, "TOO_MANY_REQUESTS"]);
        expect(second.message).toBe(await grantSentence());
        expect(await members(group)).toBe(1);
        const denied = await deniedBudget(k.uuid);
        expect(denied).toHaveLength(1);
        expect(denied[0].detail).toMatchObject({ budget_class: "grant" });
      } finally {
        resetLimits();
      }
    });

    it("counts an earlier grant row of the key toward the limit, whatever wrote it", async () => {
      setLimits(100, 1);
      try {
        const k = await freshKey("operator");
        const group = await fx.group({ name: uniq("rs-grant-prior-g") });
        // A row as an earlier gateway version wrote it: a loosening change of a
        // grant action, with no grant marker of its own.
        await one(
          `INSERT INTO audit_log (actor_type, actor_id, action, outcome, detail)
           VALUES ('api_key', $1, 'group.member.add', 'success', '{"budget_class":"loosen"}'::jsonb)`,
          [k.uuid],
        );

        const reply = await addMember(group, fx.memberId, k.key);

        expect(reply.code).toBe("TOO_MANY_REQUESTS");
        expect(reply.message).toBe(await grantSentence());
        expect(await members(group)).toBe(0);
      } finally {
        resetLimits();
      }
    });
  });

  // ---------------------------------------------------------------------------
  describe("the capabilities", () => {
    it("reports the two markers, keeps the contract at 3, and leaves the procedure sets as they were", async () => {
      const reply = await read("apiKeys.operatorCapabilities", undefined);

      expect(reply.status).toBe(200);
      const caps = reply.data as {
        contract_version: number;
        markers: string[];
        procedures: string[];
        mutations: string[];
      };
      expect(caps.contract_version).toBe(3);
      expect(caps.markers).toEqual([
        "server-reads-redacted-v1",
        "server-update-metadata-only-v1",
      ]);
      expect(caps.procedures).toHaveLength(44);
      expect(caps.mutations).toHaveLength(25);
      expect(caps.procedures).toContain("frontend.mcpServers.create");
      expect(caps.procedures).toContain("frontend.mcpServers.update");
    });

    it("reports the grant limit in each scope's budget, beside total, loosen and destroy, and keeps the contract at 3", async () => {
      process.env.ADMIN_PLANE_BUDGET_OPERATOR_GRANT = "7";
      process.env.ADMIN_PLANE_BUDGET_SYNC_GRANT = "2";
      try {
        const reply = await read("apiKeys.operatorCapabilities", undefined);

        expect(reply.status).toBe(200);
        const caps = reply.data as {
          contract_version: number;
          budget: {
            operator: Record<string, number>;
            sync: Record<string, number>;
          };
        };
        expect(caps.contract_version).toBe(3);
        expect(Object.keys(caps.budget.operator).sort()).toEqual([
          "destroy",
          "grant",
          "loosen",
          "total",
        ]);
        expect(Object.keys(caps.budget.sync).sort()).toEqual([
          "destroy",
          "grant",
          "loosen",
          "total",
        ]);
        expect(caps.budget.operator.grant).toBe(7);
        expect(caps.budget.sync.grant).toBe(2);
      } finally {
        process.env.ADMIN_PLANE_BUDGET_OPERATOR_GRANT = "100000";
        process.env.ADMIN_PLANE_BUDGET_SYNC_GRANT = "100000";
      }
    });
  });
});
