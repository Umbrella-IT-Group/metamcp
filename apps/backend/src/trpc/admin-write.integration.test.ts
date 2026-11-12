/**
 * Every admin-plane mutation records its audit row in the change's own
 * transaction, against a REAL Postgres on the real /trpc stack.
 *
 * Plan, foreman decision 1: a credential with no person in front of it changes
 * the gateway with nobody watching, so for a request authenticated by an
 * admin-plane key (sync scope for what CI calls, operator scope for the rest)
 * the audit row is part of the change. For each procedure that key can reach
 * this proves both halves with a real database fault, not a mock:
 *  - while the audit INSERT is refused (a trigger raises on that action), the
 *    mutation fails and the state it would have changed is exactly as it was;
 *  - with the fault cleared, the same call succeeds and its audit row is
 *    visible the moment the call returns (no polling: it was awaited), naming
 *    the key as the actor with the owner and scope beside it.
 * `apiKeys.create` and `apiKeys.deactivate` are covered in
 * api-key-mint.integration.test.ts, where their fixtures live.
 *
 * Opt-in via TEST_DATABASE_URL, pointed at a disposable, migrated database:
 *
 *   cd apps/backend
 *   DATABASE_URL=<url> npx drizzle-kit migrate
 *   TEST_DATABASE_URL=<url> npx vitest run \
 *     src/trpc/admin-write.integration.test.ts
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
    invalidateIdleServer: vi.fn().mockResolvedValue(undefined),
    invalidateIdleServers: vi.fn().mockResolvedValue(undefined),
    invalidateOpenApiSessions: vi.fn().mockResolvedValue(undefined),
  },
}));

const FIXED_FAILURE =
  "The change was not applied because its audit record could not be written.";

type Reply = Awaited<ReturnType<Fixture["trpc"]>>;

/** Did the call fail, whether as an HTTP error or a `success: false` body? */
function failed(reply: Reply): boolean {
  if (reply.status !== 200) return true;
  const body = reply.data as { success?: boolean } | undefined;
  return body?.success === false;
}

function failureMessage(reply: Reply): string | undefined {
  if (reply.status !== 200) return reply.message;
  return (reply.data as { message?: string } | undefined)?.message;
}

describeIfDb(
  "admin-plane mutations audit in their own transaction (real Postgres)",
  () => {
    let fx: Fixture;
    let serverName = "";
    let serverUuid = "";
    let namespaceName = "";
    let namespaceUuid = "";
    let endpointName = "";
    let dataKeyUuid = "";
    const syncOptions = () => ({ key: fx.sync.key });

    /**
     * Run `call` once with the audit INSERT for `action` refused and once
     * without. `unchanged` asserts the state a failed call must leave;
     * `changed` asserts the state the successful one produces and returns the
     * target id the audit row is keyed on.
     */
    async function inOwnTransaction(spec: {
      action: string;
      key: { uuid: string; scope: "sync" | "operator" };
      call: () => Promise<Reply>;
      unchanged: () => Promise<void>;
      changed: (reply: Reply) => Promise<string>;
    }) {
      await fx.failAuditFor(spec.action);
      try {
        const refused = await spec.call();
        expect(failed(refused)).toBe(true);
        // The fixed sentence, never a driver message or a row.
        const message = failureMessage(refused);
        expect(
          message === FIXED_FAILURE || message === "Internal server error",
        ).toBe(true);
        await spec.unchanged();
        expect(
          await fx.auditNow(
            `action = $1 AND actor_id = $2 AND outcome = 'success'`,
            [spec.action, spec.key.uuid],
          ),
        ).toHaveLength(0);
      } finally {
        await fx.clearAuditFault(spec.action);
      }

      const done = await spec.call();
      expect(failed(done)).toBe(false);
      const targetId = await spec.changed(done);
      // Visible straight away: the row was awaited inside the transaction.
      const rows = await fx.auditNow(
        `action = $1 AND actor_id = $2 AND target_id = $3`,
        [spec.action, spec.key.uuid, targetId],
      );
      expect(rows).toHaveLength(1);
      expect(rows[0]).toMatchObject({
        actor_type: "api_key",
        outcome: "success",
      });
      expect(rows[0].detail).toMatchObject({
        admin_plane: {
          key_uuid: spec.key.uuid,
          owner_user_id: fx.ownerId,
          scope: spec.key.scope,
        },
      });
    }

    const rowsWhere = async (sql: string, params: unknown[]) =>
      (await fx.suiteLock.query(sql, params)).rows;

    beforeAll(async () => {
      fx = await createFixture(TEST_DATABASE_URL as string, "wr");
      serverName = `itest-wr-srv-${fx.run}`;
      namespaceName = `itest-wr-ns-${fx.run}`;
      endpointName = `itest-wr-ep-${fx.run}`;
      const dataKey = await fx.trpc(
        "frontend.apiKeys.create",
        { name: `itest wr data ${fx.run}`, all_endpoints: true },
        "mutation",
        { cookie: fx.ownerCookie },
      );
      expect(dataKey.status).toBe(200);
      dataKeyUuid = (dataKey.data as { uuid: string }).uuid;
    }, 90_000);

    afterAll(async () => {
      if (fx) {
        await fx.db
          .delete(fx.schema.endpointsTable)
          .where(fx.eq(fx.schema.endpointsTable.name, endpointName));
        await fx.db
          .delete(fx.schema.namespacesTable)
          .where(fx.eq(fx.schema.namespacesTable.name, namespaceName));
        await fx.db
          .delete(fx.schema.mcpServersTable)
          .where(fx.eq(fx.schema.mcpServersTable.name, serverName));
      }
      await fx?.close();
    });

    it("mcpServers.create by a sync-scope key", async () => {
      await inOwnTransaction({
        action: "mcpserver.create",
        key: { ...fx.sync, scope: "sync" },
        call: () =>
          fx.trpc(
            "frontend.mcpServers.create",
            {
              name: serverName,
              type: "STREAMABLE_HTTP",
              url: "http://127.0.0.1:9/mcp",
            },
            "mutation",
            syncOptions(),
          ),
        unchanged: async () => {
          expect(
            await rowsWhere(`SELECT 1 FROM mcp_servers WHERE name = $1`, [
              serverName,
            ]),
          ).toHaveLength(0);
        },
        changed: async (reply) => {
          serverUuid = (reply.data as { data: { uuid: string } }).data.uuid;
          return serverUuid;
        },
      });
    });

    it("mcpServers.update by a sync-scope key", async () => {
      const update = (description: string) => () =>
        fx.trpc(
          "frontend.mcpServers.update",
          {
            uuid: serverUuid,
            name: serverName,
            type: "STREAMABLE_HTTP",
            url: "http://127.0.0.1:9/mcp",
            description,
          },
          "mutation",
          syncOptions(),
        );
      await inOwnTransaction({
        action: "mcpserver.update",
        key: { ...fx.sync, scope: "sync" },
        call: update("after the sync"),
        unchanged: async () => {
          const rows = await rowsWhere(
            `SELECT description FROM mcp_servers WHERE uuid = $1`,
            [serverUuid],
          );
          expect(rows[0].description).not.toBe("after the sync");
        },
        changed: async () => {
          const rows = await rowsWhere(
            `SELECT description FROM mcp_servers WHERE uuid = $1`,
            [serverUuid],
          );
          expect(rows[0].description).toBe("after the sync");
          return serverUuid;
        },
      });
    });

    it("namespaces.create by an operator-scope key", async () => {
      await inOwnTransaction({
        action: "namespace.create",
        key: { ...fx.operator, scope: "operator" },
        call: () =>
          fx.trpc(
            "frontend.namespaces.create",
            { name: namespaceName, mcpServerUuids: [serverUuid] },
            "mutation",
          ),
        unchanged: async () => {
          expect(
            await rowsWhere(`SELECT 1 FROM namespaces WHERE name = $1`, [
              namespaceName,
            ]),
          ).toHaveLength(0);
        },
        changed: async (reply) => {
          namespaceUuid = (reply.data as { data: { uuid: string } }).data.uuid;
          return namespaceUuid;
        },
      });
    });

    it("namespaces.update by an operator-scope key", async () => {
      await inOwnTransaction({
        action: "namespace.update",
        key: { ...fx.operator, scope: "operator" },
        call: () =>
          fx.trpc(
            "frontend.namespaces.update",
            {
              uuid: namespaceUuid,
              name: namespaceName,
              description: "after the update",
              mcpServerUuids: [serverUuid],
            },
            "mutation",
          ),
        unchanged: async () => {
          const rows = await rowsWhere(
            `SELECT description FROM namespaces WHERE uuid = $1`,
            [namespaceUuid],
          );
          expect(rows[0].description).not.toBe("after the update");
        },
        changed: async () => {
          const rows = await rowsWhere(
            `SELECT description FROM namespaces WHERE uuid = $1`,
            [namespaceUuid],
          );
          expect(rows[0].description).toBe("after the update");
          return namespaceUuid;
        },
      });
    });

    it("namespaces.refreshTools by an operator-scope key writes tools and mappings together with its row, or none of them", async () => {
      await inOwnTransaction({
        action: "namespace.refresh_tools",
        key: { ...fx.operator, scope: "operator" },
        call: () =>
          fx.trpc(
            "frontend.namespaces.refreshTools",
            {
              namespaceUuid,
              tools: [
                {
                  name: `${serverName}__ping`,
                  inputSchema: { type: "object" },
                },
              ],
            },
            "mutation",
          ),
        unchanged: async () => {
          // Neither the tool nor its mapping exists: not half applied.
          expect(
            await rowsWhere(`SELECT 1 FROM tools WHERE mcp_server_uuid = $1`, [
              serverUuid,
            ]),
          ).toHaveLength(0);
          expect(
            await rowsWhere(
              `SELECT 1 FROM namespace_tool_mappings WHERE namespace_uuid = $1`,
              [namespaceUuid],
            ),
          ).toHaveLength(0);
        },
        changed: async () => {
          expect(
            await rowsWhere(`SELECT 1 FROM tools WHERE mcp_server_uuid = $1`, [
              serverUuid,
            ]),
          ).toHaveLength(1);
          expect(
            await rowsWhere(
              `SELECT 1 FROM namespace_tool_mappings WHERE namespace_uuid = $1`,
              [namespaceUuid],
            ),
          ).toHaveLength(1);
          return namespaceUuid;
        },
      });
    });

    it("namespaces.updateToolStatus by an operator-scope key", async () => {
      const [tool] = await rowsWhere(
        `SELECT uuid FROM tools WHERE mcp_server_uuid = $1`,
        [serverUuid],
      );
      const status = async () =>
        (
          await rowsWhere(
            `SELECT status FROM namespace_tool_mappings
            WHERE namespace_uuid = $1 AND tool_uuid = $2`,
            [namespaceUuid, tool.uuid],
          )
        )[0].status as string;
      expect(await status()).toBe("ACTIVE");

      await inOwnTransaction({
        action: "namespace.tool_status",
        key: { ...fx.operator, scope: "operator" },
        call: () =>
          fx.trpc(
            "frontend.namespaces.updateToolStatus",
            {
              namespaceUuid,
              toolUuid: tool.uuid,
              serverUuid,
              status: "INACTIVE",
            },
            "mutation",
          ),
        unchanged: async () => {
          expect(await status()).toBe("ACTIVE");
        },
        changed: async () => {
          expect(await status()).toBe("INACTIVE");
          return namespaceUuid;
        },
      });
    });

    it("endpoints.create by an operator-scope key", async () => {
      await inOwnTransaction({
        action: "endpoint.create",
        key: { ...fx.operator, scope: "operator" },
        call: () =>
          fx.trpc(
            "frontend.endpoints.create",
            {
              name: endpointName,
              namespaceUuid,
              enableClientMaxRate: false,
              enableMaxRate: false,
            },
            "mutation",
          ),
        unchanged: async () => {
          expect(
            await rowsWhere(`SELECT 1 FROM endpoints WHERE name = $1`, [
              endpointName,
            ]),
          ).toHaveLength(0);
        },
        changed: async (reply) =>
          (reply.data as { data: { uuid: string } }).data.uuid,
      });
    });

    it("endpoints.update by an operator-scope key", async () => {
      const [endpoint] = await rowsWhere(
        `SELECT uuid FROM endpoints WHERE name = $1`,
        [endpointName],
      );
      await inOwnTransaction({
        action: "endpoint.update",
        key: { ...fx.operator, scope: "operator" },
        call: () =>
          fx.trpc(
            "frontend.endpoints.update",
            {
              uuid: endpoint.uuid,
              name: endpointName,
              namespaceUuid,
              description: "after the update",
              enableClientMaxRate: false,
              enableMaxRate: false,
            },
            "mutation",
          ),
        unchanged: async () => {
          const rows = await rowsWhere(
            `SELECT description FROM endpoints WHERE uuid = $1`,
            [endpoint.uuid],
          );
          expect(rows[0].description).not.toBe("after the update");
        },
        changed: async () => {
          const rows = await rowsWhere(
            `SELECT description FROM endpoints WHERE uuid = $1`,
            [endpoint.uuid],
          );
          expect(rows[0].description).toBe("after the update");
          return endpoint.uuid;
        },
      });
    });

    it("apiKeys.setIpPolicy by an operator-scope key", async () => {
      const policy = async () =>
        (
          await rowsWhere(
            `SELECT allowed_cidrs, ip_policy_mode FROM api_keys WHERE uuid = $1`,
            [dataKeyUuid],
          )
        )[0] as { allowed_cidrs: string[] | null; ip_policy_mode: string };

      await inOwnTransaction({
        action: "apikey.ip_policy.set",
        key: { ...fx.operator, scope: "operator" },
        call: () =>
          fx.trpc(
            "frontend.apiKeys.setIpPolicy",
            {
              uuid: dataKeyUuid,
              allowed_cidrs: ["203.0.113.0/24"],
              ip_policy_mode: "enforce",
            },
            "mutation",
          ),
        unchanged: async () => {
          expect(await policy()).toEqual({
            allowed_cidrs: null,
            ip_policy_mode: "off",
          });
        },
        changed: async () => {
          expect(await policy()).toEqual({
            allowed_cidrs: ["203.0.113.0/24"],
            ip_policy_mode: "enforce",
          });
          return dataKeyUuid;
        },
      });
    });

    it("apiKeys.setGlobalIpPolicy by an operator-scope key", async () => {
      const stored = async () =>
        (
          await rowsWhere(
            `SELECT id, value FROM config
            WHERE id IN ('API_KEY_IP_POLICY_MODE', 'API_KEY_IP_ALLOWED_CIDRS')
            ORDER BY id`,
            [],
          )
        ).map((row) => [row.id, row.value]);
      const before = await stored();

      try {
        await inOwnTransaction({
          action: "config.api_key_ip_policy.set",
          key: { ...fx.operator, scope: "operator" },
          call: () =>
            fx.trpc(
              "frontend.apiKeys.setGlobalIpPolicy",
              // `audit` cannot refuse any request, so it never interferes with
              // the calls that follow, and the rail does not judge it.
              { mode: "audit", allowed_cidrs: ["203.0.113.0/24"] },
              "mutation",
            ),
          unchanged: async () => {
            expect(await stored()).toEqual(before);
          },
          changed: async () => {
            expect(await stored()).toEqual([
              ["API_KEY_IP_ALLOWED_CIDRS", '["203.0.113.0/24"]'],
              ["API_KEY_IP_POLICY_MODE", "audit"],
            ]);
            return "API_KEY_IP_POLICY";
          },
        });
      } finally {
        await fx.suiteLock.query(
          `DELETE FROM config WHERE id IN ('API_KEY_IP_POLICY_MODE', 'API_KEY_IP_ALLOWED_CIDRS')`,
        );
      }
    });

    it("keeps a human administrator's writes on the best-effort record: an audit outage does not fail them", async () => {
      const name = `itest-wr-human-${fx.run}`;
      await fx.failAuditFor("mcpserver.create");
      try {
        const reply = await fx.trpc(
          "frontend.mcpServers.create",
          { name, type: "STREAMABLE_HTTP", url: "http://127.0.0.1:9/mcp" },
          "mutation",
          { cookie: fx.ownerCookie },
        );
        expect(failed(reply)).toBe(false);
      } finally {
        await fx.clearAuditFault("mcpserver.create");
        await fx.db
          .delete(fx.schema.mcpServersTable)
          .where(fx.eq(fx.schema.mcpServersTable.name, name));
      }
    });

    it("names no row, parameter or driver text in the failure it returns", async () => {
      await fx.failAuditFor("mcpserver.create");
      try {
        const reply = await fx.trpc(
          "frontend.mcpServers.create",
          {
            name: `itest-wr-leak-${fx.run}`,
            type: "STREAMABLE_HTTP",
            url: "http://127.0.0.1:9/mcp",
            bearerToken: "itest-vendor-secret-do-not-echo",
          },
          "mutation",
          syncOptions(),
        );
        const text = JSON.stringify(reply);

        expect(failed(reply)).toBe(true);
        expect(text).not.toContain("itest-vendor-secret-do-not-echo");
        expect(text).not.toContain("audit_log");
        expect(text).not.toContain("itest: audit insert refused");
        expect(JSON.stringify(quiet.error.mock.calls)).not.toContain(
          "itest-vendor-secret-do-not-echo",
        );
      } finally {
        await fx.clearAuditFault("mcpserver.create");
      }
    });
  },
);
