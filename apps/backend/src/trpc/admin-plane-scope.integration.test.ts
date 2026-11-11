/**
 * An admin-plane (CI) API key on the real /trpc stack, against a REAL
 * Postgres: the real router module (routers/trpc.ts, with its CORS, rate-limit
 * and admin-key middleware), the real createContext and bearer resolver, the
 * real implementations and repositories, and the real audit writer.
 *
 * It runs the configuration round trip the sync tooling performs (list, create,
 * read back, update, tool listing, IP policies, timeouts) with the bearer
 * alone, and shows that the same bearer is refused everything outside that
 * surface, while an administrator's browser session keeps it. Only the MCP
 * connection pools are stubbed: creating a server must not dial it.
 *
 * Opt-in via TEST_DATABASE_URL, pointed at a disposable, migrated database:
 *
 *   cd apps/backend
 *   DATABASE_URL=<url> npx drizzle-kit migrate
 *   TEST_DATABASE_URL=<url> npx vitest run \
 *     src/trpc/admin-plane-scope.integration.test.ts
 */

import type { AddressInfo } from "node:net";

import express from "express";
import { Client } from "pg";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

import { INTEGRATION_DB_LOCK_KEY } from "../db/repositories/integration-db-lock";

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

const RUN = Date.now().toString(36);
const OWNER_EMAIL = `itest-admin-plane-owner-${RUN}@example.test`;
const PASSWORD = `itest-throwaway-password-${RUN}`;
const OTHER_EMAIL = `itest-admin-plane-other-${RUN}@example.test`;
const APP_ORIGIN = "http://127.0.0.1:1";

type TrpcReply = {
  status: number;
  data: unknown;
  code: string | undefined;
  message: string | undefined;
};

describeIfDb(
  "admin-plane key scope on the real /trpc stack (real Postgres)",
  () => {
    let base: string;
    let server: import("node:http").Server;
    let suiteLock: Client;
    let db: typeof import("../db/index").db;
    let schema: typeof import("../db/schema");
    let eq: typeof import("drizzle-orm").eq;
    let ownerId = "";
    let otherId = "";
    let ciKey = "";
    let ciKeyUuid = "";
    let dataKeyUuid = "";
    let ipCounter = 0;

    const nextIp = () => `198.51.100.${(++ipCounter % 250) + 1}`;

    async function trpc(
      procedure: string,
      input: unknown,
      kind: "query" | "mutation",
      headers: Record<string, string> = { authorization: `Bearer ${ciKey}` },
    ): Promise<TrpcReply> {
      const url =
        kind === "query"
          ? `${base}/trpc/frontend/${procedure}${
              input === undefined
                ? ""
                : `?input=${encodeURIComponent(JSON.stringify(input))}`
            }`
          : `${base}/trpc/frontend/${procedure}`;
      const res = await fetch(url, {
        method: kind === "query" ? "GET" : "POST",
        headers: {
          "content-type": "application/json",
          "cf-connecting-ip": nextIp(),
          ...headers,
        },
        body: kind === "mutation" ? JSON.stringify(input ?? {}) : undefined,
      });
      const body = (await res.json()) as {
        result?: { data?: unknown };
        error?: { message?: string; data?: { code?: string } };
      };
      return {
        status: res.status,
        data: body.result?.data,
        code: body.error?.data?.code,
        message: body.error?.message,
      };
    }

    async function auditRows(where: string, params: unknown[]) {
      // emit() is fire-and-forget; poll briefly for the row it schedules.
      const deadline = Date.now() + 5_000;
      for (;;) {
        const { rows } = await suiteLock.query(
          `SELECT actor_type, actor_id, actor_label, action, target_id, outcome, detail
           FROM audit_log WHERE ${where} ORDER BY occurred_at`,
          params,
        );
        if (rows.length > 0 || Date.now() > deadline) return rows;
        await new Promise((resolve) => setTimeout(resolve, 25));
      }
    }

    async function signUp(
      email: string,
    ): Promise<{ id: string; cookie: string }> {
      const { auth } = await import("../auth");
      const res = await auth.handler(
        new Request(`${APP_ORIGIN}/api/auth/sign-up/email`, {
          method: "POST",
          headers: { "content-type": "application/json", origin: APP_ORIGIN },
          body: JSON.stringify({ email, password: PASSWORD, name: "itest" }),
        }),
      );
      expect(res.status).toBe(200);
      const id = ((await res.json()) as { user: { id: string } }).user.id;
      const cookie = (res.headers.getSetCookie?.() ?? [])
        .map((c) => c.split(";")[0])
        .join("; ");
      return { id, cookie };
    }

    beforeAll(async () => {
      process.env.DATABASE_URL = TEST_DATABASE_URL;
      process.env.BETTER_AUTH_SECRET = `itest-throwaway-secret-${RUN}`;
      process.env.APP_URL = APP_ORIGIN;

      suiteLock = new Client({ connectionString: TEST_DATABASE_URL });
      await suiteLock.connect();
      await suiteLock.query(
        `SELECT pg_advisory_lock(${INTEGRATION_DB_LOCK_KEY})`,
      );

      ({ db } = await import("../db/index"));
      schema = await import("../db/schema");
      ({ eq } = await import("drizzle-orm"));
      const { ApiKeysRepository } = await import(
        "../db/repositories/api-keys.repo"
      );

      for (const email of [OWNER_EMAIL, OTHER_EMAIL]) {
        await db
          .delete(schema.usersTable)
          .where(eq(schema.usersTable.email, email));
      }
      ownerId = (await signUp(OWNER_EMAIL)).id;
      otherId = (await signUp(OTHER_EMAIL)).id;
      await db
        .update(schema.usersTable)
        .set({ role: "admin" })
        .where(eq(schema.usersTable.id, ownerId));

      const repo = new ApiKeysRepository();
      const ci = await repo.create({
        name: "itest ci admin plane",
        user_id: ownerId,
        admin_plane: true,
        is_active: true,
      });
      ciKey = ci.key;
      ciKeyUuid = ci.uuid;
      const data = await repo.create({
        name: "itest data plane",
        user_id: ownerId,
        all_endpoints: true,
        is_active: true,
      } as Parameters<typeof repo.create>[0]);
      dataKeyUuid = data.uuid;

      const { default: trpcRouter } = await import("../routers/trpc");
      const app = express();
      app.use("/trpc", trpcRouter);
      await new Promise<void>((resolve) => {
        server = app.listen(0, "127.0.0.1", resolve);
      });
      base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    }, 60_000);

    afterAll(async () => {
      await new Promise((resolve) => server?.close(resolve));
      if (db) {
        await db
          .delete(schema.namespacesTable)
          .where(eq(schema.namespacesTable.name, `itest-ns-${RUN}`));
        await db
          .delete(schema.mcpServersTable)
          .where(eq(schema.mcpServersTable.name, `itest-srv-${RUN}`));
        for (const email of [OWNER_EMAIL, OTHER_EMAIL]) {
          await db
            .delete(schema.usersTable)
            .where(eq(schema.usersTable.email, email));
        }
        const { pool } = await import("../db/index");
        await pool.end();
      }
      await suiteLock?.query(
        `SELECT pg_advisory_unlock(${INTEGRATION_DB_LOCK_KEY})`,
      );
      await suiteLock?.end();
    });

    it("runs the configuration round trip with the bearer alone", async () => {
      // Reads the dump tooling performs.
      for (const procedure of [
        "frontend.mcpServers.list",
        "frontend.namespaces.list",
        "frontend.endpoints.list",
        "frontend.apiKeys.listAll",
        "frontend.config.getMcpTimeout",
        "frontend.config.getMcpMaxTotalTimeout",
      ]) {
        const reply = await trpc(procedure, undefined, "query");
        expect({ procedure, status: reply.status }).toEqual({
          procedure,
          status: 200,
        });
      }

      // Writes the sync tooling performs, read back the way it reads them.
      const srv = await trpc(
        "frontend.mcpServers.create",
        {
          name: `itest-srv-${RUN}`,
          type: "STREAMABLE_HTTP",
          url: "http://127.0.0.1:9/mcp",
        },
        "mutation",
      );
      expect(srv.status).toBe(200);
      expect(srv.data).toMatchObject({ success: true });
      const serverUuid = (srv.data as { data: { uuid: string } }).data.uuid;
      expect(
        (
          await trpc(
            "frontend.mcpServers.update",
            {
              uuid: serverUuid,
              name: `itest-srv-${RUN}`,
              type: "STREAMABLE_HTTP",
              url: "http://127.0.0.1:9/mcp",
              description: "synced",
            },
            "mutation",
          )
        ).status,
      ).toBe(200);
      expect(
        (
          await trpc(
            "frontend.tools.getByMcpServerUuid",
            { mcpServerUuid: serverUuid },
            "query",
          )
        ).status,
      ).toBe(200);

      const ns = await trpc(
        "frontend.namespaces.create",
        { name: `itest-ns-${RUN}`, mcpServerUuids: [serverUuid] },
        "mutation",
      );
      expect(ns.status).toBe(200);
      expect(ns.data).toMatchObject({ success: true });
      const namespaceUuid = (ns.data as { data: { uuid: string } }).data.uuid;
      for (const [procedure, input, kind] of [
        ["frontend.namespaces.get", { uuid: namespaceUuid }, "query"],
        ["frontend.namespaces.getTools", { namespaceUuid }, "query"],
        [
          "frontend.namespaces.update",
          {
            uuid: namespaceUuid,
            name: `itest-ns-${RUN}`,
            description: "synced",
            mcpServerUuids: [serverUuid],
          },
          "mutation",
        ],
        [
          "frontend.namespaces.refreshTools",
          {
            namespaceUuid,
            tools: [
              {
                name: `itest-srv-${RUN}__ping`,
                inputSchema: { type: "object" },
              },
            ],
          },
          "mutation",
        ],
      ] as const) {
        const reply = await trpc(procedure, input, kind);
        expect({ procedure, status: reply.status }).toEqual({
          procedure,
          status: 200,
        });
      }

      const ep = await trpc(
        "frontend.endpoints.create",
        {
          name: `itest-ep-${RUN}`,
          namespaceUuid,
          enableClientMaxRate: false,
          enableMaxRate: false,
        },
        "mutation",
      );
      expect(ep.status).toBe(200);
      expect(ep.data).toMatchObject({ success: true });
      const endpointUuid = (ep.data as { data: { uuid: string } }).data.uuid;
      expect(
        (
          await trpc(
            "frontend.endpoints.update",
            {
              uuid: endpointUuid,
              name: `itest-ep-${RUN}`,
              namespaceUuid,
              description: "synced",
              enableClientMaxRate: false,
              enableMaxRate: false,
            },
            "mutation",
          )
        ).status,
      ).toBe(200);

      // The operator CLI's IP-policy calls (kept reachable on purpose).
      const policy = await trpc(
        "frontend.apiKeys.getGlobalIpPolicy",
        undefined,
        "query",
      );
      expect(policy.status).toBe(200);
      const current = policy.data as { mode: string; allowed_cidrs: string[] };
      expect(
        (
          await trpc(
            "frontend.apiKeys.setGlobalIpPolicy",
            { mode: current.mode, allowed_cidrs: current.allowed_cidrs },
            "mutation",
          )
        ).status,
      ).toBe(200);
      expect(
        (
          await trpc(
            "frontend.apiKeys.setIpPolicy",
            { uuid: dataKeyUuid, allowed_cidrs: null, ip_policy_mode: "off" },
            "mutation",
          )
        ).status,
      ).toBe(200);

      // The persisted admin event names the key, with the owner beside it.
      const rows = await auditRows(
        `action = 'namespace.create' AND target_id = $1`,
        [namespaceUuid],
      );
      expect(rows).toHaveLength(1);
      expect(rows[0]).toMatchObject({
        actor_type: "api_key",
        actor_id: ciKeyUuid,
        outcome: "success",
        detail: expect.objectContaining({
          admin_plane: { key_uuid: ciKeyUuid, owner_user_id: ownerId },
        }),
      });
    });

    it.each([
      [
        "an acts-as key for another user",
        "frontend.apiKeys.create",
        (): unknown => ({
          name: "itest acts as other",
          user_id: otherId,
          acts_as_user_id: otherId,
          all_endpoints: true,
        }),
        "mutation",
      ],
      [
        "another admin-plane key",
        "frontend.apiKeys.create",
        (): unknown => ({
          name: "itest second admin plane",
          admin_plane: true,
        }),
        "mutation",
      ],
      [
        "the user list",
        "frontend.users.list",
        (): unknown => undefined,
        "query",
      ],
      [
        "an account disable",
        "frontend.users.setDisabled",
        (): unknown => ({ user_id: otherId, disabled: true }),
        "mutation",
      ],
      [
        "access groups",
        "frontend.accessGroups.list",
        (): unknown => undefined,
        "query",
      ],
      [
        "an auth setting",
        "frontend.config.setSignupDisabled",
        (): unknown => ({ disabled: false }),
        "mutation",
      ],
      [
        "OAuth client admin",
        "frontend.oauthClients.list",
        (): unknown => undefined,
        "query",
      ],
      [
        "a public read outside the list",
        "frontend.config.getSignupDisabled",
        (): unknown => undefined,
        "query",
      ],
    ] as const)(
      "refuses %s with 403",
      async (_label, procedure, input, kind) => {
        const keysBefore = await db.select().from(schema.apiKeysTable);

        const reply = await trpc(procedure, input(), kind);

        expect(reply.status).toBe(403);
        expect(reply.code).toBe("FORBIDDEN");
        expect(reply.message).toBe(
          "This procedure is not available to an admin-plane API key.",
        );
        // Nothing was minted on the way out.
        expect(await db.select().from(schema.apiKeysTable)).toHaveLength(
          keysBefore.length,
        );
        const denied = await auditRows(
          `action = 'rbac.denied' AND target_id = $1 AND actor_id = $2`,
          [procedure, ciKeyUuid],
        );
        expect(denied.length).toBeGreaterThanOrEqual(1);
        expect(denied[0]).toMatchObject({ actor_type: "api_key" });
      },
    );

    it("answers a mixed batch per procedure", async () => {
      const res = await fetch(
        `${base}/trpc/frontend/frontend.mcpServers.list,frontend.users.list?batch=1&input=${encodeURIComponent("{}")}`,
        {
          headers: {
            authorization: `Bearer ${ciKey}`,
            "cf-connecting-ip": nextIp(),
          },
        },
      );
      const body = (await res.json()) as Array<{
        result?: unknown;
        error?: { data?: { code?: string } };
      }>;

      expect(body).toHaveLength(2);
      expect(body[0]?.result).toBeDefined();
      expect(body[1]?.error?.data?.code).toBe("FORBIDDEN");
    });

    it("leaves an administrator's browser session its whole surface", async () => {
      const { auth } = await import("../auth");
      const signIn = await auth.handler(
        new Request(`${APP_ORIGIN}/api/auth/sign-in/email`, {
          method: "POST",
          headers: { "content-type": "application/json", origin: APP_ORIGIN },
          body: JSON.stringify({ email: OWNER_EMAIL, password: PASSWORD }),
        }),
      );
      expect(signIn.status).toBe(200);
      const cookie = (signIn.headers.getSetCookie?.() ?? [])
        .map((c) => c.split(";")[0])
        .join("; ");

      const users = await trpc("frontend.users.list", undefined, "query", {
        cookie,
      });
      expect(users.status).toBe(200);
      const minted = await trpc(
        "frontend.apiKeys.create",
        { name: "itest human minted", all_endpoints: true },
        "mutation",
        { cookie, origin: APP_ORIGIN },
      );
      expect(minted.status).toBe(200);
      const rows = await auditRows(
        `action = 'apikey.create' AND actor_id = $1`,
        [ownerId],
      );
      expect(rows.length).toBeGreaterThanOrEqual(1);
      expect(rows[0]).toMatchObject({ actor_type: "user" });
    });
  },
);
