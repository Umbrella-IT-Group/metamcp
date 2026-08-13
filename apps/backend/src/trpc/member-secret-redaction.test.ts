/**
 * Post-pentest regression cover (2026-08-13): `mcp_servers.env`,
 * `.bearer_token` and `.headers` hold the credentials THIS gateway presents to
 * the backend MCP servers it fronts, and every one of them was serialized in
 * plaintext to any member through frontend.mcpServers.list / .get and
 * frontend.namespaces.get (all protectedProcedure). The columns happened to be
 * empty on prod, so nothing leaked — the bug was latent, and would have armed
 * itself the first time anyone configured a per-server bearer token.
 *
 * These tests drive the REAL routers against the REAL serializers (only the
 * repository layer is faked), so they cover the whole policy path — session
 * role -> `includeSecrets` -> serialized payload — rather than the serializer
 * in isolation. A regression at either end fails here.
 */

import {
  createLogsRouter,
  createMcpServersRouter,
  createNamespacesRouter,
} from "@repo/trpc";
import {
  DatabaseMcpServer,
  DatabaseNamespaceWithServers,
  McpServerErrorStatusEnum,
  McpServerStatusEnum,
  McpServerTypeEnum,
} from "@repo/zod-types";
import { describe, expect, it, vi } from "vitest";

import { McpServersSerializer } from "../db/serializers/mcp-servers.serializer";
import { NamespacesSerializer } from "../db/serializers/namespaces.serializer";

const adminCtx = {
  user: { id: "admin-1", role: "admin" },
  session: { id: "s-admin" },
};
const memberCtx = {
  user: { id: "member-1", role: "member" },
  session: { id: "s-member" },
};

const SERVER_UUID = "11111111-1111-4111-8111-111111111111";
const NAMESPACE_UUID = "22222222-2222-4222-8222-222222222222";

// The secrets under test. A member must never see any of these three values.
const UPSTREAM_ENV = { VENDOR_API_KEY: "sk-live-super-secret" };
const UPSTREAM_BEARER = "upstream-bearer-token-do-not-leak";
const UPSTREAM_HEADERS = { "X-Vendor-Auth": "header-secret" };

const dbServer: DatabaseMcpServer = {
  uuid: SERVER_UUID,
  name: "vendor_backend",
  description: "backend MCP server fronted by this gateway",
  type: McpServerTypeEnum.enum.STREAMABLE_HTTP,
  command: null,
  args: [],
  env: UPSTREAM_ENV,
  url: "https://vendor.example.com/mcp",
  error_status: McpServerErrorStatusEnum.enum.NONE,
  created_at: new Date("2026-08-13T00:00:00.000Z"),
  bearerToken: UPSTREAM_BEARER,
  headers: UPSTREAM_HEADERS,
  user_id: null,
};

const dbNamespace: DatabaseNamespaceWithServers = {
  uuid: NAMESPACE_UUID,
  name: "vendor_namespace",
  description: null,
  created_at: new Date("2026-08-13T00:00:00.000Z"),
  updated_at: new Date("2026-08-13T00:00:00.000Z"),
  user_id: null,
  servers: [
    {
      uuid: SERVER_UUID,
      name: dbServer.name,
      description: dbServer.description,
      type: dbServer.type,
      command: dbServer.command,
      args: dbServer.args,
      url: dbServer.url,
      env: UPSTREAM_ENV,
      bearerToken: UPSTREAM_BEARER,
      headers: UPSTREAM_HEADERS,
      created_at: dbServer.created_at,
      user_id: null,
      status: McpServerStatusEnum.enum.ACTIVE,
      error_status: McpServerErrorStatusEnum.enum.NONE,
    },
  ],
};

// Wired to the real serializers so the assertions exercise production
// redaction, with the `includeSecrets` flag arriving exactly as the router
// computed it from the caller's role.
const buildMcpServersRouter = () =>
  createMcpServersRouter({
    list: async (_userId: string, includeSecrets: boolean) => ({
      success: true as const,
      data: McpServersSerializer.serializeMcpServerList([dbServer], {
        includeSecrets,
      }),
      message: "ok",
    }),
    get: async (
      _input: { uuid: string },
      _userId: string,
      includeSecrets: boolean,
    ) => ({
      success: true as const,
      data: McpServersSerializer.serializeMcpServer(dbServer, {
        includeSecrets,
      }),
      message: "ok",
    }),
    create: vi.fn(),
    bulkImport: vi.fn(),
    delete: vi.fn(),
    update: vi.fn(),
    reconnect: vi.fn(),
  });

const buildNamespacesRouter = () =>
  createNamespacesRouter({
    get: async (
      _input: { uuid: string },
      _userId: string,
      includeSecrets: boolean,
    ) => ({
      success: true as const,
      data: NamespacesSerializer.serializeNamespaceWithServers(dbNamespace, {
        includeSecrets,
      }),
      message: "ok",
    }),
    create: vi.fn(),
    list: vi.fn(),
    getTools: vi.fn(),
    delete: vi.fn(),
    update: vi.fn(),
    updateServerStatus: vi.fn(),
    updateToolStatus: vi.fn(),
    updateToolOverrides: vi.fn(),
    refreshTools: vi.fn(),
  });

describe("mcpServers.list / .get — upstream credentials are admin-only", () => {
  it("member: env, bearerToken and headers are redacted", async () => {
    const router = buildMcpServersRouter();

    const listed = await router.createCaller(memberCtx).list();
    expect(listed.data).toHaveLength(1);
    expect(listed.data[0].env).toEqual({});
    expect(listed.data[0].bearerToken).toBeNull();
    expect(listed.data[0].headers).toEqual({});

    const got = await router.createCaller(memberCtx).get({ uuid: SERVER_UUID });
    expect(got.data?.env).toEqual({});
    expect(got.data?.bearerToken).toBeNull();
    expect(got.data?.headers).toEqual({});

    // Nothing else smuggles the secret through some other field.
    expect(JSON.stringify(listed)).not.toContain(UPSTREAM_BEARER);
    expect(JSON.stringify(listed)).not.toContain("sk-live-super-secret");
    expect(JSON.stringify(listed)).not.toContain("header-secret");
    expect(JSON.stringify(got)).not.toContain(UPSTREAM_BEARER);
    expect(JSON.stringify(got)).not.toContain("sk-live-super-secret");
    expect(JSON.stringify(got)).not.toContain("header-secret");
  });

  it("member: non-secret server metadata still comes through", async () => {
    const router = buildMcpServersRouter();

    const listed = await router.createCaller(memberCtx).list();
    expect(listed.data[0]).toMatchObject({
      uuid: SERVER_UUID,
      name: "vendor_backend",
      type: McpServerTypeEnum.enum.STREAMABLE_HTTP,
      url: "https://vendor.example.com/mcp",
    });
  });

  it("admin: sees the real upstream credentials", async () => {
    const router = buildMcpServersRouter();

    const listed = await router.createCaller(adminCtx).list();
    expect(listed.data[0].env).toEqual(UPSTREAM_ENV);
    expect(listed.data[0].bearerToken).toBe(UPSTREAM_BEARER);
    expect(listed.data[0].headers).toEqual(UPSTREAM_HEADERS);

    const got = await router.createCaller(adminCtx).get({ uuid: SERVER_UUID });
    expect(got.data?.env).toEqual(UPSTREAM_ENV);
    expect(got.data?.bearerToken).toBe(UPSTREAM_BEARER);
    expect(got.data?.headers).toEqual(UPSTREAM_HEADERS);
  });

  it("a user row with no role at all is treated as a member", async () => {
    const router = buildMcpServersRouter();
    const roleless = { user: { id: "u-1" }, session: { id: "s-1" } };

    const listed = await router.createCaller(roleless).list();
    expect(listed.data[0].bearerToken).toBeNull();
    expect(listed.data[0].env).toEqual({});
    expect(listed.data[0].headers).toEqual({});
  });
});

describe("namespaces.get — embedded server credentials are admin-only", () => {
  it("member: every embedded server is redacted", async () => {
    const router = buildNamespacesRouter();

    const result = await router
      .createCaller(memberCtx)
      .get({ uuid: NAMESPACE_UUID });

    expect(result.data?.servers).toHaveLength(1);
    expect(result.data?.servers[0].env).toEqual({});
    expect(result.data?.servers[0].bearerToken).toBeNull();
    expect(result.data?.servers[0].headers).toEqual({});
    expect(JSON.stringify(result)).not.toContain(UPSTREAM_BEARER);
    expect(JSON.stringify(result)).not.toContain("sk-live-super-secret");
    expect(JSON.stringify(result)).not.toContain("header-secret");
  });

  it("member: namespace membership and server status still come through", async () => {
    const router = buildNamespacesRouter();

    const result = await router
      .createCaller(memberCtx)
      .get({ uuid: NAMESPACE_UUID });

    expect(result.data?.servers[0]).toMatchObject({
      uuid: SERVER_UUID,
      name: "vendor_backend",
      status: McpServerStatusEnum.enum.ACTIVE,
    });
  });

  it("admin: sees the real upstream credentials", async () => {
    const router = buildNamespacesRouter();

    const result = await router
      .createCaller(adminCtx)
      .get({ uuid: NAMESPACE_UUID });

    expect(result.data?.servers[0].env).toEqual(UPSTREAM_ENV);
    expect(result.data?.servers[0].bearerToken).toBe(UPSTREAM_BEARER);
    expect(result.data?.servers[0].headers).toEqual(UPSTREAM_HEADERS);
  });
});

describe("logs.get — admin gate", () => {
  const buildRouter = () =>
    createLogsRouter({
      // clientName is the API-key name or the OAuth user's email: whose key
      // called which tool, across every tenant of the gateway.
      getLogs: vi.fn().mockResolvedValue({
        success: true,
        data: [
          {
            id: "log-1",
            timestamp: new Date("2026-08-13T00:00:00.000Z"),
            category: "tool_call",
            serverName: "vendor_backend",
            level: "info",
            message: "tool call",
            toolName: "some_tool",
            clientName: "someone.else@umbrellaitgroup.com",
          },
        ],
        totalCount: 1,
      }),
      clearLogs: vi.fn(),
    });

  it("admin allowed, member FORBIDDEN", async () => {
    const router = buildRouter();

    const adminResult = await router.createCaller(adminCtx).get({ limit: 10 });
    expect(adminResult.data).toHaveLength(1);

    await expect(
      router.createCaller(memberCtx).get({ limit: 10 }),
    ).rejects.toMatchObject({ code: "FORBIDDEN" });
  });
});
