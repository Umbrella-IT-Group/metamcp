/**
 * The OpenAPI bridge judges a tools/call made by an override name as the tool
 * it runs, through the REAL filter and override middlewares in the order
 * `createMiddlewareEnabledHandlers` composes them.
 *
 * Fork #208 moved the override middleware outside the filter on the
 * Streamable-HTTP chain (metamcp-proxy.ts) but this chain kept the old order,
 * so the filter judged the alias, which has no mapping row of its own:
 *   - under `allow_all`, "no row" read as allowed, so a tool curated INACTIVE
 *     stayed callable through the bridge by its alias;
 *   - under the `allowlist` tool policy (migration 0040), "no row" reads as
 *     refused, so every alias of an allowlisted tool would be refused.
 * Each case below fails against the old order.
 *
 * Both middlewares read one in-memory stand-in for their tables (see
 * metamcp-middleware/tool-mapping-db.fixtures); the backend is a stub client
 * that records which tool it was asked to run.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type {
  FakeQuery,
  FakeToolMappingState,
} from "../../../lib/metamcp/metamcp-middleware/tool-mapping-db.fixtures";

const { state, queries, requestMock } = vi.hoisted(() => ({
  state: {
    servers: [],
    mappings: [],
    mounts: [],
    namespaces: [],
  } as FakeToolMappingState,
  queries: [] as FakeQuery[],
  requestMock: vi.fn(),
}));

vi.mock("@/utils/logger", () => ({
  default: { error: vi.fn(), warn: vi.fn(), info: vi.fn(), debug: vi.fn() },
}));

vi.mock("drizzle-orm", async (importOriginal) => ({
  ...(await importOriginal<typeof import("drizzle-orm")>()),
  ...(
    await import(
      "../../../lib/metamcp/metamcp-middleware/tool-mapping-db.fixtures"
    )
  ).drizzleConditionStubs,
}));
vi.mock(
  "../../../db/schema",
  async () =>
    (
      await import(
        "../../../lib/metamcp/metamcp-middleware/tool-mapping-db.fixtures"
      )
    ).toolMappingSchemaStub,
);
vi.mock("../../../db/index", async () => ({
  db: (
    await import(
      "../../../lib/metamcp/metamcp-middleware/tool-mapping-db.fixtures"
    )
  ).createToolMappingDb(state, queries),
  pool: {},
}));

vi.mock("../../../lib/metamcp/fetch-metamcp", () => ({
  getMcpServers: vi
    .fn()
    .mockResolvedValue({ "server-ninja": { name: "ninja" } }),
  // A routing miss checks for any additional mounted owner omitted from the
  // routable set, including error-gated servers (tool-call-routing.ts).
  getNamespaceServerStates: vi.fn().mockResolvedValue([]),
}));
vi.mock("../../../db/repositories/namespaces.repo", () => ({
  namespacesRepository: {
    findServersForNamespaceToolName: vi.fn().mockResolvedValue([]),
  },
}));
vi.mock("../../../lib/config.service", () => ({
  configService: {
    getMcpResetTimeoutOnProgress: vi.fn().mockResolvedValue(false),
    getMcpTimeout: vi.fn().mockResolvedValue(60000),
    getMcpMaxTotalTimeout: vi.fn().mockResolvedValue(60000),
    getMcpToolCallReconnectWarmupTimeout: vi.fn().mockResolvedValue(0),
  },
}));
vi.mock("../../../lib/metamcp/mcp-server-pool", () => ({
  mcpServerPool: {
    getSession: vi.fn().mockResolvedValue({
      client: {
        request: requestMock,
        getServerCapabilities: () => ({ tools: {} }),
        getServerVersion: () => ({ name: "ninja", version: "1.0.0" }),
      },
    }),
    invalidateServerConnection: vi.fn(),
  },
}));
vi.mock("../../../lib/metamcp/tool-call-warmup", () => ({
  acquireSessionWithBoundedWarmup: vi.fn().mockResolvedValue(undefined),
}));

import { namespacesRepository } from "../../../db/repositories/namespaces.repo";
import { getMcpServers } from "../../../lib/metamcp/fetch-metamcp";
import { mcpServerPool } from "../../../lib/metamcp/mcp-server-pool";
import { setAuditRecorderForTesting } from "../../../lib/metamcp/metamcp-middleware/auditing.functional";
import { clearFilterCache } from "../../../lib/metamcp/metamcp-middleware/filter-tools.functional";
import { clearOverrideCache } from "../../../lib/metamcp/metamcp-middleware/tool-overrides.functional";
import { acquireSessionWithBoundedWarmup } from "../../../lib/metamcp/tool-call-warmup";
import { createMiddlewareEnabledHandlers } from "./handlers";

const NS = "ns-1";
const SERVER = { uuid: "server-ninja", name: "ninja" };

const INACTIVE = "Tool has been marked as inactive in this namespace";

/** `list_things` (alias `things`) ACTIVE; `delete_things` (alias `purge`) INACTIVE. */
const curate = (policy: "allow_all" | "allowlist") => {
  state.servers = [SERVER];
  state.mounts = [{ namespaceUuid: NS, serverUuid: SERVER.uuid }];
  state.namespaces = [{ uuid: NS, toolPolicy: policy }];
  state.mappings = [
    {
      namespaceUuid: NS,
      serverUuid: SERVER.uuid,
      toolName: "list_things",
      status: "ACTIVE",
      overrideName: "things",
    },
    {
      namespaceUuid: NS,
      serverUuid: SERVER.uuid,
      toolName: "delete_things",
      status: "INACTIVE",
      overrideName: "purge",
    },
  ];
};

const call = async (name: string) => {
  const { handlerContext, callToolWithMiddleware } =
    createMiddlewareEnabledHandlers("openapi_ns-1", NS, "test-consumer");
  return callToolWithMiddleware(
    { method: "tools/call", params: { name, arguments: {} } },
    handlerContext,
  );
};

const textOf = (result: { content: unknown }) =>
  (result.content as Array<{ text?: string }>)[0]?.text;

/** Names the backend was asked to run. */
const ran = () =>
  requestMock.mock.calls.map(
    ([request]) => (request as { params: { name: string } }).params.name,
  );

beforeEach(() => {
  clearFilterCache();
  clearOverrideCache();
  queries.length = 0;
  state.beforeQueryResult = undefined;
  vi.mocked(getMcpServers).mockResolvedValue({
    [SERVER.uuid]: { name: SERVER.name },
  } as never);
  vi.mocked(mcpServerPool.getSession).mockResolvedValue({
    client: {
      request: requestMock,
      getServerCapabilities: () => ({ tools: {} }),
      getServerVersion: () => ({ name: SERVER.name, version: "1.0.0" }),
    },
  } as never);
  vi.mocked(namespacesRepository.findServersForNamespaceToolName)
    .mockReset()
    .mockResolvedValue([]);
  vi.mocked(acquireSessionWithBoundedWarmup)
    .mockReset()
    .mockResolvedValue(undefined);
  requestMock.mockReset();
  requestMock.mockImplementation(
    async (request: { params: { name: string } }) => ({
      content: [{ type: "text", text: `ran ${request.params.name}` }],
    }),
  );
  setAuditRecorderForTesting(null);
});

afterEach(() => {
  setAuditRecorderForTesting(undefined);
  clearFilterCache();
  clearOverrideCache();
});

describe("OpenAPI bridge: an alias is judged as the tool it runs", () => {
  it.each(["live", "reconnect"])(
    "%s routing cannot pick a replacement the filter did not judge",
    async (mode) => {
      curate("allowlist");
      // Mount replacement lands between the filter's snapshot and routing.
      // Only the old UUID was judged ACTIVE, so the new UUID must wait for a
      // fresh request even though it has the same name and a live connection.
      const replacement = { uuid: "server-replacement", name: SERVER.name };
      vi.mocked(getMcpServers).mockResolvedValue({
        [replacement.uuid]: { name: replacement.name },
      } as never);
      if (mode === "reconnect") {
        vi.mocked(mcpServerPool.getSession).mockResolvedValue(undefined);
        vi.mocked(
          namespacesRepository.findServersForNamespaceToolName,
        ).mockResolvedValue([
          { serverUuid: replacement.uuid, serverName: replacement.name },
        ]);
        vi.mocked(acquireSessionWithBoundedWarmup).mockResolvedValue({
          client: {
            request: requestMock,
            getServerCapabilities: () => ({ tools: {} }),
          },
        } as never);
      }

      await expect(call("ninja__list_things")).rejects.toThrow("Unknown tool");
      expect(ran()).toEqual([]);
      expect(acquireSessionWithBoundedWarmup).not.toHaveBeenCalled();
    },
  );

  it("does not list an unreviewed tool under another server's allowed prefix", async () => {
    curate("allowlist");
    const nested = { uuid: "server-nested", name: "ninja__nested" };
    state.servers = [SERVER, nested];
    state.mounts.push({ namespaceUuid: NS, serverUuid: nested.uuid });
    state.mappings = [
      {
        namespaceUuid: NS,
        serverUuid: SERVER.uuid,
        toolName: "nested__plain_read",
        status: "ACTIVE",
      },
    ];
    vi.mocked(getMcpServers).mockResolvedValue({
      [SERVER.uuid]: { name: SERVER.name },
      [nested.uuid]: { name: nested.name },
    } as never);
    vi.mocked(mcpServerPool.getSession).mockImplementation(
      async (_sessionId, uuid) =>
        ({
          client: {
            getServerCapabilities: () => ({ tools: {} }),
            getServerVersion: () => ({ name: SERVER.name, version: "1.0.0" }),
            request: async () => ({
              tools:
                uuid === nested.uuid
                  ? [{ name: "plain_read", inputSchema: { type: "object" } }]
                  : [],
            }),
          },
        }) as never,
    );

    const { handlerContext, listToolsWithMiddleware } =
      createMiddlewareEnabledHandlers("openapi_ns-1", NS, "test-consumer");
    const { tools } = await listToolsWithMiddleware(
      { method: "tools/list", params: {} },
      handlerContext,
    );
    expect(tools).toEqual([]);
  });

  it("allow_all: refuses an INACTIVE tool called by its alias", async () => {
    curate("allow_all");

    const result = await call("ninja__purge");

    expect(result.isError).toBe(true);
    expect(textOf(result)).toBe(
      `Access denied to tool "ninja__delete_things": ${INACTIVE}`,
    );
    expect(ran()).toEqual([]);
  });

  it("allowlist: runs an allowlisted tool called by its alias", async () => {
    curate("allowlist");

    const result = await call("ninja__things");

    expect(textOf(result)).toBe("ran list_things");
    expect(ran()).toEqual(["list_things"]);
  });

  it("allowlist: refuses an INACTIVE tool called by its alias", async () => {
    curate("allowlist");

    const result = await call("ninja__purge");

    expect(textOf(result)).toBe(
      `Access denied to tool "ninja__delete_things": ${INACTIVE}`,
    );
    expect(ran()).toEqual([]);
  });

  it("allowlist: refuses a tool with no row", async () => {
    curate("allowlist");

    const result = await call("ninja__unmapped");

    expect(textOf(result)).toBe(
      `Access denied to tool "ninja__unmapped": Tool is not on this namespace's allowlist`,
    );
    expect(ran()).toEqual([]);
  });
});
