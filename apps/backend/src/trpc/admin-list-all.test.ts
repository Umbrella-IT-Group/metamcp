/**
 * Admin-only `listAll` for namespaces, endpoints and MCP servers
 * (TASKLIST METAMCP-NO-PRIVATE-NAMESPACES; operator ruling 2026-10-07 that
 * administrators must be able to see every row on this gateway).
 *
 * `list` returns public rows plus the caller's own, with no admin bypass, so a
 * row owned by another user was invisible to every administrator and to the
 * platform's read-only state export. `listAll` closes that for admins only.
 * `list` is deliberately left as it was: the platform's CI config sync matches
 * servers by NAME over `mcpServers.list`, and widening it would put rows the
 * sync has never seen into its name match.
 *
 * Each suite drives the REAL router from @repo/trpc wired to the REAL impl,
 * with the repository replaced by an in-memory table whose
 * `findAllAccessibleToUser` applies the same public-plus-own filter the SQL
 * does. That is what lets one test show both halves at once: through `listAll`
 * an admin sees another user's private row, and through `list` the same admin
 * still does not.
 */
import {
  createEndpointsRouter,
  createMcpServersRouter,
  createNamespacesRouter,
} from "@repo/trpc";
import { beforeEach, describe, expect, it, vi } from "vitest";

const loggerMock = vi.hoisted(() => ({
  debug: vi.fn(),
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
}));

vi.mock("@/utils/logger", () => ({ default: loggerMock }));

const repos = vi.hoisted(() => ({
  namespaces: { findAll: vi.fn(), findAllAccessibleToUser: vi.fn() },
  endpoints: {
    findAllWithNamespaces: vi.fn(),
    findAllAccessibleToUserWithNamespaces: vi.fn(),
  },
  mcpServers: { findAll: vi.fn(), findAllAccessibleToUser: vi.fn() },
}));

vi.mock("../db/repositories", () => ({
  // endpoints.impl constructs one at module scope; nothing here calls it.
  ApiKeysRepository: class {},
  namespacesRepository: repos.namespaces,
  endpointsRepository: repos.endpoints,
  mcpServersRepository: repos.mcpServers,
  namespaceMappingsRepository: {},
  toolsRepository: {},
}));

// The impls reach the connection pools and the override cache on their
// mutation paths. None of that is under test, and all of it would drag real
// infrastructure into the graph (same stubs as admin-audit.test.ts).
vi.mock("../lib/metamcp/mcp-server-pool", () => ({ mcpServerPool: {} }));
vi.mock("../lib/metamcp/metamcp-server-pool", () => ({
  metaMcpServerPool: {},
}));
vi.mock("../lib/metamcp/server-error-tracker", () => ({
  serverErrorTracker: {},
}));
vi.mock("../lib/metamcp/metamcp-middleware/tool-overrides.functional", () => ({
  clearOverrideCache: vi.fn(),
  mapOverrideNameToOriginal: vi.fn(),
}));
vi.mock("../lib/metamcp/utils", () => ({
  convertDbServerToParams: vi.fn(),
}));

const { namespacesImplementations } = await import("./namespaces.impl");
const { endpointsImplementations } = await import("./endpoints.impl");
const { mcpServersImplementations } = await import("./mcp-servers.impl");

const adminCtx = {
  user: { id: "admin-1", role: "admin" },
  session: { id: "s-admin" },
};
const memberCtx = {
  user: { id: "member-1", role: "member" },
  session: { id: "s-member" },
};
const anonymousCtx = { user: null, session: null };

const OTHER_USER = "other-user";
const CREATED = new Date("2026-10-01T00:00:00.000Z");

const namespaceRow = (uuid: string, name: string, user_id: string | null) => ({
  uuid,
  name,
  description: null,
  created_at: CREATED,
  updated_at: CREATED,
  user_id,
});

const NAMESPACES = [
  namespaceRow("ns-public", "shared", null),
  namespaceRow("ns-admin", "admin-own", "admin-1"),
  namespaceRow("ns-private", "someone-elses", OTHER_USER),
];

const endpointRow = (uuid: string, name: string, user_id: string | null) => ({
  uuid,
  name,
  description: null,
  namespace_uuid: "ns-public",
  enable_api_key_auth: true,
  require_scoped_api_key: false,
  enable_oauth: false,
  enable_max_rate: false,
  enable_client_max_rate: false,
  max_rate: null,
  client_max_rate: null,
  max_rate_seconds: null,
  client_max_rate_seconds: null,
  client_max_rate_strategy: null,
  client_max_rate_strategy_key: null,
  use_query_param_auth: false,
  restricted: false,
  created_at: CREATED,
  updated_at: CREATED,
  user_id,
  namespace: namespaceRow("ns-public", "shared", null),
});

const ENDPOINTS = [
  endpointRow("ep-public", "shared", null),
  endpointRow("ep-private", "someone-elses", OTHER_USER),
];

const serverRow = (uuid: string, name: string, user_id: string | null) => ({
  uuid,
  name,
  description: null,
  type: "STREAMABLE_HTTP" as const,
  command: null,
  args: [],
  env: {},
  url: `http://${name}:3000/mcp`,
  error_status: "NONE" as const,
  created_at: CREATED,
  bearerToken: null,
  headers: {},
  user_id,
});

// Two rows with the SAME name, one public and one private to another user:
// the situation that makes widening `list` unsafe for a by-name consumer.
const SERVERS = [
  serverRow("srv-public", "autotask", null),
  serverRow("srv-admin", "admin-own", "admin-1"),
  serverRow("srv-private", "autotask", OTHER_USER),
];

const publicOrOwn =
  <T extends { user_id: string | null }>(rows: T[]) =>
  async (userId: string) =>
    rows.filter((row) => row.user_id === null || row.user_id === userId);

beforeEach(() => {
  vi.clearAllMocks();
  repos.namespaces.findAll.mockResolvedValue(NAMESPACES);
  repos.namespaces.findAllAccessibleToUser.mockImplementation(
    publicOrOwn(NAMESPACES),
  );
  repos.endpoints.findAllWithNamespaces.mockResolvedValue(ENDPOINTS);
  repos.endpoints.findAllAccessibleToUserWithNamespaces.mockImplementation(
    publicOrOwn(ENDPOINTS),
  );
  repos.mcpServers.findAll.mockResolvedValue(SERVERS);
  repos.mcpServers.findAllAccessibleToUser.mockImplementation(
    publicOrOwn(SERVERS),
  );
});

describe("namespaces.listAll", () => {
  const router = () => createNamespacesRouter(namespacesImplementations);

  it("refuses a member with FORBIDDEN and never reads the table", async () => {
    await expect(
      router().createCaller(memberCtx).listAll(),
    ).rejects.toMatchObject({ code: "FORBIDDEN" });
    expect(repos.namespaces.findAll).not.toHaveBeenCalled();
  });

  it("refuses an unauthenticated caller with UNAUTHORIZED", async () => {
    await expect(
      router().createCaller(anonymousCtx).listAll(),
    ).rejects.toMatchObject({ code: "UNAUTHORIZED" });
  });

  it("shows an admin another user's private namespace, with its owner", async () => {
    const result = await router().createCaller(adminCtx).listAll();

    expect(result.success).toBe(true);
    expect(result.data.map((n) => [n.uuid, n.user_id])).toEqual([
      ["ns-public", null],
      ["ns-admin", "admin-1"],
      ["ns-private", OTHER_USER],
    ]);
  });

  it("leaves list unchanged: the same admin still sees only public plus own", async () => {
    const result = await router().createCaller(adminCtx).list();

    expect(result.data.map((n) => n.uuid)).toEqual(["ns-public", "ns-admin"]);
  });
});

describe("endpoints.listAll", () => {
  const router = () => createEndpointsRouter(endpointsImplementations);

  it("refuses a member with FORBIDDEN and never reads the table", async () => {
    await expect(
      router().createCaller(memberCtx).listAll(),
    ).rejects.toMatchObject({ code: "FORBIDDEN" });
    expect(repos.endpoints.findAllWithNamespaces).not.toHaveBeenCalled();
  });

  it("shows an admin another user's private endpoint, with its owner", async () => {
    const result = await router().createCaller(adminCtx).listAll();

    expect(result.success).toBe(true);
    expect(result.data.map((e) => [e.uuid, e.user_id])).toEqual([
      ["ep-public", null],
      ["ep-private", OTHER_USER],
    ]);
  });

  it("leaves list unchanged for the same admin", async () => {
    const result = await router().createCaller(adminCtx).list();

    expect(result.data.map((e) => e.uuid)).toEqual(["ep-public"]);
  });
});

describe("mcpServers.listAll", () => {
  const router = () => createMcpServersRouter(mcpServersImplementations);

  it("refuses a member with FORBIDDEN and never reads the table", async () => {
    await expect(
      router().createCaller(memberCtx).listAll(),
    ).rejects.toMatchObject({ code: "FORBIDDEN" });
    expect(repos.mcpServers.findAll).not.toHaveBeenCalled();
  });

  it("shows another owner's private server without exposing its connection credentials", async () => {
    const privateTemplate = SERVERS.find((s) => s.uuid === "srv-private");
    if (!privateTemplate) throw new Error("missing private server fixture");
    const privateServer = {
      ...privateTemplate,
      command: "private-command",
      args: ["--token", "private-argument"],
      env: { API_KEY: "private-env-value" },
      headers: { Authorization: "Bearer private-header-value" },
      bearerToken: "private-bearer-value",
    };
    repos.mcpServers.findAll.mockResolvedValue([
      ...SERVERS.filter((s) => s.uuid !== "srv-private"),
      privateServer,
    ]);
    const result = await router().createCaller(adminCtx).listAll();

    expect(result.success).toBe(true);
    expect(result.data.map((s) => [s.uuid, s.user_id])).toEqual([
      ["srv-public", null],
      ["srv-admin", "admin-1"],
      ["srv-private", OTHER_USER],
    ]);
    // Inventory visibility does not grant another owner's connection secrets.
    const privateRow = result.data.find((s) => s.uuid === "srv-private");
    expect(privateRow).toMatchObject({
      command: null,
      args: [],
      env: {},
      url: null,
      headers: {},
      bearerToken: null,
    });
    expect(privateRow?.env).toEqual({});
    expect(privateRow?.headers).toEqual({});
  });

  it("retains the existing admin connection view for public and owned servers", async () => {
    const accessible = SERVERS.filter((s) => s.user_id !== OTHER_USER).map(
      (s) => ({
        ...s,
        env: { API_KEY: "accessible-env-value" },
        headers: { "X-API-Key": "accessible-header-value" },
        bearerToken: "still-never-returned",
      }),
    );
    repos.mcpServers.findAll.mockResolvedValue(accessible);

    const result = await router().createCaller(adminCtx).listAll();

    expect(result.data).toHaveLength(2);
    for (const row of result.data) {
      expect(row.url).toBe(accessible.find((s) => s.uuid === row.uuid)?.url);
      expect(row.env).toEqual({ API_KEY: "accessible-env-value" });
      expect(row.headers).toEqual({ "X-API-Key": "accessible-header-value" });
      expect(row.bearerToken).toBeNull();
    }
  });

  it("leaves list unchanged: a by-name consumer of list still sees one 'autotask'", async () => {
    // The CI sync builds `{name: row}` from `mcpServers.list`. Had the private
    // row leaked into `list`, both rows would compete for the one key.
    const result = await router().createCaller(adminCtx).list();

    expect(result.data.map((s) => s.uuid)).toEqual(["srv-public", "srv-admin"]);
  });
});
