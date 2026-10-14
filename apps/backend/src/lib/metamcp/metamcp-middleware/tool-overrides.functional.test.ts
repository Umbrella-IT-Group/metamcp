/**
 * Override names (aliases) resolve to the tool on the SAME server, from the
 * database and from the reverse-name cache alike.
 *
 * An override name is unique per server, not per namespace: two servers in one
 * namespace may each give a tool the alias `shared`. The reverse cache used to
 * be keyed by namespace and alias only, so once one server's `shared` was
 * cached, a call to the other server's `shared` hit that entry and was routed
 * to the first server's tool (the database path always checked the server;
 * the cache hit did not). These tests hold rows for both servers in an
 * in-memory stand-in for the tables (see tool-mapping-db.fixtures) and assert
 * that every lookup, cached or not, lands on its own server.
 *
 * The listing's override lookup also resolves the server prefix among the
 * servers MOUNTED in the namespace (upstream metatool-ai/metamcp#364): by name
 * alone it could land on another owner's same-named server, find no row, and
 * silently drop this namespace's override.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type {
  FakeQuery,
  FakeToolMappingState,
} from "./tool-mapping-db.fixtures";

const { state, queries } = vi.hoisted(() => ({
  state: {
    servers: [],
    mappings: [],
    mounts: [],
    namespaces: [],
  } as FakeToolMappingState,
  queries: [] as FakeQuery[],
}));

vi.mock("drizzle-orm", async (importOriginal) => ({
  ...(await importOriginal<typeof import("drizzle-orm")>()),
  ...(await import("./tool-mapping-db.fixtures")).drizzleConditionStubs,
}));
vi.mock(
  "../../../db/schema",
  async () =>
    (await import("./tool-mapping-db.fixtures")).toolMappingSchemaStub,
);
vi.mock("../../../db/index", async () => ({
  db: (await import("./tool-mapping-db.fixtures")).createToolMappingDb(
    state,
    queries,
  ),
}));
vi.mock("@/utils/logger", () => ({
  default: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

const {
  clearOverrideCache,
  createToolOverridesCallToolMiddleware,
  createToolOverridesListToolsMiddleware,
  mapOverrideNameToOriginal,
} = await import("./tool-overrides.functional");

const NS = "ns-1";
const context = { namespaceUuid: NS, sessionId: "sess-1" };

const ALPHA = { uuid: "server-alpha", name: "alpha" };
const BETA = { uuid: "server-beta", name: "beta" };

/** Both servers give a different tool the same alias, `shared`. */
const bothShareAnAlias = (): FakeToolMappingState => ({
  servers: [ALPHA, BETA],
  mounts: [
    { namespaceUuid: NS, serverUuid: ALPHA.uuid },
    { namespaceUuid: NS, serverUuid: BETA.uuid },
  ],
  namespaces: [{ uuid: NS, toolPolicy: "allow_all" }],
  mappings: [
    {
      namespaceUuid: NS,
      serverUuid: ALPHA.uuid,
      toolName: "alpha_tool",
      status: "ACTIVE",
      overrideName: "shared",
    },
    {
      namespaceUuid: NS,
      serverUuid: BETA.uuid,
      toolName: "beta_tool",
      status: "ACTIVE",
      overrideName: "shared",
    },
  ],
});

const EMPTY: FakeToolMappingState = {
  servers: [],
  mappings: [],
  mounts: [],
  namespaces: [],
};

const load = (next: FakeToolMappingState) => {
  state.servers = next.servers;
  state.mappings = next.mappings;
  state.mounts = next.mounts;
  state.namespaces = next.namespaces;
};

const map = (name: string) => mapOverrideNameToOriginal(name, NS, true);

const tool = (name: string) => ({
  name,
  description: "",
  inputSchema: { type: "object" as const },
});

beforeEach(() => {
  clearOverrideCache();
  queries.length = 0;
  load(EMPTY);
});

afterEach(() => {
  clearOverrideCache();
});

describe("mapOverrideNameToOriginal: an alias resolves on its own server", () => {
  it("routes two servers' shared alias each to its own tool, cached or not", async () => {
    load(bothShareAnAlias());

    // First calls go to the database and cache what they find.
    expect(await map("alpha__shared")).toBe("alpha__alpha_tool");
    expect(await map("beta__shared")).toBe("beta__beta_tool");
    // Repeat calls are cache hits; they must not cross either.
    expect(await map("alpha__shared")).toBe("alpha__alpha_tool");
    expect(await map("beta__shared")).toBe("beta__beta_tool");
  });

  it("does not lend one server's cached alias to a server that has no such alias", async () => {
    load({
      ...bothShareAnAlias(),
      mappings: [bothShareAnAlias().mappings[0]],
    });

    expect(await map("alpha__shared")).toBe("alpha__alpha_tool");
    // beta has no `shared`: the name passes through unchanged rather than
    // being routed to alpha's tool off alpha's cache entry.
    expect(await map("beta__shared")).toBe("beta__shared");
  });

  it("routes each alias home from the cache the listing fills", async () => {
    load(bothShareAnAlias());
    const listed = await createToolOverridesListToolsMiddleware({
      cacheEnabled: true,
      persistentCacheOnListTools: true,
    })(async () => ({
      tools: [tool("alpha__alpha_tool"), tool("beta__beta_tool")],
    }))({ method: "tools/list", params: {} }, context);
    expect(listed.tools.map((t) => t.name).sort()).toEqual([
      "alpha__shared",
      "beta__shared",
    ]);

    // Empty the tables, so only the cache the listing filled can answer.
    load(EMPTY);
    queries.length = 0;

    expect(await map("alpha__shared")).toBe("alpha__alpha_tool");
    expect(await map("beta__shared")).toBe("beta__beta_tool");
    expect(queries).toEqual([]);
  });

  it("clearOverrideCache(namespace) still drops the server-keyed entries", async () => {
    load(bothShareAnAlias());
    expect(await map("alpha__shared")).toBe("alpha__alpha_tool");

    clearOverrideCache(NS);
    load(EMPTY);

    expect(await map("alpha__shared")).toBe("alpha__shared");
  });

  it("returns a name that is not an override unchanged", async () => {
    load(bothShareAnAlias());

    expect(await map("alpha__alpha_tool")).toBe("alpha__alpha_tool");
    expect(await map("alpha__other")).toBe("alpha__other");
    expect(await map("no_server_prefix")).toBe("no_server_prefix");
  });
});

describe("createToolOverridesCallToolMiddleware", () => {
  const run = async (name: string) => {
    const handler = vi.fn(async () => ({
      content: [{ type: "text" as const, text: "ok" }],
    }));
    const request = {
      method: "tools/call" as const,
      params: { name, arguments: { a: 1 } },
    };
    await createToolOverridesCallToolMiddleware({ cacheEnabled: true })(
      handler,
    )(request, context);
    return handler.mock.calls[0] as unknown as [typeof request, unknown];
  };

  it("hands the handler the original name for an alias, on the alias's server", async () => {
    load(bothShareAnAlias());

    const [viaAlpha] = await run("alpha__shared");
    const [viaBeta] = await run("beta__shared");

    expect(viaAlpha.params).toEqual({
      name: "alpha__alpha_tool",
      arguments: { a: 1 },
    });
    expect(viaBeta.params).toEqual({
      name: "beta__beta_tool",
      arguments: { a: 1 },
    });
  });

  it("hands the handler a non-override call exactly as sent", async () => {
    load(bothShareAnAlias());

    const [request, passedContext] = await run("alpha__plain_read");

    expect(request).toEqual({
      method: "tools/call",
      params: { name: "alpha__plain_read", arguments: { a: 1 } },
    });
    expect(passedContext).toBe(context);
  });
});

describe("#364: the listing's override lookup is scoped to the namespace's mounted servers", () => {
  const OTHER_NS = "ns-2";
  // Two servers share the name "github". FOREIGN is mounted only in OTHER_NS
  // and comes FIRST, so a lookup by name alone lands on it.
  const OURS = { uuid: "github-ours", name: "github" };
  const FOREIGN = { uuid: "github-foreign", name: "github" };

  const twoGithubs = (): FakeToolMappingState => ({
    servers: [FOREIGN, OURS],
    mounts: [
      { namespaceUuid: OTHER_NS, serverUuid: FOREIGN.uuid },
      { namespaceUuid: NS, serverUuid: OURS.uuid },
    ],
    namespaces: [
      { uuid: NS, toolPolicy: "allow_all" },
      { uuid: OTHER_NS, toolPolicy: "allow_all" },
    ],
    mappings: [
      {
        namespaceUuid: NS,
        serverUuid: OURS.uuid,
        toolName: "read",
        status: "ACTIVE",
        overrideName: "gh_read",
      },
      {
        namespaceUuid: OTHER_NS,
        serverUuid: FOREIGN.uuid,
        toolName: "read",
        status: "ACTIVE",
        overrideName: "foreign_read",
      },
    ],
  });

  const listIn = async (namespaceUuid: string) => {
    const listed = await createToolOverridesListToolsMiddleware({
      cacheEnabled: false,
    })(async () => ({ tools: [tool("github__read")] }))(
      { method: "tools/list", params: {} },
      { namespaceUuid, sessionId: "sess-1" },
    );
    return listed.tools.map((t) => t.name);
  };

  it("applies each namespace's own override for a same-named server", async () => {
    load(twoGithubs());

    expect(await listIn(NS)).toEqual(["github__gh_read"]);
    expect(await listIn(OTHER_NS)).toEqual(["github__foreign_read"]);
  });

  it("looks the server up inside the namespace being listed", async () => {
    load(twoGithubs());
    await listIn(NS);

    expect(queries.filter((q) => q.table === "servers")).toEqual([
      {
        table: "servers",
        where: { "nsm.namespace_uuid": NS, "servers.name": "github" },
      },
    ]);
  });

  it("applies no override when two mounted servers share the prefix", async () => {
    // Which server's override would apply cannot be told from the name, so
    // none does; the tool lists under its real name and the filter judges it
    // against both servers.
    load({
      ...twoGithubs(),
      mounts: [
        { namespaceUuid: NS, serverUuid: FOREIGN.uuid },
        { namespaceUuid: NS, serverUuid: OURS.uuid },
      ],
    });

    expect(await listIn(NS)).toEqual(["github__read"]);
  });
});
