/**
 * The namespace tool filter: fail-closed enforcement (operator decision
 * 2026-09-02), the per-namespace tool policy (migration 0040), and the
 * namespace-scoped server lookup (upstream metatool-ai/metamcp#364).
 *
 * Fail closed: tool enable/disable is namespace curation, and it used to fail
 * OPEN: a DB error or an unresolved server name served (list side) or allowed
 * (call side) the tool, the opposite of the access-group gate. The fail-closed
 * cases below are written so each would FAIL against that fail-open behavior.
 *
 * Tool policy: `allow_all` (the default) serves a tool with no mapping row, as
 * the filter always has; `allowlist` reads "no row" as INACTIVE, so only an
 * ACTIVE row serves a tool. Both the list path and the call path are pinned,
 * because they are separate code paths that must not disagree.
 *
 * #364: a server prefix resolves among the servers MOUNTED in the namespace,
 * never by name across the whole estate, where a same-named server owned by
 * someone else could answer and its missing row read as "allowed".
 *
 * The db module is the evaluating stand-in in tool-mapping-db.fixtures, so
 * each test states rows (namespaces, servers, mounts, mappings) and every
 * lookup answers from them the way the database would.
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
  createFilterListToolsMiddleware,
  createFilterCallToolMiddleware,
  clearFilterCache,
} = await import("./filter-tools.functional");

const NS = "ns1";
const OTHER_NS = "ns2";
const SRV = { uuid: "srv-uuid", name: "srv" };
const TOOL_NAME = "srv__mytool";

const INACTIVE = "Tool has been marked as inactive in this namespace";
const NOT_ALLOWLISTED = "Tool is not on this namespace's allowlist";

const context = { namespaceUuid: NS, sessionId: "sess1" };
const listRequest = { method: "tools/list" as const, params: {} };
const toolNamed = (name: string) => ({
  name,
  description: "",
  inputSchema: { type: "object" as const },
});

const listNames = async (
  names: string[] = [TOOL_NAME],
  cacheEnabled = false,
) => {
  const { tools } = await createFilterListToolsMiddleware({ cacheEnabled })(
    async () => ({ tools: names.map(toolNamed) }),
  )(listRequest, context);
  return tools.map((tool) => tool.name).sort();
};

const callTool = async (name: string = TOOL_NAME, cacheEnabled = false) => {
  const handler = vi.fn(async () => ({
    content: [{ type: "text" as const, text: "ok" }],
  }));
  const mw = createFilterCallToolMiddleware({
    cacheEnabled,
    customErrorMessage: (toolName, reason) =>
      `Access denied to tool "${toolName}": ${reason}`,
  });
  const result = await mw(handler)(
    {
      method: "tools/call" as const,
      params: { name, arguments: {} },
    },
    context,
  );
  const text = (result.content as Array<{ text?: string }>)[0]?.text;
  return { handler, result, text };
};

/** Namespace NS with SRV mounted, under `policy`, holding `rows`. */
function curate(
  policy: "allow_all" | "allowlist",
  rows: Array<{ tool: string; status: "ACTIVE" | "INACTIVE" }> = [],
) {
  state.namespaces = [{ uuid: NS, toolPolicy: policy }];
  state.servers = [SRV];
  state.mounts = [{ namespaceUuid: NS, serverUuid: SRV.uuid }];
  state.mappings = rows.map((row) => ({
    namespaceUuid: NS,
    serverUuid: SRV.uuid,
    toolName: row.tool,
    status: row.status,
  }));
}

beforeEach(() => {
  vi.clearAllMocks();
  state.servers = [];
  state.mappings = [];
  state.mounts = [];
  state.namespaces = [];
  state.failOn = undefined;
  state.beforeQueryResult = undefined;
  queries.length = 0;
  clearFilterCache();
});

afterEach(() => {
  clearFilterCache();
});

describe("allow_all (the default policy): unchanged behaviour", () => {
  it("list: includes ACTIVE and no-row tools, excludes INACTIVE ones", async () => {
    curate("allow_all", [
      { tool: "on", status: "ACTIVE" },
      { tool: "off", status: "INACTIVE" },
    ]);
    expect(await listNames(["srv__on", "srv__off", "srv__unmapped"])).toEqual([
      "srv__on",
      "srv__unmapped",
    ]);
  });

  it("call: allows an ACTIVE tool", async () => {
    curate("allow_all", [{ tool: "mytool", status: "ACTIVE" }]);
    const { handler, result } = await callTool();
    expect(handler).toHaveBeenCalledTimes(1);
    expect(result.isError).toBeUndefined();
  });

  it("call: allows a tool with no mapping row (active by default)", async () => {
    curate("allow_all");
    const { handler } = await callTool();
    expect(handler).toHaveBeenCalledTimes(1);
  });

  it("call: denies an INACTIVE tool with the same text as before", async () => {
    curate("allow_all", [{ tool: "mytool", status: "INACTIVE" }]);
    const { handler, result, text } = await callTool();
    expect(handler).not.toHaveBeenCalled();
    expect(result.isError).toBe(true);
    expect(text).toBe(`Access denied to tool "${TOOL_NAME}": ${INACTIVE}`);
  });

  it("an unprefixed name is passed through untouched on both paths", async () => {
    curate("allow_all");
    expect(await listNames(["bare"])).toEqual(["bare"]);
    const { handler } = await callTool("bare");
    expect(handler).toHaveBeenCalledTimes(1);
  });
});

describe("allowlist: no row means INACTIVE", () => {
  it("list: serves only tools with an ACTIVE row", async () => {
    curate("allowlist", [
      { tool: "on", status: "ACTIVE" },
      { tool: "off", status: "INACTIVE" },
    ]);
    expect(await listNames(["srv__on", "srv__off", "srv__unmapped"])).toEqual([
      "srv__on",
    ]);
  });

  it("call: allows a tool with an ACTIVE row", async () => {
    curate("allowlist", [{ tool: "mytool", status: "ACTIVE" }]);
    const { handler, result } = await callTool();
    expect(handler).toHaveBeenCalledTimes(1);
    expect(result.isError).toBeUndefined();
  });

  it("call: refuses a tool with no row, naming the allowlist", async () => {
    curate("allowlist");
    const { handler, result, text } = await callTool();
    expect(handler).not.toHaveBeenCalled();
    expect(result.isError).toBe(true);
    expect(text).toBe(
      `Access denied to tool "${TOOL_NAME}": ${NOT_ALLOWLISTED}`,
    );
  });

  it("call: refuses an INACTIVE row with the inactive text", async () => {
    curate("allowlist", [{ tool: "mytool", status: "INACTIVE" }]);
    const { handler, text } = await callTool();
    expect(handler).not.toHaveBeenCalled();
    expect(text).toBe(`Access denied to tool "${TOOL_NAME}": ${INACTIVE}`);
  });

  it("an unprefixed name has no row, so it is excluded and refused", async () => {
    curate("allowlist");
    expect(await listNames(["bare"])).toEqual([]);
    const { handler, text } = await callTool("bare");
    expect(handler).not.toHaveBeenCalled();
    expect(text).toBe(`Access denied to tool "bare": ${NOT_ALLOWLISTED}`);
  });

  it("a value outside the two policies is read as the stricter allowlist", async () => {
    // The CHECK constraint makes this unreachable; if a row ever bypassed it,
    // the filter must not treat an unknown policy as allow_all.
    curate("allowlist");
    state.namespaces = [{ uuid: NS, toolPolicy: "something_else" }];
    expect(await listNames()).toEqual([]);
    const { handler } = await callTool();
    expect(handler).not.toHaveBeenCalled();
  });

  it("the policy is cached, and clearFilterCache(namespace) applies a flip at once", async () => {
    curate("allowlist");
    expect((await callTool(TOOL_NAME, true)).handler).not.toHaveBeenCalled();

    // Flipped in the database: the cached policy still answers.
    state.namespaces = [{ uuid: NS, toolPolicy: "allow_all" }];
    expect((await callTool(TOOL_NAME, true)).handler).not.toHaveBeenCalled();

    // What namespaces.setToolPolicy does after its write.
    clearFilterCache(NS);
    expect((await callTool(TOOL_NAME, true)).handler).toHaveBeenCalledTimes(1);
  });

  it.each([NS, undefined])(
    "a policy read started before clearing %s cannot repopulate the cache",
    async (namespaceToClear) => {
      curate("allow_all");
      let release!: () => void;
      let started!: () => void;
      const pendingRead = new Promise<void>((resolve) => {
        release = resolve;
      });
      const readStarted = new Promise<void>((resolve) => {
        started = resolve;
      });
      state.beforeQueryResult = async (query) => {
        if (query.table === "namespaces") {
          state.beforeQueryResult = undefined;
          started();
          await pendingRead;
        }
      };

      const oldCall = callTool(TOOL_NAME, true);
      await readStarted;
      state.namespaces = [{ uuid: NS, toolPolicy: "allowlist" }];
      clearFilterCache(namespaceToClear);
      release();
      await oldCall;

      // The in-flight call read before the flip. Later calls and lists must
      // use the committed policy instead of that call's delayed allow_all.
      expect((await callTool(TOOL_NAME, true)).handler).not.toHaveBeenCalled();
      expect(await listNames([TOOL_NAME], true)).toEqual([]);
    },
  );
});

describe("the call context carries the verdict to the routing handler", () => {
  // The routing handler widens its fallback for a tool with no mapping row
  // only under `allow_all` (tool-call-routing.ts), and only for the servers
  // judged here. It must read the policy this verdict used, not a fresh one.
  it.each(["allow_all", "allowlist"] as const)(
    "binds the judged policy (%s) and the judged servers",
    async (policy) => {
      curate(policy, [{ tool: "mytool", status: "ACTIVE" }]);
      const { handler } = await callTool();
      expect(handler).toHaveBeenCalledTimes(1);
      expect(handler).toHaveBeenCalledWith(
        expect.anything(),
        expect.objectContaining({
          toolPolicy: policy,
          allowedToolServerUuids: [SRV.uuid],
        }),
      );
    },
  );

  it("binds allow_all for an unprefixed name too", async () => {
    curate("allow_all");
    const { handler } = await callTool("bare");
    expect(handler).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ toolPolicy: "allow_all" }),
    );
  });
});

describe("fail closed (operator decision 2026-09-02)", () => {
  it("excludes and denies when the server prefix resolves to no mounted server", async () => {
    curate("allow_all");
    state.mounts = []; // SRV exists but is mounted nowhere
    expect(await listNames()).toEqual([]);
    const { handler, text } = await callTool();
    // Fail-open would have served it and run the handler.
    expect(handler).not.toHaveBeenCalled();
    expect(text).toBe(
      `Access denied to tool "${TOOL_NAME}": server could not be resolved`,
    );
  });

  it("excludes and denies when the server lookup errors", async () => {
    curate("allow_all");
    state.failOn = { servers: true };
    expect(await listNames()).toEqual([]);
    const { handler, text } = await callTool();
    expect(handler).not.toHaveBeenCalled();
    expect(text).toBe(
      `Access denied to tool "${TOOL_NAME}": tool status could not be verified`,
    );
  });

  it("excludes and denies when the tool-status query errors", async () => {
    curate("allow_all", [{ tool: "mytool", status: "ACTIVE" }]);
    state.failOn = { mappings: true };
    expect(await listNames()).toEqual([]);
    const { handler, text } = await callTool();
    expect(handler).not.toHaveBeenCalled();
    expect(text).toBe(
      `Access denied to tool "${TOOL_NAME}": tool status could not be verified`,
    );
  });

  it("serves nothing and denies when the policy query errors", async () => {
    curate("allow_all", [{ tool: "mytool", status: "ACTIVE" }]);
    state.failOn = { namespaces: true };
    // Even an unprefixed name: without the policy no tool can be judged.
    expect(await listNames([TOOL_NAME, "bare"])).toEqual([]);
    const { handler, text } = await callTool();
    expect(handler).not.toHaveBeenCalled();
    expect(text).toBe(
      `Access denied to tool "${TOOL_NAME}": tool status could not be verified`,
    );
  });

  it("serves nothing and denies when the namespace row does not exist", async () => {
    curate("allow_all", [{ tool: "mytool", status: "ACTIVE" }]);
    state.namespaces = [];
    expect(await listNames()).toEqual([]);
    expect((await callTool()).handler).not.toHaveBeenCalled();
  });
});

describe("#364: a server prefix means a server MOUNTED in this namespace", () => {
  // Two servers share the name "github": FOREIGN is mounted only in another
  // namespace and listed FIRST, so a lookup by name alone (no namespace, no
  // ORDER BY) lands on it, finds no row for this namespace, and reads that as
  // "no row, allowed". OURS is mounted here and holds the INACTIVE row.
  const OURS = { uuid: "github-ours", name: "github" };
  const FOREIGN = { uuid: "github-foreign", name: "github" };

  function twoGithubs(policy: "allow_all" | "allowlist") {
    state.namespaces = [
      { uuid: NS, toolPolicy: policy },
      { uuid: OTHER_NS, toolPolicy: "allow_all" },
    ];
    state.servers = [FOREIGN, OURS];
    state.mounts = [
      { namespaceUuid: OTHER_NS, serverUuid: FOREIGN.uuid },
      { namespaceUuid: NS, serverUuid: OURS.uuid },
    ];
    state.mappings = [
      {
        namespaceUuid: NS,
        serverUuid: OURS.uuid,
        toolName: "delete_repo",
        status: "INACTIVE",
      },
    ];
  }

  it("judges the tool against this namespace's own server, not a same-named foreign one", async () => {
    twoGithubs("allow_all");

    expect(await listNames(["github__delete_repo"])).toEqual([]);
    const { handler, text } = await callTool("github__delete_repo");
    expect(handler).not.toHaveBeenCalled();
    expect(text).toBe(
      `Access denied to tool "github__delete_repo": ${INACTIVE}`,
    );
  });

  it("every server lookup is scoped by this namespace", async () => {
    twoGithubs("allow_all");
    await listNames(["github__delete_repo"]);
    await callTool("github__delete_repo");

    const serverLookups = queries.filter((q) => q.table === "servers");
    expect(serverLookups.length).toBeGreaterThan(0);
    for (const lookup of serverLookups) {
      expect(lookup.where).toEqual({
        "nsm.namespace_uuid": NS,
        "servers.name": "github",
      });
    }
  });

  it("a prefix naming a server mounted only elsewhere does not resolve here", async () => {
    twoGithubs("allow_all");
    state.mounts = [{ namespaceUuid: OTHER_NS, serverUuid: FOREIGN.uuid }];
    const { handler, text } = await callTool("github__delete_repo");
    expect(handler).not.toHaveBeenCalled();
    expect(text).toBe(
      'Access denied to tool "github__delete_repo": server could not be resolved',
    );
  });

  it("two same-named servers mounted HERE: served only if served on both", async () => {
    // Routing keeps whichever registered first, which the filter cannot see,
    // so a tool INACTIVE on either of them is refused.
    state.namespaces = [{ uuid: NS, toolPolicy: "allowlist" }];
    state.servers = [OURS, FOREIGN];
    state.mounts = [
      { namespaceUuid: NS, serverUuid: OURS.uuid },
      { namespaceUuid: NS, serverUuid: FOREIGN.uuid },
    ];
    state.mappings = [
      {
        namespaceUuid: NS,
        serverUuid: OURS.uuid,
        toolName: "read",
        status: "ACTIVE",
      },
      {
        namespaceUuid: NS,
        serverUuid: FOREIGN.uuid,
        toolName: "read",
        status: "ACTIVE",
      },
      {
        namespaceUuid: NS,
        serverUuid: OURS.uuid,
        toolName: "write",
        status: "ACTIVE",
      },
    ];

    // `read` is ACTIVE on both; `write` has no row on FOREIGN (allowlist).
    expect(await listNames(["github__read", "github__write"])).toEqual([
      "github__read",
    ]);
    expect((await callTool("github__read")).handler).toHaveBeenCalledTimes(1);
    expect((await callTool("github__write")).handler).not.toHaveBeenCalled();
  });
});
