/**
 * The override middleware hands a listing back in the order it received it
 * (issue #278).
 *
 * Each tool's override is looked up concurrently, and a lookup that misses the
 * cache answers whenever its database round trip ends. The middleware used to
 * append each result to the output when its own lookup finished, so a listing
 * the proxy had already sorted came out in lookup-completion order, which
 * changes from call to call. Here every tool's lookup is delayed by a chosen
 * amount, in forward, reverse and rotated order, and the output must be the
 * input order each time (renamed tools stay in their slot).
 *
 * Oracle: the input order. Nothing is taken from the middleware itself.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type {
  FakeQuery,
  FakeToolMappingState,
} from "./tool-mapping-db.fixtures";
import type { ListingOriginsContext } from "./tool-overrides.functional";

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

const { clearOverrideCache, createToolOverridesListToolsMiddleware } =
  await import("./tool-overrides.functional");

const NS = "ns-1";
const SRV = { uuid: "server-alpha", name: "alpha" };
const context = { namespaceUuid: NS, sessionId: "sess-1" };

const tool = (name: string) => ({
  name,
  description: "",
  inputSchema: { type: "object" as const },
});

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/** Delay each override lookup by the amount set for the tool it is for. */
const delayLookups = (delays: Record<string, number>) => {
  state.beforeQueryResult = async (query) => {
    if (query.table !== "mappings") return;
    const toolName = Object.values(query.where).find(
      (value): value is string => typeof value === "string" && value in delays,
    );
    if (toolName !== undefined) await sleep(delays[toolName]);
  };
};

const INPUT = ["alpha__t1", "alpha__t2", "alpha__t3", "alpha__t4"];
const STEP = 25;
const runs = (names: string[]): Array<Record<string, number>> => {
  const n = names.length;
  const by = (f: (i: number) => number) =>
    Object.fromEntries(
      names.map((name, i) => [name.replace("alpha__", ""), f(i) * STEP]),
    );
  return [
    by((i) => i),
    by((i) => n - 1 - i),
    by((i) => (i + 1) % n),
    by((i) => (i + 2) % n),
  ];
};

beforeEach(() => {
  clearOverrideCache();
  state.servers = [SRV];
  state.mounts = [{ namespaceUuid: NS, serverUuid: SRV.uuid }];
  state.namespaces = [{ uuid: NS, toolPolicy: "allow_all" }];
  state.mappings = [
    // t2 is renamed, so the output name is not the input name.
    {
      namespaceUuid: NS,
      serverUuid: SRV.uuid,
      toolName: "t2",
      status: "ACTIVE",
      overrideName: "renamed",
    },
  ];
  state.failOn = undefined;
  state.beforeQueryResult = undefined;
  queries.length = 0;
});

afterEach(() => {
  state.beforeQueryResult = undefined;
});

describe("the override list middleware", () => {
  it("keeps the input order however the lookups finish", async () => {
    for (const delays of runs(INPUT)) {
      clearOverrideCache();
      delayLookups(delays);

      const listed = await createToolOverridesListToolsMiddleware({
        cacheEnabled: false,
      })(async () => ({ tools: INPUT.map(tool) }))(
        { method: "tools/list", params: {} },
        context,
      );

      expect(listed.tools.map((t) => t.name)).toEqual([
        "alpha__t1",
        "alpha__renamed",
        "alpha__t3",
        "alpha__t4",
      ]);
    }
  });

  it("records the origins of a shared listed name in input order", async () => {
    // t1 keeps its own name and t2 is renamed to t1's name: one listed name,
    // two origins. Their order in the sink is read by the lean catalog, so it
    // must not depend on which lookup finished first.
    state.mappings = [
      {
        namespaceUuid: NS,
        serverUuid: SRV.uuid,
        toolName: "t2",
        status: "ACTIVE",
        overrideName: "t1",
      },
    ];
    for (const delays of runs(["alpha__t1", "alpha__t2"])) {
      clearOverrideCache();
      delayLookups(delays);
      const sink = new Map<string, string[]>();
      const callContext: ListingOriginsContext = {
        ...context,
        listingOrigins: sink,
      };

      await createToolOverridesListToolsMiddleware({ cacheEnabled: false })(
        async () => ({ tools: ["alpha__t1", "alpha__t2"].map(tool) }),
      )({ method: "tools/list", params: {} }, callContext);

      expect(sink.get("alpha__t1")).toEqual(["alpha__t1", "alpha__t2"]);
    }
  });
});
