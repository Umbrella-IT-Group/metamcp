/**
 * The namespace tool filter hands a listing back in the order it received it
 * (issue #278).
 *
 * Each tool's status is looked up concurrently, and the filter used to append
 * a tool to its output when its own lookup finished, so a listing the proxy
 * had already sorted came out in lookup-completion order, which changes from
 * call to call. Here every lookup is delayed by a chosen amount, in forward,
 * reverse and rotated order, and the served tools must keep the input order
 * each time, with the inactive one left out.
 *
 * Oracle: the input order minus the tool the rows mark INACTIVE.
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

const { createFilterListToolsMiddleware, clearFilterCache } = await import(
  "./filter-tools.functional"
);

const NS = "ns1";
const SRV = { uuid: "srv-uuid", name: "srv" };
const context = { namespaceUuid: NS, sessionId: "sess1" };

const toolNamed = (name: string) => ({
  name,
  description: "",
  inputSchema: { type: "object" as const },
});

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

const INPUT = ["srv__a", "srv__b", "srv__c", "srv__d", "srv__e"];
const STEP = 25;

/** Delay each status lookup by the amount set for the tool it is for. */
const delayLookups = (delays: Record<string, number>) => {
  state.beforeQueryResult = async (query) => {
    if (query.table !== "mappings") return;
    const toolName = Object.values(query.where).find(
      (value): value is string => typeof value === "string" && value in delays,
    );
    if (toolName !== undefined) await sleep(delays[toolName]);
  };
};

const runs = (): Array<Record<string, number>> => {
  const n = INPUT.length;
  const by = (f: (i: number) => number) =>
    Object.fromEntries(
      INPUT.map((name, i) => [name.replace("srv__", ""), f(i) * STEP]),
    );
  return [
    by((i) => i),
    by((i) => n - 1 - i),
    by((i) => (i + 2) % n),
    by((i) => (i * 3) % n),
  ];
};

beforeEach(() => {
  clearFilterCache();
  state.namespaces = [{ uuid: NS, toolPolicy: "allow_all" }];
  state.servers = [SRV];
  state.mounts = [{ namespaceUuid: NS, serverUuid: SRV.uuid }];
  state.mappings = [
    {
      namespaceUuid: NS,
      serverUuid: SRV.uuid,
      toolName: "c",
      status: "INACTIVE",
    },
  ];
  state.failOn = undefined;
  state.beforeQueryResult = undefined;
  queries.length = 0;
});

afterEach(() => {
  state.beforeQueryResult = undefined;
});

describe("the policy filter on a listing", () => {
  it("keeps the input order of the tools it serves however the lookups finish", async () => {
    for (const delays of runs()) {
      clearFilterCache();
      delayLookups(delays);

      const { tools } = await createFilterListToolsMiddleware({
        cacheEnabled: false,
      })(async () => ({ tools: INPUT.map(toolNamed) }))(
        { method: "tools/list", params: {} },
        context,
      );

      expect(tools.map((t) => t.name)).toEqual([
        "srv__a",
        "srv__b",
        "srv__d",
        "srv__e",
      ]);
    }
  });
});
