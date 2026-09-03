/**
 * Namespace tool-status enforcement fails CLOSED (operator decision
 * 2026-09-02).
 *
 * Tool enable/disable is namespace curation, and it used to fail OPEN: a DB
 * error or an unresolved server name served (list side) or allowed (call side)
 * the tool, the opposite of the access-group gate. These tests pin the flipped
 * direction: on an unresolved server or a DB error the tool is now excluded
 * from a listing and denied on a call. Each fail-closed case below is written
 * so it would FAIL against the previous fail-open behavior.
 *
 * The db module is mocked with a chain stub routed by call shape: a bare
 * `.where()` is the getServerUuidByName lookup, an `.innerJoin(...).where()` is
 * the getToolStatus lookup (same convention as consumer-identity-resolver's
 * table-routed stub next door).
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { dbMock, fixtures } = vi.hoisted(() => {
  const fixtures = {
    serverRows: [] as Record<string, unknown>[],
    statusRows: [] as Record<string, unknown>[],
    serverError: false,
    statusError: false,
  };

  const dbMock = {
    select: vi.fn(() => ({
      from: () => ({
        // getServerUuidByName: from(mcpServers).where()
        where: () =>
          fixtures.serverError
            ? Promise.reject(new Error("db down"))
            : Promise.resolve(fixtures.serverRows),
        // getToolStatus: from(namespaceToolMappings).innerJoin(tools).where()
        innerJoin: () => ({
          where: () =>
            fixtures.statusError
              ? Promise.reject(new Error("db down"))
              : Promise.resolve(fixtures.statusRows),
        }),
      }),
    })),
  };

  return { dbMock, fixtures };
});

vi.mock("../../../db/index", () => ({ db: dbMock }));
vi.mock("@/utils/logger", () => ({
  default: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

const {
  createFilterListToolsMiddleware,
  createFilterCallToolMiddleware,
  clearFilterCache,
} = await import("./filter-tools.functional");

const TOOL_NAME = "srv__mytool";
const context = { namespaceUuid: "ns1", sessionId: "sess1" };
const listRequest = { method: "tools/list" as const, params: {} };
const callRequest = {
  method: "tools/call" as const,
  params: { name: TOOL_NAME, arguments: {} },
};
const tool = {
  name: TOOL_NAME,
  description: "",
  inputSchema: { type: "object" as const },
};

const listResult = () =>
  createFilterListToolsMiddleware({ cacheEnabled: false })(async () => ({
    tools: [tool],
  }))(listRequest, context);

const callResult = () => {
  const handler = vi.fn(async () => ({
    content: [{ type: "text" as const, text: "ok" }],
  }));
  const mw = createFilterCallToolMiddleware({ cacheEnabled: false });
  return { handler, run: () => mw(handler)(callRequest, context) };
};

beforeEach(() => {
  vi.clearAllMocks();
  fixtures.serverRows = [];
  fixtures.statusRows = [];
  fixtures.serverError = false;
  fixtures.statusError = false;
  clearFilterCache();
});

afterEach(() => {
  clearFilterCache();
});

describe("filterActiveTools: list side (unchanged happy paths)", () => {
  it("includes a tool whose mapping is ACTIVE", async () => {
    fixtures.serverRows = [{ uuid: "srv-uuid" }];
    fixtures.statusRows = [{ status: "ACTIVE" }];
    const { tools } = await listResult();
    expect(tools).toHaveLength(1);
  });

  it("includes a tool that has no mapping row (active by default)", async () => {
    fixtures.serverRows = [{ uuid: "srv-uuid" }];
    fixtures.statusRows = [];
    const { tools } = await listResult();
    expect(tools).toHaveLength(1);
  });

  it("excludes a tool whose mapping is INACTIVE", async () => {
    fixtures.serverRows = [{ uuid: "srv-uuid" }];
    fixtures.statusRows = [{ status: "INACTIVE" }];
    const { tools } = await listResult();
    expect(tools).toHaveLength(0);
  });
});

describe("filterActiveTools: list side fails CLOSED", () => {
  it("excludes the tool when the server name does not resolve", async () => {
    fixtures.serverRows = []; // getServerUuidByName -> null
    const { tools } = await listResult();
    // Fail-open would have served it; fail-closed drops it.
    expect(tools).toHaveLength(0);
  });

  it("excludes the tool when the tool-status query errors", async () => {
    fixtures.serverRows = [{ uuid: "srv-uuid" }];
    fixtures.statusError = true; // getToolStatus throws
    const { tools } = await listResult();
    expect(tools).toHaveLength(0);
  });
});

describe("isToolAllowed: call side fails CLOSED", () => {
  it("allows the call when the mapping is ACTIVE", async () => {
    fixtures.serverRows = [{ uuid: "srv-uuid" }];
    fixtures.statusRows = [{ status: "ACTIVE" }];
    const { handler, run } = callResult();
    const result = await run();
    expect(handler).toHaveBeenCalledTimes(1);
    expect(result.isError).toBeUndefined();
  });

  it("denies the call when the mapping is INACTIVE", async () => {
    fixtures.serverRows = [{ uuid: "srv-uuid" }];
    fixtures.statusRows = [{ status: "INACTIVE" }];
    const { handler, run } = callResult();
    const result = await run();
    expect(handler).not.toHaveBeenCalled();
    expect(result.isError).toBe(true);
  });

  it("denies the call when the server name does not resolve", async () => {
    fixtures.serverRows = []; // getServerUuidByName -> null
    const { handler, run } = callResult();
    const result = await run();
    // Fail-open would have skipped the check and run the handler.
    expect(handler).not.toHaveBeenCalled();
    expect(result.isError).toBe(true);
  });

  it("denies the call when the tool-status query errors", async () => {
    fixtures.serverRows = [{ uuid: "srv-uuid" }];
    fixtures.statusError = true; // getToolStatus throws
    const { handler, run } = callResult();
    const result = await run();
    expect(handler).not.toHaveBeenCalled();
    expect(result.isError).toBe(true);
  });
});
