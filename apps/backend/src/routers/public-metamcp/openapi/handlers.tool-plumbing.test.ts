/**
 * The OpenAPI bridge's tools/call timeout behaviour and tools/list paging,
 * against real SDK peers (a real `Client` and `Server` over
 * `InMemoryTransport`), never an extended `client.request` fake.
 *
 * What it pins, and the oracles:
 *   - the one reset-on-progress flag works on the bridge as on the MCP
 *     surface: the SDK arms it only through a registered progress handler
 *     (shared/protocol.js), so the bridge registers a no-op one;
 *   - a call that breaches the total cap also cancels the backend (the SDK
 *     sends no cancel on that path); an HTTP disconnect is NOT wired to a
 *     cancel, so a call with nothing cancelling it runs to completion;
 *   - the listing follows `nextCursor` to the last page (MCP spec,
 *     server/utilities/pagination) and stops on a repeated cursor instead of
 *     hanging, as the MCP-surface listing does.
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  CallToolRequestSchema,
  ErrorCode,
  ListToolsRequestSchema,
  McpError,
} from "@modelcontextprotocol/sdk/types.js";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  makeBackend,
  OK,
  sendProgress,
  sleep,
} from "../../../lib/metamcp/tool-call-harness.test-util";

const { getSessionMock, config } = vi.hoisted(() => ({
  getSessionMock: vi.fn(),
  config: { timeoutMs: 60_000, maxTotalMs: 600_000, resetOnProgress: true },
}));

vi.mock("../../../db", () => ({ db: {} }));
vi.mock("../../../db/schema", () => ({}));
vi.mock("@/utils/logger", () => ({
  default: { error: vi.fn(), warn: vi.fn(), info: vi.fn(), debug: vi.fn() },
}));
vi.mock("../../../lib/config.service", () => ({
  configService: {
    getMcpResetTimeoutOnProgress: async () => config.resetOnProgress,
    getMcpTimeout: async () => config.timeoutMs,
    getMcpMaxTotalTimeout: async () => config.maxTotalMs,
  },
}));
vi.mock("../../../lib/metamcp/fetch-metamcp", () => ({
  getMcpServers: vi.fn(async () => ({
    "server-autotask": { name: "autotask" },
  })),
}));
vi.mock("../../../lib/metamcp/mcp-server-pool", () => ({
  mcpServerPool: {
    getSession: getSessionMock,
    invalidateServerConnection: vi.fn(),
    isPooledClient: () => true,
  },
}));
vi.mock(
  "../../../lib/metamcp/metamcp-middleware/filter-tools.functional",
  () => ({
    createFilterCallToolMiddleware: () => (next: unknown) => next,
    createFilterListToolsMiddleware: () => (next: unknown) => next,
  }),
);
vi.mock(
  "../../../lib/metamcp/metamcp-middleware/tool-overrides.functional",
  () => ({
    createToolOverridesCallToolMiddleware: () => (next: unknown) => next,
    createToolOverridesListToolsMiddleware: () => (next: unknown) => next,
  }),
);

import { metamcpLogStore } from "../../../lib/metamcp/log-store";
import { resetToolsListTruncationReportsForTesting } from "../../../lib/metamcp/paginate-tools-list";
import {
  createOriginalCallToolHandler,
  createOriginalListToolsHandler,
  resetBridgeAuditSchemasForTesting,
} from "./handlers";

const context = { namespaceUuid: "ns-1", sessionId: "openapi_ns-1" };
const cleanups: Array<() => Promise<unknown>> = [];
const envBackup: Record<string, string | undefined> = {};

function setEnv(name: string, value: string): void {
  if (!(name in envBackup)) envBackup[name] = process.env[name];
  process.env[name] = value;
}

const callRequest = {
  method: "tools/call" as const,
  params: { name: "autotask__slow_job", arguments: {} },
};

async function backend(onCall: Parameters<typeof makeBackend>[0]) {
  const made = await makeBackend(onCall, {
    toolName: "slow_job",
    serverName: "autotask",
  });
  cleanups.push(() => made.close());
  getSessionMock.mockResolvedValue(made.session);
  return made;
}

/** A backend whose tools/list pages by `pages[cursor ?? ""]`. */
async function pagedBackend(
  pages: Record<string, { tools: string[]; next?: string }>,
) {
  let requests = 0;
  const server = new Server(
    { name: "autotask", version: "1.0.0" },
    { capabilities: { tools: {} } },
  );
  server.setRequestHandler(ListToolsRequestSchema, async (request) => {
    requests += 1;
    // Tripwire: after 200 requests the listing simply ends, so an unguarded
    // loop finishes and fails the request-count assertions instead of hanging.
    if (requests > 200) return { tools: [] };
    const page = pages[request.params?.cursor ?? ""];
    return {
      tools: page.tools.map((name) => ({
        name,
        inputSchema: { type: "object" as const },
      })),
      nextCursor: page.next,
    };
  });
  server.setRequestHandler(CallToolRequestSchema, async () => OK);
  const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
  await server.connect(serverSide);
  const client = new Client({ name: "metamcp", version: "1.0.0" });
  await client.connect(clientSide);
  cleanups.push(() => client.close());
  getSessionMock.mockResolvedValue({
    client,
    cleanup: () => client.close(),
    listChangedSubscribers: new Set(),
  });
  return { requests: () => requests };
}

beforeEach(() => {
  getSessionMock.mockReset();
  config.timeoutMs = 60_000;
  config.maxTotalMs = 600_000;
  config.resetOnProgress = true;
  resetBridgeAuditSchemasForTesting();
  resetToolsListTruncationReportsForTesting();
});

afterEach(async () => {
  vi.useRealTimers();
  vi.restoreAllMocks();
  while (cleanups.length > 0) {
    await cleanups
      .pop()?.()
      .catch(() => undefined);
  }
  for (const [name, value] of Object.entries(envBackup)) {
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
    delete envBackup[name];
  }
});

/** A backend that reports progress at 400 ms and 800 ms, then needs `finishAt`. */
const progressing = (finishAt: number, lastProgress?: number) =>
  backend(async (extra, info) => {
    await sleep(400, info.signal);
    await sendProgress(extra, 1);
    await sleep(400, info.signal);
    await sendProgress(extra, 2);
    if (lastProgress !== undefined) {
      await sleep(lastProgress - 800, info.signal);
      await sendProgress(extra, 3);
      await sleep(60_000, info.signal);
      return OK;
    }
    await sleep(finishAt - 800, info.signal);
    return OK;
  });

const rejectionOf = async (promise: Promise<unknown>): Promise<McpError> => {
  try {
    await promise;
  } catch (error) {
    return error as McpError;
  }
  throw new Error("expected the call to reject");
};

describe("OpenAPI bridge tools/call: reset on progress and the total cap", () => {
  it("lets a backend that reports progress outlive the per-request timeout", async () => {
    vi.useFakeTimers();
    config.timeoutMs = 500;
    const target = await progressing(1_200);

    const result = createOriginalCallToolHandler()(callRequest, context);
    await vi.advanceTimersByTimeAsync(1_300);

    await expect(result).resolves.toMatchObject({ content: OK.content });
    // The backend was handed the SDK's own numeric token (a handler is
    // registered), and nothing cancelled the call.
    expect(typeof target.calls[0].token).toBe("number");
    expect(target.calls[0].signal.aborted).toBe(false);
  });

  it("cancels the backend when the total cap ends the call", async () => {
    vi.useFakeTimers();
    config.timeoutMs = 500;
    config.maxTotalMs = 1_000;
    const target = await progressing(0, 1_100);

    const outcome = rejectionOf(
      createOriginalCallToolHandler()(callRequest, context),
    );
    await vi.advanceTimersByTimeAsync(1_200);
    const error = await outcome;
    for (let i = 0; i < 100; i += 1) await Promise.resolve();

    expect(error.code).toBe(ErrorCode.RequestTimeout);
    expect(error.message).toContain("Maximum total timeout exceeded");
    expect(target.calls[0].signal.aborted).toBe(true);
  });

  it("MCP_TOOL_CALL_PROGRESS=off: the request is as before, no reset", async () => {
    vi.useFakeTimers();
    setEnv("MCP_TOOL_CALL_PROGRESS", "off");
    config.timeoutMs = 500;
    const target = await progressing(1_200);

    const outcome = rejectionOf(
      createOriginalCallToolHandler()(callRequest, context),
    );
    await vi.advanceTimersByTimeAsync(600);
    const error = await outcome;

    expect(error.message).toContain("Request timed out");
    expect(target.calls[0].token).toBeUndefined();
  });

  it("MCP_TOOL_CALL_CANCEL=off: a cap breach sends the backend no cancel", async () => {
    vi.useFakeTimers();
    setEnv("MCP_TOOL_CALL_CANCEL", "off");
    config.timeoutMs = 500;
    config.maxTotalMs = 1_000;
    const target = await progressing(0, 1_100);

    const outcome = rejectionOf(
      createOriginalCallToolHandler()(callRequest, context),
    );
    await vi.advanceTimersByTimeAsync(1_200);
    const error = await outcome;
    for (let i = 0; i < 100; i += 1) await Promise.resolve();

    expect(error.message).toContain("Maximum total timeout exceeded");
    expect(target.calls[0].signal.aborted).toBe(false);
  });
});

describe("OpenAPI bridge tools/list paging", () => {
  const list = () =>
    createOriginalListToolsHandler()(
      { method: "tools/list", params: {} },
      context,
    );

  it("lists every page of a paginated backend, not only the first", async () => {
    await pagedBackend({
      "": { tools: ["a"], next: "p2" },
      p2: { tools: ["b"] },
    });

    const names = (await list()).tools.map((t) => t.name).sort();

    expect(names).toEqual(["autotask__a", "autotask__b"]);
  });

  it("stops on a repeated cursor, serves what it gathered, and reports it", async () => {
    const record = vi
      .spyOn(metamcpLogStore, "record")
      .mockImplementation(() => undefined);
    const target = await pagedBackend({
      "": { tools: ["a"], next: "A" },
      A: { tools: ["b"], next: "B" },
      B: { tools: ["c"], next: "A" },
    });

    const names = (await list()).tools.map((t) => t.name).sort();

    expect(names).toEqual(["autotask__a", "autotask__b", "autotask__c"]);
    expect(target.requests()).toBeLessThanOrEqual(4);
    const truncations = record.mock.calls
      .map(([entry]) => entry)
      .filter((entry) => entry.message.startsWith("Tool listing for server"));
    expect(truncations).toHaveLength(1);
    expect(truncations[0].category).toBe("server");
  });
});
