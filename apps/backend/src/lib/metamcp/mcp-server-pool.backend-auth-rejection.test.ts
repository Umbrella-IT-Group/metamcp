/**
 * Pool state for a backend that rejected the gateway's credentials at connect,
 * and the periodic sweep's use of the shared pagination guard.
 *
 * Oracles: the state's lifecycle is the connect-failure stamp's (set by the
 * connect result, cleared by the next successful connect, pruned with the
 * registry; mcp-server-pool.test.ts pins the stamp), and the sweep's stop
 * rules are the existing sweep tests' (a constant cursor stops after two
 * requests, fifty fresh cursors stop at the cap), now reported once per
 * server per window instead of silently.
 */
import { inspect } from "node:util";

import { StreamableHTTPError } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { findAll } = vi.hoisted(() => ({ findAll: vi.fn() }));

vi.mock("./client", () => ({ connectMetaMcpClient: vi.fn() }));
vi.mock("../config.service", () => ({
  configService: {
    getSessionLifetime: vi.fn().mockResolvedValue(null),
    getMaxConnections: vi.fn().mockResolvedValue(100),
    getMaxConnectionsPerServer: vi.fn().mockResolvedValue(5),
    getMcpTimeout: vi.fn().mockResolvedValue(60000),
    getMcpMaxTotalTimeout: vi.fn().mockResolvedValue(600000),
    getMcpResetTimeoutOnProgress: vi.fn().mockResolvedValue(true),
    getMaxAttempts: vi.fn().mockResolvedValue(3),
  },
}));
vi.mock("../../db/repositories/mcp-servers.repo", () => ({
  mcpServersRepository: { findAll },
}));
vi.mock("./server-error-tracker", () => ({
  serverErrorTracker: {
    recordServerCrash: vi.fn(),
    resetServerAttempts: vi.fn(),
    markSuccess: vi.fn(),
    getServerAttempts: vi.fn().mockReturnValue(0),
    isServerInErrorState: vi.fn().mockResolvedValue(false),
    resetServerErrorState: vi.fn(),
  },
}));

import logger from "@/utils/logger";

import { connectMetaMcpClient } from "./client";
import { metamcpLogStore } from "./log-store";
import { McpServerPool } from "./mcp-server-pool";
import { resetToolsListTruncationReportsForTesting } from "./paginate-tools-list";
import { toolsSyncCache } from "./tools-sync-cache";

const PoolConstructor = McpServerPool as unknown as new () => McpServerPool;
const connectMock = vi.mocked(connectMetaMcpClient);

type Internals = {
  backendAuthRejections: Record<string, { at: number; status: 401 | 403 }>;
  lastConnectFailureAt: Record<string, number>;
  serverParamsCache: Record<string, unknown>;
  activeSessions: Record<string, Record<string, unknown>>;
  idleSessions: Record<string, unknown>;
  createNewConnection: (params: {
    uuid: string;
    name: string;
  }) => Promise<unknown>;
  checkIdleSessionHealth: () => Promise<void>;
  sweepToolDefinitions: () => Promise<void>;
  toolsSweepLastHash: Record<string, string>;
};

let pool: McpServerPool;
let internals: Internals;

beforeEach(() => {
  toolsSyncCache.clear();
  resetToolsListTruncationReportsForTesting();
  connectMock.mockReset();
  findAll.mockReset();
  pool = new PoolConstructor();
  internals = pool as never;
  internals.activeSessions = {};
  internals.idleSessions = {};
  internals.serverParamsCache = {};
});

afterEach(() => {
  vi.restoreAllMocks();
  void pool.cleanupAll();
});

describe("backend auth rejection state", () => {
  const rejectOnce = (status: 401 | 403) =>
    connectMock.mockImplementation(async (_params, _crash, _drop, deps) => {
      deps?.onBackendAuthRejected?.({ status });
      return undefined;
    });

  it("is set by the connect hook and surfaced by getPoolStatus", async () => {
    rejectOnce(401);

    await internals.createNewConnection({ uuid: "srv-1", name: "ninja" });

    const record = pool.getPoolStatus().backendAuthRejections?.["srv-1"];
    expect(record).toMatchObject({ status: 401 });
    expect(record?.at).toBeTypeOf("number");
    // It rides with the connect-failure stamp that already makes the server
    // read unreachable.
    expect(internals.lastConnectFailureAt["srv-1"]).toBeTypeOf("number");
  });

  it("is cleared by the next successful connect", async () => {
    rejectOnce(403);
    await internals.createNewConnection({ uuid: "srv-1", name: "ninja" });
    connectMock.mockResolvedValue({ client: {}, cleanup: vi.fn() } as never);

    await internals.createNewConnection({ uuid: "srv-1", name: "ninja" });

    expect(pool.getPoolStatus().backendAuthRejections).toEqual({});
  });

  it("is not set by an ordinary failed connect", async () => {
    connectMock.mockResolvedValue(undefined);

    await internals.createNewConnection({ uuid: "srv-1", name: "ninja" });

    expect(pool.getPoolStatus().backendAuthRejections).toEqual({});
  });

  it("is pruned with the registry", async () => {
    rejectOnce(401);
    await internals.createNewConnection({ uuid: "srv-gone", name: "ninja" });
    internals.serverParamsCache["srv-gone"] = { uuid: "srv-gone" };
    findAll.mockResolvedValue([]);

    await internals.checkIdleSessionHealth();

    expect(pool.getPoolStatus().backendAuthRejections).toEqual({});
  });

  it("getPoolStatus returns a copy, not the live record", async () => {
    rejectOnce(401);
    await internals.createNewConnection({ uuid: "srv-1", name: "ninja" });

    const copy = pool.getPoolStatus().backendAuthRejections ?? {};
    delete copy["srv-1"];

    expect(internals.backendAuthRejections["srv-1"]).toBeDefined();
  });
});

describe("tool-definition sweep pagination guard", () => {
  const stuckClient = () => ({
    cleanup: vi.fn(),
    listChangedSubscribers: new Set(),
    client: {
      request: vi.fn().mockResolvedValue({
        tools: [{ name: "stuck", description: "d", inputSchema: {} }],
        nextCursor: "same-cursor",
      }),
    },
  });

  it("stops on a repeated cursor and reports it once per window as a server event", async () => {
    const record = vi
      .spyOn(metamcpLogStore, "record")
      .mockImplementation(() => undefined);
    const client = stuckClient();
    internals.activeSessions["session-A"] = { "server-1": client };
    internals.serverParamsCache["server-1"] = { name: "ninja" };

    await internals.sweepToolDefinitions();
    await internals.sweepToolDefinitions();
    await internals.sweepToolDefinitions();

    expect(client.client.request).toHaveBeenCalledTimes(6); // 2 per sweep
    const truncations = record.mock.calls
      .map(([entry]) => entry)
      .filter((entry) => entry.message.startsWith("Tool listing for server"));
    expect(truncations).toHaveLength(1);
    expect(truncations[0]).toMatchObject({
      category: "server",
      level: "warn",
      serverName: "ninja",
      serverUuid: "server-1",
    });
    expect(truncations[0].message).toContain("tool-definition sweep");
  });

  it("hashes each tool once when every page carries an empty cursor", async () => {
    const record = vi
      .spyOn(metamcpLogStore, "record")
      .mockImplementation(() => undefined);
    const tools = [
      { name: "a", description: "d", inputSchema: {} },
      { name: "b", description: "d", inputSchema: {} },
    ];
    const client = stuckClient();
    client.client.request.mockResolvedValue({ tools, nextCursor: "" });
    internals.activeSessions["session-A"] = { "server-1": client };
    internals.serverParamsCache["server-1"] = { name: "ninja" };

    await internals.sweepToolDefinitions();

    // The proxy serves a, b once; the sweep must hash that same set, or every
    // tick would read a backend with this shape as changed.
    expect(client.client.request).toHaveBeenCalledTimes(2);
    expect(internals.toolsSweepLastHash["server-1"]).toBe(
      toolsSyncCache.hashTools(tools),
    );
    expect(
      record.mock.calls.filter(([entry]) =>
        entry.message.startsWith("Tool listing for server"),
      ),
    ).toHaveLength(1);
  });

  it.each([401, 403] as const)(
    "keeps a refused sweep's HTTP %s body out of debug logs",
    async (status) => {
      const body = "private-sweep-response";
      const debug = vi
        .spyOn(logger, "debug")
        .mockImplementation(() => undefined);
      const client = stuckClient();
      client.client.request.mockRejectedValue(
        new StreamableHTTPError(status, `Error POSTing to endpoint: ${body}`),
      );
      internals.activeSessions["session-A"] = { "server-1": client };

      await internals.sweepToolDefinitions();

      expect(client.client.request).toHaveBeenCalledTimes(1);
      expect(inspect(debug.mock.calls)).toContain(`HTTP ${status}`);
      expect(inspect(debug.mock.calls)).not.toContain(body);
    },
  );

  it.each([401, 403] as const)(
    "keeps a refused re-notify probe's HTTP %s body out of the log",
    async (status) => {
      const body = "private-probe-response";
      const info = vi.spyOn(logger, "info").mockImplementation(() => undefined);
      const client = stuckClient();
      client.client.request.mockRejectedValue(
        new StreamableHTTPError(status, `Error POSTing to endpoint: ${body}`),
      );
      internals.idleSessions["server-1"] = client;

      await expect(
        pool.probeServerTools({ uuid: "server-1", name: "ninja" } as never),
      ).resolves.toBe(false);

      expect(inspect(info.mock.calls)).toContain(`HTTP ${status}`);
      expect(inspect(info.mock.calls)).not.toContain(body);
    },
  );

  it("does not report a listing of exactly the page cap that ends on its own", async () => {
    const record = vi
      .spyOn(metamcpLogStore, "record")
      .mockImplementation(() => undefined);
    // The sweep used to warn "hit the 50-page cap" here even though the
    // backend had ended its listing on page 50.
    const warn = vi.spyOn(logger, "warn").mockImplementation(() => undefined);
    let page = 0;
    const client = stuckClient();
    client.client.request.mockImplementation(async () => {
      page += 1;
      return page < 50
        ? { tools: [], nextCursor: `page-${page}` }
        : { tools: [] };
    });
    internals.activeSessions["session-A"] = { "server-1": client };

    await internals.sweepToolDefinitions();

    expect(client.client.request).toHaveBeenCalledTimes(50);
    expect(record).not.toHaveBeenCalled();
    expect(warn).not.toHaveBeenCalled();
  });
});
