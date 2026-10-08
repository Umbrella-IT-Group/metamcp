/**
 * Test for `McpServerPool.getPoolStatus()`'s `pending` field (Track C2
 * fix-round item A4 — coordinator audit follow-up, 2026-07-14).
 *
 * `/health/upstream`'s `pool.total` previously reported `idle + active`,
 * omitting in-flight creations even though admission reserved capacity for
 * them. The count now includes active connects and detached clients awaiting
 * close, and excludes idle-creation guards that have not reserved a connect.
 * idle + active + pending matches physical admission accounting.
 */

import { beforeEach, describe, expect, it, vi } from "vitest";

// Mirror the heavy-import stubs used across this directory's pool tests so
// importing the module (singleton built at load time) needs no postgres.
vi.mock("./client", () => ({
  connectMetaMcpClient: vi.fn(),
}));
vi.mock("../config.service", () => ({
  configService: {
    getSessionLifetime: vi.fn().mockResolvedValue(null),
    getMaxConnections: vi.fn().mockResolvedValue(100),
    getMaxConnectionsPerServer: vi.fn().mockResolvedValue(5),
    getMcpTimeout: vi.fn().mockResolvedValue(60000),
    getMcpMaxTotalTimeout: vi.fn().mockResolvedValue(60000),
    getMcpResetTimeoutOnProgress: vi.fn().mockResolvedValue(true),
    getMaxAttempts: vi.fn().mockResolvedValue(3),
  },
}));
vi.mock("../../db/repositories/mcp-servers.repo", () => ({
  mcpServersRepository: {},
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

import { McpServerPool } from "./mcp-server-pool";

// Bypass the private constructor — same cast pattern as the sibling pool
// test files in this directory.
const PoolConstructor = McpServerPool as unknown as new () => McpServerPool;

describe("McpServerPool.getPoolStatus — pending count", () => {
  let pool: McpServerPool;
  let internals: {
    creatingIdleSessions: Set<string>;
    pendingConnections: Record<string, number>;
  };

  beforeEach(() => {
    pool = new PoolConstructor();
    internals = pool as unknown as typeof internals;
  });

  it("reports 0 pending with no in-flight idle creations", () => {
    expect(pool.getPoolStatus().pending).toBe(0);
    void pool.cleanupAll();
  });

  it("reports actual connection reservations, independently of idle guards", () => {
    internals.creatingIdleSessions.add("server-1");
    internals.creatingIdleSessions.add("server-2");
    expect(pool.getPoolStatus().pending).toBe(0);
    internals.pendingConnections = { "server-1": 2, "server-3": 1 };
    expect(pool.getPoolStatus().pending).toBe(3);
    expect(pool.getPoolStatus().perServerCounts).toEqual({
      "server-1": 2,
      "server-3": 1,
    });
    internals.pendingConnections = {};
    void pool.cleanupAll();
  });
});
