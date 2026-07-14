/**
 * Test for `McpServerPool.getPoolStatus()`'s `pending` field (Track C2
 * fix-round item A4 — coordinator audit follow-up, 2026-07-14).
 *
 * `/health/upstream`'s `pool.total` previously reported `idle + active`,
 * omitting in-flight idle-session creations (`creatingIdleSessions`) even
 * though `getTotalConnectionCount()` — the function the MAX_TOTAL_CONNECTIONS
 * cap check actually calls — is `idle + active + pending`. A pool sitting at
 * the cap with several creations in flight would read as having headroom it
 * doesn't have. `getPoolStatus()` now surfaces the same count so the health
 * payload's `total` can match the cap logic exactly (wired in index.ts).
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
  let internals: { creatingIdleSessions: Set<string> };

  beforeEach(() => {
    pool = new PoolConstructor();
    internals = pool as unknown as { creatingIdleSessions: Set<string> };
  });

  it("reports 0 pending with no in-flight idle creations", () => {
    expect(pool.getPoolStatus().pending).toBe(0);
    void pool.cleanupAll();
  });

  it("reports pending == creatingIdleSessions.size (the same count the cap check uses)", () => {
    internals.creatingIdleSessions.add("server-1");
    internals.creatingIdleSessions.add("server-2");
    expect(pool.getPoolStatus().pending).toBe(2);
    void pool.cleanupAll();
  });
});
