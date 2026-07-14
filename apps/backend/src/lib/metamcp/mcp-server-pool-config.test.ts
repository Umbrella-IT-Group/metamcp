/**
 * Tests for `McpServerPool.getPoolConfig()` — the read-only getter that
 * feeds /health/upstream its EFFECTIVE connection caps (Track C2, defect 3).
 *
 * The health endpoint previously reported only the per-server cap and never
 * the global cap, and an operator debugging saturation on 2026-07-14 could
 * not see MAX_TOTAL_CONNECTIONS at all. getPoolConfig() surfaces both, read
 * from the pool's own fields — the single source of truth — so the payload
 * can never drift from a re-parse with different defaults.
 *
 * These tests exercise the CONSTRUCTOR's env-parse (the "same source" the
 * getter reports). NOTE: the exported singleton is built via getInstance(),
 * which currently passes hardcoded caps and bypasses this env-parse — that
 * discrepancy is a separate pool-lane defect, out of scope here.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Mirror the heavy-import stubs from mcp-server-pool.test.ts so importing the
// module (which builds a singleton at load time) needs no postgres / upstream.
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

// Bypass the private constructor. Zero-arg call makes the constructor's
// env-parsing defaults evaluate — the path we want to verify.
const PoolConstructor = McpServerPool as unknown as new () => McpServerPool;

describe("McpServerPool.getPoolConfig — truthful caps for /health/upstream", () => {
  let pool: McpServerPool | undefined;
  const savedPerServer = process.env.MAX_CONNECTIONS_PER_SERVER;
  const savedTotal = process.env.MAX_TOTAL_CONNECTIONS;

  beforeEach(() => {
    delete process.env.MAX_CONNECTIONS_PER_SERVER;
    delete process.env.MAX_TOTAL_CONNECTIONS;
  });

  afterEach(() => {
    // Stop the real intervals this pool started so they can't fire mid-suite.
    if (pool) void pool.cleanupAll();
    pool = undefined;
    if (savedPerServer === undefined) {
      delete process.env.MAX_CONNECTIONS_PER_SERVER;
    } else {
      process.env.MAX_CONNECTIONS_PER_SERVER = savedPerServer;
    }
    if (savedTotal === undefined) {
      delete process.env.MAX_TOTAL_CONNECTIONS;
    } else {
      process.env.MAX_TOTAL_CONNECTIONS = savedTotal;
    }
  });

  it("reports the fork defaults when env is unset (5 per server, 100 total)", () => {
    pool = new PoolConstructor();
    expect(pool.getPoolConfig()).toEqual({
      maxConnectionsPerServer: 5,
      maxTotalConnections: 100,
    });
  });

  it("surfaces env-set values (the prod complaint: env sets 50, payload must reflect it)", () => {
    process.env.MAX_CONNECTIONS_PER_SERVER = "50";
    process.env.MAX_TOTAL_CONNECTIONS = "250";
    pool = new PoolConstructor();
    expect(pool.getPoolConfig()).toEqual({
      maxConnectionsPerServer: 50,
      maxTotalConnections: 250,
    });
  });

  it("returns a plain read-only snapshot (no mutation of pool state)", () => {
    pool = new PoolConstructor();
    const a = pool.getPoolConfig();
    const b = pool.getPoolConfig();
    expect(a).toEqual(b);
  });
});
