/**
 * Regression test for `McpServerPool.getInstance()` honoring
 * MAX_TOTAL_CONNECTIONS / MAX_CONNECTIONS_PER_SERVER (JOB-1, fix-pool-cap-env).
 *
 * This is the test `mcp-server-pool-config.test.ts` (in the base branch,
 * PR #73) explicitly says it is NOT: those tests build the pool via the raw
 * private constructor, a path prod never runs. Prod builds the singleton
 * through `getInstance()` — confirmed by independent audit to hardcode
 * `100`/`5` and bypass the constructor's env-parse defaults entirely since
 * commit 806c2b2. THIS file exercises `getInstance()` itself, the actual
 * prod path, proving the two real incidents it traces to are fixed:
 *   - 2026-07-14 MAX_TOTAL_CONNECTIONS=400 cap raise (Umbrella-MCP-Server
 *     PR #406) — never took effect; pool silently kept enforcing 100.
 *   - 2026-05-08 MAX_CONNECTIONS_PER_SERVER=50 — never took effect; pool
 *     silently kept enforcing 5.
 *
 * `getInstance()` is a singleton, so honoring env across independent test
 * cases needs `McpServerPool.resetInstanceForTests()` (new, test-only) to
 * clear the cached instance between runs — otherwise every test after the
 * first would just get back the first test's already-constructed pool.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

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

describe("McpServerPool.getInstance — honors MAX_TOTAL_CONNECTIONS / MAX_CONNECTIONS_PER_SERVER", () => {
  const savedPerServer = process.env.MAX_CONNECTIONS_PER_SERVER;
  const savedTotal = process.env.MAX_TOTAL_CONNECTIONS;

  beforeEach(() => {
    delete process.env.MAX_CONNECTIONS_PER_SERVER;
    delete process.env.MAX_TOTAL_CONNECTIONS;
    // Defensive — no test in this file should leave a singleton behind, but
    // a prior failing run elsewhere in the same worker could have.
    McpServerPool.resetInstanceForTests();
  });

  afterEach(() => {
    // Stop the real intervals the singleton started, THEN clear the
    // reference — resetInstanceForTests() only clears the pointer, it
    // doesn't tear down timers/sessions (documented on the method itself).
    void McpServerPool.getInstance().cleanupAll();
    McpServerPool.resetInstanceForTests();
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

  it("THE incident regression: getInstance() reflects env when called with no arguments (the real prod call shape)", () => {
    process.env.MAX_TOTAL_CONNECTIONS = "400";
    process.env.MAX_CONNECTIONS_PER_SERVER = "50";

    // Zero-arg call — exactly how `export const mcpServerPool =
    // McpServerPool.getInstance();` calls it in this file, module-load time.
    const pool = McpServerPool.getInstance();

    expect(pool.getPoolConfig()).toEqual({
      maxConnectionsPerServer: 50,
      maxTotalConnections: 400,
    });
  });

  it("defaults to 100/5 through getInstance() when env is unset (unchanged behavior)", () => {
    const pool = McpServerPool.getInstance();
    expect(pool.getPoolConfig()).toEqual({
      maxConnectionsPerServer: 5,
      maxTotalConnections: 100,
    });
  });

  it("explicit arguments to getInstance() still win over env (the override path tests rely on)", () => {
    process.env.MAX_TOTAL_CONNECTIONS = "999";
    process.env.MAX_CONNECTIONS_PER_SERVER = "999";

    const pool = McpServerPool.getInstance(1, 77, 9);

    expect(pool.getPoolConfig()).toEqual({
      maxConnectionsPerServer: 9,
      maxTotalConnections: 77,
    });
  });

  it("resetInstanceForTests() actually clears the cache — the next getInstance() constructs a new instance", () => {
    const first = McpServerPool.getInstance();
    // Without a reset, getInstance() must return the SAME cached object —
    // proving the singleton pattern itself is untouched by this fix.
    expect(McpServerPool.getInstance()).toBe(first);

    void first.cleanupAll();
    McpServerPool.resetInstanceForTests();

    process.env.MAX_TOTAL_CONNECTIONS = "250";
    const second = McpServerPool.getInstance();
    expect(second).not.toBe(first);
    expect(second.getPoolConfig().maxTotalConnections).toBe(250);
  });
});
