/**
 * Unit tests for proactive capacity eviction in `McpServerPool.cleanupExpiredSessions`.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

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
import { configService } from "../config.service";

type FakeClient = {
  cleanup: () => Promise<void>;
  closed: boolean;
  listChangedSubscribers: Set<() => void | Promise<void>>;
};

interface TestablePool {
  idleSessions: Record<string, FakeClient>;
  activeSessions: Record<string, Record<string, FakeClient>>;
  sessionToServers: Record<string, Set<string>>;
  sessionTimestamps: Record<string, number>;
  cleanupTimer: NodeJS.Timeout;
  healthCheckTimer: NodeJS.Timeout;
  toolsSweepTimer: NodeJS.Timeout;
  getTotalConnectionCount(): number;
  cleanupExpiredSessions(): Promise<void>;
  cleanupAll(): Promise<void>;
}

const PoolConstructor = McpServerPool as unknown as new () => TestablePool;

function makeFakeClient(): FakeClient {
  const fake: FakeClient = {
    cleanup: vi.fn(async () => {
      fake.closed = true;
    }),
    closed: false,
    listChangedSubscribers: new Set(),
  };
  return fake;
}

describe("McpServerPool proactive capacity eviction", () => {
  let pool: TestablePool;

  beforeEach(() => {
    vi.clearAllMocks();
    pool = new PoolConstructor();
    pool.activeSessions = {};
    pool.idleSessions = {};
    pool.sessionToServers = {};
    pool.sessionTimestamps = {};
    clearInterval(pool.cleanupTimer);
    clearInterval(pool.healthCheckTimer);
    clearInterval(pool.toolsSweepTimer);
  });

  afterEach(async () => {
    await pool.cleanupAll();
  });

  it("does not evict idle sessions when total connections are below 75% watermark", async () => {
    vi.mocked(configService.getSessionLifetime).mockResolvedValue(null);
    // Default maxTotalConnections is 100, watermark is 75.
    // Populate 10 idle sessions (total 10 < 75)
    for (let i = 0; i < 10; i++) {
      pool.idleSessions[`server-${i}`] = makeFakeClient();
    }

    expect(pool.getTotalConnectionCount()).toBe(10);

    await pool.cleanupExpiredSessions();

    // All 10 idle sessions remain intact
    expect(pool.getTotalConnectionCount()).toBe(10);
    expect(Object.keys(pool.idleSessions).length).toBe(10);
  });

  it("proactively evicts idle sessions down to safe watermark when connection count >= 75%", async () => {
    vi.mocked(configService.getSessionLifetime).mockResolvedValue(null);

    // Set maxTotalConnections = 100 -> high watermark is 75
    // Add 70 active connections
    for (let i = 0; i < 70; i++) {
      pool.activeSessions[`session-${i}`] = {
        "srv-a": makeFakeClient(),
      };
      pool.sessionToServers[`session-${i}`] = new Set(["srv-a"]);
      pool.sessionTimestamps[`session-${i}`] = Date.now();
    }

    // Add 15 idle sessions -> total = 85 (exceeds 75 watermark)
    const idleClients: FakeClient[] = [];
    for (let i = 0; i < 15; i++) {
      const client = makeFakeClient();
      idleClients.push(client);
      pool.idleSessions[`idle-${i}`] = client;
    }

    expect(pool.getTotalConnectionCount()).toBe(85);

    await pool.cleanupExpiredSessions();

    // Should evict 10 idle sessions down to exactly 75 connections
    expect(pool.getTotalConnectionCount()).toBe(75);
    expect(Object.keys(pool.idleSessions).length).toBe(5);

    // Evicted clients should have had cleanup() called
    const cleanedUpCount = idleClients.filter((c) => c.closed).length;
    expect(cleanedUpCount).toBe(10);

    // Active connections remain untouched (still 70)
    expect(Object.keys(pool.activeSessions).length).toBe(70);
  });

  it("evicts all idle sessions if needed when active sessions alone exceed watermark", async () => {
    vi.mocked(configService.getSessionLifetime).mockResolvedValue(null);

    // 80 active connections
    for (let i = 0; i < 80; i++) {
      pool.activeSessions[`session-${i}`] = {
        "srv-a": makeFakeClient(),
      };
      pool.sessionToServers[`session-${i}`] = new Set(["srv-a"]);
    }

    // 5 idle sessions -> total 85
    for (let i = 0; i < 5; i++) {
      pool.idleSessions[`idle-${i}`] = makeFakeClient();
    }

    await pool.cleanupExpiredSessions();

    // All idle sessions evicted, active sessions stay
    expect(Object.keys(pool.idleSessions).length).toBe(0);
    expect(Object.keys(pool.activeSessions).length).toBe(80);
    expect(pool.getTotalConnectionCount()).toBe(80);
  });
});
