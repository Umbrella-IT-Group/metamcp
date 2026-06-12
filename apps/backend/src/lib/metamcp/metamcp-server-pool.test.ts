/**
 * Unit tests for the NAMESPACE-level pool (`MetaMcpServerPool`).
 *
 * Covers the 2026-06-12 audit findings:
 *
 *   F1 — `createIdleServer` had no in-flight guard and overwrote the
 *        idle slot without cleaning up the loser, leaking its backend
 *        ConnectedClients under a temp `idle_<ns>_<ts>` sessionId
 *        forever (the incident-#229 cap-exhaustion end state via the
 *        admin-edit route). Plus the generation counter: an in-flight
 *        creation that straddles an invalidation must discard its
 *        pre-change-config result.
 *   F2 — `invalidateOpenApiSessions` cleaned the namespace-level
 *        instance but never the backend-pool sessions keyed under
 *        `openapi_<ns>` — the id the OpenAPI request path actually
 *        uses — so OpenAPI kept executing against stale pre-change
 *        clients.
 *   F4 — `cleanupSession` deleted its maps only AFTER two unguarded
 *        awaits; a cleanup() throw stranded a permanent zombie entry.
 */

import { beforeEach, describe, expect, it, vi } from "vitest";

const { createServerMock, backendCleanupSessionMock, backendCleanupAllMock } =
  vi.hoisted(() => ({
    createServerMock: vi.fn(),
    backendCleanupSessionMock: vi.fn(),
    backendCleanupAllMock: vi.fn(),
  }));

vi.mock("./metamcp-proxy", () => ({
  createServer: createServerMock,
}));

vi.mock("./mcp-server-pool", () => ({
  mcpServerPool: {
    cleanupSession: backendCleanupSessionMock,
    cleanupAll: backendCleanupAllMock,
  },
}));

vi.mock("../config.service", () => ({
  configService: {
    getSessionLifetime: vi.fn().mockResolvedValue(null),
  },
}));

vi.mock("@/utils/logger", () => ({
  default: {
    error: vi.fn(),
    warn: vi.fn(),
    info: vi.fn(),
    debug: vi.fn(),
  },
}));

import { MetaMcpServerPool } from "./metamcp-server-pool";

// The constructor is private (singleton); a fresh instance per test so
// the static-instance accessor can't leak state across describes.
const PoolConstructor = MetaMcpServerPool as unknown as new (
  defaultIdleCount?: number,
) => MetaMcpServerPool;

type PoolInternals = {
  idleServers: Record<
    string,
    { server: unknown; cleanup: () => Promise<void> }
  >;
  activeServers: Record<
    string,
    { server: unknown; cleanup: () => Promise<void> }
  >;
  sessionToNamespace: Record<string, string>;
  sessionTimestamps: Record<string, number>;
  creatingIdleServers: Set<string>;
  idleServerGenerations: Record<string, number>;
  createIdleServer: (
    namespaceUuid: string,
    includeInactiveServers?: boolean,
  ) => Promise<void>;
};

function makeInstance(cleanup: () => Promise<void> = () => Promise.resolve()) {
  return { server: {}, cleanup };
}

describe("MetaMcpServerPool.createIdleServer — in-flight guard + generation (F1)", () => {
  let pool: MetaMcpServerPool;
  let internals: PoolInternals;

  beforeEach(() => {
    vi.clearAllMocks();
    pool = new PoolConstructor();
    internals = pool as never;
  });

  it("concurrent createIdleServer calls build exactly one server", async () => {
    let resolveCreate!: (v: unknown) => void;
    createServerMock.mockImplementation(
      () => new Promise((resolve) => (resolveCreate = resolve)),
    );

    const first = internals.createIdleServer("ns-1");
    const second = internals.createIdleServer("ns-1");

    resolveCreate(makeInstance());
    await Promise.all([first, second]);

    expect(createServerMock).toHaveBeenCalledTimes(1);
    expect(internals.idleServers["ns-1"]).toBeDefined();
  });

  it("an overwrite-loser is cleaned up, never orphaned", async () => {
    // Simulate the pre-guard race shape: a server lands in the idle
    // slot while our creation is in flight.
    const winner = makeInstance();
    const loserCleanup = vi.fn().mockResolvedValue(undefined);
    createServerMock.mockImplementation(async () => {
      internals.idleServers["ns-1"] = winner;
      return makeInstance(loserCleanup);
    });

    await internals.createIdleServer("ns-1");

    expect(internals.idleServers["ns-1"]).toBe(winner);
    expect(loserCleanup).toHaveBeenCalledTimes(1);
  });

  it("discards an in-flight result when the generation was bumped (invalidation raced)", async () => {
    const staleCleanup = vi.fn().mockResolvedValue(undefined);
    createServerMock.mockImplementation(async () => {
      // An invalidateIdleServer fires while we're connecting — the
      // instance we're building reflects the PRE-change config.
      internals.idleServerGenerations["ns-1"] =
        (internals.idleServerGenerations["ns-1"] ?? 0) + 1;
      return makeInstance(staleCleanup);
    });

    await internals.createIdleServer("ns-1");

    expect(internals.idleServers["ns-1"]).toBeUndefined();
    expect(staleCleanup).toHaveBeenCalledTimes(1);
  });

  it("invalidateIdleServer bumps the generation before rebuilding", async () => {
    createServerMock.mockResolvedValue(makeInstance());
    const before = internals.idleServerGenerations["ns-1"] ?? 0;

    await pool.invalidateIdleServer("ns-1");

    expect(internals.idleServerGenerations["ns-1"]).toBe(before + 1);
    expect(internals.idleServers["ns-1"]).toBeDefined();
  });
});

describe("MetaMcpServerPool.invalidateOpenApiSessions — backend layer cleanup (F2)", () => {
  let pool: MetaMcpServerPool;
  let internals: PoolInternals;

  beforeEach(() => {
    vi.clearAllMocks();
    backendCleanupSessionMock.mockResolvedValue(undefined);
    createServerMock.mockResolvedValue(makeInstance());
    pool = new PoolConstructor();
    internals = pool as never;
  });

  it("cleans the openapi_<ns> backend-pool sessions, not just the instance", async () => {
    const instanceCleanup = vi.fn().mockResolvedValue(undefined);
    internals.activeServers["openapi_ns-1"] = makeInstance(instanceCleanup);
    internals.sessionToNamespace["openapi_ns-1"] = "ns-1";

    await pool.invalidateOpenApiSessions(["ns-1"]);

    expect(instanceCleanup).toHaveBeenCalledTimes(1);
    expect(backendCleanupSessionMock).toHaveBeenCalledWith("openapi_ns-1");
    // Recreated with fresh config
    expect(internals.activeServers["openapi_ns-1"]).toBeDefined();
  });

  it("still cleans the backend layer when no namespace-level instance exists", async () => {
    await pool.invalidateOpenApiSessions(["ns-2"]);

    expect(backendCleanupSessionMock).toHaveBeenCalledWith("openapi_ns-2");
  });
});

describe("MetaMcpServerPool.cleanupSession — maps drop even when cleanup throws (F4)", () => {
  let pool: MetaMcpServerPool;
  let internals: PoolInternals;

  beforeEach(() => {
    vi.clearAllMocks();
    backendCleanupSessionMock.mockResolvedValue(undefined);
    createServerMock.mockResolvedValue(makeInstance());
    pool = new PoolConstructor();
    internals = pool as never;
  });

  it("a rejecting instance cleanup no longer strands a zombie map entry", async () => {
    const throwing = vi.fn().mockRejectedValue(new Error("transport wedged"));
    internals.activeServers["sess-1"] = makeInstance(throwing);
    internals.sessionToNamespace["sess-1"] = "ns-1";
    internals.sessionTimestamps["sess-1"] = 12345;

    await expect(pool.cleanupSession("sess-1")).resolves.toBeUndefined();

    expect(internals.activeServers["sess-1"]).toBeUndefined();
    expect(internals.sessionTimestamps["sess-1"]).toBeUndefined();
    expect(internals.sessionToNamespace["sess-1"]).toBeUndefined();
    // The backend layer still got its cleanup despite the throw above.
    expect(backendCleanupSessionMock).toHaveBeenCalledWith("sess-1");
  });

  it("no-ops on an unknown sessionId", async () => {
    await pool.cleanupSession("missing");
    expect(backendCleanupSessionMock).not.toHaveBeenCalled();
  });
});
