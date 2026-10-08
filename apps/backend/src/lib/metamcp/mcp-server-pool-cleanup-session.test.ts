/** Regression tests for shared backend ownership across pool teardown paths. */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// `mcp-server-pool.ts` instantiates a `connectMetaMcpClient`-driven
// pool at module load time. Stub the heavy imports so the unit test
// doesn't need a postgres or a real upstream MCP.
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

import type { ServerParameters } from "@repo/zod-types";

import logger from "@/utils/logger";

import { type ConnectedClient, connectMetaMcpClient } from "./client";
import {
  McpServerPool,
  SHUTDOWN_PENDING_CONNECT_WAIT_MS,
} from "./mcp-server-pool";
import { serverErrorTracker } from "./server-error-tracker";

// Bypass the private-constructor discipline once, file-wide, without a
// TS2673 per instantiation. Tests poke internals; the singleton
// accessor would leak state across describes.
const PoolConstructor = McpServerPool as unknown as new (
  defaultIdleCount?: number,
  maxTotalConnections?: number,
  maxConnectionsPerServer?: number,
) => McpServerPool;

type FakeClient = {
  cleanup: ReturnType<typeof vi.fn>;
  closed: boolean;
  listChangedSubscribers: Set<() => void | Promise<void>>;
};

function makeFakeClient(): FakeClient {
  const fake: FakeClient = {
    cleanup: vi.fn(async () => {
      fake.closed = true;
      fake.listChangedSubscribers.clear();
    }),
    closed: false,
    listChangedSubscribers: new Set(),
  };
  return fake;
}

type Internals = {
  activeSessions: Record<string, Record<string, FakeClient>>;
  idleSessions: Record<string, FakeClient>;
  sessionToServers: Record<string, Set<string>>;
  sessionToNamespace: Record<string, string>;
  sessionTimestamps: Record<string, number>;
  serverParamsCache: Record<string, ServerParameters>;
  createNewConnection: (
    params: ServerParameters,
  ) => Promise<ConnectedClient | undefined>;
  getTotalConnectionCount: () => number;
  countConnectionsForServer: (serverUuid: string) => number;
  activeConnectionsPerNamespace: () => Record<string, number>;
  createIdleSessionAsync: (
    serverUuid: string,
    params: ServerParameters,
  ) => void;
  evictOneForCapacity: (serverUuid: string) => Promise<boolean>;
  checkIdleSessionHealth: () => Promise<void>;
  cleanupServerSessions: (serverUuid: string) => Promise<void>;
  createIdleSession: (
    serverUuid: string,
    params: ServerParameters,
  ) => Promise<void>;
  creatingIdleSessions: Set<string>;
  idleSessionGenerations: Record<string, number>;
};

function deferred() {
  let resolve!: () => void;
  let reject!: (error: Error) => void;
  const promise = new Promise<void>((done, fail) => {
    resolve = done;
    reject = fail;
  });
  return { promise, resolve, reject };
}

const params: ServerParameters = {
  uuid: "server",
  name: "fixture",
  description: "Synthetic review fixture",
  type: "STDIO",
  stderr: "pipe",
  created_at: "2026-10-07T00:00:00.000Z",
  status: "ACTIVE",
  command: "node",
  args: [],
  env: {},
};

describe("McpServerPool shared connection ownership and teardown", () => {
  let pool: McpServerPool;
  let internals: Internals;

  beforeEach(() => {
    vi.useFakeTimers();
    vi.mocked(connectMetaMcpClient).mockReset();
    pool = new PoolConstructor();
    internals = pool as unknown as Internals;
  });

  afterEach(() => {
    vi.clearAllTimers();
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  function session(id: string, clients: Record<string, FakeClient>) {
    internals.activeSessions[id] = clients;
    internals.sessionToServers[id] = new Set(Object.keys(clients));
    internals.sessionToNamespace[id] = "namespace";
    internals.sessionTimestamps[id] = 1;
  }

  it.each(["global", "per-server"] as const)(
    "reserves the %s cap before concurrent active connects yield",
    async (limit) => {
      pool = new PoolConstructor(1, limit === "global" ? 2 : 100, 2);
      internals = pool as unknown as Internals;
      vi.spyOn(internals, "createIdleSessionAsync").mockImplementation(
        () => {},
      );
      const gate = deferred();
      vi.mocked(connectMetaMcpClient).mockImplementation(async () => {
        await gate.promise;
        return makeFakeClient() as unknown as ConnectedClient;
      });
      const requests = Array.from({ length: 20 }, (_, index) =>
        pool.getSession(
          `session-${index}`,
          limit === "global" ? `server-${index}` : "server",
          {
            ...params,
            uuid: limit === "global" ? `server-${index}` : "server",
          },
        ),
      );
      await Promise.resolve();
      expect(connectMetaMcpClient).toHaveBeenCalledTimes(2);
      expect(pool.getPoolStatus().pending).toBe(2);
      expect(internals.getTotalConnectionCount()).toBe(2);
      gate.resolve();
      const results = await Promise.all(requests);
      expect(results.filter(Boolean)).toHaveLength(2);
      expect(internals.getTotalConnectionCount()).toBe(2);
      expect(pool.getPoolStatus().pending).toBe(0);
      await pool.cleanupAll();
    },
  );

  it("keeps an established but unpublished connection reserved", async () => {
    pool = new PoolConstructor(1, 1, 1);
    internals = pool as unknown as Internals;
    const client = makeFakeClient();
    vi.mocked(connectMetaMcpClient).mockResolvedValue(
      client as unknown as ConnectedClient,
    );
    expect(await internals.createNewConnection(params)).toBe(client);
    expect(internals.getTotalConnectionCount()).toBe(1);
    expect(await internals.createNewConnection(params)).toBeUndefined();
    expect(connectMetaMcpClient).toHaveBeenCalledTimes(1);
    await pool.cleanupAll();
    expect(client.cleanup).toHaveBeenCalledTimes(1);
  });

  it("warms the only idle slot without counting its guard as a second reservation", async () => {
    pool = new PoolConstructor(1, 1, 1);
    internals = pool as unknown as Internals;
    const gate = deferred();
    const client = makeFakeClient();
    vi.mocked(connectMetaMcpClient).mockImplementation(async () => {
      await gate.promise;
      return client as unknown as ConnectedClient;
    });
    const creation = internals.createIdleSession("server", params);
    expect(connectMetaMcpClient).toHaveBeenCalledTimes(1);
    expect(pool.getPoolStatus().pending).toBe(1);
    expect(internals.getTotalConnectionCount()).toBe(1);
    gate.resolve();
    await creation;
    expect(internals.idleSessions.server).toBe(client);
    expect(pool.getPoolStatus().pending).toBe(0);
    expect(internals.getTotalConnectionCount()).toBe(1);
    await pool.cleanupAll();
  });

  it.each([false, true])(
    "releases a failed connect reservation, throws=%s",
    async (throws) => {
      pool = new PoolConstructor(1, 1, 1);
      internals = pool as unknown as Internals;
      const error = new Error("fixture connect failure");
      if (throws) vi.mocked(connectMetaMcpClient).mockRejectedValueOnce(error);
      else vi.mocked(connectMetaMcpClient).mockResolvedValueOnce(undefined);
      const failed = internals.createNewConnection(params);
      if (throws) await expect(failed).rejects.toBe(error);
      else await expect(failed).resolves.toBeUndefined();
      expect(internals.getTotalConnectionCount()).toBe(0);
      const client = makeFakeClient();
      vi.mocked(connectMetaMcpClient).mockResolvedValue(
        client as unknown as ConnectedClient,
      );
      expect(await internals.createNewConnection(params)).toBe(client);
      await pool.cleanupAll();
    },
  );

  it("does not lend or replace a connection while capacity eviction is still closing it", async () => {
    pool = new PoolConstructor(1, 1, 50);
    internals = pool as unknown as Internals;
    const gate = deferred();
    const closing = makeFakeClient();
    closing.cleanup.mockImplementation(() => gate.promise);
    internals.idleSessions.server = closing;
    const replacement = makeFakeClient();
    vi.mocked(connectMetaMcpClient).mockResolvedValue(
      replacement as unknown as ConnectedClient,
    );
    const first = internals.createNewConnection({ ...params, uuid: "first" });
    await Promise.resolve();
    expect(internals.getTotalConnectionCount()).toBe(1);
    expect(
      await internals.createNewConnection({ ...params, uuid: "second" }),
    ).toBeUndefined();
    expect(connectMetaMcpClient).not.toHaveBeenCalled();
    gate.resolve();
    expect(await first).toBe(replacement);
    expect(connectMetaMcpClient).toHaveBeenCalledTimes(1);
    await pool.cleanupAll();
  });

  it("retains a failed close against both caps and retries it before admission", async () => {
    pool = new PoolConstructor(1, 1, 1);
    internals = pool as unknown as Internals;
    const closing = makeFakeClient();
    closing.cleanup.mockRejectedValue(new Error("fixture close failed"));
    internals.idleSessions.server = closing;
    const replacement = makeFakeClient();
    vi.mocked(connectMetaMcpClient).mockResolvedValue(
      replacement as unknown as ConnectedClient,
    );
    expect(
      await internals.createNewConnection({ ...params, uuid: "other" }),
    ).toBeUndefined();
    expect(internals.idleSessions.server).toBeUndefined();
    expect(internals.getTotalConnectionCount()).toBe(1);
    expect(internals.countConnectionsForServer("server")).toBe(1);
    expect(pool.getPoolStatus().perServerCounts?.server).toBe(0);
    expect(pool.getPoolStatus().pending).toBe(1);
    expect(await internals.createNewConnection(params)).toBeUndefined();
    expect(connectMetaMcpClient).not.toHaveBeenCalled();
    closing.cleanup.mockImplementation(async () => {
      closing.closed = true;
    });
    expect(
      await internals.createNewConnection({ ...params, uuid: "other" }),
    ).toBe(replacement);
    expect(closing.closed).toBe(true);
    expect(internals.getTotalConnectionCount()).toBe(1);
    await pool.cleanupAll();
  });

  it("counts shared aliases once and admits remaining physical capacity", async () => {
    pool = new PoolConstructor(1, 2, 1);
    internals = pool as unknown as Internals;
    vi.spyOn(internals, "createIdleSessionAsync").mockImplementation(() => {});
    const shared = makeFakeClient();
    for (let index = 0; index < 100; index++)
      session(`borrower-${index}`, { server: shared });
    expect(internals.getTotalConnectionCount()).toBe(1);
    expect(internals.countConnectionsForServer("server")).toBe(1);
    const newClient = makeFakeClient();
    vi.mocked(connectMetaMcpClient).mockResolvedValue(
      newClient as unknown as ConnectedClient,
    );
    expect(
      await pool.getSession("new", "other", { ...params, uuid: "other" }),
    ).toBe(newClient);
    expect(shared.cleanup).not.toHaveBeenCalled();
    expect(pool.getPoolStatus().active).toBe(2);
    expect(internals.getTotalConnectionCount()).toBe(2);
    await pool.cleanupAll();
  });

  it("borrows an existing backend at the global cap even below its per-server cap", async () => {
    pool = new PoolConstructor(1, 2, 50);
    internals = pool as unknown as Internals;
    const shared = makeFakeClient();
    const other = makeFakeClient();
    session("owner", { server: shared });
    session("other-owner", { other });
    expect(await pool.getSession("borrower", "server", params)).toBe(shared);
    expect(connectMetaMcpClient).not.toHaveBeenCalled();
    expect(other.cleanup).not.toHaveBeenCalled();
    expect(internals.getTotalConnectionCount()).toBe(2);
    await pool.cleanupAll();
  });

  it.each([16, 21])(
    "holds production caps during a 500-request burst across %s backends",
    async (servers) => {
      pool = new PoolConstructor(1, 200, 50);
      internals = pool as unknown as Internals;
      vi.spyOn(internals, "createIdleSessionAsync").mockImplementation(
        () => {},
      );
      vi.spyOn(logger, "warn").mockImplementation(() => {});
      const gate = deferred();
      let live = 0;
      let peak = 0;
      vi.mocked(connectMetaMcpClient).mockImplementation(async () => {
        live++;
        peak = Math.max(peak, live);
        await gate.promise;
        const client = makeFakeClient();
        client.cleanup.mockImplementation(async () => {
          live--;
        });
        return client as unknown as ConnectedClient;
      });
      const requests = Array.from({ length: 500 }, (_, index) => {
        const uuid = `backend-${index % servers}`;
        return pool.getSession(`request-${index}`, uuid, { ...params, uuid });
      });
      expect(connectMetaMcpClient).toHaveBeenCalledTimes(200);
      expect(pool.getPoolStatus().pending).toBe(200);
      for (const count of Object.values(
        pool.getPoolStatus().perServerCounts ?? {},
      )) {
        expect(count).toBeLessThanOrEqual(50);
      }
      gate.resolve();
      expect((await Promise.all(requests)).filter(Boolean)).toHaveLength(200);
      expect(peak).toBe(200);
      expect(internals.getTotalConnectionCount()).toBe(200);
      await pool.cleanupAll();
      expect(live).toBe(0);
    },
  );

  it("evicts an exclusive connection instead of removing a shared owner's alias", async () => {
    const shared = makeFakeClient();
    const exclusive = makeFakeClient();
    session("old-owner", { server: shared });
    session("borrower", { server: shared });
    session("newer-owner", { private: exclusive });
    internals.sessionTimestamps["newer-owner"] = 2;
    expect(await internals.evictOneForCapacity("other")).toBe(true);
    expect(exclusive.cleanup).toHaveBeenCalledTimes(1);
    expect(shared.cleanup).not.toHaveBeenCalled();
    expect(internals.activeSessions["old-owner"].server).toBe(shared);
    expect(internals.activeSessions.borrower.server).toBe(shared);
  });

  it("uses distinct clients per namespace when choosing a floor-protected victim", async () => {
    const shared = makeFakeClient();
    const protectedClient = makeFakeClient();
    const surplus = makeFakeClient();
    for (let index = 0; index < 20; index++)
      session(`alias-${index}`, { server: shared });
    session("protected", { private: protectedClient });
    session("surplus", {
      one: surplus,
      two: makeFakeClient(),
      three: makeFakeClient(),
    });
    internals.sessionToNamespace.surplus = "other-namespace";
    internals.sessionTimestamps.surplus = 2;
    expect(internals.activeConnectionsPerNamespace()).toEqual({
      namespace: 2,
      "other-namespace": 3,
    });
    expect(await internals.evictOneForCapacity("new")).toBe(true);
    expect(protectedClient.cleanup).not.toHaveBeenCalled();
    expect(shared.cleanup).not.toHaveBeenCalled();
    expect(surplus.cleanup).toHaveBeenCalledTimes(1);
  });

  it("retries a failed detached close during periodic maintenance", async () => {
    const failed = makeFakeClient();
    failed.cleanup.mockRejectedValueOnce(new Error("fixture retry"));
    session("owner", { server: failed });
    internals.idleSessions.server = makeFakeClient();
    await pool.cleanupSession("owner");
    delete internals.idleSessions.server;
    expect(internals.getTotalConnectionCount()).toBe(1);
    await internals.checkIdleSessionHealth();
    expect(failed.cleanup).toHaveBeenCalledTimes(2);
    expect(internals.getTotalConnectionCount()).toBe(0);
  });

  it("routine idle ping failure does not discard an unrelated pending active connect for that server", async () => {
    const gate = deferred();
    const spawned = makeFakeClient();
    vi.mocked(connectMetaMcpClient).mockImplementation(async () => {
      await gate.promise;
      return spawned as unknown as ConnectedClient;
    });
    vi.spyOn(internals, "createIdleSessionAsync").mockImplementation(() => {});
    const request = pool.getSession("owner", "server", params);
    const idle = {
      ...makeFakeClient(),
      client: {
        ping: vi.fn().mockRejectedValue(new Error("fixture idle failure")),
      },
    };
    internals.idleSessions.server = idle;
    await internals.checkIdleSessionHealth();
    gate.resolve();
    expect(await request).toBe(spawned);
    expect(spawned.cleanup).not.toHaveBeenCalled();
    expect(idle.cleanup).toHaveBeenCalledTimes(1);
    await pool.cleanupAll();
  });

  it("shutdown waits for a detached teardown already in progress", async () => {
    const gate = deferred();
    const closing = makeFakeClient();
    closing.cleanup.mockImplementation(() => gate.promise);
    session("owner", { server: closing });
    internals.idleSessions.server = makeFakeClient();
    const release = pool.cleanupSession("owner");
    let finished = false;
    const shutdown = pool.cleanupAll().then(() => {
      finished = true;
    });
    for (let tick = 0; tick < 20; tick++) await Promise.resolve();
    expect(finished).toBe(false);
    gate.resolve();
    await Promise.all([release, shutdown]);
    expect(closing.cleanup).toHaveBeenCalledTimes(1);
  });

  it.each(["active", "idle", "background idle"] as const)(
    "shutdown waits for a pending %s connect and its disposal",
    async (kind) => {
      const gate = deferred();
      const client = makeFakeClient();
      vi.mocked(connectMetaMcpClient).mockImplementation(async () => {
        await gate.promise;
        return client as unknown as ConnectedClient;
      });
      const creation =
        kind === "active"
          ? pool.getSession("owner", "server", params)
          : kind === "idle"
            ? internals.createIdleSession("server", params)
            : internals.createIdleSessionAsync("server", params);
      let finished = false;
      const shutdown = pool.cleanupAll().then(() => {
        finished = true;
      });
      for (let tick = 0; tick < 20; tick++) await Promise.resolve();
      expect(finished).toBe(false);
      gate.resolve();
      await Promise.all([creation, shutdown]);
      expect(client.cleanup).toHaveBeenCalledTimes(1);
      expect(internals.getTotalConnectionCount()).toBe(0);
    },
  );

  it.each(["active", "idle", "background idle"] as const)(
    "shutdown closes established clients at once and stops waiting for a hung %s connect",
    async (kind) => {
      // An SSE backend that heartbeats without ever sending its `endpoint`
      // event keeps SDK startup, and so the whole connect, pending before
      // the initialize timeout starts. Model it as a connect that settles
      // only when the test says so, long after shutdown gave up on it.
      const hung = deferred();
      const late = makeFakeClient();
      vi.mocked(connectMetaMcpClient).mockImplementation(async () => {
        await hung.promise;
        return late as unknown as ConnectedClient;
      });
      const warn = vi.spyOn(logger, "warn").mockImplementation(() => {});
      const active = makeFakeClient();
      const idle = makeFakeClient();
      session("established", { "server-active": active });
      internals.idleSessions["server-idle"] = idle;
      const creation =
        kind === "active"
          ? pool.getSession("owner", "server", params)
          : kind === "idle"
            ? internals.createIdleSession("server", params)
            : internals.createIdleSessionAsync("server", params);
      expect(pool.getPoolStatus().pending).toBe(1);

      let finished = false;
      const shutdown = pool.cleanupAll().then(() => {
        finished = true;
      });
      for (let tick = 0; tick < 20; tick++) await Promise.resolve();
      // Established clients must not queue behind the hung connect.
      expect(active.cleanup).toHaveBeenCalledTimes(1);
      expect(idle.cleanup).toHaveBeenCalledTimes(1);
      expect(finished).toBe(false);

      await vi.advanceTimersByTimeAsync(SHUTDOWN_PENDING_CONNECT_WAIT_MS - 1);
      expect(finished).toBe(false);
      await vi.advanceTimersByTimeAsync(1);
      await shutdown;
      expect(finished).toBe(true);
      expect(warn).toHaveBeenCalledWith(
        expect.stringContaining("stopped waiting"),
      );
      // Terminal pool: the abandoned connect no longer reports a reservation.
      expect(pool.getPoolStatus().pending).toBe(0);
      expect(internals.getTotalConnectionCount()).toBe(0);

      // The backend finally answers. Its client is closed, never published.
      hung.resolve();
      await creation;
      for (let tick = 0; tick < 20; tick++) await Promise.resolve();
      expect(late.cleanup).toHaveBeenCalledTimes(1);
      expect(internals.activeSessions.owner?.server).toBeUndefined();
      expect(internals.idleSessions.server).toBeUndefined();
      expect(internals.getTotalConnectionCount()).toBe(0);
      expect(pool.getPoolStatus().pending).toBe(0);
      expect(active.cleanup).toHaveBeenCalledTimes(1);
      expect(idle.cleanup).toHaveBeenCalledTimes(1);
    },
  );

  it("shutdown sweeps a late connect whose own close failed once, and an established client once", async () => {
    const gate = deferred();
    const late = makeFakeClient();
    late.cleanup.mockRejectedValueOnce(new Error("fixture late close failed"));
    vi.mocked(connectMetaMcpClient).mockImplementation(async () => {
      await gate.promise;
      return late as unknown as ConnectedClient;
    });
    const log = vi.spyOn(logger, "error").mockImplementation(() => {});
    const failed = makeFakeClient();
    failed.cleanup.mockRejectedValue(new Error("fixture idle close failed"));
    internals.idleSessions["server-idle"] = failed;
    const creation = internals.createIdleSession("server", params);
    const shutdown = pool.cleanupAll();
    for (let tick = 0; tick < 20; tick++) await Promise.resolve();
    expect(failed.cleanup).toHaveBeenCalledTimes(1);
    gate.resolve();
    await Promise.all([creation, shutdown]);
    expect(late.cleanup).toHaveBeenCalledTimes(2);
    expect(failed.cleanup).toHaveBeenCalledTimes(1);
    expect(internals.getTotalConnectionCount()).toBe(1);
    expect(log).toHaveBeenCalledWith(
      "MCP server pool shutdown has 1 unclosed connections",
    );
  });

  it("keeps the actual getSession cap borrower alive through owner deletion and final release", async () => {
    pool = new PoolConstructor(1, 100, 1);
    internals = pool as unknown as Internals;
    const shared = makeFakeClient();
    internals.idleSessions.server = shared;

    expect(await pool.getSession("owner", "server", params)).toBe(shared);
    expect(await pool.getSession("borrower", "server", params)).toBe(shared);
    await pool.cleanupSession("owner");
    expect(internals.idleSessions.server).toBeUndefined();
    expect(shared.cleanup).not.toHaveBeenCalled();
    expect(await pool.getSession("borrower", "server", params)).toBe(shared);
    await pool.cleanupSession("borrower");
    expect(internals.idleSessions.server).toBe(shared);
  });

  it("a new borrower can take the final released client while another teardown is pending", async () => {
    pool = new PoolConstructor(1, 100, 1);
    internals = pool as unknown as Internals;
    const gate = deferred();
    const slow = makeFakeClient();
    slow.cleanup.mockImplementation(() => gate.promise);
    const shared = makeFakeClient();
    session("owner", { slow, server: shared });
    internals.idleSessions.slow = makeFakeClient();
    const pending = pool.cleanupSession("owner");
    const borrowed = await pool.getSession("borrower", "server", params);
    gate.resolve();
    await pending;
    expect(borrowed).toBe(shared);
    expect(internals.activeSessions.borrower.server).toBe(shared);
    expect(internals.idleSessions.server).toBeUndefined();
    expect(shared.cleanup).not.toHaveBeenCalled();
    expect(shared.closed).toBe(false);
  });

  it.each([false, true])(
    "discards an in-flight connection after DELETE, even if the session id is reused=%s",
    async (reused) => {
      const gate = deferred();
      const spawned = makeFakeClient();
      const original = makeFakeClient();
      session("owner", { server: original });
      vi.spyOn(internals, "createIdleSessionAsync").mockImplementation(
        () => {},
      );
      vi.spyOn(internals, "createNewConnection").mockImplementation(
        async () => {
          await gate.promise;
          return spawned as unknown as ConnectedClient;
        },
      );
      const pending = pool.getSession("owner", "other", {
        ...params,
        uuid: "other",
      });
      await pool.cleanupSession("owner");
      if (reused) {
        expect(await pool.getSession("owner", "server", params)).toBe(original);
      }
      gate.resolve();
      await expect(pending).resolves.toBeUndefined();
      expect(spawned.cleanup).toHaveBeenCalledTimes(1);
      expect(internals.activeSessions.owner?.other).toBeUndefined();
      if (reused) expect(internals.activeSessions.owner.server).toBe(original);
    },
  );

  // connectMetaMcpClient retries a failed attempt in place. A STDIO attempt
  // that crashes resets its server through the pool's crash handler, which
  // bumps the generation getSession sampled before connecting. Each crash is
  // reported while the connect is pending; `crashed` settles once every
  // crash has been reported and handled, and the client comes from a later
  // attempt once the test resolves `retried`.
  async function flush() {
    for (let tick = 0; tick < 20; tick++) await Promise.resolve();
  }

  function crashThenConnect(crashes: number, client: FakeClient) {
    const crashed = deferred();
    const retried = deferred();
    vi.mocked(connectMetaMcpClient)
      .mockResolvedValue(undefined)
      .mockImplementationOnce(async (_params, onProcessCrash) => {
        for (let attempt = 0; attempt < crashes; attempt++) {
          onProcessCrash?.(1, null);
          await flush();
        }
        crashed.resolve();
        await retried.promise;
        return client as unknown as ConnectedClient;
      });
    return { crashed: crashed.promise, retried };
  }

  it.each([
    [1, undefined],
    [2, "namespace"],
  ] as const)(
    "publishes a retry that succeeds after %i of its own attempts crashed (namespace %s)",
    async (crashes, namespace) => {
      vi.mocked(serverErrorTracker.recordServerCrash).mockReset();
      vi.spyOn(internals, "createIdleSessionAsync").mockImplementation(
        () => {},
      );
      const sibling = makeFakeClient();
      session("other", { server: sibling });
      const client = makeFakeClient();
      const { crashed, retried } = crashThenConnect(crashes, client);
      const request = pool.getSession("owner", "server", params, namespace);
      await crashed;
      // The crash reset itself is unchanged: it is recorded for the breaker,
      // closes the server's published clients and moves the generation, all
      // before the retry succeeds.
      expect(serverErrorTracker.recordServerCrash).toHaveBeenCalledTimes(
        crashes,
      );
      expect(internals.idleSessionGenerations.server).toBe(crashes);
      expect(internals.activeSessions.other.server).toBeUndefined();
      expect(sibling.cleanup).toHaveBeenCalledTimes(1);
      retried.resolve();
      expect(await request).toBe(client);
      expect(internals.activeSessions.owner.server).toBe(client);
      expect(internals.sessionToServers.owner.has("server")).toBe(true);
      expect(client.cleanup).not.toHaveBeenCalled();
      expect(await pool.getSession("owner", "server", params, namespace)).toBe(
        client,
      );
      expect(connectMetaMcpClient).toHaveBeenCalledTimes(1);
      await pool.cleanupAll();
      expect(client.cleanup).toHaveBeenCalledTimes(1);
    },
  );

  it.each(
    (
      [
        "DELETE",
        "invalidateIdleSession",
        "invalidateServerConnection",
        "cleanupIdleSession",
        "cleanupAll",
      ] as const
    ).flatMap((event) =>
      (
        [
          "without a crash",
          "after its own crash reset",
          "before its own crash reset",
          "after a crash whose recording failed",
        ] as const
      ).map((timing) => [event, timing] as const),
    ),
  )("disposes a connect when %s lands during it, %s", async (event, timing) => {
    const recordCrash = vi.mocked(serverErrorTracker.recordServerCrash);
    recordCrash.mockReset();
    const crashRecorded = deferred();
    if (timing === "before its own crash reset") {
      // Hold the crash reset until the invalidation has landed.
      recordCrash.mockImplementationOnce(() => crashRecorded.promise);
    } else if (timing === "after a crash whose recording failed") {
      // No reset runs, so nothing moves the generation for this crash.
      recordCrash.mockRejectedValueOnce(new Error("fixture db failure"));
      vi.spyOn(logger, "error").mockImplementation(() => {});
    }
    vi.spyOn(internals, "createIdleSessionAsync").mockImplementation(() => {});
    const client = makeFakeClient();
    const { crashed, retried } = crashThenConnect(
      timing === "without a crash" ? 0 : 1,
      client,
    );
    const request = pool.getSession("owner", "server", params);
    await crashed;
    // Only a crash reset that already ran has moved the generation.
    expect(internals.idleSessionGenerations.server ?? 0).toBe(
      timing === "after its own crash reset" ? 1 : 0,
    );
    const pending =
      event === "DELETE"
        ? pool.cleanupSession("owner")
        : event === "invalidateIdleSession"
          ? pool.invalidateIdleSession("server", params)
          : event === "invalidateServerConnection"
            ? pool.invalidateServerConnection("owner", "server")
            : event === "cleanupIdleSession"
              ? pool.cleanupIdleSession("server")
              : pool.cleanupAll();
    await flush();
    crashRecorded.resolve();
    await flush();
    expect(recordCrash).toHaveBeenCalledTimes(
      timing === "without a crash" ? 0 : 1,
    );
    retried.resolve();
    expect(await request).toBeUndefined();
    await pending;
    expect(client.cleanup).toHaveBeenCalledTimes(1);
    expect(internals.activeSessions.owner?.server).toBeUndefined();
    expect(internals.idleSessions.server).toBeUndefined();
  });

  it("capacity eviction preserves all shared owners when no physical slot can be released", async () => {
    const shared = makeFakeClient();
    session("owner", { server: shared });
    session("borrower", { server: shared });
    internals.sessionTimestamps.borrower = 2;

    expect(await internals.evictOneForCapacity("other")).toBe(false);
    expect(internals.activeSessions.owner.server).toBe(shared);
    expect(internals.sessionToServers.owner.has("server")).toBe(true);
    expect(internals.activeSessions.borrower.server).toBe(shared);
    expect(shared.cleanup).not.toHaveBeenCalled();
    await pool.cleanupSession("owner");
    await pool.cleanupSession("borrower");
    expect(internals.idleSessions.server).toBe(shared);
  });

  it("capacity eviction repairs a legacy idle alias without closing its active owner", async () => {
    const shared = makeFakeClient();
    session("owner", { server: shared });
    internals.idleSessions.server = shared;
    expect(await internals.evictOneForCapacity("other")).toBe(false);
    expect(internals.idleSessions.server).toBeUndefined();
    expect(internals.activeSessions.owner.server).toBe(shared);
    expect(shared.cleanup).not.toHaveBeenCalled();
  });

  it("a delayed idle ping failure preserves the promoted active client and its replacement", async () => {
    const gate = deferred();
    const ping = vi
      .fn()
      .mockImplementationOnce(() => gate.promise)
      .mockResolvedValue(undefined);
    const promoted = { ...makeFakeClient(), client: { ping } };
    const replacement = {
      ...makeFakeClient(),
      client: { ping: vi.fn().mockResolvedValue(undefined) },
    };
    internals.idleSessions.server = promoted;
    vi.spyOn(internals, "createIdleSessionAsync").mockImplementation(() => {});

    const health = internals.checkIdleSessionHealth();
    await Promise.resolve();
    await Promise.resolve();
    expect(ping).toHaveBeenCalledTimes(1);
    expect(await pool.getSession("borrower", "server", params)).toBe(promoted);
    internals.idleSessions.server = replacement;
    gate.reject(new Error("fixture delayed ping failure"));
    await health;

    expect(promoted.cleanup).not.toHaveBeenCalled();
    expect(internals.activeSessions.borrower.server).toBe(promoted);
    expect(internals.idleSessions.server).toBe(replacement);
    expect(replacement.cleanup).not.toHaveBeenCalled();
  });

  it.each(["invalidateIdleSession", "cleanupIdleSession"] as const)(
    "%s detaches a closing idle client before yielding and preserves a replacement",
    async (method) => {
      const gate = deferred();
      const closing = makeFakeClient();
      closing.cleanup.mockImplementation(() => gate.promise);
      const replacement = makeFakeClient();
      internals.idleSessions.server = closing;
      const pending =
        method === "invalidateIdleSession"
          ? pool.invalidateIdleSession("server", params)
          : pool.cleanupIdleSession("server");
      expect(internals.idleSessions.server).toBeUndefined();
      internals.idleSessions.server = replacement;
      gate.resolve();
      await pending;
      expect(internals.idleSessions.server).toBe(replacement);
      expect(closing.cleanup).toHaveBeenCalledTimes(1);
      expect(replacement.cleanup).not.toHaveBeenCalled();
    },
  );

  it("concurrent shutdown closes once and refuses to lend a closing idle client", async () => {
    const started = deferred();
    const gate = deferred();
    const shared = makeFakeClient();
    shared.cleanup.mockImplementation(() => {
      started.resolve();
      return gate.promise;
    });
    session("owner", { server: shared });
    session("borrower", { server: shared });
    const pending = Promise.all([pool.cleanupAll(), pool.cleanupAll()]);
    await started.promise;
    const late = await pool.getSession("late", "server", params);
    gate.resolve();
    await pending;
    expect(late).toBeUndefined();
    expect(shared.cleanup).toHaveBeenCalledTimes(1);
    expect(internals.activeSessions).toEqual({});
    expect(internals.idleSessions).toEqual({});
  });

  it("shutdown disposes an idle creation resolving after the teardown snapshot", async () => {
    const started = deferred();
    const closeGate = deferred();
    const connectGate = deferred();
    const closing = makeFakeClient();
    const spawned = makeFakeClient();
    closing.cleanup.mockImplementation(() => {
      started.resolve();
      return closeGate.promise;
    });
    vi.spyOn(internals, "createNewConnection").mockImplementation(async () => {
      await connectGate.promise;
      return spawned as unknown as ConnectedClient;
    });
    const creation = internals.createIdleSession("other", {
      ...params,
      uuid: "other",
    });
    internals.idleSessions.server = closing;
    const shutdown = pool.cleanupAll();
    await started.promise;
    connectGate.resolve();
    await creation;
    closeGate.resolve();
    await shutdown;
    expect(spawned.cleanup).toHaveBeenCalledTimes(1);
    expect(internals.idleSessions).toEqual({});
  });

  it("shutdown logs a failed idle close while continuing other teardowns", async () => {
    const error = new Error("fixture shutdown close failed");
    const failed = makeFakeClient();
    failed.cleanup.mockRejectedValue(error);
    const healthy = makeFakeClient();
    const log = vi.spyOn(logger, "error").mockImplementation(() => {});
    internals.idleSessions.failed = failed;
    internals.idleSessions.healthy = healthy;
    await pool.cleanupAll();
    expect(log).toHaveBeenCalledWith(
      "Error cleaning up idle session failed during shutdown:",
      error,
    );
    expect(healthy.cleanup).toHaveBeenCalledTimes(1);
    expect(internals.idleSessions).toEqual({});
  });

  it.each(["invalidateServerConnection", "cleanupServerSessions"] as const)(
    "%s detaches every shared alias before closing once and preserves replacements",
    async (method) => {
      const gate = deferred();
      const shared = makeFakeClient();
      const replacement = makeFakeClient();
      session("owner", { server: shared });
      session("borrower", { server: shared });
      internals.idleSessions.server = shared;
      const detachedAtCleanup: boolean[] = [];
      shared.cleanup.mockImplementation(() => {
        detachedAtCleanup.push(
          internals.activeSessions.owner.server !== shared &&
            internals.activeSessions.borrower.server !== shared &&
            internals.idleSessions.server !== shared,
        );
        return gate.promise;
      });

      const pending =
        method === "invalidateServerConnection"
          ? pool.invalidateServerConnection("owner", "server")
          : internals.cleanupServerSessions("server");
      expect(internals.activeSessions.owner.server).toBeUndefined();
      expect(internals.activeSessions.borrower.server).toBeUndefined();
      expect(internals.idleSessions.server).toBeUndefined();
      internals.activeSessions.borrower.server = replacement;
      internals.idleSessions.server = replacement;
      gate.resolve();
      await pending;
      expect(shared.cleanup).toHaveBeenCalledTimes(1);
      expect(detachedAtCleanup).toEqual([true]);
      expect(internals.activeSessions.borrower.server).toBe(replacement);
      expect(internals.idleSessions.server).toBe(replacement);
      expect(replacement.cleanup).not.toHaveBeenCalled();
    },
  );

  it.each([
    "invalidateIdleSession",
    "cleanupIdleSession",
    "invalidateServerConnection",
  ] as const)(
    "%s invalidates a pending idle creation before slow teardown",
    async (method) => {
      const connectGate = deferred();
      const closeGate = deferred();
      const closing = makeFakeClient();
      const spawned = makeFakeClient();
      vi.spyOn(internals, "createNewConnection")
        .mockImplementationOnce(async () => {
          await connectGate.promise;
          return spawned as unknown as ConnectedClient;
        })
        .mockResolvedValue(undefined);
      const creation = internals.createIdleSession("server", params);
      // A final public release may fill idle while its replacement connect is pending.
      internals.idleSessions.server = closing;
      closing.cleanup.mockImplementation(() => closeGate.promise);
      const pending =
        method === "invalidateIdleSession"
          ? pool.invalidateIdleSession("server", params)
          : method === "cleanupIdleSession"
            ? pool.cleanupIdleSession("server")
            : pool.invalidateServerConnection("owner", "server");
      connectGate.resolve();
      await creation;
      expect(spawned.cleanup).toHaveBeenCalledTimes(1);
      expect(internals.idleSessions.server).toBeUndefined();
      closeGate.resolve();
      await pending;
    },
  );

  it.each(["invalidateIdleSession", "cleanupIdleSession"] as const)(
    "%s removes a legacy idle alias without closing an active owner",
    async (method) => {
      const shared = makeFakeClient();
      session("owner", { server: shared });
      internals.idleSessions.server = shared;
      vi.spyOn(internals, "createNewConnection").mockResolvedValue(undefined);
      if (method === "invalidateIdleSession")
        await pool.invalidateIdleSession("server", params);
      else await pool.cleanupIdleSession("server");
      expect(internals.idleSessions.server).toBeUndefined();
      expect(internals.activeSessions.owner.server).toBe(shared);
      expect(shared.cleanup).not.toHaveBeenCalled();
    },
  );

  it("does not close a borrower when another session is deleted with idle occupied", async () => {
    const shared = makeFakeClient();
    const idle = makeFakeClient();
    session("owner", { server: shared });
    session("borrower", { server: shared });
    internals.idleSessions.server = idle;

    await pool.cleanupSession("owner");

    expect(shared.cleanup).not.toHaveBeenCalled();
    expect(shared.closed).toBe(false);
    expect(internals.activeSessions.borrower.server).toBe(shared);
    expect(internals.idleSessions.server).toBe(idle);
    expect(internals.activeSessions.owner).toBeUndefined();
    expect(internals.sessionToServers.owner).toBeUndefined();
    expect(internals.sessionToNamespace.owner).toBeUndefined();
    expect(internals.sessionTimestamps.owner).toBeUndefined();
  });

  it("does not publish a still-borrowed client into an empty idle slot", async () => {
    const shared = makeFakeClient();
    session("owner", { server: shared });
    session("borrower", { server: shared });
    await pool.cleanupSession("owner");
    expect(internals.idleSessions.server).toBeUndefined();
    expect(shared.cleanup).not.toHaveBeenCalled();
  });

  it("recycles the client only after its last owner releases it", async () => {
    const shared = makeFakeClient();
    session("owner", { server: shared });
    session("borrower", { server: shared });
    await pool.cleanupSession("owner");
    await pool.cleanupSession("borrower");
    expect(internals.idleSessions.server).toBe(shared);
    expect(shared.cleanup).not.toHaveBeenCalled();
    expect(internals.activeSessions).toEqual({});
  });

  it("destroys the final released client once when another idle client exists", async () => {
    const shared = makeFakeClient();
    session("owner", { server: shared });
    session("borrower", { server: shared });
    internals.idleSessions.server = makeFakeClient();
    await Promise.all([
      pool.cleanupSession("owner"),
      pool.cleanupSession("borrower"),
    ]);
    expect(shared.cleanup).toHaveBeenCalledTimes(1);
    expect(internals.activeSessions).toEqual({});
  });

  it("does not close a connection already retained by the idle pool", async () => {
    const shared = makeFakeClient();
    session("owner", { server: shared });
    internals.idleSessions.server = shared;
    await pool.cleanupSession("owner");
    expect(shared.cleanup).not.toHaveBeenCalled();
    expect(internals.idleSessions.server).toBe(shared);
  });

  it("removes a legacy idle alias while another active borrower remains", async () => {
    const shared = makeFakeClient();
    session("owner", { server: shared });
    session("borrower", { server: shared });
    internals.idleSessions.server = shared;
    await pool.cleanupSession("owner");
    expect(internals.idleSessions.server).toBeUndefined();
    expect(shared.cleanup).not.toHaveBeenCalled();
    await pool.cleanupSession("borrower");
    expect(internals.idleSessions.server).toBe(shared);
  });

  it("detaches a session before slow teardown so repeated DELETE cannot close twice", async () => {
    const gate = deferred();
    const active = makeFakeClient();
    active.cleanup.mockImplementation(() => gate.promise);
    session("owner", { server: active });
    internals.idleSessions.server = makeFakeClient();
    const first = pool.cleanupSession("owner");
    const second = pool.cleanupSession("owner");
    gate.resolve();
    await Promise.all([first, second]);
    expect(active.cleanup).toHaveBeenCalledTimes(1);
  });

  it.each([false, true])(
    "settles concurrent final releases once despite earlier slow clients, idle=%s",
    async (occupied) => {
      const gate = deferred();
      const slowA = makeFakeClient();
      const slowB = makeFakeClient();
      slowA.cleanup.mockImplementation(() => gate.promise);
      slowB.cleanup.mockImplementation(() => gate.promise);
      const shared = makeFakeClient();
      session("owner", { slowA, shared });
      session("borrower", { slowB, shared });
      internals.idleSessions.slowA = makeFakeClient();
      internals.idleSessions.slowB = makeFakeClient();
      if (occupied) internals.idleSessions.shared = makeFakeClient();
      const pending = Promise.all([
        pool.cleanupSession("owner"),
        pool.cleanupSession("borrower"),
      ]);
      gate.resolve();
      await pending;
      expect(internals.activeSessions).toEqual({});
      if (occupied) expect(shared.cleanup).toHaveBeenCalledTimes(1);
      else {
        expect(shared.cleanup).not.toHaveBeenCalled();
        expect(internals.idleSessions.shared).toBe(shared);
      }
    },
  );

  it("keeps unrelated owners and idle clients while disposing a private connection", async () => {
    const privateClient = makeFakeClient();
    const other = makeFakeClient();
    session("owner", { server: privateClient });
    session("unrelated", { neighbor: other });
    internals.idleSessions.server = makeFakeClient();
    await pool.cleanupSession("owner");
    expect(privateClient.cleanup).toHaveBeenCalledTimes(1);
    expect(internals.activeSessions.unrelated.neighbor).toBe(other);
    expect(other.cleanup).not.toHaveBeenCalled();
  });

  it("isolates failed teardown while removing every released session control", async () => {
    const failed = makeFakeClient();
    failed.cleanup.mockRejectedValue(new Error("fixture close failed"));
    const healthy = makeFakeClient();
    session("owner", { failed, healthy });
    internals.idleSessions.failed = makeFakeClient();
    internals.idleSessions.healthy = makeFakeClient();
    await pool.cleanupSession("owner");
    expect(healthy.cleanup).toHaveBeenCalledTimes(1);
    expect(internals.activeSessions.owner).toBeUndefined();
    expect(internals.sessionToServers.owner).toBeUndefined();
  });

  it("continues ownership decisions after a synchronous teardown failure", async () => {
    const failed = makeFakeClient();
    failed.cleanup.mockImplementation(() => {
      throw new Error("fixture synchronous close failure");
    });
    const healthy = makeFakeClient();
    session("owner", { failed, healthy });
    internals.idleSessions.failed = makeFakeClient();
    internals.idleSessions.healthy = makeFakeClient();
    await pool.cleanupSession("owner");
    expect(failed.cleanup).toHaveBeenCalledTimes(1);
    expect(healthy.cleanup).toHaveBeenCalledTimes(1);
    expect(internals.activeSessions.owner).toBeUndefined();
  });

  it("shutdown destroys a shared connection exactly once after all owners release it", async () => {
    const shared = makeFakeClient();
    session("owner", { server: shared });
    session("borrower", { server: shared });
    await pool.cleanupAll();
    expect(shared.cleanup).toHaveBeenCalledTimes(1);
    expect(internals.activeSessions).toEqual({});
    expect(internals.idleSessions).toEqual({});
  });
});
