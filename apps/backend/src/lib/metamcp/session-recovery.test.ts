import { describe, expect, it, vi } from "vitest";

vi.mock("@/utils/logger", () => ({
  default: { error: vi.fn(), warn: vi.fn(), info: vi.fn(), debug: vi.fn() },
}));

import type { ConnectedClient } from "./client";
import {
  recoverFailedSession,
  SessionRecoveries,
  SessionRecoveryPool,
} from "./session-recovery";

const client = (label: string) =>
  ({ label, listChangedSubscribers: new Set() }) as unknown as ConnectedClient;

function fakePool(pooled = true) {
  let isPooled = pooled;
  const pool = {
    isPooledClient: vi.fn(() => isPooled),
    invalidateServerConnection: vi.fn(async () => {
      isPooled = false;
    }),
  } satisfies SessionRecoveryPool;
  return pool;
}

const deferred = <T>() => {
  let resolve: (value: T) => void = () => undefined;
  const promise = new Promise<T>((r) => {
    resolve = r;
  });
  return { promise, resolve };
};

describe("recoverFailedSession", () => {
  it("shares one invalidation and one acquisition among concurrent failures on one client", async () => {
    const pool = fakePool();
    const recoveries: SessionRecoveries = new WeakMap();
    const stale = client("stale");
    const fresh = client("fresh");
    const acquired = deferred<ConnectedClient | undefined>();
    const reacquire = vi.fn(() => acquired.promise);

    const waiting = Array.from({ length: 8 }, () =>
      recoverFailedSession({
        pool,
        recoveries,
        sessionId: "s",
        serverUuid: "u",
        failedClient: stale,
        reacquire,
      }),
    );
    acquired.resolve(fresh);

    expect(await Promise.all(waiting)).toEqual(
      Array.from({ length: 8 }, () => fresh),
    );
    expect(pool.invalidateServerConnection).toHaveBeenCalledTimes(1);
    expect(reacquire).toHaveBeenCalledTimes(1);
  });

  it("skips the invalidation when the failed client no longer holds a pool slot", async () => {
    const pool = fakePool(false);
    const fresh = client("fresh");

    const result = await recoverFailedSession({
      pool,
      recoveries: new WeakMap(),
      sessionId: "s",
      serverUuid: "u",
      failedClient: client("retired"),
      reacquire: async () => fresh,
    });

    expect(result).toBe(fresh);
    expect(pool.invalidateServerConnection).not.toHaveBeenCalled();
  });

  it("hands a late failure on the same dead client the replacement, with no second cascade", async () => {
    const pool = fakePool();
    const recoveries: SessionRecoveries = new WeakMap();
    const stale = client("stale");
    const fresh = client("fresh");
    const reacquire = vi.fn(async () => fresh);
    const options = {
      pool,
      recoveries,
      sessionId: "s",
      serverUuid: "u",
      failedClient: stale,
      reacquire,
    };

    await recoverFailedSession(options);
    const late = await recoverFailedSession(options);

    expect(late).toBe(fresh);
    expect(pool.invalidateServerConnection).toHaveBeenCalledTimes(1);
    expect(reacquire).toHaveBeenCalledTimes(1);
  });

  it("forgets a recovery that produced no session, so the next failure tries again", async () => {
    const pool = fakePool();
    const recoveries: SessionRecoveries = new WeakMap();
    const stale = client("stale");
    const fresh = client("fresh");
    const reacquire = vi
      .fn<() => Promise<ConnectedClient | undefined>>()
      .mockResolvedValueOnce(undefined)
      .mockResolvedValueOnce(fresh);
    const options = {
      pool,
      recoveries,
      sessionId: "s",
      serverUuid: "u",
      failedClient: stale,
      reacquire,
    };

    expect(await recoverFailedSession(options)).toBeUndefined();
    // Let the settle handler run.
    await Promise.resolve();
    expect(await recoverFailedSession(options)).toBe(fresh);
    expect(reacquire).toHaveBeenCalledTimes(2);
  });

  it("rejects every waiter with the acquisition's error, then forgets it", async () => {
    const pool = fakePool();
    const recoveries: SessionRecoveries = new WeakMap();
    const stale = client("stale");
    const gone = new Error("server no longer present");
    const reacquire = vi
      .fn<() => Promise<ConnectedClient | undefined>>()
      .mockRejectedValueOnce(gone)
      .mockResolvedValueOnce(client("fresh"));
    const options = {
      pool,
      recoveries,
      sessionId: "s",
      serverUuid: "u",
      failedClient: stale,
      reacquire,
    };

    const first = recoverFailedSession(options);
    const second = recoverFailedSession(options);
    await expect(first).rejects.toBe(gone);
    await expect(second).rejects.toBe(gone);
    await Promise.resolve();

    await expect(recoverFailedSession(options)).resolves.toBeDefined();
    expect(reacquire).toHaveBeenCalledTimes(2);
  });

  it("keeps recoveries of different failed clients apart", async () => {
    const pool = fakePool();
    const recoveries: SessionRecoveries = new WeakMap();
    const freshA = client("freshA");
    const freshB = client("freshB");

    const a = recoverFailedSession({
      pool,
      recoveries,
      sessionId: "s",
      serverUuid: "a",
      failedClient: client("staleA"),
      reacquire: async () => freshA,
    });
    const b = recoverFailedSession({
      pool,
      recoveries,
      sessionId: "s",
      serverUuid: "b",
      failedClient: client("staleB"),
      reacquire: async () => freshB,
    });

    expect(await a).toBe(freshA);
    expect(await b).toBe(freshB);
  });
});
