import { inspect } from "node:util";

import { StreamableHTTPError } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { ServerParameters } from "@repo/zod-types";
import { describe, expect, it, vi } from "vitest";

import logger from "@/utils/logger";

import { ConnectedClient } from "./client";
import {
  RecoverySessionPool,
  requestWithSessionRecovery,
} from "./list-handler-recovery";

// The exact envelope shape the backend produces when its session died
// (matches session-error.test.ts fixtures). isRecoverableBackendError
// must classify it as recoverable.
const sessionLostError = () =>
  new Error(
    'Error POSTing to endpoint (HTTP 404): {"jsonrpc":"2.0","id":"server-error","error":{"code":-32600,"message":"Session not found"}}',
  );

const transportLostError = () => new Error("Not connected");

const makeSession = (label: string): ConnectedClient =>
  ({ label }) as unknown as ConnectedClient;

const params = { uuid: "server-1", name: "test-server" } as ServerParameters;

const makePool = (freshSession: ConnectedClient | undefined) => {
  const pool: RecoverySessionPool = {
    invalidateServerConnection: vi.fn().mockResolvedValue(undefined),
    getSession: vi.fn().mockResolvedValue(freshSession),
  };
  return pool;
};

const baseOpts = (pool: RecoverySessionPool, session: ConnectedClient) => ({
  pool,
  sessionId: "session-abc",
  serverUuid: "server-1",
  params,
  namespaceUuid: "ns-1",
  operation: "tools/list",
  serverName: "test-server",
  session,
});

describe("requestWithSessionRecovery", () => {
  it("returns the first attempt's result without touching the pool", async () => {
    const session = makeSession("stale");
    const pool = makePool(undefined);
    const attempt = vi.fn().mockResolvedValue(["tool-a"]);

    const result = await requestWithSessionRecovery({
      ...baseOpts(pool, session),
      attempt,
    });

    expect(result).toEqual(["tool-a"]);
    expect(attempt).toHaveBeenCalledTimes(1);
    expect(attempt).toHaveBeenCalledWith(session);
    expect(pool.invalidateServerConnection).not.toHaveBeenCalled();
    expect(pool.getSession).not.toHaveBeenCalled();
  });

  it("invalidates, re-acquires, and retries once on a session-lost envelope", async () => {
    const stale = makeSession("stale");
    const fresh = makeSession("fresh");
    const pool = makePool(fresh);
    const attempt = vi
      .fn()
      .mockRejectedValueOnce(sessionLostError())
      .mockResolvedValueOnce(["tool-b"]);
    const onFreshSession = vi.fn();

    const result = await requestWithSessionRecovery({
      ...baseOpts(pool, stale),
      attempt,
      onFreshSession,
    });

    expect(result).toEqual(["tool-b"]);
    expect(pool.invalidateServerConnection).toHaveBeenCalledWith(
      "session-abc",
      "server-1",
    );
    expect(pool.getSession).toHaveBeenCalledWith(
      "session-abc",
      "server-1",
      params,
      "ns-1",
    );
    expect(onFreshSession).toHaveBeenCalledWith(fresh);
    expect(attempt).toHaveBeenNthCalledWith(1, stale);
    expect(attempt).toHaveBeenNthCalledWith(2, fresh);
  });

  it("recovers from the SDK transport-lost envelope too", async () => {
    const stale = makeSession("stale");
    const fresh = makeSession("fresh");
    const pool = makePool(fresh);
    const attempt = vi
      .fn()
      .mockRejectedValueOnce(transportLostError())
      .mockResolvedValueOnce("ok");

    await expect(
      requestWithSessionRecovery({ ...baseOpts(pool, stale), attempt }),
    ).resolves.toBe("ok");
    expect(pool.invalidateServerConnection).toHaveBeenCalledTimes(1);
  });

  it("rethrows non-recoverable errors without invalidating the pool", async () => {
    const session = makeSession("stale");
    const pool = makePool(undefined);
    const boom = new Error("schema validation failed");
    const attempt = vi.fn().mockRejectedValue(boom);

    await expect(
      requestWithSessionRecovery({ ...baseOpts(pool, session), attempt }),
    ).rejects.toBe(boom);
    expect(pool.invalidateServerConnection).not.toHaveBeenCalled();
    expect(attempt).toHaveBeenCalledTimes(1);
  });

  it("throws a re-init error when no fresh session can be established", async () => {
    const session = makeSession("stale");
    const pool = makePool(undefined);
    const attempt = vi.fn().mockRejectedValue(sessionLostError());

    await expect(
      requestWithSessionRecovery({ ...baseOpts(pool, session), attempt }),
    ).rejects.toThrow(
      /Failed to re-initialize session for server server-1 .* tools\/list/,
    );
    expect(attempt).toHaveBeenCalledTimes(1);
  });

  it("propagates the retry's failure when the fresh session also fails", async () => {
    const stale = makeSession("stale");
    const fresh = makeSession("fresh");
    const pool = makePool(fresh);
    const secondFailure = new Error("backend exploded after reconnect");
    const attempt = vi
      .fn()
      .mockRejectedValueOnce(sessionLostError())
      .mockRejectedValueOnce(secondFailure);

    await expect(
      requestWithSessionRecovery({ ...baseOpts(pool, stale), attempt }),
    ).rejects.toBe(secondFailure);
    expect(attempt).toHaveBeenCalledTimes(2);
  });
});

describe("requestWithSessionRecovery envelope line for a backend refusal", () => {
  // A refusal whose body happens to read as a lost connection is still
  // recoverable (the detector matches the body text), so the recovery runs and
  // its WARN quotes the failure. The status stays, the backend's text does not.
  const BODY_SECRET = "backend-body-text-that-must-not-be-logged";
  const refusal = (status: number, body: string) =>
    new StreamableHTTPError(status, `Error POSTing to endpoint: ${body}`);

  it.each([401, 403] as const)(
    "names HTTP %s and keeps the response body out of the line",
    async (status) => {
      const warn = vi.spyOn(logger, "warn").mockImplementation(() => undefined);
      const attempt = vi
        .fn()
        .mockRejectedValueOnce(refusal(status, `Not connected ${BODY_SECRET}`))
        .mockResolvedValueOnce(["tool-a"]);

      await requestWithSessionRecovery({
        ...baseOpts(makePool(makeSession("fresh")), makeSession("stale")),
        attempt,
      });

      expect(attempt).toHaveBeenCalledTimes(2);
      expect(inspect(warn.mock.calls)).toContain(`HTTP ${status}`);
      expect(inspect(warn.mock.calls)).not.toContain(BODY_SECRET);
      warn.mockRestore();
    },
  );

  it("keeps the diagnostic text for a non-refusal envelope (negative control)", async () => {
    const warn = vi.spyOn(logger, "warn").mockImplementation(() => undefined);
    const attempt = vi
      .fn()
      .mockRejectedValueOnce(sessionLostError())
      .mockResolvedValueOnce(["tool-a"]);

    await requestWithSessionRecovery({
      ...baseOpts(makePool(makeSession("fresh")), makeSession("stale")),
      attempt,
    });

    expect(inspect(warn.mock.calls)).toContain("Session not found");
    warn.mockRestore();
  });
});
