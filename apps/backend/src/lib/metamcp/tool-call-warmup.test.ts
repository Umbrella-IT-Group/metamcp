import { ServerParameters } from "@repo/zod-types";
import { describe, expect, it, vi } from "vitest";

import { ConnectedClient } from "./client";
import {
  acquireSessionWithBoundedWarmup,
  ToolCallWarmupPool,
} from "./tool-call-warmup";

const makeSession = (label: string): ConnectedClient =>
  ({ label }) as unknown as ConnectedClient;

const params = { uuid: "server-1", name: "test-server" } as ServerParameters;

// A getSession mock that never settles — models a connect attempt still
// in flight or backing off when the caller's bounded wait expires.
const pending = () => new Promise<ConnectedClient | undefined>(() => {});

const baseOpts = (pool: ToolCallWarmupPool, timeoutMs: number) => ({
  pool,
  sessionId: "session-abc",
  serverUuid: "server-1",
  params,
  namespaceUuid: "ns-1",
  timeoutMs,
});

describe("acquireSessionWithBoundedWarmup", () => {
  it("returns the session on the first attempt when getSession resolves before the cap", async () => {
    const session = makeSession("fresh");
    const pool: ToolCallWarmupPool = {
      getSession: vi.fn().mockResolvedValue(session),
    };

    const result = await acquireSessionWithBoundedWarmup(baseOpts(pool, 1000));

    expect(result).toBe(session);
    expect(pool.getSession).toHaveBeenCalledTimes(1);
    expect(pool.getSession).toHaveBeenCalledWith(
      "session-abc",
      "server-1",
      params,
      "ns-1",
    );
  });

  it("retries once when the first attempt doesn't settle before the cap, and returns the retry's session", async () => {
    const session = makeSession("reconnected");
    const getSession = vi
      .fn()
      .mockImplementationOnce(pending)
      .mockResolvedValueOnce(session);
    const pool: ToolCallWarmupPool = { getSession };

    const result = await acquireSessionWithBoundedWarmup(baseOpts(pool, 20));

    expect(result).toBe(session);
    expect(getSession).toHaveBeenCalledTimes(2);
  });

  it("is bounded — returns undefined (never hangs) once every attempt is exhausted", async () => {
    const getSession = vi.fn().mockImplementation(pending);
    const pool: ToolCallWarmupPool = { getSession };

    const start = Date.now();
    const result = await acquireSessionWithBoundedWarmup(baseOpts(pool, 20));
    const elapsedMs = Date.now() - start;

    expect(result).toBeUndefined();
    expect(getSession).toHaveBeenCalledTimes(2);
    // Worst case is attempts * timeoutMs (2 * 20ms). Generous upper
    // bound below just proves this isn't an unbounded hang, not a tight
    // timing assertion.
    expect(elapsedMs).toBeLessThan(2000);
  });

  it("honors a custom attempts count instead of the default retry-once", async () => {
    const getSession = vi.fn().mockImplementation(pending);
    const pool: ToolCallWarmupPool = { getSession };

    const result = await acquireSessionWithBoundedWarmup({
      ...baseOpts(pool, 10),
      attempts: 1,
    });

    expect(result).toBeUndefined();
    expect(getSession).toHaveBeenCalledTimes(1);
  });

  it("treats a rejected getSession call as undefined rather than throwing", async () => {
    // Defensive branch: mcp-server-pool.ts's getSession never rejects
    // today, but this guards against a future regression there turning
    // into an unhandled rejection here.
    const getSession = vi.fn().mockRejectedValue(new Error("boom"));
    const pool: ToolCallWarmupPool = { getSession };

    await expect(
      acquireSessionWithBoundedWarmup(baseOpts(pool, 10)),
    ).resolves.toBeUndefined();
    expect(getSession).toHaveBeenCalledTimes(2);
  });
});
