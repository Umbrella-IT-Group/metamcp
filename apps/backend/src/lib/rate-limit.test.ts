/**
 * Unit tests for `SlidingWindowRateLimiting.onRequest`.
 *
 * Regression test for the has(key) vs has(namespace_uuid) defect ported
 * from upstream metamcp PR #258 (elvus, "rate-limit-and-deps", commit
 * adc1e7ee73b0e59e18179ca4b463d4b7f43d5acb): the per-client inner Map is
 * keyed by `namespace_uuid` (see the `new Map().set(namespace_uuid, ...)`
 * a few lines above), but the reuse check tested `limiter.has(key)` --
 * looking for the client key inside a map whose keys are namespace UUIDs,
 * which is essentially never true. That caused the already-tracked
 * SlidingWindowRateLimiter for a namespace to be silently replaced (losing
 * its accumulated request history) instead of reused, so the client rate
 * limit was never enforced.
 *
 * The mock `backgroundIdleSessions` map below always reports "not yet
 * initialized" (`has()` -> false), modeling the per-(namespace,client)
 * init gate staying open on every call -- which mirrors the idle-session
 * churn that repeatedly reopens it in production -- so the test isolates
 * the has(key) defect itself rather than the gate's own churn semantics.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("./metamcp/mcp-server-pool", () => ({
  mcpServerPool: {
    getBackgroundIdleSessionsByNamespace: vi.fn(),
  },
}));

import { mcpServerPool } from "./metamcp/mcp-server-pool";
import { RateLimitError, SlidingWindowRateLimiting } from "./rate-limit";

const NAMESPACE_UUID = "ns-1111-1111";
const CLIENT_KEY = "203.0.113.7";

function makeContext() {
  return {
    req: {
      endpoint: {
        namespace_uuid: NAMESPACE_UUID,
        client_max_rate: 2,
        client_max_rate_seconds: 60,
        client_max_rate_strategy: "ip",
        client_max_rate_strategy_key: "x-forwarded-for",
      },
      socket: { remoteAddress: "unused" },
      headers: { "x-forwarded-for": CLIENT_KEY },
    },
  };
}

function mockOpenIdleGate() {
  // Per-namespace map: status is always "created" and has() always
  // reports false, so the "not yet initialized for this client" gate in
  // onRequest stays open on every call -- reproducing the production
  // idle-session churn that repeatedly reopens it.
  const perNamespace = {
    get: (k: string) => (k === "status" ? "created" : undefined),
    has: () => false,
    set: vi.fn(),
  };
  const backgroundIdleSessions = new Map<string, any>([
    [NAMESPACE_UUID, perNamespace],
  ]);
  (
    mcpServerPool.getBackgroundIdleSessionsByNamespace as unknown as ReturnType<
      typeof vi.fn
    >
  ).mockReturnValue(backgroundIdleSessions);
}

describe("SlidingWindowRateLimiting", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockOpenIdleGate();
  });

  it("keys the per-client limiter map on namespace_uuid and reuses it across calls", async () => {
    const rateLimiting = new SlidingWindowRateLimiting();
    const callNext = vi.fn().mockResolvedValue("ok");

    await rateLimiting.onRequest(makeContext() as any, callNext);
    const limiterAfterFirstCall = (rateLimiting as any).limiters
      .get(CLIENT_KEY)
      ?.get(NAMESPACE_UUID);
    expect(limiterAfterFirstCall).toBeDefined();

    await rateLimiting.onRequest(makeContext() as any, callNext);
    const limiterAfterSecondCall = (rateLimiting as any).limiters
      .get(CLIENT_KEY)
      ?.get(NAMESPACE_UUID);

    // The fix keys the reuse check on namespace_uuid, so the SAME
    // SlidingWindowRateLimiter instance -- and its accumulated request
    // history -- must survive across calls for the same namespace.
    expect(limiterAfterSecondCall).toBe(limiterAfterFirstCall);
  });

  it("enforces client_max_rate once the window fills for the same namespace", async () => {
    const rateLimiting = new SlidingWindowRateLimiting();
    const callNext = vi.fn().mockResolvedValue("ok");

    // client_max_rate is 2: the first two calls must pass. The third
    // must be rejected IF the limiter is reused (fix) -- with the
    // has(key) bug present, every call gets a brand new limiter with an
    // empty window, so the third call wrongly passes too and the limit
    // is never hit.
    await rateLimiting.onRequest(makeContext() as any, callNext);
    await rateLimiting.onRequest(makeContext() as any, callNext);

    await expect(
      rateLimiting.onRequest(makeContext() as any, callNext),
    ).rejects.toThrow(RateLimitError);

    expect(callNext).toHaveBeenCalledTimes(2);
  });
});
