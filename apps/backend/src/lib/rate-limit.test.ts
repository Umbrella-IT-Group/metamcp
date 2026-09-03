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

vi.mock("../utils/logger", () => ({
  default: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

import logger from "../utils/logger";
import { mcpServerPool } from "./metamcp/mcp-server-pool";
import {
  RateLimitError,
  RateLimiting,
  SlidingWindowRateLimiter,
  SlidingWindowRateLimiting,
} from "./rate-limit";

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
        // Empty override -> the default key, which is now the edge-overwritten
        // CF-Connecting-IP rather than the forgeable XFF.
        client_max_rate_strategy_key: "",
      },
      socket: { remoteAddress: "unused" },
      headers: { "cf-connecting-ip": CLIENT_KEY },
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
    // The real inner map is a Map; cleanup() clears the marker in lockstep
    // with the limiter, so the double must answer delete too.
    delete: vi.fn(),
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

/**
 * The STABLE-namespace gate: a real per-namespace Map that actually records
 * the "initialized" marker (status pre-set to "created"), so `has(clientKey)`
 * flips true after the first request the way production does when the idle
 * session is not churning. This is the only setup that exposes the sweep's
 * marker-consistency requirement -- the always-open gate above masks it by
 * reopening on every call.
 */
function mockStableIdleGate() {
  const perNamespace = new Map<string, any>();
  perNamespace.set("status", "created");
  const backgroundIdleSessions = new Map<string, any>([
    [NAMESPACE_UUID, perNamespace],
  ]);
  (
    mcpServerPool.getBackgroundIdleSessionsByNamespace as unknown as ReturnType<
      typeof vi.fn
    >
  ).mockReturnValue(backgroundIdleSessions);
  return { perNamespace, backgroundIdleSessions };
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

/**
 * The per-client bucket must key on the edge-overwritten
 * CF-Connecting-IP, never on a caller-settable forwarding header. Keying on a
 * forgeable header lets a caller rotate it to mint a fresh bucket per request,
 * so the limit enforces nothing.
 */
describe("SlidingWindowRateLimiting -- client key selection", () => {
  const bothHeaders = () => ({
    "cf-connecting-ip": "9.9.9.9",
    "x-forwarded-for": "1.2.3.4",
  });

  const contextWithKey = (
    strategyKey: string,
    headers: Record<string, any>,
  ) => ({
    req: {
      endpoint: {
        namespace_uuid: NAMESPACE_UUID,
        client_max_rate: 5,
        client_max_rate_seconds: 60,
        client_max_rate_strategy: "ip",
        client_max_rate_strategy_key: strategyKey,
      },
      socket: { remoteAddress: "socket-addr" },
      headers,
    },
  });

  it("keys on cf-connecting-ip by default, ignoring a spoofable x-forwarded-for", async () => {
    const rl = new SlidingWindowRateLimiting();
    const callNext = vi.fn().mockResolvedValue("ok");

    await rl.onRequest(contextWithKey("", bothHeaders()) as any, callNext);

    expect((rl as any).limiters.has("9.9.9.9")).toBe(true);
    expect((rl as any).limiters.has("1.2.3.4")).toBe(false);
  });

  it("refuses a forgeable x-forwarded-for override and falls back to cf-connecting-ip", async () => {
    const rl = new SlidingWindowRateLimiting();
    const callNext = vi.fn().mockResolvedValue("ok");

    await rl.onRequest(
      contextWithKey("x-forwarded-for", bothHeaders()) as any,
      callNext,
    );

    // Keyed on the edge header, not the header the override named.
    expect((rl as any).limiters.has("9.9.9.9")).toBe(true);
    expect((rl as any).limiters.has("1.2.3.4")).toBe(false);
    expect(logger.warn).toHaveBeenCalled();
  });

  it("honors a non-forgeable custom header override", async () => {
    const rl = new SlidingWindowRateLimiting();
    const callNext = vi.fn().mockResolvedValue("ok");

    await rl.onRequest(
      contextWithKey("x-consumer-id", {
        ...bothHeaders(),
        "x-consumer-id": "consumer-42",
      }) as any,
      callNext,
    );

    expect((rl as any).limiters.has("consumer-42")).toBe(true);
    expect((rl as any).limiters.has("9.9.9.9")).toBe(false);
  });
});

/**
 * The per-(client, namespace) map is never pruned by the request path,
 * so it needs its own sweep. `cleanup` drops limiters whose window has fully
 * drained and leaves live ones in place.
 */
describe("SlidingWindowRateLimiting.cleanup -- eviction sweep", () => {
  it("drops a limiter once its window has fully drained", async () => {
    vi.useFakeTimers();
    try {
      vi.setSystemTime(new Date("2026-01-01T00:00:00Z"));
      const rl = new SlidingWindowRateLimiting();
      const callNext = vi.fn().mockResolvedValue("ok");

      await rl.onRequest(makeContext() as any, callNext);
      expect((rl as any).limiters.has(CLIENT_KEY)).toBe(true);

      // +120s, past the 60s window: the only recorded request has aged out.
      vi.setSystemTime(new Date("2026-01-01T00:02:00Z"));
      rl.cleanup();

      expect((rl as any).limiters.has(CLIENT_KEY)).toBe(false);
    } finally {
      vi.useRealTimers();
    }
  });

  it("keeps a limiter whose newest request is still inside the window", async () => {
    vi.useFakeTimers();
    try {
      vi.setSystemTime(new Date("2026-01-01T00:00:00Z"));
      const rl = new SlidingWindowRateLimiting();
      const callNext = vi.fn().mockResolvedValue("ok");

      await rl.onRequest(makeContext() as any, callNext);

      // +30s, still inside the 60s window.
      vi.setSystemTime(new Date("2026-01-01T00:00:30Z"));
      rl.cleanup();

      expect((rl as any).limiters.has(CLIENT_KEY)).toBe(true);
    } finally {
      vi.useRealTimers();
    }
  });

  it("reports an empty limiter as expired", () => {
    const limiter = new SlidingWindowRateLimiter(2, 60);
    expect(limiter.isExpired()).toBe(true);
  });

  it("re-limits a returning client after the sweep evicts its drained limiter", async () => {
    // The stable-namespace case the always-open gate cannot show: once the pool
    // marks a (client, namespace) initialized, the marker sticks, so the sweep
    // MUST clear it alongside the limiter. Otherwise the returning client takes
    // the skip-creation path with no limiter -- an unlimited pass. Without the
    // marker delete in cleanup(), the third call below would NOT throw.
    vi.useFakeTimers();
    try {
      vi.setSystemTime(new Date("2026-01-01T00:00:00Z"));
      mockStableIdleGate();
      const rl = new SlidingWindowRateLimiting();
      const callNext = vi.fn().mockResolvedValue("ok");

      // Budget is 2 per 60s (makeContext): exhaust it.
      await rl.onRequest(makeContext() as any, callNext);
      await rl.onRequest(makeContext() as any, callNext);
      await expect(
        rl.onRequest(makeContext() as any, callNext),
      ).rejects.toThrow(RateLimitError);

      // Idle past the window; the sweep evicts the drained limiter and clears
      // the marker.
      vi.setSystemTime(new Date("2026-01-01T00:02:00Z"));
      rl.cleanup();
      expect((rl as any).limiters.has(CLIENT_KEY)).toBe(false);

      // The returning client is limited again from a fresh budget, not waved
      // through: two pass, the third is refused.
      await rl.onRequest(makeContext() as any, callNext);
      await rl.onRequest(makeContext() as any, callNext);
      await expect(
        rl.onRequest(makeContext() as any, callNext),
      ).rejects.toThrow(RateLimitError);
    } finally {
      vi.useRealTimers();
    }
  });
});

/**
 * The token-bucket path treated an absent limiter as rate-limited and
 * answered a spurious 503. A namespace with no created limiter must pass
 * through; a created, over-budget limiter must still refuse.
 */
describe("RateLimiting.onRequest -- token bucket", () => {
  const idleSessions = (status: string, hasUser: boolean) => {
    const perNamespace = {
      get: (k: string) => (k === "status" ? status : undefined),
      has: () => hasUser,
      set: vi.fn(),
    };
    const map = new Map<string, any>([[NAMESPACE_UUID, perNamespace]]);
    (
      mcpServerPool.getBackgroundIdleSessionsByNamespace as unknown as ReturnType<
        typeof vi.fn
      >
    ).mockReturnValue(map);
  };

  const tokenBucketContext = () => ({
    req: {
      endpoint: {
        namespace_uuid: NAMESPACE_UUID,
        user_id: "user-1",
        max_rate: 0,
        max_rate_seconds: 1,
      },
    },
  });

  it("passes through when no limiter was created for the namespace", async () => {
    // Idle sessions exist (size > 0) but this namespace is not "created", so no
    // limiter is ever built. Before the fix this threw a spurious RateLimitError.
    idleSessions("not-created", false);

    const rl = new RateLimiting();
    const callNext = vi.fn().mockResolvedValue("ok");

    await expect(
      rl.onRequest(tokenBucketContext() as any, callNext),
    ).resolves.toBe("ok");
    expect(callNext).toHaveBeenCalledTimes(1);
  });

  it("still refuses when a created limiter is over budget", async () => {
    // status "created" + user not yet initialized -> a limiter is created; a
    // zero-capacity bucket refuses the first consume, proving enforcement is
    // intact after the missing-limiter guard.
    idleSessions("created", false);

    const rl = new RateLimiting();
    const callNext = vi.fn().mockResolvedValue("ok");

    await expect(
      rl.onRequest(tokenBucketContext() as any, callNext),
    ).rejects.toThrow(RateLimitError);
    expect(callNext).not.toHaveBeenCalled();
  });
});
