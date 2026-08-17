/**
 * Retention is a promise about a floor, so the floor is what gets tested —
 * and it is tested as EFFECTIVE, not merely as parsed.
 *
 * A pure clamp function that returns 30 for an input of 29 proves nothing on
 * its own: the failure that matters is a clamp that exists and is then not
 * the number the sweeper actually deletes with. So the suite covers both
 * halves — the function, and the value `pruneGatewayEvents()` passes to the
 * repository after the module has read the environment for real.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { loggerMock } = vi.hoisted(() => ({
  loggerMock: {
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  },
}));

vi.mock("@/utils/logger", () => ({ default: loggerMock }));

type RetentionModule = typeof import("./retention");

/**
 * Load `retention.ts` with a given env value.
 *
 * `resetModules` is load-bearing: the effective retention is parsed ONCE at
 * module load (so the WARN fires at boot rather than every five minutes on the
 * cleanup interval), which means a fresh module instance is the only way to
 * observe a different environment.
 */
async function loadWithEnv(
  value: string | undefined,
): Promise<RetentionModule> {
  vi.resetModules();
  if (value === undefined) {
    delete process.env.GATEWAY_EVENTS_RETENTION_DAYS;
  } else {
    process.env.GATEWAY_EVENTS_RETENTION_DAYS = value;
  }
  return import("./retention");
}

const originalEnv = process.env.GATEWAY_EVENTS_RETENTION_DAYS;

beforeEach(() => {
  vi.clearAllMocks();
});

afterEach(() => {
  if (originalEnv === undefined) {
    delete process.env.GATEWAY_EVENTS_RETENTION_DAYS;
  } else {
    process.env.GATEWAY_EVENTS_RETENTION_DAYS = originalEnv;
  }
});

describe("resolveGatewayEventsRetentionDays", () => {
  it("defaults to 90 when unset or empty", async () => {
    const { resolveGatewayEventsRetentionDays } = await loadWithEnv(undefined);

    expect(resolveGatewayEventsRetentionDays(undefined)).toBe(90);
    expect(resolveGatewayEventsRetentionDays("")).toBe(90);
    expect(resolveGatewayEventsRetentionDays("   ")).toBe(90);
  });

  it("honours a value at or above the floor", async () => {
    const { resolveGatewayEventsRetentionDays } = await loadWithEnv(undefined);

    expect(resolveGatewayEventsRetentionDays("30")).toBe(30);
    expect(resolveGatewayEventsRetentionDays("365")).toBe(365);
  });

  it("clamps 29 UP to 30, with a WARN naming the reason", async () => {
    const { resolveGatewayEventsRetentionDays } = await loadWithEnv(undefined);

    expect(resolveGatewayEventsRetentionDays("29")).toBe(30);
    expect(loggerMock.warn).toHaveBeenCalledTimes(1);
    const line = String(loggerMock.warn.mock.calls[0][0]);
    expect(line).toContain("GATEWAY_EVENTS_RETENTION_DAYS=29");
    expect(line).toContain("30-day immutability window");
  });

  it("clamps 0 and negatives to the floor rather than meaning 'keep forever'", async () => {
    const { resolveGatewayEventsRetentionDays } = await loadWithEnv(undefined);

    // Deliberately unlike TOOL_AUDIT_RETENTION_DAYS, where <=0 disables the
    // prune. On a table with this write rate, "keep forever" is an
    // unbounded-growth setting, and the floor must not be reachable from below.
    expect(resolveGatewayEventsRetentionDays("0")).toBe(30);
    expect(resolveGatewayEventsRetentionDays("-1")).toBe(30);
  });

  it("falls back to the default on a non-numeric value, with a WARN", async () => {
    const { resolveGatewayEventsRetentionDays } = await loadWithEnv(undefined);

    expect(resolveGatewayEventsRetentionDays("forever")).toBe(90);
    expect(loggerMock.warn).toHaveBeenCalledTimes(1);
    expect(String(loggerMock.warn.mock.calls[0][0])).toContain(
      "is not a number",
    );
  });

  it("rejects a value that only STARTS as a number, rather than reading a prefix", async () => {
    const { resolveGatewayEventsRetentionDays } = await loadWithEnv(undefined);

    // `Number.parseInt` is not a validator: it takes the leading integer and
    // discards the rest, so a typo would take effect as a number the operator
    // never wrote — "1e9" silently meaning one day is the worst of them, since
    // it clamps to the floor and looks deliberate.
    expect(resolveGatewayEventsRetentionDays("30abc")).toBe(90);
    expect(resolveGatewayEventsRetentionDays("1e9")).toBe(90);
    expect(resolveGatewayEventsRetentionDays("90 days")).toBe(90);
    expect(loggerMock.warn).toHaveBeenCalledTimes(3);
  });

  it("still accepts an integer with surrounding whitespace", async () => {
    const { resolveGatewayEventsRetentionDays } = await loadWithEnv(undefined);

    // A trailing space in an env file is a formatting accident, not a typo in
    // the value; rejecting it would turn one into the other.
    expect(resolveGatewayEventsRetentionDays(" 120 ")).toBe(120);
    expect(loggerMock.warn).not.toHaveBeenCalled();
  });
});

describe("the clamp is EFFECTIVE, not just computed", () => {
  it("GATEWAY_EVENTS_RETENTION_DAYS reads 30 when the environment says 29", async () => {
    const { GATEWAY_EVENTS_RETENTION_DAYS } = await loadWithEnv("29");

    expect(GATEWAY_EVENTS_RETENTION_DAYS).toBe(30);
    // The boot-time WARN, fired on module load rather than per sweep.
    expect(loggerMock.warn).toHaveBeenCalledTimes(1);
  });

  it("pruneGatewayEvents DELETES with the clamped value, not the raw one", async () => {
    const { pruneGatewayEvents, setGatewayEventsPrunerForTesting } =
      await loadWithEnv("29");

    const pruner = vi.fn().mockResolvedValue(undefined);
    setGatewayEventsPrunerForTesting(pruner);

    await pruneGatewayEvents();

    // The assertion the placebo-cap failure mode needs: a clamp nothing reads
    // is not a clamp.
    expect(pruner).toHaveBeenCalledWith(30);
  });

  it("pruneGatewayEvents passes an honoured value through unchanged", async () => {
    const { pruneGatewayEvents, setGatewayEventsPrunerForTesting } =
      await loadWithEnv("120");

    const pruner = vi.fn().mockResolvedValue(undefined);
    setGatewayEventsPrunerForTesting(pruner);

    await pruneGatewayEvents();

    expect(pruner).toHaveBeenCalledWith(120);
  });
});

describe("pruneGatewayEvents never throws into the cleanup interval", () => {
  it("logs and swallows a failing prune", async () => {
    const { pruneGatewayEvents, setGatewayEventsPrunerForTesting } =
      await loadWithEnv(undefined);

    setGatewayEventsPrunerForTesting(
      vi.fn().mockRejectedValue(new Error("connection terminated")),
    );

    // It rides a shared five-minute interval with the OAuth cleanup and the
    // DCR sweep; one failing sweep must not stop the ones queued behind it.
    await expect(pruneGatewayEvents()).resolves.toBeUndefined();
    expect(loggerMock.error).toHaveBeenCalledTimes(1);
    expect(String(loggerMock.error.mock.calls[0][0])).toContain(
      "Error pruning gateway_events",
    );
  });

  it("is a no-op when no database is present in the process", async () => {
    const { pruneGatewayEvents, setGatewayEventsPrunerForTesting } =
      await loadWithEnv(undefined);

    setGatewayEventsPrunerForTesting(null);

    await expect(pruneGatewayEvents()).resolves.toBeUndefined();
    expect(loggerMock.error).not.toHaveBeenCalled();
  });
});
