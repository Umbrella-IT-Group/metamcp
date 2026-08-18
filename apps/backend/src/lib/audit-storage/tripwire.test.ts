/**
 * The tripwire's job is to be SEEN, so that is what this suite pins.
 *
 * A size monitor can fail in three ways that all look identical from the
 * outside, and each one is a case below: it can never run (gating), it can run
 * and say nothing (the heartbeat), or it can say so much that the one line
 * that mattered is buried (hysteresis). The threshold arithmetic is the least
 * interesting part; a WARN that fires every five minutes for a month is a
 * monitor the operator has already muted by the time it is right.
 *
 * The escalation path is exercised through the REAL log store and the REAL
 * sink, with only the repository swapped out. Asserting on a mocked
 * `metamcpLogStore.record` would prove the call was made and nothing about
 * whether the row survives the writer's category filter, which is precisely
 * where a `system` event could be silently dropped on its way to the History
 * view this tripwire reports through.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { AuditTableStats } from "@/db/repositories/audit-storage.repo";
import type { GatewayEventEntry } from "@/db/repositories/gateway-events.repo";

const { loggerMock } = vi.hoisted(() => ({
  loggerMock: {
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  },
}));

vi.mock("@/utils/logger", () => ({ default: loggerMock }));

const MB = 1024 * 1024;

/** Sizes named by their relationship to the default 2048 MB threshold. */
const UNDER = 100 * MB;
const REARM_ZONE = 2000 * MB; // over 90%, under 100%: neither warns nor re-arms
const BELOW_REARM = 1800 * MB; // under 90%: re-arms
const AT_THRESHOLD = 2048 * MB;
const WELL_OVER = 3072 * MB;

function stats(overrides: Partial<AuditTableStats> = {}): AuditTableStats {
  return {
    table: "gateway_events",
    est_rows: 1234,
    total_bytes: UNDER,
    ...overrides,
  };
}

type TripwireModule = typeof import("./tripwire");

interface LoadedTripwire {
  tripwire: TripwireModule;
  /** Rows that reached the persistence sink, after the writer's filtering. */
  persisted: GatewayEventEntry[];
}

/**
 * Load `tripwire.ts` with a given environment.
 *
 * `resetModules` is load-bearing twice over. The effective config is parsed
 * ONCE at module load (so an invalid setting is reported at boot rather than
 * every hour), and the sweep counter and warn state are module-level, so a
 * fresh instance is both the only way to observe a different environment and
 * the way "re-arm on process restart" is expressed.
 *
 * The sink seam is claimed AFTER the tripwire import so both resolve to the
 * same generation of the module registry; taken before, the tripwire would end
 * up talking to a different sink instance than the one under assertion.
 */
async function loadTripwire(
  env: Record<string, string | undefined> = {},
): Promise<LoadedTripwire> {
  vi.resetModules();
  for (const key of [
    "AUDIT_STORAGE_CHECK_INTERVAL_SWEEPS",
    "AUDIT_STORAGE_WARN_MB",
  ]) {
    if (env[key] === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = env[key];
    }
  }

  const tripwire = await import("./tripwire");
  const sink = await import("@/lib/gateway-events/sink");

  const persisted: LoadedTripwire["persisted"] = [];
  sink.setGatewayEventSinkForTesting(async (row) => {
    persisted.push(row);
  });

  return { tripwire, persisted };
}

/**
 * Let the sink's detached write land. `recordGatewayEvent` returns before its
 * promise resolves by design, so an assertion made in the same tick would race
 * a write that is working correctly.
 */
async function flushDetachedWrites(): Promise<void> {
  await new Promise((resolve) => setImmediate(resolve));
}

const ORIGINAL_ENV = {
  AUDIT_STORAGE_CHECK_INTERVAL_SWEEPS:
    process.env.AUDIT_STORAGE_CHECK_INTERVAL_SWEEPS,
  AUDIT_STORAGE_WARN_MB: process.env.AUDIT_STORAGE_WARN_MB,
};

beforeEach(() => {
  vi.clearAllMocks();
});

afterEach(() => {
  vi.useRealTimers();
  for (const [key, value] of Object.entries(ORIGINAL_ENV)) {
    if (value === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = value;
    }
  }
});

describe("resolveAuditStorageCheckIntervalSweeps", () => {
  it("defaults to 12 sweeps (hourly) when unset or empty", async () => {
    const { tripwire } = await loadTripwire();

    expect(tripwire.resolveAuditStorageCheckIntervalSweeps(undefined)).toBe(12);
    expect(tripwire.resolveAuditStorageCheckIntervalSweeps("")).toBe(12);
    expect(tripwire.resolveAuditStorageCheckIntervalSweeps("   ")).toBe(12);
    expect(loggerMock.warn).not.toHaveBeenCalled();
  });

  it("honours an in-range value, whitespace included", async () => {
    const { tripwire } = await loadTripwire();

    expect(tripwire.resolveAuditStorageCheckIntervalSweeps("1")).toBe(1);
    expect(tripwire.resolveAuditStorageCheckIntervalSweeps("288")).toBe(288);
    // A trailing space in an env file is a formatting accident, not a typo in
    // the value; rejecting it would turn one into the other.
    expect(tripwire.resolveAuditStorageCheckIntervalSweeps(" 6 ")).toBe(6);
    expect(loggerMock.warn).not.toHaveBeenCalled();
  });

  it("rejects a value that only STARTS as a number, rather than reading a prefix", async () => {
    const { tripwire } = await loadTripwire();

    // `Number.parseInt` is not a validator: it takes the leading integer and
    // discards the rest, so "1e9" would silently mean every sweep.
    expect(tripwire.resolveAuditStorageCheckIntervalSweeps("12abc")).toBe(12);
    expect(tripwire.resolveAuditStorageCheckIntervalSweeps("1e9")).toBe(12);
    expect(tripwire.resolveAuditStorageCheckIntervalSweeps("hourly")).toBe(12);
    expect(loggerMock.warn).toHaveBeenCalledTimes(3);
    expect(String(loggerMock.warn.mock.calls[0][0])).toContain(
      "is not a number",
    );
  });

  it("refuses 0 and negatives rather than accepting them as an off switch", async () => {
    const { tripwire } = await loadTripwire();

    expect(tripwire.resolveAuditStorageCheckIntervalSweeps("0")).toBe(12);
    expect(tripwire.resolveAuditStorageCheckIntervalSweeps("-5")).toBe(12);
    expect(loggerMock.warn).toHaveBeenCalledTimes(2);
    expect(String(loggerMock.warn.mock.calls[0][0])).toContain(
      "would disable the storage check",
    );
  });

  it("caps an interval longer than a day, so the numbers land at least daily", async () => {
    const { tripwire } = await loadTripwire();

    // 288 sweeps is 24h at the cleanup interval's 5 minutes. Anything past it
    // is a mute monitor by another name.
    expect(tripwire.resolveAuditStorageCheckIntervalSweeps("289")).toBe(288);
    expect(tripwire.resolveAuditStorageCheckIntervalSweeps("999999")).toBe(288);
    expect(loggerMock.warn).toHaveBeenCalledTimes(2);
    expect(String(loggerMock.warn.mock.calls[0][0])).toContain("capped to 288");
  });
});

describe("resolveAuditStorageWarnMb", () => {
  it("defaults to 2048 MB when unset or empty", async () => {
    const { tripwire } = await loadTripwire();

    expect(tripwire.resolveAuditStorageWarnMb(undefined)).toBe(2048);
    expect(tripwire.resolveAuditStorageWarnMb("")).toBe(2048);
    expect(loggerMock.warn).not.toHaveBeenCalled();
  });

  it("honours any positive integer up to the ceiling", async () => {
    const { tripwire } = await loadTripwire();

    expect(tripwire.resolveAuditStorageWarnMb("1")).toBe(1);
    expect(tripwire.resolveAuditStorageWarnMb(" 512 ")).toBe(512);
    expect(tripwire.resolveAuditStorageWarnMb("102400")).toBe(102400);
    expect(tripwire.resolveAuditStorageWarnMb("1048576")).toBe(1048576);
    expect(loggerMock.warn).not.toHaveBeenCalled();
  });

  it("caps a threshold so large it would mute the escalation", async () => {
    const { tripwire } = await loadTripwire();

    // The interval knob refuses to be an off switch; a threshold nothing can
    // reach is the same off switch by another route, and it mutes the layer
    // that does not depend on how logging is configured.
    expect(tripwire.resolveAuditStorageWarnMb("1048577")).toBe(1048576);
    expect(tripwire.resolveAuditStorageWarnMb("999999999")).toBe(1048576);
    expect(loggerMock.warn).toHaveBeenCalledTimes(2);
    expect(String(loggerMock.warn.mock.calls[0][0])).toContain(
      "would mute the escalation entirely",
    );
  });

  it("falls back on a non-integer or unusable value, with a WARN", async () => {
    const { tripwire } = await loadTripwire();

    expect(tripwire.resolveAuditStorageWarnMb("2gb")).toBe(2048);
    expect(tripwire.resolveAuditStorageWarnMb("2.5")).toBe(2048);
    // Zero would put every table permanently over the line: an alert carrying
    // no information.
    expect(tripwire.resolveAuditStorageWarnMb("0")).toBe(2048);
    expect(tripwire.resolveAuditStorageWarnMb("-1")).toBe(2048);
    expect(loggerMock.warn).toHaveBeenCalledTimes(4);
  });
});

describe("the config is EFFECTIVE, not just computed", () => {
  it("reads the environment at module load and warns there, not per check", async () => {
    const { tripwire } = await loadTripwire({
      AUDIT_STORAGE_CHECK_INTERVAL_SWEEPS: "0",
      AUDIT_STORAGE_WARN_MB: "2gb",
    });

    expect(tripwire.AUDIT_STORAGE_CHECK_INTERVAL_SWEEPS).toBe(12);
    expect(tripwire.AUDIT_STORAGE_WARN_MB).toBe(2048);
    // Both boot-time WARNs, fired on module load. A clamp nobody reads is not
    // a clamp, and a WARN on the hourly path would become the noise it is
    // meant to cut through.
    expect(loggerMock.warn).toHaveBeenCalledTimes(2);
  });

  it("carries a valid environment through to the effective values", async () => {
    const { tripwire } = await loadTripwire({
      AUDIT_STORAGE_CHECK_INTERVAL_SWEEPS: "6",
      AUDIT_STORAGE_WARN_MB: "512",
    });

    expect(tripwire.AUDIT_STORAGE_CHECK_INTERVAL_SWEEPS).toBe(6);
    expect(tripwire.AUDIT_STORAGE_WARN_MB).toBe(512);
  });
});

describe("interval gating", () => {
  it("checks on the first sweep after boot, then only every Nth", async () => {
    const { tripwire } = await loadTripwire({
      AUDIT_STORAGE_CHECK_INTERVAL_SWEEPS: "3",
    });
    const reader = vi.fn().mockResolvedValue([stats()]);
    tripwire.setAuditStorageStatsReaderForTesting(reader);

    // The first sweep checks deliberately: a monitor silent for the first hour
    // after every restart misses its reading at the moment a deployment is
    // most likely to have changed something.
    for (let sweep = 0; sweep < 7; sweep += 1) {
      await tripwire.checkAuditStorage();
    }

    // Sweeps 1, 4 and 7 of the seven.
    expect(reader).toHaveBeenCalledTimes(3);
  });

  it("does not touch the database on a sweep that is not due", async () => {
    const { tripwire } = await loadTripwire({
      AUDIT_STORAGE_CHECK_INTERVAL_SWEEPS: "12",
    });
    const reader = vi.fn().mockResolvedValue([stats()]);
    tripwire.setAuditStorageStatsReaderForTesting(reader);

    await tripwire.checkAuditStorage(); // due
    reader.mockClear();
    loggerMock.info.mockClear();

    for (let sweep = 0; sweep < 11; sweep += 1) {
      await tripwire.checkAuditStorage();
    }

    expect(reader).not.toHaveBeenCalled();
    expect(loggerMock.info).not.toHaveBeenCalled();

    await tripwire.checkAuditStorage(); // the 12th, due again
    expect(reader).toHaveBeenCalledTimes(1);
  });
});

describe("the heartbeat: every check reports the numbers, crossing or not", () => {
  it("logs one greppable INFO line per table", async () => {
    const { tripwire } = await loadTripwire();
    tripwire.setAuditStorageStatsReaderForTesting(async () => [
      { table: "audit_log", est_rows: 42, total_bytes: 8192 },
      { table: "gateway_events", est_rows: 1_000_000, total_bytes: UNDER },
      { table: "tool_call_audit", est_rows: 7, total_bytes: 16384 },
    ]);

    await tripwire.checkAuditStorage();

    expect(loggerMock.info).toHaveBeenCalledTimes(3);
    const lines = loggerMock.info.mock.calls.map((call) => String(call[0]));
    expect(lines[0]).toBe(
      "[audit-storage] table=audit_log est_rows=42 total_bytes=8192 total_mb=0.0 threshold_mb=2048",
    );
    expect(lines[1]).toContain("table=gateway_events est_rows=1000000");
    expect(lines[1]).toContain(`total_bytes=${UNDER}`);
    expect(lines[2]).toContain("table=tool_call_audit");
  });

  it("reports a missing planner estimate as unknown rather than as zero rows", async () => {
    const { tripwire } = await loadTripwire();
    tripwire.setAuditStorageStatsReaderForTesting(async () => [
      stats({ est_rows: null, total_bytes: 8192 }),
    ]);

    await tripwire.checkAuditStorage();

    // `reltuples` is -1 until a table is first analyzed. "No estimate yet" and
    // "empty" are different facts and a fresh deployment must read as the
    // former.
    expect(String(loggerMock.info.mock.calls[0][0])).toContain(
      "est_rows=unknown",
    );
  });

  it("says unknown and does NOT warn for a table it could not resolve", async () => {
    const { tripwire, persisted } = await loadTripwire();
    tripwire.setAuditStorageStatsReaderForTesting(async () => [
      stats({ est_rows: null, total_bytes: null }),
    ]);

    await tripwire.checkAuditStorage();
    await flushDetachedWrites();

    expect(String(loggerMock.info.mock.calls[0][0])).toContain(
      "total_bytes=unknown",
    );
    // An unresolvable table means unapplied migrations, not growth. Warning
    // hourly about it on a half-migrated box would train the operator to
    // ignore this exact WARN.
    expect(loggerMock.warn).not.toHaveBeenCalled();
    expect(persisted).toHaveLength(0);
  });
});

describe("crossing the threshold escalates to BOTH signal paths", () => {
  it("logs a WARN and persists a system gateway event, once", async () => {
    const { tripwire, persisted } = await loadTripwire();
    tripwire.setAuditStorageStatsReaderForTesting(async () => [
      stats({ total_bytes: WELL_OVER, est_rows: 84_000_000 }),
    ]);

    await tripwire.checkAuditStorage();
    await flushDetachedWrites();

    expect(loggerMock.warn).toHaveBeenCalledTimes(1);
    const warned = String(loggerMock.warn.mock.calls[0][0]);
    expect(warned).toContain("[MetaMCP][system][audit-storage]");
    expect(warned).toContain("gateway_events is 3072.0 MB");
    expect(warned).toContain("AUDIT_STORAGE_WARN_MB=2048");
    // The operator's next question is what to do about it, and the answer is
    // not "lower retention" for a table nothing can trim for 30 days.
    expect(warned).toContain("30-day immutability window");

    // The half that reaches the History view the tripwire reports through.
    // `system` is one of the persisted categories, so a category regression
    // would show up here as a dropped row rather than as a passing test.
    expect(persisted).toHaveLength(1);
    expect(persisted[0]).toMatchObject({
      category: "system",
      level: "warn",
      server_name: "audit-storage",
    });
    expect(String(persisted[0].message)).toContain(
      "gateway_events is 3072.0 MB",
    );
  });

  it("warns at the threshold exactly, not only past it", async () => {
    const { tripwire } = await loadTripwire();
    tripwire.setAuditStorageStatsReaderForTesting(async () => [
      stats({ total_bytes: AT_THRESHOLD }),
    ]);

    await tripwire.checkAuditStorage();

    expect(loggerMock.warn).toHaveBeenCalledTimes(1);
  });

  it("warns per table, so one loud table cannot mask another", async () => {
    const { tripwire, persisted } = await loadTripwire();
    tripwire.setAuditStorageStatsReaderForTesting(async () => [
      { table: "audit_log", est_rows: 1, total_bytes: UNDER },
      { table: "gateway_events", est_rows: 1, total_bytes: WELL_OVER },
      { table: "tool_call_audit", est_rows: 1, total_bytes: WELL_OVER },
    ]);

    await tripwire.checkAuditStorage();
    await flushDetachedWrites();

    expect(loggerMock.warn).toHaveBeenCalledTimes(2);
    expect(persisted.map((row) => String(row.message))).toEqual([
      expect.stringContaining("gateway_events is"),
      expect.stringContaining("tool_call_audit is"),
    ]);
  });
});

describe("hysteresis: the tripwire must not become the noise", () => {
  it("holds silent while the condition persists inside the repeat window", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(new Date("2026-08-17T00:00:00Z"));

    const { tripwire, persisted } = await loadTripwire({
      AUDIT_STORAGE_CHECK_INTERVAL_SWEEPS: "1",
    });
    tripwire.setAuditStorageStatsReaderForTesting(async () => [
      stats({ total_bytes: WELL_OVER }),
    ]);

    await tripwire.checkAuditStorage();
    await flushDetachedWrites();
    expect(loggerMock.warn).toHaveBeenCalledTimes(1);

    // Eleven more hourly checks inside the same day. On a five-minute sweep an
    // unthrottled tripwire would produce 288 of these a day, which is how a
    // real warning gets filtered out of the operator's view for good.
    for (let hour = 1; hour <= 11; hour += 1) {
      vi.setSystemTime(
        new Date(`2026-08-17T${String(hour).padStart(2, "0")}:00:00Z`),
      );
      await tripwire.checkAuditStorage();
    }
    await flushDetachedWrites();

    expect(loggerMock.warn).toHaveBeenCalledTimes(1);
    expect(persisted).toHaveLength(1);
    // The heartbeat kept running throughout, so "quiet" is still evidenced.
    expect(loggerMock.info).toHaveBeenCalledTimes(12);
  });

  it("restates a condition still live after 24 hours", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(new Date("2026-08-17T00:00:00Z"));

    const { tripwire, persisted } = await loadTripwire({
      AUDIT_STORAGE_CHECK_INTERVAL_SWEEPS: "1",
    });
    tripwire.setAuditStorageStatsReaderForTesting(async () => [
      stats({ total_bytes: WELL_OVER }),
    ]);

    await tripwire.checkAuditStorage();
    vi.setSystemTime(new Date("2026-08-17T23:59:00Z"));
    await tripwire.checkAuditStorage();
    expect(loggerMock.warn).toHaveBeenCalledTimes(1);

    vi.setSystemTime(new Date("2026-08-18T00:00:01Z"));
    await tripwire.checkAuditStorage();
    await flushDetachedWrites();

    // A condition nobody fixed is still a condition. Silence past a day would
    // make an unresolved problem indistinguishable from a resolved one.
    expect(loggerMock.warn).toHaveBeenCalledTimes(2);
    expect(persisted).toHaveLength(2);
  });

  it("does NOT re-arm inside the band below the threshold", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(new Date("2026-08-17T00:00:00Z"));

    const { tripwire } = await loadTripwire({
      AUDIT_STORAGE_CHECK_INTERVAL_SWEEPS: "1",
    });
    let size = WELL_OVER;
    tripwire.setAuditStorageStatsReaderForTesting(async () => [
      stats({ total_bytes: size }),
    ]);

    await tripwire.checkAuditStorage();
    expect(loggerMock.warn).toHaveBeenCalledTimes(1);

    // Down into the 90-100% band, then back over. Re-arming on any dip would
    // turn a table wobbling across the boundary into a warning per sweep,
    // which is the flapping the repeat window exists to stop.
    size = REARM_ZONE;
    await tripwire.checkAuditStorage();
    size = WELL_OVER;
    await tripwire.checkAuditStorage();

    expect(loggerMock.warn).toHaveBeenCalledTimes(1);
  });

  it("re-arms once size drops below 90% of the threshold", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(new Date("2026-08-17T00:00:00Z"));

    const { tripwire, persisted } = await loadTripwire({
      AUDIT_STORAGE_CHECK_INTERVAL_SWEEPS: "1",
    });
    let size = WELL_OVER;
    tripwire.setAuditStorageStatsReaderForTesting(async () => [
      stats({ total_bytes: size }),
    ]);

    await tripwire.checkAuditStorage();
    expect(loggerMock.warn).toHaveBeenCalledTimes(1);

    // A real reclaim: past the window, retention deleted enough to matter.
    size = BELOW_REARM;
    await tripwire.checkAuditStorage();

    // Growing back is a NEW crossing and is reported immediately, still well
    // inside the 24h repeat window of the first one.
    size = WELL_OVER;
    await tripwire.checkAuditStorage();
    await flushDetachedWrites();

    expect(loggerMock.warn).toHaveBeenCalledTimes(2);
    expect(persisted).toHaveLength(2);
  });

  it("re-arms on process restart, so a live condition is restated at boot", async () => {
    const first = await loadTripwire();
    first.tripwire.setAuditStorageStatsReaderForTesting(async () => [
      stats({ total_bytes: WELL_OVER }),
    ]);
    await first.tripwire.checkAuditStorage();
    expect(loggerMock.warn).toHaveBeenCalledTimes(1);

    // A fresh module registry is a fresh process: the warn state is deliberately
    // in memory, so a restart re-states rather than inheriting a suppression
    // window from a run the operator may never have seen.
    const second = await loadTripwire();
    second.tripwire.setAuditStorageStatsReaderForTesting(async () => [
      stats({ total_bytes: WELL_OVER }),
    ]);
    await second.tripwire.checkAuditStorage();
    await flushDetachedWrites();

    expect(loggerMock.warn).toHaveBeenCalledTimes(2);
    expect(second.persisted).toHaveLength(1);
  });

  it("keeps warn state per table rather than globally", async () => {
    const { tripwire } = await loadTripwire({
      AUDIT_STORAGE_CHECK_INTERVAL_SWEEPS: "1",
    });
    let toolAuditBytes = UNDER;
    tripwire.setAuditStorageStatsReaderForTesting(async () => [
      { table: "gateway_events", est_rows: 1, total_bytes: WELL_OVER },
      { table: "tool_call_audit", est_rows: 1, total_bytes: toolAuditBytes },
    ]);

    await tripwire.checkAuditStorage();
    expect(loggerMock.warn).toHaveBeenCalledTimes(1);

    // The second table crossing later must not be suppressed by the first
    // table's still-open repeat window.
    toolAuditBytes = WELL_OVER;
    await tripwire.checkAuditStorage();

    expect(loggerMock.warn).toHaveBeenCalledTimes(2);
    expect(String(loggerMock.warn.mock.calls[1][0])).toContain(
      "tool_call_audit is",
    );
  });
});

describe("failure isolation: the check never reaches the sweep it rides", () => {
  it("logs and swallows a failing stats query", async () => {
    const { tripwire } = await loadTripwire();
    tripwire.setAuditStorageStatsReaderForTesting(
      vi
        .fn()
        .mockRejectedValue(
          new Error("timeout exceeded when trying to connect"),
        ),
    );

    // The pool it reads through gives up rather than waiting, at both the
    // checkout (1s) and the statement (5s), so this is the ordinary
    // saturated-or-locked database path rather than an exotic one.
    await expect(tripwire.checkAuditStorage()).resolves.toBeUndefined();
    expect(loggerMock.error).toHaveBeenCalledTimes(1);
    expect(String(loggerMock.error.mock.calls[0][0])).toContain(
      "Error checking audit table storage",
    );
  });

  it("is a no-op when no database is present in the process", async () => {
    const { tripwire } = await loadTripwire();
    tripwire.setAuditStorageStatsReaderForTesting(null);

    await expect(tripwire.checkAuditStorage()).resolves.toBeUndefined();
    expect(loggerMock.error).not.toHaveBeenCalled();
    expect(loggerMock.info).not.toHaveBeenCalled();
  });

  it("SAYS SO when it disables itself, rather than going quiet", async () => {
    const originalDatabaseUrl = process.env.DATABASE_URL;
    // Deleted explicitly rather than assumed absent, so the case is the same
    // whether or not the runner's environment happens to carry one.
    delete process.env.DATABASE_URL;
    try {
      const { tripwire } = await loadTripwire();
      // `undefined` forces a real resolve attempt, which fails at the db
      // module's import-time DATABASE_URL check.
      tripwire.setAuditStorageStatsReaderForTesting(undefined);

      await expect(tripwire.checkAuditStorage()).resolves.toBeUndefined();

      // The module argues at length that a monitor nobody hears is the failure
      // it exists to prevent. A bare `catch {}` that switches it off for the
      // process lifetime would have been exactly that, inside its own error
      // handling.
      const disabled = loggerMock.warn.mock.calls
        .map((call) => String(call[0]))
        .filter((line) => line.includes("storage checks are disabled"));
      expect(disabled).toHaveLength(1);
      // The caught error rides along, so the line says WHY rather than only
      // that it happened.
      expect(loggerMock.warn.mock.calls.at(-1)?.[1]).toBeInstanceOf(Error);
    } finally {
      if (originalDatabaseUrl === undefined) {
        delete process.env.DATABASE_URL;
      } else {
        process.env.DATABASE_URL = originalDatabaseUrl;
      }
    }
  });

  it("does not re-attempt the resolve on every later sweep", async () => {
    const originalDatabaseUrl = process.env.DATABASE_URL;
    delete process.env.DATABASE_URL;
    try {
      const { tripwire } = await loadTripwire({
        AUDIT_STORAGE_CHECK_INTERVAL_SWEEPS: "1",
      });
      tripwire.setAuditStorageStatsReaderForTesting(undefined);

      for (let sweep = 0; sweep < 5; sweep += 1) {
        await tripwire.checkAuditStorage();
      }

      // One line, not five: the null is cached, so warning once is the whole
      // truth and repeating it would be the noise this module keeps arguing
      // against.
      const disabled = loggerMock.warn.mock.calls
        .map((call) => String(call[0]))
        .filter((line) => line.includes("storage checks are disabled"));
      expect(disabled).toHaveLength(1);
    } finally {
      if (originalDatabaseUrl === undefined) {
        delete process.env.DATABASE_URL;
      } else {
        process.env.DATABASE_URL = originalDatabaseUrl;
      }
    }
  });

  it("still advances the sweep counter when the check fails", async () => {
    const { tripwire } = await loadTripwire({
      AUDIT_STORAGE_CHECK_INTERVAL_SWEEPS: "3",
    });
    const reader = vi
      .fn()
      .mockRejectedValue(new Error("connection terminated"));
    tripwire.setAuditStorageStatsReaderForTesting(reader);

    // A failure that reset the cadence would retry every five minutes for as
    // long as the database stayed unhappy, turning a diagnostic into load
    // during an incident.
    for (let sweep = 0; sweep < 4; sweep += 1) {
      await tripwire.checkAuditStorage();
    }

    expect(reader).toHaveBeenCalledTimes(2);
  });
});
