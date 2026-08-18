/**
 * The floor on `TOOL_AUDIT_RETENTION_DAYS`, and the asymmetry it deliberately
 * keeps with the gateway-events one.
 *
 * The failure being prevented is not "retention is shorter than the floor". It
 * is that a value between 1 and 29 makes the pruner issue a DELETE spanning
 * migration 0032's immutability window, which raises on the first in-window
 * row and rolls the WHOLE statement back, so the aged rows do not get pruned
 * either. Retention stops working rather than shortening. That is why the
 * clamp is here and not merely documented.
 *
 * `<= 0` must survive UNCLAMPED, because it has always meant "retain forever"
 * on this table. Clamping it to 30 would start deleting rows on a deployment
 * that asked for none to be deleted, which is the one direction a retention
 * floor must never move.
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

const { resolveToolAuditRetentionDays, TOOL_AUDIT_RETENTION_FLOOR_DAYS } =
  await import("./tool-audit-retention");

type RetentionModule = typeof import("./tool-audit-retention");

/**
 * Load the module with a given env value.
 *
 * `resetModules` is load-bearing: the effective retention is parsed ONCE at
 * module load so the WARN fires at boot rather than every five minutes, which
 * makes a fresh module instance the only way to observe a different
 * environment.
 */
async function loadWithEnv(
  value: string | undefined,
): Promise<RetentionModule> {
  vi.resetModules();
  if (value === undefined) {
    delete process.env.TOOL_AUDIT_RETENTION_DAYS;
  } else {
    process.env.TOOL_AUDIT_RETENTION_DAYS = value;
  }
  return import("./tool-audit-retention");
}

const originalEnv = process.env.TOOL_AUDIT_RETENTION_DAYS;

beforeEach(() => {
  vi.clearAllMocks();
});

afterEach(() => {
  if (originalEnv === undefined) {
    delete process.env.TOOL_AUDIT_RETENTION_DAYS;
  } else {
    process.env.TOOL_AUDIT_RETENTION_DAYS = originalEnv;
  }
});

describe("resolveToolAuditRetentionDays", () => {
  it.each([[1], [15], [29]])(
    "raises the boundary-breaking value %i to the floor",
    (raw) => {
      expect(resolveToolAuditRetentionDays(String(raw))).toBe(
        TOOL_AUDIT_RETENTION_FLOOR_DAYS,
      );
    },
  );

  it("warns loudly enough to explain the consequence, not just the change", () => {
    resolveToolAuditRetentionDays("7");

    const warned = loggerMock.warn.mock.calls.map(String).join("\n");
    expect(warned).toContain("TOOL_AUDIT_RETENTION_DAYS=7");
    expect(warned).toContain("30");
    // An operator who set 7 needs to know the setting did not merely move, or
    // they will assume the gateway is keeping 7 days and be wrong by 23.
    expect(warned).toContain("migration 0032");
  });

  it.each([[30], [31], [90], [365]])(
    "leaves the in-range value %i alone",
    (raw) => {
      expect(resolveToolAuditRetentionDays(String(raw))).toBe(raw);
    },
  );

  it.each([[0], [-1], [-90]])(
    "keeps %i as retain-forever rather than clamping it up",
    (raw) => {
      // The asymmetry with GATEWAY_EVENTS_RETENTION_DAYS, which clamps these
      // to its floor. Raising them here would start deleting rows on a
      // deployment that asked for none to be deleted.
      expect(resolveToolAuditRetentionDays(String(raw))).toBe(raw);
      expect(loggerMock.warn).not.toHaveBeenCalled();
    },
  );

  it.each([[undefined], [""], ["   "]])(
    "falls back to the 90-day default for %o",
    (raw) => {
      expect(resolveToolAuditRetentionDays(raw)).toBe(90);
    },
  );

  it.each([["30abc"], ["1e9"], ["forever"], ["thirty"]])(
    "refuses to let %o parse as a partial number",
    (raw) => {
      // `Number.parseInt` reads a leading integer and discards the rest, so
      // "30abc" would become 30 and "1e9" would become 1. Either is a typo
      // silently taking effect as a number nobody wrote.
      expect(resolveToolAuditRetentionDays(raw)).toBe(90);
      expect(loggerMock.warn).toHaveBeenCalled();
    },
  );
});

describe("the value the sweep actually uses", () => {
  // A clamp function that returns 30 for 29 proves nothing if the constant the
  // router imports was computed some other way.
  it("applies the floor to the module-level constant, read from the real env", async () => {
    const mod = await loadWithEnv("5");
    expect(mod.TOOL_AUDIT_RETENTION_DAYS).toBe(30);
  });

  it("carries retain-forever through to the constant unchanged", async () => {
    const mod = await loadWithEnv("0");
    expect(mod.TOOL_AUDIT_RETENTION_DAYS).toBe(0);
  });

  it("defaults the constant to 90 when the variable is absent", async () => {
    const mod = await loadWithEnv(undefined);
    expect(mod.TOOL_AUDIT_RETENTION_DAYS).toBe(90);
  });
});
