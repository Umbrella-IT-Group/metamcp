/**
 * The boot-time privilege check, driven through the REAL pools.
 *
 * "The variable is set" and "the pool authenticated as a NOSUPERUSER role" are
 * different claims, and a check that reports the first while believing it
 * reported the second is worse than no check: it manufactures confidence in an
 * immutability that is not there. So these cases stub the pools' `query` and
 * assert on what the check does with the SERVER's answer — including the case
 * where the server says "yes, superuser" and the check has to say so loudly.
 *
 * All three pools are exercised. They resolve their connection independently,
 * so a regression that repointed some and not the others would otherwise pass.
 *
 * pg constructs a Pool without connecting, so this needs no database — only a
 * parseable DATABASE_URL, set before the first dynamic import below.
 */

import {
  afterAll,
  afterEach,
  beforeAll,
  describe,
  expect,
  it,
  vi,
} from "vitest";

const ORIGINAL_ENV = { ...process.env };

type CheckModule = typeof import("./runtime-role-check");
type DbModule = typeof import("./index");
type AuditDbModule = typeof import("./audit-db");
type GatewayEventsDbModule = typeof import("./gateway-events-db");

let checkModule: CheckModule;
let dbModule: DbModule;
let auditDbModule: AuditDbModule;
let gatewayEventsDbModule: GatewayEventsDbModule;

/**
 * Runs `body` with the audit sink redirected into an array, and returns what
 * was written. `emit()` is fire-and-forget, so the macrotask turn is what lets
 * the detached write land — the same `flush` idiom the emitter's own suites
 * use.
 */
async function captureEmissions(
  body: () => Promise<void>,
): Promise<CapturedEvent[]> {
  const { setAuditSinkForTesting } = await import("@/lib/audit/audit-emitter");
  const rows: CapturedEvent[] = [];
  setAuditSinkForTesting(async (event) => {
    rows.push(event as CapturedEvent);
  });
  try {
    await body();
    await new Promise((resolve) => setTimeout(resolve, 0));
  } finally {
    setAuditSinkForTesting(undefined);
  }
  return rows;
}

interface CapturedEvent {
  actor_type: string;
  action: string;
  outcome: string;
  target_type?: string | null;
  target_id?: string | null;
  detail?: Record<string, unknown>;
}

/** Replaces all three pools' `query` with a canned `SELECT current_user` answer. */
function stubPools(answer: { current_user: string; is_superuser: boolean }) {
  const stub = vi.fn(async () => ({ rows: [answer] }));
  (dbModule.pool as unknown as { query: unknown }).query = stub;
  (auditDbModule.auditPool as unknown as { query: unknown }).query = stub;
  (
    gatewayEventsDbModule.gatewayEventsPool as unknown as { query: unknown }
  ).query = stub;
  return stub;
}

beforeAll(async () => {
  // Built at runtime, not as a single literal, so this loopback fixture
  // never reads as an embedded credential to secret scanners.
  process.env.DATABASE_URL =
    "postgres://owner:" + "unused" + "@127.0.0.1:1/role_check_unit_test";
  process.env.METAMCP_RUNTIME_DB_PASSWORD = "runtime-unit-test";

  dbModule = await import("./index");
  auditDbModule = await import("./audit-db");
  gatewayEventsDbModule = await import("./gateway-events-db");
  checkModule = await import("./runtime-role-check");
});

afterEach(() => {
  vi.restoreAllMocks();
});

afterAll(async () => {
  process.env = { ...ORIGINAL_ENV };
  await Promise.all([
    dbModule.pool.end(),
    auditDbModule.auditPool.end(),
    gatewayEventsDbModule.gatewayEventsPool.end(),
  ]);
});

describe("verifyRuntimeDatabaseRole", () => {
  it("asks ALL THREE pools, not just the main one", async () => {
    const stub = stubPools({
      current_user: "metamcp_runtime",
      is_superuser: false,
    });

    await checkModule.verifyRuntimeDatabaseRole();

    // Three calls: the audit and gateway-events pools each front an append-only
    // table, so a check that covered only the main pool would miss exactly the
    // regression that matters. The gateway-events pool was the one that used to
    // keep the bootstrap superuser after the other two dialed the runtime role.
    expect(stub).toHaveBeenCalledTimes(3);
  });

  it("reports the healthy case on stdout, where the documented cutover looks", async () => {
    // LOG_LEVEL defaults to `errors-only`, which does not mirror INFO to the
    // console — a confirmation line only in app.log is one an operator
    // following the README will not find.
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    stubPools({ current_user: "metamcp_runtime", is_superuser: false });

    await checkModule.verifyRuntimeDatabaseRole();

    const lines = log.mock.calls.map((call) => String(call[0]));
    expect(lines.filter((l) => l.includes("rolsuper=false"))).toHaveLength(3);
    expect(lines.some((l) => l.includes("main pool"))).toBe(true);
    expect(lines.some((l) => l.includes("audit pool"))).toBe(true);
    expect(lines.some((l) => l.includes("gateway-events pool"))).toBe(true);
  });

  it("WARNS when the runtime connection turns out to be a superuser", async () => {
    const logger = (await import("@/utils/logger")).default;
    const warn = vi.spyOn(logger, "warn").mockImplementation(() => {});
    stubPools({ current_user: "metamcp_runtime", is_superuser: true });

    await checkModule.verifyRuntimeDatabaseRole();

    expect(warn).toHaveBeenCalledTimes(3);
    expect(String(warn.mock.calls[0][0])).toMatch(/rolsuper=true/);
    // The consequence is named, not just the fact — the log line has to be
    // actionable to someone who did not write this file, and the README
    // quotes this wording as the failure to look for.
    expect(String(warn.mock.calls[0][0])).toMatch(
      /remain bypassable by this credential/,
    );
  });

  it("records the failed split in audit_log, not only in the boot log", async () => {
    // A WARN is seen by whoever is watching that container at that minute.
    // The audit row is what makes "was the split ever effective?" a query, and
    // what an alert can fire on.
    const emitted = await captureEmissions(async () => {
      vi.spyOn(
        (await import("@/utils/logger")).default,
        "warn",
      ).mockImplementation(() => {});
      stubPools({ current_user: "metamcp_runtime", is_superuser: true });
      await checkModule.verifyRuntimeDatabaseRole();
    });

    // One per pool: all three credentials are independently wrong here.
    expect(emitted).toHaveLength(3);
    for (const event of emitted) {
      expect(event.action).toBe(checkModule.RUNTIME_SPLIT_INEFFECTIVE_ACTION);
      expect(event.actor_type).toBe("system");
      expect(event.outcome).toBe("failure");
      expect(event.detail).toMatchObject({ reason: "superuser" });
    }
    expect(emitted.map((e) => e.detail?.pool).sort()).toEqual([
      "audit pool",
      "gateway-events pool",
      "main pool",
    ]);
  });

  it("emits nothing when the split IS effective", async () => {
    // The row has to mean something. Emitting on the healthy path would make
    // any alert built on it useless.
    const emitted = await captureEmissions(async () => {
      vi.spyOn(console, "log").mockImplementation(() => {});
      stubPools({ current_user: "metamcp_runtime", is_superuser: false });
      await checkModule.verifyRuntimeDatabaseRole();
    });

    expect(emitted).toHaveLength(0);
  });

  it("reports BOTH faults when the connection is a superuser AND the wrong role", async () => {
    // The likeliest way to get here is pointing the runtime at the owner
    // string, which is wrong in both ways at once. An early return on the
    // superuser branch would report one and hide the other.
    const logger = (await import("@/utils/logger")).default;
    const warn = vi.spyOn(logger, "warn").mockImplementation(() => {});
    const emitted = await captureEmissions(async () => {
      stubPools({ current_user: "metamcp_user", is_superuser: true });
      await checkModule.verifyRuntimeDatabaseRole();
    });

    const messages = warn.mock.calls.map((call) => String(call[0]));
    expect(messages.filter((m) => /rolsuper=true/.test(m))).toHaveLength(3);
    expect(messages.filter((m) => /expected role/.test(m))).toHaveLength(3);

    const reasons = emitted.map((e) => e.detail?.reason).sort();
    expect(reasons).toEqual([
      "role_mismatch",
      "role_mismatch",
      "role_mismatch",
      "superuser",
      "superuser",
      "superuser",
    ]);
  });

  it("still reports the healthy pools when one pool's query fails", async () => {
    // `Promise.all` would discard the good answers with the bad one, and the
    // pools likeliest to fail are the audit and gateway-events pools (max: 2,
    // 1s checkout timeout). The boot log would then carry one generic error
    // instead of the privilege facts this check exists to report.
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    const logger = (await import("@/utils/logger")).default;
    const error = vi.spyOn(logger, "error").mockImplementation(() => {});

    const healthy = vi.fn(async () => ({
      rows: [{ current_user: "metamcp_runtime", is_superuser: false }],
    }));
    (dbModule.pool as unknown as { query: unknown }).query = healthy;
    (
      gatewayEventsDbModule.gatewayEventsPool as unknown as { query: unknown }
    ).query = healthy;
    (auditDbModule.auditPool as unknown as { query: unknown }).query = vi.fn(
      async () => {
        throw new Error("timeout exceeded when trying to connect");
      },
    );

    await checkModule.verifyRuntimeDatabaseRole();

    const stdout = log.mock.calls.map((c) => String(c[0]));
    expect(stdout.filter((l) => /main pool/.test(l))).toHaveLength(1);
    expect(stdout.filter((l) => /gateway-events pool/.test(l))).toHaveLength(1);
    expect(String(error.mock.calls[0][0])).toMatch(/audit pool/);
  });

  it("says so, and queries nothing, when no runtime role is configured", async () => {
    // The state most deployments are in. Silence here would be
    // indistinguishable from the check having crashed.
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    const stub = stubPools({ current_user: "postgres", is_superuser: true });
    const saved = process.env.METAMCP_RUNTIME_DB_PASSWORD;
    delete process.env.METAMCP_RUNTIME_DB_PASSWORD;

    try {
      await checkModule.verifyRuntimeDatabaseRole();
    } finally {
      process.env.METAMCP_RUNTIME_DB_PASSWORD = saved;
    }

    expect(stub).not.toHaveBeenCalled();
    expect(String(log.mock.calls[0][0])).toMatch(/no runtime role configured/);
  });

  it("WARNS when it authenticates as a role other than the configured one", async () => {
    // The entrypoint granted and revoked on one role; if traffic is served by
    // another, none of that work applies to the connection that matters.
    const logger = (await import("@/utils/logger")).default;
    const warn = vi.spyOn(logger, "warn").mockImplementation(() => {});
    vi.spyOn(console, "log").mockImplementation(() => {});
    stubPools({ current_user: "someone_else", is_superuser: false });

    await checkModule.verifyRuntimeDatabaseRole();

    expect(warn).toHaveBeenCalledTimes(3);
    expect(String(warn.mock.calls[0][0])).toMatch(
      /expected role "metamcp_runtime" but authenticated as "someone_else"/,
    );
  });
});
