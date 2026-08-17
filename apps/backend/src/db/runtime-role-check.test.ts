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
 * Both pools are exercised. They resolve their connection independently, so a
 * regression that repointed one and not the other would otherwise pass.
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

let checkModule: CheckModule;
let dbModule: DbModule;
let auditDbModule: AuditDbModule;

/** Replaces both pools' `query` with a canned `SELECT current_user` answer. */
function stubPools(answer: { current_user: string; is_superuser: boolean }) {
  const stub = vi.fn(async () => ({ rows: [answer] }));
  (dbModule.pool as unknown as { query: unknown }).query = stub;
  (auditDbModule.auditPool as unknown as { query: unknown }).query = stub;
  return stub;
}

beforeAll(async () => {
  process.env.DATABASE_URL =
    "postgres://owner:unused@127.0.0.1:1/role_check_unit_test";
  process.env.METAMCP_RUNTIME_DB_PASSWORD = "runtime-unit-test";

  dbModule = await import("./index");
  auditDbModule = await import("./audit-db");
  checkModule = await import("./runtime-role-check");
});

afterEach(() => {
  vi.restoreAllMocks();
});

afterAll(async () => {
  process.env = { ...ORIGINAL_ENV };
  await Promise.all([dbModule.pool.end(), auditDbModule.auditPool.end()]);
});

describe("verifyRuntimeDatabaseRole", () => {
  it("asks BOTH pools, not just the main one", async () => {
    const stub = stubPools({
      current_user: "metamcp_runtime",
      is_superuser: false,
    });

    await checkModule.verifyRuntimeDatabaseRole();

    // Two calls: the audit pool is the one the whole feature is about, so a
    // check that covered only the main pool would miss the regression that
    // matters most.
    expect(stub).toHaveBeenCalledTimes(2);
  });

  it("reports the healthy case on stdout, where the documented cutover looks", async () => {
    // LOG_LEVEL defaults to `errors-only`, which does not mirror INFO to the
    // console — a confirmation line only in app.log is one an operator
    // following the README will not find.
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    stubPools({ current_user: "metamcp_runtime", is_superuser: false });

    await checkModule.verifyRuntimeDatabaseRole();

    const lines = log.mock.calls.map((call) => String(call[0]));
    expect(lines.filter((l) => l.includes("rolsuper=false"))).toHaveLength(2);
    expect(lines.some((l) => l.includes("main pool"))).toBe(true);
    expect(lines.some((l) => l.includes("audit pool"))).toBe(true);
  });

  it("WARNS when the runtime connection turns out to be a superuser", async () => {
    const logger = (await import("@/utils/logger")).default;
    const warn = vi.spyOn(logger, "warn").mockImplementation(() => {});
    stubPools({ current_user: "postgres", is_superuser: true });

    await checkModule.verifyRuntimeDatabaseRole();

    expect(warn).toHaveBeenCalledTimes(2);
    expect(String(warn.mock.calls[0][0])).toMatch(/IS a SUPERUSER/);
    // The consequence is named, not just the fact — the log line has to be
    // actionable to someone who did not write this file.
    expect(String(warn.mock.calls[0][0])).toMatch(/bypassable/);
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

    expect(warn).toHaveBeenCalledTimes(2);
    expect(String(warn.mock.calls[0][0])).toMatch(
      /expected role "metamcp_runtime" but authenticated as "someone_else"/,
    );
  });
});
