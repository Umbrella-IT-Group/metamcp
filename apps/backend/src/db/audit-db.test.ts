/**
 * The audit writer must not share connections with the auth path.
 *
 * Every refused MCP request emits one INSERT — including the no-credential
 * 401s, which need no credential to provoke — and the failed-attempt rate
 * limiter keys on `req.ip`, which is the same loopback address for every
 * caller behind the in-container Next.js rewrite. So an unauthenticated flood
 * is a 1:1 request-to-INSERT amplifier with no per-attacker damping. On the
 * shared pool (pg default `max: 10`, no checkout timeout, queues forever)
 * those INSERTs would contend with the session lookups, `users.disabled`
 * checks and API-key validations that REFUSE the flood.
 *
 * This pins the isolation as a property, not a comment: a different Pool
 * object, a hard ceiling, and a checkout timeout that fails fast into the
 * fire-and-forget swallow. Reverting `audit-log.repo.ts` to the shared `db`
 * fails the last case here.
 *
 * pg constructs a Pool without connecting, so this needs no database — only a
 * parseable DATABASE_URL.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";

const ORIGINAL_DATABASE_URL = process.env.DATABASE_URL;

type AuditDbModule = typeof import("./audit-db");
type DbModule = typeof import("./index");
type AuditRepoModule = typeof import("./repositories/audit-log.repo");

let auditDbModule: AuditDbModule;
let dbModule: DbModule;
let auditRepoModule: AuditRepoModule;

beforeAll(async () => {
  // Never a real database: these modules read DATABASE_URL at import time and
  // construct pools, but pg does not dial until a query is issued.
  process.env.DATABASE_URL =
    "postgres://unused:unused@127.0.0.1:1/audit_pool_unit_test";

  auditDbModule = await import("./audit-db");
  dbModule = await import("./index");
  auditRepoModule = await import("./repositories/audit-log.repo");
});

afterAll(async () => {
  // Restore so a later file in this worker sees the environment it expected.
  if (ORIGINAL_DATABASE_URL === undefined) {
    delete process.env.DATABASE_URL;
  } else {
    process.env.DATABASE_URL = ORIGINAL_DATABASE_URL;
  }
  await auditDbModule.auditPool.end();
  await dbModule.pool.end();
});

describe("audit pool isolation", () => {
  it("is a DIFFERENT pool object from the shared one", () => {
    expect(auditDbModule.auditPool).not.toBe(dbModule.pool);
    expect(auditDbModule.auditDb).not.toBe(dbModule.db);
  });

  it("is bounded — a flood cannot grow it into the auth path's budget", () => {
    expect(auditDbModule.auditPool.options.max).toBe(2);
  });

  it("fails fast rather than queueing a checkout forever", () => {
    // Unbounded queueing would relocate the starvation into memory instead of
    // removing it. The error this produces is swallowed by the emitter.
    expect(auditDbModule.auditPool.options.connectionTimeoutMillis).toBe(1000);
  });

  it("leaves the shared pool's settings untouched", () => {
    // The main pool is deliberately NOT given a ceiling or a timeout here —
    // that is a separate decision with its own blast radius. This change only
    // moves the audit writes off it.
    expect(dbModule.pool.options.max).not.toBe(2);
    expect(dbModule.pool.options.connectionTimeoutMillis).toBeFalsy();
  });

  it("survives an idle-client 'error' event instead of crashing the process", () => {
    // pg emits 'error' on the pool when a backend dies (maintenance, a killed
    // connection). An unhandled 'error' event on an EventEmitter throws.
    expect(auditDbModule.auditPool.listenerCount("error")).toBeGreaterThan(0);
    expect(() =>
      auditDbModule.auditPool.emit("error", new Error("idle client died")),
    ).not.toThrow();
  });

  it("audit-log.repo writes through the audit pool, not the shared pool", async () => {
    // The assertion that actually catches a revert: drive the repository and
    // observe WHICH pool receives the query.
    const auditQueries: unknown[] = [];
    const sharedQueries: unknown[] = [];

    const auditPool = auditDbModule.auditPool as unknown as {
      query: (...args: unknown[]) => Promise<unknown>;
    };
    const sharedPool = dbModule.pool as unknown as {
      query: (...args: unknown[]) => Promise<unknown>;
    };
    const originalAuditQuery = auditPool.query;
    const originalSharedQuery = sharedPool.query;

    auditPool.query = async (...args: unknown[]) => {
      auditQueries.push(args[0]);
      return { rows: [], rowCount: 0 };
    };
    sharedPool.query = async (...args: unknown[]) => {
      sharedQueries.push(args[0]);
      return { rows: [], rowCount: 0 };
    };

    try {
      await auditRepoModule.auditLogRepository.record({
        actor_type: "anonymous",
        action: "mcp.auth.denied",
        outcome: "denied",
      });
    } finally {
      auditPool.query = originalAuditQuery;
      sharedPool.query = originalSharedQuery;
    }

    expect(auditQueries).toHaveLength(1);
    expect(sharedQueries).toHaveLength(0);
  });
});
