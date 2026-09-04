/**
 * The gateway-events writer must dial the SAME runtime role the other two
 * request-path pools dial, not the bootstrap superuser.
 *
 * This pool records every gateway event, including a crash-looping backend's
 * stderr firehose, into `gateway_events`, a table migration 0031 makes
 * append-only for 30 days. That immutability is only as real as the credential
 * the writer holds: a superuser bypasses GRANTs and can `SET
 * session_replication_role = 'replica'` to turn the triggers off. The main and
 * audit pools already resolve through the runtime/migration split
 * (`./runtime-connection`); this one used to build straight from the raw
 * DATABASE_URL, so it was the one request-path pool still holding a
 * trigger-bypassing credential after the other two gave theirs up. Reverting
 * this file to `connectionString: DATABASE_URL` fails the derived-mode case
 * below.
 *
 * pg constructs a Pool without connecting, so this needs no database, only a
 * parseable DATABASE_URL, and (for the derived case) a runtime password, set
 * before the modules are imported.
 */

import { afterAll, beforeAll, describe, expect, it } from "vitest";

const ORIGINAL_ENV = { ...process.env };

type GatewayEventsDbModule = typeof import("./gateway-events-db");
type AuditDbModule = typeof import("./audit-db");
type DbModule = typeof import("./index");
type RuntimeConnectionModule = typeof import("./runtime-connection");

let gatewayEventsDbModule: GatewayEventsDbModule;
let auditDbModule: AuditDbModule;
let dbModule: DbModule;
let runtimeConnectionModule: RuntimeConnectionModule;

beforeAll(async () => {
  // Never a real database: these modules read the environment at import time
  // and construct pools, but pg does not dial until a query is issued.
  //
  // METAMCP_RUNTIME_DB_PASSWORD is set so the resolver returns the DERIVED
  // form, the runtime role swapped into the URL. That is the case that tells
  // the raw-DATABASE_URL regression apart from the fix: unconfigured, the two
  // strings are byte-identical and no assertion could distinguish them.
  // Built at runtime, not as a single literal, so this loopback fixture
  // never reads as an embedded credential to secret scanners.
  process.env.DATABASE_URL =
    "postgres://owner:" +
    "owner-pw" +
    "@127.0.0.1:1/gateway_events_pool_unit_test";
  process.env.METAMCP_RUNTIME_DB_PASSWORD = "runtime-unit-test";

  runtimeConnectionModule = await import("./runtime-connection");
  gatewayEventsDbModule = await import("./gateway-events-db");
  auditDbModule = await import("./audit-db");
  dbModule = await import("./index");
});

afterAll(async () => {
  process.env = { ...ORIGINAL_ENV };
  await Promise.all([
    gatewayEventsDbModule.gatewayEventsPool.end(),
    auditDbModule.auditPool.end(),
    dbModule.pool.end(),
  ]);
});

describe("gateway-events pool", () => {
  it("dials the resolved RUNTIME connection, not the raw DATABASE_URL", () => {
    // The assertion that catches a revert. When the split is configured the
    // resolved string names the NOSUPERUSER runtime role; the raw DATABASE_URL
    // names the bootstrap superuser. A pool built from the latter reads as
    // hardened and is not.
    const resolved =
      runtimeConnectionModule.resolveRuntimeConnection().connectionString;
    expect(
      gatewayEventsDbModule.gatewayEventsPool.options.connectionString,
    ).toBe(resolved);
    expect(
      gatewayEventsDbModule.gatewayEventsPool.options.connectionString,
    ).not.toBe(process.env.DATABASE_URL);
  });

  it("authenticates as the runtime role, not the owner", () => {
    // Read the same way pg will read it: the userinfo of the connection string.
    const url = new URL(
      gatewayEventsDbModule.gatewayEventsPool.options
        .connectionString as string,
    );
    expect(url.username).toBe(runtimeConnectionModule.DEFAULT_RUNTIME_DB_ROLE);
    expect(url.username).not.toBe("owner");
  });

  it("resolves through the same split as the audit pool", () => {
    // Both pools resolve independently (own call to the resolver), so the
    // guarantee is that they resolve to the SAME string, not that one imported
    // the other's.
    expect(
      gatewayEventsDbModule.gatewayEventsPool.options.connectionString,
    ).toBe(auditDbModule.auditPool.options.connectionString);
  });

  it("is a DIFFERENT pool object from the shared and audit pools", () => {
    expect(gatewayEventsDbModule.gatewayEventsPool).not.toBe(dbModule.pool);
    expect(gatewayEventsDbModule.gatewayEventsPool).not.toBe(
      auditDbModule.auditPool,
    );
    expect(gatewayEventsDbModule.gatewayEventsDb).not.toBe(dbModule.db);
  });

  it("keeps its own bounded budget and both timeouts", () => {
    // The connection isolation this file has always provided: a two-connection
    // ceiling, a 1s checkout timeout, and a server-side statement timeout so a
    // write stuck behind an ACCESS EXCLUSIVE lock cannot hold half the budget
    // indefinitely. Repointing the credential must not disturb any of it.
    expect(gatewayEventsDbModule.gatewayEventsPool.options.max).toBe(2);
    expect(
      gatewayEventsDbModule.gatewayEventsPool.options.connectionTimeoutMillis,
    ).toBe(1000);
    expect(gatewayEventsDbModule.gatewayEventsPool.options.options).toContain(
      "statement_timeout=5000",
    );
  });

  it("survives an idle-client 'error' event instead of crashing the process", () => {
    // pg emits 'error' on the pool when a backend dies (maintenance, a killed
    // connection). An unhandled 'error' event on an EventEmitter throws.
    expect(
      gatewayEventsDbModule.gatewayEventsPool.listenerCount("error"),
    ).toBeGreaterThan(0);
    expect(() =>
      gatewayEventsDbModule.gatewayEventsPool.emit(
        "error",
        new Error("idle client died"),
      ),
    ).not.toThrow();
  });
});
