/**
 * `GET /health/upstream`: the production handler `index.ts` mounts, driven
 * directly.
 *
 * What is pinned here:
 *  - the anonymous rollup is computed from ONE `mcp_servers` read, with each
 *    row's own `error_status` deciding its error state (no per-server lookup);
 *  - a successful anonymous rollup is reused for ten seconds from completion,
 *    concurrent anonymous requests share one computation, and expiry triggers
 *    exactly one refresh;
 *  - a failed computation answers the constant 500 body, is not cached, and
 *    the next request computes again;
 *  - an admin always gets a fresh computation with `servers` and `pool`, and
 *    nothing an admin request computed reaches an anonymous response;
 *  - the anonymous body's bytes for a fixed snapshot are exactly what the
 *    endpoint served before the cache, on a real socket as well as in-process.
 *
 * Mocked seams: the repositories (rows and the admin role lookup), the pool's
 * in-memory status, better-auth's session endpoint, and the per-server error
 * tracker, which is mocked only so a test can prove nothing calls it.
 */

import { readFileSync } from "node:fs";
import type { Server } from "node:http";
import path from "node:path";

import express from "express";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({
  findAll: vi.fn(),
  findByUuid: vi.fn(),
  findRoleById: vi.fn(),
  isDisabled: vi.fn(),
  getPoolStatus: vi.fn(),
  getPoolConfig: vi.fn(),
  isServerInErrorState: vi.fn(),
  authHandler: vi.fn(),
  loggerError: vi.fn(),
}));

vi.mock("../auth", () => ({ auth: { handler: h.authHandler } }));
vi.mock("../db/repositories", () => ({
  mcpServersRepository: { findAll: h.findAll, findByUuid: h.findByUuid },
  usersRepository: { findRoleById: h.findRoleById, isDisabled: h.isDisabled },
}));
vi.mock("./metamcp/mcp-server-pool", () => ({
  mcpServerPool: {
    getPoolStatus: h.getPoolStatus,
    getPoolConfig: h.getPoolConfig,
  },
}));
vi.mock("./metamcp/server-error-tracker", () => ({
  serverErrorTracker: { isServerInErrorState: h.isServerInErrorState },
}));
vi.mock("../routers/oauth/utils", () => ({
  getBaseUrl: () => "https://gateway.example.invalid",
}));
vi.mock("../utils/logger", () => ({
  default: { error: h.loggerError, info: vi.fn(), warn: vi.fn() },
}));

const { ANONYMOUS_UPSTREAM_HEALTH_TTL_MS, createUpstreamHealthHandler } =
  await import("./health-upstream-handler");

const ADMIN_COOKIE = "better-auth.session_token=admin";
const T0 = new Date("2026-11-11T05:00:00.000Z").getTime();

/** A healthy estate: two servers, both connected, neither in ERROR. */
const HEALTHY_ROWS = [
  { uuid: "srv-a", name: "backend-a", error_status: "NONE" },
  { uuid: "srv-b", name: "backend-b", error_status: "NONE" },
];
const HEALTHY_POOL = {
  idle: 2,
  active: 1,
  pending: 0,
  activeSessionIds: [],
  idleServerUuids: [],
  perServerCounts: { "srv-a": 1, "srv-b": 2 },
  lastConnectFailureAt: {},
  lastConnectSuccessAt: { "srv-a": T0 - 1000, "srv-b": T0 - 2000 },
  pingFailures: {},
};

/**
 * An unhealthy estate: one server in ERROR, one with no connections whose
 * last connect failed, one cold server with no stamp (reachable), one fine.
 */
const UNHEALTHY_ROWS = [
  { uuid: "srv-err", name: "backend-err", error_status: "ERROR" },
  { uuid: "srv-down", name: "backend-down", error_status: "NONE" },
  { uuid: "srv-cold", name: "backend-cold", error_status: "NONE" },
  { uuid: "srv-ok", name: "backend-ok", error_status: "NONE" },
];
const UNHEALTHY_POOL = {
  idle: 1,
  active: 0,
  pending: 1,
  activeSessionIds: [],
  idleServerUuids: [],
  perServerCounts: { "srv-err": 0, "srv-ok": 1 },
  lastConnectFailureAt: { "srv-down": T0 - 5000 },
  lastConnectSuccessAt: { "srv-ok": T0 - 1000 },
  pingFailures: { "srv-down": 3 },
};
const POOL_CONFIG = { maxConnectionsPerServer: 5, maxTotalConnections: 100 };

/**
 * The exact anonymous bodies for the two snapshots: the five fields in their
 * established order. An Uptime Kuma keyword monitor reads this body.
 */
const HEALTHY_BYTES =
  '{"status":"ok","healthy":true,"total_servers":2,"errored_servers":0,"unreachable_servers":0}';
const UNHEALTHY_BYTES =
  '{"status":"ok","healthy":false,"total_servers":4,"errored_servers":1,"unreachable_servers":2}';
const ERROR_BYTES = '{"status":"error","healthy":false}';

interface Deferred<T> {
  promise: Promise<T>;
  resolve: (value: T) => void;
  reject: (error: unknown) => void;
}
function deferred<T>(): Deferred<T> {
  let resolve!: (value: T) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

interface Result {
  status: number;
  body: Record<string, unknown>;
  bytes: string;
}

/**
 * Run one request through the handler. `bytes` is what express's `res.json`
 * writes for this app (no `json spaces` or replacer is configured), i.e.
 * `JSON.stringify` of the payload; the socket test below checks that on the
 * wire.
 */
function invoke(
  handler: express.RequestHandler,
  options: { cookie?: string } = {},
): Promise<Result> {
  return new Promise<Result>((resolve, reject) => {
    let status = 200;
    const res = {
      status(code: number) {
        status = code;
        return res;
      },
      json(payload: Record<string, unknown>) {
        resolve({ status, body: payload, bytes: JSON.stringify(payload) });
        return res;
      },
    };
    const req = {
      headers: options.cookie ? { cookie: options.cookie } : {},
    } as unknown as express.Request;
    Promise.resolve(
      handler(req, res as unknown as express.Response, (error?: unknown) =>
        reject(error ?? new Error("handler called next()")),
      ),
    ).catch(reject);
  });
}

/** Let pending promise callbacks (lazy imports, awaits) run. */
async function settle() {
  for (let i = 0; i < 20; i += 1) {
    await Promise.resolve();
  }
  await new Promise<void>((resolve) => setImmediate(resolve));
}

function serveSnapshot(rows: unknown[], pool: unknown) {
  h.findAll.mockResolvedValue(rows);
  h.getPoolStatus.mockReturnValue(pool);
}

beforeEach(() => {
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(T0);
  h.getPoolConfig.mockReturnValue(POOL_CONFIG);
  // better-auth resolves the admin cookie to a user whose role is admin.
  h.authHandler.mockImplementation(
    async () =>
      new Response(JSON.stringify({ user: { id: "admin-user" } }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
  );
  h.findRoleById.mockResolvedValue("admin");
  h.isDisabled.mockResolvedValue(false);
});

afterEach(() => {
  vi.useRealTimers();
  vi.resetAllMocks();
});

describe("/health/upstream — anonymous body for a fixed snapshot", () => {
  it("is byte-identical for a healthy estate", async () => {
    serveSnapshot(HEALTHY_ROWS, HEALTHY_POOL);

    const result = await invoke(createUpstreamHealthHandler());

    expect(result.status).toBe(200);
    expect(result.bytes).toBe(HEALTHY_BYTES);
  });

  it("is byte-identical for an unhealthy estate, with errors read from each row", async () => {
    serveSnapshot(UNHEALTHY_ROWS, UNHEALTHY_POOL);

    const result = await invoke(createUpstreamHealthHandler());

    expect(result.status).toBe(200);
    expect(result.bytes).toBe(UNHEALTHY_BYTES);
  });

  it("answers the constant 500 body when the rows cannot be read", async () => {
    h.findAll.mockRejectedValue(
      new Error("connect ECONNREFUSED db.internal:5432"),
    );
    h.getPoolStatus.mockReturnValue(HEALTHY_POOL);

    const result = await invoke(createUpstreamHealthHandler());

    expect(result.status).toBe(500);
    expect(result.bytes).toBe(ERROR_BYTES);
    // Logged, not swallowed.
    expect(h.loggerError).toHaveBeenCalledWith(
      "/health/upstream failed:",
      expect.any(Error),
    );
  });

  it("is the same on the wire through express", async () => {
    const app = express();
    app.get("/health/upstream", createUpstreamHealthHandler());
    const server = await new Promise<Server>((resolve) => {
      const s = app.listen(0, "127.0.0.1", () => resolve(s));
    });
    try {
      const address = server.address();
      if (!address || typeof address === "string") {
        throw new Error("test server has no TCP address");
      }
      const url = `http://127.0.0.1:${address.port}/health/upstream`;

      serveSnapshot(UNHEALTHY_ROWS, UNHEALTHY_POOL);
      const ok = await fetch(url);
      expect(ok.status).toBe(200);
      expect(await ok.text()).toBe(UNHEALTHY_BYTES);

      // Past the TTL, a failing refresh: the constant 500 on the wire.
      vi.setSystemTime(T0 + ANONYMOUS_UPSTREAM_HEALTH_TTL_MS);
      h.findAll.mockRejectedValue(new Error("db down"));
      const failed = await fetch(url);
      expect(failed.status).toBe(500);
      expect(await failed.text()).toBe(ERROR_BYTES);
    } finally {
      await new Promise<void>((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      );
    }
  });
});

describe("/health/upstream — one read per anonymous refresh", () => {
  it("shares one findAll between concurrent cold requests", async () => {
    const rows = deferred<unknown[]>();
    h.findAll.mockReturnValue(rows.promise);
    h.getPoolStatus.mockReturnValue(HEALTHY_POOL);
    const handler = createUpstreamHealthHandler();

    const pending = [invoke(handler), invoke(handler), invoke(handler)];
    await settle();
    expect(h.findAll).toHaveBeenCalledTimes(1);

    rows.resolve(HEALTHY_ROWS);
    const results = await Promise.all(pending);

    expect(results.map((r) => r.bytes)).toEqual([
      HEALTHY_BYTES,
      HEALTHY_BYTES,
      HEALTHY_BYTES,
    ]);
    expect(h.findAll).toHaveBeenCalledTimes(1);
  });

  it("makes no per-server error lookup", async () => {
    serveSnapshot(UNHEALTHY_ROWS, UNHEALTHY_POOL);
    const handler = createUpstreamHealthHandler();

    await invoke(handler);
    await invoke(handler, { cookie: ADMIN_COOKIE });

    expect(h.findAll).toHaveBeenCalledTimes(2);
    expect(h.isServerInErrorState).not.toHaveBeenCalled();
    expect(h.findByUuid).not.toHaveBeenCalled();
  });

  it("answers from the cache with no query until the TTL has passed", async () => {
    serveSnapshot(HEALTHY_ROWS, HEALTHY_POOL);
    const handler = createUpstreamHealthHandler();

    await invoke(handler);
    expect(h.findAll).toHaveBeenCalledTimes(1);

    // The estate changes; the cached rollup is still served, with no query,
    // up to the last millisecond of the TTL.
    serveSnapshot(UNHEALTHY_ROWS, UNHEALTHY_POOL);
    for (const offset of [0, 1, ANONYMOUS_UPSTREAM_HEALTH_TTL_MS - 1]) {
      vi.setSystemTime(T0 + offset);
      expect((await invoke(handler)).bytes).toBe(HEALTHY_BYTES);
    }
    expect(h.findAll).toHaveBeenCalledTimes(1);
    expect(h.getPoolStatus).toHaveBeenCalledTimes(1);
  });

  it("refreshes exactly once at expiry, even under concurrency", async () => {
    serveSnapshot(HEALTHY_ROWS, HEALTHY_POOL);
    const handler = createUpstreamHealthHandler();
    await invoke(handler);

    vi.setSystemTime(T0 + ANONYMOUS_UPSTREAM_HEALTH_TTL_MS);
    const rows = deferred<unknown[]>();
    h.findAll.mockReturnValue(rows.promise);
    h.getPoolStatus.mockReturnValue(UNHEALTHY_POOL);

    const pending = [invoke(handler), invoke(handler)];
    await settle();
    expect(h.findAll).toHaveBeenCalledTimes(2);

    rows.resolve(UNHEALTHY_ROWS);
    expect((await Promise.all(pending)).map((r) => r.bytes)).toEqual([
      UNHEALTHY_BYTES,
      UNHEALTHY_BYTES,
    ]);
    expect(h.findAll).toHaveBeenCalledTimes(2);
  });

  it("measures the TTL from when the refresh completed", async () => {
    const rows = deferred<unknown[]>();
    h.findAll.mockReturnValue(rows.promise);
    h.getPoolStatus.mockReturnValue(HEALTHY_POOL);
    const handler = createUpstreamHealthHandler();

    const first = invoke(handler);
    await settle();
    // The read takes four seconds.
    vi.setSystemTime(T0 + 4000);
    rows.resolve(HEALTHY_ROWS);
    await first;

    // Still fresh ten seconds after the START, because it completed later.
    vi.setSystemTime(T0 + ANONYMOUS_UPSTREAM_HEALTH_TTL_MS + 3999);
    await invoke(handler);
    expect(h.findAll).toHaveBeenCalledTimes(1);

    vi.setSystemTime(T0 + ANONYMOUS_UPSTREAM_HEALTH_TTL_MS + 4000);
    h.findAll.mockResolvedValue(HEALTHY_ROWS);
    await invoke(handler);
    expect(h.findAll).toHaveBeenCalledTimes(2);
  });
});

describe("/health/upstream — a failed anonymous refresh", () => {
  it("shares the failure with concurrent requests, caches nothing, and recovers", async () => {
    const rows = deferred<unknown[]>();
    h.findAll.mockReturnValue(rows.promise);
    h.getPoolStatus.mockReturnValue(HEALTHY_POOL);
    const handler = createUpstreamHealthHandler();

    const pending = [invoke(handler), invoke(handler)];
    await settle();
    rows.reject(new Error("db down"));
    const failed = await Promise.all(pending);
    expect(failed.map((r) => [r.status, r.bytes])).toEqual([
      [500, ERROR_BYTES],
      [500, ERROR_BYTES],
    ]);
    expect(h.findAll).toHaveBeenCalledTimes(1);

    // Same instant: the rejection was not cached, so the next request reads.
    h.findAll.mockResolvedValue(HEALTHY_ROWS);
    const recovered = await invoke(handler);
    expect(recovered.status).toBe(200);
    expect(recovered.bytes).toBe(HEALTHY_BYTES);
    expect(h.findAll).toHaveBeenCalledTimes(2);

    // And the recovery is cached as usual.
    await invoke(handler);
    expect(h.findAll).toHaveBeenCalledTimes(2);
  });

  it("does not extend an expired success when its refresh fails", async () => {
    serveSnapshot(HEALTHY_ROWS, HEALTHY_POOL);
    const handler = createUpstreamHealthHandler();
    await invoke(handler);

    vi.setSystemTime(T0 + ANONYMOUS_UPSTREAM_HEALTH_TTL_MS);
    h.findAll.mockRejectedValue(new Error("db down"));
    const failed = await invoke(handler);
    expect(failed.status).toBe(500);
    expect(failed.bytes).toBe(ERROR_BYTES);

    // The stale success is not served afterwards either: every request past
    // expiry reads again until one succeeds.
    const again = await invoke(handler);
    expect(again.status).toBe(500);
    expect(h.findAll).toHaveBeenCalledTimes(3);
  });
});

describe("/health/upstream — admin requests", () => {
  it("compute fresh every time and never touch the anonymous cache", async () => {
    serveSnapshot(HEALTHY_ROWS, HEALTHY_POOL);
    const handler = createUpstreamHealthHandler();

    // Warm the anonymous cache.
    await invoke(handler);
    expect(h.findAll).toHaveBeenCalledTimes(1);

    // The estate changes inside the TTL. Each admin request reads it.
    serveSnapshot(UNHEALTHY_ROWS, UNHEALTHY_POOL);
    const firstAdmin = await invoke(handler, { cookie: ADMIN_COOKIE });
    const secondAdmin = await invoke(handler, { cookie: ADMIN_COOKIE });
    expect(h.findAll).toHaveBeenCalledTimes(3);
    expect(firstAdmin.body).toMatchObject({
      healthy: false,
      total_servers: 4,
      errored_servers: 1,
      unreachable_servers: 2,
    });
    expect(secondAdmin.body.servers).toHaveLength(4);
    expect(secondAdmin.body.pool).toEqual({
      idle: 1,
      active: 0,
      pending: 1,
      total: 2,
      max_connections_per_server: 5,
      max_total_connections: 100,
    });

    // The anonymous view is still the cached rollup: the admin reads neither
    // refreshed nor replaced it.
    const anonymous = await invoke(handler);
    expect(anonymous.bytes).toBe(HEALTHY_BYTES);
    expect(h.findAll).toHaveBeenCalledTimes(3);
  });

  it("carries the same per-server detail as before", async () => {
    serveSnapshot(UNHEALTHY_ROWS, UNHEALTHY_POOL);

    const admin = await invoke(createUpstreamHealthHandler(), {
      cookie: ADMIN_COOKIE,
    });

    expect(admin.body.servers).toEqual([
      {
        uuid: "srv-err",
        name: "backend-err",
        in_error: true,
        connection_count: 0,
        reachable: false,
        last_connect_failure_at: null,
        last_connect_success_at: null,
        ping_failures: 0,
      },
      {
        uuid: "srv-down",
        name: "backend-down",
        in_error: false,
        connection_count: 0,
        reachable: false,
        last_connect_failure_at: new Date(T0 - 5000).toISOString(),
        last_connect_success_at: null,
        ping_failures: 3,
      },
      {
        uuid: "srv-cold",
        name: "backend-cold",
        in_error: false,
        connection_count: 0,
        reachable: true,
        last_connect_failure_at: null,
        last_connect_success_at: null,
        ping_failures: 0,
      },
      {
        uuid: "srv-ok",
        name: "backend-ok",
        in_error: false,
        connection_count: 1,
        reachable: true,
        last_connect_failure_at: null,
        last_connect_success_at: new Date(T0 - 1000).toISOString(),
        ping_failures: 0,
      },
    ]);
  });

  it("does not seed an anonymous response with admin detail", async () => {
    serveSnapshot(UNHEALTHY_ROWS, UNHEALTHY_POOL);
    const handler = createUpstreamHealthHandler();

    // Admin first, on a cold handler: the anonymous request that follows must
    // compute its own rollup and carry nothing from the admin's.
    await invoke(handler, { cookie: ADMIN_COOKIE });
    const anonymous = await invoke(handler);

    expect(anonymous.bytes).toBe(UNHEALTHY_BYTES);
    expect(anonymous.body).not.toHaveProperty("servers");
    expect(anonymous.body).not.toHaveProperty("pool");
    expect(anonymous.bytes).not.toContain("backend-");
    expect(h.findAll).toHaveBeenCalledTimes(2);
  });

  it("serves a non-admin cookie the anonymous view from the cache", async () => {
    serveSnapshot(HEALTHY_ROWS, HEALTHY_POOL);
    const handler = createUpstreamHealthHandler();
    await invoke(handler);

    h.findRoleById.mockResolvedValue("user");
    const member = await invoke(handler, { cookie: "better-auth.session=m" });

    expect(member.bytes).toBe(HEALTHY_BYTES);
    expect(h.findAll).toHaveBeenCalledTimes(1);
  });

  it("answers an admin the constant 500 body when the rows cannot be read", async () => {
    h.findAll.mockRejectedValue(new Error("db down"));
    h.getPoolStatus.mockReturnValue(HEALTHY_POOL);

    const admin = await invoke(createUpstreamHealthHandler(), {
      cookie: ADMIN_COOKIE,
    });

    expect(admin.status).toBe(500);
    expect(admin.bytes).toBe(ERROR_BYTES);
  });
});

/**
 * `index.ts` listens at import, so the wiring is pinned at the source, the
 * technique verified-caller.test.ts and the rate-limit mount guards use: the
 * route must be served by the handler tested above, built once.
 */
describe("/health/upstream — mounted in index.ts", () => {
  const INDEX_SOURCE = readFileSync(
    path.resolve(import.meta.dirname, "../index.ts"),
    "utf8",
  );

  it("finds the file it is meant to be guarding", () => {
    expect(INDEX_SOURCE).toContain("const app = express()");
    expect(INDEX_SOURCE).toContain("./lib/health-upstream-handler");
  });

  it("serves the route with the extracted handler, built once", () => {
    expect(INDEX_SOURCE).toMatch(
      /app\.get\(\s*"\/health\/upstream",\s*createUpstreamHealthHandler\(\)\s*\)/,
    );
    expect(INDEX_SOURCE.match(/createUpstreamHealthHandler\(\)/g)).toHaveLength(
      1,
    );
    expect(INDEX_SOURCE.match(/"\/health\/upstream"/g)).toHaveLength(1);
  });
});
