/**
 * `GET /health/upstream`: the admin per-server detail for a server whose most
 * recent connect the backend rejected with HTTP 401/403.
 *
 * Contract: three extra keys appear on that server's admin detail ONLY while
 * the pool holds a rejection record for it; a server without one keeps
 * exactly the shape it had (health-upstream-handler.test.ts pins that shape
 * byte for byte), and the anonymous body is the same five fields either way.
 * Reachability is unchanged: a connect-time rejection already reads
 * unreachable through the connect-failure stamp.
 */
import express from "express";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({
  findAll: vi.fn(),
  getPoolStatus: vi.fn(),
  getPoolConfig: vi.fn(),
  authHandler: vi.fn(),
}));

vi.mock("../auth", () => ({ auth: { handler: h.authHandler } }));
vi.mock("../db/repositories", () => ({
  mcpServersRepository: { findAll: h.findAll, findByUuid: vi.fn() },
  usersRepository: {
    findRoleById: vi.fn().mockResolvedValue("admin"),
    isDisabled: vi.fn().mockResolvedValue(false),
  },
}));
vi.mock("./metamcp/mcp-server-pool", () => ({
  mcpServerPool: {
    getPoolStatus: h.getPoolStatus,
    getPoolConfig: h.getPoolConfig,
  },
}));
vi.mock("./metamcp/server-error-tracker", () => ({
  serverErrorTracker: { isServerInErrorState: vi.fn() },
}));
vi.mock("../routers/oauth/utils", () => ({
  getBaseUrl: () => "https://gateway.example.invalid",
}));
vi.mock("../utils/logger", () => ({
  default: { error: vi.fn(), info: vi.fn(), warn: vi.fn() },
}));

const { createUpstreamHealthHandler } = await import(
  "./health-upstream-handler"
);

const T0 = new Date("2026-11-11T05:00:00.000Z").getTime();
const ROWS = [
  { uuid: "srv-rejected", name: "backend-rejected", error_status: "NONE" },
  { uuid: "srv-ok", name: "backend-ok", error_status: "NONE" },
];
const POOL = {
  idle: 1,
  active: 0,
  pending: 0,
  perServerCounts: { "srv-ok": 1 },
  lastConnectFailureAt: { "srv-rejected": T0 - 5000 },
  lastConnectSuccessAt: { "srv-ok": T0 - 1000 },
  pingFailures: {},
};

function invoke(
  handler: express.RequestHandler,
  cookie?: string,
): Promise<{ body: Record<string, unknown>; bytes: string }> {
  return new Promise((resolve, reject) => {
    const res = {
      status: () => res,
      json(payload: Record<string, unknown>) {
        resolve({ body: payload, bytes: JSON.stringify(payload) });
        return res;
      },
    };
    const req = {
      headers: cookie ? { cookie } : {},
    } as unknown as express.Request;
    Promise.resolve(
      handler(req, res as unknown as express.Response, (error?: unknown) =>
        reject(error ?? new Error("next() called")),
      ),
    ).catch(reject);
  });
}

beforeEach(() => {
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(T0);
  h.findAll.mockResolvedValue(ROWS);
  h.getPoolConfig.mockReturnValue({
    maxConnectionsPerServer: 5,
    maxTotalConnections: 100,
  });
  h.authHandler.mockImplementation(
    async () =>
      new Response(JSON.stringify({ user: { id: "admin-user" } }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
  );
});
afterEach(() => {
  vi.useRealTimers();
});

describe("/health/upstream: backend credentials rejection", () => {
  it("adds the rejection keys to the admin detail of the rejected server only", async () => {
    h.getPoolStatus.mockReturnValue({
      ...POOL,
      backendAuthRejections: {
        "srv-rejected": { at: T0 - 3000, status: 401 },
      },
    });

    const admin = await invoke(
      createUpstreamHealthHandler(),
      "better-auth.session_token=admin",
    );

    const servers = admin.body.servers as Array<Record<string, unknown>>;
    expect(servers[0]).toMatchObject({
      uuid: "srv-rejected",
      reachable: false,
      auth_rejected: true,
      auth_rejected_http_status: 401,
      auth_rejected_at: new Date(T0 - 3000).toISOString(),
    });
    expect(Object.keys(servers[1])).not.toContain("auth_rejected");
    expect(Object.keys(servers[1])).not.toContain("auth_rejected_http_status");
    expect(Object.keys(servers[1])).not.toContain("auth_rejected_at");
  });

  it("leaves every server's detail untouched when the pool holds no rejection", async () => {
    h.getPoolStatus.mockReturnValue({ ...POOL, backendAuthRejections: {} });

    const admin = await invoke(
      createUpstreamHealthHandler(),
      "better-auth.session_token=admin",
    );

    for (const server of admin.body.servers as Array<Record<string, unknown>>) {
      expect(Object.keys(server)).toEqual([
        "uuid",
        "name",
        "in_error",
        "connection_count",
        "reachable",
        "last_connect_failure_at",
        "last_connect_success_at",
        "ping_failures",
      ]);
    }
  });

  it("serves the same five anonymous fields with or without a rejection", async () => {
    h.getPoolStatus.mockReturnValue({
      ...POOL,
      backendAuthRejections: {
        "srv-rejected": { at: T0 - 3000, status: 403 },
      },
    });

    const anonymous = await invoke(createUpstreamHealthHandler());

    expect(Object.keys(anonymous.body)).toEqual([
      "status",
      "healthy",
      "total_servers",
      "errored_servers",
      "unreachable_servers",
    ]);
    expect(anonymous.bytes).not.toContain("auth_rejected");
  });
});
