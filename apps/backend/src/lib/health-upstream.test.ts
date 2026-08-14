/**
 * `GET /health/upstream` used to return the full backend-MCP topology
 * (`servers[]`: every upstream by UUID and name) plus raw connection-pool
 * internals to anyone who could reach the URL — no authentication at all.
 * The endpoint has to STAY reachable unauthenticated, because Grafana and
 * the Cloudflare healthcheck consume the liveness rollup, so the fix is a
 * split response rather than a 401.
 *
 * Two properties are worth pinning:
 *  - a non-admin (including an anonymous prober) gets the liveness fields
 *    and NOTHING else, and
 *  - the admin check fails closed on every error path, without throwing —
 *    a health endpoint that 500s because a session lookup hiccuped would
 *    page the on-call for nothing.
 */

import express from "express";
import { beforeEach, describe, expect, it, vi } from "vitest";

const handler = vi.fn();
const findRoleById = vi.fn();

vi.mock("../auth", () => ({ auth: { handler } }));
vi.mock("../db/repositories", () => ({ usersRepository: { findRoleById } }));
vi.mock("../routers/oauth/utils", () => ({
  getBaseUrl: () => "https://gateway.example",
}));
vi.mock("../utils/logger", () => ({
  default: { error: vi.fn(), info: vi.fn(), warn: vi.fn() },
}));

const {
  buildUpstreamHealthBody,
  buildUpstreamHealthErrorBody,
  isAdminHealthRequest,
} = await import("./health-upstream");

const LIVENESS = {
  healthy: false,
  total_servers: 9,
  errored_servers: 1,
  unreachable_servers: 2,
};

const DETAIL = {
  pool: { idle: 3, active: 4, max_total_connections: 100 },
  servers: [{ uuid: "srv-1", name: "mcp-autotask" }],
};

/** A request with (or without) a session cookie. */
const reqWith = (cookie?: string) =>
  ({ headers: cookie ? { cookie } : {} }) as unknown as express.Request;

const sessionOk = (body: unknown) =>
  ({ ok: true, json: async () => body }) as unknown as Response;

describe("buildUpstreamHealthBody — what an unauthenticated prober sees", () => {
  it("returns exactly the five liveness fields and no detail", () => {
    const body = buildUpstreamHealthBody(LIVENESS, null);

    expect(Object.keys(body).sort()).toEqual([
      "errored_servers",
      "healthy",
      "status",
      "total_servers",
      "unreachable_servers",
    ]);
    // Named explicitly as well as by key-set, so a rename of either field
    // cannot quietly satisfy the assertion above.
    expect(body).not.toHaveProperty("servers");
    expect(body).not.toHaveProperty("pool");
  });

  it("still reports the values a monitor alarms on", () => {
    // The whole point of not 401-ing: probes must keep working.
    const body = buildUpstreamHealthBody(LIVENESS, null);

    expect(body.status).toBe("ok");
    expect(body.healthy).toBe(false);
    expect(body.total_servers).toBe(9);
    expect(body.errored_servers).toBe(1);
    expect(body.unreachable_servers).toBe(2);
  });

  it("leaks no server name or uuid anywhere in the serialised body", () => {
    const body = buildUpstreamHealthBody(LIVENESS, null);

    expect(JSON.stringify(body)).not.toContain("mcp-autotask");
    expect(JSON.stringify(body)).not.toContain("srv-1");
  });
});

describe("buildUpstreamHealthBody — what an admin sees", () => {
  it("attaches servers and pool on top of the same liveness fields", () => {
    const body = buildUpstreamHealthBody(LIVENESS, DETAIL);

    expect(body.servers).toEqual(DETAIL.servers);
    expect(body.pool).toEqual(DETAIL.pool);
    expect(body.total_servers).toBe(9);
  });
});

describe("buildUpstreamHealthErrorBody — the 500 branch", () => {
  it("is a constant: two fields, no echo of whatever threw", () => {
    // The branch used to serialise `error.message`. The errors it actually
    // catches come from pg, so that message reads like
    // `connect ECONNREFUSED postgres-internal:5432` — internal host, port,
    // sometimes SQL — handed to an unauthenticated caller on the endpoint
    // the success path was just gated for. The body takes no error at all
    // now, so there is nothing to forget to redact.
    const body = buildUpstreamHealthErrorBody();

    expect(body).toEqual({ status: "error", healthy: false });
    // Named as well as key-set-matched, per this file's convention.
    expect(body).not.toHaveProperty("error");
    expect(body).not.toHaveProperty("message");
  });

  it("hands back a fresh object each call", () => {
    // Express serialises the returned object directly; sharing one instance
    // across responses would let a later mutation rewrite an earlier reply.
    expect(buildUpstreamHealthErrorBody()).not.toBe(
      buildUpstreamHealthErrorBody(),
    );
  });
});

describe("isAdminHealthRequest", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("is false with no cookie, without touching auth or the database", async () => {
    // The common case — an external monitor. It must not cost a session
    // round-trip or a query.
    await expect(isAdminHealthRequest(reqWith())).resolves.toBe(false);
    expect(handler).not.toHaveBeenCalled();
    expect(findRoleById).not.toHaveBeenCalled();
  });

  it("is true for a cookie resolving to an admin", async () => {
    handler.mockResolvedValue(sessionOk({ user: { id: "u-admin" } }));
    findRoleById.mockResolvedValue("admin");

    await expect(isAdminHealthRequest(reqWith("session=x"))).resolves.toBe(
      true,
    );
    expect(findRoleById).toHaveBeenCalledWith("u-admin");
  });

  it("is false for an authenticated member", async () => {
    handler.mockResolvedValue(sessionOk({ user: { id: "u-member" } }));
    findRoleById.mockResolvedValue("member");

    await expect(isAdminHealthRequest(reqWith("session=x"))).resolves.toBe(
      false,
    );
  });

  it("is false when the role comes back unknown or absent", async () => {
    // findRoleById returns undefined for an id with no row. A truthy test
    // here would be a bug; the check is strict equality with "admin".
    handler.mockResolvedValue(sessionOk({ user: { id: "u-ghost" } }));

    for (const role of [undefined, null, "", "Admin", "administrator"]) {
      findRoleById.mockResolvedValue(role);
      await expect(isAdminHealthRequest(reqWith("session=x"))).resolves.toBe(
        false,
      );
    }
  });

  it("is false when the session is rejected", async () => {
    handler.mockResolvedValue({ ok: false } as unknown as Response);

    await expect(isAdminHealthRequest(reqWith("bad=cookie"))).resolves.toBe(
      false,
    );
    expect(findRoleById).not.toHaveBeenCalled();
  });

  it("is false when the session carries no user id", async () => {
    handler.mockResolvedValue(sessionOk({}));

    await expect(isAdminHealthRequest(reqWith("session=x"))).resolves.toBe(
      false,
    );
    expect(findRoleById).not.toHaveBeenCalled();
  });

  it("resolves false rather than throwing when auth blows up", async () => {
    // A rejection escaping here would turn the health endpoint into a 500 —
    // the monitor would alarm on the session check, not on gateway health.
    handler.mockRejectedValue(new Error("better-auth exploded"));

    await expect(isAdminHealthRequest(reqWith("session=x"))).resolves.toBe(
      false,
    );
  });

  it("resolves false rather than throwing when the database blows up", async () => {
    handler.mockResolvedValue(sessionOk({ user: { id: "u-admin" } }));
    findRoleById.mockRejectedValue(new Error("connection terminated"));

    await expect(isAdminHealthRequest(reqWith("session=x"))).resolves.toBe(
      false,
    );
  });
});
