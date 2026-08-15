/**
 * Integration tests for the gate on the two `/metamcp/:endpoint_name/admin/*`
 * routes.
 *
 * These sit on the PUBLIC endpoints router, next to the API-key data plane,
 * and were gated by `authenticateApiKey` alone — a key check with no role
 * check, satisfied by any endpoint key on the gateway. Neither route is
 * scoped to the endpoint named in its own URL: `reset-errors` with an empty
 * body clears the ERROR state of EVERY server and kicks off a
 * re-initialization sweep, and `error-status` answers with `findAll()`, the
 * whole server inventory. They are an operator control panel reachable with
 * a consumer credential.
 *
 * They now carry the same three middlewares, in the same order, as the whole
 * `/mcp-proxy` surface, so this suite mirrors `routers/mcp-proxy.admin-gate.
 * test.ts`. It drives the REAL `adminRouter` over a real socket. Mocked
 * seams:
 *  - `better-auth-mcp.middleware`, so a session can be simulated without a
 *    database, leaving `req.user` exactly as better-auth does,
 *  - `users.repo`, so the disabled lookup answers on command,
 *  - the endpoints repo, so the REAL `lookupEndpoint` runs (the 404-for-an-
 *    unknown-endpoint ordering is part of what is pinned here) without
 *    postgres,
 *  - the mcp-servers repo, the error tracker and `lib/startup`, so the
 *    handlers' own side effects are observable and `@/db` stays out of the
 *    import graph.
 *
 * `requireAdminMcpMiddleware` and `requireEnabledMcpMiddleware` are NOT
 * mocked; they are the code under test. Asserting the repositories stay
 * UNCALLED is the point of every denial case: the estate-wide reset and the
 * estate-wide listing must not run at all, rather than run and have their
 * response rewritten.
 *
 * `public-metamcp.estate-gate.test.ts` replaces this router with an empty
 * one so it can test `GET /metamcp/` without dragging in `@/db`; that stub
 * pins nothing about these routes, which is why they are tested here.
 */
import type { Server } from "node:http";

import express from "express";
import {
  afterAll,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";

vi.mock("@/utils/logger", () => ({
  default: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  },
}));

// Everything the mock factories touch lives in one `vi.hoisted` block: the
// factories are hoisted above this file's imports, so they cannot close over
// ordinary module-level consts.
const h = vi.hoisted(() => ({
  /** Session the mocked auth middleware attaches; null = signed out. */
  sessionUser: null as { id?: string; role?: string } | null,
  isDisabled: vi.fn(),
  findByName: vi.fn(),
  findAll: vi.fn(),
  resetServerErrorState: vi.fn(),
  resetAllAttempts: vi.fn(),
  getServerAttempts: vi.fn(),
  initializeIdleServers: vi.fn(),
}));

vi.mock("@/middleware/better-auth-mcp.middleware", () => ({
  betterAuthMcpMiddleware: (
    req: express.Request,
    res: express.Response,
    next: express.NextFunction,
  ) => {
    if (!h.sessionUser) {
      return res.status(401).json({ error: "Authentication required" });
    }
    (req as express.Request & { user?: unknown }).user = h.sessionUser;
    return next();
  },
}));

vi.mock("../../db/repositories/users.repo", () => ({
  usersRepository: { isDisabled: h.isDisabled },
}));

vi.mock("../../db/repositories/endpoints.repo", () => ({
  endpointsRepository: { findByName: h.findByName },
}));

vi.mock("../../db/repositories", () => ({
  mcpServersRepository: { findAll: h.findAll },
}));

vi.mock("../../lib/metamcp/server-error-tracker", () => ({
  serverErrorTracker: {
    resetServerErrorState: h.resetServerErrorState,
    resetAllAttempts: h.resetAllAttempts,
    getServerAttempts: h.getServerAttempts,
  },
}));

vi.mock("../../lib/startup", () => ({
  initializeIdleServers: h.initializeIdleServers,
}));

import adminRouter from "./admin";

let server: Server;
let baseUrl: string;

const RESET_PATH = "/metamcp/autotask/admin/reset-errors";
const STATUS_PATH = "/metamcp/autotask/admin/error-status";

/** Both routes, so one cannot be gated and the other forgotten. */
const surface: [string, string][] = [
  ["POST", RESET_PATH],
  ["GET", STATUS_PATH],
];

beforeAll(async () => {
  const app = express();
  app.use("/metamcp", adminRouter);
  await new Promise<void>((resolve) => {
    server = app.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  if (typeof address === "object" && address) {
    baseUrl = `http://127.0.0.1:${address.port}`;
  }
});

afterAll(async () => {
  await new Promise((resolve) => server.close(resolve));
});

beforeEach(() => {
  h.sessionUser = null;
  vi.clearAllMocks();
  // Default: a live account and a real endpoint. Each denial test arms its
  // own answer, so one that forgot to would fail OPEN and be caught by its
  // own assertion.
  h.isDisabled.mockResolvedValue(false);
  h.findByName.mockResolvedValue({
    uuid: "endpoint-1",
    name: "autotask",
    namespace_uuid: "ns-1",
  });
  h.findAll.mockResolvedValue([
    { uuid: "server-1", name: "autotask-upstream", error_status: "ERROR" },
  ]);
  h.resetServerErrorState.mockResolvedValue(undefined);
  h.getServerAttempts.mockReturnValue(0);
  h.initializeIdleServers.mockResolvedValue(undefined);
});

const signInAs = (role: string | undefined, id = "user-1") => {
  h.sessionUser = role === undefined ? { id } : { id, role };
};

/** No handler on either route ran. */
const expectNoEstateAccess = () => {
  expect(h.findAll).not.toHaveBeenCalled();
  expect(h.resetServerErrorState).not.toHaveBeenCalled();
  expect(h.resetAllAttempts).not.toHaveBeenCalled();
  expect(h.initializeIdleServers).not.toHaveBeenCalled();
};

describe("/metamcp/:endpoint_name/admin/* — the role gate", () => {
  it.each(surface)("member gets 403 on %s %s", async (method, path) => {
    signInAs("member");

    const response = await fetch(`${baseUrl}${path}`, { method });

    expect(response.status).toBe(403);
    expect(await response.json()).toMatchObject({ error: "Forbidden" });
    expectNoEstateAccess();
  });

  it.each(surface)("admin gets through on %s %s", async (method, path) => {
    signInAs("admin");

    const response = await fetch(`${baseUrl}${path}`, { method });

    expect(response.status).toBe(200);
    expect(h.findAll).toHaveBeenCalledTimes(1);
  });

  it("denies a session whose user carries no role at all", async () => {
    signInAs(undefined);

    const response = await fetch(`${baseUrl}${RESET_PATH}`, { method: "POST" });

    expect(response.status).toBe(403);
    expectNoEstateAccess();
  });

  it("denies an unrecognized role rather than defaulting to allow", async () => {
    signInAs("superuser");

    const response = await fetch(`${baseUrl}${RESET_PATH}`, { method: "POST" });

    expect(response.status).toBe(403);
    expectNoEstateAccess();
  });

  it.each(surface)(
    "an API key alone no longer opens %s %s",
    async (method, path) => {
      // The exact shape the routes used to accept: a consumer endpoint key,
      // no session cookie. It is now answered by the session check.
      const response = await fetch(`${baseUrl}${path}`, {
        method,
        headers: { "X-API-Key": "sk_mt_someone_elses_endpoint_key" },
      });

      expect(response.status).toBe(401);
      expectNoEstateAccess();
    },
  );
});

describe("/metamcp/:endpoint_name/admin/* — the disabled-account gate", () => {
  it.each(surface)("disabled admin gets 403 on %s %s", async (method, path) => {
    signInAs("admin");
    h.isDisabled.mockResolvedValue(true);

    const response = await fetch(`${baseUrl}${path}`, { method });

    expect(response.status).toBe(403);
    expect(h.isDisabled).toHaveBeenCalledWith("user-1");
    expectNoEstateAccess();
  });

  it("refuses the disabled account with the ROLE gate's exact body", async () => {
    // Indistinguishable on the wire from "you are not an admin": a caller
    // must not learn from here that an account exists and is locked out.
    signInAs("member");
    const roleDenial = await fetch(`${baseUrl}${RESET_PATH}`, {
      method: "POST",
    });
    const roleBody = await roleDenial.text();

    signInAs("admin");
    h.isDisabled.mockResolvedValue(true);
    const disabledDenial = await fetch(`${baseUrl}${RESET_PATH}`, {
      method: "POST",
    });

    expect(disabledDenial.status).toBe(roleDenial.status);
    expect(await disabledDenial.text()).toBe(roleBody);
  });

  it("denies when the disabled lookup throws, without hanging the request", async () => {
    signInAs("admin");
    h.isDisabled.mockRejectedValue(new Error("connection terminated"));

    const response = await fetch(`${baseUrl}${RESET_PATH}`, { method: "POST" });

    expect(response.status).toBe(403);
    expectNoEstateAccess();
  });
});

describe("/metamcp/:endpoint_name/admin/* — lookup still runs first", () => {
  it.each(surface)(
    "an unknown endpoint is 404, not 401, on %s %s",
    async (method, path) => {
      // Ordering pin: `lookupEndpoint` stays ahead of authentication so a
      // typo answers "no such endpoint" rather than "sign in". This is the
      // ordering the API-key version had, so the gate discloses nothing new.
      h.findByName.mockResolvedValue(undefined);

      const response = await fetch(
        `${baseUrl}${path.replace("autotask", "no-such-endpoint")}`,
        { method },
      );

      expect(response.status).toBe(404);
      expectNoEstateAccess();
    },
  );
});

describe("POST reset-errors — the admin path still works", () => {
  it("resets every errored server and triggers the idle sweep for an admin", async () => {
    signInAs("admin");

    const response = await fetch(`${baseUrl}${RESET_PATH}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });

    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({ success: true, reset: 1 });
    expect(h.resetServerErrorState).toHaveBeenCalledWith("server-1");
    expect(h.resetAllAttempts).toHaveBeenCalledTimes(1);
    expect(h.initializeIdleServers).toHaveBeenCalledTimes(1);
  });

  it("answers a failure with the constant body, never the error text", async () => {
    signInAs("admin");
    h.findAll.mockRejectedValue(
      new Error('connect ECONNREFUSED postgres-internal:5432 db "metamcp"'),
    );

    const response = await fetch(`${baseUrl}${RESET_PATH}`, { method: "POST" });
    const body = await response.text();

    expect(response.status).toBe(500);
    expect(JSON.parse(body)).toEqual({ error: "internal_server_error" });
    expect(body).not.toContain("postgres-internal");
  });
});
