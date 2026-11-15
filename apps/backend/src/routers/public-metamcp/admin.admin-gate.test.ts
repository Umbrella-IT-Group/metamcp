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
 *  - the endpoints repo, so the REAL `lookupEndpointAfterAuth` runs without
 *    postgres (where it sits in the chain is part of what is pinned here: an
 *    anonymous caller must not be able to tell a real endpoint name from an
 *    invented one, while an authenticated admin still gets a plain 404),
 *  - the mcp-servers repo, the error tracker and `lib/startup`, so the
 *    handlers' own side effects are observable and `@/db` stays out of the
 *    import graph,
 *  - the shared server error reset (`lib/metamcp/reset-server-errors`), which
 *    the reset route and the tRPC `mcpServers.resetErrors` procedure both
 *    call; its own steps are pinned in that module's test and against a real
 *    Postgres in trpc/admin-plane-key-powers.integration.test.ts.
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
  resetServerErrors: vi.fn(),
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

// TEST-EDIT (error reset): the reset route now calls
// the implementation it shares with the tRPC procedure instead of resetting
// through the error tracker itself, so that is the seam a denial must leave
// uncalled.
vi.mock("../../lib/metamcp/reset-server-errors", () => ({
  resetServerErrors: h.resetServerErrors,
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
  h.resetServerErrors.mockResolvedValue({
    reset: [{ uuid: "server-1", name: "autotask-upstream" }],
    recovery: {
      status: "succeeded",
      servers: [
        { uuid: "server-1", name: "autotask-upstream", status: "connected" },
      ],
    },
  });
});

const signInAs = (role: string | undefined, id = "user-1") => {
  h.sessionUser = role === undefined ? { id } : { id, role };
};

/** No handler on either route ran. */
const expectNoEstateAccess = () => {
  expect(h.resetServerErrors).not.toHaveBeenCalled();
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
    // TEST-EDIT (key powers): the reset route reaches the shared reset, which
    // selects the servers itself; the status route still lists them.
    if (path === RESET_PATH) {
      expect(h.resetServerErrors).toHaveBeenCalledTimes(1);
    } else {
      expect(h.findAll).toHaveBeenCalledTimes(1);
    }
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

describe("/metamcp/:endpoint_name/admin/* — lookup runs behind the gate", () => {
  it.each(surface)(
    "an anonymous caller cannot tell a real endpoint from an invented one on %s %s",
    async (method, path) => {
      // ENUMERATION-ORACLE PIN, and the reason `lookupEndpoint` moved behind
      // the gate. It used to run first, so a signed-out caller got 404 for a
      // name that does not exist and 401 for one that does: a free
      // does-this-exist answer for every guess, on routes anyone can reach.
      // Real name first, with no session.
      const real = await fetch(`${baseUrl}${path}`, { method });
      const realBody = await real.text();

      // Then a name the repository refuses to resolve. Nothing about the
      // answer may differ, and the lookup must not have been consulted at
      // all: an unauthenticated request should not reach the database.
      h.findByName.mockResolvedValue(undefined);
      const invented = await fetch(
        `${baseUrl}${path.replace("autotask", "no-such-endpoint")}`,
        { method },
      );

      expect(real.status).toBe(401);
      expect(invented.status).toBe(real.status);
      expect(await invented.text()).toBe(realBody);
      expect(h.findByName).not.toHaveBeenCalled();
      expectNoEstateAccess();
    },
  );

  it.each(surface)(
    "an authenticated admin still gets an honest 404 for an unknown endpoint on %s %s",
    async (method, path) => {
      // The 404 is not deleted, it is MOVED behind the gate. An operator who
      // has proven who they are is exactly who should be told a name is
      // wrong, and they can already list every endpoint in the admin UI.
      signInAs("admin");
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
  // TEST-EDIT (key powers): the route hands the request to the reset it shares
  // with the tRPC procedure (status change and audit row in one transaction,
  // then recovery of the reset servers only), so this asserts that hand-off
  // and the unchanged response shape instead of the old in-route sweep.
  it("resets every errored server through the shared reset, as the signed-in person", async () => {
    signInAs("admin");

    const response = await fetch(`${baseUrl}${RESET_PATH}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });

    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({
      success: true,
      reset: 1,
      servers: ["autotask-upstream"],
      recovery: { status: "succeeded" },
    });
    expect(h.resetServerErrors).toHaveBeenCalledTimes(1);
    const [input, actor] = h.resetServerErrors.mock.calls[0];
    expect(input).toEqual({ serverUuid: undefined });
    expect(actor).toMatchObject({ actor_id: "user-1" });
    expect(actor).not.toHaveProperty("admin_plane");
  });

  it("passes a named server through and answers an unknown one with 404", async () => {
    signInAs("admin");
    const { TRPCError } = await import("@trpc/server");
    h.resetServerErrors.mockRejectedValue(
      new TRPCError({ code: "NOT_FOUND", message: "MCP server not found" }),
    );

    const response = await fetch(`${baseUrl}${RESET_PATH}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ serverUuid: "server-404" }),
    });

    expect(response.status).toBe(404);
    expect(await response.json()).toEqual({
      success: false,
      error: "MCP server not found",
    });
    expect(h.resetServerErrors.mock.calls[0][0]).toEqual({
      serverUuid: "server-404",
    });
  });

  it("answers a failure with the constant body, never the error text", async () => {
    signInAs("admin");
    // TEST-EDIT (key powers): the failure now comes from the shared reset, which
    // propagates database and audit errors instead of swallowing them.
    h.resetServerErrors.mockRejectedValue(
      new Error('connect ECONNREFUSED postgres-internal:5432 db "metamcp"'),
    );

    const response = await fetch(`${baseUrl}${RESET_PATH}`, { method: "POST" });
    const body = await response.text();

    expect(response.status).toBe(500);
    expect(JSON.parse(body)).toEqual({ error: "internal_server_error" });
    expect(body).not.toContain("postgres-internal");
  });
});
