/**
 * Integration tests for the two gates on /mcp-proxy — the member-role RCE and
 * the disabled-account lockout.
 *
 * GET /mcp-proxy/server/stdio spawns a process with the backend's full
 * environment (`mcp-proxy/server.ts` `createTransport` ->
 * `ProcessManagedStdioTransport.start`), and used to take the `command`,
 * `args` and `env` for it straight off the QUERY STRING. Its only gate was
 * `betterAuthMcpMiddleware`, a session check with no role check, so any
 * member-role account could execute commands on the gateway host.
 *
 * The command is now sourced from the `mcp_servers` row (see
 * `mcp-proxy/server.spawn-source.test.ts`), but that is the OTHER half of the
 * defence and this suite deliberately does not depend on it: the query shape
 * below is kept verbatim because what these tests pin is that a non-admin is
 * refused BEFORE any of it is looked at.
 *
 * The second gate answers the other half of the same question. Being an admin
 * is not the same as being an ALLOWED admin: `users.disabled` (migration
 * 0027) locks an account out, nothing on this router re-read it, and sessions
 * live 30 days here — so a disabled admin kept the spawn route above for the
 * remaining life of a cookie they already held.
 *
 * These drive the REAL `mcpProxyRouter` composition (parent router, mount
 * order, both sub-router mounts) over a real socket, mirroring
 * `routers/m365.test.ts`. Three seams are mocked:
 *  - `better-auth-mcp.middleware`, so a session can be simulated without a
 *    database, leaving `req.user` exactly as better-auth does,
 *  - `users.repo`, so the disabled lookup answers on command — and so
 *    `db/index.ts`, which throws without DATABASE_URL, stays out of the
 *    import graph,
 *  - the two sub-routers, replaced by stubs that record invocation and
 *    mirror the real route tables. Recording invocation is the point: for a
 *    member the spawn-capable handler must never run at all, and asserting
 *    the stub stayed untouched proves the gate short-circuits before
 *    delegation rather than merely rewriting the response.
 *
 * `requireAdminMcpMiddleware` and `requireEnabledMcpMiddleware` are NOT
 * mocked; they are the code under test.
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
const h = vi.hoisted(() => {
  const state = {
    /** Session the mocked auth middleware attaches; null = signed out. */
    sessionUser: null as { id?: string; role?: string } | null,
    /** Every sub-router handler that actually ran. */
    handlerCalls: [] as string[],
  };

  /** Route tables copied from the real sub-routers: [method, path]. */
  const SERVER_ROUTES: [string, string][] = [
    ["get", "/stdio"],
    ["get", "/sse"],
    ["get", "/mcp"],
    ["post", "/mcp"],
    ["delete", "/mcp"],
    ["post", "/message"],
    ["get", "/health"],
  ];

  const METAMCP_ROUTES: [string, string][] = [
    ["get", "/:uuid/mcp"],
    ["post", "/:uuid/mcp"],
    ["delete", "/:uuid/mcp"],
    ["get", "/:uuid/sse"],
    ["post", "/:uuid/message"],
    ["get", "/health"],
    ["get", "/info"],
  ];

  const buildStubRouter = async (label: string, routes: [string, string][]) => {
    // Dynamic import: this runs before the file's static imports are
    // evaluated, so `express` is not yet bound as a value here.
    const { Router } = await import("express");
    const stub = Router();
    type Registrar = (
      this: express.Router,
      path: string,
      handler: express.RequestHandler,
    ) => unknown;
    for (const [method, routePath] of routes) {
      const register = (stub as unknown as Record<string, Registrar>)[method];
      register.call(stub, routePath, (_req, res) => {
        state.handlerCalls.push(
          `${label}:${method.toUpperCase()} ${routePath}`,
        );
        res.status(200).json({ reached: true });
      });
    }
    return stub;
  };

  return {
    state,
    isDisabled: vi.fn(),
    SERVER_ROUTES,
    METAMCP_ROUTES,
    buildStubRouter,
  };
});

vi.mock("../db/repositories/users.repo", () => ({
  usersRepository: { isDisabled: h.isDisabled },
}));

vi.mock("../middleware/better-auth-mcp.middleware", () => ({
  betterAuthMcpMiddleware: (
    req: express.Request,
    res: express.Response,
    next: express.NextFunction,
  ) => {
    if (!h.state.sessionUser) {
      return res.status(401).json({ error: "Authentication required" });
    }
    (req as express.Request & { user?: unknown }).user = h.state.sessionUser;
    return next();
  },
}));

vi.mock("./mcp-proxy/server", async () => ({
  default: await h.buildStubRouter("server", h.SERVER_ROUTES),
}));

vi.mock("./mcp-proxy/metamcp", async () => ({
  default: await h.buildStubRouter("metamcp", h.METAMCP_ROUTES),
}));

import mcpProxyRouter from "./mcp-proxy";

let server: Server;
let baseUrl: string;

/** The exact RCE shape: command + args + env straight off the query string. */
const RCE_PATH =
  "/mcp-proxy/server/stdio?transportType=STDIO&command=%2Fbin%2Fsh" +
  "&args=-c%20id&env=%7B%7D";

beforeAll(async () => {
  const app = express();
  app.use("/mcp-proxy", mcpProxyRouter);
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
  h.state.sessionUser = null;
  h.state.handlerCalls.length = 0;
  // Default: the account is live. Each disabled test arms its own answer, so
  // one that forgot to would fail OPEN and be caught by its own assertion.
  h.isDisabled.mockReset().mockResolvedValue(false);
});

const signInAs = (role: string | undefined, id = "user-1") => {
  h.state.sessionUser = role === undefined ? { id } : { id, role };
};

describe("/mcp-proxy — member-role RCE gate", () => {
  it("rejects a member on the STDIO spawn route without reaching the handler", async () => {
    signInAs("member");

    const response = await fetch(`${baseUrl}${RCE_PATH}`);

    expect(response.status).toBe(403);
    expect(await response.json()).toMatchObject({ error: "Forbidden" });
    // The spawn-capable handler must never have run.
    expect(h.state.handlerCalls).toEqual([]);
  });

  it("lets an admin through to the STDIO route", async () => {
    signInAs("admin");

    const response = await fetch(`${baseUrl}${RCE_PATH}`);

    expect(response.status).toBe(200);
    expect(h.state.handlerCalls).toEqual(["server:GET /stdio"]);
  });

  it("rejects a member on DELETE /server/mcp (was session-only, not admin-only)", async () => {
    signInAs("member");

    const response = await fetch(`${baseUrl}/mcp-proxy/server/mcp`, {
      method: "DELETE",
      headers: { "mcp-session-id": "someone-elses-session" },
    });

    expect(response.status).toBe(403);
    expect(h.state.handlerCalls).toEqual([]);
  });

  it("lets an admin through to DELETE /server/mcp", async () => {
    signInAs("admin");

    const response = await fetch(`${baseUrl}/mcp-proxy/server/mcp`, {
      method: "DELETE",
      headers: { "mcp-session-id": "own-session" },
    });

    expect(response.status).toBe(200);
    expect(h.state.handlerCalls).toEqual(["server:DELETE /mcp"]);
  });
});

// Both sub-routers, every method, so a route added later cannot quietly land
// outside the gates. Shared by the role suite and the disabled suite below —
// one list means a new route cannot be added to one gate's coverage and
// forgotten by the other's.
const surface: [string, string][] = [
  ["GET", "/mcp-proxy/server/stdio"],
  ["GET", "/mcp-proxy/server/sse"],
  ["GET", "/mcp-proxy/server/mcp"],
  ["POST", "/mcp-proxy/server/mcp"],
  ["DELETE", "/mcp-proxy/server/mcp"],
  ["POST", "/mcp-proxy/server/message"],
  ["GET", "/mcp-proxy/server/health"],
  ["GET", "/mcp-proxy/metamcp/ns-1/mcp"],
  ["POST", "/mcp-proxy/metamcp/ns-1/mcp"],
  ["DELETE", "/mcp-proxy/metamcp/ns-1/mcp"],
  ["GET", "/mcp-proxy/metamcp/ns-1/sse"],
  ["POST", "/mcp-proxy/metamcp/ns-1/message"],
  ["GET", "/mcp-proxy/metamcp/health"],
  ["GET", "/mcp-proxy/metamcp/info"],
];

describe("/mcp-proxy — whole-surface coverage", () => {
  it.each(surface)("member gets 403 on %s %s", async (method, path) => {
    signInAs("member");

    const response = await fetch(`${baseUrl}${path}`, { method });

    expect(response.status).toBe(403);
    expect(h.state.handlerCalls).toEqual([]);
  });

  it.each(surface)("admin gets through on %s %s", async (method, path) => {
    signInAs("admin");

    const response = await fetch(`${baseUrl}${path}`, { method });

    expect(response.status).toBe(200);
    expect(h.state.handlerCalls).toHaveLength(1);
  });
});

describe("/mcp-proxy — the gate is fail-closed", () => {
  it("denies a session whose user carries no role at all", async () => {
    signInAs(undefined);

    const response = await fetch(`${baseUrl}${RCE_PATH}`);

    expect(response.status).toBe(403);
    expect(h.state.handlerCalls).toEqual([]);
  });

  it("denies an unrecognized role rather than defaulting to allow", async () => {
    signInAs("superuser");

    const response = await fetch(`${baseUrl}${RCE_PATH}`);

    expect(response.status).toBe(403);
    expect(h.state.handlerCalls).toEqual([]);
  });

  it("denies a role that differs from admin only by case", async () => {
    signInAs("Admin");

    const response = await fetch(`${baseUrl}${RCE_PATH}`);

    expect(response.status).toBe(403);
    expect(h.state.handlerCalls).toEqual([]);
  });

  it("still answers 401 (not 403) when there is no session at all", async () => {
    // Order proof: authentication runs before authorization, so an anonymous
    // caller is stopped by the session check and never reaches the role gate.
    const response = await fetch(`${baseUrl}${RCE_PATH}`);

    expect(response.status).toBe(401);
    expect(h.state.handlerCalls).toEqual([]);
  });
});

describe("/mcp-proxy — the disabled-account gate", () => {
  it("refuses a DISABLED ADMIN on the STDIO spawn route", async () => {
    // The whole point of the gate: role alone said yes. Disable is the
    // containment button, and until this check it did not reach the one
    // route on this gateway that runs commands.
    signInAs("admin");
    h.isDisabled.mockResolvedValue(true);

    const response = await fetch(`${baseUrl}${RCE_PATH}`);

    expect(response.status).toBe(403);
    expect(h.isDisabled).toHaveBeenCalledWith("user-1");
    expect(h.state.handlerCalls).toEqual([]);
  });

  it.each(surface)("disabled admin gets 403 on %s %s", async (method, path) => {
    signInAs("admin");
    h.isDisabled.mockResolvedValue(true);

    const response = await fetch(`${baseUrl}${path}`, { method });

    expect(response.status).toBe(403);
    expect(h.state.handlerCalls).toEqual([]);
  });

  it.each(surface)(
    "enabled admin is still served %s %s",
    async (method, path) => {
      // The gate has to be additive: closing the lockout must not close the
      // proxy for the operators who use it.
      signInAs("admin");

      const response = await fetch(`${baseUrl}${path}`, { method });

      expect(response.status).toBe(200);
      expect(h.state.handlerCalls).toHaveLength(1);
    },
  );

  it("refuses the disabled account with the ROLE gate's exact body", async () => {
    // Indistinguishable on the wire from "you are not an admin": a caller
    // must not be able to use this endpoint to learn that an account exists
    // and has been locked out. The reason goes to the log instead.
    signInAs("member");
    const roleDenial = await fetch(`${baseUrl}${RCE_PATH}`);
    const roleBody = await roleDenial.text();

    signInAs("admin");
    h.isDisabled.mockResolvedValue(true);
    const disabledDenial = await fetch(`${baseUrl}${RCE_PATH}`);

    expect(disabledDenial.status).toBe(roleDenial.status);
    expect(await disabledDenial.text()).toBe(roleBody);
  });

  it("runs BEFORE the role gate, so the lockout does not depend on it", async () => {
    // Ordering pin, not an accident of implementation: if /mcp-proxy is ever
    // opened to another role, the disabled check must already be in front of
    // that decision rather than behind it. A member reaching the disabled
    // lookup at all is what proves the order.
    signInAs("member");

    const response = await fetch(`${baseUrl}${RCE_PATH}`);

    expect(response.status).toBe(403);
    expect(h.isDisabled).toHaveBeenCalledWith("user-1");
    expect(h.state.handlerCalls).toEqual([]);
  });

  it("denies when the disabled lookup throws, without hanging the request", async () => {
    // An async express middleware that rejects hands nothing to next(err), so
    // a propagated database failure would leave a spawn-capable route waiting
    // rather than refused. It is caught at the gate and answered 403.
    signInAs("admin");
    h.isDisabled.mockRejectedValue(new Error("connection terminated"));

    const response = await fetch(`${baseUrl}${RCE_PATH}`);

    expect(response.status).toBe(403);
    expect(h.state.handlerCalls).toEqual([]);
  });

  it("denies a session that carries no user id, without querying", async () => {
    // isDisabled(undefined) would match no row and fail closed anyway, but
    // the id is what the gate is about — deny before the query, not after.
    h.state.sessionUser = { role: "admin" };

    const response = await fetch(`${baseUrl}${RCE_PATH}`);

    expect(response.status).toBe(403);
    expect(h.isDisabled).not.toHaveBeenCalled();
    expect(h.state.handlerCalls).toEqual([]);
  });

  it("still answers 401 when there is no session at all", async () => {
    // The disabled gate must not turn an anonymous caller's 401 into a 403:
    // authentication still runs first.
    const response = await fetch(`${baseUrl}${RCE_PATH}`);

    expect(response.status).toBe(401);
    expect(h.isDisabled).not.toHaveBeenCalled();
  });
});
