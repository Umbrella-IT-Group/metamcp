/**
 * Integration tests for the /mcp-proxy admin gate — the member-role RCE.
 *
 * GET /mcp-proxy/server/stdio takes `command`, `args` and `env` off the
 * QUERY STRING and spawns them with the backend's full environment
 * (`mcp-proxy/server.ts` `createTransport` ->
 * `ProcessManagedStdioTransport.start`). Its only gate was
 * `betterAuthMcpMiddleware`, a session check with no role check, so any
 * member-role account could execute commands on the gateway host.
 *
 * These drive the REAL `mcpProxyRouter` composition (parent router, mount
 * order, both sub-router mounts) over a real socket, mirroring
 * `routers/m365.test.ts`. Two seams are mocked:
 *  - `better-auth-mcp.middleware`, so a session can be simulated without a
 *    database, leaving `req.user` exactly as better-auth does,
 *  - the two sub-routers, replaced by stubs that record invocation and
 *    mirror the real route tables. Recording invocation is the point: for a
 *    member the spawn-capable handler must never run at all, and asserting
 *    the stub stayed untouched proves the gate short-circuits before
 *    delegation rather than merely rewriting the response.
 *
 * `requireAdminMcpMiddleware` itself is NOT mocked; it is the code under
 * test.
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

  return { state, SERVER_ROUTES, METAMCP_ROUTES, buildStubRouter };
});

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

describe("/mcp-proxy — whole-surface coverage", () => {
  // Both sub-routers, every method, so a route added later cannot quietly
  // land outside the gate.
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
