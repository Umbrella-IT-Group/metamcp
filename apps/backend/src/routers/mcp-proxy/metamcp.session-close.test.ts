/**
 * A session on the Inspector's namespace route, `/mcp-proxy/metamcp/:uuid/mcp`,
 * lives until its DELETE, not until its initialize response ends
 * (METAMCP-PROXY-NAMESPACE-SESSION-CLOSE).
 *
 * The route used to register its session cleanup on the initialize response's
 * `close` event. That response ends as soon as the initialize is answered, so
 * the session was torn down at once and every follow-up request on it got 404
 * "Transport not found". These tests make second and third requests on the
 * same session, then DELETE it and check what the DELETE released.
 *
 * Driven over a real socket through the real router, a real SDK transport and
 * a real SDK `Server`; only the namespace server factory, the connection pool
 * and the database are faked (same harness as metamcp.body-limit.test.ts).
 */
import type { Server as HttpServer } from "node:http";

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
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
  default: { error: vi.fn(), warn: vi.fn(), info: vi.fn(), debug: vi.fn() },
}));
vi.mock("@/db", () => ({ db: {}, pool: { on: vi.fn() } }));
vi.mock("@/db/audit-db", () => ({ auditDb: {}, auditPool: { on: vi.fn() } }));

// Each namespace server the route creates, with its cleanup spy, in order.
const created = vi.hoisted(() => [] as { cleanup: ReturnType<typeof vi.fn> }[]);

vi.mock("../../lib/metamcp/index", () => ({
  createServer: vi.fn(async () => {
    const instance = {
      server: new Server(
        { name: "session-close-namespace", version: "0.0.0" },
        { capabilities: {} },
      ),
      cleanup: vi.fn().mockResolvedValue(undefined),
    };
    created.push(instance);
    return instance;
  }),
}));
vi.mock("../../lib/metamcp/mcp-server-pool", () => ({
  mcpServerPool: { cleanupSession: vi.fn().mockResolvedValue(undefined) },
}));

import { createServer } from "../../lib/metamcp/index";
import { mcpServerPool } from "../../lib/metamcp/mcp-server-pool";
import metamcpRouter from "./metamcp";

const PROTOCOL_VERSION = "2025-06-18";
const NAMESPACE_UUID = "cccccccc-3333-4333-8333-cccccccccccc";
const ROUTE = `/mcp-proxy/metamcp/${NAMESPACE_UUID}/mcp`;

let httpServer: HttpServer;
let baseUrl = "";
let rpcId = 0;

function send(
  method: "POST" | "DELETE",
  sessionId?: string,
  body?: string,
): Promise<Response> {
  return fetch(`${baseUrl}${ROUTE}`, {
    method,
    headers: {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      ...(sessionId
        ? {
            "mcp-session-id": sessionId,
            "mcp-protocol-version": PROTOCOL_VERSION,
          }
        : {}),
    },
    body,
  });
}

const rpc = (method: string, params: Record<string, unknown> = {}) =>
  JSON.stringify({ jsonrpc: "2.0", id: (rpcId += 1), method, params });

async function initialize(): Promise<string> {
  const response = await send(
    "POST",
    undefined,
    rpc("initialize", {
      protocolVersion: PROTOCOL_VERSION,
      capabilities: {},
      clientInfo: { name: "inspector", version: "0.0.0" },
    }),
  );
  expect(response.status).toBe(200);
  await response.text();
  const sessionId = response.headers.get("mcp-session-id") ?? "";
  expect(sessionId).not.toBe("");
  return sessionId;
}

/** Let a `close` handler queued behind a finished response run. */
const settle = () => new Promise((resolve) => setTimeout(resolve, 50));

beforeAll(async () => {
  const app = express();
  // The parent router's admin-session gate, reduced to the user it leaves.
  app.use((req, _res, next) => {
    Object.assign(req, { user: { id: "admin-1", role: "admin" } });
    next();
  });
  app.use("/mcp-proxy/metamcp", metamcpRouter);
  await new Promise<void>((resolve) => {
    httpServer = app.listen(0, "127.0.0.1", resolve);
  });
  const address = httpServer.address();
  if (typeof address === "object" && address) {
    baseUrl = `http://127.0.0.1:${address.port}`;
  }
});

afterAll(async () => {
  httpServer.closeAllConnections();
  await new Promise<void>((resolve) => httpServer.close(() => resolve()));
});

beforeEach(() => {
  created.length = 0;
  vi.mocked(createServer).mockClear();
  vi.mocked(mcpServerPool.cleanupSession).mockClear();
});

describe("POST /mcp-proxy/metamcp/:uuid/mcp session lifetime", () => {
  it("serves later requests on the session after the initialize response ends", async () => {
    const sessionId = await initialize();
    await settle();

    for (const method of ["ping", "tools/list"]) {
      const response = await send("POST", sessionId, rpc(method));
      // tools/list is not a capability of the stand-in server, so the SDK
      // answers it with a JSON-RPC error. What matters is the 200: the
      // session is there to answer at all.
      expect(response.status).toBe(200);
      await response.text();
    }

    expect(createServer).toHaveBeenCalledTimes(1);
    expect(created[0].cleanup).not.toHaveBeenCalled();
    expect(mcpServerPool.cleanupSession).not.toHaveBeenCalled();

    const deleted = await send("DELETE", sessionId);
    expect(deleted.status).toBe(200);
  });

  it("releases the session on DELETE, after which it is gone", async () => {
    const sessionId = await initialize();
    const pinged = await send("POST", sessionId, rpc("ping"));
    expect(pinged.status).toBe(200);
    await pinged.text();

    const deleted = await send("DELETE", sessionId);

    expect(deleted.status).toBe(200);
    expect(created[0].cleanup).toHaveBeenCalledTimes(1);
    expect(mcpServerPool.cleanupSession).toHaveBeenCalledWith(sessionId);

    const after = await send("POST", sessionId, rpc("ping"));
    expect(after.status).toBe(404);
    await after.text();
  });
});
