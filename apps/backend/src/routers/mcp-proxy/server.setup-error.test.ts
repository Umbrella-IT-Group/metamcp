/**
 * A throw while `POST /mcp-proxy/server/mcp` sets up a new session must close
 * the upstream transport it started (METAMCP-SETUP-ERROR-LEAKS).
 *
 * The route starts the upstream transport (a STDIO child, an SSE stream, a
 * StreamableHTTP client) before it wires the proxy and hands the transport its
 * first request. Two throws used to leave that transport open: the proxy
 * wiring (`mcpProxy`), whose catch called `cleanupSession` while the session
 * maps were still empty because `onsessioninitialized` had not run, and the
 * first `handleRequest`, whose catch closed nothing at all. Neither answer
 * carries a session id, so nothing could reach the session again.
 *
 * A session that DID initialize before the throw is left alone, as the success
 * path leaves it: its id went to the client, which can keep using it or DELETE
 * it. Every case makes a further request afterwards, on a fresh session or on
 * the one that survived, to show the route still serves.
 *
 * Same harness as server.body-limit.test.ts: a real socket, the real router,
 * the real proxy wiring (wrapped so one call can be made to throw) and a real
 * SDK server transport; the upstream end is a stand-in that counts starts and
 * closes.
 */
import type { Server as HttpServer } from "node:http";

import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
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

// Every upstream transport the route has started and closed, since boot.
const upstream = vi.hoisted(() => ({ started: 0, closed: 0 }));

vi.mock("@modelcontextprotocol/sdk/client/streamableHttp.js", () => ({
  StreamableHTTPClientTransport: class {
    onmessage?: (message: unknown) => void;
    onclose?: () => void;
    onerror?: (error: Error) => void;
    sessionId = "upstream-session";
    private closedOnce = false;
    async start() {
      upstream.started += 1;
    }
    async close() {
      // Counted once per transport, as a real close is idempotent.
      if (this.closedOnce) return;
      this.closedOnce = true;
      upstream.closed += 1;
      this.onclose?.();
    }
    async send(message: { id?: unknown; method?: string }) {
      if (message.id === undefined || message.method === undefined) return;
      const result =
        message.method === "initialize"
          ? {
              protocolVersion: "2025-06-18",
              capabilities: {},
              serverInfo: { name: "upstream-echo", version: "0.0.0" },
            }
          : {};
      queueMicrotask(() =>
        this.onmessage?.({ jsonrpc: "2.0", id: message.id, result }),
      );
    }
    async terminateSession() {}
  },
}));

// The real proxy wiring behind a spy, so a single call can be made to throw.
vi.mock("../../lib/mcp-proxy", async (importOriginal) => {
  const real = await importOriginal<typeof import("../../lib/mcp-proxy")>();
  return { default: vi.fn(real.default) };
});

vi.mock("@/lib/metamcp/url-guard", () => ({
  assertPublicMcpUrl: vi.fn(async (url: string) => ({ url: new URL(url) })),
  createGuardedFetch: vi.fn(() => fetch),
}));
vi.mock("../../db/repositories", () => ({
  mcpServersRepository: {
    findAllAccessibleToUser: vi.fn().mockResolvedValue([]),
  },
}));
vi.mock("../../db/index", () => ({ db: {}, pool: {} }));
vi.mock("../../lib/metamcp/mcp-server-pool", () => ({
  mcpServerPool: { handleServerCrashWithoutNamespace: vi.fn() },
}));
vi.mock("../../lib/metamcp/client", () => ({
  transformDockerUrl: (url: string) => url,
}));

const { default: mcpProxy } = await import("../../lib/mcp-proxy");
const { default: serverRouter } = await import("./server");

const PROTOCOL_VERSION = "2025-06-18";
const UPSTREAM = "https://upstream.example.test/mcp";

let httpServer: HttpServer;
let baseUrl = "";
let rpcId = 0;

const request = (method: string, params: Record<string, unknown> = {}) =>
  JSON.stringify({ jsonrpc: "2.0", id: (rpcId += 1), method, params });

const initializeBody = () =>
  request("initialize", {
    protocolVersion: PROTOCOL_VERSION,
    capabilities: {},
    clientInfo: { name: "inspector", version: "0.0.0" },
  });

function post(body: string, sessionId?: string): Promise<Response> {
  const query = new URLSearchParams({
    transportType: "STREAMABLE_HTTP",
    url: UPSTREAM,
  });
  return fetch(`${baseUrl}/mcp-proxy/server/mcp?${query}`, {
    method: "POST",
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

/** Open a session and make a second request on it; both must be served. */
async function openSessionAndPing(): Promise<string> {
  const opened = await post(initializeBody());
  expect(opened.status).toBe(200);
  await opened.text();
  const sessionId = opened.headers.get("mcp-session-id") ?? "";
  expect(sessionId).not.toBe("");
  const pinged = await post(request("ping"), sessionId);
  expect(pinged.status).toBe(200);
  await pinged.text();
  return sessionId;
}

/** Let any close still queued behind a response run before counting. */
const settle = () => new Promise((resolve) => setTimeout(resolve, 50));

beforeAll(async () => {
  const app = express();
  // The parent router's admin-session gate, reduced to the user it leaves.
  app.use((req, _res, next) => {
    Object.assign(req, { user: { id: "admin-1", role: "admin" } });
    next();
  });
  app.use("/mcp-proxy/server", serverRouter);
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

describe("POST /mcp-proxy/server/mcp: a throw during setup closes what it started", () => {
  // Taken before the spy replaces it, so a case can run the real method.
  const realHandleRequest =
    StreamableHTTPServerTransport.prototype.handleRequest;
  const handleRequest = vi.spyOn(
    StreamableHTTPServerTransport.prototype,
    "handleRequest",
  );

  beforeEach(() => {
    handleRequest.mockClear();
    vi.mocked(mcpProxy).mockClear();
  });

  it("closes the upstream transport when the proxy wiring throws", async () => {
    const before = { ...upstream };
    vi.mocked(mcpProxy).mockImplementationOnce(() => {
      throw new Error("proxy wiring failed");
    });

    const failed = await post(initializeBody());

    expect(failed.status).toBe(500);
    await failed.text();
    expect(upstream.started - before.started).toBe(1);
    await vi.waitFor(() => expect(upstream.closed - before.closed).toBe(1));
    expect(handleRequest).not.toHaveBeenCalled();

    await openSessionAndPing();
  });

  it("closes the upstream transport when the first request throws before initializing", async () => {
    const before = { ...upstream };
    handleRequest.mockRejectedValueOnce(new Error("first request failed"));

    const failed = await post(initializeBody());

    expect(failed.status).toBe(500);
    await failed.text();
    expect(upstream.started - before.started).toBe(1);
    await vi.waitFor(() => expect(upstream.closed - before.closed).toBe(1));
    // Closed once, not once per side of the proxy.
    await settle();
    expect(upstream.closed - before.closed).toBe(1);

    await openSessionAndPing();
  });

  it("keeps a session that initialized before the throw, and serves a second request on it", async () => {
    const before = { ...upstream };
    handleRequest.mockImplementationOnce(async function (
      this: StreamableHTTPServerTransport,
      ...args: Parameters<StreamableHTTPServerTransport["handleRequest"]>
    ) {
      // Answer the initialize for real, then fail on the way out.
      await realHandleRequest.apply(this, args);
      throw new Error("failed after answering");
    });

    const opened = await post(initializeBody());

    expect(opened.status).toBe(200);
    await opened.text();
    const sessionId = opened.headers.get("mcp-session-id") ?? "";
    expect(sessionId).not.toBe("");

    const pinged = await post(request("ping"), sessionId);
    expect(pinged.status).toBe(200);
    await pinged.text();
    await settle();
    expect(upstream.started - before.started).toBe(1);
    expect(upstream.closed - before.closed).toBe(0);
  });
});
