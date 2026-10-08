/**
 * The request-body ceiling on the Inspector's single-server route,
 * `POST /mcp-proxy/server/mcp`, at the byte.
 *
 * Same contract as the public route (see
 * routers/public-metamcp/streamable-http.body-limit.test.ts and
 * lib/metamcp/mcp-request-body-limit): exactly the limit is served, one byte
 * more is refused with 413 and a JSON-RPC error, for the initialize that
 * creates the transport and for later requests on its session.
 *
 * Driven over a real socket through the real router, the real proxy wiring
 * (lib/mcp-proxy) and a real SDK server transport. The upstream end is a
 * stand-in client transport that answers each request, so no connection
 * leaves the process; the destination guard, the database and the pool are
 * faked. Dropping `maxRequestBodySize` from the route fails these tests.
 */
import type { Server as HttpServer } from "node:http";

import express from "express";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

vi.mock("@/utils/logger", () => ({
  default: { error: vi.fn(), warn: vi.fn(), info: vi.fn(), debug: vi.fn() },
}));

// The upstream MCP server, reduced to a transport that answers every request
// it is sent: `initialize` with a server identity, anything else with `{}`.
vi.mock("@modelcontextprotocol/sdk/client/streamableHttp.js", () => ({
  StreamableHTTPClientTransport: class {
    onmessage?: (message: unknown) => void;
    onclose?: () => void;
    onerror?: (error: Error) => void;
    sessionId = "upstream-session";
    async start() {}
    async close() {
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

// The destination guard has its own suites (url-guard.test.ts,
// server.remote-url.test.ts); here it only has to let the stand-in through.
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

const { MCP_REQUEST_BODY_LIMIT_BYTES } = await import(
  "../../lib/metamcp/mcp-request-body-limit"
);
const { default: serverRouter } = await import("./server");

const PROTOCOL_VERSION = "2025-06-18";
const UPSTREAM = "https://upstream.example.test/mcp";
const LIMIT = MCP_REQUEST_BODY_LIMIT_BYTES;
const TOO_LARGE = {
  jsonrpc: "2.0",
  error: {
    code: -32000,
    message: `Payload Too Large: Request body must not exceed ${LIMIT} bytes`,
  },
  id: null,
};

let httpServer: HttpServer;
let baseUrl = "";
let rpcId = 0;

/** A JSON-RPC request serialized to exactly `bytes` bytes (padding in `_meta`). */
function paddedRequest(
  method: string,
  params: Record<string, unknown>,
  bytes: number,
): string {
  const message = {
    jsonrpc: "2.0",
    id: (rpcId += 1),
    method,
    params: { ...params, _meta: { pad: "" } },
  };
  const padding = bytes - Buffer.byteLength(JSON.stringify(message));
  if (padding < 0) throw new Error(`cannot pad ${method} down to ${bytes}`);
  message.params._meta.pad = "x".repeat(padding);
  const body = JSON.stringify(message);
  expect(Buffer.byteLength(body)).toBe(bytes);
  return body;
}

const initializeBody = (bytes: number) =>
  paddedRequest(
    "initialize",
    {
      protocolVersion: PROTOCOL_VERSION,
      capabilities: {},
      clientInfo: { name: "inspector", version: "0.0.0" },
    },
    bytes,
  );

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

async function resultOf(response: Response): Promise<unknown> {
  const text = await response.text();
  const data = text.startsWith("{")
    ? text
    : text
        .split("\n")
        .find((line) => line.startsWith("data: "))
        ?.slice("data: ".length);
  return data ? (JSON.parse(data) as { result?: unknown }).result : undefined;
}

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

describe("POST /mcp-proxy/server/mcp body ceiling", () => {
  it("serves an initialize of exactly the limit", async () => {
    const response = await post(initializeBody(LIMIT));

    expect(response.status).toBe(200);
    expect(await resultOf(response)).toMatchObject({
      serverInfo: { name: "upstream-echo" },
    });
  });

  it("refuses an initialize one byte over the limit with 413 and a JSON-RPC error", async () => {
    const response = await post(initializeBody(LIMIT + 1));

    expect(response.status).toBe(413);
    expect(await response.json()).toEqual(TOO_LARGE);
  });

  it("holds the same limit for later requests on the session", async () => {
    const opened = await post(initializeBody(1024));
    expect(opened.status).toBe(200);
    await opened.text();
    const sessionId = opened.headers.get("mcp-session-id") ?? "";
    expect(sessionId).not.toBe("");

    const atLimit = await post(paddedRequest("ping", {}, LIMIT), sessionId);
    expect(atLimit.status).toBe(200);
    expect(await resultOf(atLimit)).toEqual({});

    const over = await post(paddedRequest("ping", {}, LIMIT + 1), sessionId);
    expect(over.status).toBe(413);
    expect(await over.json()).toEqual(TOO_LARGE);
  });
});
