/**
 * The request-body ceiling on the Inspector's namespace route,
 * `POST /mcp-proxy/metamcp/:uuid/mcp`, at the byte.
 *
 * Same contract as the public route (see
 * routers/public-metamcp/streamable-http.body-limit.test.ts and
 * lib/metamcp/mcp-request-body-limit): exactly the limit is served, one byte
 * more is refused with 413 and a JSON-RPC error, for the initialize that
 * creates the transport and for later requests on its session. Driven over a
 * real socket through the real router and a real SDK transport and `Server`;
 * only the namespace server factory, the connection pool and the database are
 * faked. Dropping `maxRequestBodySize` from the route fails these tests.
 *
 * Only the initialize leg is driven. This route registers its session cleanup
 * on the initialize response's `close` event, so the session is gone once
 * that response ends and a follow-up request on it gets 404 "Transport not
 * found". That is the route's existing behaviour, not something this ceiling
 * changes; it is the same transport object either way.
 *
 * Unlike the other two routes, this one allocates nothing for a session until
 * the transport accepts its initialize (`createServer` runs in
 * `onsessioninitialized`), so a refused initialize has nothing to tear down.
 * The tests below pin that, and that a declared oversize is refused before a
 * transport is even handed the request.
 */
import type { Server as HttpServer } from "node:http";

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
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
vi.mock("@/db", () => ({ db: {}, pool: { on: vi.fn() } }));
vi.mock("@/db/audit-db", () => ({ auditDb: {}, auditPool: { on: vi.fn() } }));

// The namespace's MetaMCP server, as `createServer` would build it, minus the
// backend connections: a real SDK server so `initialize` and `ping` are
// answered by the SDK.
vi.mock("../../lib/metamcp/index", () => ({
  createServer: vi.fn(async () => ({
    server: new Server(
      { name: "body-limit-namespace", version: "0.0.0" },
      { capabilities: {} },
    ),
    cleanup: vi.fn().mockResolvedValue(undefined),
  })),
}));
vi.mock("../../lib/metamcp/mcp-server-pool", () => ({
  mcpServerPool: { cleanupSession: vi.fn().mockResolvedValue(undefined) },
}));

import { createServer } from "../../lib/metamcp/index";
import { MCP_REQUEST_BODY_LIMIT_BYTES } from "../../lib/metamcp/mcp-request-body-limit";
import { mcpServerPool } from "../../lib/metamcp/mcp-server-pool";
import metamcpRouter from "./metamcp";

const PROTOCOL_VERSION = "2025-06-18";
const NAMESPACE_UUID = "bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb";
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

function post(body: string | ReadableStream<Uint8Array>): Promise<Response> {
  return fetch(`${baseUrl}/mcp-proxy/metamcp/${NAMESPACE_UUID}/mcp`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
    },
    body,
    // Required by undici for a streamed body; ignored for a string.
    duplex: "half",
  } as RequestInit);
}

/**
 * The same bytes sent without a Content-Length (chunked), so the declared-length
 * check cannot fire and the transport has to count bytes as they arrive.
 */
function chunked(body: string): ReadableStream<Uint8Array> {
  const bytes = new TextEncoder().encode(body);
  return new ReadableStream<Uint8Array>({
    start(controller) {
      for (let at = 0; at < bytes.length; at += 1024 * 1024) {
        controller.enqueue(bytes.subarray(at, at + 1024 * 1024));
      }
      controller.close();
    },
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

describe("POST /mcp-proxy/metamcp/:uuid/mcp body ceiling", () => {
  it("serves an initialize of exactly the limit", async () => {
    const response = await post(initializeBody(LIMIT));

    expect(response.status).toBe(200);
    expect(await resultOf(response)).toMatchObject({
      serverInfo: { name: "body-limit-namespace" },
    });
  });

  it("refuses an initialize one byte over the limit with 413 and a JSON-RPC error", async () => {
    const response = await post(initializeBody(LIMIT + 1));

    expect(response.status).toBe(413);
    expect(await response.json()).toEqual(TOO_LARGE);
  });
});

describe("POST /mcp-proxy/metamcp/:uuid/mcp resources on a refused request", () => {
  const handleRequest = vi.spyOn(
    StreamableHTTPServerTransport.prototype,
    "handleRequest",
  );

  beforeEach(() => {
    vi.mocked(createServer).mockClear();
    vi.mocked(mcpServerPool.cleanupSession).mockClear();
    handleRequest.mockClear();
  });

  it("refuses a declared oversize initialize before a transport is handed it", async () => {
    const response = await post(initializeBody(LIMIT + 1));

    expect(response.status).toBe(413);
    expect(await response.json()).toEqual(TOO_LARGE);
    expect(handleRequest).not.toHaveBeenCalled();
    expect(createServer).not.toHaveBeenCalled();
  });

  it("allocates nothing for an initialize refused while its body was read", async () => {
    const response = await post(chunked(initializeBody(LIMIT + 1)));

    expect(response.status).toBe(413);
    expect(await response.json()).toEqual(TOO_LARGE);
    expect(handleRequest).toHaveBeenCalledTimes(1);
    expect(createServer).not.toHaveBeenCalled();
    expect(mcpServerPool.cleanupSession).not.toHaveBeenCalled();
  });
});
