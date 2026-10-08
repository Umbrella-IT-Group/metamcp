/**
 * The request-body ceiling on the public Streamable HTTP route, at the byte,
 * on every transport the route builds: a fresh session's and a lazily
 * recovered one's.
 *
 * SDK 1.30.1 started capping the body the transport reads at 4 MiB unless the
 * caller sets `maxRequestBodySize`, which refused tool calls production was
 * carrying (a base64 upload of about 3 MiB). The gateway sets the ceiling
 * explicitly (lib/metamcp/mcp-request-body-limit explains the value); these
 * tests pin that it holds exactly: a body of exactly the limit is served, one
 * byte more is refused with 413 and a JSON-RPC error, on each construction
 * site. Dropping the option from either site fails the tests for that site.
 *
 * A refused initialize must not leave its session behind. The route admits a
 * fresh session (a per-credential slot, a pooled server instance, a resident
 * transport, an `mcp_sessions` row) before the transport reads the body, and
 * the 413 carries no session id, so nothing could ever use or close it. So a
 * declared oversize is refused before any of that, and a body refused only
 * while it is read is torn down after the transport answers. An oversized
 * request on a live session, by contrast, is answered 413 and the session
 * keeps serving.
 *
 * What is real: the router, the session manager, the SDK transports, a real
 * SDK `Server` per pooled instance (so `initialize` and `ping` are answered by
 * the SDK) and transport-recovery hydration. What is faked: the DB-touching
 * boundaries (`mcp_sessions` as an in-memory table), the express auth
 * middlewares and the durable event sink. Same harness shape as
 * streamable-http.ceiling-evict.test.ts.
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

const h = vi.hoisted(() => {
  const rows = new Map<string, unknown>();
  const state = {
    rows,
    /** Session ids whose pooled server saw its transport close, in order. */
    closedSessions: [] as string[],
    /** When set, every `persist` waits for it before writing its row. */
    persistGate: undefined as Promise<void> | undefined,
    logger: { error: vi.fn(), warn: vi.fn(), info: vi.fn(), debug: vi.fn() },
    getServer: vi.fn(),
    poolCleanup: vi.fn(async (_sessionId: string) => undefined),
    persist: vi.fn(async (row: { session_id: string }) => {
      await state.persistGate;
      rows.set(row.session_id, {
        ...row,
        created_at: new Date(),
        last_seen_at: new Date(),
      });
    }),
    findById: vi.fn(async (sessionId: string) => rows.get(sessionId) ?? null),
    delete: vi.fn(async (sessionId: string) => {
      rows.delete(sessionId);
    }),
  };
  return state;
});

vi.mock("@/utils/logger", () => ({ default: h.logger }));
vi.mock("../../lib/health-upstream", () => ({
  isAdminHealthRequest: vi.fn().mockResolvedValue(false),
}));
vi.mock("@/db", () => ({ db: {}, pool: { on: vi.fn() } }));
vi.mock("@/middleware/api-key-oauth.middleware", () => ({
  authenticateApiKey: vi.fn(),
}));
vi.mock("@/middleware/lookup-endpoint-middleware", () => ({
  lookupEndpoint: vi.fn(),
}));
vi.mock("@/middleware/rate-limit.middleware", () => ({
  rateLimitMiddleware: vi.fn(),
}));
vi.mock("@/db/repositories/mcp-sessions.repo", () => ({
  mcpSessionsRepository: {
    persist: h.persist,
    findById: h.findById,
    touch: vi.fn().mockResolvedValue(undefined),
    delete: h.delete,
    pruneOlderThan: vi.fn().mockResolvedValue(0),
  },
}));
vi.mock("../../lib/metamcp/consumer-identity-resolver", () => ({
  resolveClientIdentity: vi.fn().mockResolvedValue({ name: "test-consumer" }),
}));
vi.mock("../../lib/metamcp/metamcp-server-pool", () => ({
  metaMcpServerPool: {
    getServer: h.getServer,
    getServerInstance: vi.fn(),
    cleanupSession: h.poolCleanup,
    getMcpServerPoolStatus: vi.fn().mockReturnValue({ idle: 0, active: 0 }),
    getPoolStatus: vi.fn().mockReturnValue({ idle: 0, active: 0 }),
  },
}));
vi.mock("../../lib/metamcp/log-store", () => ({
  metamcpLogStore: { record: vi.fn() },
}));
// The real ceiling, observed: a refused request must never reach admission.
vi.mock(
  "../../lib/metamcp/credential-session-quota",
  async (importOriginal) => {
    const actual =
      await importOriginal<
        typeof import("../../lib/metamcp/credential-session-quota")
      >();
    return {
      ...actual,
      checkConcurrentSessionCeiling: vi.fn(
        actual.checkConcurrentSessionCeiling,
      ),
      checkConcurrentSessionCeilingForRecovery: vi.fn(
        actual.checkConcurrentSessionCeilingForRecovery,
      ),
    };
  },
);

import { authenticateApiKey } from "@/middleware/api-key-oauth.middleware";
import { lookupEndpoint } from "@/middleware/lookup-endpoint-middleware";
import { rateLimitMiddleware } from "@/middleware/rate-limit.middleware";

import {
  checkConcurrentSessionCeiling,
  checkConcurrentSessionCeilingForRecovery,
  countLiveSessionsForIdentity,
} from "../../lib/metamcp/credential-session-quota";
import { MCP_REQUEST_BODY_LIMIT_BYTES } from "../../lib/metamcp/mcp-request-body-limit";
import streamableHttpRouter, {
  buildSessionsHealthPayload,
  publicSessionSweeper,
  reapIdleSession,
} from "./streamable-http";

const PROTOCOL_VERSION = "2025-06-18";
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
let keyCounter = 0;
let rawKey = "";
let keyUuid = "";
let rpcId = 0;

/**
 * A JSON-RPC request serialized to exactly `bytes` bytes, the excess carried
 * in `params._meta`, which every MCP request accepts and the SDK ignores.
 */
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
      clientInfo: { name: "body-limit-client", version: "0.0.0" },
    },
    bytes,
  );

const pingBody = (bytes: number) => paddedRequest("ping", {}, bytes);

function post(
  body: string | ReadableStream<Uint8Array>,
  sessionId?: string,
): Promise<Response> {
  return fetch(`${baseUrl}/metamcp/ep-1/mcp`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      "x-api-key": rawKey,
      ...(sessionId
        ? {
            "mcp-session-id": sessionId,
            "mcp-protocol-version": PROTOCOL_VERSION,
          }
        : {}),
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

/** Sessions resident in the route's session manager. */
function residentSessions(): number {
  const { streamableHttpSessions } = buildSessionsHealthPayload(true) as {
    streamableHttpSessions: { count: number };
  };
  return streamableHttpSessions.count;
}

/** This test's credential, as the per-credential ceiling counts it. */
const liveSessionsForKey = () =>
  countLiveSessionsForIdentity({ method: "api_key", credentialId: keyUuid });

/** Times a session id's pooled server saw its transport close. */
const closesOf = (sessionId: string) =>
  h.closedSessions.filter((closed) => closed === sessionId).length;

/** Let any teardown still queued behind a response run before counting. */
const settle = () => new Promise((resolve) => setTimeout(resolve, 50));

const handleRequest = vi.spyOn(
  StreamableHTTPServerTransport.prototype,
  "handleRequest",
);

async function openSession(): Promise<string> {
  const response = await post(initializeBody(1024));
  expect(response.status).toBe(200);
  await response.text();
  const sessionId = response.headers.get("mcp-session-id");
  if (!sessionId) throw new Error("initialize returned no Mcp-Session-Id");
  return sessionId;
}

/** The JSON-RPC result the SDK answers on an SSE stream or as JSON. */
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
  vi.mocked(lookupEndpoint).mockImplementation(((
    req: express.Request,
    _res: express.Response,
    next: () => void,
  ) => {
    const endpoint = String(req.params.endpoint_name);
    Object.assign(req, {
      namespaceUuid: `ns-${endpoint}`,
      endpointName: endpoint,
      endpoint: { uuid: `uuid-${endpoint}`, name: endpoint },
      authMethod: "api_key",
      apiKeyUuid: keyUuid,
      auditRequestId: "req-body-limit",
      auditClientIp: "203.0.113.30",
    });
    next();
  }) as never);
  vi.mocked(authenticateApiKey).mockImplementation(((
    _req: express.Request,
    _res: express.Response,
    next: () => void,
  ) => next()) as never);
  vi.mocked(rateLimitMiddleware).mockImplementation(((
    _req: express.Request,
    _res: express.Response,
    next: () => void,
  ) => next()) as never);

  const app = express();
  app.use("/metamcp", streamableHttpRouter);
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
  vi.clearAllMocks();
  // A fresh credential per test keeps each one clear of the per-credential
  // session ceiling, which is module state shared by the whole file.
  keyCounter += 1;
  keyUuid = `3f7f8a1e-0000-4000-8000-${String(keyCounter).padStart(12, "0")}`;
  rawKey = `body-limit-key-${keyCounter}`;
  h.persistGate = undefined;
  h.getServer.mockImplementation(async (sessionId: string) => {
    const server = new Server(
      { name: "body-limit-gateway", version: "0.0.0" },
      { capabilities: {} },
    );
    // Fires when the transport the route connected this server to closes.
    server.onclose = () => h.closedSessions.push(sessionId);
    return {
      server,
      cleanup: vi.fn().mockResolvedValue(undefined),
      handlerContext: {} as Record<string, unknown>,
    };
  });
});

describe("a fresh session's transport", () => {
  it("serves an initialize of exactly the limit", async () => {
    const response = await post(initializeBody(LIMIT));

    expect(response.status).toBe(200);
    expect(await resultOf(response)).toMatchObject({
      serverInfo: { name: "body-limit-gateway" },
    });
  });

  it("refuses an initialize one byte over the limit with 413 and a JSON-RPC error", async () => {
    const response = await post(initializeBody(LIMIT + 1));

    expect(response.status).toBe(413);
    expect(await response.json()).toEqual(TOO_LARGE);
  });

  it("refuses an over-limit body sent without a Content-Length", async () => {
    // Chunked: the declared-length check cannot fire, so the transport has to
    // stop counting bytes as they arrive.
    const bytes = new TextEncoder().encode(initializeBody(LIMIT + 1));
    const chunked = new ReadableStream<Uint8Array>({
      start(controller) {
        for (let at = 0; at < bytes.length; at += 1024 * 1024) {
          controller.enqueue(bytes.subarray(at, at + 1024 * 1024));
        }
        controller.close();
      },
    });

    const response = await post(chunked);

    expect(response.status).toBe(413);
    expect(await response.json()).toEqual(TOO_LARGE);
  });

  it("holds the same limit for later requests on the session", async () => {
    const sessionId = await openSession();

    const atLimit = await post(pingBody(LIMIT), sessionId);
    expect(atLimit.status).toBe(200);
    expect(await resultOf(atLimit)).toEqual({});

    const over = await post(pingBody(LIMIT + 1), sessionId);
    expect(over.status).toBe(413);
    expect(await over.json()).toEqual(TOO_LARGE);
  });
});

describe("a lazily recovered session's transport", () => {
  /** A session whose transport is gone but whose row survives, as after an idle reap or a restart. */
  async function reapedSession(): Promise<string> {
    const sessionId = await openSession();
    await reapIdleSession(sessionId);
    h.findById.mockClear();
    return sessionId;
  }

  it("serves a request of exactly the limit", async () => {
    const sessionId = await reapedSession();

    const response = await post(pingBody(LIMIT), sessionId);

    // Recovered from the row, not served by a resident transport.
    expect(h.findById).toHaveBeenCalledWith(sessionId);
    expect(response.status).toBe(200);
    expect(await resultOf(response)).toEqual({});
  });

  it("refuses a declared oversize request with 413 before recovering anything", async () => {
    const sessionId = await reapedSession();
    h.getServer.mockClear();
    handleRequest.mockClear();

    const response = await post(pingBody(LIMIT + 1), sessionId);

    expect(response.status).toBe(413);
    expect(await response.json()).toEqual(TOO_LARGE);
    expect(h.findById).not.toHaveBeenCalled();
    expect(checkConcurrentSessionCeilingForRecovery).not.toHaveBeenCalled();
    expect(h.getServer).not.toHaveBeenCalled();
    expect(handleRequest).not.toHaveBeenCalled();
  });

  it("refuses a body over the limit read in chunks, and the recovered session keeps serving", async () => {
    const sessionId = await reapedSession();

    const response = await post(chunked(pingBody(LIMIT + 1)), sessionId);

    expect(h.findById).toHaveBeenCalledWith(sessionId);
    expect(response.status).toBe(413);
    expect(await response.json()).toEqual(TOO_LARGE);

    // Recovery hydrates the transport as initialized and the client holds its
    // id, so this is an oversized request on a live session: it stays.
    const ping = await post(pingBody(1024), sessionId);
    expect(ping.status).toBe(200);
    expect(await resultOf(ping)).toEqual({});
    expect(h.findById).toHaveBeenCalledTimes(1);
  });
});

describe("a refused initialize's session", () => {
  it("is never admitted or allocated when the declared length is over the limit", async () => {
    const residentBefore = residentSessions();

    const response = await post(initializeBody(LIMIT + 1));

    expect(response.status).toBe(413);
    expect(await response.json()).toEqual(TOO_LARGE);
    await settle();
    expect(checkConcurrentSessionCeiling).not.toHaveBeenCalled();
    expect(h.getServer).not.toHaveBeenCalled();
    expect(handleRequest).not.toHaveBeenCalled();
    expect(h.persist).not.toHaveBeenCalled();
    expect(residentSessions()).toBe(residentBefore);
    expect(liveSessionsForKey()).toBe(0);
  });

  it("is torn down when the body is refused while it is read", async () => {
    // Hold the row write until the 413 is back, so the teardown meets a
    // slow insert: the order in which a delete issued at once would land
    // first and leave the row behind.
    let releasePersist = () => {};
    h.persistGate = new Promise<void>((resolve) => {
      releasePersist = resolve;
    });
    const residentBefore = residentSessions();

    const response = await post(chunked(initializeBody(LIMIT + 1)));

    expect(response.status).toBe(413);
    expect(await response.json()).toEqual(TOO_LARGE);
    expect(checkConcurrentSessionCeiling).toHaveBeenCalledTimes(1);
    expect(h.getServer).toHaveBeenCalledTimes(1);
    const sessionId = String(h.getServer.mock.calls[0]?.[0]);
    expect(h.persist).toHaveBeenCalledWith(
      expect.objectContaining({ session_id: sessionId }),
    );

    // Transport, pool, registration, idle tracking and the credential's slot
    // are released without waiting for the database.
    await vi.waitFor(() => {
      expect(closesOf(sessionId)).toBe(1);
      expect(h.poolCleanup).toHaveBeenCalledWith(sessionId);
    });
    expect(residentSessions()).toBe(residentBefore);
    expect(publicSessionSweeper.getActivity(sessionId)).toBeUndefined();
    expect(liveSessionsForKey()).toBe(0);
    // The row delete waits for the insert instead of overtaking it.
    expect(h.delete).not.toHaveBeenCalled();

    releasePersist();
    await vi.waitFor(() => expect(h.delete).toHaveBeenCalledWith(sessionId));
    await vi.waitFor(() => expect(h.rows.has(sessionId)).toBe(false));
    await settle();
    expect(closesOf(sessionId)).toBe(1);
    expect(h.poolCleanup).toHaveBeenCalledTimes(1);
  });

  it("is torn down when the first request is not an initialize", async () => {
    // Within the limit, refused by the transport for another reason: the
    // client gets no session id either, so the same teardown applies.
    const residentBefore = residentSessions();

    const response = await post(pingBody(1024));

    expect(response.status).toBe(400);
    const sessionId = String(h.getServer.mock.calls[0]?.[0]);
    await vi.waitFor(() => {
      expect(closesOf(sessionId)).toBe(1);
      expect(h.poolCleanup).toHaveBeenCalledWith(sessionId);
      expect(h.rows.has(sessionId)).toBe(false);
    });
    expect(residentSessions()).toBe(residentBefore);
    expect(liveSessionsForKey()).toBe(0);
  });
});

describe("an oversized request on a live session", () => {
  it("is answered 413 and the session keeps serving", async () => {
    const sessionId = await openSession();
    const residentBefore = residentSessions();

    const declared = await post(pingBody(LIMIT + 1), sessionId);
    expect(declared.status).toBe(413);
    expect(await declared.json()).toEqual(TOO_LARGE);

    const read = await post(chunked(pingBody(LIMIT + 1)), sessionId);
    expect(read.status).toBe(413);
    expect(await read.json()).toEqual(TOO_LARGE);

    const ping = await post(pingBody(1024), sessionId);
    expect(ping.status).toBe(200);
    expect(await resultOf(ping)).toEqual({});
    await settle();
    expect(closesOf(sessionId)).toBe(0);
    expect(h.poolCleanup).not.toHaveBeenCalled();
    expect(h.delete).not.toHaveBeenCalled();
    expect(h.findById).not.toHaveBeenCalled();
    expect(h.getServer).toHaveBeenCalledTimes(1);
    expect(residentSessions()).toBe(residentBefore);
    expect(liveSessionsForKey()).toBe(1);
  });
});
