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
 * A first request that cannot open a session (anything but an `initialize`)
 * is answered before admission, so it allocates none of that either. The
 * route reads the body itself to decide, so the last block pins, case by
 * case, that every answer a session-less POST gets (status, headers, JSON-RPC
 * error) is the one the SDK transport alone gives for the same request, and
 * that an `initialize` still opens its session from the body read for that
 * decision.
 *
 * What is real: the router, the session manager, the SDK transports, a real
 * SDK `Server` per pooled instance (so `initialize` and `ping` are answered by
 * the SDK) and transport-recovery hydration. What is faked: the DB-touching
 * boundaries (`mcp_sessions` as an in-memory table), the express auth
 * middlewares and the durable event sink. Same harness shape as
 * streamable-http.ceiling-evict.test.ts.
 */
import { randomUUID } from "node:crypto";
import http, { type Server as HttpServer } from "node:http";

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { MAX_BATCH_SIZE } from "@modelcontextprotocol/sdk/server/requestBody.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import {
  InitializeRequestSchema,
  JSONRPCMessageSchema,
} from "@modelcontextprotocol/sdk/types.js";
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
import { metamcpLogStore } from "../../lib/metamcp/log-store";
import { MCP_REQUEST_BODY_LIMIT_BYTES } from "../../lib/metamcp/mcp-request-body-limit";
import streamableHttpRouter, {
  buildSessionsHealthPayload,
  cleanupSession,
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
const NOT_INITIALIZED = {
  jsonrpc: "2.0",
  error: { code: -32000, message: "Bad Request: Server not initialized" },
  id: null,
};
const INVALID_JSON = {
  jsonrpc: "2.0",
  error: { code: -32700, message: "Parse error: Invalid JSON" },
  id: null,
};
const ONLY_ONE_INITIALIZE = {
  jsonrpc: "2.0",
  error: {
    code: -32600,
    message: "Invalid Request: Only one initialization request is allowed",
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
 * A POST with no Mcp-Session-Id, this test's credential and any header
 * overridden, to the route or (`url`) to another server.
 */
function postWithout(
  body: string | ReadableStream<Uint8Array>,
  headers: Record<string, string> = {},
  url = `${baseUrl}/metamcp/ep-1/mcp`,
): Promise<Response> {
  return fetch(url, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      "x-api-key": rawKey,
      ...headers,
    },
    body,
    duplex: "half",
  } as RequestInit);
}

/** A JSON-RPC request with a fresh id. */
const rpc = (method: string, extra: Record<string, unknown> = {}) => ({
  jsonrpc: "2.0",
  id: (rpcId += 1),
  method,
  ...extra,
});

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

  it("is torn down when the transport refuses an initialize batched with another message", async () => {
    // Within the limit and holding an `initialize`, so it is admitted, but the
    // transport takes an initialize only on its own and refuses the batch:
    // the client gets no session id either, so the same teardown applies.
    // (A first request with no initialize at all is never admitted; see
    // "a session-less request that cannot open a session" below.)
    const residentBefore = residentSessions();

    const response = await post(
      JSON.stringify([
        JSON.parse(initializeBody(1024)),
        JSON.parse(pingBody(1024)),
      ]),
    );

    expect(response.status).toBe(400);
    expect(await response.json()).toEqual(ONLY_ONE_INITIALIZE);
    expect(checkConcurrentSessionCeiling).toHaveBeenCalledTimes(1);
    expect(h.getServer).toHaveBeenCalledTimes(1);
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

/**
 * Only an `initialize` can open a session, so the route answers any other
 * session-less POST before admission: no ceiling slot, pooled instance,
 * connect, registration, idle tracking, row or "client connected" event.
 */
describe("a session-less request that cannot open a session", () => {
  /** Lines the route logs for a request it answered without a session. */
  const answeredLines = () =>
    h.logger.info.mock.calls
      .map((call) => String(call[0]))
      .filter((line) => line.includes("without opening a session"));

  function expectNothingAllocated(residentBefore: number): void {
    expect(checkConcurrentSessionCeiling).not.toHaveBeenCalled();
    expect(h.getServer).not.toHaveBeenCalled();
    expect(h.persist).not.toHaveBeenCalled();
    expect(h.delete).not.toHaveBeenCalled();
    expect(h.poolCleanup).not.toHaveBeenCalled();
    expect(metamcpLogStore.record).not.toHaveBeenCalled();
    expect(residentSessions()).toBe(residentBefore);
    expect(liveSessionsForKey()).toBe(0);
  }

  it.each([
    ["tools/list", () => rpc("tools/list"), "tools/list"],
    [
      "notifications/initialized",
      () => ({ jsonrpc: "2.0", method: "notifications/initialized" }),
      "notifications/initialized",
    ],
    [
      "a batch without an initialize",
      () => [
        rpc("tools/list"),
        { jsonrpc: "2.0", method: "notifications/initialized" },
      ],
      "batch of 2: tools/list, notifications/initialized",
    ],
  ])(
    "answers %s with the transport's 400 and allocates nothing",
    async (_label, message, logged) => {
      const residentBefore = residentSessions();
      const beginTracking = vi.spyOn(publicSessionSweeper, "beginTracking");
      const body = message();

      try {
        const response = await postWithout(JSON.stringify(body));

        expect(response.status).toBe(400);
        expect(response.headers.get("mcp-session-id")).toBeNull();
        expect(await response.json()).toEqual(NOT_INITIALIZED);
        await settle();
        expectNothingAllocated(residentBefore);
        expect(beginTracking).not.toHaveBeenCalled();
        // The SDK answered, on one transport handed the body the route read.
        expect(handleRequest).toHaveBeenCalledTimes(1);
        expect(handleRequest.mock.calls[0]?.[2]).toEqual(body);
        expect(answeredLines()).toEqual([
          `Public endpoint ep-1: answered a POST without an Mcp-Session-Id (HTTP 400) without opening a session; methods: ${logged}; Mcp-Protocol-Version: absent.`,
        ]);
      } finally {
        beginTracking.mockRestore();
      }
    },
  );

  it("refuses an oversized batch before validating any of its messages", async () => {
    // The SDK caps batches before schema validation. Walking an arbitrary
    // array here defeats that CPU bound, even for a small byte-sized body.
    // An initialize at the end cannot make an oversized batch admissible.
    const residentBefore = residentSessions();
    const initializeValidation = vi.spyOn(InitializeRequestSchema, "safeParse");
    const messageValidation = vi.spyOn(JSONRPCMessageSchema, "safeParse");
    try {
      const response = await postWithout(
        JSON.stringify([
          ...Array.from({ length: MAX_BATCH_SIZE }, () => null),
          JSON.parse(initializeBody(1024)),
        ]),
      );

      expect(response.status).toBe(400);
      expect(await response.json()).toEqual({
        jsonrpc: "2.0",
        error: {
          code: -32600,
          message: `Invalid Request: Batch must not exceed ${MAX_BATCH_SIZE} messages`,
        },
        id: null,
      });
      expect(initializeValidation).not.toHaveBeenCalled();
      expect(messageValidation).not.toHaveBeenCalled();
      expectNothingAllocated(residentBefore);
      expect(answeredLines()).toEqual([
        `Public endpoint ep-1: answered a POST without an Mcp-Session-Id (HTTP 400) without opening a session; methods: batch of ${MAX_BATCH_SIZE + 1}: (over SDK batch limit); Mcp-Protocol-Version: absent.`,
      ]);
    } finally {
      initializeValidation.mockRestore();
      messageValidation.mockRestore();
    }
  });

  it("answers a body that is not JSON with the transport's 400 -32700 and allocates nothing", async () => {
    const residentBefore = residentSessions();

    const response = await postWithout("{not json");

    expect(response.status).toBe(400);
    expect(response.headers.get("content-type")).toBe("application/json");
    expect(await response.json()).toEqual(INVALID_JSON);
    await settle();
    expectNothingAllocated(residentBefore);
    // The adapter still runs first. The transport sees a spent stream and
    // emits its own parse error without opening a session.
    expect(handleRequest).toHaveBeenCalledTimes(1);
    expect(handleRequest.mock.calls[0]?.[2]).toBeUndefined();
    expect(answeredLines()).toEqual([
      "Public endpoint ep-1: answered a POST without an Mcp-Session-Id (HTTP 400) without opening a session; body is not JSON; Mcp-Protocol-Version: absent.",
    ]);
  });

  it("keeps its 413 when the body is over the limit without a Content-Length", async () => {
    // Pushed back onto the stream and left to the transport, as before.
    const response = await postWithout(chunked(pingBody(LIMIT + 1)));

    expect(response.status).toBe(413);
    expect(await response.json()).toEqual(TOO_LARGE);
  });

  it("keeps its 406 when the Accept header lacks text/event-stream", async () => {
    const response = await postWithout(JSON.stringify(rpc("tools/list")), {
      accept: "application/json",
    });

    expect(response.status).toBe(406);
    expect(await response.json()).toEqual({
      jsonrpc: "2.0",
      error: {
        code: -32000,
        message:
          "Not Acceptable: Client must accept both application/json and text/event-stream",
      },
      id: null,
    });
  });

  it("logs method names only: no params, no ids, no forged lines", async () => {
    const response = await postWithout(
      JSON.stringify([
        {
          jsonrpc: "2.0",
          id: 987654321,
          method: "tools/call",
          params: {
            name: "lookup",
            arguments: { note: "do-not-log-this-value" },
          },
        },
        { jsonrpc: "2.0", id: 2, method: "tools/call\nforged log line" },
        { jsonrpc: "2.0", id: 3, result: {} },
        rpc("tools/call"),
      ]),
      { "mcp-protocol-version": "2025-06-18" },
    );
    expect(response.status).toBe(400);
    await response.text();

    const lines = answeredLines();
    expect(lines).toEqual([
      "Public endpoint ep-1: answered a POST without an Mcp-Session-Id (HTTP 400) without opening a session; methods: batch of 4: tools/call x2, (unloggable method name), (response); Mcp-Protocol-Version: 2025-06-18.",
    ]);
    expect(lines[0]).not.toContain("987654321");
    expect(lines[0]).not.toContain("do-not-log-this-value");
    expect(lines[0]).not.toContain("forged");
    expect(lines[0]).not.toContain(rawKey);
  });

  it("still opens a session for an initialize, from the body read to decide", async () => {
    const body = initializeBody(1024);

    const response = await postWithout(body);

    expect(response.status).toBe(200);
    expect(await resultOf(response)).toMatchObject({
      serverInfo: { name: "body-limit-gateway" },
    });
    const sessionId = response.headers.get("mcp-session-id") ?? "";
    expect(sessionId).not.toBe("");
    expect(checkConcurrentSessionCeiling).toHaveBeenCalledTimes(1);
    expect(h.getServer).toHaveBeenCalledTimes(1);
    expect(h.persist).toHaveBeenCalledWith(
      expect.objectContaining({ session_id: sessionId }),
    );
    // Read once: the transport was handed the parsed body.
    expect(handleRequest).toHaveBeenCalledTimes(1);
    expect(handleRequest.mock.calls[0]?.[2]).toEqual(JSON.parse(body));
    expect(answeredLines()).toEqual([]);

    const ping = await post(pingBody(1024), sessionId);
    expect(ping.status).toBe(200);
    expect(await resultOf(ping)).toEqual({});
  });

  it("waits for a chunked initialize, preserving split UTF-8 and BOM bytes", async () => {
    const message = JSON.parse(initializeBody(1024));
    message.params.clientInfo.name = "utf8-☃";
    const body = `\uFEFF${JSON.stringify(message)}`;
    const bytes = new TextEncoder().encode(body);
    const snowman = bytes.indexOf(0xe2);
    let upload!: ReadableStreamDefaultController<Uint8Array>;
    let uploadClosed = false;
    const pending = postWithout(
      new ReadableStream<Uint8Array>({
        start(controller) {
          upload = controller;
          // Break the BOM across chunks; the remainder arrives after routing.
          controller.enqueue(bytes.subarray(0, 1));
        },
      }),
    );
    try {
      await vi.waitFor(() => {
        expect(h.logger.info).toHaveBeenCalledWith(
          "POST /mcp request for endpoint: ep-1",
        );
      });
      expect(h.getServer).not.toHaveBeenCalled();
      const incoming = vi.mocked(authenticateApiKey).mock.calls[0]?.[0];
      if (!incoming) throw new Error("upload never reached authentication");
      const partialReceived = new Promise<void>((resolve) => {
        incoming.once("data", () => resolve());
      });
      upload.enqueue(bytes.subarray(1, snowman + 1));
      // Wait for this partial UTF-8 sequence to reach Node, so the last
      // bytes cannot be coalesced into the same incoming data chunk.
      await partialReceived;
      expect(h.getServer).not.toHaveBeenCalled();
      upload.enqueue(bytes.subarray(snowman + 1));
      upload.close();
      uploadClosed = true;

      const response = await pending;
      expect(response.status).toBe(200);
      expect(await resultOf(response)).toMatchObject({
        serverInfo: { name: "body-limit-gateway" },
      });
      expect(handleRequest.mock.calls[0]?.[2]).toEqual(message);
      const sessionId = response.headers.get("mcp-session-id");
      expect(sessionId).toBeTruthy();
      await cleanupSession(sessionId as string);
    } finally {
      // Also end the upload if an assertion fails before it was closed.
      if (!uploadClosed) upload.close();
    }
  });

  it("releases an aborted partial upload without admitting a session", async () => {
    const residentBefore = residentSessions();
    const abort = new AbortController();
    const upload = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode('{"jsonrpc":"2.0",'));
      },
    });
    const pending = fetch(`${baseUrl}/metamcp/ep-1/mcp`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
        "x-api-key": rawKey,
      },
      body: upload,
      duplex: "half",
      signal: abort.signal,
    } as RequestInit).catch((error: unknown) => error);
    try {
      await vi.waitFor(() => {
        expect(h.logger.info).toHaveBeenCalledWith(
          "POST /mcp request for endpoint: ep-1",
        );
      });
      abort.abort();
      await pending;
      await vi.waitFor(() => {
        expect(answeredLines()).toHaveLength(1);
      });
      expect(answeredLines()[0]).toContain("body could not be read");
      expectNothingAllocated(residentBefore);
      const incoming = vi.mocked(authenticateApiKey).mock.calls[0]?.[0];
      expect(incoming?.listenerCount("data")).toBe(0);
      expect(incoming?.listenerCount("error")).toBe(0);
    } finally {
      abort.abort();
      await pending;
    }
  });

  it("still opens a session for a batch holding only an initialize", async () => {
    const response = await postWithout(
      JSON.stringify([JSON.parse(initializeBody(1024))]),
    );

    expect(response.status).toBe(200);
    await response.text();
    const sessionId = response.headers.get("mcp-session-id") ?? "";
    expect(sessionId).not.toBe("");
    expect(liveSessionsForKey()).toBe(1);

    const ping = await post(pingBody(1024), sessionId);
    expect(ping.status).toBe(200);
    expect(await resultOf(ping)).toEqual({});
  });

  it("leaves the connection reusable after answering without a session", async () => {
    // The route reads these bodies to the end itself, so the HTTP layer must
    // still see a finished request and keep the socket for the next one. The
    // pause outlasts the 500 ms after which the SDK's HTTP adapter closes a
    // socket whose request body it believes is still arriving.
    const agent = new http.Agent({ keepAlive: true, maxSockets: 1 });
    const pause = () => new Promise((resolve) => setTimeout(resolve, 700));
    try {
      const answered = await rawPost(agent, JSON.stringify(rpc("tools/list")));
      await pause();
      const notJson = await rawPost(agent, "{not json");
      await pause();
      const initialized = await rawPost(agent, initializeBody(1024));

      expect([answered.status, notJson.status, initialized.status]).toEqual([
        400, 400, 200,
      ]);
      expect([notJson.reused, initialized.reused]).toEqual([true, true]);
      expect(initialized.sessionId).toBeTruthy();
      await cleanupSession(initialized.sessionId as string);
    } finally {
      agent.destroy();
    }
  });
});

/** One POST over a node:http agent, reporting whether it reused a socket. */
function rawPost(
  agent: http.Agent,
  body: string,
  headers: Record<string, string | string[]> = {},
  targetUrl = `${baseUrl}/metamcp/ep-1/mcp`,
): Promise<{
  status: number;
  reused: boolean;
  sessionId?: string;
  headers: http.IncomingHttpHeaders;
  body: string;
}> {
  const url = new URL(targetUrl);
  return new Promise((resolve, reject) => {
    const request = http.request(
      {
        host: url.hostname,
        port: url.port,
        path: url.pathname,
        method: "POST",
        agent,
        headers: {
          "content-type": "application/json",
          accept: "application/json, text/event-stream",
          "x-api-key": rawKey,
          "content-length": Buffer.byteLength(body),
          ...headers,
        },
      },
      (response) => {
        let text = "";
        response.setEncoding("utf8");
        response.on("data", (chunk: string) => {
          text += chunk;
        });
        response.on("error", reject);
        response.on("end", () =>
          resolve({
            status: response.statusCode ?? 0,
            reused: request.reusedSocket,
            sessionId: response.headers["mcp-session-id"] as string | undefined,
            headers: response.headers,
            body: text,
          }),
        );
      },
    );
    request.on("error", reject);
    request.end(body);
  });
}

/**
 * Every answer a session-less POST gets, compared field by field with the
 * answer the SDK transport gives on its own: status, every header but the
 * connection-level ones, and the body. The reference is the route's answering
 * part as it was before the pre-read: a fresh transport, connected to a real
 * SDK server and never initialized, reading the body itself.
 */
describe("a session-less POST gets the SDK transport's own answer", () => {
  let referenceServer: HttpServer;
  let referenceUrl = "";

  beforeAll(async () => {
    const app = express();
    app.post("/metamcp/:endpoint_name/mcp", async (req, res) => {
      const server = new Server(
        { name: "reference", version: "0.0.0" },
        { capabilities: {} },
      );
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
        maxRequestBodySize: LIMIT,
      });
      await server.connect(transport);
      await transport.handleRequest(req, res);
      await transport.close();
    });
    await new Promise<void>((resolve) => {
      referenceServer = app.listen(0, "127.0.0.1", resolve);
    });
    const address = referenceServer.address();
    if (typeof address === "object" && address) {
      referenceUrl = `http://127.0.0.1:${address.port}/metamcp/ep-1/mcp`;
    }
  });

  afterAll(async () => {
    referenceServer.closeAllConnections();
    await new Promise<void>((resolve) =>
      referenceServer.close(() => resolve()),
    );
  });

  async function answerOf(response: Response) {
    const connectionHeaders = ["date", "connection", "keep-alive"];
    return {
      status: response.status,
      headers: [...response.headers].filter(
        ([name]) => !connectionHeaders.includes(name),
      ),
      body: await response.text(),
    };
  }

  it.each<{
    label: string;
    body: string;
    headers: Record<string, string | string[]>;
    status: number;
  }>([
    {
      label: "the adapter's invalid-Host refusal for a non-JSON body",
      body: "{not json",
      headers: { host: "invalid host" },
      status: 400,
    },
    {
      label: "Accept repeated across two header lines",
      body: '{"jsonrpc":"2.0","id":1,"method":"tools/list"}',
      headers: { accept: ["application/json", "text/event-stream"] },
      status: 400,
    },
    {
      label: "a repeated Content-Type with JSON first",
      body: '{"jsonrpc":"2.0","id":1,"method":"tools/list"}',
      headers: { "content-type": ["application/json", "text/plain"] },
      status: 415,
    },
    {
      label: "a repeated Content-Type with JSON second",
      body: '{"jsonrpc":"2.0","id":1,"method":"tools/list"}',
      headers: { "content-type": ["text/plain", "application/json"] },
      status: 415,
    },
  ])("keeps $label", async ({ body, headers, status }) => {
    const agent = new http.Agent({ keepAlive: true });
    const answer = (response: Awaited<ReturnType<typeof rawPost>>) => ({
      status: response.status,
      headers: Object.entries(response.headers).filter(
        ([name]) => !["date", "connection", "keep-alive"].includes(name),
      ),
      body: response.body,
    });
    try {
      const route = await rawPost(agent, body, headers);
      const sdk = await rawPost(agent, body, headers, referenceUrl);

      expect(route.status).toBe(status);
      expect(answer(route)).toEqual(answer(sdk));
    } finally {
      agent.destroy();
    }
  });

  const toolsList = () => JSON.stringify(rpc("tools/list"));

  it.each<{
    label: string;
    body: () => string | ReadableStream<Uint8Array>;
    headers?: Record<string, string>;
    status: number;
  }>([
    { label: "tools/list", body: toolsList, status: 400 },
    { label: "ping", body: () => JSON.stringify(rpc("ping")), status: 400 },
    {
      label: "notifications/initialized",
      body: () =>
        JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }),
      status: 400,
    },
    {
      label: "a response message",
      body: () => JSON.stringify({ jsonrpc: "2.0", id: 7, result: {} }),
      status: 400,
    },
    {
      label: "a batch without an initialize",
      body: () => JSON.stringify([rpc("tools/list"), rpc("prompts/list")]),
      status: 400,
    },
    { label: "an empty batch", body: () => "[]", status: 400 },
    {
      label: "a batch over the SDK's message limit",
      body: () =>
        JSON.stringify(Array.from({ length: 101 }, () => rpc("ping"))),
      status: 400,
    },
    {
      label: "an initialize without its required params",
      body: () => JSON.stringify(rpc("initialize", { params: {} })),
      status: 400,
    },
    {
      label: "JSON that is not JSON-RPC",
      body: () => JSON.stringify({ hello: "world" }),
      status: 400,
    },
    { label: "JSON null", body: () => "null", status: 400 },
    { label: "a body that is not JSON", body: () => "{not json", status: 400 },
    { label: "an empty body", body: () => "", status: 400 },
    {
      label: "a body behind a UTF-8 byte order mark",
      body: () => `\uFEFF${toolsList()}`,
      status: 400,
    },
    {
      label: "an unsupported Mcp-Protocol-Version",
      body: toolsList,
      headers: { "mcp-protocol-version": "1999-01-01" },
      status: 400,
    },
    {
      label: "a Content-Type with parameters",
      body: toolsList,
      headers: { "content-type": "application/json; charset=utf-8" },
      status: 400,
    },
    {
      label: "an Accept without text/event-stream",
      body: toolsList,
      headers: { accept: "application/json" },
      status: 406,
    },
    {
      label: "an Accept without text/event-stream and a body that is not JSON",
      body: () => "{not json",
      headers: { accept: "application/json" },
      status: 406,
    },
    {
      label: "a Content-Type that is not JSON and a body that is not JSON",
      body: () => "{not json",
      headers: { "content-type": "text/plain" },
      status: 415,
    },
    {
      label: "an initialize batched with another message",
      body: () =>
        JSON.stringify([
          JSON.parse(initializeBody(1024)),
          JSON.parse(pingBody(1024)),
        ]),
      status: 400,
    },
    {
      label: "a body over the limit without a Content-Length",
      body: () => chunked(pingBody(LIMIT + 1)),
      status: 413,
    },
  ])("$label", async ({ body, headers, status }) => {
    const route = await answerOf(await postWithout(body(), headers));
    const sdk = await answerOf(
      await postWithout(body(), headers, referenceUrl),
    );

    expect(route).toEqual(sdk);
    expect(route.status).toBe(status);
    expect(route.headers.map(([name]) => name)).not.toContain("mcp-session-id");
  });
});
