/**
 * Caller binding on the SSE transport (migration 0030).
 *
 * The `/message` leg drives `tools/call` for every SSE consumer and reached
 * the auditing middleware with nothing stamped at all — no consumer label and
 * no caller binding — so those calls landed as fully un-attributed rows. That
 * is the failure mode worth a test: an all-NULL row is indistinguishable from
 * a path nobody uses, so the gap could not be seen from the table it damaged.
 *
 * Both legs are driven for real over a socket rather than unit-tested, because
 * what is under test is the WIRING: the router entering the request-scoped
 * store around the dispatch, and stamping the pooled instance it acquires.
 * Only the DB-touching boundary is mocked.
 */
import type { Server } from "node:http";

import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
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

vi.mock("@/middleware/api-key-oauth.middleware", () => ({
  authenticateApiKey: vi.fn(),
}));
vi.mock("@/middleware/lookup-endpoint-middleware", () => ({
  lookupEndpoint: vi.fn(),
}));
vi.mock("@/middleware/rate-limit.middleware", () => ({
  rateLimitMiddleware: vi.fn(),
}));

vi.mock("../../lib/metamcp/consumer-identity-resolver", () => ({
  resolveClientIdentity: vi.fn().mockResolvedValue({ name: "test-consumer" }),
}));

vi.mock("../../lib/metamcp/metamcp-server-pool", () => ({
  metaMcpServerPool: {
    getServer: vi.fn(),
    cleanupSession: vi.fn().mockResolvedValue(undefined),
  },
}));

import { authenticateApiKey } from "@/middleware/api-key-oauth.middleware";
import { lookupEndpoint } from "@/middleware/lookup-endpoint-middleware";
import { rateLimitMiddleware } from "@/middleware/rate-limit.middleware";

import type { CallerContext } from "../../lib/metamcp/caller-context-store";
import { getCallerContext } from "../../lib/metamcp/caller-context-store";
import { metaMcpServerPool } from "../../lib/metamcp/metamcp-server-pool";
import sseRouter from "./sse";

const CALLER = {
  namespaceUuid: "ns-1",
  endpointName: "ep-1",
  authMethod: "api_key",
  apiKeyUuid: "3f7f8a1e-0000-4000-8000-000000000005",
  apiKeyUserId: "key-owner-1",
  apiKeyActsAsUserId: "acted-as-user-1",
  // Stamped app-wide by auditContextMiddleware in production.
  auditRequestId: "req-sse",
  auditClientIp: "203.0.113.7",
};

let server: Server;
let baseUrl = "";

/** What the auditing middleware would see, captured from inside the dispatch. */
let seen: CallerContext | undefined;
let instance: {
  server: { connect: ReturnType<typeof vi.fn> };
  cleanup: ReturnType<typeof vi.fn>;
  handlerContext: Record<string, unknown>;
};

function makeInstance() {
  return {
    // `connect` receives the transport the router just built, which is the
    // only handle a test has on it. Attaching `onmessage` here is what lets
    // the assertion run at the exact point a tools/call would be dispatched.
    server: {
      connect: vi.fn(async (transport: Transport) => {
        transport.onmessage = () => {
          seen = getCallerContext();
        };
        // The real SDK `Server.connect` starts the transport, which is what
        // writes the SSE headers and the `endpoint` frame the client waits
        // for. Without it the stream never flushes and the request hangs.
        await transport.start();
      }),
    },
    cleanup: vi.fn().mockResolvedValue(undefined),
    handlerContext: {} as Record<string, unknown>,
  };
}

beforeAll(async () => {
  vi.mocked(lookupEndpoint).mockImplementation(((
    req: express.Request,
    _res: express.Response,
    next: () => void,
  ) => {
    Object.assign(req, CALLER);
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
  app.use("/metamcp", sseRouter);
  await new Promise<void>((resolve) => {
    server = app.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  if (typeof address === "object" && address) {
    baseUrl = `http://127.0.0.1:${address.port}`;
  }
});

afterAll(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

beforeEach(() => {
  seen = undefined;
  instance = makeInstance();
  vi.mocked(metaMcpServerPool.getServer).mockResolvedValue(instance as never);
});

/**
 * Open the SSE stream and read the `endpoint` frame the transport emits, which
 * is where the sessionId the /message leg needs comes from. The stream is left
 * open (aborted by the caller) — closing it tears the session down.
 */
async function openStream(): Promise<{
  sessionId: string;
  abort: AbortController;
}> {
  const abort = new AbortController();
  const response = await fetch(`${baseUrl}/metamcp/ep-1/sse`, {
    signal: abort.signal,
  });
  if (!response.body) throw new Error("SSE response carried no body");
  const reader = response.body.getReader();
  const frame = new TextDecoder().decode((await reader.read()).value);
  const match = /sessionId=([\w-]+)/.exec(frame);
  if (!match) throw new Error(`no sessionId in SSE frame: ${frame}`);
  return { sessionId: match[1], abort };
}

const postMessage = (sessionId: string) =>
  fetch(`${baseUrl}/metamcp/ep-1/message?sessionId=${sessionId}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
  });

describe("SSE /message leg — tool calls are attributable", () => {
  it("dispatches inside this request's caller binding", async () => {
    const { sessionId, abort } = await openStream();

    const response = await postMessage(sessionId);
    expect(response.status).toBe(202);

    expect(seen).toEqual({
      clientName: "test-consumer",
      apiKeyUuid: "3f7f8a1e-0000-4000-8000-000000000005",
      authMethod: "api_key",
      userId: "key-owner-1",
      actsAsUserId: "acted-as-user-1",
      callerIp: "203.0.113.7",
      requestId: "req-sse",
    });

    abort.abort();
  });

  it("takes the binding from the message request, not from the one that opened the stream", async () => {
    const { sessionId, abort } = await openStream();

    // A later message arrives with a different request id and address — the
    // stream-open values must not be what gets audited.
    vi.mocked(lookupEndpoint).mockImplementationOnce(((
      req: express.Request,
      _res: express.Response,
      next: () => void,
    ) => {
      Object.assign(req, {
        ...CALLER,
        auditRequestId: "req-sse-later",
        auditClientIp: "198.51.100.4",
      });
      next();
    }) as never);

    await postMessage(sessionId);

    expect(seen?.requestId).toBe("req-sse-later");
    expect(seen?.callerIp).toBe("198.51.100.4");

    abort.abort();
  });
});

describe("SSE /sse leg — the acquired instance carries the fallback binding", () => {
  it("stamps the pooled instance at stream open", async () => {
    const { abort } = await openStream();

    expect(instance.handlerContext).toMatchObject({
      clientName: "test-consumer",
      apiKeyUuid: "3f7f8a1e-0000-4000-8000-000000000005",
      authMethod: "api_key",
      userId: "key-owner-1",
      actsAsUserId: "acted-as-user-1",
      callerIp: "203.0.113.7",
      requestId: "req-sse",
    });

    abort.abort();
  });
});
