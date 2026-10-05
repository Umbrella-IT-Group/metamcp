/**
 * The SSE stream-open leg at the per-credential ceiling.
 *
 * The ceiling is one budget across both transports, so a new SSE stream at
 * the ceiling may be admitted by evicting the credential's idle
 * StreamableHTTP session, the same way a new StreamableHTTP session is. An SSE
 * session itself is never evicted: it is one open stream, in use for as long
 * as it exists, and its manager registers no eviction hook.
 *
 * The StreamableHTTP manager is stood in for by a counter with the same
 * contract (it lists per credential and its evictor drops the session
 * synchronously), registered beside the real SSE manager this router module
 * registers on import. Driven over a real socket, as in
 * `sse.caller-binding.test.ts`.
 */
import type { Server } from "node:http";

import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import express from "express";
import {
  afterAll,
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";

const h = vi.hoisted(() => ({
  logger: { error: vi.fn(), warn: vi.fn(), info: vi.fn(), debug: vi.fn() },
  getServer: vi.fn(),
}));

vi.mock("@/utils/logger", () => ({ default: h.logger }));

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
    getServer: h.getServer,
    cleanupSession: vi.fn().mockResolvedValue(undefined),
  },
}));

vi.mock("../../lib/metamcp/log-store", () => ({
  metamcpLogStore: { record: vi.fn() },
}));

import { authenticateApiKey } from "@/middleware/api-key-oauth.middleware";
import { lookupEndpoint } from "@/middleware/lookup-endpoint-middleware";
import { rateLimitMiddleware } from "@/middleware/rate-limit.middleware";

import {
  countLiveSessionsForIdentity,
  registerSessionActivityProbe,
  registerSessionCounter,
} from "../../lib/metamcp/credential-session-quota";
import type { SessionIdentity } from "../../lib/metamcp/session-auth";
import sseRouter from "./sse";

const KEY_UUID = "3f7f8a1e-0000-4000-8000-0000000000aa";
const IDENTITY: SessionIdentity = { method: "api_key", credentialId: KEY_UUID };
const ORIGINAL_CEILING = process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL;

/** The stand-in StreamableHTTP sessions of this credential: id -> endpoint. */
const streamableSessions = new Map<string, string>();
const evictSessionForAdmission = vi.fn((sessionId: string) => {
  if (!streamableSessions.delete(sessionId)) return undefined;
  return Promise.resolve();
});

let server: Server;
let baseUrl = "";

function makeInstance() {
  return {
    server: {
      // The real SDK `Server.connect` starts the transport, which writes the
      // SSE headers and the `endpoint` frame the client waits for.
      connect: vi.fn(async (transport: Transport) => {
        await transport.start();
      }),
    },
    cleanup: vi.fn().mockResolvedValue(undefined),
    handlerContext: {} as Record<string, unknown>,
  };
}

/** Open the SSE stream and wait for its `endpoint` frame. */
async function openStream(): Promise<{
  status: number;
  abort: AbortController;
  body: string;
}> {
  const abort = new AbortController();
  const response = await fetch(`${baseUrl}/metamcp/ep-1/sse`, {
    signal: abort.signal,
  });
  if (response.status !== 200 || !response.body) {
    return { status: response.status, abort, body: await response.text() };
  }
  const reader = response.body.getReader();
  const frame = new TextDecoder().decode((await reader.read()).value);
  return { status: response.status, abort, body: frame };
}

beforeAll(async () => {
  registerSessionCounter({
    countSessionsForIdentity: (identity) =>
      identity.credentialId === KEY_UUID ? streamableSessions.size : 0,
    listSessionsForIdentity: (identity) =>
      identity.credentialId === KEY_UUID
        ? [...streamableSessions].map(([sessionId, endpointName]) => ({
            sessionId,
            endpointName,
          }))
        : [],
    evictSessionForAdmission,
  });
  // Reports EVERY id as long idle, SSE stream ids included, so the SSE
  // exclusion below is proven to come from the missing eviction hook rather
  // than from the session being untracked.
  registerSessionActivityProbe(() => ({ idleMs: 3_600_000, inFlight: false }));

  vi.mocked(lookupEndpoint).mockImplementation(((
    req: express.Request,
    _res: express.Response,
    next: () => void,
  ) => {
    Object.assign(req, {
      namespaceUuid: "ns-1",
      endpointName: "ep-1",
      authMethod: "api_key",
      apiKeyUuid: KEY_UUID,
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
  vi.clearAllMocks();
  streamableSessions.clear();
  h.getServer.mockImplementation(async () => makeInstance());
});

afterEach(async () => {
  if (ORIGINAL_CEILING === undefined) {
    delete process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL;
  } else {
    process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL = ORIGINAL_CEILING;
  }
  // Every stream a test opened is aborted; wait for the router's close
  // handler to drop it so the next test starts from an empty credential.
  streamableSessions.clear();
  await vi.waitFor(() =>
    expect(countLiveSessionsForIdentity(IDENTITY)).toBe(0),
  );
});

describe("GET /sse at the ceiling", () => {
  it("admits a new stream by evicting the credential's idle StreamableHTTP session", async () => {
    process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL = "2";
    // Both report the same idle time, so the tie goes to the lower id.
    streamableSessions.set("streamable-b", "autotask");
    streamableSessions.set("streamable-a", "ninja");
    // The count while the stream is being connected, i.e. after the SSE
    // session is registered: the reservation must already be back by then.
    let countWhileConnecting: number | undefined;
    h.getServer.mockImplementationOnce(async () => {
      const instance = makeInstance();
      const connect = instance.server.connect;
      instance.server.connect = vi.fn(async (transport: Transport) => {
        countWhileConnecting = countLiveSessionsForIdentity(IDENTITY);
        await connect(transport);
      });
      return instance;
    });

    const stream = await openStream();
    try {
      expect(stream.status).toBe(200);
      expect(stream.body).toContain("sessionId=");
      expect(evictSessionForAdmission).toHaveBeenCalledTimes(1);
      expect(evictSessionForAdmission).toHaveBeenCalledWith("streamable-a");
      // One StreamableHTTP session left, plus the new SSE stream; the slot
      // reservation was released once the stream registered.
      expect(streamableSessions.size).toBe(1);
      expect(countLiveSessionsForIdentity(IDENTITY)).toBe(2);
      expect(countWhileConnecting).toBe(2);
      const evictionLines = h.logger.info.mock.calls
        .map((call) => String(call[0]))
        .filter((line) =>
          line.startsWith("Concurrent-session ceiling: evicted idle session"),
        );
      expect(evictionLines).toHaveLength(1);
      expect(evictionLines[0]).toMatch(
        /^Concurrent-session ceiling: evicted idle session on ninja \(idle 3600s\) for api_key credential "test-consumer" to admit a new session \(2\/2\)/,
      );
    } finally {
      stream.abort.abort();
    }
  });

  it("never evicts an SSE stream: with only streams at the ceiling, refuses with today's exact body", async () => {
    process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL = "1";
    const first = await openStream();
    try {
      expect(first.status).toBe(200);
      expect(countLiveSessionsForIdentity(IDENTITY)).toBe(1);

      const second = await openStream();

      expect(second.status).toBe(429);
      expect(JSON.parse(second.body)).toEqual({
        error:
          "Too many concurrent sessions for this credential (1/1). Close idle sessions, or ask an administrator to raise MCP_MAX_SESSIONS_PER_CREDENTIAL.",
      });
      expect(evictSessionForAdmission).not.toHaveBeenCalled();
      expect(countLiveSessionsForIdentity(IDENTITY)).toBe(1);
    } finally {
      first.abort.abort();
    }
  });

  it("a stream open that fails after evicting still hands its reserved slot back", async () => {
    process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL = "1";
    streamableSessions.set("streamable-old", "ninja");
    h.getServer.mockResolvedValueOnce(undefined);

    const failed = await openStream();

    expect(failed.status).toBe(500);
    expect(evictSessionForAdmission).toHaveBeenCalledWith("streamable-old");
    // Victim gone, no stream registered, and no reservation left behind: a
    // failed admission must not hold a slot.
    expect(countLiveSessionsForIdentity(IDENTITY)).toBe(0);
  });
});
