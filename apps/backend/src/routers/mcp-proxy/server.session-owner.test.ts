/**
 * Sessions on the Inspector's single-server routes (`/mcp-proxy/server`)
 * belong to the signed-in user who opened them and close with the server row
 * they were opened from.
 *
 *  - The opener's later requests are served. Any other request naming the
 *    session (another user, or no user) gets exactly the answer a session id
 *    that was never issued gets on that route, and nothing reaches upstream.
 *  - Closing a row's sessions (what an update or delete of the row does) ends
 *    the sessions opened from that row, by uuid or by a matching url, and no
 *    other.
 *  - A row change that lands while a connection is still opening, and a
 *    request that ends while it is opening, leave no usable session and close
 *    what the open started.
 *
 * Driven over a real socket through the real router, the real proxy wiring
 * (lib/mcp-proxy), the real SDK server transports and the real session
 * registry. The upstream end is a stand-in client transport that answers each
 * request and counts starts, sends and closes; the destination guard, the
 * database and the pool are faked. The signed-in user is chosen per request by
 * an `x-test-user` header; no header means no user. An `x-test-numeric-user`
 * header signs in a user whose id is a number, which the registry does not
 * accept as a user id.
 */
import type { Server as HttpServer } from "node:http";
import { inspect } from "node:util";

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

const { upstream, UpstreamStandIn } = vi.hoisted(() => {
  const upstream = {
    started: 0,
    closed: 0,
    sent: 0,
    terminated: 0,
    /** When set, every start waits for it (and fails if it rejects). */
    startGate: undefined as Promise<void> | undefined,
    /** When set, every close waits for it after counting. */
    closeGate: undefined as Promise<void> | undefined,
    /** When set, every close fails with this message after counting. */
    closeFailure: undefined as string | undefined,
    /** The most recently built stand-in. */
    latest: undefined as { onmessage?: unknown } | undefined,
  };
  /**
   * The upstream MCP server, reduced to a transport that answers every
   * request it is sent: `initialize` with a server identity, anything else
   * with `{}`.
   */
  class UpstreamStandIn {
    onmessage?: (message: unknown) => void;
    onclose?: () => void;
    onerror?: (error: Error) => void;
    sessionId = "upstream-session";
    constructor() {
      upstream.latest = this;
    }
    async start() {
      upstream.started += 1;
      if (upstream.startGate) await upstream.startGate;
    }
    async close() {
      upstream.closed += 1;
      if (upstream.closeGate) await upstream.closeGate;
      if (upstream.closeFailure) throw new Error(upstream.closeFailure);
      this.onclose?.();
    }
    async send(message: { id?: unknown; method?: string }) {
      upstream.sent += 1;
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
    async terminateSession() {
      upstream.terminated += 1;
    }
  }
  return { upstream, UpstreamStandIn };
});

vi.mock("@modelcontextprotocol/sdk/client/streamableHttp.js", () => ({
  StreamableHTTPClientTransport: UpstreamStandIn,
}));
vi.mock("@modelcontextprotocol/sdk/client/sse.js", () => ({
  SSEClientTransport: UpstreamStandIn,
  SseError: class SseError extends Error {
    constructor(
      public code: number | undefined,
      message: string,
    ) {
      super(message);
    }
  },
}));

// The destination guard has its own suites (url-guard.test.ts,
// server.remote-url.test.ts); here it only has to let the stand-in through.
vi.mock("@/lib/metamcp/url-guard", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/lib/metamcp/url-guard")>()),
  assertPublicMcpUrl: vi.fn(async (url: string) => ({ url: new URL(url) })),
  createGuardedFetch: vi.fn(() => fetch),
}));
vi.mock("../../db/repositories", () => ({
  mcpServersRepository: { findAllAccessibleToUser: vi.fn() },
  oauthSessionsRepository: {
    findByMcpServerUuid: vi.fn(async () => undefined),
  },
}));
vi.mock("../../db/index", () => ({ db: {}, pool: {} }));
vi.mock("../../lib/metamcp/mcp-server-pool", () => ({
  mcpServerPool: { handleServerCrashWithoutNamespace: vi.fn() },
}));
vi.mock("../../lib/metamcp/client", () => ({
  transformDockerUrl: (url: string) => url,
  POOL_GUARD_OPTIONS: {},
}));

const { default: logger } = await import("@/utils/logger");
const { mcpServersRepository } = await import("../../db/repositories");
const { closeInspectorSessionsForServer, inspectorOpensPending } = await import(
  "../../lib/metamcp/inspector-sessions"
);
const { default: serverRouter } = await import("./server");

const PROTOCOL_VERSION = "2025-06-18";
const USER_A = "user-a";
const USER_B = "user-b";

/** A registered Streamable HTTP row, public so every user here can see it. */
const row = (uuid: string, name: string, url: string) => ({
  uuid,
  name,
  description: null,
  type: "STREAMABLE_HTTP",
  command: null,
  args: [],
  env: {},
  url,
  bearerToken: null,
  headers: {},
  error_status: "NONE",
  created_at: new Date("2026-11-01T00:00:00Z"),
  user_id: null,
});
const ROW_A = row(
  "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa",
  "row-a",
  "https://a.example.test/mcp",
);
const ROW_B = row(
  "bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb",
  "row-b",
  "https://b.example.test/mcp",
);
const ROW_BY_URL = row(
  "cccccccc-3333-4333-8333-cccccccccccc",
  "row-by-url",
  "https://c.example.test/mcp",
);
const ROW_SSE = {
  ...row(
    "eeeeeeee-5555-4555-8555-eeeeeeeeeeee",
    "row-sse",
    "https://e.example.test/sse",
  ),
  type: "SSE",
};
const ROWS = [ROW_A, ROW_B, ROW_BY_URL, ROW_SSE];
const UNREGISTERED_URL = "https://unregistered.example.test/mcp";
const NEVER_ISSUED = "00000000-0000-4000-8000-000000000000";

const byUuid = (target: { uuid: string }) => ({
  transportType: "STREAMABLE_HTTP",
  mcpServerUuid: target.uuid,
});
const byUrl = (url: string) => ({ transportType: "STREAMABLE_HTTP", url });

let httpServer: HttpServer;
let baseUrl = "";
let rpcId = 0;

const rpc = (method: string, params: Record<string, unknown> = {}) =>
  JSON.stringify({ jsonrpc: "2.0", id: (rpcId += 1), method, params });

const initializeBody = () =>
  rpc("initialize", {
    protocolVersion: PROTOCOL_VERSION,
    capabilities: {},
    clientInfo: { name: "inspector", version: "0.0.0" },
  });

const userHeader = (user: string | null): Record<string, string> =>
  user ? { "x-test-user": user } : {};

/** A signed-in user whose id the registry does not accept (a number). */
const NUMERIC_USER = { "x-test-numeric-user": "42" };

function deferred<T = void>() {
  let resolve!: (value: T) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

/** POST /mcp: an initialize when `sessionId` is absent, else `body` on it. */
function postMcp(
  user: string | null,
  options: {
    query?: Record<string, string>;
    sessionId?: string;
    body?: string;
    signal?: AbortSignal;
  } = {},
): Promise<Response> {
  const query = new URLSearchParams(options.query ?? byUuid(ROW_A));
  return fetch(`${baseUrl}/mcp-proxy/server/mcp?${query}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      ...userHeader(user),
      ...(options.sessionId
        ? {
            "mcp-session-id": options.sessionId,
            "mcp-protocol-version": PROTOCOL_VERSION,
          }
        : {}),
    },
    body: options.body ?? initializeBody(),
    signal: options.signal,
  });
}

const ping = (user: string | null, sessionId: string) =>
  postMcp(user, { sessionId, body: rpc("ping") });

/** GET /mcp on a session. A served stream stays open, so it is cut here. */
async function getMcp(user: string | null, sessionId: string) {
  const controller = new AbortController();
  const response = await fetch(`${baseUrl}/mcp-proxy/server/mcp`, {
    headers: {
      accept: "text/event-stream",
      "mcp-session-id": sessionId,
      "mcp-protocol-version": PROTOCOL_VERSION,
      ...userHeader(user),
    },
    signal: controller.signal,
  });
  const answer =
    response.status === 200
      ? { status: 200, type: response.headers.get("content-type"), body: "" }
      : await answerOf(response, sessionId);
  controller.abort();
  return answer;
}

const deleteMcp = (user: string | null, sessionId: string) =>
  fetch(`${baseUrl}/mcp-proxy/server/mcp`, {
    method: "DELETE",
    headers: { "mcp-session-id": sessionId, ...userHeader(user) },
  });

/** Status, content type and body, with the request's own echoed id masked. */
async function answerOf(response: Response, sessionId: string) {
  return {
    status: response.status,
    type: response.headers.get("content-type"),
    body: (await response.text()).replaceAll(sessionId, "<id>"),
  };
}

/** Open a Streamable HTTP session and return its id. */
async function openMcp(
  user: string,
  query: Record<string, string> = byUuid(ROW_A),
): Promise<string> {
  const opened = await postMcp(user, { query });
  expect(opened.status).toBe(200);
  await opened.text();
  const sessionId = opened.headers.get("mcp-session-id") ?? "";
  expect(sessionId).not.toBe("");
  return sessionId;
}

/** Read an SSE stream until `predicate` holds for what has arrived. */
async function readUntil(
  reader: ReadableStreamDefaultReader<Uint8Array>,
  predicate: (text: string) => boolean,
): Promise<{ text: string; done: boolean }> {
  const decoder = new TextDecoder();
  let text = "";
  for (;;) {
    const { value, done } = await reader.read();
    if (done) return { text, done: true };
    text += decoder.decode(value, { stream: true });
    if (predicate(text)) return { text, done: false };
  }
}

/** GET /sse: the open stream and the session id its endpoint event names. */
async function openSse(
  user: string,
  query: Record<string, string> = byUuid(ROW_A),
) {
  const controller = new AbortController();
  const response = await fetch(
    `${baseUrl}/mcp-proxy/server/sse?${new URLSearchParams(query)}`,
    {
      headers: { accept: "text/event-stream", ...userHeader(user) },
      signal: controller.signal,
    },
  );
  expect(response.status).toBe(200);
  const reader = (response.body as ReadableStream<Uint8Array>).getReader();
  const { text } = await readUntil(reader, (seen) =>
    seen.includes("event: endpoint"),
  );
  const endpoint = /event: endpoint\ndata: (.+)\n/.exec(text)?.[1] ?? "";
  const sessionId = new URL(endpoint, baseUrl).searchParams.get("sessionId");
  expect(sessionId).toBeTruthy();
  return { controller, reader, sessionId: sessionId as string };
}

const postMessage = (user: string | null, sessionId: string) =>
  fetch(
    `${baseUrl}/mcp-proxy/server/message?${new URLSearchParams({ sessionId })}`,
    {
      method: "POST",
      headers: { "content-type": "application/json", ...userHeader(user) },
      body: rpc("ping"),
    },
  );

/** Let a close still queued behind a response run before counting. */
const settle = () => new Promise((resolve) => setTimeout(resolve, 50));

beforeAll(async () => {
  const app = express();
  // The parent router's admin-session gate, reduced to the user it leaves.
  app.use((req, _res, next) => {
    const id = req.headers["x-test-user"];
    if (typeof id === "string") {
      Object.assign(req, {
        user: { id, role: "admin", email: `${id}@example.test` },
      });
    }
    const numericId = req.headers["x-test-numeric-user"];
    if (typeof numericId === "string") {
      Object.assign(req, {
        user: {
          id: Number(numericId),
          role: "admin",
          email: "numeric@example.test",
        },
      });
    }
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

beforeEach(async () => {
  upstream.startGate = undefined;
  upstream.closeGate = undefined;
  upstream.closeFailure = undefined;
  vi.mocked(mcpServersRepository.findAllAccessibleToUser).mockReset();
  vi.mocked(mcpServersRepository.findAllAccessibleToUser).mockResolvedValue(
    ROWS as never,
  );
  // Each case counts the sessions it opened on a row, so none is left over
  // from an earlier case.
  for (const target of ROWS) {
    await closeInspectorSessionsForServer(target.uuid);
  }
  await settle();
});

describe("Streamable HTTP session: who it answers", () => {
  it("serves the opener's later POST and GET requests", async () => {
    const sessionId = await openMcp(USER_A);

    const pinged = await ping(USER_A, sessionId);
    expect(pinged.status).toBe(200);
    await pinged.text();
    expect((await getMcp(USER_A, sessionId)).status).toBe(200);
  });

  it("answers another user's POST exactly like a never-issued id and sends nothing upstream", async () => {
    const sessionId = await openMcp(USER_A);
    await settle();
    const sentBefore = upstream.sent;

    const foreign = await answerOf(await ping(USER_B, sessionId), sessionId);
    const unknown = await answerOf(
      await ping(USER_B, NEVER_ISSUED),
      NEVER_ISSUED,
    );

    expect(foreign.status).toBe(404);
    expect(foreign).toEqual(unknown);
    await settle();
    expect(upstream.sent).toBe(sentBefore);
  });

  it("answers another user's GET exactly like a never-issued id", async () => {
    const sessionId = await openMcp(USER_A);

    const foreign = await getMcp(USER_B, sessionId);
    const unknown = await getMcp(USER_B, NEVER_ISSUED);

    expect(foreign.status).toBe(404);
    expect(foreign).toEqual(unknown);
  });

  it("answers another user's DELETE like a never-issued id and leaves the session working; the opener's DELETE closes it", async () => {
    const sessionId = await openMcp(USER_A);
    await settle();
    const before = { ...upstream };

    const foreign = await answerOf(
      await deleteMcp(USER_B, sessionId),
      sessionId,
    );
    const unknown = await answerOf(
      await deleteMcp(USER_B, NEVER_ISSUED),
      NEVER_ISSUED,
    );
    expect(foreign.status).toBe(404);
    expect(foreign).toEqual(unknown);
    await settle();
    expect(upstream.closed).toBe(before.closed);
    expect(upstream.terminated).toBe(before.terminated);

    const stillThere = await ping(USER_A, sessionId);
    expect(stillThere.status).toBe(200);
    await stillThere.text();

    const deleted = await deleteMcp(USER_A, sessionId);
    expect(deleted.status).toBe(200);
    expect(upstream.terminated).toBe(before.terminated + 1);
    await vi.waitFor(() =>
      expect(upstream.closed).toBeGreaterThan(before.closed),
    );
    const gone = await ping(USER_A, sessionId);
    expect(gone.status).toBe(404);
    await gone.text();
    // The cleanup forgot the session, so a row close finds nothing of it.
    expect(await closeInspectorSessionsForServer(ROW_A.uuid)).toBe(0);
  });

  it("answers a request with no signed-in user like a never-issued id", async () => {
    const sessionId = await openMcp(USER_A);
    await settle();
    const before = { ...upstream };

    const posted = await answerOf(await ping(null, sessionId), sessionId);
    expect(posted.status).toBe(404);
    expect(posted).toEqual(
      await answerOf(await ping(null, NEVER_ISSUED), NEVER_ISSUED),
    );
    const got = await getMcp(null, sessionId);
    expect(got.status).toBe(404);
    expect(got).toEqual(await getMcp(null, NEVER_ISSUED));
    const deleted = await answerOf(await deleteMcp(null, sessionId), sessionId);
    expect(deleted.status).toBe(404);
    expect(deleted).toEqual(
      await answerOf(await deleteMcp(null, NEVER_ISSUED), NEVER_ISSUED),
    );
    await settle();
    expect(upstream.sent).toBe(before.sent);
    expect(upstream.closed).toBe(before.closed);
    expect(upstream.terminated).toBe(before.terminated);

    const stillThere = await ping(USER_A, sessionId);
    expect(stillThere.status).toBe(200);
    await stillThere.text();
  });

  it("keeps two users' sessions apart", async () => {
    const sessionA = await openMcp(USER_A);
    const sessionB = await openMcp(USER_B, byUuid(ROW_B));

    for (const [user, sessionId, status] of [
      [USER_A, sessionA, 200],
      [USER_B, sessionB, 200],
      [USER_A, sessionB, 404],
      [USER_B, sessionA, 404],
    ] as const) {
      const response = await ping(user, sessionId);
      expect(response.status).toBe(status);
      await response.text();
    }
  });

  it("applies the same rule to a session opened by a matching url and by an unregistered url", async () => {
    for (const url of [ROW_BY_URL.url, UNREGISTERED_URL]) {
      const sessionId = await openMcp(USER_A, byUrl(url));

      const own = await ping(USER_A, sessionId);
      expect(own.status).toBe(200);
      await own.text();
      const foreign = await answerOf(await ping(USER_B, sessionId), sessionId);
      expect(foreign).toEqual(
        await answerOf(await ping(USER_B, NEVER_ISSUED), NEVER_ISSUED),
      );
    }
  });
});

describe("Streamable HTTP session: cleanup", () => {
  it("forgets the session and stops routing to it before its transports finish closing", async () => {
    const sessionId = await openMcp(USER_A);
    await settle();
    const gate = deferred();
    upstream.closeGate = gate.promise;
    const before = { ...upstream };

    const deleting = deleteMcp(USER_A, sessionId);
    await vi.waitFor(() =>
      expect(upstream.closed).toBeGreaterThan(before.closed),
    );

    try {
      expect(await closeInspectorSessionsForServer(ROW_A.uuid)).toBe(0);
      const pinged = await ping(USER_A, sessionId);
      expect(pinged.status).toBe(404);
      await pinged.text();
      // A second DELETE meanwhile answers at once, without waiting on the
      // close in progress or ending the upstream session again.
      let againStatus: number | undefined;
      const again = deleteMcp(USER_A, sessionId).then((response) => {
        againStatus = response.status;
        return response.text();
      });
      await vi.waitFor(() => expect(againStatus).toBe(404));
      await again;
      expect(upstream.terminated).toBe(before.terminated + 1);
    } finally {
      gate.resolve();
    }
    const deleted = await deleting;
    expect(deleted.status).toBe(200);
  });
});

describe("SSE session: who it answers", () => {
  it("accepts the opener's messages and answers another user's like a never-issued id", async () => {
    const pendingBefore = inspectorOpensPending();
    const { controller, sessionId } = await openSse(USER_A);
    try {
      // The stream stays open, but the open itself is over.
      expect(inspectorOpensPending()).toBe(pendingBefore);
      await settle();
      const sentBefore = upstream.sent;

      const foreign = await answerOf(
        await postMessage(USER_B, sessionId),
        sessionId,
      );
      const unknown = await answerOf(
        await postMessage(USER_B, NEVER_ISSUED),
        NEVER_ISSUED,
      );
      expect(foreign.status).toBe(404);
      expect(foreign).toEqual(unknown);
      expect(
        await answerOf(await postMessage(null, sessionId), sessionId),
      ).toEqual(unknown);
      await settle();
      expect(upstream.sent).toBe(sentBefore);

      const own = await postMessage(USER_A, sessionId);
      expect(own.status).toBe(202);
      await own.text();
      await vi.waitFor(() => expect(upstream.sent).toBe(sentBefore + 1));
    } finally {
      controller.abort();
    }
  });
});

describe("closing a row's sessions", () => {
  it("ends the row's Streamable HTTP and SSE sessions and leaves another row's working", async () => {
    const mcpA = await openMcp(USER_A, byUuid(ROW_A));
    const sseA = await openSse(USER_A, byUuid(ROW_A));
    const mcpB = await openMcp(USER_A, byUuid(ROW_B));
    await settle();
    const closedBefore = upstream.closed;

    expect(await closeInspectorSessionsForServer(ROW_A.uuid)).toBe(2);

    await vi.waitFor(() =>
      expect(upstream.closed).toBeGreaterThanOrEqual(closedBefore + 2),
    );
    const afterMcp = await ping(USER_A, mcpA);
    expect(afterMcp.status).toBe(404);
    await afterMcp.text();
    expect((await readUntil(sseA.reader, () => false)).done).toBe(true);
    const afterSse = await postMessage(USER_A, sseA.sessionId);
    expect(afterSse.status).toBe(404);
    await afterSse.text();

    const other = await ping(USER_A, mcpB);
    expect(other.status).toBe(200);
    await other.text();
  });

  it("ends a session whose upstream is an SSE row", async () => {
    const sessionId = await openMcp(USER_A, {
      transportType: "SSE",
      mcpServerUuid: ROW_SSE.uuid,
    });

    expect(await closeInspectorSessionsForServer(ROW_SSE.uuid)).toBe(1);

    const after = await ping(USER_A, sessionId);
    expect(after.status).toBe(404);
    await after.text();
  });

  it("ends a session opened by a url that matches the row", async () => {
    const sessionId = await openMcp(USER_A, byUrl(ROW_BY_URL.url));

    expect(await closeInspectorSessionsForServer(ROW_BY_URL.uuid)).toBe(1);

    const after = await ping(USER_A, sessionId);
    expect(after.status).toBe(404);
    await after.text();
  });

  it("leaves a session opened by an unregistered url alone", async () => {
    const sessionId = await openMcp(USER_A, byUrl(UNREGISTERED_URL));

    for (const target of ROWS) {
      await closeInspectorSessionsForServer(target.uuid);
    }

    const after = await ping(USER_A, sessionId);
    expect(after.status).toBe(200);
    await after.text();
  });
});

describe("a row change while a connection is opening", () => {
  /** What an open left behind: no usable id, nothing started still open. */
  async function expectNothingUsable(
    response: Response,
    before: typeof upstream,
    pendingBefore: number,
  ) {
    // Status first: a usable SSE session's body never ends.
    expect(response.status).toBe(409);
    expect(response.headers.get("mcp-session-id")).toBeNull();
    const body = await response.text();
    expect(body).not.toContain("event: endpoint");
    expect(JSON.parse(body)).toEqual({
      jsonrpc: "2.0",
      error: {
        code: -32000,
        message:
          "This connection was not opened because the server changed while it was opening. Connect again.",
      },
      id: null,
    });
    await vi.waitFor(() =>
      expect(upstream.closed - before.closed).toBeGreaterThanOrEqual(
        upstream.started - before.started,
      ),
    );
    expect(upstream.started - before.started).toBe(1);
    await vi.waitFor(() => expect(inspectorOpensPending()).toBe(pendingBefore));
    expect(await closeInspectorSessionsForServer(ROW_A.uuid)).toBe(0);
    expect(await closeInspectorSessionsForServer(ROW_BY_URL.uuid)).toBe(0);
  }

  it.each([
    ["by uuid", byUuid(ROW_A), ROW_A],
    ["by a matching url", byUrl(ROW_BY_URL.url), ROW_BY_URL],
  ])(
    "POST /mcp %s: a change committed during the row lookup leaves no usable session",
    async (_label, query, target) => {
      const lookup = deferred<typeof ROWS>();
      vi.mocked(
        mcpServersRepository.findAllAccessibleToUser,
      ).mockImplementationOnce(() => lookup.promise as never);
      const before = { ...upstream };
      const pendingBefore = inspectorOpensPending();

      const opening = postMcp(USER_A, { query });
      await vi.waitFor(() =>
        expect(
          mcpServersRepository.findAllAccessibleToUser,
        ).toHaveBeenCalledTimes(1),
      );
      await closeInspectorSessionsForServer(target.uuid);
      lookup.resolve(ROWS);

      await expectNothingUsable(await opening, before, pendingBefore);
    },
  );

  it.each([
    ["by uuid", byUuid(ROW_A), ROW_A],
    ["by a matching url", byUrl(ROW_BY_URL.url), ROW_BY_URL],
  ])(
    "POST /mcp %s: a change committed while the transport starts leaves no usable session",
    async (_label, query, target) => {
      const gate = deferred();
      upstream.startGate = gate.promise;
      const before = { ...upstream };
      const pendingBefore = inspectorOpensPending();

      const opening = postMcp(USER_A, { query });
      await vi.waitFor(() => expect(upstream.started).toBe(before.started + 1));
      await closeInspectorSessionsForServer(target.uuid);
      gate.resolve();

      await expectNothingUsable(await opening, before, pendingBefore);
    },
  );

  it("GET /sse: a change committed while the transport starts leaves no usable session", async () => {
    const gate = deferred();
    upstream.startGate = gate.promise;
    const before = { ...upstream };
    const pendingBefore = inspectorOpensPending();

    const opening = fetch(
      `${baseUrl}/mcp-proxy/server/sse?${new URLSearchParams(byUuid(ROW_A))}`,
      { headers: { accept: "text/event-stream", ...userHeader(USER_A) } },
    );
    await vi.waitFor(() => expect(upstream.started).toBe(before.started + 1));
    await closeInspectorSessionsForServer(ROW_A.uuid);
    gate.resolve();

    await expectNothingUsable(await opening, before, pendingBefore);
  });

  it("POST /mcp: a change committed while the initialize body is still arriving leaves no usable session", async () => {
    // The change lands after the check that follows the transport open, so
    // registering the session is what refuses it.
    const before = { ...upstream };
    const pendingBefore = inspectorOpensPending();
    const infoBefore = vi.mocked(logger.info).mock.calls.length;
    upstream.latest = undefined;
    const body = new TextEncoder().encode(initializeBody());
    const rest = deferred();
    let firstSent = false;
    const heldBody = new ReadableStream<Uint8Array>({
      async pull(controller) {
        if (!firstSent) {
          firstSent = true;
          controller.enqueue(body.subarray(0, 16));
          return;
        }
        await rest.promise;
        controller.enqueue(body.subarray(16));
        controller.close();
      },
    });

    const opening = fetch(
      `${baseUrl}/mcp-proxy/server/mcp?${new URLSearchParams(byUuid(ROW_A))}`,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          accept: "application/json, text/event-stream",
          ...userHeader(USER_A),
        },
        body: heldBody,
        duplex: "half",
      } as RequestInit,
    );
    // The upstream transport is open and wired to the client transport, so
    // the route is past the post-open check and waiting on the body.
    await vi.waitFor(() =>
      expect(upstream.latest?.onmessage).toBeTypeOf("function"),
    );
    await closeInspectorSessionsForServer(ROW_A.uuid);
    rest.resolve();

    const response = await opening;
    expect(response.status).toBe(404);
    expect(response.headers.get("mcp-session-id")).toBeNull();
    expect(JSON.parse(await response.text())).toMatchObject({
      jsonrpc: "2.0",
      error: { message: "Session not found" },
    });
    await vi.waitFor(() =>
      expect(upstream.closed - before.closed).toBeGreaterThanOrEqual(
        upstream.started - before.started,
      ),
    );
    expect(upstream.started - before.started).toBe(1);
    await vi.waitFor(() => expect(inspectorOpensPending()).toBe(pendingBefore));
    expect(await closeInspectorSessionsForServer(ROW_A.uuid)).toBe(0);
    // Nothing routes to the refused session: it never went live.
    expect(
      vi
        .mocked(logger.info)
        .mock.calls.slice(infoBefore)
        .filter(([message]) => String(message).startsWith("Client <-> Proxy")),
    ).toEqual([]);
  });

  it("a change to another row lets the open finish (control)", async () => {
    const gate = deferred();
    upstream.startGate = gate.promise;
    const before = { ...upstream };

    const opening = postMcp(USER_A, { query: byUuid(ROW_A) });
    await vi.waitFor(() => expect(upstream.started).toBe(before.started + 1));
    await closeInspectorSessionsForServer(ROW_B.uuid);
    gate.resolve();

    const response = await opening;
    expect(response.status).toBe(200);
    await response.text();
    const sessionId = response.headers.get("mcp-session-id") ?? "";
    const pinged = await ping(USER_A, sessionId);
    expect(pinged.status).toBe(200);
    await pinged.text();
  });

  it("an open with nothing committed meanwhile finishes (control)", async () => {
    const lookup = deferred<typeof ROWS>();
    vi.mocked(
      mcpServersRepository.findAllAccessibleToUser,
    ).mockImplementationOnce(() => lookup.promise as never);

    const opening = postMcp(USER_A, { query: byUuid(ROW_A) });
    await vi.waitFor(() =>
      expect(
        mcpServersRepository.findAllAccessibleToUser,
      ).toHaveBeenCalledTimes(1),
    );
    lookup.resolve(ROWS);

    const response = await opening;
    expect(response.status).toBe(200);
    await response.text();
    expect(response.headers.get("mcp-session-id")).toBeTruthy();
  });
});

describe("an open by a request with no usable user id", () => {
  it.each([
    ["GET /sse", "no signed-in user", {}, 400, 0],
    ["GET /sse", "a user whose id is a number", NUMERIC_USER, 409, 1],
    ["POST /mcp", "no signed-in user", {}, 400, 0],
    ["POST /mcp", "a user whose id is a number", NUMERIC_USER, 404, 1],
  ])(
    "%s with %s issues no session id and leaves nothing open",
    async (route, _label, headers, status, started) => {
      const before = { ...upstream };
      const pendingBefore = inspectorOpensPending();
      const infoBefore = vi.mocked(logger.info).mock.calls.length;
      const query = new URLSearchParams(byUuid(ROW_A));

      const response =
        route === "GET /sse"
          ? await fetch(`${baseUrl}/mcp-proxy/server/sse?${query}`, {
              headers: { accept: "text/event-stream", ...headers },
            })
          : await fetch(`${baseUrl}/mcp-proxy/server/mcp?${query}`, {
              method: "POST",
              headers: {
                "content-type": "application/json",
                accept: "application/json, text/event-stream",
                ...headers,
              },
              body: initializeBody(),
            });

      // Status first: a usable SSE session's body never ends.
      expect(response.status).toBe(status);
      expect(response.headers.get("mcp-session-id")).toBeNull();
      expect(await response.text()).not.toContain("event: endpoint");
      expect(upstream.started - before.started).toBe(started);
      await vi.waitFor(() =>
        expect(inspectorOpensPending()).toBe(pendingBefore),
      );
      // Each transport the open started is closed, once: nothing else took
      // the refused session in and closed it again.
      await settle();
      expect(upstream.closed - before.closed).toBe(started);
      expect(await closeInspectorSessionsForServer(ROW_A.uuid)).toBe(0);
      expect(
        vi
          .mocked(logger.info)
          .mock.calls.slice(infoBefore)
          .filter(([message]) =>
            String(message).startsWith("Client <-> Proxy"),
          ),
      ).toEqual([]);
    },
  );
});

describe("what a refused open logs", () => {
  it("a failed upstream close is logged by a fixed label, without its error text, url or session id", async () => {
    const idInError = "11111111-9999-4999-8999-111111111111";
    const gate = deferred();
    upstream.startGate = gate.promise;
    upstream.closeFailure = `close failed for https://vendor.example.test/mcp?mcp-session-id=${idInError}`;
    const before = { ...upstream };
    const errorsBefore = vi.mocked(logger.error).mock.calls.length;

    const opening = postMcp(USER_A, { query: byUuid(ROW_A) });
    await vi.waitFor(() => expect(upstream.started).toBe(before.started + 1));
    await closeInspectorSessionsForServer(ROW_A.uuid);
    gate.resolve();
    const response = await opening;
    expect(response.status).toBe(409);
    await response.text();
    await vi.waitFor(() =>
      expect(upstream.closed).toBeGreaterThan(before.closed),
    );

    const closeLogs = vi
      .mocked(logger.error)
      .mock.calls.slice(errorsBefore)
      .filter(([label]) =>
        String(label).includes("of a session that was not opened"),
      );
    expect(closeLogs.map(([label]) => label)).toEqual([
      "Error closing the server transport of a session that was not opened:",
    ]);
    const rendered = closeLogs
      .flat()
      .map((part) => (typeof part === "string" ? part : inspect(part)))
      .join(" ");
    expect(rendered).not.toContain("close failed");
    expect(rendered).not.toContain("vendor.example.test");
    expect(rendered).not.toContain(idInError);
  });
});

describe("an open that ends early", () => {
  it.each([
    ["POST /mcp", "mcp"],
    ["GET /sse", "sse"],
  ])(
    "%s: a request that disconnects while opening releases its open, and the transport that finishes afterwards closes unregistered",
    async (_label, route) => {
      const gate = deferred();
      upstream.startGate = gate.promise;
      const before = { ...upstream };
      const pendingBefore = inspectorOpensPending();
      const controller = new AbortController();

      const opening =
        route === "mcp"
          ? postMcp(USER_A, {
              query: byUuid(ROW_A),
              signal: controller.signal,
            })
          : fetch(
              `${baseUrl}/mcp-proxy/server/sse?${new URLSearchParams(byUuid(ROW_A))}`,
              {
                headers: { accept: "text/event-stream", ...userHeader(USER_A) },
                signal: controller.signal,
              },
            );
      await vi.waitFor(() => expect(upstream.started).toBe(before.started + 1));
      expect(inspectorOpensPending()).toBe(pendingBefore + 1);

      controller.abort();
      await expect(opening).rejects.toThrow();
      await vi.waitFor(() =>
        expect(inspectorOpensPending()).toBe(pendingBefore),
      );

      gate.resolve();
      await vi.waitFor(() =>
        expect(upstream.closed).toBeGreaterThan(before.closed),
      );
      await settle();
      expect(await closeInspectorSessionsForServer(ROW_A.uuid)).toBe(0);
    },
  );

  it("an open the resolver refuses releases its open", async () => {
    const pendingBefore = inspectorOpensPending();

    const refused = await postMcp(USER_A, {
      query: byUuid({ uuid: NEVER_ISSUED }),
    });

    expect(refused.status).toBe(400);
    await refused.text();
    expect(inspectorOpensPending()).toBe(pendingBefore);
  });

  it("an open whose transport fails to start releases its open", async () => {
    upstream.startGate = Promise.reject(new Error("upstream unavailable"));
    upstream.startGate.catch(() => undefined);
    const pendingBefore = inspectorOpensPending();

    const failed = await postMcp(USER_A, { query: byUuid(ROW_A) });

    expect(failed.status).toBe(500);
    await failed.text();
    expect(inspectorOpensPending()).toBe(pendingBefore);
  });
});
