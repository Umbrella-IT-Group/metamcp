/**
 * Sessions on the Inspector's namespace routes (`/mcp-proxy/metamcp/:uuid`)
 * belong to the signed-in user who opened them.
 *
 *  - The opener's later requests are served, on a Streamable HTTP session and
 *    on an SSE session.
 *  - Any other request naming the session (another user, or no user) gets the
 *    answer a session id that was never issued gets on that route, and reaches
 *    nothing. DELETE keeps its existing answers: 200 for any id, cleaning up
 *    only the opener's session, and 400 without an id.
 *  - Cleanup forgets the session first and runs every phase even when an
 *    earlier one fails.
 *
 * Driven over a real socket through the real router, real SDK transports, a
 * real SDK `Server` and the real session registry; only the namespace server
 * factory, the connection pool and the database are faked (the harness of
 * metamcp.session-close.test.ts). The signed-in user is chosen per request by
 * an `x-test-user` header; no header means no user.
 */
import type { Server as HttpServer } from "node:http";

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import { ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
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

const { created, behaviour } = vi.hoisted(() => ({
  /** Each namespace server the route creates, in order. */
  created: [] as {
    cleanup: ReturnType<typeof vi.fn>;
    toolListings: number;
  }[],
  /** Failures the next created server's cleanup phases produce. */
  behaviour: {
    failTransportClose: false,
    failServerCleanup: false,
    /** When set, the server cleanup waits for it. */
    cleanupGate: undefined as Promise<void> | undefined,
  },
}));

vi.mock("../../lib/metamcp/index", () => ({
  createServer: vi.fn(async () => {
    const record = {
      cleanup: vi.fn(async () => {
        if (behaviour.cleanupGate) await behaviour.cleanupGate;
        if (behaviour.failServerCleanup) {
          throw new Error("server cleanup failed");
        }
      }),
      toolListings: 0,
    };
    const real = new Server(
      { name: "session-owner-namespace", version: "0.0.0" },
      { capabilities: { tools: {} } },
    );
    // Counts what reached the namespace server, so a refused request can be
    // shown to have reached nothing.
    real.setRequestHandler(ListToolsRequestSchema, async () => {
      record.toolListings += 1;
      return { tools: [] };
    });
    const failClose = behaviour.failTransportClose;
    const server = {
      connect: async (transport: Transport) => {
        if (failClose) {
          const close = transport.close.bind(transport);
          transport.close = async () => {
            await close();
            throw new Error("transport close failed");
          };
        }
        await real.connect(transport);
      },
    };
    created.push(record);
    return { server, cleanup: record.cleanup };
  }),
}));
vi.mock("../../lib/metamcp/mcp-server-pool", () => ({
  mcpServerPool: { cleanupSession: vi.fn().mockResolvedValue(undefined) },
}));

import { createServer } from "../../lib/metamcp/index";
import { inspectorSessionBelongsToCaller } from "../../lib/metamcp/inspector-sessions";
import { mcpServerPool } from "../../lib/metamcp/mcp-server-pool";
import metamcpRouter from "./metamcp";

const PROTOCOL_VERSION = "2025-06-18";
const NAMESPACE_UUID = "dddddddd-4444-4444-8444-dddddddddddd";
const BASE = `/mcp-proxy/metamcp/${NAMESPACE_UUID}`;
const USER_A = "user-a";
const USER_B = "user-b";
const NEVER_ISSUED = "00000000-0000-4000-8000-000000000000";

let httpServer: HttpServer;
let baseUrl = "";
let rpcId = 0;

const rpc = (method: string, params: Record<string, unknown> = {}) =>
  JSON.stringify({ jsonrpc: "2.0", id: (rpcId += 1), method, params });

const userHeader = (user: string | null): Record<string, string> =>
  user ? { "x-test-user": user } : {};

function send(
  method: "GET" | "POST" | "DELETE",
  user: string | null,
  sessionId?: string,
  body?: string,
  signal?: AbortSignal,
): Promise<Response> {
  return fetch(`${baseUrl}${BASE}/mcp`, {
    method,
    headers: {
      "content-type": "application/json",
      accept:
        method === "GET"
          ? "text/event-stream"
          : "application/json, text/event-stream",
      ...userHeader(user),
      ...(sessionId
        ? {
            "mcp-session-id": sessionId,
            "mcp-protocol-version": PROTOCOL_VERSION,
          }
        : {}),
    },
    body,
    signal,
  });
}

/** Status, content type and body, with the request's own echoed id masked. */
async function answerOf(response: Response, sessionId: string) {
  return {
    status: response.status,
    type: response.headers.get("content-type"),
    body: (await response.text()).replaceAll(sessionId, "<id>"),
  };
}

const listTools = (user: string | null, sessionId: string) =>
  send("POST", user, sessionId, rpc("tools/list"));

/** GET on a session. A served stream stays open, so it is cut here. */
async function getStream(user: string | null, sessionId: string) {
  const controller = new AbortController();
  const response = await send(
    "GET",
    user,
    sessionId,
    undefined,
    controller.signal,
  );
  const answer =
    response.status === 200
      ? { status: 200, type: response.headers.get("content-type"), body: "" }
      : await answerOf(response, sessionId);
  controller.abort();
  return answer;
}

async function initialize(user: string): Promise<string> {
  const response = await send(
    "POST",
    user,
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

/** GET /:uuid/sse: the open stream and the session id its endpoint names. */
async function openSse(user: string) {
  const controller = new AbortController();
  const response = await fetch(`${baseUrl}${BASE}/sse`, {
    headers: { accept: "text/event-stream", ...userHeader(user) },
    signal: controller.signal,
  });
  expect(response.status).toBe(200);
  const reader = (response.body as ReadableStream<Uint8Array>).getReader();
  const decoder = new TextDecoder();
  let text = "";
  while (!text.includes("event: endpoint")) {
    const { value, done } = await reader.read();
    if (done) break;
    text += decoder.decode(value, { stream: true });
  }
  const endpoint = /event: endpoint\ndata: (.+)\n/.exec(text)?.[1] ?? "";
  const sessionId = new URL(endpoint, baseUrl).searchParams.get("sessionId");
  expect(sessionId).toBeTruthy();
  return { controller, sessionId: sessionId as string };
}

const postMessage = (user: string | null, sessionId: string) =>
  fetch(`${baseUrl}${BASE}/message?${new URLSearchParams({ sessionId })}`, {
    method: "POST",
    headers: { "content-type": "application/json", ...userHeader(user) },
    body: rpc("tools/list"),
  });

/** Let a close or cleanup queued behind a finished response run. */
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
  behaviour.failTransportClose = false;
  behaviour.failServerCleanup = false;
  behaviour.cleanupGate = undefined;
  vi.mocked(createServer).mockClear();
  vi.mocked(mcpServerPool.cleanupSession).mockClear();
});

describe("namespace Streamable HTTP session: who it answers", () => {
  it("serves the opener's later POST and GET requests", async () => {
    const sessionId = await initialize(USER_A);

    const listed = await listTools(USER_A, sessionId);
    expect(listed.status).toBe(200);
    await listed.text();
    expect(created[0].toolListings).toBe(1);
    expect((await getStream(USER_A, sessionId)).status).toBe(200);
  });

  it("answers another user's POST like a never-issued id and reaches nothing", async () => {
    const sessionId = await initialize(USER_A);

    const foreign = await answerOf(
      await listTools(USER_B, sessionId),
      sessionId,
    );
    const unknown = await answerOf(
      await listTools(USER_B, NEVER_ISSUED),
      NEVER_ISSUED,
    );

    expect(foreign.status).toBe(404);
    expect(foreign).toEqual(unknown);
    expect(created[0].toolListings).toBe(0);
  });

  it("answers another user's GET like a never-issued id", async () => {
    const sessionId = await initialize(USER_A);

    const foreign = await getStream(USER_B, sessionId);

    expect(foreign.status).toBe(404);
    expect(foreign).toEqual(await getStream(USER_B, NEVER_ISSUED));
  });

  it("answers another user's DELETE with 200 like a never-issued id, cleans up nothing, and the session keeps working", async () => {
    const sessionId = await initialize(USER_A);

    const foreign = await answerOf(
      await send("DELETE", USER_B, sessionId),
      sessionId,
    );
    const unknown = await answerOf(
      await send("DELETE", USER_B, NEVER_ISSUED),
      NEVER_ISSUED,
    );
    expect(foreign.status).toBe(200);
    expect(foreign).toEqual(unknown);
    await settle();
    expect(created[0].cleanup).not.toHaveBeenCalled();
    expect(mcpServerPool.cleanupSession).not.toHaveBeenCalledWith(sessionId);

    const listed = await listTools(USER_A, sessionId);
    expect(listed.status).toBe(200);
    await listed.text();
  });

  it("the opener's DELETE releases the session", async () => {
    const sessionId = await initialize(USER_A);

    const deleted = await send("DELETE", USER_A, sessionId);

    expect(deleted.status).toBe(200);
    expect(created[0].cleanup).toHaveBeenCalledTimes(1);
    expect(mcpServerPool.cleanupSession).toHaveBeenCalledWith(sessionId);
    expect(
      inspectorSessionBelongsToCaller(sessionId, {
        user: { id: USER_A },
      } as never),
    ).toBe(false);
    const after = await listTools(USER_A, sessionId);
    expect(after.status).toBe(404);
    await after.text();
  });

  it("keeps the 400 for a DELETE without a session id", async () => {
    const response = await send("DELETE", USER_A);

    expect(response.status).toBe(400);
    expect(await response.text()).toBe("Missing sessionId");
  });

  it("answers a request with no signed-in user like a never-issued id", async () => {
    const sessionId = await initialize(USER_A);

    const posted = await answerOf(await listTools(null, sessionId), sessionId);
    expect(posted.status).toBe(404);
    expect(posted).toEqual(
      await answerOf(await listTools(null, NEVER_ISSUED), NEVER_ISSUED),
    );
    const got = await getStream(null, sessionId);
    expect(got.status).toBe(404);
    expect(got).toEqual(await getStream(null, NEVER_ISSUED));
    const deleted = await answerOf(
      await send("DELETE", null, sessionId),
      sessionId,
    );
    expect(deleted).toEqual(
      await answerOf(await send("DELETE", null, NEVER_ISSUED), NEVER_ISSUED),
    );
    await settle();
    expect(created[0].cleanup).not.toHaveBeenCalled();
    expect(created[0].toolListings).toBe(0);

    const listed = await listTools(USER_A, sessionId);
    expect(listed.status).toBe(200);
    await listed.text();
  });

  it("keeps two users' sessions apart", async () => {
    const sessionA = await initialize(USER_A);
    const sessionB = await initialize(USER_B);

    for (const [user, sessionId, status] of [
      [USER_A, sessionA, 200],
      [USER_B, sessionB, 200],
      [USER_A, sessionB, 404],
      [USER_B, sessionA, 404],
    ] as const) {
      const response = await listTools(user, sessionId);
      expect(response.status).toBe(status);
      await response.text();
    }
  });
});

describe("namespace SSE session: who it answers", () => {
  it("accepts the opener's messages and answers another user's like a never-issued id", async () => {
    const { controller, sessionId } = await openSse(USER_A);
    try {
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
      expect(created[0].toolListings).toBe(0);

      const own = await postMessage(USER_A, sessionId);
      expect(own.status).toBe(202);
      await own.text();
      await vi.waitFor(() => expect(created[0].toolListings).toBe(1));
    } finally {
      controller.abort();
    }
  });
});

describe("namespace session cleanup", () => {
  it("forgets the session and stops routing to it before its cleanup finishes", async () => {
    const sessionId = await initialize(USER_A);
    let release: () => void = () => {};
    behaviour.cleanupGate = new Promise<void>((resolve) => {
      release = resolve;
    });

    const deleting = send("DELETE", USER_A, sessionId);
    await vi.waitFor(() => expect(created[0].cleanup).toHaveBeenCalled());

    expect(
      inspectorSessionBelongsToCaller(sessionId, {
        user: { id: USER_A },
      } as never),
    ).toBe(false);
    const listed = await listTools(USER_A, sessionId);
    expect(listed.status).toBe(404);
    await listed.text();

    release();
    expect((await deleting).status).toBe(200);
  });

  it.each([
    ["closing the transport", "failTransportClose"],
    ["cleaning up the server", "failServerCleanup"],
  ] as const)(
    "forgets the session and runs the remaining phases when %s fails",
    async (_label, failure) => {
      behaviour[failure] = true;
      const sessionId = await initialize(USER_A);

      const deleted = await send("DELETE", USER_A, sessionId);
      await deleted.text();

      expect(created[0].cleanup).toHaveBeenCalledTimes(1);
      expect(mcpServerPool.cleanupSession).toHaveBeenCalledWith(sessionId);
      expect(
        inspectorSessionBelongsToCaller(sessionId, {
          user: { id: USER_A },
        } as never),
      ).toBe(false);
      const after = await listTools(USER_A, sessionId);
      expect(after.status).toBe(404);
      await after.text();
    },
  );
});
