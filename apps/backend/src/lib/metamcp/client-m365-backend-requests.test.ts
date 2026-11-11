/**
 * Replies to requests an m365-injected backend sends, through the production
 * wiring: `createMetaMcpClient` builds the real SDK Streamable-HTTP transport
 * with the real injected fetch over the pool's guarded fetch, and the backend
 * is a small stateful Streamable-HTTP server on 127.0.0.1. Only the mint
 * service is a stub, so nothing leaves the machine.
 *
 * What this pins. A pooled backend connection is opened inside whichever
 * request first needs it and then serves other callers (the pool's idle
 * hand-off). The SDK opens the standing GET stream from that opening scope and
 * answers the backend's requests on it (a ping, a method the client does not
 * support) from there, so a reply runs in the opening scope, not in the scope
 * of the caller whose tool call is in flight. A reply only completes a request
 * the backend correlates by id within its session; it is not a tool
 * invocation. So every reply leaves with no Graph token and no user id,
 * whoever opened the connection, and an opener whose token cannot be minted
 * does not hold the replies back. A caller's own tool call still carries
 * exactly that caller's token, and a caller with no delegated identity (a
 * plain API key) sends none.
 *
 * Every wait is bounded and keyed to an event the backend observed (the
 * standing stream opening, a reply arriving), never a fixed sleep.
 */
import type { IncomingMessage, Server, ServerResponse } from "node:http";
import { createServer } from "node:http";

import type { Client } from "@modelcontextprotocol/sdk/client/index.js";
import type { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { getAccessToken } = vi.hoisted(() => ({
  getAccessToken: vi.fn<(userId: string) => Promise<string>>(),
}));

// client.ts's module-load chain reaches db/index (which throws on a missing
// DATABASE_URL); stub it out, matching client-verified-caller.test.ts.
vi.mock("../../db/repositories/index", () => ({ mcpServersRepository: {} }));
vi.mock("../../db/repositories/oauth-sessions.repo", () => ({
  oauthSessionsRepository: {},
}));
vi.mock("../config.service", () => ({
  configService: { getMcpMaxAttempts: vi.fn().mockResolvedValue(1) },
}));
vi.mock("@/utils/logger", () => ({
  default: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));
// The only stub on the injection path: the injected fetch itself runs
// unchanged.
vi.mock("../m365/mint-service", () => ({
  m365MintService: { getAccessToken },
}));

import { M365BrokerError } from "../m365/errors";
import { runWithM365UserContext } from "../m365/request-context";
import { runWithCallerContext } from "./caller-context-store";
import { createMetaMcpClient } from "./client";

/** How long the backend waits for a reply before recording "no reply". */
const REPLY_WAIT_MS = 2_000;
/** Upper bound on any wait for a fixture event. */
const EVENT_WAIT_MS = 5_000;

const UNENROLLED = "user-unenrolled";

interface SeenRequest {
  httpMethod: string;
  sessionId: string | null;
  /** The JSON-RPC method, "reply" for a response, "" with no JSON body. */
  kind: string;
  id?: unknown;
  authorization: string | null;
  userId: string | null;
}

type JsonObject = Record<string, unknown>;
type Outcome = JsonObject | "no reply" | "no standing stream";

/** "result", "error <code>", or why there was nothing to read. */
function describeOutcome(outcome: Outcome): string {
  if (typeof outcome === "string") return outcome;
  if (Object.hasOwn(outcome, "result")) return "result";
  return `error ${String((outcome.error as JsonObject | undefined)?.code)}`;
}

/** Reject if `promise` has not settled within the event bound. */
async function within<T>(promise: Promise<T>, what: string): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  const bound = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(
      () => reject(new Error(`timed out waiting for ${what}`)),
      EVENT_WAIT_MS,
    );
  });
  try {
    return await Promise.race([promise, bound]);
  } finally {
    clearTimeout(timer);
  }
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

function writeEvent(res: ServerResponse, message: JsonObject): void {
  res.write(`event: message\ndata: ${JSON.stringify(message)}\n\n`);
}

function respondJson(
  res: ServerResponse,
  message: JsonObject,
  headers: Record<string, string> = {},
): void {
  res.writeHead(200, { "content-type": "application/json", ...headers });
  res.end(JSON.stringify(message));
}

/**
 * A stateful Streamable-HTTP MCP backend that records the identity headers of
 * every request and can send requests to the client: on a session's standing
 * GET stream, or on the response stream of the tool call that asked for it.
 */
function createBackend() {
  const seen: SeenRequest[] = [];
  const sessions = new Set<string>();
  const streams = new Map<string, ServerResponse>();
  const streamWaiters = new Map<string, Array<() => void>>();
  const replyWaiters = new Map<string, (message: JsonObject) => void>();
  const timers = new Set<NodeJS.Timeout>();
  let sessionCount = 0;

  /** Wait (bounded by REPLY_WAIT_MS) for the client's reply to `id`. */
  function awaitReply(sessionId: string, id: string): Promise<Outcome> {
    const key = `${sessionId} ${id}`;
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        timers.delete(timer);
        replyWaiters.delete(key);
        resolve("no reply");
      }, REPLY_WAIT_MS);
      timers.add(timer);
      replyWaiters.set(key, (message) => {
        clearTimeout(timer);
        timers.delete(timer);
        replyWaiters.delete(key);
        resolve(message);
      });
    });
  }

  /** Send a request to the client on the session's standing GET stream. */
  function requestOnStream(
    sessionId: string,
    request: { id: string; method: string; params?: JsonObject },
  ): Promise<Outcome> {
    const stream = streams.get(sessionId);
    if (!stream) return Promise.resolve("no standing stream");
    const replied = awaitReply(sessionId, request.id);
    writeEvent(stream, { jsonrpc: "2.0", ...request });
    return replied;
  }

  /** Resolves once the session's standing GET stream is open. */
  function streamOpen(sessionId: string): Promise<void> {
    if (streams.has(sessionId)) return Promise.resolve();
    return new Promise((resolve) => {
      streamWaiters.set(sessionId, [
        ...(streamWaiters.get(sessionId) ?? []),
        resolve,
      ]);
    });
  }

  async function toolCall(
    res: ServerResponse,
    sessionId: string,
    message: JsonObject,
  ): Promise<void> {
    const params = message.params as
      | { name?: string; arguments?: { tag?: string } }
      | undefined;
    const tag = params?.arguments?.tag ?? "untagged";
    const result = (text: string) => ({
      jsonrpc: "2.0",
      id: message.id,
      result: { content: [{ type: "text", text }] },
    });

    if (params?.name === "ask-on-stream") {
      // A ping and a request the client has no handler for, on the standing
      // stream, while this call is held open.
      const [ping, unsupported] = await Promise.all([
        requestOnStream(sessionId, { id: `ping-${tag}`, method: "ping" }),
        requestOnStream(sessionId, {
          id: `ask-${tag}`,
          method: "elicitation/create",
          params: {
            message: "Proceed?",
            requestedSchema: { type: "object", properties: {} },
          },
        }),
      ]);
      respondJson(
        res,
        result(
          `ping: ${describeOutcome(ping)}; elicitation/create: ${describeOutcome(unsupported)}`,
        ),
      );
      return;
    }

    if (params?.name === "ask-on-response") {
      // A ping on this call's own response stream, related to the call.
      res.writeHead(200, { "content-type": "text/event-stream" });
      const replied = awaitReply(sessionId, `related-${tag}`);
      writeEvent(res, { jsonrpc: "2.0", id: `related-${tag}`, method: "ping" });
      writeEvent(res, result(`ping: ${describeOutcome(await replied)}`));
      res.end();
      return;
    }

    respondJson(res, result("ok"));
  }

  async function handle(req: IncomingMessage, res: ServerResponse) {
    const httpMethod = (req.method ?? "GET").toUpperCase();
    const sessionHeader = req.headers["mcp-session-id"];
    const sessionId = typeof sessionHeader === "string" ? sessionHeader : null;
    const body = await readBody(req);
    let message: JsonObject | undefined;
    try {
      message = body ? (JSON.parse(body) as JsonObject) : undefined;
    } catch {
      message = undefined;
    }
    const kind =
      message === undefined
        ? ""
        : typeof message.method === "string"
          ? message.method
          : "reply";
    seen.push({
      httpMethod,
      sessionId,
      kind,
      id: message?.id,
      authorization: req.headers.authorization ?? null,
      userId: (req.headers["x-umbrella-user-id"] as string | undefined) ?? null,
    });

    if (httpMethod === "GET") {
      if (!sessionId || !sessions.has(sessionId)) {
        res.writeHead(400).end();
        return;
      }
      res.writeHead(200, {
        "content-type": "text/event-stream",
        "cache-control": "no-cache",
      });
      res.flushHeaders();
      streams.set(sessionId, res);
      res.on("close", () => {
        if (streams.get(sessionId) === res) streams.delete(sessionId);
      });
      for (const resolve of streamWaiters.get(sessionId) ?? []) resolve();
      streamWaiters.delete(sessionId);
      return;
    }
    if (httpMethod === "DELETE") {
      if (sessionId) sessions.delete(sessionId);
      res.writeHead(200).end();
      return;
    }
    if (httpMethod !== "POST" || !message || Array.isArray(message)) {
      res.writeHead(400).end();
      return;
    }

    if (kind === "initialize") {
      const id = `backend-session-${++sessionCount}`;
      sessions.add(id);
      const params = message.params as { protocolVersion?: string };
      respondJson(
        res,
        {
          jsonrpc: "2.0",
          id: message.id,
          result: {
            protocolVersion: params.protocolVersion,
            capabilities: { tools: {} },
            serverInfo: { name: "m365", version: "1.0.0" },
          },
        },
        { "mcp-session-id": id },
      );
      return;
    }
    if (!sessionId || !sessions.has(sessionId)) {
      res.writeHead(404).end();
      return;
    }
    if (kind === "reply") {
      replyWaiters.get(`${sessionId} ${String(message.id)}`)?.(message);
      res.writeHead(202).end();
      return;
    }
    if (kind.startsWith("notifications/")) {
      res.writeHead(202).end();
      return;
    }
    if (kind === "tools/list") {
      respondJson(res, {
        jsonrpc: "2.0",
        id: message.id,
        result: {
          tools: ["ask-on-stream", "ask-on-response", "echo"].map((name) => ({
            name,
            inputSchema: { type: "object", properties: {} },
          })),
        },
      });
      return;
    }
    if (kind === "tools/call") {
      await toolCall(res, sessionId, message);
      return;
    }
    respondJson(res, { jsonrpc: "2.0", id: message.id, result: {} });
  }

  const server: Server = createServer((req, res) => {
    handle(req, res).catch((error: unknown) => {
      res.destroy(error instanceof Error ? error : new Error(String(error)));
    });
  });

  return {
    seen,
    requestOnStream,
    streamOpen,
    listen: () =>
      new Promise<string>((resolve) => {
        server.listen(0, "127.0.0.1", () => {
          const address = server.address();
          if (!address || typeof address === "string") {
            throw new Error("backend has no port");
          }
          resolve(`http://127.0.0.1:${address.port}/mcp`);
        });
      }),
    close: () =>
      new Promise<void>((resolve) => {
        for (const timer of timers) clearTimeout(timer);
        timers.clear();
        for (const stream of streams.values()) stream.end();
        streams.clear();
        server.close(() => resolve());
        server.closeAllConnections();
      }),
  };
}

const ENV_KEYS = [
  "M365_INJECTED_SERVER_NAMES",
  "VERIFIED_CALLER_SERVER_NAMES",
  "TRANSFORM_LOCALHOST_TO_DOCKER_INTERNAL",
] as const;
const savedEnv: Record<string, string | undefined> = {};

let backend: ReturnType<typeof createBackend>;
let backendUrl: string;
const clients: Client[] = [];

const textOf = (result: unknown): string =>
  ((result as { content?: Array<{ text?: string }> }).content?.[0]?.text ??
    "") as string;

/**
 * Open the m365 connection inside `userId`'s scope (no scope when undefined),
 * the way the pool opens one inside the request that first needs it, and wait
 * for its standing GET stream.
 */
async function connectAs(
  userId: string | undefined,
): Promise<{ client: Client; sessionId: string }> {
  const { client, transport } = createMetaMcpClient({
    uuid: "srv-m365",
    name: "m365",
    description: "",
    status: "active",
    created_at: new Date().toISOString(),
    type: "STREAMABLE_HTTP",
    url: backendUrl,
  } as never);
  if (!client || !transport) throw new Error("no client built");
  clients.push(client);
  await runWithM365UserContext(userId ? { userId } : undefined, () =>
    client.connect(transport),
  );
  const sessionId = (transport as StreamableHTTPClientTransport).sessionId;
  if (!sessionId) throw new Error("the backend issued no session");
  await within(backend.streamOpen(sessionId), "the standing GET stream");
  return { client, sessionId };
}

const replies = () => backend.seen.filter((r) => r.kind === "reply");
const toolCalls = () => backend.seen.filter((r) => r.kind === "tools/call");

function expectTokenFree(requests: SeenRequest[], sessionId: string) {
  for (const request of requests) {
    expect(request).toMatchObject({
      sessionId,
      authorization: null,
      userId: null,
    });
  }
}

beforeEach(async () => {
  for (const key of ENV_KEYS) savedEnv[key] = process.env[key];
  for (const key of ENV_KEYS) delete process.env[key];
  getAccessToken.mockReset();
  getAccessToken.mockImplementation(async (userId: string) => {
    if (userId === UNENROLLED) {
      throw new M365BrokerError(
        "credential_missing",
        "No Microsoft 365 account is connected for your user yet.",
        "https://mcp.example.com/m365/enroll",
      );
    }
    return `graph-${userId}`;
  });
  backend = createBackend();
  backendUrl = await backend.listen();
});

afterEach(async () => {
  for (const client of clients.splice(0)) await client.close();
  await backend.close();
  for (const key of ENV_KEYS) {
    if (savedEnv[key] === undefined) delete process.env[key];
    else process.env[key] = savedEnv[key];
  }
});

// A missing reply costs one REPLY_WAIT_MS per wait; the bound keeps a
// regression a readable assertion failure rather than a test timeout.
describe(
  "m365 replies to backend requests carry no user token",
  {
    timeout: 15_000,
  },
  () => {
    it("answers a ping and an unsupported request on the standing stream with no token while a tool call is in flight on a handed-off connection, and that call completes", async () => {
      const { client, sessionId } = await connectAs("user-a");

      const result = await runWithM365UserContext({ userId: "user-b" }, () =>
        client.callTool({ name: "ask-on-stream", arguments: { tag: "b" } }),
      );

      // The backend only sends its requests on a stream it holds open for the
      // call's own session, so this text also proves user-b's call used the
      // connection opened in user-a's scope.
      expect(textOf(result)).toBe(
        "ping: result; elicitation/create: error -32601",
      );
      expect(backend.seen.filter((r) => r.kind === "initialize")).toHaveLength(
        1,
      );
      expect(toolCalls()).toEqual([
        expect.objectContaining({
          sessionId,
          authorization: "Bearer graph-user-b",
          userId: "user-b",
        }),
      ]);
      expect(replies().map((r) => r.id)).toEqual(
        expect.arrayContaining(["ping-b", "ask-b"]),
      );
      expect(replies()).toHaveLength(2);
      expectTokenFree(replies(), sessionId);
      // One mint, for the tool call; none for either reply.
      expect(getAccessToken.mock.calls).toEqual([["user-b"]]);
    });

    it("answers a ping with no call in flight with no token", async () => {
      const { sessionId } = await connectAs("user-a");

      const outcome = await backend.requestOnStream(sessionId, {
        id: "idle-ping",
        method: "ping",
      });

      expect(describeOutcome(outcome)).toBe("result");
      expect(replies()).toEqual([expect.objectContaining({ id: "idle-ping" })]);
      expectTokenFree(replies(), sessionId);
      expect(getAccessToken).not.toHaveBeenCalled();
    });

    it("answers a request on a tool call's own response stream with no token", async () => {
      const { client, sessionId } = await connectAs("user-a");

      const result = await runWithM365UserContext({ userId: "user-b" }, () =>
        client.callTool({ name: "ask-on-response", arguments: { tag: "b" } }),
      );

      expect(textOf(result)).toBe("ping: result");
      expect(toolCalls()).toEqual([
        expect.objectContaining({
          sessionId,
          authorization: "Bearer graph-user-b",
          userId: "user-b",
        }),
      ]);
      expect(replies()).toEqual([expect.objectContaining({ id: "related-b" })]);
      expectTokenFree(replies(), sessionId);
      expect(getAccessToken.mock.calls).toEqual([["user-b"]]);
    });

    it("a connection opened by a user whose token cannot be minted still answers the backend, and the next user's call completes", async () => {
      const { client, sessionId } = await connectAs(UNENROLLED);

      const idle = await backend.requestOnStream(sessionId, {
        id: "idle-ping",
        method: "ping",
      });
      await runWithM365UserContext({ userId: "user-a" }, () =>
        client.listTools(),
      );
      const result = await runWithM365UserContext({ userId: "user-a" }, () =>
        client.callTool({ name: "ask-on-stream", arguments: { tag: "a" } }),
      );

      expect(describeOutcome(idle)).toBe("result");
      expect(textOf(result)).toBe(
        "ping: result; elicitation/create: error -32601",
      );
      expect(toolCalls()).toEqual([
        expect.objectContaining({
          sessionId,
          authorization: "Bearer graph-user-a",
          userId: "user-a",
        }),
      ]);
      expect(replies()).toHaveLength(3);
      expectTokenFree(replies(), sessionId);
      // The opener's grant is never consulted for traffic it did not send.
      expect(getAccessToken.mock.calls).toEqual([["user-a"]]);
    });

    it("a plain API-key caller's tool call, and the replies sent during it, carry no token", async () => {
      const { client, sessionId } = await connectAs("user-a");

      // A plain API key binds a caller but no delegated m365 identity.
      const result = await runWithCallerContext(
        { authMethod: "api_key", apiKeyUuid: "key-1", userId: "user-key" },
        () =>
          client.callTool({ name: "ask-on-stream", arguments: { tag: "k" } }),
      );

      expect(textOf(result)).toBe(
        "ping: result; elicitation/create: error -32601",
      );
      expectTokenFree(toolCalls(), sessionId);
      expect(replies()).toHaveLength(2);
      expectTokenFree(replies(), sessionId);
      expect(getAccessToken).not.toHaveBeenCalled();
    });
  },
);
