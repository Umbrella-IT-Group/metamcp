/**
 * A backend that answers the handshake with HTTP 401/403 stops the connect
 * after one attempt and is named as a credentials rejection; a refusal of one
 * later POST over a live connection is an answer to one request, not a drop.
 *
 * Real SDK `Client` and `StreamableHTTPClientTransport` with a fake `fetch`
 * (the transport boundary), so the error shapes are the SDK's own. Oracles:
 * RFC 9110 sections 15.5.2 and 15.5.4; the SDK's transport error shapes
 * (client/streamableHttp.js, client/sse.js); and the connect loop's existing
 * contract that a 5xx retries `maxAttempts` times with backoff.
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { SseError } from "@modelcontextprotocol/sdk/client/sse.js";
import {
  StreamableHTTPClientTransport,
  StreamableHTTPError,
} from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { ServerParameters } from "@repo/zod-types";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../../db/repositories/index", () => ({
  mcpServersRepository: {},
}));
vi.mock("../../db/repositories/oauth-sessions.repo", () => ({
  oauthSessionsRepository: {},
}));
vi.mock("./server-error-tracker", () => ({
  serverErrorTracker: {
    getServerMaxAttempts: vi.fn().mockResolvedValue(3),
    isServerInErrorState: vi.fn().mockResolvedValue(false),
    recordServerCrash: vi.fn(),
    markSuccess: vi.fn(),
  },
}));

import { connectMetaMcpClient } from "./client";
import { metamcpLogStore } from "./log-store";
import { serverErrorTracker } from "./server-error-tracker";

const params = {
  uuid: "srv-1",
  name: "ninja",
  description: "",
  type: "STREAMABLE_HTTP",
  url: "http://backend.test/mcp",
  created_at: new Date().toISOString(),
  status: "active",
} as unknown as ServerParameters;

const BODY_SECRET = "backend-body-text-that-must-not-be-logged";

interface Backend {
  /** HTTP status for the initialize POST (200 = answer properly). */
  initialize: number;
  /** HTTP status for every later POST (tools/call). */
  call: number;
  posts: string[];
}

function backend(initial: Partial<Backend>): Backend {
  return { initialize: 200, call: 200, posts: [], ...initial };
}

/** The transport boundary: answers like an MCP server, or refuses. */
function fakeFetch(state: Backend): typeof fetch {
  return (async (_url: unknown, init?: RequestInit) => {
    const method = init?.method ?? "GET";
    if (method === "GET") return new Response(null, { status: 405 });
    if (method === "DELETE") return new Response(null, { status: 200 });
    const body = JSON.parse(String(init?.body)) as {
      id?: number;
      method: string;
    };
    state.posts.push(body.method);
    if (body.method === "initialize") {
      if (state.initialize !== 200) {
        return new Response(BODY_SECRET, { status: state.initialize });
      }
      return Response.json({
        jsonrpc: "2.0",
        id: body.id,
        result: {
          protocolVersion: "2025-06-18",
          capabilities: { tools: {} },
          serverInfo: { name: "fake", version: "1" },
        },
      });
    }
    if (body.method === "notifications/initialized") {
      return new Response(null, { status: 202 });
    }
    return new Response(BODY_SECRET, { status: state.call });
  }) as typeof fetch;
}

function connectWith(
  state: Backend,
  extra: {
    onTransportDrop?: (reason: "close" | "error", error?: Error) => void;
    onBackendAuthRejected?: (info: { status: 401 | 403 }) => void;
  } = {},
) {
  let transport: StreamableHTTPClientTransport | undefined;
  const createClient = vi.fn(() => {
    transport = new StreamableHTTPClientTransport(new URL(params.url ?? ""), {
      fetch: fakeFetch(state),
    });
    return {
      client: new Client({ name: "metamcp", version: "1.0.0" }),
      transport,
    };
  });
  const promise = connectMetaMcpClient(
    params,
    undefined,
    extra.onTransportDrop,
    {
      createClient: createClient as never,
      onBackendAuthRejected: extra.onBackendAuthRejected,
    },
  );
  return { promise, createClient, transport: () => transport };
}

let record: ReturnType<typeof vi.spyOn>;
const events = () =>
  record.mock.calls.map(
    ([entry]) => entry as { message: string; level: string; error?: unknown },
  );

beforeEach(() => {
  record = vi.spyOn(metamcpLogStore, "record").mockImplementation(() => {});
  vi.mocked(serverErrorTracker.recordServerCrash).mockClear();
});
afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe("connect-time HTTP 401/403", () => {
  it.each([
    [401, "the backend rejected the gateway's credentials (HTTP 401)"],
    [403, "the backend refused the gateway's access (HTTP 403)"],
  ] as const)(
    "makes one attempt with no backoff for %s, names it, and calls the hook",
    async (status, text) => {
      vi.useFakeTimers();
      const state = backend({ initialize: status });
      const hook = vi.fn();
      const attempt = connectWith(state, { onBackendAuthRejected: hook });

      // No timer is ever needed: the loop returns before its backoff sleep.
      const result = await attempt.promise;

      expect(result).toBeUndefined();
      expect(attempt.createClient).toHaveBeenCalledTimes(1);
      expect(vi.getTimerCount()).toBe(0);
      expect(hook).toHaveBeenCalledWith({ status });
      const failed = events().filter((e) =>
        e.message.startsWith("Connect attempt 1/3 failed"),
      );
      expect(failed).toHaveLength(1);
      expect(failed[0].message).toContain(text);
      expect(failed[0].level).toBe("error");
      // The backend's response text is not part of the event.
      expect(failed[0].error).toBeUndefined();
      expect(JSON.stringify(events())).not.toContain(BODY_SECRET);
      // A rejection is not a crash: the breaker is never fed.
      expect(serverErrorTracker.recordServerCrash).not.toHaveBeenCalled();
    },
  );

  it("still retries a 502 for every attempt (negative control)", async () => {
    vi.useFakeTimers();
    const state = backend({ initialize: 502 });
    const hook = vi.fn();
    const attempt = connectWith(state, { onBackendAuthRejected: hook });

    await vi.runAllTimersAsync();
    const result = await attempt.promise;

    expect(result).toBeUndefined();
    expect(attempt.createClient).toHaveBeenCalledTimes(3);
    expect(hook).not.toHaveBeenCalled();
  });
});

describe("a 401/403 answer to one POST over a live connection", () => {
  async function connected(state: Backend) {
    const onTransportDrop = vi.fn();
    const hook = vi.fn();
    const attempt = connectWith(state, {
      onTransportDrop,
      onBackendAuthRejected: hook,
    });
    const client = await attempt.promise;
    expect(client).toBeDefined();
    return { client, attempt, onTransportDrop, hook };
  }

  it.each([401, 403] as const)(
    "does not run the drop path for %s, sets no pool state, and announces it once",
    async (status) => {
      const state = backend({ call: status });
      const { client, onTransportDrop, hook } = await connected(state);

      for (let i = 0; i < 2; i += 1) {
        await expect(
          client?.client.callTool({ name: "t", arguments: {} }),
        ).rejects.toMatchObject({ code: status });
      }

      expect(onTransportDrop).not.toHaveBeenCalled();
      expect(hook).not.toHaveBeenCalled();
      const announced = events().filter((e) =>
        e.message.includes(`answered with HTTP ${status}`),
      );
      expect(announced).toHaveLength(1);
      expect(announced[0].level).toBe("warn");
      expect(announced[0].message).toContain("stays pooled");
      expect(announced[0].error).toBeUndefined();
      expect(JSON.stringify(events())).not.toContain(BODY_SECRET);
      await client?.cleanup();
    },
  );

  describe("narrowness: every other transport error still drops", () => {
    async function dropFor(error: Error) {
      const state = backend({});
      const { client, attempt, onTransportDrop } = await connected(state);
      attempt.transport()?.onerror?.(error);
      await client?.cleanup();
      return onTransportDrop;
    }

    it("a refused SSE stream (SseError 401) is a dead channel", async () => {
      const drop = await dropFor(
        new SseError(401, "Unauthorized", {} as never),
      );
      expect(drop).toHaveBeenCalledWith("error", expect.any(Error));
    });

    it("a refused stream open (Failed to open SSE stream, 403) is a dead channel", async () => {
      const drop = await dropFor(
        new StreamableHTTPError(403, "Failed to open SSE stream: Forbidden"),
      );
      expect(drop).toHaveBeenCalledWith("error", expect.any(Error));
    });

    it("an ordinary transport error still drops", async () => {
      const drop = await dropFor(new Error("terminated"));
      expect(drop).toHaveBeenCalledWith("error", expect.any(Error));
    });

    it("a 502 answer to a POST still drops", async () => {
      const drop = await dropFor(
        new StreamableHTTPError(502, "Error POSTing to endpoint: bad gateway"),
      );
      expect(drop).toHaveBeenCalledWith("error", expect.any(Error));
    });
  });
});
