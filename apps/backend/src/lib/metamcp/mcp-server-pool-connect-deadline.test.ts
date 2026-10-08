/**
 * Pool-level regression for the transport start deadline
 * (`TRANSPORT_START_TIMEOUT_MS` in client.ts), driven through the real
 * connect path: pool admission, `connectMetaMcpClient`, `createMetaMcpClient`,
 * and the installed SDK's `Client`, `SSEClientTransport` and
 * `StreamableHTTPClientTransport`. Only the guarded fetch is replaced, by
 * three fake backends:
 *
 * - `hung` (SSE) answers the stream GET with 200 `text/event-stream`, then
 *   sends heartbeat comments and never its `endpoint` event. SDK start waits
 *   for that event before `initialize` (and its timeout) begins, so without
 *   the deadline this connect never settled and held a per-server and a
 *   global reservation indefinitely, out of reach of eviction.
 * - `slow` (SSE) is a working backend whose `endpoint` event and `initialize`
 *   answer arrive after delays the test sets.
 * - `stream` (Streamable HTTP) allocates a backend session in its
 *   `initialize` answer (the `mcp-session-id` header) and answers the
 *   initialized notification after a delay the test sets, or never. It
 *   counts the sessions it hands out and the session DELETEs it receives,
 *   which is how a session leaked by a closed transport shows up.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const backends = vi.hoisted(() => {
  type Stream = { url: string; signal: AbortSignal; aborted: boolean };
  const streams: Stream[] = [];
  const sinks = new Map<string, ReadableStreamDefaultController<Uint8Array>>();
  const encoder = new TextEncoder();
  const state = {
    // SSE `slow` backend.
    endpointDelayMs: 0,
    initializeDelayMs: 0,
    // Streamable HTTP `stream` backend; null means the initialized
    // notification is never answered.
    httpInitializeDelayMs: 0,
    httpInitializedDelayMs: 0 as number | null,
  };
  const http = {
    sessionsCreated: [] as string[],
    sessionsDeleted: [] as string[],
    initializedPosts: [] as { session: string | null; signal: AbortSignal }[],
  };

  const openStream = (url: URL, signal: AbortSignal): Response => {
    const stream: Stream = { url: url.pathname, signal, aborted: false };
    streams.push(stream);
    const session = String(streams.length);
    let heartbeat: ReturnType<typeof setInterval> | undefined;
    let endpoint: ReturnType<typeof setTimeout> | undefined;
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        signal.addEventListener(
          "abort",
          () => {
            clearInterval(heartbeat);
            clearTimeout(endpoint);
            // A reply due on a closed stream is dropped, as a real
            // server's write to a closed socket would be.
            sinks.delete(session);
            stream.aborted = true;
            controller.error(signal.reason);
          },
          { once: true },
        );
        if (url.pathname === "/slow/sse") {
          sinks.set(session, controller);
          endpoint = setTimeout(
            () =>
              controller.enqueue(
                encoder.encode(
                  `event: endpoint\ndata: /slow/messages?session=${session}\n\n`,
                ),
              ),
            state.endpointDelayMs,
          );
        } else {
          heartbeat = setInterval(
            () => controller.enqueue(encoder.encode(": heartbeat\n\n")),
            15_000,
          );
        }
      },
    });
    return new Response(body, {
      status: 200,
      headers: { "content-type": "text/event-stream" },
    });
  };

  /** Answer after `delayMs` (never when null) unless the request aborts. */
  const answerAfter = (
    signal: AbortSignal | undefined,
    delayMs: number | null,
    answer: () => Response,
  ): Promise<Response> =>
    new Promise((resolve, reject) => {
      const timer =
        delayMs === null
          ? undefined
          : setTimeout(() => resolve(answer()), delayMs);
      signal?.addEventListener(
        "abort",
        () => {
          clearTimeout(timer);
          reject(signal.reason);
        },
        { once: true },
      );
    });

  const streamableFetch = async (
    init: RequestInit,
    method: string,
  ): Promise<Response> => {
    const signal = init.signal ?? undefined;
    const session = new Headers(init.headers).get("mcp-session-id");
    if (method === "GET") {
      // No standalone server-to-client stream; the SDK treats 405 as that.
      return new Response(null, { status: 405 });
    }
    if (method === "DELETE") {
      http.sessionsDeleted.push(session ?? "");
      return new Response(null, { status: 200 });
    }
    const message = JSON.parse(String(init.body)) as {
      id?: number;
      method: string;
      params?: { protocolVersion?: string };
    };
    if (message.method === "initialize") {
      return answerAfter(signal, state.httpInitializeDelayMs, () => {
        // The session exists from the moment the backend answers.
        const id = `http-session-${http.sessionsCreated.length + 1}`;
        http.sessionsCreated.push(id);
        const reply = {
          jsonrpc: "2.0",
          id: message.id,
          result: {
            protocolVersion: message.params?.protocolVersion,
            capabilities: { tools: {} },
            serverInfo: { name: "stream", version: "1.0.0" },
          },
        };
        return new Response(JSON.stringify(reply), {
          status: 200,
          headers: {
            "content-type": "application/json",
            "mcp-session-id": id,
          },
        });
      });
    }
    if (message.method === "notifications/initialized") {
      if (signal) http.initializedPosts.push({ session, signal });
      return answerAfter(
        signal,
        state.httpInitializedDelayMs,
        () => new Response(null, { status: 202 }),
      );
    }
    return new Response(null, { status: 202 });
  };

  const fetch = async (
    input: string | URL,
    init: RequestInit = {},
  ): Promise<Response> => {
    const url = new URL(String(input));
    const method = init.method ?? "GET";
    if (url.pathname.startsWith("/stream/")) {
      return streamableFetch(init, method);
    }
    if (method === "GET") {
      return openStream(url, init.signal as AbortSignal);
    }
    // SSE POST back-channel; only the slow backend ever advertises one.
    const message = JSON.parse(String(init.body)) as {
      id?: number;
      method: string;
      params?: { protocolVersion?: string };
    };
    if (message.method === "initialize") {
      const session = url.searchParams.get("session") ?? "";
      const reply = {
        jsonrpc: "2.0",
        id: message.id,
        result: {
          protocolVersion: message.params?.protocolVersion,
          capabilities: { tools: {} },
          serverInfo: { name: "slow", version: "1.0.0" },
        },
      };
      setTimeout(
        () =>
          sinks
            .get(session)
            ?.enqueue(
              encoder.encode(
                `event: message\ndata: ${JSON.stringify(reply)}\n\n`,
              ),
            ),
        state.initializeDelayMs,
      );
    }
    return new Response(null, { status: 202 });
  };

  return { fetch, streams, sinks, state, http };
});

vi.mock("./url-guard", async (importOriginal) => ({
  ...(await importOriginal<typeof import("./url-guard")>()),
  createGuardedFetch: () => backends.fetch,
}));
vi.mock("../config.service", () => ({
  configService: {
    getSessionLifetime: vi.fn().mockResolvedValue(null),
  },
}));
vi.mock("../../db/repositories/index", () => ({
  mcpServersRepository: {},
}));
vi.mock("../../db/repositories/mcp-servers.repo", () => ({
  mcpServersRepository: {},
}));
vi.mock("../../db/repositories/oauth-sessions.repo", () => ({
  oauthSessionsRepository: {},
}));
vi.mock("./server-error-tracker", () => ({
  serverErrorTracker: {
    // The production default (MCP_MAX_ATTEMPTS), so the retry loop is real.
    getServerMaxAttempts: vi.fn().mockResolvedValue(3),
    isServerInErrorState: vi.fn().mockResolvedValue(false),
    recordServerCrash: vi.fn(),
    resetServerAttempts: vi.fn(),
    markSuccess: vi.fn(),
    getServerAttempts: vi.fn().mockReturnValue(0),
    resetServerErrorState: vi.fn().mockResolvedValue(undefined),
  },
}));

import type { ServerParameters } from "@repo/zod-types";

import logger from "@/utils/logger";

import { TRANSPORT_START_TIMEOUT_MS } from "./client";
import { metamcpLogStore } from "./log-store";
import {
  McpServerPool,
  SHUTDOWN_PENDING_CONNECT_WAIT_MS,
} from "./mcp-server-pool";

const PoolConstructor = McpServerPool as unknown as new (
  defaultIdleCount?: number,
  maxTotalConnections?: number,
  maxConnectionsPerServer?: number,
) => McpServerPool;

type Internals = {
  cleanupTimer: NodeJS.Timeout | null;
  healthCheckTimer: NodeJS.Timeout | null;
  toolsSweepTimer: NodeJS.Timeout | null;
  getTotalConnectionCount: () => number;
  countConnectionsForServer: (serverUuid: string) => number;
};

const backendParams = (
  uuid: string,
  name: string,
  type: "SSE" | "STREAMABLE_HTTP",
  path: string,
) =>
  ({
    uuid,
    name,
    description: `Synthetic ${type} backend`,
    type,
    stderr: "pipe",
    url: `http://${uuid}-backend:3000${path}`,
    created_at: "2026-10-07T00:00:00.000Z",
    status: "ACTIVE",
  }) satisfies ServerParameters;

const hung = backendParams("hung", "hung-sse", "SSE", "/hung/sse");
const slow = backendParams("slow", "slow-sse", "SSE", "/slow/sse");
const stream = backendParams(
  "stream",
  "stream-http",
  "STREAMABLE_HTTP",
  "/stream/mcp",
);

// Production caps (MAX_TOTAL_CONNECTIONS / MAX_CONNECTIONS_PER_SERVER).
const MAX_TOTAL = 200;
const MAX_PER_SERVER = 50;

// Three timed-out starts (the mocked default) plus the 1 s and 2 s backoff
// sleeps between them; Math.random is pinned so there is no jitter.
const WHOLE_CONNECT_MS = 3 * TRANSPORT_START_TIMEOUT_MS + 1000 + 2000;

describe("McpServerPool transport start deadline (real SDK connect path)", () => {
  let pool: McpServerPool;
  let internals: Internals;
  let warnSpy: ReturnType<typeof vi.spyOn>;

  const deadlineWarnings = () =>
    warnSpy.mock.calls
      .map((call: unknown[]) => String(call[0]))
      .filter((message: string) => message.includes("deadline"));

  // The pool's maintenance sweeps open their own idle connects (and ping
  // idle clients) every 60 s. Stop them where a test isolates one connect.
  const stopMaintenance = () => {
    for (const timer of [
      internals.cleanupTimer,
      internals.healthCheckTimer,
      internals.toolsSweepTimer,
    ]) {
      if (timer) clearInterval(timer);
    }
  };

  beforeEach(() => {
    vi.useFakeTimers();
    backends.streams.length = 0;
    backends.sinks.clear();
    backends.state.endpointDelayMs = 0;
    backends.state.initializeDelayMs = 0;
    backends.state.httpInitializeDelayMs = 0;
    backends.state.httpInitializedDelayMs = 0;
    backends.http.sessionsCreated.length = 0;
    backends.http.sessionsDeleted.length = 0;
    backends.http.initializedPosts.length = 0;
    vi.spyOn(Math, "random").mockReturnValue(0);
    vi.spyOn(metamcpLogStore, "record").mockImplementation(() => {});
    vi.spyOn(logger, "info").mockImplementation(() => {});
    vi.spyOn(console, "log").mockImplementation(() => {});
    warnSpy = vi.spyOn(logger, "warn").mockImplementation(() => {});
    pool = new PoolConstructor(1, MAX_TOTAL, MAX_PER_SERVER);
    internals = pool as unknown as Internals;
  });

  afterEach(async () => {
    const shutdown = pool.cleanupAll();
    await vi.advanceTimersByTimeAsync(SHUTDOWN_PENDING_CONNECT_WAIT_MS);
    await shutdown;
    vi.clearAllTimers();
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it("releases a hung SSE start's per-server and global reservation at its deadline", async () => {
    stopMaintenance();
    const startedAt = Date.now();
    let settled = false;
    const session = pool
      .getSession("session", hung.uuid, hung, "namespace")
      .finally(() => {
        settled = true;
      });
    await vi.advanceTimersByTimeAsync(0);

    // Reserved against both caps while the stream waits for `endpoint`.
    expect(pool.getPoolStatus().pending).toBe(1);
    expect(internals.countConnectionsForServer(hung.uuid)).toBe(1);
    expect(internals.getTotalConnectionCount()).toBe(1);
    expect(backends.streams).toHaveLength(1);

    await vi.advanceTimersByTimeAsync(TRANSPORT_START_TIMEOUT_MS - 1);
    expect(backends.streams[0].aborted).toBe(false);
    await vi.advanceTimersByTimeAsync(1);
    // The first attempt's stream is aborted on the wire at its deadline.
    expect(backends.streams[0].aborted).toBe(true);
    expect(backends.streams[0].signal.aborted).toBe(true);
    expect(deadlineWarnings()).toHaveLength(1);

    // Retries keep the reservation (an ordinary failed attempt does too),
    // each start bounded by its own deadline.
    await vi.advanceTimersByTimeAsync(
      WHOLE_CONNECT_MS - TRANSPORT_START_TIMEOUT_MS - 1,
    );
    expect(settled).toBe(false);
    expect(pool.getPoolStatus().pending).toBe(1);
    await vi.advanceTimersByTimeAsync(1);
    expect(settled).toBe(true);
    await expect(session).resolves.toBeUndefined();

    // Both reservations are back to baseline.
    expect(pool.getPoolStatus().pending).toBe(0);
    expect(internals.countConnectionsForServer(hung.uuid)).toBe(0);
    expect(internals.getTotalConnectionCount()).toBe(0);
    expect(pool.getPoolStatus().lastConnectFailureAt?.[hung.uuid]).toBe(
      startedAt + WHOLE_CONNECT_MS,
    );

    // Every attempt opened one stream and closed it; one WARN per attempt,
    // naming the server and the deadline.
    expect(backends.streams).toHaveLength(3);
    expect(backends.streams.every((s) => s.aborted)).toBe(true);
    expect(deadlineWarnings()).toEqual([
      expect.stringContaining("hung-sse (hung)"),
      expect.stringContaining("hung-sse (hung)"),
      expect.stringContaining("hung-sse (hung)"),
    ]);
    for (const message of deadlineWarnings()) {
      expect(message).toContain(`${TRANSPORT_START_TIMEOUT_MS}ms`);
    }

    // Nothing reconnects behind the pool's back afterwards.
    await vi.advanceTimersByTimeAsync(10 * TRANSPORT_START_TIMEOUT_MS);
    expect(backends.streams).toHaveLength(3);
    expect(internals.getTotalConnectionCount()).toBe(0);
  });

  it("publishes an SSE backend whose endpoint arrives 1 ms before the start deadline, however long initialize then takes", async () => {
    stopMaintenance();
    // `initialize` answered 1 s inside the SDK's own 60 s request timeout,
    // which starts only once start has resolved.
    backends.state.endpointDelayMs = TRANSPORT_START_TIMEOUT_MS - 1;
    backends.state.initializeDelayMs = 59_000;
    const handshakeMs = TRANSPORT_START_TIMEOUT_MS - 1 + 59_000;
    let settled = false;
    const session = pool
      .getSession("session", slow.uuid, slow, "namespace")
      .finally(() => {
        settled = true;
      });

    await vi.advanceTimersByTimeAsync(handshakeMs - 1);
    expect(settled).toBe(false);
    await vi.advanceTimersByTimeAsync(1);
    expect(settled).toBe(true);
    const client = await session;
    expect(client).toBeDefined();
    expect(pool.getPoolStatus().active).toBe(1);
    expect(backends.streams[0].aborted).toBe(false);

    // Crossing the deadline later leaves the live stream alone, and the
    // idle replacement started after publication lands the same way.
    await vi.advanceTimersByTimeAsync(2 * handshakeMs);
    expect(backends.streams).toHaveLength(2);
    expect(backends.streams.some((s) => s.aborted)).toBe(false);
    expect(pool.getPoolStatus()).toMatchObject({
      active: 1,
      idle: 1,
      pending: 0,
    });
    expect(deadlineWarnings()).toHaveLength(0);
  });

  it("never closes a Streamable HTTP transport after initialize allocated its session: a hung initialized notification costs one session, not one per retry", async () => {
    stopMaintenance();
    // `initialize` answers at once and allocates a backend session; the
    // initialized-notification POST that follows never answers. In
    // production the guarded fetch's idle timeout ends that POST, exactly
    // as before the start deadline existed; this fake never does, so
    // anything that closes the transport here is ours.
    backends.state.httpInitializedDelayMs = null;
    let settled = false;
    void pool
      .getSession("session", stream.uuid, stream, "namespace")
      .finally(() => {
        settled = true;
      });

    await vi.advanceTimersByTimeAsync(0);
    expect(backends.http.sessionsCreated).toEqual(["http-session-1"]);
    expect(backends.http.initializedPosts).toHaveLength(1);
    expect(backends.http.initializedPosts[0].session).toBe("http-session-1");

    // Well past any whole-connect budget: three 60 s attempts plus backoff.
    await vi.advanceTimersByTimeAsync(10 * 60_000);

    // One session handed out, none abandoned: the transport holding it was
    // never closed (its in-flight POST was never aborted) and no retry
    // opened another.
    expect(backends.http.sessionsCreated).toEqual(["http-session-1"]);
    expect(backends.http.sessionsDeleted).toEqual([]);
    expect(backends.http.initializedPosts).toHaveLength(1);
    expect(backends.http.initializedPosts[0].signal.aborted).toBe(false);
    expect(deadlineWarnings()).toHaveLength(0);
    expect(settled).toBe(false);
    // The slot stays reserved while its transport, and the backend session
    // behind it, are open: releasing it now would let the caps overshoot.
    expect(pool.getPoolStatus().pending).toBe(1);
    expect(internals.countConnectionsForServer(stream.uuid)).toBe(1);
  });

  it("lets a Streamable HTTP handshake finish past 60 s: initialize at 55 s, initialized notification 10 s later", async () => {
    stopMaintenance();
    // The SDK's 60 s timeout covers `initialize` alone, so this handshake
    // succeeds without any deadline of ours; a 60 s budget over the whole
    // connect would cut it at 60 s, inside the notification's round trip.
    backends.state.httpInitializeDelayMs = 55_000;
    backends.state.httpInitializedDelayMs = 10_000;
    const handshakeMs = 55_000 + 10_000;
    let settled = false;
    const session = pool
      .getSession("session", stream.uuid, stream, "namespace")
      .finally(() => {
        settled = true;
      });

    await vi.advanceTimersByTimeAsync(handshakeMs - 1);
    expect(settled).toBe(false);
    expect(backends.http.sessionsCreated).toEqual(["http-session-1"]);
    await vi.advanceTimersByTimeAsync(1);
    expect(settled).toBe(true);
    const client = await session;
    expect(client).toBeDefined();
    expect(pool.getPoolStatus().active).toBe(1);
    expect(backends.http.initializedPosts).toHaveLength(1);
    expect(backends.http.initializedPosts[0].signal.aborted).toBe(false);

    // The idle replacement started after publication takes the same path
    // and lands too: two live sessions, none abandoned or deleted.
    await vi.advanceTimersByTimeAsync(2 * handshakeMs);
    expect(backends.http.sessionsCreated).toEqual([
      "http-session-1",
      "http-session-2",
    ]);
    expect(backends.http.sessionsDeleted).toEqual([]);
    expect(
      backends.http.initializedPosts.some((post) => post.signal.aborted),
    ).toBe(false);
    expect(pool.getPoolStatus()).toMatchObject({
      active: 1,
      idle: 1,
      pending: 0,
    });
    expect(deadlineWarnings()).toHaveLength(0);
  });

  it("keeps a hung backend's pinned slots bounded under sustained session demand", async () => {
    // Production shape: maintenance sweeps running, a new public session
    // for the hung backend every 10 s for 20 minutes. Each connect now
    // holds its slot for at most WHOLE_CONNECT_MS, so at most that window's
    // arrivals, plus the single guarded idle connect the health sweep keeps
    // retrying, are ever pinned.
    const arrivalMs = 10_000;
    const bound = Math.ceil(WHOLE_CONNECT_MS / arrivalMs) + 1;
    expect(bound).toBeLessThan(MAX_PER_SERVER);

    let peak = 0;
    const sample = () => {
      const pinned = internals.countConnectionsForServer(hung.uuid);
      peak = Math.max(peak, pinned);
      // Nothing else is connected: every pinned slot is a hung connect.
      expect(internals.getTotalConnectionCount()).toBe(pinned);
    };
    for (let i = 0; i < 120; i++) {
      void pool.getSession(`session-${i}`, hung.uuid, hung, "namespace");
      await vi.advanceTimersByTimeAsync(0);
      sample();
      await vi.advanceTimersByTimeAsync(arrivalMs);
      sample();
    }
    expect(peak).toBeLessThanOrEqual(bound);

    // Demand stops: every session connect drains by its deadline. Only the
    // health sweep's single idle retry can still be in flight.
    await vi.advanceTimersByTimeAsync(WHOLE_CONNECT_MS);
    expect(internals.countConnectionsForServer(hung.uuid)).toBeLessThanOrEqual(
      1,
    );
    expect(internals.getTotalConnectionCount()).toBeLessThanOrEqual(1);
  });
});
