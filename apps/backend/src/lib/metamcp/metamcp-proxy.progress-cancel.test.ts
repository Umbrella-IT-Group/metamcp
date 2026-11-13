/**
 * Progress relay, timeout reset, explicit cancel and total-cap cancel on the
 * gateway's tools/call path, driven end to end with real SDK peers on both
 * hops (see tool-call-harness.test-util.ts).
 *
 * Oracles: the MCP spec pages basic/utilities/progress (a notification carries
 * the token of the request it belongs to, none after completion) and
 * basic/utilities/cancellation (notifications/cancelled aborts the in-flight
 * request, a cancel for a finished request is ignored), and the SDK's own
 * shared/protocol.js for the reset/cap/cancel mechanics each test cites.
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import {
  CallToolResultSchema,
  ErrorCode,
  McpError,
  ProgressNotificationSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import logger from "@/utils/logger";

import type { ConnectedClient } from "./client";
import {
  connectGateway,
  DroppableTransport,
  flush,
  gateSends,
  type Gateway,
  makeBackend,
  methodOf,
  OK,
  sendProgress,
  sleep,
  type TestBackend,
} from "./tool-call-harness.test-util";

const { getSessionMock, invalidateServerConnectionMock, config } = vi.hoisted(
  () => ({
    getSessionMock: vi.fn(),
    invalidateServerConnectionMock: vi.fn(),
    config: { timeoutMs: 5_000, maxTotalMs: 600_000, resetOnProgress: true },
  }),
);

vi.mock("@/utils/logger", () => ({
  default: { error: vi.fn(), warn: vi.fn(), info: vi.fn(), debug: vi.fn() },
}));
vi.mock("../../db", () => ({ db: {} }));
vi.mock("../../db/schema", () => ({}));
vi.mock("../../db/repositories/namespaces.repo", () => ({
  namespacesRepository: {
    findServersForNamespaceToolName: vi.fn().mockResolvedValue([]),
  },
}));
vi.mock("../../db/repositories/oauth-sessions.repo", () => ({
  oauthSessionsRepository: {},
}));
vi.mock("../../trpc/tools.impl", () => ({ toolsImplementations: {} }));
vi.mock("../config.service", () => ({
  configService: {
    getMcpResetTimeoutOnProgress: async () => config.resetOnProgress,
    getMcpTimeout: async () => config.timeoutMs,
    getMcpMaxTotalTimeout: async () => config.maxTotalMs,
    getMcpToolCallReconnectWarmupTimeout: async () => 0,
  },
}));
vi.mock("./fetch-metamcp", () => ({
  getMcpServers: vi.fn(async () => ({ "server-ninja": { name: "ninja" } })),
  getNamespaceServerStates: vi.fn(async () => []),
}));
vi.mock("./mcp-server-pool", () => ({
  mcpServerPool: {
    getSession: getSessionMock,
    invalidateServerConnection: invalidateServerConnectionMock,
    cleanupSession: vi.fn(),
    isPooledClient: () => true,
  },
}));
// The chain is pass-through: the handler under test is the proxy's own
// tools/call routing, progress relay and cancel wiring.
vi.mock("./metamcp-middleware/auditing.functional", () => ({
  createAuditingMiddleware: () => (next: unknown) => next,
}));
vi.mock("./metamcp-middleware/filter-tools.functional", () => ({
  createFilterCallToolMiddleware: () => (next: unknown) => next,
  createFilterListToolsMiddleware: () => (next: unknown) => next,
}));
vi.mock("./metamcp-middleware/tool-overrides.functional", () => ({
  createToolOverridesCallToolMiddleware: () => (next: unknown) => next,
  createToolOverridesListToolsMiddleware: () => (next: unknown) => next,
  mapOverrideNameToOriginal: vi.fn(async (name: string) => name),
}));
vi.mock("./cold-connect-broker-fallback", () => ({
  resolveColdConnectBrokerFallback: () => undefined,
}));
vi.mock("./tool-call-warmup", () => ({
  acquireSessionWithBoundedWarmup: vi.fn(async () => undefined),
}));

import { createServer } from "./metamcp-proxy";

const TOOL = "ninja__long_job";

const cleanups: Array<() => Promise<unknown> | unknown> = [];
const envBackup: Record<string, string | undefined> = {};

function setEnv(name: string, value: string): void {
  if (!(name in envBackup)) envBackup[name] = process.env[name];
  process.env[name] = value;
}

async function backend(
  onCall: Parameters<typeof makeBackend>[0],
): Promise<TestBackend> {
  const made = await makeBackend(onCall);
  cleanups.push(() => made.close());
  return made;
}

async function gateway(
  options: Parameters<typeof connectGateway>[1] = {},
): Promise<Gateway> {
  const made = await connectGateway(createServer, options);
  cleanups.push(() => made.close());
  return made;
}

/** The consumer sends tools/call; a token is optional. */
function call(
  consumer: Client,
  options: {
    token?: string | number;
    id?: string;
    signal?: AbortSignal;
    timeout?: number;
  } = {},
) {
  return consumer.request(
    {
      method: "tools/call",
      params: {
        name: TOOL,
        arguments: { id: options.id ?? "x" },
        ...(options.token !== undefined
          ? { _meta: { progressToken: options.token } }
          : {}),
      },
    },
    CallToolResultSchema,
    { signal: options.signal, timeout: options.timeout ?? 10_000_000 },
  );
}

async function rejectionOf(promise: Promise<unknown>): Promise<McpError> {
  try {
    await promise;
  } catch (error) {
    return error as McpError;
  }
  throw new Error("expected the call to reject");
}

/** Records the progress the consumer receives, plus the ordering events. */
function collectProgress(consumer: Client) {
  const events: Array<number | string> = [];
  const tokens: Array<string | number> = [];
  consumer.setNotificationHandler(ProgressNotificationSchema, (n) => {
    events.push(n.params.progress);
    tokens.push(n.params.progressToken);
  });
  return { events, tokens };
}

beforeEach(() => {
  getSessionMock.mockReset();
  invalidateServerConnectionMock.mockReset();
  invalidateServerConnectionMock.mockResolvedValue(undefined);
  config.timeoutMs = 5_000;
  config.maxTotalMs = 600_000;
  config.resetOnProgress = true;
  for (const fn of Object.values(logger))
    (fn as ReturnType<typeof vi.fn>).mockClear();
});

afterEach(async () => {
  vi.useRealTimers();
  while (cleanups.length > 0) {
    await Promise.resolve(cleanups.pop()?.()).catch(() => undefined);
  }
  for (const [name, value] of Object.entries(envBackup)) {
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
    delete envBackup[name];
  }
});

describe("progress relay", () => {
  it("relays backend progress to the consumer under the consumer's token, in order, before the result", async () => {
    const target = await backend(async (extra) => {
      await sendProgress(extra, 1);
      await sendProgress(extra, 2);
      await sendProgress(extra, 3);
      return OK;
    });
    getSessionMock.mockResolvedValue(target.session);

    let release: () => void = () => undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const gw = await gateway({
      wrapTransport: (transport) =>
        gateSends(
          transport,
          (message) => methodOf(message) === "notifications/progress",
          () => gate,
        ),
    });
    const { events, tokens } = collectProgress(gw.consumer);

    let settled = false;
    const result = call(gw.consumer, { token: "tok-abc" }).then((value) => {
      settled = true;
      events.push("result");
      return value;
    });
    await flush();

    // Progress sends are held, and the result is held behind them: the proxy
    // awaits the relay before returning.
    expect(settled).toBe(false);
    release();
    await result;

    expect(events).toEqual([1, 2, 3, "result"]);
    expect(tokens).toEqual(["tok-abc", "tok-abc", "tok-abc"]);
  });

  it("never lets the backend see the consumer's token", async () => {
    const target = await backend(async () => OK);
    getSessionMock.mockResolvedValue(target.session);
    const gw = await gateway();

    await call(gw.consumer, { token: "tok-abc" });

    // The SDK replaces the token with its own request id when it registers a
    // progress handler (shared/protocol.js, request()).
    expect(target.calls).toHaveLength(1);
    expect(typeof target.calls[0].token).toBe("number");
  });

  it("resets the per-request timeout when the backend reports progress", async () => {
    vi.useFakeTimers();
    config.timeoutMs = 500;
    const target = await backend(async (extra, callInfo) => {
      await sleep(400, callInfo.signal);
      await sendProgress(extra, 1);
      await sleep(400, callInfo.signal);
      await sendProgress(extra, 2);
      await sleep(400, callInfo.signal);
      return OK;
    });
    getSessionMock.mockResolvedValue(target.session);
    const gw = await gateway();

    const result = call(gw.consumer);
    await vi.advanceTimersByTimeAsync(1_300);

    // 1200 ms in total against a 500 ms timeout: only a reset on each
    // progress notification lets it finish.
    await expect(result).resolves.toMatchObject({ content: OK.content });
  });

  it("reset off: progress still reaches the consumer but the call times out at the per-request timeout", async () => {
    vi.useFakeTimers();
    config.timeoutMs = 500;
    config.resetOnProgress = false;
    const target = await backend(async (extra, callInfo) => {
      await sleep(400, callInfo.signal);
      await sendProgress(extra, 1);
      await sleep(400, callInfo.signal);
      await sendProgress(extra, 2);
      await sleep(400, callInfo.signal);
      return OK;
    });
    getSessionMock.mockResolvedValue(target.session);
    const gw = await gateway();
    const { events } = collectProgress(gw.consumer);

    const outcome = rejectionOf(call(gw.consumer, { token: "tok-abc" }));
    await vi.advanceTimersByTimeAsync(600);
    const error = await outcome;

    // The relay is registered (the consumer sent a token), but the stored
    // flag still decides whether progress extends the call (shared/
    // protocol.js, `timeoutInfo.resetTimeoutOnProgress`).
    expect(error.code).toBe(ErrorCode.RequestTimeout);
    expect(error.message).toContain("Request timed out");
    expect(events).toEqual([1]);
  });

  it("reset off and no consumer token: no progress handler is registered", async () => {
    config.resetOnProgress = false;
    const target = await backend(async () => OK);
    getSessionMock.mockResolvedValue(target.session);
    const gw = await gateway();

    await call(gw.consumer);

    expect(target.calls[0].token).toBeUndefined();
  });

  it("ends a progressing call at the total cap and cancels the backend", async () => {
    vi.useFakeTimers();
    config.timeoutMs = 500;
    config.maxTotalMs = 1_000;
    const target = await backend(async (extra, callInfo) => {
      await sleep(400, callInfo.signal);
      await sendProgress(extra, 1);
      await sleep(400, callInfo.signal);
      await sendProgress(extra, 2);
      await sleep(300, callInfo.signal);
      await sendProgress(extra, 3);
      await sleep(60_000, callInfo.signal);
      return OK;
    });
    getSessionMock.mockResolvedValue(target.session);
    const gw = await gateway();

    const outcome = rejectionOf(call(gw.consumer));
    await vi.advanceTimersByTimeAsync(1_200);
    const error = await outcome;
    await flush();

    // The SDK checks the cap when progress arrives (shared/protocol.js,
    // _resetTimeout) and sends no cancel on that path; the gateway does.
    expect(error.code).toBe(ErrorCode.RequestTimeout);
    expect(error.message).toContain("Maximum total timeout exceeded");
    expect((error.data as { maxTotalTimeout?: number }).maxTotalTimeout).toBe(
      1_000,
    );
    expect(target.calls[0].signal.aborted).toBe(true);
  });

  it("sends no progress to a consumer that sent no token", async () => {
    const target = await backend(async (extra) => {
      await sendProgress(extra, 1);
      await sendProgress(extra, 2);
      return OK;
    });
    getSessionMock.mockResolvedValue(target.session);
    const gw = await gateway();
    const { events } = collectProgress(gw.consumer);

    await call(gw.consumer);

    expect(events).toEqual([]);
  });

  it("never fails the call when the relay cannot send", async () => {
    const target = await backend(async (extra) => {
      await sendProgress(extra, 1);
      await sendProgress(extra, 2);
      return OK;
    });
    getSessionMock.mockResolvedValue(target.session);
    const gw = await gateway({
      wrapTransport: (transport) => {
        const original = transport.send.bind(transport);
        transport.send = async (message, options) => {
          if (methodOf(message) === "notifications/progress") {
            throw new Error("consumer link refused the notification");
          }
          return original(message, options);
        };
      },
    });

    await expect(
      call(gw.consumer, { token: "tok-abc" }),
    ).resolves.toMatchObject({ content: OK.content });

    const warnings = (logger.warn as ReturnType<typeof vi.fn>).mock.calls
      .map(([message]) => String(message))
      .filter((message) => message.includes("progress relay"));
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toContain(JSON.stringify(TOOL));
    expect(warnings[0]).not.toContain("refused the notification");
  });

  it("MCP_TOOL_CALL_PROGRESS=off restores the old request: token verbatim, nothing relayed, no reset", async () => {
    vi.useFakeTimers();
    setEnv("MCP_TOOL_CALL_PROGRESS", "off");
    config.timeoutMs = 500;
    const target = await backend(async (extra, callInfo) => {
      await sleep(400, callInfo.signal);
      await extra
        .sendNotification({
          method: "notifications/progress",
          params: { progressToken: callInfo.token ?? "none", progress: 1 },
        })
        .catch(() => undefined);
      await sleep(400, callInfo.signal);
      return OK;
    });
    getSessionMock.mockResolvedValue(target.session);
    const gw = await gateway();
    const { events } = collectProgress(gw.consumer);

    const outcome = rejectionOf(call(gw.consumer, { token: "tok-off" }));
    await vi.advanceTimersByTimeAsync(600);
    const error = await outcome;

    expect(target.calls[0].token).toBe("tok-off");
    expect(events).toEqual([]);
    expect(error.message).toContain("Request timed out");
  });

  it("keeps two parallel calls on one proxy apart: own tokens, own signals", async () => {
    vi.useFakeTimers();
    const aborted: Record<string, boolean> = {};
    const target = await backend(async (extra, callInfo) => {
      const id = String(callInfo.args.id);
      if (id === "A") {
        let n = 0;
        while (!callInfo.signal.aborted) {
          await sleep(100, callInfo.signal);
          n += 1;
          await sendProgress(extra, 100 + n);
        }
        aborted.A = true;
        return OK;
      }
      for (let n = 1; n <= 3; n += 1) {
        await sleep(100, callInfo.signal);
        await sendProgress(extra, n);
      }
      aborted.B = callInfo.signal.aborted;
      return OK;
    });
    getSessionMock.mockResolvedValue(target.session);
    const gw = await gateway();
    const seen: Array<{ token: string | number; progress: number }> = [];
    gw.consumer.setNotificationHandler(ProgressNotificationSchema, (n) => {
      seen.push({
        token: n.params.progressToken,
        progress: n.params.progress,
      });
    });

    const cancelA = new AbortController();
    const callA = rejectionOf(
      call(gw.consumer, { token: "tok-A", id: "A", signal: cancelA.signal }),
    );
    const callB = call(gw.consumer, { token: "tok-B", id: "B" });
    await vi.advanceTimersByTimeAsync(150);
    cancelA.abort();
    await vi.advanceTimersByTimeAsync(400);
    await callA;
    await expect(callB).resolves.toMatchObject({ content: OK.content });
    await flush();

    expect(aborted.A).toBe(true);
    expect(aborted.B).toBe(false);
    const forB = seen.filter((n) => n.token === "tok-B");
    expect(forB.map((n) => n.progress)).toEqual([1, 2, 3]);
    // Everything A sent after its cancel was dropped, none under B's token.
    const forA = seen.filter((n) => n.token === "tok-A");
    expect(forA.length).toBeLessThanOrEqual(2);
    expect(forA.every((n) => n.progress > 100)).toBe(true);
  });
});

describe("explicit cancel", () => {
  /** A backend that runs until its request is aborted. */
  const runsUntilAborted = (state: { completed: boolean }) =>
    backend(async (_extra, callInfo) => {
      await new Promise<void>((resolve) => {
        if (callInfo.signal.aborted) return resolve();
        callInfo.signal.addEventListener("abort", () => resolve(), {
          once: true,
        });
      });
      state.completed = true;
      return OK;
    });

  it("aborts the backend request when the consumer cancels", async () => {
    const state = { completed: false };
    const target = await runsUntilAborted(state);
    getSessionMock.mockResolvedValue(target.session);
    const gw = await gateway();

    const controller = new AbortController();
    const outcome = rejectionOf(
      call(gw.consumer, { signal: controller.signal }),
    );
    await flush();
    expect(target.calls[0].signal.aborted).toBe(false);

    controller.abort();
    await outcome;
    await flush();

    expect(target.calls).toHaveLength(1);
    expect(target.calls[0].signal.aborted).toBe(true);
  });

  it("logs a cancelled call at info and never at error", async () => {
    const target = await runsUntilAborted({ completed: false });
    getSessionMock.mockResolvedValue(target.session);
    const gw = await gateway();

    const controller = new AbortController();
    const outcome = rejectionOf(
      call(gw.consumer, { signal: controller.signal }),
    );
    await flush();
    controller.abort();
    await outcome;
    await flush();

    expect(logger.error).not.toHaveBeenCalled();
    expect(logger.info).toHaveBeenCalledWith(
      `Tool call ${JSON.stringify(TOOL)} cancelled by the caller; outcome unknown`,
    );
  });

  it("does not send a call that was cancelled before the backend request", async () => {
    const target = await backend(async () => OK);
    let releaseSession: (session: ConnectedClient) => void = () => undefined;
    getSessionMock.mockReturnValue(
      new Promise<ConnectedClient>((resolve) => {
        releaseSession = resolve;
      }),
    );
    const gw = await gateway();

    const controller = new AbortController();
    const outcome = rejectionOf(
      call(gw.consumer, { signal: controller.signal }),
    );
    await flush();
    controller.abort();
    await outcome;
    await flush();
    releaseSession(target.session);
    await flush();

    // The SDK refuses a request whose signal is already aborted before it
    // sends anything (shared/protocol.js, `signal.throwIfAborted()`).
    expect(target.calls).toHaveLength(0);
  });

  /**
   * A pooled session whose tools/call fails with the SDK's own pre-send
   * "Not connected" (the exact shape the replay guard accepts), while its
   * routing lookup is answered by a real backend.
   */
  async function sessionFailingNotConnected(): Promise<{
    session: ConnectedClient;
    real: TestBackend;
  }> {
    const real = await backend(async () => OK);
    const unconnected = new Client({ name: "metamcp", version: "1.0.0" });
    const client = {
      request: (req: { method: string }, schema: never, options: never) =>
        req.method === "tools/call"
          ? unconnected.request(req as never, schema, options)
          : real.session.client.request(req as never, schema, options),
      getServerCapabilities: () => ({ tools: {} }),
      getServerVersion: () => ({ name: "ninja", version: "1.0.0" }),
    } as unknown as Client;
    return {
      session: {
        client,
        cleanup: async () => undefined,
        listChangedSubscribers: new Set(),
      },
      real,
    };
  }

  it("does not recover or replay a call cancelled before the first attempt", async () => {
    const { session, real } = await sessionFailingNotConnected();
    let releaseSession: (session: ConnectedClient) => void = () => undefined;
    getSessionMock.mockReturnValue(
      new Promise<ConnectedClient>((resolve) => {
        releaseSession = resolve;
      }),
    );
    const gw = await gateway();

    const controller = new AbortController();
    const outcome = rejectionOf(
      call(gw.consumer, { signal: controller.signal }),
    );
    await flush();
    controller.abort();
    await outcome;
    await flush();
    releaseSession(session);
    await flush();

    expect(invalidateServerConnectionMock).not.toHaveBeenCalled();
    expect(getSessionMock).toHaveBeenCalledTimes(1);
    expect(real.calls).toHaveLength(0);
  });

  it("ends a cancel that lands during session recovery in the info line, not an error", async () => {
    const { session } = await sessionFailingNotConnected();
    const healthy = await backend(async () => OK);
    let releaseRecovery: (session: ConnectedClient) => void = () => undefined;
    getSessionMock.mockResolvedValueOnce(session).mockReturnValueOnce(
      new Promise<ConnectedClient>((resolve) => {
        releaseRecovery = resolve;
      }),
    );
    const gw = await gateway();

    const controller = new AbortController();
    const outcome = rejectionOf(
      call(gw.consumer, { signal: controller.signal }),
    );
    // First attempt failed "Not connected"; the recovery now waits on the
    // pool for a replacement session.
    await flush();
    expect(getSessionMock).toHaveBeenCalledTimes(2);

    controller.abort();
    await outcome;
    await flush();
    releaseRecovery(healthy.session);
    await flush();

    // The second attempt's pre-send abort check throws the typed reason.
    expect(healthy.calls).toHaveLength(0);
    expect(logger.error).not.toHaveBeenCalled();
    expect(getSessionMock).toHaveBeenCalledTimes(2);
    expect(logger.info).toHaveBeenCalledWith(
      `Tool call ${JSON.stringify(TOOL)} cancelled by the caller; outcome unknown`,
    );
  });
});

describe("a closed consumer transport is not a cancel", () => {
  it("lets the backend call run to completion when the consumer closes the link", async () => {
    const state = { completed: false };
    let finish: () => void = () => undefined;
    const target = await backend(async () => {
      await new Promise<void>((resolve) => {
        finish = resolve;
      });
      state.completed = true;
      return OK;
    });
    getSessionMock.mockResolvedValue(target.session);
    const gw = await gateway();

    const outcome = rejectionOf(call(gw.consumer));
    await flush();
    await gw.consumer.close();
    await outcome;
    await flush();

    // shared/protocol.js _onclose aborts every handler's signal and, in the
    // same synchronous run, clears the transport: the gateway tells a close
    // from a cancel by that state, one promise turn after the abort.
    expect(target.calls[0].signal.aborted).toBe(false);
    finish();
    await flush();
    expect(state.completed).toBe(true);
    expect(target.calls).toHaveLength(1);
  });

  it("lets the backend call run to completion when a stream-style transport drops without close()", async () => {
    let finish: () => void = () => undefined;
    const target = await backend(async () => {
      await new Promise<void>((resolve) => {
        finish = resolve;
      });
      return OK;
    });
    getSessionMock.mockResolvedValue(target.session);
    const { server } = await createServer("ns-1", "sess-1");
    const transport = new DroppableTransport();
    await server.connect(transport);
    transport.onmessage?.({
      jsonrpc: "2.0",
      id: 7,
      method: "tools/call",
      params: { name: TOOL, arguments: {} },
    });
    await flush();
    expect(target.calls).toHaveLength(1);

    // The legacy SSE transport reports a dropped stream through onclose and
    // never calls close() (the SDK's server/sse.js).
    transport.drop();
    await flush();

    expect(target.calls[0].signal.aborted).toBe(false);
    finish();
    await flush();
    expect(target.calls).toHaveLength(1);
  });
});

describe("MCP_TOOL_CALL_CANCEL=off", () => {
  it("leaves the backend call running when the consumer cancels", async () => {
    setEnv("MCP_TOOL_CALL_CANCEL", "off");
    const target = await backend(async (_extra, callInfo) => {
      await sleep(0, callInfo.signal);
      await new Promise<void>(() => undefined);
      return OK;
    });
    getSessionMock.mockResolvedValue(target.session);
    const gw = await gateway();

    const controller = new AbortController();
    const outcome = rejectionOf(
      call(gw.consumer, { signal: controller.signal }),
    );
    await flush();
    controller.abort();
    await outcome;
    await flush();

    expect(target.calls[0].signal.aborted).toBe(false);
  });

  it("sends the backend no cancel when the total cap rejects the call", async () => {
    vi.useFakeTimers();
    setEnv("MCP_TOOL_CALL_CANCEL", "off");
    config.timeoutMs = 500;
    config.maxTotalMs = 1_000;
    const target = await backend(async (extra, callInfo) => {
      await sleep(400, callInfo.signal);
      await sendProgress(extra, 1);
      await sleep(400, callInfo.signal);
      await sendProgress(extra, 2);
      await sleep(300, callInfo.signal);
      await sendProgress(extra, 3);
      await new Promise<void>(() => undefined);
      return OK;
    });
    getSessionMock.mockResolvedValue(target.session);
    const gw = await gateway();

    const outcome = rejectionOf(call(gw.consumer));
    await vi.advanceTimersByTimeAsync(1_200);
    const error = await outcome;
    await flush();

    expect(error.message).toContain("Maximum total timeout exceeded");
    expect(target.calls[0].signal.aborted).toBe(false);
  });
});
