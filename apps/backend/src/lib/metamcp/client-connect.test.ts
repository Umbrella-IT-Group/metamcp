/**
 * Behavior tests for `connectMetaMcpClient`'s retry loop, the `closing`
 * guard and the M365 broker short-circuit (Track A5). The real connect
 * path builds a live SDK transport and dials the network, so these use
 * the `deps.createClient` injection seam to hand `connectMetaMcpClient`
 * a fake client/transport whose `connect()` outcome the test controls.
 *
 * The db-backed `server-error-tracker` is mocked so importing `client.ts`
 * doesn't require a live DATABASE_URL and so maxAttempts is deterministic.
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import { ServerParameters } from "@repo/zod-types";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import logger from "@/utils/logger";

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
  },
}));

import { M365BrokerError } from "../m365/errors";
import {
  runWithM365UserContext,
  takeConnectBrokerFailure,
} from "../m365/request-context";
import { ProcessManagedStdioTransport } from "../stdio-transport/process-managed-transport";
import {
  ConnectedClient,
  connectMetaMcpClient,
  TRANSPORT_START_TIMEOUT_MS,
} from "./client";
import { metamcpLogStore } from "./log-store";
import { serverErrorTracker } from "./server-error-tracker";

const ENROLL = "https://mcp.example.com/m365/enroll";

const params = {
  uuid: "srv-m365",
  name: "m365",
  description: "",
  type: "STREAMABLE_HTTP",
  url: "http://backend:3000/mcp",
  created_at: new Date().toISOString(),
  status: "active",
} as unknown as ServerParameters;

function makeFakeClient(
  connectImpl: (transport: Transport) => Promise<void>,
): Client {
  return {
    connect: vi.fn(connectImpl),
    close: vi.fn().mockResolvedValue(undefined),
    setNotificationHandler: vi.fn(),
    getServerVersion: vi.fn(() => ({ name: "fake", version: "0" })),
    getServerCapabilities: vi.fn(() => ({ tools: {} })),
  } as unknown as Client;
}

/** Non-instanceof transport — connect-throw tests never reach the wiring. */
function makeFakeTransport(): Transport {
  return {
    onclose: undefined,
    onerror: undefined,
    start: vi.fn().mockResolvedValue(undefined),
    send: vi.fn().mockResolvedValue(undefined),
    close: vi.fn().mockResolvedValue(undefined),
  } as unknown as Transport;
}

/**
 * A real StreamableHTTPClientTransport instance (so `isHttpTransport`
 * wiring runs) with `close` overridden to deterministically fire the
 * production-wired `onclose` the way the SDK does on teardown, and to do
 * no network I/O.
 */
function makeRealHttpTransport(): Transport {
  const t = new StreamableHTTPClientTransport(
    new URL("http://backend:3000/mcp"),
  );
  t.close = vi.fn(async () => {
    t.onclose?.();
  }) as unknown as typeof t.close;
  return t as unknown as Transport;
}

function recordedMessages(spy: ReturnType<typeof vi.spyOn>): string[] {
  return spy.mock.calls.map(
    (call: unknown[]) => (call[0] as { message: string }).message,
  );
}

describe("connectMetaMcpClient — M365 broker short-circuit", () => {
  let recordSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    recordSpy = vi
      .spyOn(metamcpLogStore, "record")
      .mockImplementation(() => {});
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("makes exactly one attempt, latches the enrollment prompt, logs no backend drop", async () => {
    // credential_missing is a DETERMINISTIC identity code, unlike
    // mint_failed (see the sibling describe block below) — it must stay
    // one-attempt even after mint_failed was carved out to retry.
    const brokerError = new M365BrokerError(
      "credential_missing",
      "No stored M365 grant for this user.",
      ENROLL,
    );
    const client = makeFakeClient(async () => {
      throw brokerError;
    });
    const transport = makeFakeTransport();
    const createClient = vi.fn(() => ({ client, transport }));
    const onTransportDrop = vi.fn();

    let latched: ReturnType<typeof takeConnectBrokerFailure> | undefined;
    const result = await runWithM365UserContext({ userId: "ray" }, async () => {
      const r = await connectMetaMcpClient(params, undefined, onTransportDrop, {
        createClient,
      });
      latched = takeConnectBrokerFailure();
      return r;
    });

    // Non-retryable: exactly one attempt.
    expect(result).toBeUndefined();
    expect(createClient).toHaveBeenCalledTimes(1);
    expect(client.connect).toHaveBeenCalledTimes(1);

    // Enrollment payload reaches the consumer surface (latched for the
    // outer tools/call handler to drain).
    expect(latched?.serverName).toBe("m365");
    expect(latched?.error).toBe(brokerError);
    expect(latched?.error.enrollUrl).toBe(ENROLL);

    // No retry storm, no fake backend-drop.
    const messages = recordedMessages(recordSpy);
    expect(messages.some((m) => m.includes("Connect attempt"))).toBe(false);
    expect(messages.some((m) => m.includes("backend drop"))).toBe(false);
    expect(onTransportDrop).not.toHaveBeenCalled();
  });
});

describe("connectMetaMcpClient — M365 mint_failed is retried like a transient failure", () => {
  let recordSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    recordSpy = vi
      .spyOn(metamcpLogStore, "record")
      .mockImplementation(() => {});
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it("retries up to maxAttempts (not a one-attempt short-circuit) then latches on exhaustion", async () => {
    // mint_failed is thrown by mint-service for TRANSIENT operational
    // failures (token-endpoint unreachable, 5xx) — unlike the deterministic
    // identity codes, this must keep the pre-PR retry-with-backoff
    // resilience, not collapse into the one-attempt short-circuit.
    const brokerError = new M365BrokerError(
      "mint_failed",
      "Microsoft identity platform returned 503 — try again shortly.",
    );
    const client = makeFakeClient(async () => {
      throw brokerError;
    });
    const transport = makeFakeTransport();
    const createClient = vi.fn(() => ({ client, transport }));
    const onTransportDrop = vi.fn();

    let latched: ReturnType<typeof takeConnectBrokerFailure> | undefined;
    vi.useFakeTimers();
    const pending = runWithM365UserContext({ userId: "ray" }, async () => {
      const r = await connectMetaMcpClient(params, undefined, onTransportDrop, {
        createClient,
      });
      latched = takeConnectBrokerFailure();
      return r;
    });
    await vi.runAllTimersAsync();
    const result = await pending;

    expect(result).toBeUndefined();
    // maxAttempts (mocked) = 3 — full retry loop, not one attempt.
    expect(createClient).toHaveBeenCalledTimes(3);
    expect(client.connect).toHaveBeenCalledTimes(3);
    expect(onTransportDrop).not.toHaveBeenCalled();

    // Latched only once retries are exhausted, carrying the actionable
    // "try again shortly" broker message rather than a generic connect
    // failure / "Unknown tool".
    expect(latched?.serverName).toBe("m365");
    expect(latched?.error).toBe(brokerError);
    expect(latched?.error.code).toBe("mint_failed");

    // Every attempt logged with the typed mint_failed message, not the
    // generic cause-unwrap path (there's no undici cause to unwrap here).
    const messages = recordedMessages(recordSpy);
    const attemptLogs = messages.filter((m) => m.includes("Connect attempt"));
    expect(attemptLogs.length).toBe(3);
    expect(attemptLogs[0]).toContain("mint_failed");
    expect(messages.some((m) => m.includes("backend drop"))).toBe(false);
  });
});

describe("connectMetaMcpClient — ordinary transient failure", () => {
  let recordSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    recordSpy = vi
      .spyOn(metamcpLogStore, "record")
      .mockImplementation(() => {});
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it("retries up to maxAttempts and reports the unwrapped cause, not 'fetch failed'", async () => {
    // undici-style wrapper: TypeError('fetch failed') whose cause is the
    // ECONNREFUSED system error.
    const leaf = Object.assign(new Error("connect ECONNREFUSED"), {
      code: "ECONNREFUSED",
      syscall: "connect",
      address: "172.18.0.13",
      port: 3000,
    });
    const wrapper = new TypeError("fetch failed");
    (wrapper as Error & { cause?: unknown }).cause = leaf;

    const client = makeFakeClient(async () => {
      throw wrapper;
    });
    const transport = makeFakeTransport();
    const createClient = vi.fn(() => ({ client, transport }));

    vi.useFakeTimers();
    const pending = connectMetaMcpClient(params, undefined, undefined, {
      createClient,
    });
    await vi.runAllTimersAsync();
    const result = await pending;

    expect(result).toBeUndefined();
    // maxAttempts (mocked) = 3.
    expect(createClient).toHaveBeenCalledTimes(3);
    expect(client.connect).toHaveBeenCalledTimes(3);

    const messages = recordedMessages(recordSpy);
    const attemptLogs = messages.filter((m) => m.includes("Connect attempt"));
    expect(attemptLogs.length).toBe(3);
    // Actionable leaf surfaced instead of the generic wrapper text.
    expect(attemptLogs[0]).toContain("connect ECONNREFUSED 172.18.0.13:3000");
    expect(attemptLogs[0]).not.toContain("fetch failed");
  });
});

describe("connectMetaMcpClient — closing guard on established connections", () => {
  let recordSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    recordSpy = vi
      .spyOn(metamcpLogStore, "record")
      .mockImplementation(() => {});
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("does not log an unexpected drop for an intentional cleanup close", async () => {
    const client = makeFakeClient(async () => {});
    const transport = makeRealHttpTransport();
    const createClient = vi.fn(() => ({ client, transport }));
    const onTransportDrop = vi.fn();

    const result = (await connectMetaMcpClient(
      params,
      undefined,
      onTransportDrop,
      { createClient },
    )) as ConnectedClient;
    expect(result).toBeDefined();

    recordSpy.mockClear(); // drop the "Connected" record from the assertion window
    await result.cleanup();

    const messages = recordedMessages(recordSpy);
    expect(
      messages.some(
        (m) => m.includes("unexpectedly") || m.includes("backend drop"),
      ),
    ).toBe(false);
    expect(onTransportDrop).not.toHaveBeenCalled();
  });

  it("still logs a backend drop when an established connection drops remotely", async () => {
    const client = makeFakeClient(async () => {});
    const transport = makeRealHttpTransport();
    const createClient = vi.fn(() => ({ client, transport }));
    const onTransportDrop = vi.fn();

    const result = (await connectMetaMcpClient(
      params,
      undefined,
      onTransportDrop,
      { createClient },
    )) as ConnectedClient;
    expect(result).toBeDefined();

    recordSpy.mockClear();
    // The SDK surfaces an async error on the live socket (watchtower
    // bounce / backend container replace).
    transport.onerror?.(new Error("terminated"));

    const messages = recordedMessages(recordSpy);
    expect(messages.some((m) => m.includes("backend drop"))).toBe(true);
    expect(messages.some((m) => m.includes("established"))).toBe(true);
    expect(onTransportDrop).toHaveBeenCalledWith("error", expect.any(Error));
  });
});

// -------------------------------------------------------------------
// Transport start deadline
//
// `client.connect()` starts the transport, then runs the handshake
// (`initialize`, then the initialized notification). The SDK times
// `initialize` out but never start, so an SSE backend that heartbeats
// without its `endpoint` event left the connect pending forever, its
// transport open and its pool reservation held. Only start is bounded:
// a deadline over the whole connect would also cut a handshake the SDK
// allows, and close a Streamable HTTP transport whose `initialize` had
// already allocated a backend session. The fake client here does what
// the SDK's `connect` does, start then handshake, with a handshake the
// test controls. The real-SDK reproductions live in
// `mcp-server-pool-connect-deadline.test.ts`.
// -------------------------------------------------------------------

describe("connectMetaMcpClient — transport start deadline", () => {
  let recordSpy: ReturnType<typeof vi.spyOn>;
  let warnSpy: ReturnType<typeof vi.spyOn>;

  const deadlineWarnings = () =>
    warnSpy.mock.calls
      .map((call: unknown[]) => String(call[0]))
      .filter((message: string) => message.includes("deadline"));

  /** Start the transport, then run `handshake`, as `Client.connect` does. */
  const makeStartingClient = (
    handshake: () => Promise<void> = async () => {},
  ) =>
    makeFakeClient(async (transport) => {
      await transport.start();
      await handshake();
    });

  /** A fake transport whose `start` the test controls. */
  const makeTransportWithStart = (start: () => Promise<void>) => {
    const transport = makeFakeTransport();
    const startSpy = vi.fn(start);
    transport.start = startSpy;
    return { transport, startSpy };
  };

  beforeEach(() => {
    vi.useFakeTimers();
    recordSpy = vi
      .spyOn(metamcpLogStore, "record")
      .mockImplementation(() => {});
    warnSpy = vi.spyOn(logger, "warn").mockImplementation(() => {});
    vi.spyOn(console, "log").mockImplementation(() => {});
    // No backoff jitter, so the retry schedule is exact.
    vi.spyOn(Math, "random").mockReturnValue(0);
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it("cuts a start that never settles at the deadline: rejects, closes its transport once, warns once", async () => {
    vi.mocked(serverErrorTracker.getServerMaxAttempts).mockResolvedValueOnce(1);
    const handshake = vi.fn(async () => {});
    const client = makeStartingClient(handshake);
    const { transport, startSpy } = makeTransportWithStart(
      () => new Promise<void>(() => {}),
    );
    const createClient = vi.fn(() => ({ client, transport }));

    let settled = false;
    const pending = connectMetaMcpClient(params, undefined, undefined, {
      createClient,
    }).finally(() => {
      settled = true;
    });

    await vi.advanceTimersByTimeAsync(TRANSPORT_START_TIMEOUT_MS - 1);
    expect(startSpy).toHaveBeenCalledTimes(1);
    expect(settled).toBe(false);
    expect(transport.close).not.toHaveBeenCalled();
    expect(deadlineWarnings()).toHaveLength(0);

    await vi.advanceTimersByTimeAsync(1);
    expect(settled).toBe(true);
    // The pool's contract is unchanged: a failed connect resolves undefined.
    await expect(pending).resolves.toBeUndefined();
    expect(transport.close).toHaveBeenCalledTimes(1);
    expect(client.close).toHaveBeenCalledTimes(1);
    // The handshake never began, so no backend session could exist.
    expect(handshake).not.toHaveBeenCalled();

    // The start rejected into the ordinary failure path.
    const attemptLogs = recordedMessages(recordSpy).filter((m) =>
      m.includes("Connect attempt"),
    );
    expect(attemptLogs).toHaveLength(1);
    expect(attemptLogs[0]).toContain("1/1 failed");
    expect(attemptLogs[0]).toContain(`${TRANSPORT_START_TIMEOUT_MS}ms`);

    // Exactly one WARN, naming the server and the deadline.
    expect(deadlineWarnings()).toEqual([
      expect.stringContaining(`m365 (srv-m365)`),
    ]);
    expect(deadlineWarnings()[0]).toContain(`${TRANSPORT_START_TIMEOUT_MS}ms`);

    // Nothing left armed: no later close, warning or attempt.
    await vi.advanceTimersByTimeAsync(10 * TRANSPORT_START_TIMEOUT_MS);
    expect(transport.close).toHaveBeenCalledTimes(1);
    expect(createClient).toHaveBeenCalledTimes(1);
    expect(deadlineWarnings()).toHaveLength(1);
  });

  it("bounds every retry's start by its own deadline, so the whole connect settles on schedule", async () => {
    // maxAttempts (mocked) = 3. Each attempt gets a fresh transport.
    const transports: Transport[] = [];
    const client = makeStartingClient();
    const createClient = vi.fn(() => {
      const { transport } = makeTransportWithStart(
        () => new Promise<void>(() => {}),
      );
      transports.push(transport);
      return { client, transport };
    });

    let settled = false;
    const pending = connectMetaMcpClient(params, undefined, undefined, {
      createClient,
    }).finally(() => {
      settled = true;
    });

    // Three deadlines plus the 1 s and 2 s backoff sleeps between them.
    const whole = 3 * TRANSPORT_START_TIMEOUT_MS + 1000 + 2000;
    await vi.advanceTimersByTimeAsync(whole - 1);
    expect(settled).toBe(false);
    expect(createClient).toHaveBeenCalledTimes(3);
    await vi.advanceTimersByTimeAsync(1);
    expect(settled).toBe(true);
    await expect(pending).resolves.toBeUndefined();

    expect(transports).toHaveLength(3);
    for (const transport of transports) {
      expect(transport.close).toHaveBeenCalledTimes(1);
    }
    // One WARN per timed-out start.
    expect(deadlineWarnings()).toHaveLength(3);
  });

  it("leaves a start that settles 1 ms before the deadline untouched, however long the handshake then takes", async () => {
    // A handshake far longer than the start deadline: once start has
    // settled, nothing of ours may cut the connect.
    const handshakeMs = 3 * TRANSPORT_START_TIMEOUT_MS;
    const client = makeStartingClient(
      () => new Promise<void>((resolve) => setTimeout(resolve, handshakeMs)),
    );
    const { transport } = makeTransportWithStart(
      () =>
        new Promise<void>((resolve) =>
          setTimeout(resolve, TRANSPORT_START_TIMEOUT_MS - 1),
        ),
    );
    const createClient = vi.fn(() => ({ client, transport }));

    let settled = false;
    const pending = connectMetaMcpClient(params, undefined, undefined, {
      createClient,
    }).finally(() => {
      settled = true;
    });
    await vi.advanceTimersByTimeAsync(
      TRANSPORT_START_TIMEOUT_MS - 1 + handshakeMs - 1,
    );
    expect(settled).toBe(false);
    await vi.advanceTimersByTimeAsync(1);
    const result = (await pending) as ConnectedClient;
    expect(result).toBeDefined();
    expect(result.client).toBe(client);

    // The deadline timer was cleared with start: crossing it later must
    // not close the live transport or warn.
    await vi.advanceTimersByTimeAsync(10 * TRANSPORT_START_TIMEOUT_MS);
    expect(transport.close).not.toHaveBeenCalled();
    expect(client.close).not.toHaveBeenCalled();
    expect(deadlineWarnings()).toHaveLength(0);
    expect(createClient).toHaveBeenCalledTimes(1);
    expect(
      recordedMessages(recordSpy).filter((m) => m.includes("Connect attempt")),
    ).toHaveLength(0);
  });

  it("never times the handshake: a started connect stays with the SDK's own bounds and is not closed", async () => {
    // The handshake never settles here. In production the SDK's request
    // timeout bounds `initialize` and the guarded fetch's idle timeout the
    // initialized notification, as before this deadline existed; our code
    // must arm nothing after start, or it would close a transport that may
    // already hold a backend session (Streamable HTTP allocates one in the
    // `initialize` response).
    const client = makeStartingClient(() => new Promise<void>(() => {}));
    const { transport, startSpy } = makeTransportWithStart(async () => {});
    const createClient = vi.fn(() => ({ client, transport }));

    let settled = false;
    void connectMetaMcpClient(params, undefined, undefined, {
      createClient,
    }).finally(() => {
      settled = true;
    });

    await vi.advanceTimersByTimeAsync(20 * TRANSPORT_START_TIMEOUT_MS);
    expect(startSpy).toHaveBeenCalledTimes(1);
    expect(settled).toBe(false);
    expect(transport.close).not.toHaveBeenCalled();
    expect(client.close).not.toHaveBeenCalled();
    expect(createClient).toHaveBeenCalledTimes(1);
    expect(deadlineWarnings()).toHaveLength(0);
  });
});

// -------------------------------------------------------------------
// Spec session termination on teardown
//
// `Protocol.close()` only closes the local transport; without an
// explicit `terminateSession()` the backend never sees the spec DELETE
// and keeps the session object forever (prod 2026-08-13: 1027 sessions
// created / 0 terminated against one backend). These pin the three
// properties of the fix in `client.ts`'s `cleanup()` choke point:
// DELETE-then-close ordering, fail-open on a broken/hung backend, and
// a clean skip for transports that carry no HTTP session.
// -------------------------------------------------------------------

/**
 * A real `StreamableHTTPClientTransport` — so `terminateBackendSession`'s
 * `instanceof` gate sees the production type — with `terminateSession`
 * and `close` stubbed to record ordering and do no network I/O.
 * `terminateImpl` lets a test decide whether the DELETE resolves,
 * rejects, or never settles.
 */
function makeTerminableHttpTransport(
  terminateImpl: () => Promise<void> = async () => {},
) {
  const calls: string[] = [];
  const t = new StreamableHTTPClientTransport(
    new URL("http://backend:3000/mcp"),
  );
  const terminateSession = vi.fn(async () => {
    calls.push("terminate");
    await terminateImpl();
  });
  const close = vi.fn(async () => {
    calls.push("close");
    t.onclose?.();
  });
  t.terminateSession = terminateSession as unknown as typeof t.terminateSession;
  t.close = close as unknown as typeof t.close;
  return {
    transport: t as unknown as Transport,
    calls,
    terminateSession,
    close,
  };
}

/**
 * A real (never-started, so no child process is spawned) STDIO transport.
 * Constructing one is side-effect free; `start()` is what spawns.
 */
function makeStdioTransport() {
  const t = new ProcessManagedStdioTransport({
    command: "true",
    stderr: "pipe",
  });
  const close = vi.fn(async () => {
    t.onclose?.();
  });
  t.close = close as unknown as typeof t.close;
  return { transport: t as unknown as Transport, close };
}

async function connectForTeardown(transport: Transport, client: Client) {
  const createClient = vi.fn(() => ({ client, transport }));
  const result = (await connectMetaMcpClient(params, undefined, undefined, {
    createClient,
  })) as ConnectedClient;
  expect(result).toBeDefined();
  return result;
}

describe("ConnectedClient.cleanup — spec session termination", () => {
  let warnSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    vi.spyOn(metamcpLogStore, "record").mockImplementation(() => {});
    warnSpy = vi.spyOn(logger, "warn").mockImplementation(() => {});
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it("sends the session DELETE before closing a streamable-HTTP transport", async () => {
    const client = makeFakeClient(async () => {});
    const { transport, calls, terminateSession } =
      makeTerminableHttpTransport();

    const result = await connectForTeardown(transport, client);
    await result.cleanup();

    // Ordering is load-bearing: `close()` aborts the transport's abort
    // controller, so a DELETE issued after it could never reach the wire.
    expect(calls).toEqual(["terminate", "close"]);
    expect(terminateSession).toHaveBeenCalledTimes(1);
    expect(client.close).toHaveBeenCalledTimes(1);
    expect(warnSpy).not.toHaveBeenCalled();
  });

  it("closes anyway and warns once when the DELETE rejects", async () => {
    const client = makeFakeClient(async () => {});
    const { transport, calls, close } = makeTerminableHttpTransport(
      async () => {
        throw new Error("connect ECONNREFUSED 172.18.0.13:3000");
      },
    );

    const result = await connectForTeardown(transport, client);
    // Must NOT reject — a dead backend cannot be allowed to abort the
    // pool's eviction path.
    await expect(result.cleanup()).resolves.toBeUndefined();

    expect(calls).toEqual(["terminate", "close"]);
    expect(close).toHaveBeenCalledTimes(1);
    expect(client.close).toHaveBeenCalledTimes(1);
    expect(warnSpy).toHaveBeenCalledTimes(1);
    const [message, error] = warnSpy.mock.calls[0] as [string, Error];
    expect(message).toContain("Failed to terminate backend session");
    expect(message).toContain("m365");
    expect(message).toContain("srv-m365");
    expect(error.message).toContain("ECONNREFUSED");
  });

  it("closes anyway and warns once when the DELETE hangs past the timeout", async () => {
    const client = makeFakeClient(async () => {});
    // Never settles — the hung-backend case the 2s bound exists for.
    const { transport, calls, close } = makeTerminableHttpTransport(
      () => new Promise<void>(() => {}),
    );

    const result = await connectForTeardown(transport, client);

    vi.useFakeTimers();
    const pending = result.cleanup();
    // SESSION_TERMINATE_TIMEOUT_MS in client.ts.
    await vi.advanceTimersByTimeAsync(2000);
    await expect(pending).resolves.toBeUndefined();

    expect(calls).toEqual(["terminate", "close"]);
    expect(close).toHaveBeenCalledTimes(1);
    expect(client.close).toHaveBeenCalledTimes(1);
    expect(warnSpy).toHaveBeenCalledTimes(1);
    const [message, error] = warnSpy.mock.calls[0] as [string, Error];
    expect(message).toContain("Failed to terminate backend session");
    expect(error.message).toContain("exceeded 2000ms");
  });

  it("skips termination for a STDIO transport and closes without warning", async () => {
    const client = makeFakeClient(async () => {});
    const { transport, close } = makeStdioTransport();

    // The skip is not cosmetic: STDIO carries no HTTP session and the
    // SDK class has no such method, so calling it would TypeError.
    expect(
      (transport as unknown as Record<string, unknown>).terminateSession,
    ).toBeUndefined();

    const result = await connectForTeardown(transport, client);
    await expect(result.cleanup()).resolves.toBeUndefined();

    expect(close).toHaveBeenCalledTimes(1);
    expect(client.close).toHaveBeenCalledTimes(1);
    expect(warnSpy).not.toHaveBeenCalled();
  });

  it("sends one DELETE, not two, when cleanup runs twice", async () => {
    // The invalidation cascade can reach the same ConnectedClient as both
    // an idle and an active slot. The SDK clears its session id after a
    // successful DELETE and `terminateSession()` no-ops without one, so
    // the second teardown must not re-issue it. Modelled here with the
    // SDK's own guard shape.
    const client = makeFakeClient(async () => {});
    const calls: string[] = [];
    const t = new StreamableHTTPClientTransport(
      new URL("http://backend:3000/mcp"),
    );
    const internals = t as unknown as { _sessionId?: string };
    internals._sessionId = "session-abc";
    const terminateSession = vi.fn(async () => {
      if (!internals._sessionId) return; // mirrors the SDK's early return
      calls.push("terminate");
      internals._sessionId = undefined;
    });
    t.terminateSession =
      terminateSession as unknown as typeof t.terminateSession;
    t.close = vi.fn(async () => {
      calls.push("close");
      t.onclose?.();
    }) as unknown as typeof t.close;

    const result = await connectForTeardown(t as unknown as Transport, client);
    await result.cleanup();
    await result.cleanup();

    expect(terminateSession).toHaveBeenCalledTimes(2);
    // Only the first call reached the wire.
    expect(calls).toEqual(["terminate", "close", "close"]);
    expect(warnSpy).not.toHaveBeenCalled();
  });
});
