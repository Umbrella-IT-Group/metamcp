import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import {
  EmptyResultSchema,
  LoggingMessageNotificationSchema,
} from "@modelcontextprotocol/sdk/types.js";
import * as React from "react";
import { act } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// React's DOM renderer is the only one in this repo's dependencies, and this
// suite runs in Node with no DOM. The hook renders nothing, so the renderer
// needs only a window to read `event` from and a container to hold nothing;
// both are stubs. This runs before the imports below because react-dom reads
// the environment when it is first loaded.
vi.hoisted(() => {
  const target = globalThis as unknown as Record<string, unknown>;
  target.IS_REACT_ACT_ENVIRONMENT = true;
  target.window = {
    event: undefined,
    HTMLIFrameElement: class {},
    addEventListener() {},
    removeEventListener() {},
  };
});

vi.mock("@/lib/trpc", () => {
  const setting = { useQuery: () => ({ data: undefined }) };
  return {
    trpc: {
      frontend: {
        config: {
          getMcpTimeout: setting,
          getMcpMaxTotalTimeout: setting,
          getMcpResetTimeoutOnProgress: setting,
        },
      },
    },
  };
});

const { clearAuth } = vi.hoisted(() => ({ clearAuth: vi.fn() }));

vi.mock("@/lib/oauth-provider", () => ({
  createAuthProvider: () => ({
    tokens: async () => undefined,
    clear: clearAuth,
  }),
}));

vi.mock("@/lib/env", () => ({
  getAppUrl: () => "https://gateway.example.test",
}));

// Only the hook's own import is replaced; the SDK's transports keep the real
// module.
vi.mock("@modelcontextprotocol/sdk/client/auth.js", async (importOriginal) => ({
  ...(await importOriginal<
    typeof import("@modelcontextprotocol/sdk/client/auth.js")
  >()),
  auth: vi.fn(),
}));

import { auth } from "@modelcontextprotocol/sdk/client/auth.js";

import { useConnection } from "@/hooks/useConnection";
import { StdErrNotificationSchema } from "@/lib/notificationTypes";

import { RpcTrafficStore } from "./rpc-traffic/store";

type Props = Parameters<typeof useConnection>[0];

interface Gate {
  promise: Promise<void>;
  open: () => void;
  fail: (reason: unknown) => void;
}

function gate(): Gate {
  let open!: () => void;
  let fail!: (reason: unknown) => void;
  const promise = new Promise<void>((resolve, reject) => {
    open = resolve;
    fail = reject;
  });
  return { promise, open, fail };
}

// A started call, held in an object: an async function that returned the
// promise itself would make `await` wait for the call to finish.
interface Started {
  finished: Promise<void>;
}

const settle = () => new Promise<void>((resolve) => setTimeout(resolve, 0));

const SERVER = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const TARGET_A: Props = {
  mcpServerUuid: SERVER,
  transportType: "SSE",
  command: "",
  args: "",
  url: "/mcp-proxy/metamcp/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa/sse",
  isMetaMCP: true,
  captureTraffic: true,
};
const TARGET_B: Props = {
  ...TARGET_A,
  url: "/mcp-proxy/metamcp/bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb/sse",
};

// The network, as the hook meets it: the proxy health request (fetch) and the
// handshake (Client.connect). Each call takes the next gate from its queue and
// waits for it; with no gate left it answers at once. So a test decides, per
// attempt, which of the two finishes when.
function network() {
  const healthGates: Gate[] = [];
  const connectGates: Gate[] = [];
  const closeGates: Gate[] = [];
  const attempts: { client: Client; transport: Transport }[] = [];
  const closed: Client[] = [];
  const order: string[] = [];

  vi.stubGlobal(
    "fetch",
    vi.fn(async () => {
      const next = healthGates.shift();
      if (next) await next.promise;
      return new Response(JSON.stringify({ status: "ok" }));
    }),
  );
  vi.spyOn(Client.prototype, "connect").mockImplementation(async function (
    this: Client,
    transport: Transport,
  ) {
    attempts.push({ client: this, transport });
    const next = connectGates.shift();
    if (next) await next.promise;
    // The server's answer to initialize, as the traffic tap would see it.
    transport.onmessage?.({ jsonrpc: "2.0", id: 0, result: {} });
  } as unknown as Client["connect"]);
  vi.spyOn(Client.prototype, "close").mockImplementation(async function (
    this: Client,
  ) {
    closed.push(this);
    order.push("close");
    const next = closeGates.shift();
    if (next) await next.promise;
    // A real close ends the transport, which the tap records as a close.
    attempts.find((attempt) => attempt.client === this)?.transport.onclose?.();
  } as unknown as Client["close"]);
  vi.spyOn(
    StreamableHTTPClientTransport.prototype,
    "terminateSession",
  ).mockImplementation(async () => {
    order.push("terminateSession");
  });
  const sent = vi.spyOn(SSEClientTransport.prototype, "send");
  const notified = vi.spyOn(Client.prototype, "notification");

  return {
    healthGates,
    connectGates,
    closeGates,
    attempts,
    closed,
    order,
    sent,
    notified,
  };
}

// Mounts the real hook under a real React root and keeps the latest value it
// returned. Every call that can change state goes through act.
function mountConnection() {
  const container = {
    nodeType: 1,
    nodeName: "DIV",
    tagName: "DIV",
    namespaceURI: "http://www.w3.org/1999/xhtml",
    textContent: "",
    childNodes: [],
    ownerDocument: null,
    addEventListener() {},
    removeEventListener() {},
  };
  const root = createRoot(container as unknown as Element);
  let latest: ReturnType<typeof useConnection> | undefined;
  function Consumer(props: Props) {
    latest = useConnection(props);
    return null;
  }
  return {
    get current() {
      if (!latest) throw new Error("the hook has not rendered");
      return latest;
    },
    render: (props: Props) =>
      act(async () => {
        root.render(React.createElement(Consumer, props));
      }),
    unmount: () =>
      act(async () => {
        root.unmount();
      }),
    // Runs `work` (which starts a connect or a disconnect), lets it run until
    // it waits on a gate, and hands back what to wait for later.
    start: async (work: () => Promise<void>): Promise<Started> => {
      let finished!: Promise<void>;
      await act(async () => {
        finished = work();
        await settle();
      });
      return { finished };
    },
    // Lets a started call complete (or fail) and waits for it.
    complete: (started: Started, how?: () => void) =>
      act(async () => {
        how?.();
        await started.finished;
        await settle();
      }),
    // Runs a whole call to its end.
    run: (work: () => Promise<void>) =>
      act(async () => {
        await work();
      }),
  };
}

async function mounted(props: Props) {
  const hook = mountConnection();
  await hook.render(props);
  return hook;
}

beforeEach(() => {
  vi.spyOn(console, "error").mockImplementation(() => {});
  vi.mocked(auth).mockReset();
  clearAuth.mockClear();
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("the connection hook's attempts", () => {
  it("reports connecting while the handshake is pending, then connected", async () => {
    const net = network();
    const handshake = gate();
    net.connectGates.push(handshake);
    const hook = await mounted(TARGET_A);
    expect(hook.current.connectionStatus).toBe("disconnected");

    const started = await hook.start(() => hook.current.connect());
    expect(hook.current.connectionStatus).toBe("connecting");

    await hook.complete(started, handshake.open);
    expect(hook.current.connectionStatus).toBe("connected");
    expect(hook.current.mcpClient).toBe(net.attempts[0]?.client);
    // The current attempt's handshake is in the log the page shows.
    expect(hook.current.rpcTraffic?.exportEntries()).toHaveLength(1);
  });

  // Both ways a second attempt can supersede the first: the page connects to
  // another target, and a second connect() on the same target (a double click,
  // or an effect that runs twice).
  describe.each([
    ["after a target change", true],
    ["on the same target", false],
  ])("when a second connect starts %s", (_name, switchTarget) => {
    const supersede = async (hook: Awaited<ReturnType<typeof mounted>>) => {
      if (switchTarget) await hook.render(TARGET_B);
      await hook.run(() => hook.current.connect());
    };

    it("keeps the later attempt active when the earlier one completes last", async () => {
      const net = network();
      const first = gate();
      net.connectGates.push(first);
      const hook = await mounted(TARGET_A);

      const slow = await hook.start(() => hook.current.connect());
      const logOfA = hook.current.rpcTraffic;
      await supersede(hook);
      const [attemptA, attemptB] = net.attempts;
      expect(net.attempts).toHaveLength(2);
      expect(hook.current.mcpClient).toBe(attemptB?.client);
      expect(hook.current.connectionStatus).toBe("connected");
      const logOfB = hook.current.rpcTraffic;
      expect(logOfB).toBeInstanceOf(RpcTrafficStore);
      expect(logOfB).not.toBe(logOfA);
      expect(logOfB?.exportEntries()).toHaveLength(1);

      await hook.complete(slow, first.open);

      // The earlier attempt finished last and must change nothing the page
      // sees, must close what it opened, and must write nothing to either log
      // (its handshake answer and its close).
      expect(hook.current.mcpClient).toBe(attemptB?.client);
      expect(hook.current.connectionStatus).toBe("connected");
      expect(hook.current.rpcTraffic).toBe(logOfB);
      expect(net.closed).toEqual([attemptA?.client]);
      expect(logOfB?.exportEntries()).toHaveLength(1);
      expect(logOfA?.exportEntries()).toEqual([]);
    });

    it("does not let a superseded failure overwrite a newer success", async () => {
      const net = network();
      const first = gate();
      net.connectGates.push(first);
      const published = vi.spyOn(
        RpcTrafficStore.prototype,
        "publishTransportError",
      );
      const hook = await mounted(TARGET_A);

      const slow = await hook.start(() => hook.current.connect());
      await supersede(hook);
      const [attemptA, attemptB] = net.attempts;

      await hook.complete(slow, () =>
        first.fail(new Error("handshake refused")),
      );

      expect(hook.current.connectionStatus).toBe("connected");
      expect(hook.current.mcpClient).toBe(attemptB?.client);
      expect(published).not.toHaveBeenCalled();
      expect(console.error).not.toHaveBeenCalled();
      expect(net.closed).toEqual([attemptA?.client]);
    });

    it("does not let a superseded proxy health check connect", async () => {
      const net = network();
      const health = gate();
      net.healthGates.push(health);
      const hook = await mounted(TARGET_A);

      const slow = await hook.start(() => hook.current.connect());
      expect(hook.current.connectionStatus).toBe("connecting");
      await supersede(hook);
      expect(net.attempts).toHaveLength(1);

      // It answers healthy, late: it must not go on to open a connection.
      await hook.complete(slow, health.open);
      expect(net.attempts).toHaveLength(1);
      expect(hook.current.mcpClient).toBe(net.attempts[0]?.client);
      expect(hook.current.connectionStatus).toBe("connected");
    });

    it("does not let a superseded proxy health failure report or overwrite", async () => {
      const net = network();
      const health = gate();
      net.healthGates.push(health);
      const published = vi.spyOn(
        RpcTrafficStore.prototype,
        "publishTransportError",
      );
      const hook = await mounted(TARGET_A);

      const slow = await hook.start(() => hook.current.connect());
      await supersede(hook);

      await hook.complete(slow, () =>
        health.fail(new TypeError("unreachable")),
      );

      expect(published).not.toHaveBeenCalled();
      expect(hook.current.connectionStatus).toBe("connected");
      expect(hook.current.mcpClient).toBe(net.attempts[0]?.client);
    });

    it("does not start the sign-in flow or retry for a superseded attempt", async () => {
      const net = network();
      const first = gate();
      net.connectGates.push(first);
      vi.stubGlobal("sessionStorage", {
        setItem: vi.fn(),
        getItem: vi.fn(),
        removeItem: vi.fn(),
      });
      vi.mocked(auth).mockResolvedValue("AUTHORIZED");
      const hook = await mounted(TARGET_A);

      const slow = await hook.start(() => hook.current.connect());
      await supersede(hook);
      expect(net.attempts).toHaveLength(2);

      await hook.complete(slow, () =>
        first.fail(new Error("401 Unauthorized")),
      );

      expect(auth).not.toHaveBeenCalled();
      expect(net.attempts).toHaveLength(2);
      expect(hook.current.connectionStatus).toBe("connected");
      expect(hook.current.mcpClient).toBe(net.attempts[1]?.client);
    });
  });

  it("still retries once after a sign-in and keeps the failed attempt's log", async () => {
    const net = network();
    const first = gate();
    net.connectGates.push(first);
    vi.stubGlobal("sessionStorage", {
      setItem: vi.fn(),
      getItem: vi.fn(),
      removeItem: vi.fn(),
    });
    vi.mocked(auth).mockResolvedValue("AUTHORIZED");
    const hook = await mounted(TARGET_A);

    const started = await hook.start(() => hook.current.connect());
    const logOfFirst = hook.current.rpcTraffic;
    await hook.complete(started, () =>
      first.fail(new Error("401 Unauthorized")),
    );

    expect(auth).toHaveBeenCalledTimes(1);
    expect(net.attempts).toHaveLength(2);
    expect(hook.current.connectionStatus).toBe("connected");
    expect(hook.current.mcpClient).toBe(net.attempts[1]?.client);
    expect(hook.current.rpcTraffic).toBe(logOfFirst);
  });

  it("does not let an attempt finish after disconnect", async () => {
    const net = network();
    const handshake = gate();
    net.connectGates.push(handshake);
    const hook = await mounted(TARGET_A);

    const started = await hook.start(() => hook.current.connect());
    expect(hook.current.connectionStatus).toBe("connecting");
    await hook.run(() => hook.current.disconnect());
    expect(hook.current.connectionStatus).toBe("disconnected");

    await hook.complete(started, handshake.open);
    expect(hook.current.connectionStatus).toBe("disconnected");
    expect(hook.current.mcpClient).toBeNull();
    expect(net.closed).toEqual([net.attempts[0]?.client]);
    // A disconnect leaves the log in place, so it is still the one on screen:
    // the abandoned attempt's late answer and its close are not added to it.
    expect(hook.current.rpcTraffic?.exportEntries()).toEqual([]);
  });

  it("does not let an attempt for the old target finish after a target change", async () => {
    const net = network();
    const handshake = gate();
    net.connectGates.push(handshake);
    const hook = await mounted(TARGET_A);

    const started = await hook.start(() => hook.current.connect());
    expect(hook.current.connectionStatus).toBe("connecting");
    // The page moved to another target and has not connected to it (yet).
    await hook.render(TARGET_B);
    expect(hook.current.connectionStatus).toBe("disconnected");

    await hook.complete(started, handshake.open);
    expect(hook.current.connectionStatus).toBe("disconnected");
    expect(hook.current.mcpClient).toBeNull();
    expect(net.closed).toEqual([net.attempts[0]?.client]);
  });

  it("closes an attempt still in flight when the page unmounts, and sends no cancellation", async () => {
    const net = network();
    const handshake = gate();
    net.connectGates.push(handshake);
    const hook = await mounted(TARGET_A);

    const started = await hook.start(() => hook.current.connect());
    await hook.unmount();
    await hook.complete(started, handshake.open);

    expect(net.closed).toEqual([net.attempts[0]?.client]);
    expect(net.sent).not.toHaveBeenCalled();
    expect(net.notified).not.toHaveBeenCalled();
  });

  it("ends the session of an abandoned streamable HTTP attempt before closing it", async () => {
    const net = network();
    const first = gate();
    net.connectGates.push(first);
    const streamable: Props = {
      mcpServerUuid: SERVER,
      transportType: "STREAMABLE_HTTP",
      command: "",
      args: "",
      url: "https://backend.example.test/mcp",
      captureTraffic: true,
    };
    const hook = await mounted(streamable);

    const slow = await hook.start(() => hook.current.connect());
    await hook.run(() => hook.current.connect());
    net.order.length = 0;

    await hook.complete(slow, first.open);

    // close() aborts the transport's controller, so a DELETE issued after it
    // could never reach the wire: terminate first, then close.
    expect(net.order).toEqual(["terminateSession", "close"]);
  });

  it("reconnects the way the page does, disconnect and then connect, and ends connected", async () => {
    const net = network();
    const hook = await mounted(TARGET_A);
    await hook.run(() => hook.current.connect());
    expect(hook.current.connectionStatus).toBe("connected");

    // The second handshake is still pending when React renders the
    // "connecting" status; the status leaving "connected" must not make the
    // hook disconnect the attempt that has just started.
    const handshake = gate();
    net.connectGates.push(handshake);
    await hook.render(TARGET_B);
    const started = await hook.start(async () => {
      await hook.current.disconnect();
      await hook.current.connect();
    });
    expect(hook.current.connectionStatus).toBe("connecting");

    await hook.complete(started, handshake.open);
    expect(hook.current.connectionStatus).toBe("connected");
    expect(hook.current.mcpClient).toBe(net.attempts[1]?.client);
    expect(net.closed).toEqual([net.attempts[0]?.client]);
  });

  it("keeps a newer connection when an earlier disconnect finishes last", async () => {
    const net = network();
    const hook = await mounted(TARGET_A);
    await hook.run(() => hook.current.connect());
    const close = gate();
    net.closeGates.push(close);
    const disconnecting = await hook.start(() => hook.current.disconnect());

    await hook.render(TARGET_B);
    await hook.run(() => hook.current.connect());
    const newer = net.attempts[1]?.client;
    expect(hook.current.mcpClient).toBe(newer);

    await hook.complete(disconnecting, close.open);
    expect(clearAuth).not.toHaveBeenCalled();
    expect(hook.current.mcpClient).toBe(newer);
    expect(hook.current.connectionStatus).toBe("connected");
    expect(net.closed).toEqual([net.attempts[0]?.client]);
    await hook.unmount();
  });

  it.each(["SSE", "STREAMABLE_HTTP"] as const)(
    "closes the previous transport when the target changes to %s",
    async (nextType) => {
      const net = network();
      const previousType = nextType === "SSE" ? "STREAMABLE_HTTP" : "SSE";
      const hook = await mounted({
        ...TARGET_A,
        isMetaMCP: false,
        transportType: previousType,
      });
      await hook.run(() => hook.current.connect());
      await hook.render({
        ...TARGET_B,
        isMetaMCP: false,
        transportType: nextType,
      });
      net.order.length = 0;

      await hook.run(() => hook.current.disconnect());
      expect(net.order).toEqual(
        previousType === "STREAMABLE_HTTP"
          ? ["terminateSession", "close"]
          : ["close"],
      );
      expect(net.closed).toEqual([net.attempts[0]?.client]);
      await hook.unmount();
    },
  );

  it("closes a published connection before replacing it with another connect", async () => {
    const net = network();
    const hook = await mounted(TARGET_A);
    await hook.run(() => hook.current.connect());
    const handshake = gate();
    net.connectGates.push(handshake);

    const replacement = await hook.start(() => hook.current.connect());
    expect(hook.current.connectionStatus).toBe("connecting");
    expect(hook.current.mcpClient).toBeNull();
    expect(net.closed).toEqual([net.attempts[0]?.client]);

    await hook.complete(replacement, handshake.open);
    expect(hook.current.mcpClient).toBe(net.attempts[1]?.client);
    await hook.unmount();
    expect(net.closed).toEqual(net.attempts.map(({ client }) => client));
  });

  it("does not run a queued reconnect after unmount", async () => {
    const net = network();
    const hook = await mounted(TARGET_A);
    await hook.run(() => hook.current.connect());
    const close = gate();
    net.closeGates.push(close);
    const reconnect = await hook.start(async () => {
      await hook.current.disconnect();
      await hook.current.connect();
    });

    await hook.unmount();
    await hook.complete(reconnect, close.open);
    expect(net.attempts).toHaveLength(1);
    expect(net.closed).toEqual([net.attempts[0]?.client]);
  });

  it("invalidates a pending attempt as soon as the hook is disabled", async () => {
    const net = network();
    const handshake = gate();
    net.connectGates.push(handshake);
    const hook = await mounted(TARGET_A);
    const pending = await hook.start(() => hook.current.connect());

    await hook.render({ ...TARGET_A, enabled: false });
    expect(hook.current.connectionStatus).toBe("disconnected");
    await hook.complete(pending, handshake.open);
    expect(hook.current.mcpClient).toBeNull();
    expect(hook.current.rpcTraffic?.exportEntries()).toEqual([]);
    expect(net.closed).toEqual([net.attempts[0]?.client]);
    await hook.unmount();
  });

  it("ignores late notifications from a superseded handshake", async () => {
    const net = network();
    const handshake = gate();
    net.connectGates.push(handshake);
    const onNotification = vi.fn();
    const onStdErrNotification = vi.fn();
    const registered = vi.spyOn(Client.prototype, "setNotificationHandler");
    const hook = await mounted({
      ...TARGET_A,
      onNotification,
      onStdErrNotification,
    });
    const pending = await hook.start(() => hook.current.connect());
    const first = net.attempts[0]?.client;
    const handlers = registered.mock.calls
      .filter(
        ([schema], index) =>
          registered.mock.contexts[index] === first &&
          (schema === LoggingMessageNotificationSchema ||
            schema === StdErrNotificationSchema),
      )
      .map(([, handler]) => handler);
    expect(handlers).toHaveLength(2);
    await hook.run(async () => {
      for (const handler of handlers) {
        await handler({ method: "notifications/test" });
      }
      await first?.fallbackNotificationHandler?.({
        method: "notifications/test",
      });
    });
    expect(onNotification).toHaveBeenCalledTimes(2);
    expect(onStdErrNotification).toHaveBeenCalledOnce();
    onNotification.mockClear();
    onStdErrNotification.mockClear();

    await hook.render({ ...TARGET_B, onNotification, onStdErrNotification });
    await hook.run(() => hook.current.connect());
    await hook.run(async () => {
      for (const handler of handlers) {
        await handler({ method: "notifications/test" });
      }
      await first?.fallbackNotificationHandler?.({
        method: "notifications/test",
      });
    });

    expect(onNotification).not.toHaveBeenCalled();
    expect(onStdErrNotification).not.toHaveBeenCalled();
    await hook.complete(pending, handshake.open);
    await hook.unmount();
  });

  it.each(["request", "notification"] as const)(
    "refuses a %s through a connection that is still closing",
    async (kind) => {
      const net = network();
      const requested = vi
        .spyOn(Client.prototype, "request")
        .mockResolvedValue({});
      net.notified.mockResolvedValue(undefined);
      const hook = await mounted(TARGET_A);
      await hook.run(() => hook.current.connect());
      const close = gate();
      net.closeGates.push(close);
      const disconnecting = await hook.start(() => hook.current.disconnect());

      await expect(
        kind === "request"
          ? hook.current.makeRequest({ method: "ping" }, EmptyResultSchema)
          : hook.current.sendNotification({
              method: "notifications/roots/list_changed",
            }),
      ).rejects.toThrow("MCP client not connected");
      expect(requested).not.toHaveBeenCalled();
      expect(net.notified).not.toHaveBeenCalled();
      await hook.complete(disconnecting, close.open);
      await hook.unmount();
    },
  );

  it("ignores progress from a request on a connection that has been replaced", async () => {
    const net = network();
    const requested = vi
      .spyOn(Client.prototype, "request")
      .mockResolvedValue({});
    const onNotification = vi.fn();
    const hook = await mounted({ ...TARGET_A, onNotification });
    await hook.run(() => hook.current.connect());
    await hook.current.makeRequest({ method: "ping" }, EmptyResultSchema, {
      resetTimeoutOnProgress: true,
    });
    const onprogress = requested.mock.calls[0]?.[2]?.onprogress;
    expect(onprogress).toBeTypeOf("function");
    onprogress?.({ progress: 1 });
    expect(onNotification).toHaveBeenCalledOnce();
    onNotification.mockClear();

    const close = gate();
    net.closeGates.push(close);
    const disconnecting = await hook.start(() => hook.current.disconnect());
    await hook.render({ ...TARGET_B, onNotification });
    await hook.run(() => hook.current.connect());
    onprogress?.({ progress: 2 });
    expect(onNotification).not.toHaveBeenCalled();
    await hook.complete(disconnecting, close.open);
    await hook.unmount();
  });

  it("still closes a client when ending its streamable session fails", async () => {
    const net = network();
    const hook = await mounted({
      ...TARGET_A,
      isMetaMCP: false,
      transportType: "STREAMABLE_HTTP",
    });
    await hook.run(() => hook.current.connect());
    const failure = new Error("session DELETE refused");
    vi.mocked(
      StreamableHTTPClientTransport.prototype.terminateSession,
    ).mockRejectedValueOnce(failure);

    await hook.run(() => hook.current.disconnect());
    expect(net.closed).toEqual([net.attempts[0]?.client]);
    expect(console.error).toHaveBeenCalledWith(
      "Error ending MCP session:",
      failure,
    );
    expect(hook.current.connectionStatus).toBe("disconnected");
    await hook.unmount();
  });

  it("keeps the sign-in verifier on unmount and ignores a late authorization result", async () => {
    const net = network();
    const handshake = gate();
    net.connectGates.push(handshake);
    const signingIn = gate();
    vi.mocked(auth).mockImplementation(async () => {
      await signingIn.promise;
      return "AUTHORIZED";
    });
    vi.stubGlobal("sessionStorage", {
      setItem: vi.fn(),
      getItem: vi.fn(),
      removeItem: vi.fn(),
    });
    const hook = await mounted(TARGET_A);
    const pending = await hook.start(() => hook.current.connect());
    await hook.run(async () => {
      handshake.fail(new Error("401 Unauthorized"));
      await settle();
    });
    expect(auth).toHaveBeenCalledOnce();

    // OAuth can navigate away while connect() is still awaiting auth().
    // Clearing credentials here would delete the callback's code verifier.
    await hook.unmount();
    expect(clearAuth).not.toHaveBeenCalled();
    await hook.complete(pending, signingIn.open);
    expect(net.attempts).toHaveLength(1);
    expect(net.closed).toEqual([net.attempts[0]?.client]);
  });

  it("leaves connecting after an unload cancels a pending handshake", async () => {
    const net = network();
    const handshake = gate();
    net.connectGates.push(handshake);
    const registered = vi.spyOn(window, "addEventListener");
    const hook = await mounted(TARGET_A);
    const pending = await hook.start(() => hook.current.connect());
    const beforeUnload = registered.mock.calls.find(
      ([event]) => event === "beforeunload",
    )?.[1];
    expect(beforeUnload).toBeTypeOf("function");

    // Navigation can be cancelled by another beforeunload listener. The page
    // must then show disconnected instead of an attempt it has invalidated.
    await hook.run(async () => {
      if (typeof beforeUnload === "function") {
        beforeUnload(new Event("beforeunload"));
      }
    });
    expect(hook.current.connectionStatus).toBe("disconnected");
    expect(clearAuth).not.toHaveBeenCalled();
    await hook.complete(pending, handshake.open);
    expect(hook.current.mcpClient).toBeNull();
    expect(hook.current.connectionStatus).toBe("disconnected");
    expect(net.closed).toEqual([net.attempts[0]?.client]);
    await hook.unmount();
  });
});
