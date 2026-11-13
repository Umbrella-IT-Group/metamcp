/**
 * The traffic log's store: its limits, its snapshot contract, the initialize
 * result it captures, and which log a connect attempt writes to.
 *
 * Oracles: React's `useSyncExternalStore` contract (getSnapshot returns a
 * cached value that changes only when the store does, and subscribers are
 * told once per change), JSON-RPC 2.0 sections 4 and 5 for ids and message
 * shapes, and the MCP lifecycle specification for the initialize exchange.
 * Time, the scheduler and every limit are injected, so nothing here sleeps.
 */
import { describe, expect, it } from "vitest";

import { buildRpcTrafficPairs } from "./correlation";
import { reuseOrCreateStore, RpcTrafficStore } from "./store";
import type { RpcTrafficInput } from "./types";

function harness(
  options: ConstructorParameters<typeof RpcTrafficStore>[0] = {},
) {
  let nowMs = Date.parse("2026-11-12T12:00:00.000Z");
  const pending: (() => void)[] = [];
  const store = new RpcTrafficStore({
    now: () => nowMs,
    // A manual scheduler: nothing is emitted until flush() runs it.
    schedule: (run) => {
      pending.push(run);
    },
    ...options,
  });
  return {
    store,
    advance: (ms: number) => {
      nowMs += ms;
    },
    flush: () => {
      for (const run of pending.splice(0)) run();
    },
    scheduled: () => pending.length,
  };
}

const request = (id: unknown, method = "tools/list", params?: unknown) => ({
  jsonrpc: "2.0",
  id,
  method,
  ...(params === undefined ? {} : { params }),
});
const response = (id: unknown, result: unknown = {}) => ({
  jsonrpc: "2.0",
  id,
  result,
});
const sent = (message: unknown): RpcTrafficInput => ({
  direction: "send",
  message,
});
const received = (message: unknown): RpcTrafficInput => ({
  direction: "receive",
  message,
});

describe("entries", () => {
  it("numbers rows, stamps them from the clock and records the size", () => {
    const { store, advance } = harness();
    store.publish(sent(request(1)));
    advance(25);
    store.publish(received(response(1)));
    const [first, second] = store.exportEntries();
    expect(first).toMatchObject({
      id: "rpc-1",
      direction: "send",
      timestamp: "2026-11-12T12:00:00.000Z",
      bytes: JSON.stringify(request(1)).length,
    });
    expect(second).toMatchObject({
      id: "rpc-2",
      direction: "receive",
      timestamp: "2026-11-12T12:00:00.025Z",
    });
    expect(first?.truncated).toBeUndefined();
  });

  it("keeps the newest rows when over the entry cap", () => {
    const { store } = harness({ maxEntries: 3 });
    for (let id = 1; id <= 5; id++) store.publish(sent(request(id)));
    expect(store.size()).toBe(3);
    expect(store.exportEntries().map((row) => row.id)).toEqual([
      "rpc-3",
      "rpc-4",
      "rpc-5",
    ]);
  });
});

describe("the byte cap", () => {
  const padded = (id: number, padding: number) =>
    request(id, "tools/call", { padding: "x".repeat(padding) });

  it("drops the oldest rows first", () => {
    const size = JSON.stringify(padded(1, 100)).length;
    const { store } = harness({ maxBytes: size * 2 + 10 });
    store.publish(sent(padded(1, 100)));
    store.publish(sent(padded(2, 100)));
    expect(store.size()).toBe(2);
    store.publish(sent(padded(3, 100)));
    expect(store.exportEntries().map((row) => row.id)).toEqual([
      "rpc-2",
      "rpc-3",
    ]);
  });

  it("always keeps the newest row, even when it alone is over the cap", () => {
    const { store } = harness({ maxBytes: 10 });
    store.publish(sent(padded(1, 100)));
    store.publish(sent(padded(2, 100)));
    expect(store.exportEntries().map((row) => row.id)).toEqual(["rpc-2"]);
  });

  it("counts a merged row at its new size", () => {
    const progress = (value: number, padding: number) => ({
      jsonrpc: "2.0",
      method: "notifications/progress",
      params: { progressToken: "t", progress: value, pad: "x".repeat(padding) },
    });
    const small = JSON.stringify(progress(1, 0)).length;
    const { store } = harness({ maxBytes: small * 2 + 5 });
    store.publish(received(progress(1, 0)));
    // Merges into the row above and replaces it with a much larger one.
    store.publish(received(progress(2, small * 3)));
    expect(store.size()).toBe(1);
    // The large row alone is over the cap and is kept. Adding a second row
    // pushes it out: it is counted at its new size, not the old one.
    store.publish(sent(request(1)));
    expect(store.exportEntries().map((row) => row.direction)).toEqual(["send"]);
  });

  it("starts counting from zero after a clear", () => {
    const size = JSON.stringify(padded(1, 100)).length;
    const { store } = harness({ maxBytes: size * 2 + 10 });
    store.publish(sent(padded(1, 100)));
    store.publish(sent(padded(2, 100)));
    store.clear();
    store.publish(sent(padded(3, 100)));
    store.publish(sent(padded(4, 100)));
    expect(store.size()).toBe(2);
  });
});

describe("large messages", () => {
  const message = (padding: number) =>
    response(5, { padding: "y".repeat(padding) });

  it("stores a message at the limit intact", () => {
    const limit = JSON.stringify(message(200)).length;
    const { store } = harness({ maxMessageBytes: limit });
    store.publish(received(message(200)));
    const [row] = store.exportEntries();
    expect(row?.message).toEqual(message(200));
    expect(row?.truncated).toBeUndefined();
    expect(row?.bytes).toBe(limit);
  });

  it("keeps only the envelope of a message one character over the limit", () => {
    const limit = JSON.stringify(message(200)).length - 1;
    const { store } = harness({ maxMessageBytes: limit });
    store.publish(received(message(200)));
    const [row] = store.exportEntries();
    expect(row?.truncated).toBe(true);
    expect(row?.bytes).toBe(limit + 1);
    expect(row?.message).toEqual({
      jsonrpc: "2.0",
      id: 5,
      result: { truncated: true, bytes: limit + 1 },
    });
    expect(JSON.stringify(row?.message)).not.toContain("yyyy");
  });

  it("keeps the method and a marker for params, and an error's code and marker for its data", () => {
    const { store } = harness({ maxMessageBytes: 50 });
    store.publish(sent(request(1, "tools/call", { secret: "z".repeat(500) })));
    store.publish(
      received({
        jsonrpc: "2.0",
        id: 1,
        error: { code: -32000, message: "bad", data: "d".repeat(500) },
      }),
    );
    const [call, failed] = store.exportEntries();
    expect(call?.message).toMatchObject({
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: { truncated: true },
    });
    expect(failed?.message).toMatchObject({
      id: 1,
      error: { code: -32000, message: "bad", data: { truncated: true } },
    });
    expect(JSON.stringify(call?.message)).not.toContain("zzzz");
    expect(JSON.stringify(failed?.message)).not.toContain("dddd");
  });

  it("still pairs a truncated response with its request", () => {
    const { store } = harness({ maxMessageBytes: 50 });
    store.publish(sent(request(9, "tools/list")));
    store.publish(received(response(9, { tools: "t".repeat(500) })));
    const { responseLabels } = buildRpcTrafficPairs(store.exportEntries());
    expect([...responseLabels.values()]).toHaveLength(1);
    expect([...responseLabels.values()][0]?.method).toBe("tools/list");
  });

  it("cuts an id or method a server could make enormous", () => {
    const { store } = harness({ maxMessageBytes: 50 });
    store.publish(
      received({
        jsonrpc: "2.0",
        id: "i".repeat(5000),
        method: "m".repeat(5000),
        params: {},
      }),
    );
    const rows = store.exportEntries();
    expect(rows).toHaveLength(1);
    const message = rows[0]?.message as { id: string; method: string };
    expect(message.id.length).toBeLessThan(300);
    expect(message.method.length).toBeLessThan(300);
  });
});

describe("the snapshot", () => {
  it("is the same array until the store changes, and a new one after", () => {
    const { store, flush } = harness();
    const empty = store.getSnapshot();
    expect(store.getSnapshot()).toBe(empty);

    store.publish(sent(request(1)));
    // Rows are held at once, but the snapshot waits for the scheduler.
    expect(store.size()).toBe(1);
    expect(store.getSnapshot()).toBe(empty);

    flush();
    const first = store.getSnapshot();
    expect(first).not.toBe(empty);
    expect(first).toHaveLength(1);
    expect(store.getSnapshot()).toBe(first);

    store.publish(sent(request(2)));
    flush();
    const second = store.getSnapshot();
    expect(second).not.toBe(first);
    expect(second).toHaveLength(2);
    // An earlier snapshot is never changed under its holder.
    expect(first).toHaveLength(1);
  });

  it("tells subscribers once per emit, however many rows arrived", () => {
    const { store, flush, scheduled } = harness();
    let calls = 0;
    store.subscribe(() => {
      calls += 1;
    });
    store.publish(sent(request(1)));
    store.publish(sent(request(2)));
    store.publish(received(response(1)));
    expect(scheduled()).toBe(1);
    expect(calls).toBe(0);
    flush();
    expect(calls).toBe(1);
    store.publish(sent(request(3)));
    flush();
    expect(calls).toBe(2);
  });

  it("stops telling a subscriber that unsubscribed", () => {
    const { store, flush } = harness();
    let calls = 0;
    const unsubscribe = store.subscribe(() => {
      calls += 1;
    });
    unsubscribe();
    store.publish(sent(request(1)));
    flush();
    expect(calls).toBe(0);
  });

  it("emits at once when there is no animation frame to wait for", () => {
    const store = new RpcTrafficStore({ now: () => 0 });
    let calls = 0;
    store.subscribe(() => {
      calls += 1;
    });
    store.publish(sent(request(1)));
    expect(calls).toBe(1);
    expect(store.getSnapshot()).toHaveLength(1);
  });

  it("serves a frozen empty snapshot to a server render", () => {
    const { store } = harness();
    store.publish(sent(request(1)));
    expect(store.getServerSnapshot()).toHaveLength(0);
    expect(Object.isFrozen(store.getServerSnapshot())).toBe(true);
  });

  it("clears the rows and tells subscribers", () => {
    const { store, flush } = harness();
    store.publish(sent(request(1)));
    flush();
    let calls = 0;
    store.subscribe(() => {
      calls += 1;
    });
    store.clear();
    expect(store.size()).toBe(0);
    expect(store.exportEntries()).toEqual([]);
    flush();
    expect(calls).toBe(1);
    expect(store.getSnapshot()).toHaveLength(0);
  });

  it("exports a fresh copy read from the live rows, not the deferred snapshot", () => {
    const { store } = harness();
    store.publish(sent(request(1)));
    // The scheduler has not run (a background tab): the snapshot is stale and
    // the export is not.
    expect(store.getSnapshot()).toHaveLength(0);
    const exported = store.exportEntries();
    expect(exported).toHaveLength(1);
    exported.pop();
    expect(store.exportEntries()).toHaveLength(1);
  });
});

describe("the initialize result", () => {
  const init = { protocolVersion: "2025-11-25", serverInfo: { name: "srv" } };

  it("is available the moment the response is published, before any snapshot", () => {
    const { store } = harness();
    expect(store.initializeResult()).toBeNull();
    store.publish(sent(request(0, "initialize", { protocolVersion: "x" })));
    expect(store.initializeResult()).toBeNull();
    store.publish(received(response(0, init)));
    // The scheduler never ran: the snapshot is empty and the result is here.
    expect(store.getSnapshot()).toHaveLength(0);
    expect(store.initializeResult()).toEqual(init);
  });

  it('belongs to the response whose id matches, and id 0 is not "0"', () => {
    const { store } = harness();
    store.publish(sent(request(0, "initialize")));
    store.publish(received(response("0", { protocolVersion: "wrong" })));
    expect(store.initializeResult()).toBeNull();
    store.publish(received(response(7, { protocolVersion: "wrong" })));
    expect(store.initializeResult()).toBeNull();
    store.publish(received(response(0, init)));
    expect(store.initializeResult()).toEqual(init);
  });

  it("ignores an error response and a request of the same id from the server", () => {
    const { store } = harness();
    store.publish(sent(request(0, "initialize")));
    store.publish(
      received({ jsonrpc: "2.0", id: 0, error: { code: -1, message: "no" } }),
    );
    store.publish(received(request(0, "sampling/createMessage", { m: 1 })));
    expect(store.initializeResult()).toBeNull();
  });

  it("survives eviction of the row and a clear", () => {
    const { store } = harness({ maxEntries: 1 });
    store.publish(sent(request(0, "initialize")));
    store.publish(received(response(0, init)));
    store.publish(sent(request(1)));
    store.publish(sent(request(2)));
    expect(store.exportEntries().map((row) => row.id)).toEqual(["rpc-4"]);
    expect(store.initializeResult()).toEqual(init);
    store.clear();
    expect(store.initializeResult()).toEqual(init);
  });
});

describe("transport events", () => {
  it("records an error object once, however many routes carry it", () => {
    const { store } = harness();
    const failure = new Error("SSE error: Non-200 status code (403)");
    store.publishTransportError(failure);
    store.publishTransportError(failure);
    store.sink.transport("error", failure);
    const rows = store.exportEntries();
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      direction: "receive",
      message: {
        transportEvent: "error",
        error: "SSE error: Non-200 status code (403)",
      },
    });
  });

  it("records two different errors, even with the same text", () => {
    const { store } = harness();
    store.publishTransportError(new Error("down"));
    store.publishTransportError(new Error("down"));
    expect(store.size()).toBe(2);
  });

  it("records a thrown string each time (a primitive has no identity)", () => {
    const { store } = harness();
    store.publishTransportError("down");
    store.publishTransportError("down");
    expect(store.size()).toBe(2);
  });

  it("cuts a long error text", () => {
    const { store } = harness();
    store.publishTransportError(
      new Error(`Error POSTing: ${"b".repeat(9000)}`),
    );
    const rows = store.exportEntries();
    expect(rows).toHaveLength(1);
    const text = (rows[0]?.message as { error: string }).error;
    expect(text.length).toBeLessThan(2100);
    expect(text.startsWith("Error POSTing: bbb")).toBe(true);
  });

  it("records a close, and the sink routes both kinds", () => {
    const { store } = harness();
    store.sink.transport("closed");
    store.sink.transport("error", new Error("x"));
    store.sink.message("send", { jsonrpc: "2.0", id: 1, method: "ping" });
    expect(store.exportEntries().map((row) => row.message)).toEqual([
      { transportEvent: "closed" },
      { transportEvent: "error", error: "x" },
      { jsonrpc: "2.0", id: 1, method: "ping" },
    ]);
  });
});

describe("merging bursts", () => {
  const progress = (value: number, token = "t") => ({
    jsonrpc: "2.0",
    method: "notifications/progress",
    params: { progressToken: token, progress: value },
  });

  it("folds progress of one token into one row inside the window", () => {
    const { store, advance } = harness();
    store.publish(received(progress(1)));
    advance(100);
    store.publish(received(progress(2)));
    advance(100);
    store.publish(received(progress(3)));
    const rows = store.exportEntries();
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      repeatCount: 3,
      message: progress(3),
      timestamp: "2026-11-12T12:00:00.200Z",
    });
  });

  it("starts a new row after the window, for another token, and for a log line", () => {
    const { store, advance } = harness();
    store.publish(received(progress(1)));
    advance(400);
    store.publish(received(progress(2)));
    expect(store.size()).toBe(2);
    store.publish(received(progress(3, "other")));
    expect(store.size()).toBe(3);
    const line = (text: string) => ({
      jsonrpc: "2.0",
      method: "notifications/message",
      params: { level: "info", data: text },
    });
    store.publish(received(line("a")));
    store.publish(received(line("b")));
    expect(store.size()).toBe(5);
  });

  it("honours a window it is given", () => {
    const { store, advance } = harness({ windowMs: 10 });
    store.publish(received(progress(1)));
    advance(11);
    store.publish(received(progress(2)));
    expect(store.size()).toBe(2);
  });
});

describe("reuseOrCreateStore", () => {
  const create = () => ({ made: true });
  const previous = { made: false };

  it("makes no store when capture is off, even with one to reuse", () => {
    expect(
      reuseOrCreateStore({
        capture: false,
        previous,
        retryCount: 1,
        create,
      }),
    ).toBeNull();
  });

  it("keeps the store across a retry inside one connect", () => {
    expect(
      reuseOrCreateStore({ capture: true, previous, retryCount: 1, create }),
    ).toBe(previous);
    expect(
      reuseOrCreateStore({ capture: true, previous, retryCount: 2, create }),
    ).toBe(previous);
  });

  it("starts a new store for a new connect, so a log never outlives its target", () => {
    const fresh = reuseOrCreateStore({
      capture: true,
      previous,
      retryCount: 0,
      create,
    });
    expect(fresh).toEqual({ made: true });
    expect(fresh).not.toBe(previous);
  });

  it("makes one when there is nothing to keep", () => {
    expect(
      reuseOrCreateStore({
        capture: true,
        previous: null,
        retryCount: 1,
        create,
      }),
    ).toEqual({ made: true });
  });
});
