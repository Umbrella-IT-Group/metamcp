/**
 * The gateway-event sink's ONE contract: it must never break the thing it
 * describes.
 *
 * `recordGatewayEvent()` is called from `lib/metamcp/log-store.record()`,
 * which runs inside transport `onclose`/`onerror` handlers, the connect retry
 * loop, and the public StreamableHTTP session initialiser. A throw escaping
 * this module would not lose a history row — it would break a reconnect
 * handler or a session open. Every failure shape a sink can produce is pinned
 * here: a synchronous throw, a rejected promise (the pool-saturation case),
 * and no sink at all.
 *
 * Also pinned: the two rules that keep the table honest — `tool_call` is never
 * written here (it lives in `tool_call_audit` with more detail), and every
 * caller-supplied field is clamped before it reaches a row nothing can trim
 * for 30 days.
 */

import { GatewayEventCategorySchema } from "@repo/zod-types";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { loggerMock } = vi.hoisted(() => ({
  loggerMock: {
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  },
}));

vi.mock("@/utils/logger", () => ({ default: loggerMock }));

const {
  gatewayEventFailureCount,
  PERSISTED_CATEGORIES,
  recordGatewayEvent,
  resetGatewayEventFailureReportingForTesting,
  setGatewayEventSinkForTesting,
} = await import("./sink");

const { GATEWAY_EVENT_MESSAGE_MAX, GATEWAY_EVENT_TEXT_MAX } = await import(
  "./bounds"
);

/** Flush the detached promise chain `recordGatewayEvent()` schedules. */
const flush = () => new Promise((resolve) => setTimeout(resolve, 0));

const EVENT = {
  category: "connection",
  level: "warn",
  serverName: "example-backend",
  message: "Transport closed unexpectedly (backend drop)",
} as const;

beforeEach(() => {
  vi.clearAllMocks();
  // The drop reporter throttles to one line a minute PROCESS-WIDE, so without
  // this every case after the first would observe silence for the wrong reason
  // and assert nothing.
  resetGatewayEventFailureReportingForTesting();
});

afterEach(() => {
  setGatewayEventSinkForTesting(undefined);
});

describe("recordGatewayEvent — never breaks the caller", () => {
  it("returns void, not a promise a caller could await into a hot path", () => {
    setGatewayEventSinkForTesting(vi.fn().mockResolvedValue(undefined));
    expect(recordGatewayEvent(EVENT)).toBeUndefined();
  });

  it("does not throw when the sink REJECTS — the pool-saturation case", async () => {
    // What `db/gateway-events-db` actually produces under load: the pool is
    // capped at 2 connections with a 1s checkout timeout, so the third
    // concurrent write rejects rather than queueing. Dropping the row is
    // designed behaviour; throwing is not.
    const saturated = vi
      .fn()
      .mockRejectedValue(new Error("timeout exceeded when trying to connect"));
    setGatewayEventSinkForTesting(saturated);

    expect(() => recordGatewayEvent(EVENT)).not.toThrow();
    await flush();

    expect(saturated).toHaveBeenCalledTimes(1);
    expect(gatewayEventFailureCount()).toBe(1);
  });

  it("does not throw when the sink throws SYNCHRONOUSLY", async () => {
    setGatewayEventSinkForTesting(
      vi.fn().mockImplementation(() => {
        throw new Error("sync boom");
      }),
    );

    expect(() => recordGatewayEvent(EVENT)).not.toThrow();
    await flush();

    expect(gatewayEventFailureCount()).toBe(1);
  });

  it("does not throw when there is no sink at all", async () => {
    setGatewayEventSinkForTesting(null);

    expect(() => recordGatewayEvent(EVENT)).not.toThrow();
    await flush();

    // A disabled sink is not a failure — no database in this process is the
    // normal state for unit tests and tooling.
    expect(gatewayEventFailureCount()).toBe(0);
    expect(loggerMock.warn).not.toHaveBeenCalled();
  });
});

describe("dropped rows are reported, but do not flood the log", () => {
  it("WARNs on the first drop, with a running total", async () => {
    setGatewayEventSinkForTesting(vi.fn().mockRejectedValue(new Error("down")));

    recordGatewayEvent(EVENT);
    await flush();

    expect(loggerMock.warn).toHaveBeenCalledTimes(1);
    expect(loggerMock.warn.mock.calls[0][0]).toContain(
      "1 event row(s) lost since startup",
    );
    // WARN, not ERROR: a lost history row is a degraded record, not a failed
    // request, and a sink that pages on a database blip gets turned off.
    expect(loggerMock.error).not.toHaveBeenCalled();
  });

  it("throttles the next reports while still counting every drop", async () => {
    setGatewayEventSinkForTesting(vi.fn().mockRejectedValue(new Error("down")));

    for (let i = 0; i < 25; i += 1) {
      recordGatewayEvent(EVENT);
    }
    await flush();

    expect(gatewayEventFailureCount()).toBe(25);
    expect(loggerMock.warn).toHaveBeenCalledTimes(1);
  });
});

describe("the writer's allow-list and the reader's filter enum agree", () => {
  it("persists exactly the categories the history contract lets a caller filter on", () => {
    // Drift either way is a silent product bug: a category the writer stores but
    // the enum omits is a row nobody can filter to, and one the enum offers but
    // the writer drops is a filter that always returns nothing.
    expect([...PERSISTED_CATEGORIES].sort()).toEqual(
      [...GatewayEventCategorySchema.options].sort(),
    );
  });
});

describe("what reaches the row", () => {
  it("SKIPS tool_call — those rows live in tool_call_audit", async () => {
    const sink = vi.fn().mockResolvedValue(undefined);
    setGatewayEventSinkForTesting(sink);

    recordGatewayEvent({
      category: "tool_call",
      level: "info",
      serverName: "example-backend",
      message: "example_tool (12ms)",
    });
    await flush();

    expect(sink).not.toHaveBeenCalled();
  });

  it("persists the four categories that had no durable home", async () => {
    const sink = vi.fn().mockResolvedValue(undefined);
    setGatewayEventSinkForTesting(sink);

    for (const category of ["connection", "client", "server", "system"]) {
      recordGatewayEvent({ ...EVENT, category });
    }
    await flush();

    expect(sink).toHaveBeenCalledTimes(4);
    expect(sink.mock.calls.map((call) => call[0].category)).toEqual([
      "connection",
      "client",
      "server",
      "system",
    ]);
  });

  it("clamps the message and the identity columns", async () => {
    const sink = vi.fn().mockResolvedValue(undefined);
    setGatewayEventSinkForTesting(sink);

    recordGatewayEvent({
      category: "server",
      level: "error",
      serverName: "s".repeat(GATEWAY_EVENT_TEXT_MAX + 500),
      clientName: "c".repeat(GATEWAY_EVENT_TEXT_MAX + 500),
      sessionId: "i".repeat(GATEWAY_EVENT_TEXT_MAX + 500),
      // A backend that writes a megabyte of stderr on one line reaches the log
      // store verbatim today; the row it produces is immutable for 30 days.
      message: "m".repeat(GATEWAY_EVENT_MESSAGE_MAX + 5000),
    });
    await flush();

    const row = sink.mock.calls[0][0];
    expect(row.message).toHaveLength(GATEWAY_EVENT_MESSAGE_MAX);
    expect(row.server_name).toHaveLength(GATEWAY_EVENT_TEXT_MAX);
    expect(row.client_name).toHaveLength(GATEWAY_EVENT_TEXT_MAX);
    expect(row.session_id).toHaveLength(GATEWAY_EVENT_TEXT_MAX);
  });

  it("drops oversized metadata rather than storing half a JSON document", async () => {
    const sink = vi.fn().mockResolvedValue(undefined);
    setGatewayEventSinkForTesting(sink);

    recordGatewayEvent({
      ...EVENT,
      metadata: { error: "x".repeat(5000) },
    });
    await flush();

    expect(sink.mock.calls[0][0].metadata).toBeNull();
  });

  it("keeps small metadata, and snapshots it against later mutation", async () => {
    const sink = vi.fn().mockResolvedValue(undefined);
    setGatewayEventSinkForTesting(sink);

    const metadata: Record<string, unknown> = { error: "socket hang up" };
    recordGatewayEvent({ ...EVENT, metadata });
    // The write is detached, so a caller that mutates its own object after
    // calling must not be able to change what gets persisted.
    metadata.error = "rewritten";
    await flush();

    expect(sink.mock.calls[0][0].metadata).toEqual({
      error: "socket hang up",
    });
  });
});
