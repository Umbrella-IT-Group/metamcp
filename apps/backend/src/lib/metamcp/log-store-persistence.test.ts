/**
 * The log store gained a second destination: every entry it rings also goes to
 * `gateway_events` (migration 0031) so the Live Logs view has a history that
 * survives a restart.
 *
 * Two properties are pinned here, and the second is the one that would hurt.
 *
 * COVERAGE BY CONSTRUCTION. The persistence call lives inside `record()`
 * rather than at each emitter, so a call site added later is durable without
 * anyone opting in. Testing it here is what stops a refactor from quietly
 * moving the write back out to the call sites.
 *
 * THE RING BUFFER DOES NOT DEPEND ON THE DATABASE. `record()` runs inside
 * transport error handlers and the connect retry loop. If a persistence
 * failure could break it, adding history would have made the live view — the
 * thing that already worked — fragile.
 */

import { beforeEach, describe, expect, it, vi } from "vitest";

const { loggerMock, recordGatewayEventMock } = vi.hoisted(() => ({
  loggerMock: {
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  },
  recordGatewayEventMock: vi.fn(),
}));

vi.mock("@/utils/logger", () => ({ default: loggerMock }));
vi.mock("@/lib/gateway-events/sink", () => ({
  recordGatewayEvent: recordGatewayEventMock,
}));

const { metamcpLogStore } = await import("./log-store");

beforeEach(() => {
  vi.clearAllMocks();
});

describe("record() writes to the durable history as well as the ring", () => {
  it("forwards the full envelope, flattened for the row", () => {
    metamcpLogStore.record({
      category: "connection",
      serverName: "example-backend",
      serverUuid: "11111111-1111-4111-8111-111111111111",
      level: "warn",
      message: "Transport closed unexpectedly (backend drop, 4m12s)",
      clientName: "example-consumer",
      sessionId: "session-abc",
      error: new Error("socket hang up"),
    });

    expect(recordGatewayEventMock).toHaveBeenCalledTimes(1);
    expect(recordGatewayEventMock.mock.calls[0][0]).toEqual({
      category: "connection",
      level: "warn",
      serverUuid: "11111111-1111-4111-8111-111111111111",
      serverName: "example-backend",
      clientName: "example-consumer",
      sessionId: "session-abc",
      message: "Transport closed unexpectedly (backend drop, 4m12s)",
      // The flat columns have no room for the normalized error text, so it
      // rides in metadata rather than being lost.
      metadata: { error: "socket hang up" },
    });
  });

  it("sends no metadata when there is no error to carry", () => {
    metamcpLogStore.record({
      category: "system",
      serverName: "gateway",
      level: "info",
      message: "pool warmed",
    });

    expect(recordGatewayEventMock.mock.calls[0][0].metadata).toBeUndefined();
  });

  it("covers the legacy addLog() entry point too", () => {
    metamcpLogStore.addLog("example-backend", "error", "stderr line");

    expect(recordGatewayEventMock).toHaveBeenCalledTimes(1);
    expect(recordGatewayEventMock.mock.calls[0][0]).toMatchObject({
      category: "server",
      level: "error",
      message: "stderr line",
    });
  });

  it("forwards tool_call unchanged — the SINK decides what is persisted", () => {
    // The filter deliberately lives in one place (lib/gateway-events/sink), not
    // split across the store and the sink where the two could drift.
    metamcpLogStore.record({
      category: "tool_call",
      serverName: "example-backend",
      level: "info",
      message: "example_tool (12ms)",
      toolName: "example_tool",
      durationMs: 12,
    });

    expect(recordGatewayEventMock).toHaveBeenCalledTimes(1);
    expect(recordGatewayEventMock.mock.calls[0][0].category).toBe("tool_call");
  });
});

describe("the pre-existing behaviour is independent of the history write", () => {
  it("keeps the ring entry, the stdout mirror and the listeners when the sink misbehaves", () => {
    // The sink is built so this cannot happen (`lib/gateway-events/sink` wraps
    // everything). The assertion is that the log store does not RELY on that:
    // `record()` runs inside transport onclose/onerror handlers, and adding a
    // history must not have made the live path depend on a database.
    recordGatewayEventMock.mockImplementationOnce(() => {
      throw new Error("assume the sink's own guarantees were broken");
    });

    const before = metamcpLogStore.getLogCount();
    const seen: string[] = [];
    const detach = metamcpLogStore.addListener((log) => seen.push(log.message));

    expect(() =>
      metamcpLogStore.record({
        category: "connection",
        serverName: "example-backend",
        level: "warn",
        message: "Transport error (backend drop)",
      }),
    ).toThrow();
    detach();

    // Everything the store did before this feature existed still happened: the
    // persistence call is ordered LAST precisely so a failure there cannot
    // reach any of it.
    expect(metamcpLogStore.getLogCount()).toBe(before + 1);
    expect(metamcpLogStore.getLogs(1)[0]).toMatchObject({
      message: "Transport error (backend drop)",
    });
    expect(loggerMock.warn).toHaveBeenCalledTimes(1);
    expect(seen).toEqual(["Transport error (backend drop)"]);
  });
});
