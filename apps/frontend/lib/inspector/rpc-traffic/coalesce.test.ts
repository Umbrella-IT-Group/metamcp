/**
 * Which notifications fold into the row before them in the traffic log.
 *
 * Oracle: the MCP specification's notification definitions. A progress
 * notification carries a `progressToken` that names the request it reports on
 * (basic/utilities/progress); `notifications/cancelled` carries the
 * `requestId` it cancels (basic/utilities/cancellation); `notifications/message`
 * is one log line (server/utilities/logging); the `*list_changed`
 * notifications carry no parameters and mean "list again". Merging anything
 * that carries information of its own loses it from the log.
 */
import { describe, expect, it } from "vitest";

import {
  getRpcCoalesceKey,
  mergeRpcTrafficEntry,
  RPC_COALESCE_WINDOW_MS,
  shouldCoalesceWithLast,
} from "./coalesce";
import type { RpcTrafficDirection, RpcTrafficEntry } from "./types";

const T0 = Date.parse("2026-11-12T12:00:00.000Z");

function entry(
  message: unknown,
  overrides: Partial<RpcTrafficEntry> = {},
): RpcTrafficEntry {
  return {
    id: "rpc-1",
    direction: "receive",
    timestamp: new Date(T0).toISOString(),
    message,
    bytes: 10,
    ...overrides,
  };
}

const progress = (token: unknown, value = 1) => ({
  jsonrpc: "2.0",
  method: "notifications/progress",
  params: { progressToken: token, progress: value },
});

function merges(
  last: unknown,
  next: unknown,
  options: {
    direction?: RpcTrafficDirection;
    gapMs?: number;
  } = {},
): boolean {
  const direction = options.direction ?? "receive";
  return shouldCoalesceWithLast(
    entry(last),
    { direction, message: next },
    T0 + (options.gapMs ?? 10),
  );
}

describe("getRpcCoalesceKey", () => {
  it("keys a progress notification by its token", () => {
    expect(
      getRpcCoalesceKey({ direction: "receive", message: progress("a") }),
    ).not.toBeNull();
    expect(
      getRpcCoalesceKey({ direction: "receive", message: progress("a") }),
    ).toBe(
      getRpcCoalesceKey({ direction: "receive", message: progress("a", 9) }),
    );
    expect(
      getRpcCoalesceKey({ direction: "receive", message: progress("a") }),
    ).not.toBe(
      getRpcCoalesceKey({ direction: "receive", message: progress("b") }),
    );
  });

  it('keeps token 0 and token "0" apart', () => {
    expect(
      getRpcCoalesceKey({ direction: "receive", message: progress(0) }),
    ).not.toBe(
      getRpcCoalesceKey({ direction: "receive", message: progress("0") }),
    );
  });

  it("never keys a progress notification that has no usable token", () => {
    for (const token of [undefined, null, {}, [], true]) {
      expect(
        getRpcCoalesceKey({ direction: "receive", message: progress(token) }),
      ).toBeNull();
    }
  });

  it("keys the three list_changed notifications by method and direction", () => {
    const methods = [
      "notifications/tools/list_changed",
      "notifications/resources/list_changed",
      "notifications/prompts/list_changed",
    ];
    const keys = methods.map((method) =>
      getRpcCoalesceKey({
        direction: "receive",
        message: { jsonrpc: "2.0", method },
      }),
    );
    expect(keys.every((key) => key !== null)).toBe(true);
    expect(new Set(keys).size).toBe(3);
    expect(
      getRpcCoalesceKey({
        direction: "send",
        message: { jsonrpc: "2.0", method: methods[0] },
      }),
    ).not.toBe(keys[0]);
  });

  it("never keys a request or a response, whatever its method", () => {
    const notShaped = [
      { jsonrpc: "2.0", id: 1, method: "notifications/progress" },
      { jsonrpc: "2.0", id: 1, method: "tools/list" },
      { jsonrpc: "2.0", id: 1, result: {} },
      { jsonrpc: "2.0", id: 1, error: { code: -32000, message: "x" } },
      { jsonrpc: "2.0", id: 0, method: "notifications/tools/list_changed" },
    ];
    for (const message of notShaped) {
      expect(getRpcCoalesceKey({ direction: "receive", message })).toBeNull();
    }
  });

  it("never keys anything that is not a JSON-RPC object", () => {
    for (const message of [
      null,
      undefined,
      3,
      "text",
      [],
      { transportEvent: "closed" },
    ]) {
      expect(getRpcCoalesceKey({ direction: "receive", message })).toBeNull();
    }
  });
});

describe("shouldCoalesceWithLast", () => {
  it("merges progress of one token inside the window", () => {
    expect(merges(progress("a", 1), progress("a", 2))).toBe(true);
    expect(
      merges(progress("a", 1), progress("a", 2), {
        gapMs: RPC_COALESCE_WINDOW_MS,
      }),
    ).toBe(true);
  });

  it("does not merge progress of another token", () => {
    expect(merges(progress("a"), progress("b"))).toBe(false);
  });

  it("does not merge log messages, which are one line each", () => {
    const log = (text: string) => ({
      jsonrpc: "2.0",
      method: "notifications/message",
      params: { level: "info", data: text },
    });
    expect(merges(log("first"), log("second"))).toBe(false);
  });

  it("does not merge cancellations of different requests", () => {
    const cancelled = (requestId: number) => ({
      jsonrpc: "2.0",
      method: "notifications/cancelled",
      params: { requestId },
    });
    expect(merges(cancelled(1), cancelled(2))).toBe(false);
    // Not even the same request twice: a cancellation is never folded away.
    expect(merges(cancelled(1), cancelled(1))).toBe(false);
  });

  it("merges the same list_changed notification and not different ones", () => {
    const changed = (kind: string) => ({
      jsonrpc: "2.0",
      method: `notifications/${kind}/list_changed`,
    });
    for (const kind of ["tools", "resources", "prompts"]) {
      expect(merges(changed(kind), changed(kind))).toBe(true);
    }
    expect(merges(changed("tools"), changed("prompts"))).toBe(false);
  });

  it("does not merge outside the window, or when the clock went backwards", () => {
    expect(
      merges(progress("a"), progress("a"), {
        gapMs: RPC_COALESCE_WINDOW_MS + 1,
      }),
    ).toBe(false);
    expect(merges(progress("a"), progress("a"), { gapMs: -1 })).toBe(false);
  });

  it("does not merge across directions", () => {
    expect(
      shouldCoalesceWithLast(
        entry(progress("a"), { direction: "send" }),
        { direction: "receive", message: progress("a") },
        T0 + 10,
      ),
    ).toBe(false);
  });

  it("does not merge requests or responses", () => {
    const request = { jsonrpc: "2.0", id: 1, method: "tools/list" };
    const response = { jsonrpc: "2.0", id: 1, result: { tools: [] } };
    expect(merges(request, request)).toBe(false);
    expect(merges(response, response)).toBe(false);
    expect(merges(progress("a"), response)).toBe(false);
  });

  it("uses a window it is given", () => {
    expect(
      shouldCoalesceWithLast(
        entry(progress("a")),
        { direction: "receive", message: progress("a") },
        T0 + 50,
        49,
      ),
    ).toBe(false);
  });
});

describe("mergeRpcTrafficEntry", () => {
  it("shows the latest burst and counts the merge", () => {
    const first = entry(progress("a", 1), { id: "rpc-4", bytes: 80 });
    const second = mergeRpcTrafficEntry(first, {
      timestamp: "2026-11-12T12:00:00.100Z",
      message: progress("a", 2),
      bytes: 81,
    });
    expect(second).toEqual({
      id: "rpc-4",
      direction: "receive",
      timestamp: "2026-11-12T12:00:00.100Z",
      message: progress("a", 2),
      bytes: 81,
      repeatCount: 2,
    });
    const third = mergeRpcTrafficEntry(second, {
      timestamp: "2026-11-12T12:00:00.200Z",
      message: progress("a", 3),
      bytes: 81,
    });
    expect(third.repeatCount).toBe(3);
  });

  it("takes truncation from the latest burst, not the earlier row", () => {
    const truncated = entry({}, { truncated: true });
    expect(
      mergeRpcTrafficEntry(truncated, {
        timestamp: truncated.timestamp,
        message: {},
        bytes: 2,
      }).truncated,
    ).toBeUndefined();
  });
});
