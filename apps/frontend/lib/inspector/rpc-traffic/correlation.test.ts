/**
 * Pairing a response with the request it answers.
 *
 * Oracle: JSON-RPC 2.0 section 4 (the id of a request is a string or a
 * number, and a response carries the id of the request it answers) and
 * section 5 (a response holds exactly one of `result` or `error`). Ids 0 and
 * "0" are different values. MCP lets either side send requests, so the same
 * id can be in use in both directions at once.
 */
import { describe, expect, it } from "vitest";

import { buildRpcTrafficPairs } from "./correlation";
import type { RpcTrafficDirection, RpcTrafficEntry } from "./types";

const T0 = Date.parse("2026-11-12T12:00:00.000Z");

let counter = 0;
function entry(
  direction: RpcTrafficDirection,
  message: unknown,
  atMs: number,
): RpcTrafficEntry {
  counter += 1;
  return {
    id: `rpc-${counter}`,
    direction,
    timestamp: new Date(T0 + atMs).toISOString(),
    message,
    bytes: 1,
  };
}

const request = (id: unknown, method = "tools/list") => ({
  jsonrpc: "2.0",
  id,
  method,
});
const result = (id: unknown) => ({ jsonrpc: "2.0", id, result: {} });
const failure = (id: unknown) => ({
  jsonrpc: "2.0",
  id,
  error: { code: -32601, message: "no" },
});

describe("buildRpcTrafficPairs", () => {
  it("pairs a response with its request and measures the latency", () => {
    const sent = entry("send", request(1, "tools/call"), 0);
    const received = entry("receive", result(1), 42);
    const { responseLabels, requestPairs } = buildRpcTrafficPairs([
      sent,
      received,
    ]);
    expect(responseLabels.get(received.id)).toEqual({
      requestEntryId: sent.id,
      method: "tools/call",
      latencyMs: 42,
      outcome: "result",
    });
    expect(requestPairs.get(sent.id)).toEqual({
      responseEntryId: received.id,
      latencyMs: 42,
      outcome: "result",
    });
  });

  it("reports an error response as an error", () => {
    const sent = entry("send", request(7), 0);
    const received = entry("receive", failure(7), 5);
    const { responseLabels, requestPairs } = buildRpcTrafficPairs([
      sent,
      received,
    ]);
    expect(responseLabels.get(received.id)?.outcome).toBe("error");
    expect(requestPairs.get(sent.id)?.outcome).toBe("error");
  });

  it('keeps id 0 and id "0" apart', () => {
    const sent = entry("send", request(0), 0);
    const wrong = entry("receive", result("0"), 3);
    const right = entry("receive", result(0), 6);
    const { responseLabels } = buildRpcTrafficPairs([sent, wrong, right]);
    expect(responseLabels.has(wrong.id)).toBe(false);
    expect(responseLabels.get(right.id)?.latencyMs).toBe(6);
  });

  it("does not confuse the server's request with the client's of the same id", () => {
    const clientAsks = entry("send", request(1, "tools/list"), 0);
    const serverAsks = entry(
      "receive",
      request(1, "sampling/createMessage"),
      2,
    );
    const clientAnswers = entry("send", result(1), 9);
    const serverAnswers = entry("receive", result(1), 20);
    const { responseLabels } = buildRpcTrafficPairs([
      clientAsks,
      serverAsks,
      clientAnswers,
      serverAnswers,
    ]);
    // The client's answer belongs to the server's question, and the server's
    // answer to the client's.
    expect(responseLabels.get(clientAnswers.id)).toMatchObject({
      requestEntryId: serverAsks.id,
      method: "sampling/createMessage",
      latencyMs: 7,
    });
    expect(responseLabels.get(serverAnswers.id)).toMatchObject({
      requestEntryId: clientAsks.id,
      method: "tools/list",
      latencyMs: 20,
    });
  });

  it("gives an unanswered request and an unmatched response no pair", () => {
    const lonelyRequest = entry("send", request(1), 0);
    const lonelyResponse = entry("receive", result(99), 5);
    const { responseLabels, requestPairs } = buildRpcTrafficPairs([
      lonelyRequest,
      lonelyResponse,
    ]);
    expect(responseLabels.size).toBe(0);
    expect(requestPairs.size).toBe(0);
  });

  it("pairs a response only once", () => {
    const sent = entry("send", request(1), 0);
    const first = entry("receive", result(1), 5);
    const duplicate = entry("receive", result(1), 9);
    const { responseLabels } = buildRpcTrafficPairs([sent, first, duplicate]);
    expect(responseLabels.has(first.id)).toBe(true);
    expect(responseLabels.has(duplicate.id)).toBe(false);
  });

  it("ignores a response that appears to arrive before its request", () => {
    const sent = entry("send", request(1), 10);
    const early = entry("receive", result(1), 4);
    const { responseLabels, requestPairs } = buildRpcTrafficPairs([
      sent,
      early,
    ]);
    expect(responseLabels.size).toBe(0);
    expect(requestPairs.size).toBe(0);
  });

  it("skips notifications and transport events", () => {
    const notification = entry(
      "receive",
      { jsonrpc: "2.0", method: "notifications/progress", params: {} },
      1,
    );
    const transportError = entry(
      "receive",
      { transportEvent: "error", error: "network down" },
      2,
    );
    const closed = entry("receive", { transportEvent: "closed" }, 3);
    const { responseLabels, requestPairs } = buildRpcTrafficPairs([
      notification,
      transportError,
      closed,
    ]);
    expect(responseLabels.size).toBe(0);
    expect(requestPairs.size).toBe(0);
  });

  it("skips an entry whose timestamp cannot be read", () => {
    const sent = { ...entry("send", request(1), 0), timestamp: "not a date" };
    const received = entry("receive", result(1), 5);
    expect(buildRpcTrafficPairs([sent, received]).responseLabels.size).toBe(0);
  });
});
