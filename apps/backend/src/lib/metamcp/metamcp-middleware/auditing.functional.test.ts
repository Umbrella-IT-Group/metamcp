import { createHash } from "node:crypto";

import { CallToolRequest } from "@modelcontextprotocol/sdk/types.js";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  createAuditingMiddleware,
  setAuditRecorderForTesting,
} from "./auditing.functional";
import { MetaMCPHandlerContext } from "./functional-middleware";

const context: MetaMCPHandlerContext = {
  namespaceUuid: "ns-123",
  sessionId: "sess-456",
  clientName: "Tara connector",
};

const makeRequest = (args?: Record<string, unknown>): CallToolRequest =>
  ({
    method: "tools/call",
    params: { name: "autotask__search", arguments: args },
  }) as CallToolRequest;

const okHandler = vi.fn().mockResolvedValue({ content: [] });

// Flush the fire-and-forget persist() chain (resolveRecorder().then(...)).
const flush = () => new Promise((r) => setTimeout(r, 0));

afterEach(() => {
  // Reset the module-level recorder cache so no test leaks its sink.
  setAuditRecorderForTesting(null);
  vi.clearAllMocks();
});

describe("auditing middleware DB write-through", () => {
  it("persists a success row with parsed server/tool, identity, and latency", async () => {
    const recorder = vi.fn().mockResolvedValue(undefined);
    setAuditRecorderForTesting(recorder);

    const wrapped = createAuditingMiddleware()(okHandler);
    await wrapped(makeRequest({ q: "printer" }), context);
    await flush();

    expect(recorder).toHaveBeenCalledTimes(1);
    const entry = recorder.mock.calls[0][0];
    expect(entry.server_name).toBe("autotask");
    expect(entry.tool_name).toBe("search");
    expect(entry.client_name).toBe("Tara connector");
    expect(entry.namespace_uuid).toBe("ns-123");
    expect(entry.session_id).toBe("sess-456");
    expect(entry.success).toBe(true);
    expect(entry.error_code).toBeUndefined();
    expect(entry.latency_ms).toBeGreaterThanOrEqual(0);
  });

  it("hashes params with sha256 and never persists raw arguments", async () => {
    const recorder = vi.fn().mockResolvedValue(undefined);
    setAuditRecorderForTesting(recorder);
    const args = { password: "hunter2-super-secret" };

    const wrapped = createAuditingMiddleware()(okHandler);
    await wrapped(makeRequest(args), context);
    await flush();

    const entry = recorder.mock.calls[0][0];
    expect(entry.params_hash).toBe(
      createHash("sha256").update(JSON.stringify(args)).digest("hex"),
    );
    expect(JSON.stringify(entry)).not.toContain("hunter2-super-secret");
  });

  it("persists null params_hash when the call has no arguments", async () => {
    const recorder = vi.fn().mockResolvedValue(undefined);
    setAuditRecorderForTesting(recorder);

    const wrapped = createAuditingMiddleware()(okHandler);
    await wrapped(makeRequest(undefined), context);
    await flush();

    expect(recorder.mock.calls[0][0].params_hash).toBeNull();
  });

  it("persists a failure row with the error's code and rethrows", async () => {
    const recorder = vi.fn().mockResolvedValue(undefined);
    setAuditRecorderForTesting(recorder);
    const failing = vi
      .fn()
      .mockRejectedValue(Object.assign(new Error("boom"), { code: -32602 }));

    const wrapped = createAuditingMiddleware()(failing);
    await expect(wrapped(makeRequest({ a: 1 }), context)).rejects.toThrow(
      "boom",
    );
    await flush();

    const entry = recorder.mock.calls[0][0];
    expect(entry.success).toBe(false);
    expect(entry.error_code).toBe("-32602");
  });

  it("falls back to the error class name when there is no code", async () => {
    const recorder = vi.fn().mockResolvedValue(undefined);
    setAuditRecorderForTesting(recorder);
    const failing = vi.fn().mockRejectedValue(new TypeError("bad shape"));

    const wrapped = createAuditingMiddleware()(failing);
    await expect(wrapped(makeRequest(), context)).rejects.toThrow("bad shape");
    await flush();

    expect(recorder.mock.calls[0][0].error_code).toBe("TypeError");
  });

  it("never fails the tool call when the audit write rejects", async () => {
    setAuditRecorderForTesting(
      vi.fn().mockRejectedValue(new Error("db down")),
    );

    const wrapped = createAuditingMiddleware()(okHandler);
    const result = await wrapped(makeRequest({ a: 1 }), context);
    await flush();

    expect(result).toEqual({ content: [] });
  });

  it("is inert when persistence is disabled (recorder=null)", async () => {
    setAuditRecorderForTesting(null);

    const wrapped = createAuditingMiddleware()(okHandler);
    const result = await wrapped(makeRequest({ a: 1 }), context);
    await flush();

    expect(result).toEqual({ content: [] });
    expect(okHandler).toHaveBeenCalledTimes(1);
  });
});
