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
  clientName: "example connector",
  apiKeyUuid: "3f7f8a1e-0000-4000-8000-000000000001",
  authMethod: "api_key",
  userId: "user-owner-1",
  callerIp: "203.0.113.7",
  requestId: "req-aaaa",
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
    expect(entry.client_name).toBe("example connector");
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

describe("caller binding (migration 0030)", () => {
  it("carries the credential, method, account, address and request id onto the row", async () => {
    const recorder = vi.fn().mockResolvedValue(undefined);
    setAuditRecorderForTesting(recorder);

    const wrapped = createAuditingMiddleware()(okHandler);
    await wrapped(makeRequest({ q: "printer" }), context);
    await flush();

    const entry = recorder.mock.calls[0][0];
    expect(entry.api_key_uuid).toBe("3f7f8a1e-0000-4000-8000-000000000001");
    expect(entry.auth_method).toBe("api_key");
    expect(entry.user_id).toBe("user-owner-1");
    expect(entry.caller_ip).toBe("203.0.113.7");
    expect(entry.request_id).toBe("req-aaaa");
  });

  it("carries the same binding onto a FAILURE row", async () => {
    // A denied or failing call is the one an investigation reads first, so it
    // must be as attributable as a successful one.
    const recorder = vi.fn().mockResolvedValue(undefined);
    setAuditRecorderForTesting(recorder);
    const failing = vi
      .fn()
      .mockRejectedValue(Object.assign(new Error("denied"), { code: -32602 }));

    const wrapped = createAuditingMiddleware()(failing);
    await expect(wrapped(makeRequest({ a: 1 }), context)).rejects.toThrow(
      "denied",
    );
    await flush();

    const entry = recorder.mock.calls[0][0];
    expect(entry.success).toBe(false);
    expect(entry.api_key_uuid).toBe("3f7f8a1e-0000-4000-8000-000000000001");
    expect(entry.user_id).toBe("user-owner-1");
    expect(entry.caller_ip).toBe("203.0.113.7");
    expect(entry.request_id).toBe("req-aaaa");
  });

  it("writes NULLs without throwing when no identity was resolved", async () => {
    // An unauthenticated / passthrough endpoint resolves none of these. The
    // row must still land: dropping it would leave the call unrecorded
    // entirely, which is strictly worse than recording it un-attributed.
    const recorder = vi.fn().mockResolvedValue(undefined);
    setAuditRecorderForTesting(recorder);
    const bare: MetaMCPHandlerContext = {
      namespaceUuid: "ns-123",
      sessionId: "sess-456",
    };

    const wrapped = createAuditingMiddleware()(okHandler);
    const result = await wrapped(makeRequest({ a: 1 }), bare);
    await flush();

    expect(result).toEqual({ content: [] });
    const entry = recorder.mock.calls[0][0];
    expect(entry.api_key_uuid).toBeNull();
    expect(entry.auth_method).toBeNull();
    expect(entry.user_id).toBeNull();
    expect(entry.caller_ip).toBeNull();
    expect(entry.request_id).toBeNull();
    // The rest of the row is unaffected.
    expect(entry.server_name).toBe("autotask");
    expect(entry.success).toBe(true);
  });

  it("gives two calls on one session distinct request ids", async () => {
    // The regression this guards: `clientName` is stamped once at session
    // creation, and copying that pattern for `requestId` would brand every
    // call in a long-lived session with the initialize request's id.
    const recorder = vi.fn().mockResolvedValue(undefined);
    setAuditRecorderForTesting(recorder);

    const wrapped = createAuditingMiddleware()(okHandler);
    await wrapped(makeRequest({ a: 1 }), { ...context, requestId: "req-one" });
    await wrapped(makeRequest({ a: 2 }), { ...context, requestId: "req-two" });
    await flush();

    expect(recorder).toHaveBeenCalledTimes(2);
    expect(recorder.mock.calls[0][0].request_id).toBe("req-one");
    expect(recorder.mock.calls[1][0].request_id).toBe("req-two");
    // Same session id on both — the session is not the discriminator.
    expect(recorder.mock.calls[0][0].session_id).toBe(
      recorder.mock.calls[1][0].session_id,
    );
  });
});
