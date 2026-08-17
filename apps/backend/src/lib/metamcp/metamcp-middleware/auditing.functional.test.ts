import { createHash } from "node:crypto";

import { CallToolRequest } from "@modelcontextprotocol/sdk/types.js";
import { afterEach, describe, expect, it, vi } from "vitest";

import { runWithCallerContext } from "../caller-context-store";
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
    setAuditRecorderForTesting(vi.fn().mockRejectedValue(new Error("db down")));

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

describe("caller binding — request-scoped store wins over the pooled context", () => {
  // The handler context belongs to a POOLED server instance, so under
  // parallel calls on one session it describes whichever request stamped it
  // last, and the session it is reached through is resolved by namespace +
  // endpoint rather than re-derived from the credential presented now. A row
  // built from it can therefore name the wrong principal — worse than naming
  // none. The request-scoped store is the authoritative source.
  const stale: MetaMCPHandlerContext = {
    namespaceUuid: "ns-123",
    sessionId: "sess-456",
    clientName: "previous consumer",
    apiKeyUuid: "3f7f8a1e-0000-4000-8000-00000000000a",
    authMethod: "api_key",
    userId: "previous-owner",
    callerIp: "198.51.100.99",
    requestId: "req-previous",
  };

  it("attributes the call to the request in scope, not to the last stamp on the instance", async () => {
    const recorder = vi.fn().mockResolvedValue(undefined);
    setAuditRecorderForTesting(recorder);

    const wrapped = createAuditingMiddleware()(okHandler);
    await runWithCallerContext(
      {
        clientName: "live consumer",
        apiKeyUuid: "3f7f8a1e-0000-4000-8000-00000000000b",
        authMethod: "oauth",
        userId: "live-user",
        callerIp: "203.0.113.7",
        requestId: "req-live",
      },
      () => wrapped(makeRequest({ a: 1 }), stale),
    );
    await flush();

    const entry = recorder.mock.calls[0][0];
    expect(entry.client_name).toBe("live consumer");
    expect(entry.api_key_uuid).toBe("3f7f8a1e-0000-4000-8000-00000000000b");
    expect(entry.auth_method).toBe("oauth");
    expect(entry.user_id).toBe("live-user");
    expect(entry.caller_ip).toBe("203.0.113.7");
    expect(entry.request_id).toBe("req-live");
    // The namespace/session halves still come from the handler context.
    expect(entry.namespace_uuid).toBe("ns-123");
    expect(entry.session_id).toBe("sess-456");
  });

  it("never mixes the two sources — a store with gaps does not backfill from the instance", async () => {
    // Field-by-field coalescing would take api_key_uuid from the live request
    // and request_id from the stale stamp: a row that looks complete and is
    // false. One source, whole.
    const recorder = vi.fn().mockResolvedValue(undefined);
    setAuditRecorderForTesting(recorder);

    const wrapped = createAuditingMiddleware()(okHandler);
    await runWithCallerContext(
      { authMethod: "session", userId: "admin-1" },
      () => wrapped(makeRequest({ a: 1 }), stale),
    );
    await flush();

    const entry = recorder.mock.calls[0][0];
    expect(entry.auth_method).toBe("session");
    expect(entry.user_id).toBe("admin-1");
    expect(entry.api_key_uuid).toBeNull();
    expect(entry.caller_ip).toBeNull();
    expect(entry.request_id).toBeNull();
    expect(entry.client_name).toBeNull();
  });

  it("falls back to the handler context when the call runs outside any request scope", async () => {
    const recorder = vi.fn().mockResolvedValue(undefined);
    setAuditRecorderForTesting(recorder);

    const wrapped = createAuditingMiddleware()(okHandler);
    await wrapped(makeRequest({ a: 1 }), stale);
    await flush();

    const entry = recorder.mock.calls[0][0];
    expect(entry.client_name).toBe("previous consumer");
    expect(entry.request_id).toBe("req-previous");
  });

  it("records an acts-as target alongside the credential owner", async () => {
    const recorder = vi.fn().mockResolvedValue(undefined);
    setAuditRecorderForTesting(recorder);

    const wrapped = createAuditingMiddleware()(okHandler);
    await runWithCallerContext(
      {
        apiKeyUuid: "3f7f8a1e-0000-4000-8000-00000000000c",
        authMethod: "api_key",
        userId: "key-owner-1",
        actsAsUserId: "acted-as-user-1",
      },
      () => wrapped(makeRequest({ a: 1 }), stale),
    );
    await flush();

    const entry = recorder.mock.calls[0][0];
    expect(entry.user_id).toBe("key-owner-1");
    expect(entry.acts_as_user_id).toBe("acted-as-user-1");
  });
});

describe("a refused or failing call must not read as a successful one", () => {
  // An MCP tool failure is a RESULT, not a throw: a gateway denial from the
  // filter middleware (answered upstream as HTTP 403) and a backend tool's own
  // error both come back as `isError: true` with a normal resolve. Recording
  // those as success=true put them in exactly the bucket an investigation
  // filters OUT while hunting denials.
  it("writes success=false for an isError result", async () => {
    const recorder = vi.fn().mockResolvedValue(undefined);
    setAuditRecorderForTesting(recorder);
    const denied = vi.fn().mockResolvedValue({
      isError: true,
      content: [{ type: "text", text: 'Access denied to tool "search"' }],
    });

    const wrapped = createAuditingMiddleware()(denied);
    const result = await wrapped(makeRequest({ a: 1 }), context);
    await flush();

    // The result still passes through untouched — this middleware observes.
    expect(result.isError).toBe(true);
    const entry = recorder.mock.calls[0][0];
    expect(entry.success).toBe(false);
    expect(entry.error_code).toBe("tool_error");
    // Still fully attributed: a denial is the row most worth attributing.
    expect(entry.api_key_uuid).toBe("3f7f8a1e-0000-4000-8000-000000000001");
  });

  it("keeps success=true and no error code for an ordinary result", async () => {
    const recorder = vi.fn().mockResolvedValue(undefined);
    setAuditRecorderForTesting(recorder);

    const wrapped = createAuditingMiddleware()(okHandler);
    await wrapped(makeRequest({ a: 1 }), context);
    await flush();

    const entry = recorder.mock.calls[0][0];
    expect(entry.success).toBe(true);
    expect(entry.error_code).toBeUndefined();
  });
});
