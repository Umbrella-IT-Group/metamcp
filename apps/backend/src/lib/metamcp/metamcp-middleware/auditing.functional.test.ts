import { createHash } from "node:crypto";

import { CallToolRequest } from "@modelcontextprotocol/sdk/types.js";
import {
  afterAll,
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";

import logger from "@/utils/logger";

import { runWithCallerContext } from "../caller-context-store";
import { metamcpLogStore } from "../log-store";
import {
  recordToolArgSchema,
  resetToolArgSchemasForTest,
} from "../tool-arg-keys";
import {
  createAuditingMiddleware,
  setAuditRecorderForTesting,
} from "./auditing.functional";
import { MetaMCPHandlerContext } from "./functional-middleware";
import { markRetiredToolResult } from "./retired-tool-marker";

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

// The audit stores only names the tool's own schema declares (tool-arg-keys.ts).
// Every request below calls autotask__search, declared here as a listing would.
beforeEach(() => {
  recordToolArgSchema("autotask__search", {
    type: "object",
    properties: {
      mode: {},
      ticket: {},
      note: {},
      action: {},
      identifier: {},
      company: {},
    },
  });
});
afterAll(() => resetToolArgSchemasForTest());

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

describe("args_shape (migration 0039)", () => {
  it("an unlisted tool name stores counts only, never caller-chosen names", async () => {
    const recorder = vi.fn().mockResolvedValue(undefined);
    setAuditRecorderForTesting(recorder);
    const wrapped = createAuditingMiddleware()(okHandler);
    await wrapped(
      {
        method: "tools/call",
        params: {
          name: "autotask__unlisted",
          arguments: { mode: "x", Alice_Smith: 1 },
        },
      } as CallToolRequest,
      context,
    );
    await flush();
    expect(recorder.mock.calls[0][0].args_shape).toEqual({
      keys: [],
      unverified_keys: 2,
    });
  });

  it("records the shape on a success row, never the values", async () => {
    const recorder = vi.fn().mockResolvedValue(undefined);
    setAuditRecorderForTesting(recorder);

    const wrapped = createAuditingMiddleware()(okHandler);
    await wrapped(
      makeRequest({ mode: "note_add", ticket: 123, note: { text: "secret" } }),
      context,
    );
    await flush();

    const entry = recorder.mock.calls[0][0];
    expect(entry.args_shape).toEqual({
      sel: { mode: "note_add" },
      keys: ["mode", "note", "ticket"],
    });
    expect(JSON.stringify(entry.args_shape)).not.toMatch(/secret|123/);
  });

  it("records the shape on a failure row (thrown error) too", async () => {
    const recorder = vi.fn().mockResolvedValue(undefined);
    setAuditRecorderForTesting(recorder);
    const failing = vi.fn().mockRejectedValue(new Error("boom"));

    const wrapped = createAuditingMiddleware()(failing);
    await expect(
      wrapped(makeRequest({ action: "run_script", identifier: "d1" }), context),
    ).rejects.toThrow("boom");
    await flush();

    expect(recorder.mock.calls[0][0].args_shape).toEqual({
      sel: { action: "run_script" },
      keys: ["action", "identifier"],
    });
  });

  it("records an empty shape (not null) for a call with no arguments", async () => {
    const recorder = vi.fn().mockResolvedValue(undefined);
    setAuditRecorderForTesting(recorder);

    const wrapped = createAuditingMiddleware()(okHandler);
    await wrapped(makeRequest(undefined), context);
    await flush();

    // `params_hash` is null for this call, but the shape is still recorded:
    // args_shape IS NOT NULL is the marker for "a post-0039 row".
    expect(recorder.mock.calls[0][0].args_shape).toEqual({ keys: [] });
  });

  it("is computed from the ORIGINAL arguments even when an inner middleware rewrites the request", async () => {
    const recorder = vi.fn().mockResolvedValue(undefined);
    setAuditRecorderForTesting(recorder);
    const rewriting = vi.fn().mockImplementation(async (request) => {
      // An inner layer (the override middleware builds a new request) may
      // mutate what it was handed; the audit shape was taken at entry.
      request.params.arguments = { rewritten: true };
      return { content: [] };
    });

    const wrapped = createAuditingMiddleware()(rewriting);
    await wrapped(makeRequest({ mode: "list", company: "c1" }), context);
    await flush();

    expect(recorder.mock.calls[0][0].args_shape).toEqual({
      sel: { mode: "list" },
      keys: ["company", "mode"],
    });
  });

  describe("kill switch", () => {
    const saved = process.env.TOOL_AUDIT_ARGS_SHAPE;
    afterEach(() => {
      if (saved === undefined) delete process.env.TOOL_AUDIT_ARGS_SHAPE;
      else process.env.TOOL_AUDIT_ARGS_SHAPE = saved;
    });

    it("stores NULL when TOOL_AUDIT_ARGS_SHAPE=off and still records the row", async () => {
      process.env.TOOL_AUDIT_ARGS_SHAPE = "off";
      const recorder = vi.fn().mockResolvedValue(undefined);
      setAuditRecorderForTesting(recorder);

      const wrapped = createAuditingMiddleware()(okHandler);
      await wrapped(makeRequest({ mode: "list" }), context);
      await flush();

      const entry = recorder.mock.calls[0][0];
      expect(entry.args_shape).toBeNull();
      expect(entry.success).toBe(true);
      expect(entry.params_hash).not.toBeNull();
    });
  });

  it("never fails the call when the arguments cannot be read", async () => {
    const recorder = vi.fn().mockResolvedValue(undefined);
    setAuditRecorderForTesting(recorder);
    // A plain-object Proxy whose key enumeration throws: the one input a JSON
    // parser cannot produce but that proves the guard is in place.
    const hostile = new Proxy(
      {},
      {
        ownKeys() {
          throw new Error("hostile");
        },
      },
    );

    const wrapped = createAuditingMiddleware()(okHandler);
    const warn = vi.spyOn(logger, "warn").mockImplementation(() => undefined);
    const result = await wrapped(
      makeRequest(hostile as Record<string, unknown>),
      context,
    );
    await flush();

    expect(result).toEqual({ content: [] });
    expect(recorder.mock.calls[0][0].args_shape).toBeNull();
    expect(warn).toHaveBeenCalledTimes(1);
    expect(String(warn.mock.calls[0][0])).toContain(
      "Audit argument shape fault",
    );
    expect(String(warn.mock.calls[0][0])).not.toContain("hostile");
    warn.mockRestore();
  });
});

describe("in-band classification (migration 0039 error_detail)", () => {
  const inbandBody = {
    error: true,
    code: "invalid_input",
    message: "mode is not allowed here",
  };
  const inbandResult = () => ({
    content: [{ type: "text", text: JSON.stringify(inbandBody) }],
    structuredContent: { ...inbandBody },
  });
  const handlerReturning = (result: unknown) =>
    vi.fn().mockResolvedValue(result);

  it("records an in-band refusal as failed, inband_error, with the tool's code", async () => {
    const recorder = vi.fn().mockResolvedValue(undefined);
    setAuditRecorderForTesting(recorder);

    const wrapped = createAuditingMiddleware()(
      handlerReturning(inbandResult()),
    );
    await wrapped(makeRequest({ mode: "list", company: "c1" }), context);
    await flush();

    const entry = recorder.mock.calls[0][0];
    expect(entry.success).toBe(false);
    expect(entry.error_code).toBe("inband_error");
    expect(entry.error_detail).toBe("invalid_input");
    expect(entry.args_shape).toEqual({
      sel: { mode: "list" },
      keys: ["company", "mode"],
    });
  });

  it("returns the IDENTICAL object it received, for failed, in-band and success results", async () => {
    setAuditRecorderForTesting(vi.fn().mockResolvedValue(undefined));
    const results = [
      { isError: true, content: [{ type: "text", text: "denied" }] },
      inbandResult(),
      { content: [{ type: "text", text: "ok" }] },
      markRetiredToolResult(
        { isError: true, content: [{ type: "text", text: "retired" }] },
        { replacement: "a__b" },
      ),
    ];
    for (const result of results) {
      const wrapped = createAuditingMiddleware()(handlerReturning(result));
      const returned = await wrapped(makeRequest({ a: 1 }), context);
      // toBe, not toEqual: the wire must be unchanged, so it is the same object.
      expect(returned).toBe(result);
    }
  });

  it("does not mutate a deep-frozen in-band result", async () => {
    setAuditRecorderForTesting(vi.fn().mockResolvedValue(undefined));
    const frozen = Object.freeze({
      content: Object.freeze([
        Object.freeze({ type: "text", text: JSON.stringify(inbandBody) }),
      ]),
      structuredContent: Object.freeze({ ...inbandBody }),
    });
    const wrapped = createAuditingMiddleware()(handlerReturning(frozen));
    await expect(wrapped(makeRequest({ a: 1 }), context)).resolves.toBe(frozen);
  });

  it("a success with error:null stays a success", async () => {
    const recorder = vi.fn().mockResolvedValue(undefined);
    setAuditRecorderForTesting(recorder);
    const ok = {
      content: [],
      structuredContent: { status: "dispatched", error: null },
    };

    const wrapped = createAuditingMiddleware()(handlerReturning(ok));
    await wrapped(makeRequest({ a: 1 }), context);
    await flush();

    const entry = recorder.mock.calls[0][0];
    expect(entry.success).toBe(true);
    expect(entry.error_code).toBeUndefined();
    expect(entry.error_detail).toBeUndefined();
  });

  it("records a retired-name redirect as tool_retired", async () => {
    const recorder = vi.fn().mockResolvedValue(undefined);
    setAuditRecorderForTesting(recorder);
    const redirect = markRetiredToolResult(
      { isError: true, content: [{ type: "text", text: "retired" }] },
      { replacement: "autotask__ticket_manage" },
    );

    const wrapped = createAuditingMiddleware()(handlerReturning(redirect));
    await wrapped(makeRequest({ a: 1 }), context);
    await flush();

    const entry = recorder.mock.calls[0][0];
    expect(entry.success).toBe(false);
    expect(entry.error_code).toBe("tool_retired");
    expect(entry.server_name).toBe("autotask");
  });

  it("records an isError 'Unknown tool' result as unknown_tool", async () => {
    const recorder = vi.fn().mockResolvedValue(undefined);
    setAuditRecorderForTesting(recorder);
    const unknown = {
      isError: true,
      content: [{ type: "text", text: "Unknown tool: 'add_note'" }],
    };

    const wrapped = createAuditingMiddleware()(handlerReturning(unknown));
    await wrapped(makeRequest({ a: 1 }), context);
    await flush();

    expect(recorder.mock.calls[0][0].error_code).toBe("unknown_tool");
  });

  it("records a thrown 'Unknown tool' as unknown_tool and still rethrows it", async () => {
    const recorder = vi.fn().mockResolvedValue(undefined);
    setAuditRecorderForTesting(recorder);
    const failing = vi.fn().mockRejectedValue(new Error("Unknown tool: x__y"));

    const wrapped = createAuditingMiddleware()(failing);
    await expect(wrapped(makeRequest({ a: 1 }), context)).rejects.toThrow(
      "Unknown tool: x__y",
    );
    await flush();

    const entry = recorder.mock.calls[0][0];
    expect(entry.success).toBe(false);
    expect(entry.error_code).toBe("unknown_tool");
  });

  it("any other thrown error keeps its original class", async () => {
    const recorder = vi.fn().mockResolvedValue(undefined);
    setAuditRecorderForTesting(recorder);
    const timeout = Object.assign(new Error("Request timed out"), {
      code: -32001,
    });

    const wrapped = createAuditingMiddleware()(
      vi.fn().mockRejectedValue(timeout),
    );
    await expect(wrapped(makeRequest({ a: 1 }), context)).rejects.toBe(timeout);
    await flush();

    expect(recorder.mock.calls[0][0].error_code).toBe("-32001");
  });

  it("preserves an opaque thrown failure when unknown-tool classification cannot read its message", async () => {
    const recorder = vi.fn().mockResolvedValue(undefined);
    setAuditRecorderForTesting(recorder);
    const failure = {
      code: -32001,
      get message() {
        throw new Error("private-fault-data");
      },
    };
    const wrapped = createAuditingMiddleware()(
      vi.fn().mockRejectedValue(failure),
    );
    await expect(wrapped(makeRequest({ a: 1 }), context)).rejects.toBe(failure);
    await flush();
    expect(recorder.mock.calls[0][0].error_code).toBe("-32001");
  });

  describe("kill switch", () => {
    const saved = process.env.TOOL_AUDIT_INBAND_CLASSIFY;
    afterEach(() => {
      if (saved === undefined) delete process.env.TOOL_AUDIT_INBAND_CLASSIFY;
      else process.env.TOOL_AUDIT_INBAND_CLASSIFY = saved;
    });

    it("off makes an in-band error a success again but leaves isError handling intact", async () => {
      process.env.TOOL_AUDIT_INBAND_CLASSIFY = "off";
      const recorder = vi.fn().mockResolvedValue(undefined);
      setAuditRecorderForTesting(recorder);

      await createAuditingMiddleware()(handlerReturning(inbandResult()))(
        makeRequest({ a: 1 }),
        context,
      );
      await createAuditingMiddleware()(
        handlerReturning({
          isError: true,
          content: [{ type: "text", text: "denied" }],
        }),
      )(makeRequest({ a: 1 }), context);
      await flush();

      expect(recorder.mock.calls[0][0].success).toBe(true);
      expect(recorder.mock.calls[0][0].error_code).toBeUndefined();
      expect(recorder.mock.calls[1][0].success).toBe(false);
      expect(recorder.mock.calls[1][0].error_code).toBe("tool_error");
    });
  });

  describe("classifier fault", () => {
    it("records the row as before and never throws out of the middleware", async () => {
      const recorder = vi.fn().mockResolvedValue(undefined);
      setAuditRecorderForTesting(recorder);
      // A plain object whose property reads throw: reachable only through a
      // hostile Proxy, which a JSON parser cannot produce but proves the guard.
      const hostile = new Proxy(
        {},
        {
          getPrototypeOf() {
            throw new Error("hostile");
          },
          get(_target, property) {
            // `await` and promise resolution probe `then`; answer that one
            // honestly so only the classifier's own reads can throw.
            if (property === "then") return undefined;
            throw new Error("hostile");
          },
        },
      );

      const warn = vi.spyOn(logger, "warn").mockImplementation(() => undefined);

      const wrapped = createAuditingMiddleware()(handlerReturning(hostile));
      await expect(wrapped(makeRequest({ a: 1 }), context)).resolves.toBe(
        hostile,
      );
      await flush();

      const entry = recorder.mock.calls[0][0];
      expect(entry.success).toBe(true);
      expect(entry.error_code).toBeUndefined();
      // One WARN names the fault, so a systematic classifier bug is visible.
      expect(warn).toHaveBeenCalledTimes(1);
      expect(String(warn.mock.calls[0][0])).toContain("Audit classifier fault");
      warn.mockRestore();
    });
  });

  describe("Live Logs wording", () => {
    // The Grafana "MCP errors" panels count any metamcp line matching this as
    // an error. In-band refusals and retirements are handled outcomes, so
    // their lines are worded without these words and logged at warn.
    const DASHBOARD_ERROR_WORDS = /\b(error|fatal|panic|exception)\b/i;

    const recordSpy = () => vi.spyOn(metamcpLogStore, "record");
    afterEach(() => vi.restoreAllMocks());

    it("an in-band refusal logs at warn without the dashboard error words", async () => {
      setAuditRecorderForTesting(null);
      const spy = recordSpy().mockImplementation(() => undefined);

      await createAuditingMiddleware()(handlerReturning(inbandResult()))(
        makeRequest({ a: 1 }),
        context,
      );

      const logged = spy.mock.calls[0][0];
      expect(logged.level).toBe("warn");
      expect(logged.message).toContain("refused in-band: invalid_input");
      expect(DASHBOARD_ERROR_WORDS.test(logged.message)).toBe(false);
    });

    it("an in-band refusal with no code logs 'unclassified'", async () => {
      setAuditRecorderForTesting(null);
      const spy = recordSpy().mockImplementation(() => undefined);
      const noCode = {
        content: [],
        structuredContent: { error: "provide query or entity_id" },
      };

      await createAuditingMiddleware()(handlerReturning(noCode))(
        makeRequest({ a: 1 }),
        context,
      );

      expect(spy.mock.calls[0][0].message).toContain(
        "refused in-band: unclassified",
      );
    });

    it("a code token that is itself a dashboard word is not echoed", async () => {
      setAuditRecorderForTesting(null);
      const spy = recordSpy().mockImplementation(() => undefined);
      const wordy = {
        content: [],
        structuredContent: { error: true, code: "error" },
      };

      await createAuditingMiddleware()(handlerReturning(wordy))(
        makeRequest({ a: 1 }),
        context,
      );

      const logged = spy.mock.calls[0][0];
      expect(DASHBOARD_ERROR_WORDS.test(logged.message)).toBe(false);
      expect(logged.message).toContain("unclassified");
    });

    it("a retired-name redirect logs at warn without the dashboard error words", async () => {
      setAuditRecorderForTesting(null);
      const spy = recordSpy().mockImplementation(() => undefined);
      const withReplacement = markRetiredToolResult(
        { isError: true, content: [{ type: "text", text: "x" }] },
        { replacement: "autotask__ticket_manage" },
      );
      const withoutReplacement = markRetiredToolResult(
        { isError: true, content: [{ type: "text", text: "x" }] },
        { replacement: null },
      );

      await createAuditingMiddleware()(handlerReturning(withReplacement))(
        makeRequest({ a: 1 }),
        context,
      );
      await createAuditingMiddleware()(handlerReturning(withoutReplacement))(
        makeRequest({ a: 1 }),
        context,
      );

      const [first, second] = spy.mock.calls.map((call) => call[0]);
      expect(first.level).toBe("warn");
      expect(first.message).toContain(
        "is retired; replacement autotask__ticket_manage",
      );
      expect(second.message).toContain("is retired; no replacement");
      expect(DASHBOARD_ERROR_WORDS.test(first.message)).toBe(false);
      expect(DASHBOARD_ERROR_WORDS.test(second.message)).toBe(false);
    });

    it("isError results keep the original error level and text", async () => {
      setAuditRecorderForTesting(null);
      const spy = recordSpy().mockImplementation(() => undefined);

      await createAuditingMiddleware()(
        handlerReturning({
          isError: true,
          content: [{ type: "text", text: "boom" }],
        }),
      )(makeRequest({ a: 1 }), context);

      const logged = spy.mock.calls[0][0];
      expect(logged.level).toBe("error");
      expect(logged.message).toMatch(/^search returned an error \(\d+ms\)$/);
    });

    it("a success keeps the original info line", async () => {
      setAuditRecorderForTesting(null);
      const spy = recordSpy().mockImplementation(() => undefined);

      await createAuditingMiddleware()(okHandler)(
        makeRequest({ a: 1 }),
        context,
      );

      const logged = spy.mock.calls[0][0];
      expect(logged.level).toBe("info");
      expect(logged.message).toMatch(/^search \(\d+ms\)$/);
    });
  });
});
