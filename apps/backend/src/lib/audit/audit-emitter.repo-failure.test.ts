/**
 * MUTATION PROOF for the fire-and-forget guarantee, taken one layer deeper
 * than the sink seam.
 *
 * The other suites swap `setAuditSinkForTesting`, which proves the emitter
 * tolerates a bad sink but leaves the lazy `import()` of the repository
 * untested. This file mutates the REPOSITORY itself — `auditLogRepository.
 * record` rejects on every call, the shape a real outage takes (Postgres
 * down, connection pool exhausted, the append-only trigger rejecting a
 * malformed row) — and pins that both wired detectors return their normal
 * response anyway.
 *
 * It also asserts `record` was actually CALLED. Without that, a regression
 * that silently disabled auditing altogether would make every "the request
 * still works" assertion pass for the wrong reason.
 */

import { createLogsRouter, setTrpcAuditSink } from "@repo/trpc";
import { DatabaseEndpoint } from "@repo/zod-types";
import express from "express";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { recordMock, validateApiKeyMock, isDisabledMock, loggerMock } =
  vi.hoisted(() => ({
    recordMock: vi.fn(),
    validateApiKeyMock: vi.fn(),
    isDisabledMock: vi.fn(),
    loggerMock: {
      debug: vi.fn(),
      info: vi.fn(),
      warn: vi.fn(),
      error: vi.fn(),
    },
  }));

vi.mock("@/utils/logger", () => ({ default: loggerMock }));

// THE MUTATION: the durable sink the emitter lazily imports always fails.
vi.mock("../../db/repositories/audit-log.repo", () => ({
  auditLogRepository: { record: recordMock },
}));

vi.mock("../../db/repositories/api-keys.repo", () => ({
  ApiKeysRepository: class {
    validateApiKey = validateApiKeyMock;
  },
}));

vi.mock("../../db/repositories/users.repo", () => ({
  usersRepository: { isDisabled: isDisabledMock },
}));

// The bearer middleware reads the token row directly now (it used to call its
// own /oauth/introspect over HTTP), so oauth.repo is on its module-load import
// chain and reaches db/index like the two above. This suite drives only the
// API-key branch, so the lookup is never reached.
vi.mock("../../db/repositories/oauth.repo", () => ({
  oauthRepository: { getAccessToken: vi.fn().mockResolvedValue(null) },
}));

const { authenticateApiKey } = await import(
  "../../middleware/api-key-oauth.middleware"
);
const { trpcDenialSink } = await import("./trpc-denial-sink");
const { resetAuditFailureReportingForTesting } = await import(
  "./audit-emitter"
);

const ENDPOINT: DatabaseEndpoint = {
  uuid: "11111111-1111-4111-8111-111111111111",
  name: "autotask",
  description: null,
  namespace_uuid: "33333333-3333-4333-8333-333333333333",
  enable_api_key_auth: true,
  require_scoped_api_key: false,
  enable_max_rate: false,
  enable_client_max_rate: false,
  max_rate_seconds: null,
  max_rate: null,
  client_max_rate: null,
  client_max_rate_seconds: null,
  client_max_rate_strategy: null,
  client_max_rate_strategy_key: null,
  enable_oauth: false,
  use_query_param_auth: false,
  created_at: new Date("2026-07-01T00:00:00Z"),
  updated_at: new Date("2026-07-01T00:00:00Z"),
  user_id: null,
};

/** Flush the detached promise chain `emit()` schedules. */
const flush = () => new Promise((resolve) => setTimeout(resolve, 0));

let ipCounter = 0;

beforeEach(() => {
  vi.clearAllMocks();
  recordMock.mockRejectedValue(new Error("audit_log INSERT failed"));
  isDisabledMock.mockResolvedValue(false);
  setTrpcAuditSink(trpcDenialSink);
  // The emitter throttles failure reports to one a minute process-wide, so
  // without this only whichever case ran first would see a line.
  resetAuditFailureReportingForTesting();
});

describe("MCP bearer path with a failing audit_log", () => {
  it("answers the normal 401 and reports no error to the caller", async () => {
    validateApiKeyMock.mockResolvedValue({ valid: false });
    ipCounter += 1;

    const req = {
      method: "POST",
      url: "/mcp",
      headers: {
        "x-api-key": "sk_mt_livekey000000",
        "cf-connecting-ip": "203.0.113.7",
      },
      query: {},
      protocol: "https",
      get: () => "mcp.example.com",
      ip: `10.1.0.${ipCounter}`,
      socket: { remoteAddress: "127.0.0.1" },
      endpoint: ENDPOINT,
      auditRequestId: "req-under-test",
      auditClientIp: "203.0.113.7",
    } as unknown as express.Request;

    let statusCode = 200;
    let body: Record<string, unknown> | undefined;
    const res = {
      status(code: number) {
        statusCode = code;
        return res;
      },
      json(payload: Record<string, unknown>) {
        body = payload;
        return res;
      },
      set() {
        return res;
      },
    };
    let served = false;

    await authenticateApiKey(req, res as unknown as express.Response, () => {
      served = true;
    });
    await flush();

    expect(served).toBe(false);
    expect(statusCode).toBe(401);
    expect(body).toMatchObject({ error: "invalid_api_key" });
    // The write was attempted and failed — the proof is a real mutation, not
    // a disabled emitter.
    expect(recordMock).toHaveBeenCalledTimes(1);
    // WARN, not debug. Production runs LOG_LEVEL=info, whose console floor in
    // utils/logger is INFO, so a debug line never reaches the console an
    // operator watches: the row was lost AND the loss was invisible. This
    // assertion is the one that catches a regression back to that.
    expect(loggerMock.warn).toHaveBeenCalled();
    expect(loggerMock.debug).not.toHaveBeenCalled();
  });

  it("names the loss in the warning so a responder can size it", async () => {
    validateApiKeyMock.mockResolvedValue({ valid: false });
    ipCounter += 1;

    const req = {
      method: "POST",
      url: "/mcp",
      headers: {
        "x-api-key": "sk_mt_livekey000000",
        "cf-connecting-ip": "203.0.113.7",
      },
      query: {},
      protocol: "https",
      get: () => "mcp.example.com",
      ip: `10.1.0.${ipCounter}`,
      socket: { remoteAddress: "127.0.0.1" },
      endpoint: ENDPOINT,
      auditRequestId: "req-under-test",
      auditClientIp: "203.0.113.7",
    } as unknown as express.Request;

    const res = {
      status() {
        return res;
      },
      json() {
        return res;
      },
      set() {
        return res;
      },
    };

    await authenticateApiKey(req, res as unknown as express.Response, () => {});
    await flush();

    // A bare "write failed" cannot be triaged. The count is what separates a
    // recycled connection from the sink being down for the whole incident.
    expect(loggerMock.warn.mock.calls[0]?.[0]).toContain("audit row(s) lost");
    // And it must still carry the underlying error, or the line says something
    // broke without saying what.
    expect(loggerMock.warn.mock.calls[0]?.[1]).toBeInstanceOf(Error);
  });
});

describe("RBAC choke point with a failing audit_log", () => {
  it("still throws a clean FORBIDDEN", async () => {
    const router = createLogsRouter({
      getLogs: vi
        .fn()
        .mockResolvedValue({ success: true, data: [], totalCount: 0 }),
    });

    await expect(
      router
        .createCaller({
          user: { id: "member-1", role: "member" },
          session: { id: "s-member" },
          audit: { actor_ip: "203.0.113.7", request_id: "req-under-test" },
        })
        .get({}),
    ).rejects.toMatchObject({ code: "FORBIDDEN" });
    await flush();

    expect(recordMock).toHaveBeenCalledTimes(1);
  });

  it("still lets an admin through", async () => {
    const router = createLogsRouter({
      getLogs: vi
        .fn()
        .mockResolvedValue({ success: true, data: [], totalCount: 0 }),
    });

    await expect(
      router
        .createCaller({
          user: { id: "admin-1", role: "admin" },
          session: { id: "s-admin" },
        })
        .get({}),
    ).resolves.toMatchObject({ success: true });
    await flush();

    expect(recordMock).not.toHaveBeenCalled();
  });
});
