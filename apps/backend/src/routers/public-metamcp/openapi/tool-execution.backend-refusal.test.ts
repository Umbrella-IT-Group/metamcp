/**
 * A backend's HTTP 401 or 403 answer to a tool call, through the whole OpenAPI
 * route: `executeToolWithMiddleware`, the real middleware chain (audit
 * recorder included), the real handler and a real SDK `Client` on a real
 * `StreamableHTTPClientTransport` whose fetch answers the refusal.
 *
 * The oracle is "no sink holds the backend's response body". The sinks are
 * every logger level, the Live Logs entries, the durable gateway events and the
 * `tool_call_audit` rows. The consumer's own reply is deliberately unchanged
 * (the 500 body still carries the error text), so the test pins that too.
 *
 * The outer route catch used to log the rethrown error itself, which exposed
 * the body even though the handler fixes keep it out of their own lines. A 502
 * is the control: a failure that is not a refusal keeps its diagnostic error
 * in the log, so the redaction is not a blanket one.
 */
import { inspect } from "node:util";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  makeHttpRefusingBackend,
  sleep,
} from "../../../lib/metamcp/tool-call-harness.test-util";

const { getSessionMock, getOpenApiServerMock, recordEventMock } = vi.hoisted(
  () => ({
    getSessionMock: vi.fn(),
    getOpenApiServerMock: vi.fn(),
    recordEventMock: vi.fn(),
  }),
);

vi.mock("../../../db/index", () => ({ db: {}, pool: {} }));
vi.mock("@/utils/logger", () => ({
  default: { error: vi.fn(), warn: vi.fn(), info: vi.fn(), debug: vi.fn() },
}));
vi.mock("@/lib/gateway-events/sink", () => ({
  recordGatewayEvent: recordEventMock,
}));
vi.mock("../../../lib/config.service", () => ({
  configService: {
    getMcpResetTimeoutOnProgress: async () => false,
    getMcpTimeout: async () => 60_000,
    getMcpMaxTotalTimeout: async () => 600_000,
  },
}));
vi.mock("../../../lib/metamcp/fetch-metamcp", () => ({
  getMcpServers: vi.fn(async () => ({
    "server-autotask": { name: "autotask" },
  })),
}));
vi.mock("../../../lib/metamcp/mcp-server-pool", () => ({
  mcpServerPool: {
    getSession: getSessionMock,
    invalidateServerConnection: vi.fn(),
    isPooledClient: () => true,
  },
}));
vi.mock("../../../lib/metamcp/metamcp-server-pool", () => ({
  metaMcpServerPool: { getOpenApiServer: getOpenApiServerMock },
}));
vi.mock("../../../lib/metamcp/caller-context", () => ({
  resolveCallerContext: vi.fn(() => undefined),
}));
vi.mock("../../../lib/metamcp/consumer-identity-resolver", () => ({
  resolveClientIdentity: vi.fn().mockResolvedValue({ name: "test-consumer" }),
}));
// The two curation middlewares read the database; the chain around them
// (audit, retired-tool, timeout hint) and the handler run for real.
vi.mock(
  "../../../lib/metamcp/metamcp-middleware/filter-tools.functional",
  () => ({
    createFilterCallToolMiddleware: () => (next: unknown) => next,
    createFilterListToolsMiddleware: () => (next: unknown) => next,
  }),
);
vi.mock(
  "../../../lib/metamcp/metamcp-middleware/tool-overrides.functional",
  () => ({
    createToolOverridesCallToolMiddleware: () => (next: unknown) => next,
    createToolOverridesListToolsMiddleware: () => (next: unknown) => next,
  }),
);

import logger from "@/utils/logger";

import {
  MetaMcpLogEntry,
  metamcpLogStore,
} from "../../../lib/metamcp/log-store";
import { setAuditRecorderForTesting } from "../../../lib/metamcp/metamcp-middleware/auditing.functional";
import { resetBridgeAuditSchemasForTesting } from "./handlers";
import { executeToolWithMiddleware } from "./tool-execution";

const BODY_SECRET = "backend-body-text-that-must-not-be-logged";
const cleanups: Array<() => Promise<unknown>> = [];

function makeRes() {
  const sent: { status?: number; body?: { message?: string } } = {};
  const res = {
    status: vi.fn((code: number) => {
      sent.status = code;
      return res;
    }),
    json: vi.fn((body: { message?: string }) => {
      sent.body = body;
      return res;
    }),
  };
  return { res, sent };
}

/** One tool call through the route, with every sink captured. */
async function callThroughRoute(status: number) {
  const made = await makeHttpRefusingBackend([status], {
    serverName: "autotask",
    body: BODY_SECRET,
  });
  cleanups.push(() => made.close());
  getSessionMock.mockResolvedValue(made.session);

  const audit = vi.fn().mockResolvedValue(undefined);
  setAuditRecorderForTesting(audit);
  const events: MetaMcpLogEntry[] = [];
  const unsubscribe = metamcpLogStore.addListener((entry) =>
    events.push(entry),
  );
  const loggers = [logger.error, logger.warn, logger.info, logger.debug].map(
    (fn) => vi.mocked(fn),
  );
  loggers.forEach((fn) => fn.mockClear());
  recordEventMock.mockClear();

  const { res, sent } = makeRes();
  const req = {
    namespaceUuid: "ns-1",
    params: { tool_name: "autotask__slow_job" },
  } as unknown as Parameters<typeof executeToolWithMiddleware>[0];
  await executeToolWithMiddleware(req, res as never, {});
  // The audit write is detached from the call; let it land.
  await sleep(0);
  unsubscribe();

  const dump = (value: unknown) => inspect(value, { depth: null });
  return {
    sent,
    logs: dump(loggers.flatMap((fn) => fn.mock.calls)),
    events: dump(events),
    eventCount: events.length,
    gatewayEvents: dump(recordEventMock.mock.calls),
    auditRows: audit.mock.calls.map(([row]) => row),
    audit: dump(audit.mock.calls),
  };
}

beforeEach(() => {
  getSessionMock.mockReset();
  getOpenApiServerMock.mockReset();
  getOpenApiServerMock.mockResolvedValue({});
  resetBridgeAuditSchemasForTesting();
});

afterEach(async () => {
  setAuditRecorderForTesting(null);
  while (cleanups.length > 0) {
    await cleanups
      .pop()?.()
      .catch(() => undefined);
  }
});

describe("OpenAPI route: a backend's HTTP 401 or 403 answer to a tool call", () => {
  it.each([401, 403] as const)(
    "keeps the HTTP %s response body out of every log line, event and audit row",
    async (status) => {
      const seen = await callThroughRoute(status);

      // The sinks were really written (the absence checks below are not
      // vacuous), and they name the status instead of the body.
      expect(seen.eventCount).toBe(1);
      expect(seen.auditRows).toHaveLength(1);
      expect(seen.auditRows[0]).toMatchObject({
        success: false,
        error_code: String(status),
      });
      expect(seen.logs).toContain(`HTTP ${status}`);

      expect(seen.logs).not.toContain(BODY_SECRET);
      expect(seen.events).not.toContain(BODY_SECRET);
      expect(seen.gatewayEvents).not.toContain(BODY_SECRET);
      expect(seen.audit).not.toContain(BODY_SECRET);
    },
  );

  it.each([401, 403] as const)(
    "still answers the consumer exactly as before for HTTP %s",
    async (status) => {
      const { sent } = await callThroughRoute(status);

      expect(sent.status).toBe(500);
      expect(sent.body).toMatchObject({ error: "Tool execution failed" });
      expect(sent.body?.message).toContain(BODY_SECRET);
    },
  );

  it("keeps the diagnostic error in the log for a 502 (negative control)", async () => {
    const seen = await callThroughRoute(502);

    expect(seen.logs).toContain(BODY_SECRET);
    expect(seen.auditRows).toHaveLength(1);
    expect(seen.auditRows[0]).toMatchObject({ error_code: "502" });
  });
});
