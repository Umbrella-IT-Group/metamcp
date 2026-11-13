import { format } from "node:util";

import { DrizzleQueryError } from "drizzle-orm/errors";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../../../db/index", () => ({ db: {}, pool: {} }));
vi.mock("@/utils/logger", () => ({
  default: { error: vi.fn(), warn: vi.fn(), info: vi.fn(), debug: vi.fn() },
}));
vi.mock("../../../lib/config.service", () => ({
  configService: {
    getMcpResetTimeoutOnProgress: vi.fn(),
    getMcpTimeout: vi.fn(),
    getMcpMaxTotalTimeout: vi.fn(),
  },
}));
vi.mock("../../../lib/metamcp/fetch-metamcp", () => ({
  getMcpServers: vi.fn(async () => ({
    "server-vendor": { name: "vendor" },
  })),
}));
vi.mock("../../../lib/metamcp/mcp-server-pool", () => ({
  mcpServerPool: {
    getSession: vi.fn(),
    invalidateServerConnection: vi.fn(),
    isPooledClient: () => true,
  },
}));
vi.mock("../../../lib/metamcp/metamcp-server-pool", () => ({
  metaMcpServerPool: { getOpenApiServer: vi.fn(async () => ({})) },
}));
vi.mock("../../../lib/metamcp/caller-context", () => ({
  resolveCallerContext: vi.fn(),
}));
vi.mock("../../../lib/metamcp/consumer-identity-resolver", () => ({
  resolveClientIdentity: vi.fn(async () => ({ name: "test-consumer" })),
}));
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

import { configService } from "../../../lib/config.service";
import { metamcpLogStore } from "../../../lib/metamcp/log-store";
import { mcpServerPool } from "../../../lib/metamcp/mcp-server-pool";
import { setAuditRecorderForTesting } from "../../../lib/metamcp/metamcp-middleware/auditing.functional";
import {
  createOriginalListToolsHandler,
  resetBridgeAuditSchemasForTesting,
} from "./handlers";
import { executeToolWithMiddleware } from "./tool-execution";

const SECRET = "fake-config-secret-aaaa1111";
const QUERY = 'select "value" from "config" where "key" = $1';
const GETTERS = [
  "getMcpResetTimeoutOnProgress",
  "getMcpTimeout",
  "getMcpMaxTotalTimeout",
] as const;
const request = vi.fn();
const audit = vi.fn();

function failedRead(): DrizzleQueryError {
  return new DrizzleQueryError(
    QUERY,
    [SECRET],
    Object.assign(new Error(`rejected value ${SECRET}`), {
      code: "23514",
      constraint: "config_value_check",
      detail: `Failing row contains (${SECRET})`,
    }),
  );
}

function loggedText(): string {
  return [logger.error, logger.warn, logger.info, logger.debug]
    .flatMap((fn) => vi.mocked(fn).mock.calls)
    .map((args) => format(...args))
    .join("\n");
}

function expectSafe(value: unknown): void {
  const text = typeof value === "string" ? value : JSON.stringify(value);
  expect(text).not.toContain(SECRET);
  expect(text).not.toContain(QUERY);
  expect(text).not.toContain("Failed query");
  expect(text).not.toContain("Failing row contains");
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(configService.getMcpResetTimeoutOnProgress)
    .mockReset()
    .mockResolvedValue(false);
  vi.mocked(configService.getMcpTimeout).mockReset().mockResolvedValue(60_000);
  vi.mocked(configService.getMcpMaxTotalTimeout)
    .mockReset()
    .mockResolvedValue(600_000);
  vi.mocked(mcpServerPool.getSession).mockResolvedValue({
    client: {
      request,
      getServerCapabilities: () => ({ tools: {} }),
      getServerVersion: () => ({ name: "vendor" }),
    },
  } as never);
  setAuditRecorderForTesting(audit);
  resetBridgeAuditSchemasForTesting();
});

afterEach(() => {
  setAuditRecorderForTesting(null);
  resetBridgeAuditSchemasForTesting();
});

describe.each(GETTERS)("OpenAPI configuration failure in %s", (getter) => {
  it.each([false, true])(
    "keeps query values out of a listing and every log (audit: %s)",
    async (auditListing) => {
      vi.mocked(configService[getter]).mockRejectedValueOnce(failedRead());

      const result = await createOriginalListToolsHandler(false, {
        audit: auditListing,
      })(
        { method: "tools/list", params: {} },
        { namespaceUuid: "ns-1", sessionId: "openapi_ns-1" },
      );

      expect(result.tools).toEqual([]);
      expect(request).not.toHaveBeenCalled();
      expectSafe(result);
      expectSafe(loggedText());
      expect(loggedText()).toContain("DrizzleQueryError");
      expect(loggedText()).toContain("23514");
      expect(loggedText()).toContain("config_value_check");
      if (auditListing) expect(logger.error).not.toHaveBeenCalled();
    },
  );

  it("returns a fixed retryable failure without leaking into the response, logs or audit", async () => {
    vi.mocked(configService[getter]).mockRejectedValueOnce(failedRead());
    const entries: unknown[] = [];
    const unsubscribe = metamcpLogStore.addListener((entry) =>
      entries.push(entry),
    );
    const res = {
      status: vi.fn().mockReturnThis(),
      json: vi.fn().mockReturnThis(),
    };
    try {
      await executeToolWithMiddleware(
        {
          namespaceUuid: "ns-1",
          params: { tool_name: "vendor__read" },
        } as never,
        res as never,
        {},
      );
      await new Promise<void>((resolve) => setImmediate(resolve));

      expect(res.status).toHaveBeenCalledWith(500);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          error: "Tool execution failed",
          message: expect.stringContaining(
            "Tool-call configuration could not be read. Retry shortly.",
          ),
          retryable: true,
        }),
      );
      expect(request).not.toHaveBeenCalled();
      expect(entries).toHaveLength(1);
      expect(audit).toHaveBeenCalledTimes(1);
      expect(audit).toHaveBeenCalledWith(
        expect.objectContaining({ success: false }),
      );
      expectSafe(res.json.mock.calls);
      expectSafe(entries);
      expectSafe(audit.mock.calls);
      expectSafe(loggedText());
      expect(loggedText()).toContain("DrizzleQueryError");
      expect(loggedText()).toContain("23514");
    } finally {
      unsubscribe();
    }
  });
});
