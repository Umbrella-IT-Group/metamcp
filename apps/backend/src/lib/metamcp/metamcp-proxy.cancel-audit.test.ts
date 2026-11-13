/**
 * A consumer cancel, audited by the REAL auditing middleware, end to end.
 *
 * The cancelled call ends as a throw (never a result), the audit row says
 * `success=false, error_code='cancelled', error_detail='outcome_unknown'`
 * (the cancel and the backend's own answer race, so the backend may have
 * finished: a security review reads the row as possibly executed), and the
 * Live Logs entry is a WARN without the words the log-based dashboards count
 * as failures and without the thrown error attached.
 *
 * Oracle: the MCP spec's basic/utilities/cancellation page (the receiver
 * stops work and sends no response; a cancel for an unknown or finished
 * request is ignored) and the audit recorder row contract in
 * auditing.functional.ts. A real SDK cancel drives everything.
 */
import { CallToolResultSchema } from "@modelcontextprotocol/sdk/types.js";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  connectGateway,
  flush,
  type Gateway,
  makeBackend,
  OK,
  type TestBackend,
} from "./tool-call-harness.test-util";

const { getSessionMock, auditRepoImports } = vi.hoisted(() => ({
  getSessionMock: vi.fn(),
  auditRepoImports: { count: 0 },
}));

vi.mock("@/utils/logger", () => ({
  default: { error: vi.fn(), warn: vi.fn(), info: vi.fn(), debug: vi.fn() },
}));
vi.mock("../../db", () => ({ db: {} }));
vi.mock("../../db/schema", () => ({}));
vi.mock("../../db/repositories/namespaces.repo", () => ({
  namespacesRepository: {
    findServersForNamespaceToolName: vi.fn().mockResolvedValue([]),
  },
}));
vi.mock("../../db/repositories/oauth-sessions.repo", () => ({
  oauthSessionsRepository: {},
}));
// The audit sink is pinned in beforeEach so the lazy repository import never
// starts; the count proves it stayed that way.
vi.mock("../../db/repositories/tool-call-audit.repo", () => {
  auditRepoImports.count += 1;
  return { toolCallAuditRepository: { record: vi.fn() } };
});
vi.mock("../../trpc/tools.impl", () => ({
  toolsImplementations: {
    syncFromListing: vi.fn().mockResolvedValue(undefined),
  },
}));
vi.mock("../config.service", () => ({
  configService: {
    getMcpResetTimeoutOnProgress: async () => true,
    getMcpTimeout: async () => 5_000,
    getMcpMaxTotalTimeout: async () => 600_000,
    getMcpToolCallReconnectWarmupTimeout: async () => 0,
  },
}));
vi.mock("./fetch-metamcp", () => {
  const getMcpServers = vi.fn(async () => ({
    "server-ninja": { name: "ninja" },
  }));
  return {
    getMcpServers,
    getNamespaceListingServers: vi.fn(async () => ({
      routable: await getMcpServers(),
      errorGated: {},
    })),
    getNamespaceServerStates: vi.fn(async () => []),
  };
});
vi.mock("./mcp-server-pool", () => ({
  mcpServerPool: {
    getSession: getSessionMock,
    invalidateServerConnection: vi.fn(),
    cleanupSession: vi.fn(),
    isPooledClient: () => true,
    getPoolStatus: () => ({ idle: 1, active: 1 }),
  },
}));
// The filter needs the database and the overrides read it; both pass through.
// The auditing, retired-tool and timeout-hint middleware are the real ones.
vi.mock("./metamcp-middleware/filter-tools.functional", () => ({
  createFilterCallToolMiddleware: () => (next: unknown) => next,
  createFilterListToolsMiddleware: () => (next: unknown) => next,
}));
vi.mock("./metamcp-middleware/tool-overrides.functional", () => ({
  createToolOverridesCallToolMiddleware: () => (next: unknown) => next,
  createToolOverridesListToolsMiddleware: () => (next: unknown) => next,
  mapOverrideNameToOriginal: vi.fn(async (name: string) => name),
}));
vi.mock("./cold-connect-broker-fallback", () => ({
  resolveColdConnectBrokerFallback: () => undefined,
}));
vi.mock("./tool-call-warmup", () => ({
  acquireSessionWithBoundedWarmup: vi.fn(async () => undefined),
}));

import { metamcpLogStore } from "./log-store";
import { setAuditRecorderForTesting } from "./metamcp-middleware/auditing.functional";
import { createServer } from "./metamcp-proxy";

const TOOL = "ninja__long_job";
const DASHBOARD_ERROR_WORDS = /\b(error|fatal|panic|exception)\b/i;

const cleanups: Array<() => Promise<unknown>> = [];
const recorder = vi.fn().mockResolvedValue(undefined);
let liveLogs: ReturnType<typeof vi.spyOn>;

async function backend(
  onCall: Parameters<typeof makeBackend>[0],
): Promise<TestBackend> {
  const made = await makeBackend(onCall);
  cleanups.push(() => made.close());
  return made;
}

async function gateway(): Promise<Gateway> {
  const made = await connectGateway(createServer);
  cleanups.push(() => made.close());
  return made;
}

const call = (gw: Gateway, signal?: AbortSignal) =>
  gw.consumer.request(
    { method: "tools/call", params: { name: TOOL, arguments: { id: "x" } } },
    CallToolResultSchema,
    { signal, timeout: 10_000_000 },
  );

/** The audit row is written after the call and its listing settle. */
async function rows(expected: number) {
  for (let i = 0; i < 200 && recorder.mock.calls.length < expected; i += 1) {
    await flush(20);
  }
  return recorder.mock.calls.map(([row]) => row);
}

const toolCallEntries = () =>
  liveLogs.mock.calls
    .map(([entry]) => entry as Record<string, unknown>)
    .filter((entry) => entry.category === "tool_call");

beforeEach(() => {
  getSessionMock.mockReset();
  recorder.mockClear();
  setAuditRecorderForTesting(recorder);
  liveLogs = vi.spyOn(metamcpLogStore, "record");
});

afterEach(async () => {
  setAuditRecorderForTesting(null);
  liveLogs.mockRestore();
  while (cleanups.length > 0) {
    await cleanups
      .pop()?.()
      .catch(() => undefined);
  }
});

describe("a cancelled call, audited", () => {
  it("records one row: failed, cancelled, outcome unknown", async () => {
    const target = await backend(async (_extra, info) => {
      await new Promise<void>((resolve) =>
        info.signal.addEventListener("abort", () => resolve(), { once: true }),
      );
      return OK;
    });
    getSessionMock.mockResolvedValue(target.session);
    const gw = await gateway();

    const controller = new AbortController();
    const outcome = call(gw, controller.signal).catch(() => undefined);
    await flush();
    controller.abort();
    await outcome;
    const written = await rows(1);
    await flush();

    expect(written).toHaveLength(1);
    expect(written[0]).toMatchObject({
      server_name: "ninja",
      tool_name: "long_job",
      success: false,
      error_code: "cancelled",
      error_detail: "outcome_unknown",
    });

    const entries = toolCallEntries();
    expect(entries).toHaveLength(1);
    expect(entries[0].level).toBe("warn");
    expect(entries[0].error).toBeUndefined();
    expect(String(entries[0].message)).toContain(
      "cancelled by the caller; outcome unknown",
    );
    expect(String(entries[0].message)).not.toMatch(DASHBOARD_ERROR_WORDS);
  });

  it("records an ordinary success row when an unrelated cancel arrives afterwards", async () => {
    const target = await backend(async () => OK);
    getSessionMock.mockResolvedValue(target.session);
    const gw = await gateway();

    await call(gw);
    // The spec: a cancel for an unknown or finished request is ignored.
    await gw.consumer.notification({
      method: "notifications/cancelled",
      params: { requestId: 424242 },
    });
    const written = await rows(1);
    await flush();

    expect(written).toHaveLength(1);
    expect(written[0]).toMatchObject({ tool_name: "long_job", success: true });
    expect(written[0].error_code).toBeUndefined();
    expect(written[0].error_detail).toBeUndefined();
  });
});
