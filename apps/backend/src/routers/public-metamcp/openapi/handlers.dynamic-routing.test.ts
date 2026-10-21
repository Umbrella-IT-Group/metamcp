/**
 * The OpenAPI bridge's tools/call routing matches the Streamable-HTTP proxy's
 * (metamcp-proxy.dynamic-routing.test.ts): both go through
 * tool-call-routing.ts. Driven through `executeToolWithMiddleware`, so the
 * REAL audit middleware, chain and HTTP mapping run; only the DB-touching
 * boundary and the pool are faked, and the bounded warm-up is the real one.
 *
 * What it pins for the bridge:
 *   - only the prefix's server is asked for a session;
 *   - a namespace with no tool mapping rows under `allow_all` warms the
 *     prefix's server instead of answering 404 "Tool not found";
 *   - `allowlist` never routes without an ACTIVE row;
 *   - a mounted server that cannot be used answers the honest "Backend
 *     unavailable" body, with the status kept at 404 (live pipelines key on
 *     it), and its audit row is classed `backend_unavailable`;
 *   - a genuinely unknown name keeps 404 "Tool not found" and `unknown_tool`;
 *   - parallel calls failing on one dead client share one recovery.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const {
  getSessionMock,
  invalidateServerConnectionMock,
  isPooledClientMock,
  findServersMock,
  serverStatesMock,
  getMcpServersMock,
  filterState,
} = vi.hoisted(() => ({
  getSessionMock: vi.fn(),
  invalidateServerConnectionMock: vi.fn(),
  isPooledClientMock: vi.fn(),
  findServersMock: vi.fn(),
  serverStatesMock: vi.fn(),
  getMcpServersMock: vi.fn(),
  filterState: {
    toolPolicy: "allow_all" as "allow_all" | "allowlist" | undefined,
  },
}));

vi.mock("@/utils/logger", () => ({
  default: { error: vi.fn(), warn: vi.fn(), info: vi.fn(), debug: vi.fn() },
}));

vi.mock("../../../db/index", () => ({ db: {}, pool: {} }));

// Binds the policy the real filter would have judged the call under.
vi.mock(
  "../../../lib/metamcp/metamcp-middleware/filter-tools.functional",
  () => ({
    createFilterCallToolMiddleware:
      () =>
      (next: (request: unknown, context: unknown) => unknown) =>
      (request: unknown, context: object) =>
        next(request, { ...context, toolPolicy: filterState.toolPolicy }),
    createFilterListToolsMiddleware: () => (h: unknown) => h,
  }),
);
vi.mock(
  "../../../lib/metamcp/metamcp-middleware/tool-overrides.functional",
  () => ({
    createToolOverridesCallToolMiddleware: () => (h: unknown) => h,
    createToolOverridesListToolsMiddleware: () => (h: unknown) => h,
  }),
);

vi.mock("../../../lib/metamcp/fetch-metamcp", () => ({
  getMcpServers: getMcpServersMock,
  getNamespaceServerStates: serverStatesMock,
}));
vi.mock("../../../db/repositories/namespaces.repo", () => ({
  namespacesRepository: {
    findServersForNamespaceToolName: findServersMock,
  },
}));
vi.mock("../../../lib/config.service", () => ({
  configService: {
    getMcpResetTimeoutOnProgress: vi.fn().mockResolvedValue(false),
    getMcpTimeout: vi.fn().mockResolvedValue(60000),
    getMcpMaxTotalTimeout: vi.fn().mockResolvedValue(60000),
    getMcpToolCallReconnectWarmupTimeout: vi.fn().mockResolvedValue(50),
  },
}));
vi.mock("../../../lib/metamcp/mcp-server-pool", () => ({
  mcpServerPool: {
    getSession: getSessionMock,
    invalidateServerConnection: invalidateServerConnectionMock,
    isPooledClient: isPooledClientMock,
  },
}));
vi.mock("../../../lib/metamcp/metamcp-server-pool", () => ({
  metaMcpServerPool: { getOpenApiServer: vi.fn().mockResolvedValue({}) },
}));
vi.mock("../../../lib/metamcp/caller-context", () => ({
  resolveCallerContext: vi.fn().mockReturnValue({}),
}));
vi.mock("../../../lib/metamcp/consumer-identity-resolver", () => ({
  resolveClientIdentity: vi.fn().mockResolvedValue({ name: "test-consumer" }),
}));

import { setAuditRecorderForTesting } from "../../../lib/metamcp/metamcp-middleware/auditing.functional";
import { executeToolWithMiddleware } from "./tool-execution";

const SERVERS = {
  "server-alpha": { uuid: "server-alpha", name: "alpha" },
  "server-beta": { uuid: "server-beta", name: "beta" },
  "server-gamma": { uuid: "server-gamma", name: "gamma" },
};
const TOOL = "gamma__run_report";

interface FakeSession {
  session: unknown;
  ran: string[];
}

function fakeSession(failCall?: () => Error | undefined): FakeSession {
  const ran: string[] = [];
  return {
    ran,
    session: {
      client: {
        request: vi.fn(async (req: { params: { name: string } }) => {
          const failure = failCall?.();
          if (failure) throw failure;
          ran.push(req.params.name);
          await new Promise((resolve) => setTimeout(resolve, 5));
          return {
            content: [{ type: "text", text: `ran ${req.params.name}` }],
          };
        }),
        getServerCapabilities: () => ({ tools: {} }),
        getServerVersion: () => ({ name: "gamma", version: "1.0.0" }),
      },
      listChangedSubscribers: new Set(),
    },
  };
}

function makeRes() {
  const res = {
    statusCode: 200,
    body: undefined as unknown,
    status: vi.fn((code: number) => {
      res.statusCode = code;
      return res;
    }),
    json: vi.fn((body: unknown) => {
      res.body = body;
      return res;
    }),
  };
  return res;
}

const run = async (toolName = TOOL) => {
  const res = makeRes();
  await executeToolWithMiddleware(
    { namespaceUuid: "ns-1", params: { tool_name: toolName } } as never,
    res as never,
    {},
  );
  return res;
};

const recorder = vi.fn();
// Flush the fire-and-forget persist() chain the audit middleware detaches.
const flush = () => new Promise((resolve) => setTimeout(resolve, 0));

const unavailableBody = (reason: string, server = "gamma") => ({
  error: "Backend unavailable",
  message: `Backend "${server}" is unavailable (${reason}): tool "${TOOL}" was not run. Retry the call.`,
  retryable: true,
});

beforeEach(() => {
  getSessionMock.mockReset();
  invalidateServerConnectionMock.mockReset();
  invalidateServerConnectionMock.mockResolvedValue(undefined);
  isPooledClientMock.mockReset();
  isPooledClientMock.mockReturnValue(true);
  findServersMock.mockReset();
  findServersMock.mockResolvedValue([]);
  serverStatesMock.mockReset();
  serverStatesMock.mockResolvedValue([]);
  getMcpServersMock.mockReset();
  getMcpServersMock.mockResolvedValue(SERVERS);
  filterState.toolPolicy = "allow_all";
  recorder.mockReset();
  recorder.mockResolvedValue(undefined);
  setAuditRecorderForTesting(recorder);
});

afterEach(() => {
  setAuditRecorderForTesting(undefined);
});

describe("OpenAPI bridge: prefix-first routing", () => {
  it("asks only the prefix's server for a session", async () => {
    const gamma = fakeSession();
    getSessionMock.mockResolvedValue(gamma.session);

    const res = await run();

    expect(res.statusCode).toBe(200);
    expect(gamma.ran).toEqual(["run_report"]);
    expect(getSessionMock.mock.calls.map(([, uuid]) => uuid)).toEqual([
      "server-gamma",
    ]);
  });

  it("keeps 404 'Tool not found' and the unknown_tool class for a prefix nobody carries", async () => {
    const res = await run("nosuch__run_report");
    await flush();

    expect(res.statusCode).toBe(404);
    expect(res.body).toMatchObject({ error: "Tool not found" });
    expect(getSessionMock).not.toHaveBeenCalled();
    expect(recorder.mock.calls[0][0]).toMatchObject({
      success: false,
      error_code: "unknown_tool",
    });
  });
});

describe("OpenAPI bridge: zero mapping rows", () => {
  it("allow_all warms the prefix's server and runs the tool", async () => {
    const gamma = fakeSession();
    getSessionMock
      .mockResolvedValueOnce(undefined)
      .mockResolvedValue(gamma.session);

    const res = await run();

    expect(res.statusCode).toBe(200);
    expect(gamma.ran).toEqual(["run_report"]);
  });

  it("allowlist does not route without an ACTIVE row", async () => {
    filterState.toolPolicy = "allowlist";
    const gamma = fakeSession();
    getSessionMock
      .mockResolvedValueOnce(undefined)
      .mockResolvedValue(gamma.session);

    const res = await run();

    expect(res.statusCode).toBe(404);
    expect(res.body).toMatchObject(unavailableBody("no_session"));
    expect(gamma.ran).toEqual([]);
    expect(getSessionMock).toHaveBeenCalledTimes(1);
  });
});

describe("OpenAPI bridge: a mounted server that cannot be used", () => {
  it("answers 404 'Backend unavailable' with the backend_unavailable audit class once the warm-up is exhausted", async () => {
    getSessionMock.mockResolvedValue(undefined);

    const res = await run();
    await flush();

    // Status kept at 404 on purpose; the body is the change.
    expect(res.statusCode).toBe(404);
    expect(res.body).toMatchObject(unavailableBody("no_session"));
    expect(recorder).toHaveBeenCalledTimes(1);
    expect(recorder.mock.calls[0][0]).toMatchObject({
      server_name: "gamma",
      tool_name: "run_report",
      success: false,
      error_code: "backend_unavailable",
    });
  });

  it("answers 'Backend unavailable' (error_gated) for an error-gated server", async () => {
    getMcpServersMock.mockResolvedValue({
      "server-alpha": SERVERS["server-alpha"],
    });
    serverStatesMock.mockResolvedValue([
      {
        uuid: "server-gamma",
        name: "gamma",
        mountStatus: "ACTIVE",
        errorStatus: "ERROR",
      },
    ]);

    const res = await run();

    expect(res.statusCode).toBe(404);
    expect(res.body).toMatchObject(unavailableBody("error_gated"));
    expect(getSessionMock).not.toHaveBeenCalled();
  });
});

describe("OpenAPI bridge: parallel calls on one dead client share one recovery", () => {
  it("8 parallel calls: one invalidation, all succeed on the replacement", async () => {
    let retired = false;
    const stale = fakeSession(() => new Error("Not connected"));
    const fresh = fakeSession();
    // Before the invalidation the pool still hands out the stale client.
    getSessionMock.mockImplementation(async () =>
      retired ? fresh.session : stale.session,
    );
    isPooledClientMock.mockImplementation(() => !retired);
    invalidateServerConnectionMock.mockImplementation(async () => {
      retired = true;
    });

    const results = await Promise.all(Array.from({ length: 8 }, () => run()));

    expect(results.map((res) => res.statusCode)).toEqual(
      Array.from({ length: 8 }, () => 200),
    );
    expect(fresh.ran).toHaveLength(8);
    expect(invalidateServerConnectionMock).toHaveBeenCalledTimes(1);
  });
});
