/**
 * stdio servers are refused by `mcpServers.create`, `.update` and
 * `.bulkImport` unless ALLOW_STDIO_SERVERS is exactly "true".
 *
 * Driven over HTTP through `fetchRequestHandler` with the REAL `@repo/trpc`
 * router, its input schemas and the real implementations, so three things are
 * proven together rather than inferred from a helper's return value:
 *  - the caller gets HTTP 400 with code BAD_REQUEST, not `success: false`
 *    inside an HTTP 200 (each method has a broad catch that would do that to
 *    a throw inside it);
 *  - bulk import's schema normalization (no type, empty type, `std`, any case
 *    of `stdio`) cannot carry a stdio entry past the gate;
 *  - nothing happens on a refusal: no repository read or write, no conversion
 *    to spawn parameters, no pool call and no audit row.
 *
 * Only the layer under the implementations is replaced: repositories, pools,
 * the conversion helper and the audit sink.
 */

import { createMcpServersRouter } from "@repo/trpc";
import { fetchRequestHandler } from "@trpc/server/adapters/fetch";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@/utils/logger", () => ({
  default: { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() },
}));

const { repo, mappings, pool, metaPool, errorTracker, convert } = vi.hoisted(
  () => ({
    repo: {
      create: vi.fn(),
      update: vi.fn(),
      findByUuid: vi.fn(),
      bulkCreate: vi.fn(),
    },
    mappings: { findNamespacesByServerUuid: vi.fn() },
    pool: {
      ensureIdleSessionForNewServer: vi.fn(),
      invalidateIdleSession: vi.fn(),
    },
    metaPool: {
      invalidateIdleServers: vi.fn(),
      invalidateOpenApiSessions: vi.fn(),
    },
    errorTracker: { resetServerErrorState: vi.fn() },
    convert: vi.fn(),
  }),
);

vi.mock("../db/repositories", () => ({
  mcpServersRepository: repo,
  namespaceMappingsRepository: mappings,
}));
vi.mock("../lib/metamcp/mcp-server-pool", () => ({ mcpServerPool: pool }));
vi.mock("../lib/metamcp/metamcp-server-pool", () => ({
  metaMcpServerPool: metaPool,
}));
vi.mock("../lib/metamcp/server-error-tracker", () => ({
  serverErrorTracker: errorTracker,
}));
vi.mock("../lib/metamcp/metamcp-middleware/tool-overrides.functional", () => ({
  clearOverrideCache: vi.fn(),
}));
vi.mock("../lib/metamcp/utils", () => ({ convertDbServerToParams: convert }));

const { setAuditSinkForTesting } = await import("@/lib/audit/audit-emitter");
const { STDIO_SERVERS_DISABLED_MESSAGE } = await import(
  "../lib/metamcp/stdio-policy"
);
const { mcpServersImplementations } = await import("./mcp-servers.impl");

const adminCtx = {
  user: { id: "admin-1", role: "admin", email: "admin@example.invalid" },
  session: { id: "s-admin" },
  audit: {
    actor_ip: "203.0.113.7",
    actor_user_agent: "vitest",
    request_id: "req-stdio-policy",
  },
};

const SERVER_UUID = "44444444-4444-4444-8444-444444444444";

const row = (overrides: Record<string, unknown> = {}) => ({
  uuid: SERVER_UUID,
  name: "backend",
  description: null,
  type: "STREAMABLE_HTTP",
  command: null,
  args: [],
  env: {},
  url: "https://backend.example.invalid/mcp",
  bearerToken: null,
  headers: {},
  error_status: "NONE",
  created_at: new Date("2026-11-11T00:00:00.000Z"),
  user_id: null,
  ...overrides,
});

const stdioRow = () =>
  row({ type: "STDIO", command: "npx", args: ["some-mcp"], url: null });

type TrpcHttpBody = {
  result?: { data: Record<string, unknown> };
  error?: { message: string; data: { code: string; httpStatus: number } };
};

/** POST a mutation through the real HTTP pipeline, as the dashboard does. */
async function mutate(path: string, input: unknown) {
  const response = await fetchRequestHandler({
    endpoint: "/trpc",
    req: new Request(`http://test.invalid/trpc/${path}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(input),
    }),
    router: createMcpServersRouter(mcpServersImplementations),
    createContext: () => adminCtx as never,
    onError: () => {
      // Deliberate refusals; tRPC would otherwise print each to the console.
    },
  });
  return {
    status: response.status,
    body: (await response.json()) as TrpcHttpBody,
  };
}

let auditRows: Array<{ action: string }>;
const flush = () => new Promise((resolve) => setTimeout(resolve, 0));

beforeEach(() => {
  vi.clearAllMocks();
  repo.create.mockImplementation(async (input: Record<string, unknown>) =>
    row({ ...input, uuid: SERVER_UUID }),
  );
  repo.update.mockImplementation(async (input: Record<string, unknown>) =>
    row({ ...input }),
  );
  repo.findByUuid.mockResolvedValue(row());
  repo.bulkCreate.mockImplementation(
    async (servers: Array<Record<string, unknown>>) =>
      servers.map((server, index) =>
        row({ ...server, uuid: `5555555${index}-5555-4555-8555-555555555555` }),
      ),
  );
  mappings.findNamespacesByServerUuid.mockResolvedValue([]);
  pool.ensureIdleSessionForNewServer.mockResolvedValue(undefined);
  pool.invalidateIdleSession.mockResolvedValue(undefined);
  metaPool.invalidateIdleServers.mockResolvedValue(undefined);
  metaPool.invalidateOpenApiSessions.mockResolvedValue(undefined);
  errorTracker.resetServerErrorState.mockResolvedValue(undefined);
  convert.mockResolvedValue(null);

  auditRows = [];
  setAuditSinkForTesting(async (event) => {
    auditRows.push(event as { action: string });
  });
});

afterEach(() => {
  setAuditSinkForTesting(undefined);
  vi.unstubAllEnvs();
});

/** The refusal reached the client as a real HTTP 400 BAD_REQUEST. */
function expectBadRequest(result: Awaited<ReturnType<typeof mutate>>) {
  expect(result.status).toBe(400);
  expect(result.body.result).toBeUndefined();
  expect(result.body.error?.data.code).toBe("BAD_REQUEST");
  expect(result.body.error?.data.httpStatus).toBe(400);
  expect(result.body.error?.message).toContain(STDIO_SERVERS_DISABLED_MESSAGE);
}

/** Nothing was read, written, converted, pooled or audited. */
async function expectNoSideEffects() {
  await flush();
  expect(repo.create).not.toHaveBeenCalled();
  expect(repo.update).not.toHaveBeenCalled();
  expect(repo.findByUuid).not.toHaveBeenCalled();
  expect(repo.bulkCreate).not.toHaveBeenCalled();
  expect(convert).not.toHaveBeenCalled();
  expect(pool.ensureIdleSessionForNewServer).not.toHaveBeenCalled();
  expect(pool.invalidateIdleSession).not.toHaveBeenCalled();
  expect(metaPool.invalidateIdleServers).not.toHaveBeenCalled();
  expect(metaPool.invalidateOpenApiSessions).not.toHaveBeenCalled();
  expect(errorTracker.resetServerErrorState).not.toHaveBeenCalled();
  expect(mappings.findNamespacesByServerUuid).not.toHaveBeenCalled();
  expect(auditRows).toEqual([]);
}

const STDIO_CREATE = { name: "local-tool", type: "STDIO", command: "npx" };
const HTTP_CREATE = {
  name: "backend",
  type: "STREAMABLE_HTTP",
  url: "https://backend.example.invalid/mcp",
};
const SSE_CREATE = {
  name: "sse-backend",
  type: "SSE",
  url: "https://sse.example.invalid/sse",
};

// Every value that is not exactly "true" refuses. `undefined` means unset.
const REFUSING_VALUES: Array<[string, string | undefined]> = [
  ["unset", undefined],
  ["empty", ""],
  ["false", "false"],
  ["TRUE", "TRUE"],
  ["1", "1"],
  ["yes", "yes"],
  ["padded ' true'", " true"],
];

const setFlag = (value: string | undefined) => {
  vi.stubEnv("ALLOW_STDIO_SERVERS", value);
};

describe("mcpServers.create", () => {
  it.each(REFUSING_VALUES)(
    "refuses a stdio server with HTTP 400 and no side effects when the flag is %s",
    async (_label, value) => {
      setFlag(value);

      const result = await mutate("create", STDIO_CREATE);

      expectBadRequest(result);
      await expectNoSideEffects();
    },
  );

  it('creates a stdio server when the flag is exactly "true"', async () => {
    setFlag("true");

    const result = await mutate("create", STDIO_CREATE);
    await flush();

    expect(result.status).toBe(200);
    expect(result.body.result?.data).toMatchObject({ success: true });
    expect(repo.create).toHaveBeenCalledTimes(1);
    expect(repo.create.mock.calls[0][0]).toMatchObject({ type: "STDIO" });
    expect(auditRows.map((r) => r.action)).toEqual(["mcpserver.create"]);
  });

  it.each([
    ["Streamable HTTP", HTTP_CREATE],
    ["SSE", SSE_CREATE],
  ])("still creates a %s server with the flag unset", async (_label, input) => {
    setFlag(undefined);

    const result = await mutate("create", input);
    await flush();

    expect(result.status).toBe(200);
    expect(result.body.result?.data).toMatchObject({ success: true });
    expect(repo.create).toHaveBeenCalledTimes(1);
    expect(auditRows.map((r) => r.action)).toEqual(["mcpserver.create"]);
  });
});

describe("mcpServers.update", () => {
  const STDIO_UPDATE = { uuid: SERVER_UUID, ...STDIO_CREATE };

  it.each(REFUSING_VALUES)(
    "refuses a change to stdio with HTTP 400 and no side effects when the flag is %s",
    async (_label, value) => {
      setFlag(value);

      const result = await mutate("update", STDIO_UPDATE);

      expectBadRequest(result);
      // Not even the existence read: the answer does not depend on the row.
      await expectNoSideEffects();
    },
  );

  it("refuses an edit that keeps a stored stdio server stdio", async () => {
    setFlag(undefined);
    repo.findByUuid.mockResolvedValue(stdioRow());

    const result = await mutate("update", {
      ...STDIO_UPDATE,
      description: "renamed",
    });

    expectBadRequest(result);
    await expectNoSideEffects();
  });

  it("lets a stored stdio server be switched to Streamable HTTP with the flag unset", async () => {
    setFlag(undefined);
    repo.findByUuid.mockResolvedValue(stdioRow());

    const result = await mutate("update", {
      uuid: SERVER_UUID,
      ...HTTP_CREATE,
    });
    await flush();

    expect(result.status).toBe(200);
    expect(result.body.result?.data).toMatchObject({ success: true });
    expect(repo.update).toHaveBeenCalledTimes(1);
    expect(repo.update.mock.calls[0][0]).toMatchObject({
      type: "STREAMABLE_HTTP",
    });
  });

  it.each([
    ["Streamable HTTP", HTTP_CREATE],
    ["SSE", SSE_CREATE],
  ])("still updates a %s server with the flag unset", async (_label, input) => {
    setFlag(undefined);

    const result = await mutate("update", { uuid: SERVER_UUID, ...input });
    await flush();

    expect(result.status).toBe(200);
    expect(result.body.result?.data).toMatchObject({ success: true });
    expect(repo.update).toHaveBeenCalledTimes(1);
    expect(auditRows.map((r) => r.action)).toEqual(["mcpserver.update"]);
  });

  it('updates a stdio server when the flag is exactly "true"', async () => {
    setFlag("true");
    repo.findByUuid.mockResolvedValue(stdioRow());

    const result = await mutate("update", STDIO_UPDATE);
    await flush();

    expect(result.status).toBe(200);
    expect(result.body.result?.data).toMatchObject({ success: true });
    expect(repo.update).toHaveBeenCalledTimes(1);
  });
});

describe("mcpServers.bulkImport", () => {
  const HTTP_ENTRY = {
    type: "streamable_http",
    url: "https://backend.example.invalid/mcp",
  };

  it.each([
    ["an explicit STDIO type", { type: "STDIO", command: "npx" }],
    ["lower-case stdio", { type: "stdio", command: "npx" }],
    ["the std alias", { type: "std", command: "npx" }],
    ["the Std alias", { type: "Std", command: "npx" }],
    ["an empty type", { type: "", command: "npx" }],
    ["no type at all", { command: "npx" }],
  ])(
    "refuses the WHOLE import when one entry is %s, writing nothing",
    async (_label, stdioEntry) => {
      setFlag(undefined);

      const result = await mutate("bulkImport", {
        mcpServers: { "http-one": HTTP_ENTRY, "local-tool": stdioEntry },
      });

      expectBadRequest(result);
      expect(result.body.error?.message).toContain("Nothing was imported");
      expect(result.body.error?.message).toContain('"local-tool"');
      expect(result.body.error?.message).not.toContain('"http-one"');
      // Zero rows reach bulkCreate: the allowed HTTP entry is not imported
      // either, so an import is never half applied.
      await expectNoSideEffects();
    },
  );

  it.each(REFUSING_VALUES)(
    "refuses a stdio entry when the flag is %s",
    async (_label, value) => {
      setFlag(value);

      const result = await mutate("bulkImport", {
        mcpServers: { "local-tool": { type: "STDIO", command: "npx" } },
      });

      expectBadRequest(result);
      await expectNoSideEffects();
    },
  );

  it("bounds the names it lists in the refusal", async () => {
    setFlag(undefined);
    const longName = "x".repeat(500);
    const mcpServers: Record<string, unknown> = { [longName]: {} };
    for (let i = 0; i < 14; i++) {
      mcpServers[`local-${i}`] = { command: "npx" };
    }

    const result = await mutate("bulkImport", { mcpServers });

    expectBadRequest(result);
    const message = result.body.error?.message ?? "";
    expect(message).toContain(`"${"x".repeat(64)}"`);
    expect(message).not.toContain("x".repeat(65));
    expect(message).toContain("and 5 more");
    expect(repo.bulkCreate).not.toHaveBeenCalled();
  });

  it("imports an all-HTTP/SSE request unchanged with the flag unset", async () => {
    setFlag(undefined);

    const result = await mutate("bulkImport", {
      mcpServers: {
        "http-one": HTTP_ENTRY,
        "sse-one": { type: "sse", url: "https://sse.example.invalid/sse" },
      },
    });
    await flush();

    expect(result.status).toBe(200);
    expect(result.body.result?.data).toMatchObject({
      success: true,
      imported: 2,
    });
    expect(repo.bulkCreate).toHaveBeenCalledTimes(1);
    expect(
      repo.bulkCreate.mock.calls[0][0].map(
        (server: { name: string; type: string }) => [server.name, server.type],
      ),
    ).toEqual([
      ["http-one", "STREAMABLE_HTTP"],
      ["sse-one", "SSE"],
    ]);
    expect(auditRows.map((r) => r.action)).toEqual(["mcpserver.bulk_import"]);
  });

  it('imports a mixed request in full when the flag is exactly "true"', async () => {
    setFlag("true");

    const result = await mutate("bulkImport", {
      mcpServers: { "http-one": HTTP_ENTRY, "local-tool": { command: "npx" } },
    });

    expect(result.status).toBe(200);
    expect(result.body.result?.data).toMatchObject({
      success: true,
      imported: 2,
    });
    expect(repo.bulkCreate).toHaveBeenCalledTimes(1);
    expect(
      repo.bulkCreate.mock.calls[0][0].map(
        (server: { type: string }) => server.type,
      ),
    ).toEqual(["STREAMABLE_HTTP", "STDIO"]);
  });
});
