/**
 * `X-Umbrella-User-Id` and `X-Umbrella-Caller` are gateway-set only, so
 * `mcpServers.create`, `.update` and `.bulkImport` refuse either name as a
 * stored header key, in any casing and with surrounding whitespace ignored.
 *
 * Driven over HTTP through `fetchRequestHandler` with the REAL `@repo/trpc`
 * router, its input schemas and the real implementations, as the stdio policy
 * test is: the caller gets HTTP 400 BAD_REQUEST with one fixed sentence (not
 * `success: false` inside an HTTP 200), and a refusal reads, writes, pools and
 * audits nothing. A row whose headers name neither is saved as before.
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
      updateReportingChange: vi.fn(),
      findByUuid: vi.fn(),
      bulkCreate: vi.fn(),
    },
    mappings: { findNamespacesByServerUuid: vi.fn() },
    pool: {
      ensureIdleSessionForNewServer: vi.fn(),
      invalidateIdleSession: vi.fn(),
      invalidateServerConnection: vi.fn(),
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
const { mcpServersImplementations, STORED_IDENTITY_HEADER_REFUSED } =
  await import("./mcp-servers.impl");

const adminCtx = {
  user: { id: "admin-1", role: "admin", email: "admin@example.invalid" },
  session: { id: "s-admin" },
  audit: {
    actor_ip: "203.0.113.7",
    actor_user_agent: "vitest",
    request_id: "req-identity-headers",
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
  created_at: new Date("2026-11-13T00:00:00.000Z"),
  user_id: null,
  ...overrides,
});

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
  repo.updateReportingChange.mockImplementation(
    async (input: Record<string, unknown>) => ({
      server: row({ ...input }),
      destinationOrCredentialChanged: false,
    }),
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
});

/** The refusal reached the client as HTTP 400 with the fixed sentence. */
function expectRefused(
  result: Awaited<ReturnType<typeof mutate>>,
  message: string = STORED_IDENTITY_HEADER_REFUSED,
) {
  expect(result.status).toBe(400);
  expect(result.body.result).toBeUndefined();
  expect(result.body.error?.data.code).toBe("BAD_REQUEST");
  expect(result.body.error?.message).toBe(message);
}

/** Nothing was read, written, converted, pooled or audited. */
async function expectNoSideEffects() {
  await flush();
  expect(repo.create).not.toHaveBeenCalled();
  expect(repo.updateReportingChange).not.toHaveBeenCalled();
  expect(repo.findByUuid).not.toHaveBeenCalled();
  expect(repo.bulkCreate).not.toHaveBeenCalled();
  expect(convert).not.toHaveBeenCalled();
  expect(pool.ensureIdleSessionForNewServer).not.toHaveBeenCalled();
  expect(auditRows).toEqual([]);
}

const HTTP_CREATE = {
  name: "backend",
  type: "STREAMABLE_HTTP",
  url: "https://backend.example.invalid/mcp",
};

// Each identity header name as an administrator might type it.
const IDENTITY_HEADER_KEYS: Array<[string]> = [
  ["X-Umbrella-User-Id"],
  ["x-umbrella-user-id"],
  ["X-UMBRELLA-USER-ID"],
  ["X-Umbrella-Caller"],
  ["x-umbrella-caller"],
  ["X-uMbReLlA-cAlLeR"],
  [" X-Umbrella-User-Id "],
  ["\tx-umbrella-caller"],
];

const CUSTOM_HEADERS = { "X-Custom-Tenant": "tenant-a" };

it("the refusal is one fixed sentence that names both headers", () => {
  expect(STORED_IDENTITY_HEADER_REFUSED).toContain("X-Umbrella-User-Id");
  expect(STORED_IDENTITY_HEADER_REFUSED).toContain("X-Umbrella-Caller");
});

describe("mcpServers.create", () => {
  it.each(IDENTITY_HEADER_KEYS)(
    "refuses a stored %j header with HTTP 400 and no side effects",
    async (key) => {
      const result = await mutate("create", {
        ...HTTP_CREATE,
        headers: { ...CUSTOM_HEADERS, [key]: "user-stored" },
      });

      expectRefused(result);
      await expectNoSideEffects();
    },
  );

  it("still creates a server whose headers name neither, and stores them", async () => {
    const result = await mutate("create", {
      ...HTTP_CREATE,
      headers: CUSTOM_HEADERS,
    });
    await flush();

    expect(result.status).toBe(200);
    expect(result.body.result?.data).toMatchObject({ success: true });
    expect(repo.create).toHaveBeenCalledTimes(1);
    expect(repo.create.mock.calls[0][0]).toMatchObject({
      headers: CUSTOM_HEADERS,
    });
  });
});

describe("mcpServers.update", () => {
  it.each(IDENTITY_HEADER_KEYS)(
    "refuses a stored %j header with HTTP 400 and no side effects",
    async (key) => {
      const result = await mutate("update", {
        uuid: SERVER_UUID,
        ...HTTP_CREATE,
        headers: { ...CUSTOM_HEADERS, [key]: "user-stored" },
      });

      expectRefused(result);
      // Not even the existence read: the answer does not depend on the row.
      await expectNoSideEffects();
    },
  );

  it("still updates a server whose headers name neither, and stores them", async () => {
    const result = await mutate("update", {
      uuid: SERVER_UUID,
      ...HTTP_CREATE,
      headers: CUSTOM_HEADERS,
    });
    await flush();

    expect(result.status).toBe(200);
    expect(result.body.result?.data).toMatchObject({ success: true });
    expect(repo.updateReportingChange).toHaveBeenCalledTimes(1);
    expect(repo.updateReportingChange.mock.calls[0][0]).toMatchObject({
      headers: CUSTOM_HEADERS,
    });
  });
});

describe("mcpServers.bulkImport", () => {
  const HTTP_ENTRY = {
    type: "streamable_http",
    url: "https://backend.example.invalid/mcp",
    headers: CUSTOM_HEADERS,
  };

  it.each(IDENTITY_HEADER_KEYS)(
    "refuses the WHOLE import when one entry stores a %j header, writing nothing",
    async (key) => {
      const result = await mutate("bulkImport", {
        mcpServers: {
          "http-one": HTTP_ENTRY,
          "http-two": { ...HTTP_ENTRY, headers: { [key]: "user-stored" } },
        },
      });

      expectRefused(
        result,
        `${STORED_IDENTITY_HEADER_REFUSED} Nothing was imported.`,
      );
      await expectNoSideEffects();
    },
  );

  it("still imports entries whose headers name neither, and stores them", async () => {
    const result = await mutate("bulkImport", {
      mcpServers: { "http-one": HTTP_ENTRY },
    });
    await flush();

    expect(result.status).toBe(200);
    expect(result.body.result?.data).toMatchObject({
      success: true,
      imported: 1,
    });
    expect(repo.bulkCreate.mock.calls[0][0]).toEqual([
      expect.objectContaining({ headers: CUSTOM_HEADERS }),
    ]);
  });
});
