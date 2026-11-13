/**
 * A failed MCP server write is reported in the log without the row it failed
 * to write.
 *
 * An MCP server row carries the credentials the gateway uses to reach a third
 * party: environment variables, HTTP headers and a bearer token. Drizzle wraps
 * a failed query in a DrizzleQueryError whose message is
 * "Failed query: <sql>\nparams: <bound values>" and which also keeps the bound
 * values on `.params`; the node-postgres error under it quotes the row in its
 * `detail` ("Failing row contains (...)"). The logger formats its arguments
 * with util.format, so handing it the raw error copies those values into the
 * container log. These tests drive the real create and update handlers with a
 * repository that throws such an error, and read what the logger was given
 * the way the logger does.
 *
 * Repositories and pools are mocked so the unit needs no postgres.
 */
import { format } from "node:util";

import { DrizzleQueryError } from "drizzle-orm/errors";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { loggerMock } = vi.hoisted(() => ({
  loggerMock: {
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  },
}));

vi.mock("@/utils/logger", () => ({ default: loggerMock }));

vi.mock("../db/repositories", () => ({
  mcpServersRepository: {
    create: vi.fn(),
    findByUuid: vi.fn(),
    updateReportingChange: vi.fn(),
  },
  namespaceMappingsRepository: {
    findNamespacesByServerUuid: vi.fn(async () => []),
  },
}));

vi.mock("../lib/audit/admin-event", () => ({ emitAdminEvent: vi.fn() }));

vi.mock("../lib/metamcp/mcp-server-pool", () => ({
  mcpServerPool: {
    invalidateServerConnection: vi.fn(async () => undefined),
    invalidateIdleSession: vi.fn(async () => undefined),
    ensureIdleSessionForNewServer: vi.fn(async () => undefined),
  },
}));
vi.mock("../lib/metamcp/metamcp-server-pool", () => ({
  metaMcpServerPool: {
    invalidateIdleServers: vi.fn(async () => undefined),
    invalidateOpenApiSessions: vi.fn(async () => undefined),
  },
}));
vi.mock("../lib/metamcp/metamcp-middleware/tool-overrides.functional", () => ({
  clearOverrideCache: vi.fn(),
}));
vi.mock("../lib/metamcp/server-error-tracker", () => ({
  serverErrorTracker: { resetServerErrorState: vi.fn(async () => undefined) },
}));
vi.mock("../lib/metamcp/utils", () => ({
  convertDbServerToParams: vi.fn(async () => undefined),
}));

import { mcpServersRepository } from "../db/repositories";
import { mcpServersImplementations } from "./mcp-servers.impl";

// Obviously fake credentials: one in an environment variable, one in a header,
// one as the bearer token.
const ENV_SECRET = "fake-env-secret-aaaa1111";
const HEADER_SECRET = "fake-header-secret-bbbb2222";
const BEARER_SECRET = "fake-bearer-secret-cccc3333";
const SECRETS = [ENV_SECRET, HEADER_SECRET, BEARER_SECRET];

const UUID = "11111111-1111-4111-8111-111111111111";

const ACTOR = {
  actor_id: "admin-1",
  actor_label: "admin@example.test",
  actor_ip: null,
  actor_user_agent: null,
  request_id: null,
};

/**
 * What node-postgres hands Drizzle for a rejected statement: a message that
 * can quote values, a `detail` that does quote the failing row, and the stable
 * identifiers (SQLSTATE, constraint, table) an operator diagnoses from.
 */
function postgresCause(): Error {
  return Object.assign(
    new Error(`value too long for type character varying(255): ${ENV_SECRET}`),
    {
      code: "22001",
      constraint: "mcp_servers_env_len",
      table: "mcp_servers",
      detail: `Failing row contains (${ENV_SECRET}, ${HEADER_SECRET}, ${BEARER_SECRET}).`,
    },
  );
}

/** A real Drizzle query error whose bound values hold every secret. */
function failedWrite(statement: string): DrizzleQueryError {
  return new DrizzleQueryError(
    statement,
    [
      "vendor",
      JSON.stringify({ UPSTREAM_API_KEY: ENV_SECRET }),
      JSON.stringify({ Authorization: `Bearer ${HEADER_SECRET}` }),
      BEARER_SECRET,
    ],
    postgresCause(),
  );
}

/** Everything the logger was given, formatted the way the logger formats it. */
function loggedText(): string {
  return [
    ...loggerMock.debug.mock.calls,
    ...loggerMock.info.mock.calls,
    ...loggerMock.warn.mock.calls,
    ...loggerMock.error.mock.calls,
  ]
    .map((args) => format(...args))
    .join("\n");
}

function expectLogIsFree(logged: string, statement: string): void {
  for (const secret of SECRETS) {
    expect(logged).not.toContain(secret);
  }
  expect(logged).not.toContain(statement);
  expect(logged).not.toContain("Failed query");
  expect(logged).not.toContain("Failing row contains");
}

const row = {
  uuid: UUID,
  name: "vendor",
  description: null,
  type: "STREAMABLE_HTTP",
  command: null,
  args: [],
  env: {},
  url: "https://mcp.example.test/mcp",
  bearerToken: null,
  headers: {},
  error_status: "NONE",
  created_at: new Date("2026-11-01T00:00:00Z"),
  user_id: null,
} as never;

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(mcpServersRepository.findByUuid).mockResolvedValue(row);
});

describe("mcpServers.create when the insert fails", () => {
  const statement =
    'insert into "mcp_servers" ("name", "env", "headers", "bearerToken") values ($1, $2, $3, $4)';

  it("keeps the credentials, the query text and the database detail out of the log", async () => {
    vi.mocked(mcpServersRepository.create).mockRejectedValue(
      failedWrite(statement),
    );

    const result = await mcpServersImplementations.create(
      {
        name: "vendor",
        type: "STREAMABLE_HTTP",
        url: "https://mcp.example.test/mcp",
        env: { UPSTREAM_API_KEY: ENV_SECRET },
        headers: { Authorization: `Bearer ${HEADER_SECRET}` },
        bearerToken: BEARER_SECRET,
      } as never,
      "admin-1",
      ACTOR,
    );

    expect(result.success).toBe(false);
    expect(loggerMock.error).toHaveBeenCalledTimes(1);
    expectLogIsFree(loggedText(), statement);
  });

  it("still names the failing handler, the error class and the SQLSTATE", async () => {
    vi.mocked(mcpServersRepository.create).mockRejectedValue(
      failedWrite(statement),
    );

    await mcpServersImplementations.create(
      {
        name: "vendor",
        type: "STREAMABLE_HTTP",
        url: "https://mcp.example.test/mcp",
        env: { UPSTREAM_API_KEY: ENV_SECRET },
      } as never,
      "admin-1",
      ACTOR,
    );

    const logged = loggedText();
    expect(logged).toContain("Error creating MCP server:");
    expect(logged).toContain("DrizzleQueryError");
    expect(logged).toContain("22001");
    expect(logged).toContain("mcp_servers_env_len");
  });
});

describe("mcpServers.update when the write fails", () => {
  const statement =
    'update "mcp_servers" set "env" = $1, "headers" = $2, "bearerToken" = $3 where "mcp_servers"."uuid" = $4';

  it("keeps the credentials, the query text and the database detail out of the log", async () => {
    vi.mocked(mcpServersRepository.updateReportingChange).mockRejectedValue(
      failedWrite(statement),
    );

    const result = await mcpServersImplementations.update(
      {
        uuid: UUID,
        name: "vendor",
        type: "STREAMABLE_HTTP",
        url: "https://mcp.example.test/mcp",
        env: { UPSTREAM_API_KEY: ENV_SECRET },
        headers: { Authorization: `Bearer ${HEADER_SECRET}` },
        bearerToken: BEARER_SECRET,
      } as never,
      "admin-1",
      ACTOR,
    );

    expect(result.success).toBe(false);
    expect(loggerMock.error).toHaveBeenCalledTimes(1);
    expectLogIsFree(loggedText(), statement);
  });

  it("still names the failing handler, the error class and the SQLSTATE", async () => {
    vi.mocked(mcpServersRepository.updateReportingChange).mockRejectedValue(
      failedWrite(statement),
    );

    await mcpServersImplementations.update(
      {
        uuid: UUID,
        name: "vendor",
        type: "STREAMABLE_HTTP",
        url: "https://mcp.example.test/mcp",
      } as never,
      "admin-1",
      ACTOR,
    );

    const logged = loggedText();
    expect(logged).toContain("Error updating MCP server:");
    expect(logged).toContain("DrizzleQueryError");
    expect(logged).toContain("22001");
  });
});

describe("mcpServers.get when the read fails", () => {
  it("keeps the bound lookup values out of the log", async () => {
    const statement =
      'select "uuid", "env", "headers" from "mcp_servers" where "mcp_servers"."uuid" = $1';
    vi.mocked(mcpServersRepository.findByUuid).mockRejectedValue(
      failedWrite(statement),
    );

    const result = await mcpServersImplementations.get(
      { uuid: UUID } as never,
      "admin-1",
      true,
    );

    expect(result.success).toBe(false);
    expectLogIsFree(loggedText(), statement);
    expect(loggedText()).toContain("DrizzleQueryError");
  });
});
