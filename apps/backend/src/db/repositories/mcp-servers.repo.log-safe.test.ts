/**
 * The MCP servers repository reports a failed write without the row it failed
 * to write.
 *
 * `create`, `update` and `bulkCreate` catch the Drizzle error themselves, log
 * it, and throw a fixed message to their caller, so this log line is where the
 * server definition (environment variables, HTTP headers) would be copied into
 * the container log if the raw error were handed to the logger. The logger
 * formats its arguments with util.format, which prints a DrizzleQueryError's
 * message ("Failed query: <sql>\nparams: <bound values>"), its `params` and its
 * `cause`.
 *
 * Runs against a Drizzle mock (the repo destructures `db` at module load), so
 * it asserts what the repository logs and throws, not the postgres engine.
 */
import { format } from "node:util";

import { DrizzleQueryError } from "drizzle-orm/errors";
import { DatabaseError } from "pg";
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

const insertChain = {
  values: vi.fn().mockReturnThis(),
  returning: vi.fn(),
};
const updateChain = {
  set: vi.fn().mockReturnThis(),
  where: vi.fn().mockReturnThis(),
  returning: vi.fn(),
};
const currentRow = {
  type: "STREAMABLE_HTTP",
  url: null,
  bearerToken: null,
  headers: {},
};
const selectChain = {
  from: vi.fn().mockReturnThis(),
  where: vi.fn().mockReturnThis(),
  for: vi.fn(async () => [currentRow]),
};

vi.mock("../index", () => ({
  db: {
    insert: vi.fn(() => insertChain),
    update: vi.fn(() => updateChain),
    transaction: vi.fn(async (run: (tx: unknown) => Promise<unknown>) =>
      run({
        select: vi.fn(() => selectChain),
        update: vi.fn(() => updateChain),
      }),
    ),
  },
}));

// schema.ts pulls @repo/zod-types, which vitest cannot resolve in unit mode;
// stub the one table the repo touches.
vi.mock("../schema", () => ({
  mcpServersTable: {
    uuid: { name: "uuid" },
    name: { name: "name" },
    bearerToken: { name: "bearer_token" },
    created_at: { name: "created_at" },
    user_id: { name: "user_id" },
  },
}));

import { mcpServersRepository } from "./mcp-servers.repo";

// Obviously fake credentials: one in an environment variable, one in a header.
const ENV_SECRET = "fake-env-secret-dddd4444";
const HEADER_SECRET = "fake-header-secret-eeee5555";
const STATEMENT =
  'insert into "mcp_servers" ("name", "env", "headers") values ($1, $2, $3)';

/** What node-postgres raises for a rejected statement, as the real class. */
function postgresError(code: string, constraint: string): DatabaseError {
  const error = new DatabaseError(
    `value too long for type character varying(255): ${ENV_SECRET}`,
    0,
    "error",
  );
  error.code = code;
  error.constraint = constraint;
  error.table = "mcp_servers";
  error.detail = `Failing row contains (${ENV_SECRET}, ${HEADER_SECRET}).`;
  return error;
}

function failedWrite(code: string, constraint: string): DrizzleQueryError {
  return new DrizzleQueryError(
    STATEMENT,
    [
      "vendor",
      JSON.stringify({ UPSTREAM_API_KEY: ENV_SECRET }),
      JSON.stringify({ Authorization: `Bearer ${HEADER_SECRET}` }),
    ],
    postgresError(code, constraint),
  );
}

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

function expectLogIsFree(logged: string): void {
  expect(logged).not.toContain(ENV_SECRET);
  expect(logged).not.toContain(HEADER_SECRET);
  expect(logged).not.toContain(STATEMENT);
  expect(logged).not.toContain("Failed query");
  expect(logged).not.toContain("Failing row contains");
}

const server = {
  name: "vendor",
  type: "STREAMABLE_HTTP",
  url: "https://mcp.example.test/mcp",
  env: { UPSTREAM_API_KEY: ENV_SECRET },
  headers: { Authorization: `Bearer ${HEADER_SECRET}` },
} as never;

beforeEach(() => {
  vi.clearAllMocks();
  insertChain.values.mockReturnThis();
  updateChain.set.mockReturnThis();
  updateChain.where.mockReturnThis();
  selectChain.from.mockReturnThis();
  selectChain.where.mockReturnThis();
});

describe("McpServersRepository write failures", () => {
  it("create logs the error class and database code, not the row", async () => {
    insertChain.returning.mockRejectedValue(
      failedWrite("22001", "mcp_servers_env_len"),
    );

    await expect(mcpServersRepository.create(server)).rejects.toThrow(
      "Failed to create MCP server. Please check your input and try again.",
    );

    const logged = loggedText();
    expectLogIsFree(logged);
    expect(logged).toContain("Database error in create:");
    expect(logged).toContain("DrizzleQueryError");
    expect(logged).toContain("22001");
    expect(logged).toContain("mcp_servers_env_len");
  });

  it("create keeps the row out of the log when the name is a duplicate", async () => {
    insertChain.returning.mockRejectedValue(
      failedWrite("23505", "mcp_servers_name_user_unique_idx"),
    );

    await expect(mcpServersRepository.create(server)).rejects.toThrow(
      'Server name "vendor" already exists.',
    );

    const logged = loggedText();
    expectLogIsFree(logged);
    expect(logged).toContain("23505");
  });

  it("update logs the error class and database code, not the row", async () => {
    updateChain.returning.mockRejectedValue(
      failedWrite("22001", "mcp_servers_env_len"),
    );

    await expect(
      mcpServersRepository.updateReportingChange({
        ...(server as object),
        uuid: "11111111-1111-4111-8111-111111111111",
      } as never),
    ).rejects.toThrow(
      "Failed to update MCP server. Please check your input and try again.",
    );

    const logged = loggedText();
    expectLogIsFree(logged);
    expect(logged).toContain("Database error in update:");
    expect(logged).toContain("DrizzleQueryError");
    expect(logged).toContain("22001");
  });

  it("bulkCreate logs the error class and database code, not the rows", async () => {
    insertChain.returning.mockRejectedValue(
      failedWrite("22001", "mcp_servers_env_len"),
    );

    await expect(mcpServersRepository.bulkCreate([server])).rejects.toThrow(
      "Failed to bulk create MCP servers. Please check your input and try again.",
    );

    const logged = loggedText();
    expectLogIsFree(logged);
    expect(logged).toContain("Database error in bulk create:");
    expect(logged).toContain("DrizzleQueryError");
    expect(logged).toContain("22001");
  });
});
