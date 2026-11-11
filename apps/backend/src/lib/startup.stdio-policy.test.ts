/**
 * Boot skips stored stdio servers unless ALLOW_STDIO_SERVERS is exactly
 * "true": they are not converted to spawn parameters, not handed to the pool
 * to warm, and not changed in the database. One warning per skipped row.
 *
 * This is the boot path only. The pool's transport factory is the backstop
 * for every other path (client-stdio-policy.test.ts).
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { loggerMock, repo, namespacesRepo, pools, convert } = vi.hoisted(() => ({
  loggerMock: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
  repo: {
    findAll: vi.fn(),
    resetAllErrorStatuses: vi.fn(),
    // Tripwires for "the rows are kept as they are".
    update: vi.fn(),
    deleteByUuid: vi.fn(),
    updateServerErrorStatus: vi.fn(),
  },
  namespacesRepo: { findAll: vi.fn() },
  pools: {
    ensureIdleSessions: vi.fn(),
    ensureIdleServers: vi.fn(),
  },
  convert: vi.fn(),
}));

vi.mock("@/utils/logger", () => ({ default: loggerMock }));
vi.mock("../db/repositories", () => ({
  mcpServersRepository: repo,
  namespacesRepository: namespacesRepo,
}));
vi.mock("./bootstrap.service", () => ({
  initializeEnvironmentConfiguration: vi.fn(),
}));
vi.mock("./metamcp", () => ({
  metaMcpServerPool: { ensureIdleServers: pools.ensureIdleServers },
  mcpServerPool: { ensureIdleSessions: pools.ensureIdleSessions },
}));
vi.mock("./metamcp/server-error-tracker", () => ({
  serverErrorTracker: { resetAllAttempts: vi.fn() },
}));
vi.mock("./metamcp/utils", () => ({ convertDbServerToParams: convert }));

import { __resetStdioSkipWarningsForTesting } from "./metamcp/stdio-policy";
import { initializeIdleServers } from "./startup";

const dbRow = (uuid: string, name: string, type: string | null) => ({
  uuid,
  name,
  type,
  command: type === "STDIO" || type === null ? "secret-command" : null,
  args: [],
  env: {},
  url: type === "STDIO" || type === null ? null : `https://${name}.invalid/mcp`,
  headers: {},
  bearerToken: null,
  error_status: "NONE",
  created_at: new Date("2026-11-11T00:00:00.000Z"),
  user_id: null,
});

const ROWS = [
  dbRow("11111111-0000-4000-8000-000000000001", "stdio-one", "STDIO"),
  dbRow("11111111-0000-4000-8000-000000000002", "http-one", "STREAMABLE_HTTP"),
  dbRow("11111111-0000-4000-8000-000000000003", "untyped-one", null),
  dbRow("11111111-0000-4000-8000-000000000004", "sse-one", "SSE"),
];

const skipWarnings = () =>
  loggerMock.warn.mock.calls
    .map((call) => String(call[0]))
    .filter((line) => line.includes("was not started"));

// startup.ts reports through console.log; keep the test output quiet.
let consoleLog: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  vi.clearAllMocks();
  __resetStdioSkipWarningsForTesting();
  consoleLog = vi.spyOn(console, "log").mockImplementation(() => {});
  repo.findAll.mockResolvedValue(ROWS.map((row) => ({ ...row })));
  repo.resetAllErrorStatuses.mockResolvedValue(0);
  namespacesRepo.findAll.mockResolvedValue([{ uuid: "ns-1" }]);
  pools.ensureIdleSessions.mockResolvedValue(undefined);
  pools.ensureIdleServers.mockResolvedValue(undefined);
  convert.mockImplementation(async (row: { uuid: string; type: string }) => ({
    uuid: row.uuid,
    type: row.type,
  }));
});

afterEach(() => {
  consoleLog.mockRestore();
  vi.unstubAllEnvs();
});

describe("initializeIdleServers with stdio servers disabled", () => {
  it.each([
    ["unset", undefined],
    ["empty", ""],
    ["false", "false"],
    ["TRUE", "TRUE"],
    ["1", "1"],
    ["yes", "yes"],
  ])(
    "skips stdio and untyped rows before conversion when the flag is %s",
    async (_label, value) => {
      vi.stubEnv("ALLOW_STDIO_SERVERS", value);

      await initializeIdleServers();

      expect(convert.mock.calls.map(([row]) => row.name)).toEqual([
        "http-one",
        "sse-one",
      ]);
      expect(pools.ensureIdleSessions).toHaveBeenCalledTimes(1);
      expect(Object.keys(pools.ensureIdleSessions.mock.calls[0][0])).toEqual([
        "11111111-0000-4000-8000-000000000002",
        "11111111-0000-4000-8000-000000000004",
      ]);
    },
  );

  it("warns once per skipped row, naming the server and not its command", async () => {
    vi.stubEnv("ALLOW_STDIO_SERVERS", undefined);

    await initializeIdleServers();

    const warnings = skipWarnings();
    expect(warnings).toHaveLength(2);
    expect(warnings[0]).toContain('"stdio-one"');
    expect(warnings[1]).toContain('"untyped-one"');
    expect(JSON.stringify(loggerMock.warn.mock.calls)).not.toContain(
      "secret-command",
    );
  });

  it("leaves the stored rows unchanged", async () => {
    vi.stubEnv("ALLOW_STDIO_SERVERS", undefined);

    await initializeIdleServers();

    expect(repo.update).not.toHaveBeenCalled();
    expect(repo.deleteByUuid).not.toHaveBeenCalled();
    expect(repo.updateServerErrorStatus).not.toHaveBeenCalled();
  });

  it("still warms the namespaces, whose pooled connections hit the factory gate", async () => {
    vi.stubEnv("ALLOW_STDIO_SERVERS", undefined);

    await initializeIdleServers();

    expect(pools.ensureIdleServers).toHaveBeenCalledWith(["ns-1"], false);
  });
});

describe('initializeIdleServers with ALLOW_STDIO_SERVERS="true"', () => {
  it("converts and warms every row, stdio included, with no skip warning", async () => {
    vi.stubEnv("ALLOW_STDIO_SERVERS", "true");

    await initializeIdleServers();

    expect(convert.mock.calls.map(([row]) => row.name)).toEqual([
      "stdio-one",
      "http-one",
      "untyped-one",
      "sse-one",
    ]);
    expect(Object.keys(pools.ensureIdleSessions.mock.calls[0][0])).toHaveLength(
      4,
    );
    expect(skipWarnings()).toEqual([]);
  });
});
