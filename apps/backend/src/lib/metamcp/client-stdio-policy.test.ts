/**
 * The pool's transport factory refuses stdio servers unless
 * ALLOW_STDIO_SERVERS is exactly "true".
 *
 * `createMetaMcpClient` builds every pooled connection (namespace sessions,
 * reconnects, lazy connects), so it is the backstop behind startup's filter.
 * The stdio transport class is replaced by a recorder, so the assertions are
 * on what would have been CONSTRUCTED and STARTED (the step that spawns), and
 * the env resolver is spied, so a refusal is shown to happen before the
 * child's env is resolved.
 */

import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { ServerParameters } from "@repo/zod-types";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { constructed, started, resolveEnvSpy, loggerMock } = vi.hoisted(() => ({
  constructed: [] as Array<{ command: string; args?: string[] }>,
  started: [] as string[],
  resolveEnvSpy: vi.fn((env: Record<string, string>) => ({ ...env })),
  loggerMock: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

vi.mock("../stdio-transport/process-managed-transport", () => ({
  ProcessManagedStdioTransport: class {
    stderr = undefined;
    onclose?: () => void;
    onerror?: (error: Error) => void;
    onprocesscrash?: () => void;
    private readonly command: string;
    constructor(params: { command: string; args?: string[] }) {
      constructed.push(params);
      this.command = params.command;
    }
    async start() {
      started.push(this.command);
    }
    async close() {}
    async send() {}
  },
}));

vi.mock("./utils", async (importOriginal) => ({
  ...(await importOriginal<typeof import("./utils")>()),
  resolveEnvVariables: resolveEnvSpy,
}));

// client.ts's module-load chain reaches db/index (which throws without
// DATABASE_URL); same stubs as client-gateway-header.test.ts.
vi.mock("../../db/repositories/index", () => ({ mcpServersRepository: {} }));
vi.mock("../../db/repositories/oauth-sessions.repo", () => ({
  oauthSessionsRepository: {},
}));
vi.mock("../config.service", () => ({
  configService: { getMcpMaxAttempts: vi.fn().mockResolvedValue(1) },
}));
vi.mock("./server-error-tracker", () => ({
  serverErrorTracker: {
    getServerMaxAttempts: vi.fn().mockResolvedValue(1),
    isServerInErrorState: vi.fn().mockResolvedValue(false),
  },
}));
vi.mock("@/utils/logger", () => ({ default: loggerMock }));

import { connectMetaMcpClient, createMetaMcpClient } from "./client";
import { __resetStdioSkipWarningsForTesting } from "./stdio-policy";

const SECRET_COMMAND = "secret-command-value";
const SECRET_ARG = "--secret-arg-value";
const SECRET_ENV = "secret-env-value";

const stdioParams = (over: Record<string, unknown> = {}) =>
  ({
    uuid: "aaaaaaaa-0000-4000-8000-000000000001",
    name: "local-tool",
    description: "",
    status: "active",
    created_at: new Date().toISOString(),
    type: "STDIO",
    command: SECRET_COMMAND,
    args: [SECRET_ARG],
    env: { API_KEY: SECRET_ENV },
    url: null,
    headers: {},
    ...over,
  }) as unknown as ServerParameters;

const remoteParams = (type: "SSE" | "STREAMABLE_HTTP") =>
  ({
    uuid: "bbbbbbbb-0000-4000-8000-000000000002",
    name: "backend",
    description: "",
    status: "active",
    created_at: new Date().toISOString(),
    type,
    url: "http://10.0.0.5:3000/mcp",
    headers: {},
  }) as unknown as ServerParameters;

const REFUSING_VALUES: Array<[string, string | undefined]> = [
  ["unset", undefined],
  ["empty", ""],
  ["false", "false"],
  ["TRUE", "TRUE"],
  ["1", "1"],
  ["yes", "yes"],
];

/** The skip warnings this policy wrote, as plain strings. */
const skipWarnings = () =>
  loggerMock.warn.mock.calls
    .map((call) => String(call[0]))
    .filter((line) => line.includes("was not started"));

beforeEach(() => {
  vi.clearAllMocks();
  constructed.length = 0;
  started.length = 0;
  __resetStdioSkipWarningsForTesting();
});

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("createMetaMcpClient: stdio refused by default", () => {
  it.each(REFUSING_VALUES)(
    "returns the skip shape for a STDIO server when the flag is %s, building nothing",
    (_label, value) => {
      vi.stubEnv("ALLOW_STDIO_SERVERS", value);

      const result = createMetaMcpClient(stdioParams());

      expect(result).toEqual({ client: undefined, transport: undefined });
      expect(constructed).toEqual([]);
      expect(resolveEnvSpy).not.toHaveBeenCalled();
    },
  );

  it.each([
    ["missing", undefined],
    ["empty", ""],
  ])("treats a %s type as stdio and refuses it", (_label, type) => {
    vi.stubEnv("ALLOW_STDIO_SERVERS", undefined);

    const result = createMetaMcpClient(stdioParams({ type }));

    expect(result).toEqual({ client: undefined, transport: undefined });
    expect(constructed).toEqual([]);
    expect(resolveEnvSpy).not.toHaveBeenCalled();
  });

  it("connectMetaMcpClient gives up at once: no transport built or started", async () => {
    vi.stubEnv("ALLOW_STDIO_SERVERS", undefined);

    const result = await connectMetaMcpClient(stdioParams());

    expect(result).toBeUndefined();
    expect(constructed).toEqual([]);
    expect(started).toEqual([]);
  });

  it("warns once per server per process, naming no command, args or env", () => {
    vi.stubEnv("ALLOW_STDIO_SERVERS", undefined);
    const other = stdioParams({
      uuid: "aaaaaaaa-0000-4000-8000-000000000009",
      name: "other-tool",
    });

    for (let i = 0; i < 3; i++) createMetaMcpClient(stdioParams());
    for (let i = 0; i < 2; i++) createMetaMcpClient(other);

    const warnings = skipWarnings();
    expect(warnings).toHaveLength(2);
    expect(warnings[0]).toContain('"local-tool"');
    expect(warnings[1]).toContain('"other-tool"');
    const everything = JSON.stringify(loggerMock.warn.mock.calls);
    expect(everything).not.toContain(SECRET_COMMAND);
    expect(everything).not.toContain(SECRET_ARG);
    expect(everything).not.toContain(SECRET_ENV);
  });
});

describe('createMetaMcpClient: stdio allowed only with exactly "true"', () => {
  it("builds the stdio transport from the server's own parameters", () => {
    vi.stubEnv("ALLOW_STDIO_SERVERS", "true");

    const result = createMetaMcpClient(stdioParams());

    expect(result.client).toBeDefined();
    expect(result.transport).toBeDefined();
    expect(constructed).toHaveLength(1);
    expect(constructed[0]).toMatchObject({
      command: SECRET_COMMAND,
      args: [SECRET_ARG],
    });
    expect(resolveEnvSpy).toHaveBeenCalledTimes(1);
    expect(skipWarnings()).toEqual([]);
  });

  it("still treats a missing type as stdio when allowed", () => {
    vi.stubEnv("ALLOW_STDIO_SERVERS", "true");

    const result = createMetaMcpClient(stdioParams({ type: undefined }));

    expect(result.transport).toBeDefined();
    expect(constructed).toHaveLength(1);
  });
});

describe("createMetaMcpClient: HTTP and SSE are unaffected", () => {
  it.each([
    ["STREAMABLE_HTTP", StreamableHTTPClientTransport],
    ["SSE", SSEClientTransport],
  ] as const)(
    "builds a %s transport with the flag unset",
    (type, TransportClass) => {
      vi.stubEnv("ALLOW_STDIO_SERVERS", undefined);

      const result = createMetaMcpClient(remoteParams(type));

      expect(result.client).toBeDefined();
      expect(result.transport).toBeInstanceOf(TransportClass);
      expect(constructed).toEqual([]);
      expect(skipWarnings()).toEqual([]);
    },
  );
});
