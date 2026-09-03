/**
 * Log hygiene: the OpenAPI bridge logs the caller-controlled tool name
 * (a URL-decoded path segment) when a tool execution fails. Interpolating it
 * raw lets an embedded CR/LF forge whole log lines; the fix runs it through
 * JSON.stringify first, matching the mcp-proxy connection-log treatment.
 *
 * The module graph is fully mocked at tool-execution's own import boundary so
 * the test needs no postgres and no live backend.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";

const { getOpenApiServerMock, loggerErrorMock } = vi.hoisted(() => ({
  getOpenApiServerMock: vi.fn(),
  loggerErrorMock: vi.fn(),
}));

vi.mock("@/utils/logger", () => ({
  default: {
    error: loggerErrorMock,
    warn: vi.fn(),
    info: vi.fn(),
    debug: vi.fn(),
  },
}));

vi.mock("../../../lib/metamcp/metamcp-server-pool", () => ({
  metaMcpServerPool: { getOpenApiServer: getOpenApiServerMock },
}));

vi.mock("../../../lib/metamcp/caller-context", () => ({
  resolveCallerContext: vi.fn(),
}));

vi.mock("../../../lib/metamcp/consumer-identity-resolver", () => ({
  resolveClientIdentity: vi.fn().mockResolvedValue({ name: "test-consumer" }),
}));

vi.mock("./handlers", () => ({
  createMiddlewareEnabledHandlers: vi.fn(),
}));

import { executeToolWithMiddleware } from "./tool-execution";

/** A tool name carrying a real newline, the log-forging payload. */
const HOSTILE_TOOL_NAME = "server__evilTool\ninjected fake log line";

function makeRes() {
  const res = {
    statusCode: 200,
    status: vi.fn(function status(this: unknown, code: number) {
      (res as { statusCode: number }).statusCode = code;
      return res;
    }),
    json: vi.fn(function json(this: unknown) {
      return res;
    }),
  };
  return res;
}

beforeEach(() => {
  vi.clearAllMocks();
  // Fail pool acquisition so the catch runs and the tool name reaches the log.
  getOpenApiServerMock.mockResolvedValue(undefined);
});

describe("executeToolWithMiddleware -- tool name is escaped before it enters a log line", () => {
  it("JSON.stringifies a tool name containing a newline (no raw CR/LF in the log)", async () => {
    const req = {
      namespaceUuid: "ns-1",
      params: { tool_name: HOSTILE_TOOL_NAME },
    } as unknown as Parameters<typeof executeToolWithMiddleware>[0];

    await executeToolWithMiddleware(req, makeRes() as never, {});

    expect(loggerErrorMock).toHaveBeenCalled();
    const logged = String(loggerErrorMock.mock.calls[0][0]);

    // The line still names the failing tool for the operator.
    expect(logged).toContain("Error executing tool");
    // A real newline in the name can no longer split the log line: it is
    // escaped to the two-character sequence backslash-n.
    expect(logged).not.toContain("\n");
    expect(logged).toContain("server__evilTool\\ninjected fake log line");
  });
});
