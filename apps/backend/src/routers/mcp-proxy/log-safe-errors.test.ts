import type { Server as HttpServer } from "node:http";
import { format } from "node:util";

import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { DrizzleQueryError } from "drizzle-orm/errors";
import express from "express";
import {
  afterAll,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";

const { loggerMock } = vi.hoisted(() => ({
  loggerMock: {
    error: vi.fn(),
    warn: vi.fn(),
    info: vi.fn(),
    debug: vi.fn(),
  },
}));
vi.mock("@/utils/logger", () => ({ default: loggerMock }));
vi.mock("../../db/repositories", () => ({
  mcpServersRepository: { findAllAccessibleToUser: vi.fn() },
}));
vi.mock("../../db/index", () => ({ db: {}, pool: {} }));
vi.mock("../../lib/metamcp/mcp-server-pool", () => ({ mcpServerPool: {} }));
vi.mock("../../lib/metamcp/client", () => ({
  transformDockerUrl: (url: string) => url,
}));
vi.mock("../../lib/metamcp/index", () => ({ createServer: vi.fn() }));
vi.mock("@/lib/metamcp/url-guard", () => ({
  assertPublicMcpUrl: vi.fn(async (url: string) => ({ url: new URL(url) })),
  createGuardedFetch: vi.fn(() => fetch),
}));

import { mcpServersRepository } from "../../db/repositories";
import { createServer } from "../../lib/metamcp/index";
import metamcpRouter from "./metamcp";
import serverRouter from "./server";

const SECRET = "fake-proxy-secret-gggg7777";
const QUERY = 'select "env", "headers" from "mcp_servers" where "user_id" = $1';
const NAMESPACE_UUID = "cccccccc-3333-4333-8333-cccccccccccc";
const EXPECTED_BODY = {
  error: "internal_server_error",
  message: "MCP proxy request failed. Check the gateway logs for details.",
};

function databaseError(connectionRefused = false): DrizzleQueryError {
  const error = new DrizzleQueryError(
    QUERY,
    [SECRET],
    Object.assign(new Error(`rejected value ${SECRET}`), {
      code: "23514",
      constraint: "mcp_servers_config_check",
      detail: `Failing row contains (${SECRET})`,
    }),
  );
  // Also exercise the legacy /sse connection-refused branch, which used to
  // bypass the outer catch and return the error object directly.
  if (connectionRefused) Object.assign(error, { code: "ECONNREFUSED" });
  return error;
}

let httpServer: HttpServer;
let baseUrl: string;

beforeAll(async () => {
  const app = express();
  // Both subrouters are mounted behind the parent router's admin gate in
  // production. No upstream connection or database is used by these tests.
  app.use((req, _res, next) => {
    Object.assign(req, { user: { id: "admin-1", role: "admin" } });
    next();
  });
  app.use("/server", serverRouter);
  app.use("/metamcp", metamcpRouter);
  await new Promise<void>((resolve) => {
    httpServer = app.listen(0, "127.0.0.1", resolve);
  });
  const address = httpServer.address();
  if (typeof address !== "object" || !address) throw new Error("No address");
  baseUrl = `http://127.0.0.1:${address.port}`;
});

afterAll(async () => {
  vi.restoreAllMocks();
  httpServer.closeAllConnections();
  await new Promise<void>((resolve) => httpServer.close(() => resolve()));
});

beforeEach(() => {
  vi.clearAllMocks();
});

async function expectSafeFailure(response: Response): Promise<void> {
  expect(response.status).toBe(500);
  const body = await response.text();
  expect(body).not.toContain(SECRET);
  expect(body).not.toContain(QUERY);
  expect(JSON.parse(body)).toEqual(EXPECTED_BODY);

  const logged = loggerMock.error.mock.calls
    .map((args) => format(...args))
    .join("\n");
  expect(logged).not.toContain(SECRET);
  expect(logged).not.toContain(QUERY);
  expect(logged).toContain("DrizzleQueryError");
  expect(logged).toContain("23514");
  expect(logged).toContain("mcp_servers_config_check");
}

describe("Inspector proxy error responses", () => {
  it.each([
    ["POST", "/mcp", false],
    ["GET", "/stdio", false],
    ["GET", "/sse", false],
    ["GET", "/sse", true],
  ] as const)(
    "%s /server%s keeps database values out of the body and log (connection refused: %s)",
    async (method, path, connectionRefused) => {
      vi.mocked(mcpServersRepository.findAllAccessibleToUser).mockRejectedValue(
        databaseError(connectionRefused),
      );
      const query = new URLSearchParams({
        transportType: "STREAMABLE_HTTP",
        url: "https://upstream.example.test/mcp",
      });

      await expectSafeFailure(
        await fetch(`${baseUrl}/server${path}?${query}`, { method }),
      );
    },
  );

  it("keeps a namespace setup failure out of the SSE body and log", async () => {
    vi.mocked(createServer).mockRejectedValue(databaseError());

    await expectSafeFailure(
      await fetch(`${baseUrl}/metamcp/${NAMESPACE_UUID}/sse`),
    );
  });

  it("keeps an unexpected namespace POST failure out of the body and log", async () => {
    vi.spyOn(
      StreamableHTTPServerTransport.prototype,
      "handleRequest",
    ).mockRejectedValueOnce(databaseError());

    await expectSafeFailure(
      await fetch(`${baseUrl}/metamcp/${NAMESPACE_UUID}/mcp`, {
        method: "POST",
      }),
    );
  });
});
