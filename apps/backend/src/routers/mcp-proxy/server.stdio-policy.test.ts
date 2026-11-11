/**
 * The admin MCP proxy refuses stdio servers unless ALLOW_STDIO_SERVERS is
 * exactly "true".
 *
 * All three routes that start an upstream transport (POST /mcp, GET /stdio,
 * GET /sse) reach `createTransport`, and each picks the transport from the
 * request's `transportType`, so each is driven here over real HTTP through
 * the real router. A refusal must be HTTP 400 with one constant body (each
 * route's catch answers an ordinary throw with 500), and it must come before
 * the server row is looked up and before a stdio transport is constructed or
 * started (the step that spawns). The stdio transport is a recorder that also
 * answers `initialize`, so the allowed path can be shown to work end to end.
 */
import type { Server as HttpServer } from "node:http";

import express from "express";
import {
  afterAll,
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";

vi.mock("@/utils/logger", () => ({
  default: { error: vi.fn(), warn: vi.fn(), info: vi.fn(), debug: vi.fn() },
}));

const { stdio, remote, findAllAccessibleToUserMock } = vi.hoisted(() => ({
  stdio: {
    constructed: [] as Array<{ command: string; args: string[] }>,
    started: 0,
  },
  remote: { started: 0 },
  findAllAccessibleToUserMock: vi.fn(),
}));

/**
 * A transport that answers every request it is sent: `initialize` with a
 * server identity, anything else with `{}`. Shared by the stdio recorder and
 * the remote stand-ins.
 */
const echoSend = function (
  this: { onmessage?: (message: unknown) => void },
  message: { id?: unknown; method?: string },
) {
  if (message.id === undefined || message.method === undefined) return;
  const result =
    message.method === "initialize"
      ? {
          protocolVersion: "2025-06-18",
          capabilities: {},
          serverInfo: { name: "upstream-echo", version: "0.0.0" },
        }
      : {};
  queueMicrotask(() =>
    this.onmessage?.({ jsonrpc: "2.0", id: message.id, result }),
  );
};

vi.mock("../../lib/stdio-transport/process-managed-transport", () => ({
  ProcessManagedStdioTransport: class {
    stderr = undefined;
    onmessage?: (message: unknown) => void;
    onclose?: () => void;
    onerror?: (error: Error) => void;
    onprocesscrash?: () => void;
    constructor(params: { command: string; args: string[] }) {
      stdio.constructed.push(params);
    }
    async start() {
      stdio.started += 1;
    }
    async close() {
      this.onclose?.();
    }
    async send(message: { id?: unknown; method?: string }) {
      echoSend.call(this, message);
    }
  },
}));

const RemoteStandIn = class {
  onmessage?: (message: unknown) => void;
  onclose?: () => void;
  onerror?: (error: Error) => void;
  sessionId = "upstream-session";
  async start() {
    remote.started += 1;
  }
  async close() {
    this.onclose?.();
  }
  async send(message: { id?: unknown; method?: string }) {
    echoSend.call(this, message);
  }
  async terminateSession() {}
};

vi.mock("@modelcontextprotocol/sdk/client/streamableHttp.js", () => ({
  StreamableHTTPClientTransport: RemoteStandIn,
}));
vi.mock("@modelcontextprotocol/sdk/client/sse.js", async (importOriginal) => ({
  ...(await importOriginal<
    typeof import("@modelcontextprotocol/sdk/client/sse.js")
  >()),
  SSEClientTransport: RemoteStandIn,
}));

// The destination guard has its own suites; here it lets the stand-ins through.
vi.mock("@/lib/metamcp/url-guard", () => ({
  assertPublicMcpUrl: vi.fn(async (url: string) => ({ url: new URL(url) })),
  createGuardedFetch: vi.fn(() => fetch),
}));
vi.mock("../../db/repositories", () => ({
  mcpServersRepository: {
    findAllAccessibleToUser: findAllAccessibleToUserMock,
    findByUuid: vi.fn(async () => {
      throw new Error("findByUuid must not be reached on this path");
    }),
    findAll: vi.fn(async () => {
      throw new Error("findAll must not be reached on this path");
    }),
  },
}));
// The real resolveEnvVariables and getDefaultEnvironment stay in the graph;
// db/index throws without DATABASE_URL.
vi.mock("../../db/index", () => ({ db: {}, pool: {} }));
vi.mock("../../lib/metamcp/mcp-server-pool", () => ({
  mcpServerPool: { handleServerCrashWithoutNamespace: vi.fn() },
}));
vi.mock("../../lib/metamcp/client", () => ({
  transformDockerUrl: (url: string) => url,
}));

const { STDIO_SERVERS_DISABLED_MESSAGE } = await import(
  "../../lib/metamcp/stdio-policy"
);
const { default: serverRouter } = await import("./server");

const SERVER_UUID = "cccccccc-1111-4111-8111-cccccccccccc";
const PROTOCOL_VERSION = "2025-06-18";

const stdioRow = () => ({
  uuid: SERVER_UUID,
  name: "local-tool",
  type: "STDIO",
  command: "node",
  args: ["server.js"],
  env: {},
  url: null,
  user_id: null,
  error_status: "NONE",
});

/** The exact refusal every route must answer with. */
const EXPECTED_BODY = {
  jsonrpc: "2.0",
  error: { code: -32000, message: STDIO_SERVERS_DISABLED_MESSAGE },
  id: null,
};

const INITIALIZE = JSON.stringify({
  jsonrpc: "2.0",
  id: 1,
  method: "initialize",
  params: {
    protocolVersion: PROTOCOL_VERSION,
    capabilities: {},
    clientInfo: { name: "inspector", version: "0.0.0" },
  },
});

let httpServer: HttpServer;
let baseUrl = "";
const open: AbortController[] = [];

type Route = "POST /mcp" | "GET /stdio" | "GET /sse";
const ROUTES: Route[] = ["POST /mcp", "GET /stdio", "GET /sse"];

/** Call a route the way the Inspector does, with a stream it can abort. */
async function call(
  route: Route,
  query: Record<string, string>,
): Promise<Response> {
  const controller = new AbortController();
  open.push(controller);
  const search = new URLSearchParams(query).toString();
  const [method, path] = route.split(" ");
  return fetch(`${baseUrl}/mcp-proxy/server${path}?${search}`, {
    method,
    signal: controller.signal,
    ...(method === "POST"
      ? {
          headers: {
            "content-type": "application/json",
            accept: "application/json, text/event-stream",
          },
          body: INITIALIZE,
        }
      : {}),
  });
}

beforeAll(async () => {
  const app = express();
  // The parent router's admin-session gate, reduced to the user it leaves.
  app.use((req, _res, next) => {
    Object.assign(req, { user: { id: "admin-1", role: "admin" } });
    next();
  });
  app.use("/mcp-proxy/server", serverRouter);
  await new Promise<void>((resolve) => {
    httpServer = app.listen(0, "127.0.0.1", resolve);
  });
  const address = httpServer.address();
  if (typeof address === "object" && address) {
    baseUrl = `http://127.0.0.1:${address.port}`;
  }
});

afterAll(async () => {
  httpServer.closeAllConnections();
  await new Promise<void>((resolve) => httpServer.close(() => resolve()));
});

beforeEach(() => {
  stdio.constructed.length = 0;
  stdio.started = 0;
  remote.started = 0;
  findAllAccessibleToUserMock.mockReset().mockResolvedValue([stdioRow()]);
});

afterEach(() => {
  for (const controller of open.splice(0)) controller.abort();
  vi.unstubAllEnvs();
});

const REFUSING_VALUES: Array<[string, string | undefined]> = [
  ["unset", undefined],
  ["empty", ""],
  ["false", "false"],
  ["TRUE", "TRUE"],
  ["1", "1"],
  ["yes", "yes"],
];

const CASES = ROUTES.flatMap((route) =>
  REFUSING_VALUES.map(([label, value]) => [route, label, value] as const),
);

describe("stdio refused by default on every proxy route", () => {
  it.each(CASES)(
    "%s answers 400 with the constant body when the flag is %s",
    async (route, _label, value) => {
      vi.stubEnv("ALLOW_STDIO_SERVERS", value);

      const response = await call(route, {
        transportType: "STDIO",
        mcpServerUuid: SERVER_UUID,
      });

      expect(response.status).toBe(400);
      expect(response.headers.get("content-type")).toContain(
        "application/json",
      );
      expect(await response.json()).toEqual(EXPECTED_BODY);
      // Refused before the row lookup, and nothing was built or started.
      expect(findAllAccessibleToUserMock).not.toHaveBeenCalled();
      expect(stdio.constructed).toEqual([]);
      expect(stdio.started).toBe(0);
    },
  );

  it("answers the same bytes on all three routes, whatever the request carries", async () => {
    vi.stubEnv("ALLOW_STDIO_SERVERS", undefined);
    const bodies: string[] = [];
    const queries: Array<Record<string, string>> = [
      { transportType: "STDIO", mcpServerUuid: SERVER_UUID },
      {
        transportType: "STDIO",
        command: "/bin/sh",
        args: "-c id",
        env: JSON.stringify({ LD_PRELOAD: "/tmp/x.so" }),
      },
      { transportType: "STDIO" },
    ];

    for (const route of ROUTES) {
      for (const query of queries) {
        const response = await call(route, query);
        expect(response.status).toBe(400);
        bodies.push(await response.text());
      }
    }

    expect(new Set(bodies).size).toBe(1);
    expect(JSON.parse(bodies[0])).toEqual(EXPECTED_BODY);
    expect(stdio.constructed).toEqual([]);
    expect(findAllAccessibleToUserMock).not.toHaveBeenCalled();
  });
});

describe('stdio allowed with exactly "true"', () => {
  it.each(ROUTES)(
    "%s resolves the registered row and starts its transport",
    async (route) => {
      vi.stubEnv("ALLOW_STDIO_SERVERS", "true");

      const response = await call(route, {
        transportType: "STDIO",
        mcpServerUuid: SERVER_UUID,
      });

      expect(response.status).toBe(200);
      expect(findAllAccessibleToUserMock).toHaveBeenCalledWith("admin-1");
      expect(stdio.constructed).toHaveLength(1);
      expect(stdio.constructed[0]).toMatchObject({
        command: expect.stringContaining("node"),
        args: ["server.js"],
      });
      expect(stdio.started).toBe(1);
    },
  );
});

describe("HTTP and SSE unchanged with the flag unset", () => {
  it("POST /mcp still proxies a Streamable HTTP server", async () => {
    vi.stubEnv("ALLOW_STDIO_SERVERS", undefined);
    findAllAccessibleToUserMock.mockResolvedValue([]);

    const response = await call("POST /mcp", {
      transportType: "STREAMABLE_HTTP",
      url: "https://upstream.example.test/mcp",
    });

    expect(response.status).toBe(200);
    expect(response.headers.get("mcp-session-id")).toBeTruthy();
    expect(remote.started).toBe(1);
    expect(stdio.constructed).toEqual([]);
  });

  it("GET /sse still proxies an SSE server", async () => {
    vi.stubEnv("ALLOW_STDIO_SERVERS", undefined);
    findAllAccessibleToUserMock.mockResolvedValue([]);

    const response = await call("GET /sse", {
      transportType: "SSE",
      url: "https://upstream.example.test/sse",
    });

    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("text/event-stream");
    expect(remote.started).toBe(1);
    expect(stdio.constructed).toEqual([]);
  });
});
