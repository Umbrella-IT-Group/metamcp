/**
 * The OpenAPI bridge's tool-execution routes (GET and POST
 * `/:endpoint_name/api/:tool_name`) take the endpoint's configured rate limits,
 * as the MCP routes do: the per-client window (429), the endpoint bucket (503),
 * both together, and nothing when neither is enabled. A refused call never
 * reaches tool execution, and the counters are the ones the MCP routes use.
 *
 * Drives the real `openApiRouter` and the real `rateLimitMiddleware` over HTTP.
 * Mocked: the endpoint lookup and API-key authentication (each stamps what the
 * real one stamps), tool execution (a counter standing in for the backend
 * call), and the backend pool's idle-session map the per-client window reads.
 */
import type { AddressInfo } from "node:net";

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

const { endpointConfig, executed, idleSessions } = vi.hoisted(() => ({
  endpointConfig: { current: {} as Record<string, unknown> },
  executed: { count: 0 },
  idleSessions: new Map<string, Map<string, string>>(),
}));

vi.mock("@/utils/logger", () => ({
  default: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

vi.mock("../../../middleware/lookup-endpoint-middleware", () => ({
  lookupEndpoint: (
    req: express.Request,
    _res: express.Response,
    next: express.NextFunction,
  ) => {
    const endpoint = endpointConfig.current;
    Object.assign(req, {
      endpoint,
      endpointName: req.params.endpoint_name,
      namespaceUuid: endpoint.namespace_uuid,
    });
    next();
  },
}));

vi.mock("@/middleware/api-key-oauth.middleware", () => ({
  authenticateApiKey: (
    req: express.Request,
    _res: express.Response,
    next: express.NextFunction,
  ) => {
    Object.assign(req, {
      authMethod: "api_key",
      apiKeyUuid: String(req.headers["x-test-key"] ?? "key-1"),
    });
    next();
  },
}));

vi.mock("./tool-execution", () => ({
  executeToolWithMiddleware: async (
    _req: express.Request,
    res: express.Response,
  ) => {
    executed.count += 1;
    res.json({ ok: true });
  },
}));

vi.mock("./handlers", () => ({ createMiddlewareEnabledHandlers: vi.fn() }));
vi.mock("./schema-generator", () => ({ generateOpenApiSchema: vi.fn() }));
vi.mock("../../../lib/metamcp/metamcp-server-pool", () => ({
  metaMcpServerPool: {},
}));
vi.mock("../../../lib/metamcp/mcp-server-pool", () => ({
  mcpServerPool: {
    getBackgroundIdleSessionsByNamespace: () => idleSessions,
  },
}));

import { rateLimitMiddleware } from "../../../middleware/rate-limit.middleware";
import openApiRouter from "./routes";

let baseUrl: string;
let server: ReturnType<express.Express["listen"]>;
let namespaceCounter = 0;

/**
 * A fresh endpoint config in its own namespace, so each test starts with
 * empty counters (both limiters key on the namespace). The per-client window
 * only counts while the namespace has a warmed idle session, so one is marked
 * the way the pool marks it.
 */
function configure(limits: Record<string, unknown>): string {
  namespaceCounter += 1;
  const namespaceUuid = `ns-rate-${namespaceCounter}`;
  idleSessions.set(namespaceUuid, new Map([["status", "created"]]));
  endpointConfig.current = {
    name: "bridge",
    namespace_uuid: namespaceUuid,
    enable_max_rate: false,
    max_rate: 0,
    max_rate_seconds: 0,
    enable_client_max_rate: false,
    client_max_rate: 0,
    client_max_rate_seconds: 0,
    client_max_rate_strategy: "",
    client_max_rate_strategy_key: "",
    ...limits,
  };
  return namespaceUuid;
}

const post = (headers: Record<string, string> = {}) =>
  fetch(`${baseUrl}/bridge/api/writer__write`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "cf-connecting-ip": "198.51.100.7",
      ...headers,
    },
    body: "{}",
  });

const get = (headers: Record<string, string> = {}) =>
  fetch(`${baseUrl}/bridge/api/writer__write`, {
    headers: { "cf-connecting-ip": "198.51.100.7", ...headers },
  });

async function statuses(
  send: () => Promise<Response>,
  times: number,
): Promise<number[]> {
  const result: number[] = [];
  for (let i = 0; i < times; i += 1) {
    const response = await send();
    await response.arrayBuffer();
    result.push(response.status);
  }
  return result;
}

beforeAll(async () => {
  const app = express();
  app.use(openApiRouter);
  // Stands in for an MCP route: the same middleware chain order the MCP
  // routes use, ending in a handler that does nothing.
  app.post(
    "/:endpoint_name/mcp",
    (req, _res, next) => {
      const endpoint = endpointConfig.current;
      Object.assign(req, {
        endpoint,
        namespaceUuid: endpoint.namespace_uuid,
        authMethod: "api_key",
        apiKeyUuid: String(req.headers["x-test-key"] ?? "key-1"),
      });
      next();
    },
    rateLimitMiddleware,
    (_req, res) => {
      res.json({ ok: true });
    },
  );
  await new Promise<void>((resolve) => {
    server = app.listen(0, "127.0.0.1", resolve);
  });
  baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterAll(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

beforeEach(() => {
  executed.count = 0;
});

describe("OpenAPI bridge tool execution is rate limited like the MCP routes", () => {
  it("the endpoint bucket refuses POST past its capacity with 503 and runs nothing more", async () => {
    configure({ enable_max_rate: true, max_rate: 2, max_rate_seconds: 0 });
    expect(await statuses(post, 4)).toEqual([200, 200, 503, 503]);
    expect(executed.count).toBe(2);
  });

  it("the endpoint bucket refuses GET past its capacity with 503", async () => {
    configure({ enable_max_rate: true, max_rate: 2, max_rate_seconds: 0 });
    expect(await statuses(get, 3)).toEqual([200, 200, 503]);
    expect(executed.count).toBe(2);
  });

  it("GET and POST draw on one bucket", async () => {
    configure({ enable_max_rate: true, max_rate: 2, max_rate_seconds: 0 });
    expect(await statuses(get, 1)).toEqual([200]);
    expect(await statuses(post, 2)).toEqual([200, 503]);
    expect(executed.count).toBe(2);
  });

  it("the per-client window refuses past its limit with 429 and runs nothing more", async () => {
    configure({
      enable_client_max_rate: true,
      client_max_rate: 2,
      client_max_rate_seconds: 60,
    });
    expect(await statuses(post, 3)).toEqual([200, 200, 429]);
    expect(await statuses(get, 1)).toEqual([429]);
    expect(executed.count).toBe(2);
  });

  it("the per-client window keys on the edge client address", async () => {
    configure({
      enable_client_max_rate: true,
      client_max_rate: 1,
      client_max_rate_seconds: 60,
    });
    expect(await statuses(post, 2)).toEqual([200, 429]);
    expect(
      await statuses(() => post({ "cf-connecting-ip": "198.51.100.8" }), 1),
    ).toEqual([200]);
    expect(executed.count).toBe(2);
  });

  it("with both limits enabled, the tighter one refuses first", async () => {
    configure({
      enable_max_rate: true,
      max_rate: 10,
      max_rate_seconds: 0,
      enable_client_max_rate: true,
      client_max_rate: 2,
      client_max_rate_seconds: 60,
    });
    expect(await statuses(post, 3)).toEqual([200, 200, 429]);
    expect(executed.count).toBe(2);

    configure({
      enable_max_rate: true,
      max_rate: 1,
      max_rate_seconds: 0,
      enable_client_max_rate: true,
      client_max_rate: 10,
      client_max_rate_seconds: 60,
    });
    executed.count = 0;
    expect(await statuses(post, 2)).toEqual([200, 503]);
    expect(executed.count).toBe(1);
  });

  it("with neither limit enabled, nothing is refused", async () => {
    configure({
      max_rate: 1,
      max_rate_seconds: 0,
      client_max_rate: 1,
      client_max_rate_seconds: 60,
    });
    expect(await statuses(post, 4)).toEqual([200, 200, 200, 200]);
    expect(await statuses(get, 2)).toEqual([200, 200]);
    expect(executed.count).toBe(6);
  });

  it("the endpoint bucket is per credential, and an MCP route draws on the same one", async () => {
    configure({ enable_max_rate: true, max_rate: 2, max_rate_seconds: 0 });
    const mcp = () =>
      fetch(`${baseUrl}/bridge/mcp`, {
        method: "POST",
        headers: { "cf-connecting-ip": "198.51.100.7" },
      });
    expect(await statuses(post, 1)).toEqual([200]);
    expect(await statuses(mcp, 1)).toEqual([200]);
    expect(await statuses(post, 1)).toEqual([503]);
    // Another credential on the same endpoint has its own bucket.
    expect(await statuses(() => post({ "x-test-key": "key-2" }), 1)).toEqual([
      200,
    ]);
    expect(executed.count).toBe(2);
  });
});
