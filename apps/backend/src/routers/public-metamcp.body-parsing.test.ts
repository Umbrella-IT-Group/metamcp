/**
 * Where a JSON body is parsed on the public `/metamcp` router.
 *
 * `globalBodyParser` leaves `/metamcp/*` unparsed so the MCP transports can
 * read the stream themselves. The router used to parse any POST whose path
 * contained `/api/tools/` at 50mb before every child router, ahead of
 * endpoint lookup and authentication. That pre-parse is gone: the OpenAPI
 * bridge (`POST /:endpoint_name/api/:tool_name`) has its own parser at the
 * default 100kb, in front of its own lookup and authentication, and the
 * `/:endpoint_name/api/tools/` spelling now gets that parser like any other
 * tool name.
 *
 * Driven over a real socket through the REAL parent router, mounted behind
 * the REAL `globalBodyParser` and in front of the terminal error handler as
 * index.ts mounts it, with the REAL bridge router,
 * endpoint lookup and API-key authentication. Mocked seams:
 *  - the streamable-HTTP router, replaced by a controlled first child that
 *    reports whether the body reached it unread (only for requests carrying
 *    the probe header; everything else falls through),
 *  - the SSE and admin routers, replaced by empty routers so `@/db` stays out
 *    of the import graph (the admin router's own parser is pinned elsewhere),
 *  - the repositories the lookup and the API-key check read,
 *  - the tool executor, which records the body it was handed.
 */
import type { Server } from "node:http";

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

const h = vi.hoisted(() => ({
  validateApiKey: vi.fn(),
  findByName: vi.fn(),
  execute: vi.fn(),
}));

vi.mock("@/utils/logger", () => ({
  default: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

vi.mock("../lib/health-upstream", () => ({
  isAdminHealthRequest: vi.fn().mockResolvedValue(false),
}));

vi.mock("../db/repositories/endpoints.repo", () => ({
  endpointsRepository: {
    findByName: h.findByName,
    findAllWithNamespaces: vi.fn().mockResolvedValue([]),
  },
}));
vi.mock("../db/repositories/api-keys.repo", () => ({
  ApiKeysRepository: class {
    validateApiKey = h.validateApiKey;
  },
}));
vi.mock("../db/repositories/users.repo", () => ({
  usersRepository: { isDisabled: vi.fn().mockResolvedValue(false) },
}));
vi.mock("../db/repositories/oauth.repo", () => ({
  oauthRepository: { getAccessToken: vi.fn().mockResolvedValue(null) },
}));
vi.mock("../db/repositories/access-groups.repo", () => ({
  accessGroupsRepository: {
    hasEndpointGrant: vi.fn().mockResolvedValue(false),
  },
}));
vi.mock("../db/repositories/audit-log.repo", () => ({
  auditLogRepository: { record: vi.fn().mockResolvedValue(undefined) },
}));

vi.mock("../lib/metamcp/metamcp-server-pool", () => ({
  metaMcpServerPool: { getOpenApiServer: vi.fn() },
}));
vi.mock("./public-metamcp/openapi/handlers", () => ({
  createMiddlewareEnabledHandlers: vi.fn(),
}));
vi.mock("./public-metamcp/openapi/tool-execution", () => ({
  executeToolWithMiddleware: h.execute,
}));

// The controlled first child. It answers only requests carrying the probe
// header, and reports whether anything ahead of it parsed the body.
vi.mock("./public-metamcp/streamable-http", async () => {
  const { Router } = await import("express");
  const router = Router();
  router.use(async (req, res, next) => {
    if (req.headers["x-test-probe"] !== "first-child") {
      next();
      return;
    }
    if (req.body !== undefined) {
      res.status(200).json({ parsedBefore: true, raw: null });
      return;
    }
    const chunks: Buffer[] = [];
    for await (const chunk of req) chunks.push(chunk as Buffer);
    res.status(200).json({
      parsedBefore: false,
      raw: Buffer.concat(chunks).toString("utf8"),
    });
  });
  return { default: router };
});
vi.mock("./public-metamcp/sse", async () => ({
  default: (await import("express")).Router(),
}));
vi.mock("./public-metamcp/admin", async () => ({
  default: (await import("express")).Router(),
}));

process.env.APP_URL = "https://gateway.example.test";

const { default: publicEndpointsRouter } = await import("./public-metamcp");
const { globalBodyParser } = await import("../lib/global-body-parser");
const { errorHandler, BAD_REQUEST_BODY } = await import(
  "../middleware/error-handler.middleware"
);

const API_KEY = "sk_mt_bodyparsing0000";

const ENDPOINT = {
  uuid: "11111111-1111-4111-8111-111111111111",
  name: "autotask",
  description: null,
  namespace_uuid: "33333333-3333-4333-8333-333333333333",
  enable_api_key_auth: true,
  require_scoped_api_key: false,
  enable_max_rate: false,
  enable_client_max_rate: false,
  max_rate_seconds: null,
  max_rate: null,
  client_max_rate: null,
  client_max_rate_seconds: null,
  client_max_rate_strategy: null,
  client_max_rate_strategy_key: null,
  enable_oauth: false,
  use_query_param_auth: false,
  restricted: false,
  created_at: new Date("2026-07-01T00:00:00Z"),
  updated_at: new Date("2026-07-01T00:00:00Z"),
  user_id: null,
};

/** Over the bridge's 100kb parser default, far under the old 50mb. */
const OVER_BRIDGE_BYTES = 150 * 1024;

let server: Server;
let baseUrl: string;

beforeAll(async () => {
  const app = express();
  // index.ts mounts the declared-length guard ahead of this; it answers only
  // declared lengths over 10 MiB, which no case here sends, and is pinned in
  // lib/global-body-parser-limits.test.ts.
  app.use(globalBodyParser);
  app.use("/metamcp", publicEndpointsRouter);
  app.use(errorHandler);
  server = await new Promise<Server>((resolve) => {
    const s = app.listen(0, "127.0.0.1", () => resolve(s));
  });
  const address = server.address();
  baseUrl = `http://127.0.0.1:${typeof address === "object" && address ? address.port : 0}`;
});

afterAll(async () => {
  server.closeAllConnections();
  await new Promise((resolve) => server.close(resolve));
});

beforeEach(() => {
  vi.clearAllMocks();
  h.findByName.mockImplementation(async (name: string) =>
    name === ENDPOINT.name ? ENDPOINT : undefined,
  );
  h.validateApiKey.mockImplementation(async (key: string) =>
    key === API_KEY
      ? {
          valid: true,
          user_id: null,
          key_uuid: "44444444-4444-4444-8444-444444444444",
        }
      : { valid: false },
  );
  h.execute.mockImplementation(
    async (_req: express.Request, res: express.Response, body: unknown) => {
      res.status(200).json({ executed: true, body });
    },
  );
});

function post(
  path: string,
  body: string,
  headers: Record<string, string> = {},
): Promise<Response> {
  return fetch(`${baseUrl}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...headers },
    body,
  });
}

describe("the parent router", () => {
  it.each(["/metamcp/autotask/api/tools/", "/metamcp/autotask/api/tools/x"])(
    "hands a JSON POST to %s to its first child with the body unread",
    async (path) => {
      const body = JSON.stringify({ query: "open tickets" });
      const response = await post(path, body, {
        "x-test-probe": "first-child",
      });

      expect(response.status).toBe(200);
      expect(await response.json()).toEqual({
        parsedBefore: false,
        raw: body,
      });
    },
  );
});

describe("the OpenAPI bridge", () => {
  it("hands an authorized JSON POST's body to the executor", async () => {
    const response = await post(
      "/metamcp/autotask/api/autotask__ticket_search",
      JSON.stringify({ query: "open tickets" }),
      { "X-API-Key": API_KEY },
    );

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      executed: true,
      body: { query: "open tickets" },
    });
    expect(h.execute).toHaveBeenCalledTimes(1);
    expect(h.validateApiKey).toHaveBeenCalledWith(API_KEY, expect.anything());
  });

  it.each([
    ["no key", {}],
    ["an invalid key", { "X-API-Key": "sk_mt_wrongkey0000" }],
  ])("refuses a POST with %s and never executes", async (_label, headers) => {
    const response = await post(
      "/metamcp/autotask/api/autotask__ticket_search",
      JSON.stringify({ query: "open tickets" }),
      headers as Record<string, string>,
    );

    expect(response.status).toBe(401);
    expect(h.execute).not.toHaveBeenCalled();
  });

  it("parses the /api/tools/ spelling with the bridge's own parser", async () => {
    const response = await post(
      "/metamcp/autotask/api/tools/",
      JSON.stringify({ query: "open tickets" }),
      { "X-API-Key": API_KEY },
    );

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      executed: true,
      body: { query: "open tickets" },
    });
  });

  it("applies the bridge's 100kb limit to the /api/tools/ spelling", async () => {
    const response = await post(
      "/metamcp/autotask/api/tools/",
      JSON.stringify({ blob: "x".repeat(OVER_BRIDGE_BYTES) }),
      { "X-API-Key": API_KEY },
    );

    expect(response.status).toBe(413);
    expect(await response.json()).toEqual(BAD_REQUEST_BODY);
    expect(h.execute).not.toHaveBeenCalled();
  });
});
