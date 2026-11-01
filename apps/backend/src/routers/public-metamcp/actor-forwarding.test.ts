/**
 * Real public routes -> SDK server transport -> proxy tools/call -> pooled
 * createMetaMcpClient -> HTTP backend. Only authentication, persistence, pool
 * ownership and DB-backed middleware are stubbed. The caller store and both
 * sides' protocol handling run unchanged, so a missed async boundary cannot
 * hide behind a direct call to runWithCallerContext.
 */
import type { Server } from "node:http";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import express from "express";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({
  getSession: vi.fn(),
  getServer: vi.fn(),
  getServerInstance: vi.fn(),
  cleanupSession: vi.fn(),
  listing: vi.fn(),
}));

vi.mock("@/utils/logger", () => ({
  default: { error: vi.fn(), warn: vi.fn(), info: vi.fn(), debug: vi.fn() },
}));
vi.mock("@/db", () => ({ db: {}, pool: { on: vi.fn() } }));
vi.mock("@/db/repositories", () => ({ mcpServersRepository: {} }));
vi.mock("@/db/repositories/oauth-sessions.repo", () => ({
  oauthSessionsRepository: {},
}));
vi.mock("@/db/repositories/mcp-sessions.repo", () => ({
  mcpSessionsRepository: {
    persist: vi.fn().mockResolvedValue(undefined),
    touch: vi.fn().mockResolvedValue(undefined),
    delete: vi.fn().mockResolvedValue(undefined),
    pruneOlderThan: vi.fn().mockResolvedValue(0),
  },
}));
vi.mock("@/trpc/tools.impl", () => ({
  toolsImplementations: { syncFromListing: vi.fn() },
}));
vi.mock("@/lib/config.service", () => ({
  configService: {
    getSessionLifetime: async () => null,
    getMcpResetTimeoutOnProgress: async () => false,
    getMcpTimeout: async () => 5_000,
    getMcpMaxTotalTimeout: async () => 10_000,
  },
}));
vi.mock("@/lib/health-upstream", () => ({
  isAdminHealthRequest: async () => false,
}));
vi.mock("@/middleware/lookup-endpoint-middleware", () => ({
  lookupEndpoint: (
    req: express.Request,
    _res: express.Response,
    next: express.NextFunction,
  ) => {
    Object.assign(req, { namespaceUuid: "ns-actor", endpointName: "actors" });
    next();
  },
}));
vi.mock("@/middleware/api-key-oauth.middleware", () => ({
  authenticateApiKey: (
    req: express.Request,
    _res: express.Response,
    next: express.NextFunction,
  ) => {
    Object.assign(req, { authMethod: "api_key", apiKeyUuid: "shared-key" });
    next();
  },
}));
vi.mock("@/middleware/rate-limit.middleware", () => ({
  rateLimitMiddleware: (
    _req: express.Request,
    _res: express.Response,
    next: express.NextFunction,
  ) => next(),
}));
vi.mock("@/lib/metamcp/consumer-identity-resolver", () => ({
  resolveClientIdentity: async () => ({ name: "shared-key" }),
}));
vi.mock("@/lib/metamcp/metamcp-server-pool", () => ({
  metaMcpServerPool: {
    getServer: h.getServer,
    getServerInstance: h.getServerInstance,
    cleanupSession: h.cleanupSession,
    getMcpServerPoolStatus: () => ({ idle: 0, active: 0 }),
  },
}));
vi.mock("@/lib/metamcp/mcp-server-pool", () => ({
  mcpServerPool: {
    getSession: h.getSession,
    cleanupSession: vi.fn(),
    getPoolStatus: () => ({ idle: 0, active: 1 }),
  },
}));
vi.mock("@/lib/metamcp/fetch-metamcp", () => ({
  getNamespaceListingServers: h.listing,
  getMcpServers: async () => (await h.listing()).routable,
}));
vi.mock("@/lib/metamcp/metamcp-middleware/auditing.functional", () => ({
  createAuditingMiddleware: () => (next: unknown) => next,
}));
vi.mock("@/lib/metamcp/metamcp-middleware/filter-tools.functional", () => ({
  createFilterCallToolMiddleware: () => (next: unknown) => next,
  createFilterListToolsMiddleware: () => (next: unknown) => next,
}));
vi.mock("@/lib/metamcp/metamcp-middleware/tool-overrides.functional", () => ({
  createToolOverridesCallToolMiddleware: () => (next: unknown) => next,
  createToolOverridesListToolsMiddleware: () => (next: unknown) => next,
  mapOverrideNameToOriginal: async (name: string) => name,
}));

import type { ConnectedClient } from "../../lib/metamcp/client";
import { createMetaMcpClient } from "../../lib/metamcp/client";
import { createServer } from "../../lib/metamcp/metamcp-proxy";
import { toolsSyncCache } from "../../lib/metamcp/tools-sync-cache";
import sseRouter from "./sse";
import streamableHttpRouter, { cleanupSession } from "./streamable-http";

interface SeenRequest {
  method: string;
  rpcMethod?: string;
  callId?: string;
  actor?: string;
}

let httpServer: Server;
let baseUrl: string;
let pooled: ConnectedClient | undefined;
let connecting: Promise<ConnectedClient> | undefined;
const instances = new Map<string, Awaited<ReturnType<typeof createServer>>>();
const consumers: Client[] = [];
const seen: SeenRequest[] = [];

beforeEach(async () => {
  vi.clearAllMocks();
  toolsSyncCache.clear();
  instances.clear();
  seen.length = 0;
  pooled = undefined;
  connecting = undefined;

  const app = express();
  app.all("/backend/mcp", express.json(), (req, res) => {
    const message = req.body as
      | {
          id?: number;
          method?: string;
          params?: {
            protocolVersion?: string;
            arguments?: { callId?: string };
          };
        }
      | undefined;
    seen.push({
      method: req.method,
      rpcMethod: message?.method,
      callId: message?.params?.arguments?.callId,
      actor: req.headers["x-mcp-actor"] as string | undefined,
    });
    if (req.method === "GET") return void res.sendStatus(405);
    if (req.method === "DELETE") return void res.sendStatus(200);
    let result: unknown;
    switch (message?.method) {
      case "initialize":
        res.setHeader("mcp-session-id", "pooled-backend-session");
        result = {
          protocolVersion: message.params?.protocolVersion,
          capabilities: { tools: {} },
          serverInfo: { name: "actor-backend", version: "1.0.0" },
        };
        break;
      case "tools/list":
        result = {
          tools: [{ name: "echo", inputSchema: { type: "object" } }],
        };
        break;
      case "tools/call":
        result = { content: [{ type: "text", text: "ok" }] };
        break;
      default:
        return void res.status(202).end();
    }
    res.json({ jsonrpc: "2.0", id: message?.id, result });
  });
  app.use("/metamcp", sseRouter, streamableHttpRouter);
  await new Promise<void>((resolve) => {
    httpServer = app.listen(0, "127.0.0.1", resolve);
  });
  const address = httpServer.address();
  if (!address || typeof address === "string") throw new Error("no port");
  baseUrl = `http://127.0.0.1:${address.port}`;

  const params = {
    uuid: "backend-actor",
    name: "actors",
    type: "STREAMABLE_HTTP",
    url: `${baseUrl}/backend/mcp`,
    headers: { "X-MCP-Actor": "stored@example.com" },
  };
  h.listing.mockResolvedValue({
    routable: { [params.uuid]: params },
    errorGated: {},
  });
  h.getSession.mockImplementation(() => {
    connecting ??= (async () => {
      const { client, transport } = createMetaMcpClient(params as never);
      if (!client || !transport) throw new Error("no pooled client");
      await client.connect(transport);
      pooled = {
        client,
        cleanup: () => client.close(),
        listChangedSubscribers: new Set(),
      };
      return pooled;
    })();
    return connecting;
  });
  h.getServer.mockImplementation(async (sessionId: string) => {
    const instance = await createServer("ns-actor", sessionId);
    instances.set(sessionId, instance);
    return instance;
  });
  h.getServerInstance.mockImplementation((sessionId: string) =>
    instances.get(sessionId),
  );
  h.cleanupSession.mockImplementation(async (sessionId: string) => {
    const instance = instances.get(sessionId);
    instances.delete(sessionId);
    await instance?.cleanup();
  });
});

afterEach(async () => {
  for (const client of consumers.splice(0)) await client.close();
  for (const sessionId of instances.keys()) await cleanupSession(sessionId);
  await pooled?.cleanup();
  await new Promise<void>((resolve, reject) => {
    httpServer.close((error) => (error ? reject(error) : resolve()));
    httpServer.closeAllConnections();
  });
});

describe.each(["SSE", "STREAMABLE_HTTP"] as const)(
  "%s public endpoint actor forwarding",
  (type) => {
    it("attributes concurrent callers and a later unlabelled call on one pooled connection", async () => {
      async function consumer(actor: string | undefined) {
        const state = { actor };
        const send = (url: string | URL, init?: RequestInit) => {
          const headers = new Headers(init?.headers);
          if (state.actor) headers.set("X-MCP-Actor", state.actor);
          return fetch(url, { ...init, headers });
        };
        const transport: Transport =
          type === "SSE"
            ? new SSEClientTransport(new URL(`${baseUrl}/metamcp/actors/sse`), {
                fetch: send,
              })
            : new StreamableHTTPClientTransport(
                new URL(`${baseUrl}/metamcp/actors/mcp`),
                { fetch: send },
              );
        const client = new Client({ name: "operator", version: "1.0.0" });
        consumers.push(client);
        await client.connect(transport);
        await client.listTools();
        return { client, state };
      }

      // The first listing cold-connects the backend inside caller one's
      // scope. Later tool calls must not inherit that connection's label.
      const first = await consumer(" tech.one@example.com ");
      const second = await consumer("tech.two@example.com");
      const call = (client: Client, callId: string) =>
        client.callTool({ name: "actors__echo", arguments: { callId } });
      const results = await Promise.all([
        call(first.client, "one"),
        call(second.client, "two"),
      ]);
      first.state.actor = undefined;
      results.push(await call(first.client, "none"));
      for (const result of results) expect(result.isError).toBeFalsy();

      expect(seen.filter((r) => r.rpcMethod === "initialize")).toHaveLength(1);
      const calls = seen.filter((r) => r.rpcMethod === "tools/call");
      expect(calls).toHaveLength(3);
      expect(Object.fromEntries(calls.map((r) => [r.callId, r.actor]))).toEqual(
        {
          one: "tech.one@example.com",
          two: "tech.two@example.com",
          none: undefined,
        },
      );
    });
  },
);
