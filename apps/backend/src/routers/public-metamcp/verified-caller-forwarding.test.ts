/**
 * Real public routes -> SDK server transport -> proxy tools/call -> pooled
 * createMetaMcpClient -> HTTP backend, for a backend named in
 * `VERIFIED_CALLER_SERVER_NAMES`.
 *
 * The question this answers end to end: does the backend learn who is calling
 * from the gateway's authentication of the presented credential, and ONLY
 * from that? Each consumer presents its own credential and also sends a
 * forged `X-Umbrella-User-Id` naming someone else. The auth middleware is the
 * one stub that matters: it stamps the identity fields exactly as
 * `authenticateApiKey` does (`apiKeyUserId`, `apiKeyActsAsUserId`,
 * `oauthUserId`), keyed by the credential. Everything between that stamp and
 * the backend socket runs unchanged, as in `actor-forwarding.test.ts`.
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

/**
 * What the auth middleware resolves for each presented credential. The keys
 * are bearer values the consumers send; the values are the request fields
 * `authenticateApiKey` stamps for that credential.
 */
const CREDENTIALS: Record<string, Record<string, string>> = {
  "key-owner": {
    authMethod: "api_key",
    apiKeyUuid: "k-owner",
    apiKeyUserId: "user-owner",
  },
  "key-acts-as": {
    authMethod: "api_key",
    apiKeyUuid: "k-acts-as",
    apiKeyUserId: "user-admin",
    apiKeyActsAsUserId: "user-bound",
  },
  "oauth-token": { authMethod: "oauth", oauthUserId: "user-oauth" },
  "key-ownerless": { authMethod: "api_key", apiKeyUuid: "k-ownerless" },
};

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
    Object.assign(req, { namespaceUuid: "ns-team", endpointName: "team" });
    next();
  },
}));
vi.mock("@/middleware/api-key-oauth.middleware", () => ({
  authenticateApiKey: (
    req: express.Request,
    res: express.Response,
    next: express.NextFunction,
  ) => {
    const token = (req.headers.authorization ?? "").replace(/^Bearer /, "");
    const fields = CREDENTIALS[token];
    if (!fields) return void res.status(401).end();
    Object.assign(req, fields);
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
  resolveClientIdentity: async () => ({ name: "consumer" }),
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
  userId?: string;
}

let httpServer: Server;
let baseUrl: string;
let pooled: ConnectedClient | undefined;
let connecting: Promise<ConnectedClient> | undefined;
const instances = new Map<string, Awaited<ReturnType<typeof createServer>>>();
const consumers: Client[] = [];
const seen: SeenRequest[] = [];
const ORIGINAL_NAMES = process.env.VERIFIED_CALLER_SERVER_NAMES;

beforeEach(async () => {
  vi.clearAllMocks();
  toolsSyncCache.clear();
  instances.clear();
  seen.length = 0;
  pooled = undefined;
  connecting = undefined;
  process.env.VERIFIED_CALLER_SERVER_NAMES = "team";

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
      userId: req.headers["x-umbrella-user-id"] as string | undefined,
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
          serverInfo: { name: "team-backend", version: "1.0.0" },
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
    uuid: "backend-team",
    name: "team",
    type: "STREAMABLE_HTTP",
    url: `${baseUrl}/backend/mcp`,
    // A value stored on the server row is the other way a forged id could
    // ride along; it must never arrive either.
    headers: { "X-Umbrella-User-Id": "user-stored" },
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
    const instance = await createServer("ns-team", sessionId);
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
  if (ORIGINAL_NAMES === undefined) {
    delete process.env.VERIFIED_CALLER_SERVER_NAMES;
  } else {
    process.env.VERIFIED_CALLER_SERVER_NAMES = ORIGINAL_NAMES;
  }
});

describe.each(["SSE", "STREAMABLE_HTTP"] as const)(
  "%s public endpoint verified caller",
  (type) => {
    it("each consumer's tool calls name its verified identity, never the id it forged", async () => {
      async function consumer(credential: string) {
        const send = (url: string | URL, init?: RequestInit) => {
          const headers = new Headers(init?.headers);
          headers.set("Authorization", `Bearer ${credential}`);
          // Every consumer claims to be the same victim.
          headers.set("X-Umbrella-User-Id", "user-victim");
          return fetch(url, { ...init, headers });
        };
        const transport: Transport =
          type === "SSE"
            ? new SSEClientTransport(new URL(`${baseUrl}/metamcp/team/sse`), {
                fetch: send,
              })
            : new StreamableHTTPClientTransport(
                new URL(`${baseUrl}/metamcp/team/mcp`),
                { fetch: send },
              );
        const client = new Client({ name: "teammate", version: "1.0.0" });
        consumers.push(client);
        await client.connect(transport);
        await client.listTools();
        return client;
      }

      // The first listing cold-connects the backend inside the first
      // consumer's scope; the handshake must still name nobody.
      const owner = await consumer("key-owner");
      const actsAs = await consumer("key-acts-as");
      const oauth = await consumer("oauth-token");
      const ownerless = await consumer("key-ownerless");
      const call = (client: Client, callId: string) =>
        client.callTool({ name: "team__echo", arguments: { callId } });
      const results = await Promise.all([
        call(owner, "owner"),
        call(actsAs, "acts-as"),
        call(oauth, "oauth"),
        call(ownerless, "ownerless"),
      ]);
      for (const result of results) expect(result.isError).toBeFalsy();

      const calls = seen.filter((r) => r.rpcMethod === "tools/call");
      expect(calls).toHaveLength(4);
      expect(
        Object.fromEntries(calls.map((r) => [r.callId, r.userId])),
      ).toEqual({
        owner: "user-owner",
        "acts-as": "user-bound",
        oauth: "user-oauth",
        ownerless: undefined,
      });

      // Handshake, listing and stream traffic carry no identity.
      expect(seen.filter((r) => r.rpcMethod === "initialize")).toHaveLength(1);
      for (const r of seen.filter((r) => r.rpcMethod !== "tools/call")) {
        expect([r.method, r.rpcMethod, r.userId]).toEqual([
          r.method,
          r.rpcMethod,
          undefined,
        ]);
      }
      // Neither forged value reached the backend on any request.
      const values = seen.map((r) => r.userId);
      expect(values).not.toContain("user-victim");
      expect(values).not.toContain("user-stored");
    });
  },
);
