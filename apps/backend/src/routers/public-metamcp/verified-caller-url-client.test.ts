/**
 * An OAuth client whose id is an https URL (a client metadata document client)
 * through the REAL authentication middleware, the real public Streamable-HTTP
 * route, the SDK server transport, the pooled client and an HTTP backend that
 * records what reaches it.
 *
 * The question: does the backend receive a verified-caller credential for such
 * a client, for every id the registration side accepts? Without the alias the
 * id fails the credential grammar and the request silently carries no
 * `X-Umbrella-Caller`, so a backend that binds sessions to it would refuse a
 * valid client. A narrower pattern (`^https://\S{1,500}$`) once stopped at 508
 * characters while the id check admits 512, so the boundary cases are 508, 509
 * and 512.
 *
 * Only the repositories are faked (the access-token row the middleware reads,
 * the endpoint lookup, the pool's listing); the middleware, the route, the
 * caller-context stamping and the verified-caller wrapper all run unchanged.
 * Expected credentials are hash prefixes computed outside this code base
 * (`sha256sum` and Python `hashlib`) over `https://clients.example.com/`
 * followed by the letter c up to the stated length.
 */
import type { Server } from "node:http";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import express from "express";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({
  getSession: vi.fn(),
  getServer: vi.fn(),
  getServerInstance: vi.fn(),
  cleanupSession: vi.fn(),
  listing: vi.fn(),
  getAccessToken: vi.fn(),
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
// The repositories the REAL middleware reads, at their module seams.
vi.mock("../../db/repositories/oauth.repo", () => ({
  oauthRepository: { getAccessToken: h.getAccessToken },
}));
vi.mock("../../db/repositories/users.repo", () => ({
  usersRepository: { isDisabled: vi.fn().mockResolvedValue(false) },
}));
vi.mock("../../db/repositories/api-keys.repo", () => ({
  ApiKeysRepository: class {
    validateApiKey = vi.fn();
  },
}));
vi.mock("../../db/repositories/access-groups.repo", () => ({
  accessGroupsRepository: {
    hasEndpointGrant: vi.fn().mockResolvedValue(false),
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
    Object.assign(req, {
      namespaceUuid: "ns-team",
      endpointName: "team",
      endpoint: {
        uuid: "11111111-1111-4111-8111-111111111111",
        name: "team",
        description: null,
        namespace_uuid: "ns-team",
        enable_api_key_auth: false,
        require_scoped_api_key: false,
        enable_max_rate: false,
        enable_client_max_rate: false,
        max_rate_seconds: null,
        max_rate: null,
        client_max_rate: null,
        client_max_rate_seconds: null,
        client_max_rate_strategy: null,
        client_max_rate_strategy_key: null,
        enable_oauth: true,
        use_query_param_auth: false,
        restricted: false,
        created_at: new Date("2026-07-01T00:00:00Z"),
        updated_at: new Date("2026-07-01T00:00:00Z"),
        user_id: null,
      },
    });
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
  resolveClientIdentity: async (auth: Record<string, string | undefined>) => ({
    name: "label",
    account: auth.oauthUserId
      ? { userId: auth.oauthUserId, email: "person@example.com" }
      : undefined,
  }),
}));
vi.mock("@/lib/metamcp/metamcp-server-pool", () => ({
  metaMcpServerPool: {
    getServer: h.getServer,
    getServerInstance: h.getServerInstance,
    cleanupSession: h.cleanupSession,
    getOpenApiServer: async () => ({}),
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
import streamableHttpRouter, { cleanupSession } from "./streamable-http";

const PREFIX = "https://clients.example.com/";
const urlOf = (length: number) => PREFIX + "c".repeat(length - PREFIX.length);
const FAMILY_A = "6ba7b810-9dad-41d1-80b4-00c04fd430c8";
const FAMILY_B = "f47ac10b-58cc-4372-a567-0e02b2c3d479";

interface TokenRow {
  client_id: string;
  family_id: string;
}

/** The access-token rows the fake repository holds, by bearer value. */
const TOKENS: Record<string, TokenRow> = {
  mcp_token_len508: { client_id: urlOf(508), family_id: FAMILY_A },
  mcp_token_len509: { client_id: urlOf(509), family_id: FAMILY_A },
  mcp_token_len512: { client_id: urlOf(512), family_id: FAMILY_A },
  // A second connection of the 512-character client, and a refreshed token
  // of the first connection (same family, new token value).
  mcp_token_len512_other: { client_id: urlOf(512), family_id: FAMILY_B },
  mcp_token_len512_refreshed: { client_id: urlOf(512), family_id: FAMILY_A },
  mcp_token_len513: { client_id: urlOf(513), family_id: FAMILY_A },
  mcp_token_dcr: { client_id: "mcp_client_first", family_id: FAMILY_A },
};

/** Expected credential halves, from the independent hash oracle. */
const EXPECTED: Record<string, string | null> = {
  mcp_token_len508:
    "oauth:cimd.4c7ed3b8549530f03d1f6eccef6a76ef.6ba7b8109dad41d1",
  mcp_token_len509:
    "oauth:cimd.5aea74de8b153340a47764df6bcfadd0.6ba7b8109dad41d1",
  mcp_token_len512:
    "oauth:cimd.6a3ba33688d36ff1af237ba53bc21ecf.6ba7b8109dad41d1",
  mcp_token_len512_other:
    "oauth:cimd.6a3ba33688d36ff1af237ba53bc21ecf.f47ac10b58cc4372",
  mcp_token_len512_refreshed:
    "oauth:cimd.6a3ba33688d36ff1af237ba53bc21ecf.6ba7b8109dad41d1",
  // Over the limit: no credential at all, and the gateway still answers.
  mcp_token_len513: null,
  mcp_token_dcr: "oauth:mcp_client_first",
};

interface SeenRequest {
  rpcMethod?: string;
  callId?: string;
  userId?: string;
  caller?: string;
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

  h.getAccessToken.mockImplementation(async (token: string) => {
    const row = TOKENS[token];
    if (!row) return null;
    return {
      access_token: "hash",
      access_token_last4: token.slice(-4),
      client_id: row.client_id,
      user_id: "user-oauth",
      scope: "mcp",
      expires_at: new Date(Date.now() + 60 * 60 * 1000),
      refresh_token: null,
      refresh_token_expires_at: null,
      family_id: row.family_id,
      created_at: new Date(Date.now() - 60_000),
    };
  });

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
      rpcMethod: message?.method,
      callId: message?.params?.arguments?.callId,
      userId: req.headers["x-umbrella-user-id"] as string | undefined,
      caller: req.headers["x-umbrella-caller"] as string | undefined,
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
        result = { tools: [{ name: "echo", inputSchema: { type: "object" } }] };
        break;
      case "tools/call":
        result = { content: [{ type: "text", text: "ok" }] };
        break;
      default:
        return void res.status(202).end();
    }
    res.json({ jsonrpc: "2.0", id: message?.id, result });
  });
  app.use("/metamcp", streamableHttpRouter);
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

async function consumer(token: string): Promise<Client> {
  const send = (url: string | URL, init?: RequestInit) => {
    const headers = new Headers(init?.headers);
    headers.set("Authorization", `Bearer ${token}`);
    // A consumer cannot name itself: whatever it sends is replaced.
    headers.set("X-Umbrella-Caller", "v1.Zm9yZ2Vk");
    return fetch(url, { ...init, headers });
  };
  const client = new Client({ name: "teammate", version: "1.0.0" });
  consumers.push(client);
  await client.connect(
    new StreamableHTTPClientTransport(new URL(`${baseUrl}/metamcp/team/mcp`), {
      fetch: send,
    }),
  );
  await client.listTools();
  return client;
}

function credSeen(request: SeenRequest): string | null {
  if (request.caller === undefined) return null;
  return (
    JSON.parse(
      Buffer.from(request.caller.replace(/^v1\./, ""), "base64url").toString(
        "utf8",
      ),
    ) as { cred: string }
  ).cred;
}

describe("verified caller credential for a URL-identified OAuth client, end to end", () => {
  it("reaches the backend as cimd.<url hash>.<family> for 508, 509 and 512-character ids, and as nothing for an over-limit id", async () => {
    const tokens = Object.keys(TOKENS);
    const clients: Client[] = [];
    for (const token of tokens) clients.push(await consumer(token));

    const results = await Promise.all(
      clients.map((client, index) =>
        client.callTool({
          name: "team__echo",
          arguments: { callId: tokens[index] },
        }),
      ),
    );
    for (const result of results) expect(result.isError).toBeFalsy();

    const calls = seen.filter((r) => r.rpcMethod === "tools/call");
    expect(calls).toHaveLength(tokens.length);
    const byToken = Object.fromEntries(
      calls.map((r) => [r.callId, credSeen(r)]),
    );
    expect(byToken).toEqual(EXPECTED);

    // The user id header is independent of the credential and always sent.
    for (const call of calls) expect(call.userId).toBe("user-oauth");
    // The forged header never arrived.
    expect(seen.map((r) => r.caller)).not.toContain("v1.Zm9yZ2Vk");
  });

  it("keeps two connections of one client distinct, and one connection stable across a refreshed token", async () => {
    const first = await consumer("mcp_token_len512");
    const refreshed = await consumer("mcp_token_len512_refreshed");
    const other = await consumer("mcp_token_len512_other");
    await Promise.all(
      [first, refreshed, other].map((client, index) =>
        client.callTool({
          name: "team__echo",
          arguments: { callId: String(index) },
        }),
      ),
    );

    const creds = Object.fromEntries(
      seen
        .filter((r) => r.rpcMethod === "tools/call")
        .map((r) => [r.callId, credSeen(r)]),
    );
    expect(creds["0"]).toBe(creds["1"]);
    expect(creds["2"]).not.toBe(creds["0"]);
  });
});
