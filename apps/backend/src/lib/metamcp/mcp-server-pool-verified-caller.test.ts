/**
 * The verified caller on connections the pool SHARES between public sessions.
 *
 * A pooled backend connection is one backend MCP session, and the pool hands
 * it to more than one public session: at the per-server cap a new session is
 * given an existing session's live connection, and a closed session's
 * connection goes back to the idle slot for the next session to adopt. So a
 * backend cannot tell callers apart by its own MCP session id. What tells
 * them apart is the per-request caller binding, which the pooled fetch reads
 * at send time; these tests drive the real pool through both sharing paths
 * and check that every tool call carries the caller that made it.
 *
 * Real: McpServerPool, createMetaMcpClient, the guarded fetch and the
 * verified-caller wrapper, the SDK client and transport. Replaced: the
 * socket (undici), by an in-process Streamable-HTTP backend that answers each
 * tool call with the identity headers it received.
 */
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

const h = vi.hoisted(() => {
  process.env.MCP_ACTIVE_HEALTH_CHECK = "false";

  let sessions = 0;
  const json = (body: unknown, extra: Record<string, string> = {}) =>
    new Response(JSON.stringify(body), {
      status: 200,
      headers: { "content-type": "application/json", ...extra },
    });

  /** A minimal Streamable-HTTP backend that echoes the identity it saw. */
  const backend = async (
    _url: unknown,
    init?: {
      method?: string;
      headers?: ConstructorParameters<typeof Headers>[0];
      body?: unknown;
    },
  ): Promise<Response> => {
    const headers = new Headers(init?.headers);
    const method = (init?.method ?? "GET").toUpperCase();
    if (method === "DELETE") return new Response(null, { status: 200 });
    if (method === "GET") return new Response(null, { status: 405 });

    const message = JSON.parse(String(init?.body)) as {
      id?: number;
      method?: string;
    };
    if (message.method === "initialize") {
      sessions += 1;
      return json(
        {
          jsonrpc: "2.0",
          id: message.id,
          result: {
            protocolVersion: "2025-06-18",
            capabilities: { tools: {} },
            serverInfo: { name: "identity-echo", version: "0" },
          },
        },
        { "mcp-session-id": `backend-session-${sessions}` },
      );
    }
    if (message.id === undefined) return new Response(null, { status: 202 });
    if (message.method === "tools/call") {
      const caller = headers.get("x-umbrella-caller");
      const payload = caller
        ? (JSON.parse(
            Buffer.from(caller.replace(/^v1\./, ""), "base64url").toString(
              "utf8",
            ),
          ) as { uid: string; cred: string })
        : undefined;
      const text = JSON.stringify({
        session: headers.get("mcp-session-id"),
        userId: headers.get("x-umbrella-user-id"),
        pair: payload ? `${payload.uid} ${payload.cred}` : null,
      });
      return json({
        jsonrpc: "2.0",
        id: message.id,
        result: { content: [{ type: "text", text }] },
      });
    }
    return json({ jsonrpc: "2.0", id: message.id, result: {} });
  };
  return { backend, backendSessions: () => sessions };
});

vi.mock("undici", () => ({
  fetch: h.backend,
  Agent: class {
    constructor(..._args: unknown[]) {}
  },
}));
vi.mock("@/utils/logger", () => ({
  default: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));
vi.mock("../config.service", () => ({
  configService: {
    getSessionLifetime: vi.fn().mockResolvedValue(null),
    getMcpMaxAttempts: vi.fn().mockResolvedValue(1),
  },
}));
vi.mock("../../db/repositories/index", () => ({ mcpServersRepository: {} }));
vi.mock("../../db/repositories/mcp-servers.repo", () => ({
  mcpServersRepository: {},
}));
vi.mock("../../db/repositories/oauth-sessions.repo", () => ({
  oauthSessionsRepository: {},
}));
vi.mock("./server-error-tracker", () => ({
  serverErrorTracker: {
    getServerMaxAttempts: vi.fn().mockResolvedValue(1),
    isServerInErrorState: vi.fn().mockResolvedValue(false),
    recordServerCrash: vi.fn(),
    resetServerAttempts: vi.fn(),
    resetServerErrorState: vi.fn(),
    markSuccess: vi.fn(),
  },
}));

import { CallToolResultSchema } from "@modelcontextprotocol/sdk/types.js";
import type { ServerParameters } from "@repo/zod-types";

import {
  type CallerContext,
  runWithCallerContext,
} from "./caller-context-store";
import type { ConnectedClient } from "./client";
import { McpServerPool } from "./mcp-server-pool";

const PoolConstructor = McpServerPool as unknown as new (
  defaultIdleCount?: number,
  maxTotalConnections?: number,
  maxConnectionsPerServer?: number,
) => McpServerPool;

const SERVER_UUID = "22222222-2222-4222-8222-222222222222";
const params = {
  uuid: SERVER_UUID,
  name: "team",
  description: "",
  type: "STREAMABLE_HTTP",
  url: "http://10.0.0.7:3000/mcp",
  created_at: new Date().toISOString(),
  status: "active",
} as unknown as ServerParameters;

// Two people, each on their own credential, and the first person on a second
// credential. None of them sends an asserted actor.
const FIRST: CallerContext = {
  authMethod: "oauth",
  userId: "user-first",
  oauthClientId: "mcp_client_first",
};
const SECOND: CallerContext = {
  authMethod: "api_key",
  userId: "user-second",
  apiKeyUuid: "00000000-0000-4000-8000-0000000000b2",
};
const FIRST_OTHER_KEY: CallerContext = {
  authMethod: "api_key",
  userId: "user-first",
  apiKeyUuid: "00000000-0000-4000-8000-0000000000b1",
};

interface Seen {
  session: string | null;
  userId: string | null;
  pair: string | null;
}

/** What the backend saw for one tools/call made by `caller`. */
const seenFor = async (
  connection: ConnectedClient | undefined,
  caller: CallerContext,
): Promise<Seen> => {
  if (!connection) throw new Error("the pool returned no connection");
  const result = await runWithCallerContext(caller, () =>
    connection.client.request(
      { method: "tools/call", params: { name: "write", arguments: {} } },
      CallToolResultSchema,
    ),
  );
  return JSON.parse((result.content[0] as { text: string }).text) as Seen;
};

const ORIGINAL_NAMES = process.env.VERIFIED_CALLER_SERVER_NAMES;
const pools: McpServerPool[] = [];

beforeAll(() => {
  process.env.VERIFIED_CALLER_SERVER_NAMES = "team";
});

afterAll(async () => {
  await Promise.all(pools.map((pool) => pool.cleanupAll()));
  if (ORIGINAL_NAMES === undefined) {
    delete process.env.VERIFIED_CALLER_SERVER_NAMES;
  } else {
    process.env.VERIFIED_CALLER_SERVER_NAMES = ORIGINAL_NAMES;
  }
});

describe("the verified caller on a connection the pool shares between sessions", () => {
  it("at the per-server cap, a second session given the first session's live connection carries its own caller", async () => {
    // A cap of one connection per server makes the second session share.
    const pool = new PoolConstructor(1, 100, 1);
    pools.push(pool);

    const first = await pool.getSession(
      "public-session-1",
      SERVER_UUID,
      params,
    );
    const firstSeen = await seenFor(first, FIRST);
    const second = await pool.getSession(
      "public-session-2",
      SERVER_UUID,
      params,
    );
    const secondSeen = await seenFor(second, SECOND);
    const firstAgain = await seenFor(first, FIRST_OTHER_KEY);

    // One connection, one backend session, for both public sessions.
    expect(second).toBe(first);
    expect(secondSeen.session).toBe(firstSeen.session);
    // Each call names the caller that made it.
    expect(firstSeen).toMatchObject({
      userId: "user-first",
      pair: "user-first oauth:mcp_client_first",
    });
    expect(secondSeen).toMatchObject({
      userId: "user-second",
      pair: `user-second api_key:${SECOND.apiKeyUuid}`,
    });
    expect(firstAgain).toMatchObject({
      userId: "user-first",
      pair: `user-first api_key:${FIRST_OTHER_KEY.apiKeyUuid}`,
    });
  });

  it("a connection handed on after its session closes carries the next session's caller", async () => {
    const before = h.backendSessions();
    const pool = new PoolConstructor(1, 100, 1);
    pools.push(pool);

    const first = await pool.getSession(
      "public-session-3",
      SERVER_UUID,
      params,
    );
    const firstSeen = await seenFor(first, FIRST);
    await pool.cleanupSession("public-session-3");

    const next = await pool.getSession("public-session-4", SERVER_UUID, params);
    const nextSeen = await seenFor(next, SECOND);

    // The next session adopted the same backend session.
    expect(nextSeen.session).toBe(firstSeen.session);
    expect(h.backendSessions()).toBe(before + 1);
    expect(nextSeen).toMatchObject({
      userId: "user-second",
      pair: `user-second api_key:${SECOND.apiKeyUuid}`,
    });
  });

  it("a call outside any caller binding on a shared connection carries neither header", async () => {
    const pool = new PoolConstructor(1, 100, 1);
    pools.push(pool);
    const connection = await pool.getSession(
      "public-session-5",
      SERVER_UUID,
      params,
    );
    await seenFor(connection, FIRST);
    if (!connection) throw new Error("the pool returned no connection");
    const result = await connection.client.request(
      { method: "tools/call", params: { name: "write", arguments: {} } },
      CallToolResultSchema,
    );
    expect(
      JSON.parse((result.content[0] as { text: string }).text),
    ).toMatchObject({ userId: null, pair: null });
  });
});
