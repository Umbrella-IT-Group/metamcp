/**
 * The gateway-verified `X-Umbrella-User-Id` on the POOLED data-plane
 * transports built by `createMetaMcpClient`.
 *
 * What this pins: a backend named in `VERIFIED_CALLER_SERVER_NAMES` receives
 * the verified caller's user id on its tool calls and on nothing else, a value
 * stored on the server row (or put there any other way) never reaches it, a
 * backend that is not named gets no identity from the caller binding, the m365
 * injection keeps its own behaviour, and on every server, whatever its name,
 * a stored `X-Umbrella-User-Id` or `X-Umbrella-Caller` is never sent while
 * the row's other stored headers are.
 *
 * Driven through the production wiring: undici is mocked as the network and
 * every URL is an IP literal, so no resolver is touched. The SDK client and
 * transports are real.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

interface SeenRequest {
  url: string;
  httpMethod: string;
  rpcMethod?: string;
  toolName?: string;
  userId: string | null;
  caller: string | null;
  authorization: string | null;
  custom: string | null;
}

const { undiciFetch, seen, getAccessToken } = vi.hoisted(() => {
  const seen: SeenRequest[] = [];
  const json = (body: unknown, extra: Record<string, string> = {}) =>
    new Response(JSON.stringify(body), {
      status: 200,
      headers: { "content-type": "application/json", ...extra },
    });
  // A minimal stateful Streamable-HTTP MCP backend that records the user-id
  // header each request reached it with.
  const undiciFetch = vi.fn(async (url: unknown, init?: RequestInit) => {
    const headers = new Headers(init?.headers);
    const httpMethod = (init?.method ?? "GET").toUpperCase();
    const message =
      httpMethod === "POST" && typeof init?.body === "string"
        ? (JSON.parse(init.body) as {
            id?: number;
            method?: string;
            params?: { protocolVersion?: string; name?: string };
          })
        : undefined;
    seen.push({
      url: String(url),
      httpMethod,
      rpcMethod: message?.method,
      toolName: message?.params?.name,
      userId: headers.get("x-umbrella-user-id"),
      caller: headers.get("x-umbrella-caller"),
      authorization: headers.get("authorization"),
      custom: headers.get("x-custom-tenant"),
    });
    if (httpMethod === "DELETE") return new Response(null, { status: 200 });
    // No standalone stream: the SDK treats 405 as "not offered".
    if (httpMethod === "GET") return new Response(null, { status: 405 });
    switch (message?.method) {
      case "initialize":
        return json(
          {
            jsonrpc: "2.0",
            id: message.id,
            result: {
              protocolVersion: message.params?.protocolVersion,
              capabilities: { tools: {} },
              serverInfo: { name: "fake-backend", version: "1.0.0" },
            },
          },
          { "mcp-session-id": "backend-session-1" },
        );
      case "tools/list":
        return json({ jsonrpc: "2.0", id: message.id, result: { tools: [] } });
      case "tools/call":
        return json({
          jsonrpc: "2.0",
          id: message.id,
          result: { content: [{ type: "text", text: "ok" }] },
        });
      case undefined:
        return new Response("ok", { status: 200 });
      default:
        return new Response(null, { status: 202 });
    }
  });
  const getAccessToken = vi.fn(async (userId: string) => `graph-${userId}`);
  return { undiciFetch, seen, getAccessToken };
});
vi.mock("undici", () => ({
  fetch: undiciFetch,
  Agent: class {
    constructor(..._args: unknown[]) {}
  },
}));

// client.ts's module-load chain reaches db/index (which throws on a missing
// DATABASE_URL); stub it out, matching client-actor-header.test.ts.
vi.mock("../../db/repositories/index", () => ({ mcpServersRepository: {} }));
vi.mock("../../db/repositories/oauth-sessions.repo", () => ({
  oauthSessionsRepository: {},
}));
vi.mock("../config.service", () => ({
  configService: { getMcpMaxAttempts: vi.fn().mockResolvedValue(3) },
}));
vi.mock("@/utils/logger", () => ({
  default: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));
// The m365 case needs a Graph token without Entra: the mint service is the
// only stub, so the injected fetch itself runs unchanged.
vi.mock("../m365/mint-service", () => ({
  m365MintService: { getAccessToken },
}));

import { runWithM365UserContext } from "../m365/request-context";
import { runWithCallerContext } from "./caller-context-store";
import { createMetaMcpClient } from "./client";

const INTERNAL_URL = "http://10.0.0.5:3000/mcp";
const INTERNAL_SSE_URL = "http://10.0.0.5:3000/sse";
const PUBLIC_URL = "http://93.184.216.34:3000/mcp";
const SPOOF = { "X-Umbrella-User-Id": "user-victim" };

const ENV_KEYS = [
  "VERIFIED_CALLER_SERVER_NAMES",
  "M365_INJECTED_SERVER_NAMES",
  "TRANSFORM_LOCALHOST_TO_DOCKER_INTERNAL",
] as const;
const savedEnv: Record<string, string | undefined> = {};

const asParams = (over: Record<string, unknown>) =>
  ({
    uuid: "srv-uuid",
    name: "team",
    description: "",
    status: "active",
    created_at: new Date().toISOString(),
    ...over,
  }) as never;

type InstalledFetch = (url: URL, init?: RequestInit) => Promise<Response>;

/** The request fetch each transport was built with (an SDK private). */
const installedFetch = (transport: unknown): InstalledFetch =>
  (transport as { _fetch: InstalledFetch })._fetch;

/** The SSE transport's stream fetch (`eventSourceInit.fetch`). */
const streamFetch = (transport: unknown): InstalledFetch =>
  (transport as { _eventSourceInit: { fetch: InstalledFetch } })
    ._eventSourceInit.fetch;

const toolCallInit = (headers: Record<string, string> = {}): RequestInit => ({
  method: "POST",
  headers: { "content-type": "application/json", ...headers },
  body: JSON.stringify({
    jsonrpc: "2.0",
    id: 1,
    method: "tools/call",
    params: { name: "ask", arguments: {} },
  }),
});

beforeEach(() => {
  undiciFetch.mockClear();
  getAccessToken.mockClear();
  seen.length = 0;
  for (const key of ENV_KEYS) savedEnv[key] = process.env[key];
  for (const key of ENV_KEYS) delete process.env[key];
  process.env.VERIFIED_CALLER_SERVER_NAMES = "team";
});

afterEach(() => {
  for (const key of ENV_KEYS) {
    if (savedEnv[key] === undefined) delete process.env[key];
    else process.env[key] = savedEnv[key];
  }
});

describe("X-Umbrella-User-Id on a named backend", () => {
  it("a real SDK client on one pooled connection: each tool call carries its own verified caller, and a stored value never arrives", async () => {
    const { client, transport } = createMetaMcpClient(
      asParams({ type: "STREAMABLE_HTTP", url: INTERNAL_URL, headers: SPOOF }),
    );
    if (!client || !transport) throw new Error("no client built");

    // Connected outside any caller scope, as the pool's idle warm-up does.
    await client.connect(transport);
    await client.listTools();

    // The tool name says which caller sent each call, so every call is
    // matched to its own caller rather than only counted.
    const call = (toolName: string, caller: Record<string, string>) =>
      runWithCallerContext(caller, () =>
        client.callTool({ name: toolName, arguments: {} }),
      );
    const results = await Promise.all([
      call("for-key-owner", { authMethod: "api_key", userId: "user-owner" }),
      call("for-acts-as", {
        authMethod: "api_key",
        userId: "user-admin",
        actsAsUserId: "user-bound",
      }),
      call("for-oauth", { authMethod: "oauth", userId: "user-oauth" }),
      call("for-ownerless-key", { authMethod: "api_key", apiKeyUuid: "k-1" }),
    ]);
    for (const result of results) expect(result.isError).toBeFalsy();
    await client.callTool({ name: "for-no-scope", arguments: {} });

    const calls = seen.filter((r) => r.rpcMethod === "tools/call");
    expect(
      Object.fromEntries(calls.map((r) => [r.toolName, r.userId])),
    ).toEqual({
      "for-key-owner": "user-owner",
      "for-acts-as": "user-bound",
      "for-oauth": "user-oauth",
      "for-ownerless-key": null,
      "for-no-scope": null,
    });
    // The handshake and the listing name nobody, and the stored value
    // reached the backend on no request at all.
    for (const r of seen.filter((r) => r.rpcMethod !== "tools/call")) {
      expect([r.httpMethod, r.rpcMethod, r.userId]).toEqual([
        r.httpMethod,
        r.rpcMethod,
        null,
      ]);
    }
    expect(seen.some((r) => r.userId === "user-victim")).toBe(false);

    await client.close();
  });

  it("a cold connect inside a caller's scope sends no identity on the handshake or the listing", async () => {
    const { client, transport } = createMetaMcpClient(
      asParams({ type: "STREAMABLE_HTTP", url: INTERNAL_URL }),
    );
    if (!client || !transport) throw new Error("no client built");
    try {
      await runWithCallerContext(
        { authMethod: "api_key", userId: "user-one" },
        async () => {
          await client.connect(transport);
          await client.listTools();
          await client.callTool({ name: "first", arguments: {} });
        },
      );
      await runWithCallerContext(
        { authMethod: "api_key", userId: "user-two" },
        () => client.callTool({ name: "second", arguments: {} }),
      );

      expect(seen.find((r) => r.rpcMethod === "initialize")?.userId).toBeNull();
      expect(seen.find((r) => r.rpcMethod === "tools/list")?.userId).toBeNull();
      expect(
        seen.filter((r) => r.httpMethod === "GET").map((r) => r.userId),
      ).toEqual(seen.filter((r) => r.httpMethod === "GET").map(() => null));
      expect(
        seen
          .filter((r) => r.rpcMethod === "tools/call")
          .map((r) => [r.toolName, r.userId]),
      ).toEqual([
        ["first", "user-one"],
        ["second", "user-two"],
      ]);
    } finally {
      await client.close();
    }
  });

  it("SSE: the back-channel tool call carries the verified caller and replaces a supplied value", async () => {
    const { transport } = createMetaMcpClient(
      asParams({ type: "SSE", url: INTERNAL_SSE_URL }),
    );
    await runWithCallerContext({ authMethod: "oauth", userId: "user-1" }, () =>
      installedFetch(transport)(
        new URL("http://10.0.0.5:3000/messages"),
        toolCallInit(SPOOF),
      ),
    );
    expect(seen).toHaveLength(1);
    expect(seen[0].userId).toBe("user-1");
  });

  it("SSE: the stream GET carries no identity and drops a stored value", async () => {
    const { transport } = createMetaMcpClient(
      asParams({ type: "SSE", url: INTERNAL_SSE_URL, headers: SPOOF }),
    );
    await runWithCallerContext({ authMethod: "oauth", userId: "user-1" }, () =>
      streamFetch(transport)(new URL(INTERNAL_SSE_URL), {}),
    );
    expect(seen).toHaveLength(1);
    expect(seen[0].userId).toBeNull();
  });

  it("a named backend at a public address never receives the identity", async () => {
    const { transport } = createMetaMcpClient(
      asParams({ type: "STREAMABLE_HTTP", url: PUBLIC_URL }),
    );
    await runWithCallerContext({ authMethod: "oauth", userId: "user-1" }, () =>
      installedFetch(transport)(new URL(PUBLIC_URL), toolCallInit()),
    );
    expect(seen).toHaveLength(1);
    expect(seen[0].userId).toBeNull();
  });

  it.each([301, 302, 303])(
    "drops the identity when a same-origin %i rewrites the tool POST to GET",
    async (status) => {
      // The wrapper classifies the original POST, but the guard owns the
      // redirect loop. A follow-up GET must not inherit that POST's identity.
      const record = undiciFetch.getMockImplementation();
      if (!record) throw new Error("no recording fetch installed");
      undiciFetch.mockImplementationOnce(async (url, init) => {
        await record(url, init);
        return new Response(null, {
          status,
          headers: { location: "/redirected" },
        });
      });
      const { transport } = createMetaMcpClient(
        asParams({ type: "STREAMABLE_HTTP", url: INTERNAL_URL }),
      );
      await runWithCallerContext(
        { authMethod: "oauth", userId: "user-1" },
        () => installedFetch(transport)(new URL(INTERNAL_URL), toolCallInit()),
      );
      expect(seen.map((r) => [r.httpMethod, r.userId])).toEqual([
        ["POST", "user-1"],
        ["GET", null],
      ]);
    },
  );

  it.each([307, 308])(
    "keeps the identity when a same-origin %i replays the same tool POST",
    async (status) => {
      // 307 and 308 resend the same method and body, so the follow-up is the
      // same executing request and keeps the caller it was set for.
      const record = undiciFetch.getMockImplementation();
      if (!record) throw new Error("no recording fetch installed");
      undiciFetch.mockImplementationOnce(async (url, init) => {
        await record(url, init);
        return new Response(null, {
          status,
          headers: { location: "/redirected" },
        });
      });
      const { transport } = createMetaMcpClient(
        asParams({ type: "STREAMABLE_HTTP", url: INTERNAL_URL }),
      );
      await runWithCallerContext(
        { authMethod: "oauth", userId: "user-1" },
        () => installedFetch(transport)(new URL(INTERNAL_URL), toolCallInit()),
      );
      expect(seen.map((r) => [r.httpMethod, r.userId])).toEqual([
        ["POST", "user-1"],
        ["POST", "user-1"],
      ]);
    },
  );

  it("refuses to build a transport for a server that is also in the m365 list", () => {
    process.env.VERIFIED_CALLER_SERVER_NAMES = "m365";
    expect(() =>
      createMetaMcpClient(
        asParams({ name: "m365", type: "STREAMABLE_HTTP", url: INTERNAL_URL }),
      ),
    ).toThrow(/M365_INJECTED_SERVER_NAMES/);
  });
});

describe("backends that are not named get no identity from the caller binding", () => {
  it("an unnamed backend gets no identity from the caller binding", async () => {
    const { transport } = createMetaMcpClient(
      asParams({ name: "other", type: "STREAMABLE_HTTP", url: INTERNAL_URL }),
    );
    await runWithCallerContext({ authMethod: "oauth", userId: "user-1" }, () =>
      installedFetch(transport)(new URL(INTERNAL_URL), toolCallInit()),
    );
    expect(seen[0].userId).toBeNull();
  });

  it("m365 keeps its own identity: the m365 user, never the caller binding", async () => {
    // The verified-caller wrapper is not on m365's fetch, so the caller
    // binding below (a different user) must not appear anywhere.
    const { transport } = createMetaMcpClient(
      asParams({ name: "m365", type: "STREAMABLE_HTTP", url: INTERNAL_URL }),
    );
    await runWithCallerContext(
      { authMethod: "oauth", userId: "caller-binding-user" },
      () =>
        runWithM365UserContext({ userId: "m365-user" }, () =>
          installedFetch(transport)(new URL(INTERNAL_URL), toolCallInit(SPOOF)),
        ),
    );
    expect(seen).toHaveLength(1);
    expect(seen[0].userId).toBe("m365-user");
    expect(seen[0].authorization).toBe("Bearer graph-m365-user");
    expect(getAccessToken).toHaveBeenCalledWith("m365-user");
  });

  it("m365 with no m365 user sends neither header, even inside a caller binding", async () => {
    const { transport } = createMetaMcpClient(
      asParams({ name: "m365", type: "STREAMABLE_HTTP", url: INTERNAL_URL }),
    );
    await runWithCallerContext(
      { authMethod: "api_key", userId: "caller-binding-user" },
      () =>
        installedFetch(transport)(new URL(INTERNAL_URL), toolCallInit(SPOOF)),
    );
    expect(seen).toHaveLength(1);
    expect(seen[0].userId).toBeNull();
    expect(seen[0].authorization).toBeNull();
    expect(getAccessToken).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// X-Umbrella-Caller on the pooled transports.
// ---------------------------------------------------------------------------

const KEY_ONE = "00000000-0000-4000-8000-0000000000a1";
const KEY_TWO = "00000000-0000-4000-8000-0000000000a2";
const CLIENT_ONE = "mcp_client_one";
const CLIENT_TWO = "mcp_client_two";
const SUPPLIED_BOTH = {
  "X-Umbrella-User-Id": "user-supplied",
  "X-Umbrella-Caller": "v1.c3VwcGxpZWQ",
};

/** The identifying pair a backend would read from a recorded request. */
function pairSeen(r: SeenRequest): string | null {
  if (r.caller === null) return null;
  const payload = JSON.parse(
    Buffer.from(r.caller.replace(/^v1\./, ""), "base64url").toString("utf8"),
  ) as { uid: string; cred: string };
  // The two headers are set from one binding, so they always agree.
  expect(payload.uid).toBe(r.userId);
  return `${payload.uid} ${payload.cred}`;
}

describe("X-Umbrella-Caller on a named backend", () => {
  it("two callers on one pooled connection each carry their own caller header", async () => {
    const { client, transport } = createMetaMcpClient(
      asParams({
        type: "STREAMABLE_HTTP",
        url: INTERNAL_URL,
        headers: SUPPLIED_BOTH,
      }),
    );
    if (!client || !transport) throw new Error("no client built");

    // Connected outside any caller scope, as the pool's idle warm-up does:
    // one backend session serves every call below.
    await client.connect(transport);
    await client.listTools();

    const call = (toolName: string, caller: Record<string, string>) =>
      runWithCallerContext(caller, () =>
        client.callTool({ name: toolName, arguments: {} }),
      );
    const results = await Promise.all([
      call("key-one", {
        authMethod: "api_key",
        userId: "user-1",
        apiKeyUuid: KEY_ONE,
      }),
      call("key-two-same-user", {
        authMethod: "api_key",
        userId: "user-1",
        apiKeyUuid: KEY_TWO,
      }),
      call("acts-as", {
        authMethod: "api_key",
        userId: "user-admin",
        actsAsUserId: "user-2",
        apiKeyUuid: KEY_ONE,
      }),
      call("oauth-one", {
        authMethod: "oauth",
        userId: "user-1",
        oauthClientId: CLIENT_ONE,
      }),
      call("oauth-two-same-user", {
        authMethod: "oauth",
        userId: "user-1",
        oauthClientId: CLIENT_TWO,
      }),
      call("oauth-no-client", { authMethod: "oauth", userId: "user-1" }),
      call("ownerless-key", { authMethod: "api_key", apiKeyUuid: KEY_ONE }),
    ]);
    for (const result of results) expect(result.isError).toBeFalsy();
    await client.callTool({ name: "no-scope", arguments: {} });

    const calls = seen.filter((r) => r.rpcMethod === "tools/call");
    expect(
      Object.fromEntries(calls.map((r) => [r.toolName, pairSeen(r)])),
    ).toEqual({
      "key-one": `user-1 api_key:${KEY_ONE}`,
      "key-two-same-user": `user-1 api_key:${KEY_TWO}`,
      "acts-as": `user-2 api_key:${KEY_ONE}`,
      "oauth-one": `user-1 oauth:${CLIENT_ONE}`,
      "oauth-two-same-user": `user-1 oauth:${CLIENT_TWO}`,
      // The user id still goes; the structured header needs a credential.
      "oauth-no-client": null,
      "ownerless-key": null,
      "no-scope": null,
    });
    expect(calls.find((r) => r.toolName === "oauth-no-client")?.userId).toBe(
      "user-1",
    );
    // The handshake and the listing carry neither header, and the stored
    // values reached the backend on no request at all.
    for (const r of seen.filter((r) => r.rpcMethod !== "tools/call")) {
      expect([r.httpMethod, r.rpcMethod, r.caller]).toEqual([
        r.httpMethod,
        r.rpcMethod,
        null,
      ]);
    }
    expect(
      seen.some((r) => r.caller === SUPPLIED_BOTH["X-Umbrella-Caller"]),
    ).toBe(false);
    expect(seen.some((r) => r.userId === "user-supplied")).toBe(false);

    await client.close();
  });

  it("a cold connect inside a caller's scope sends no caller header on the handshake or the listing", async () => {
    const { client, transport } = createMetaMcpClient(
      asParams({ type: "STREAMABLE_HTTP", url: INTERNAL_URL }),
    );
    if (!client || !transport) throw new Error("no client built");
    try {
      await runWithCallerContext(
        { authMethod: "api_key", userId: "user-one", apiKeyUuid: KEY_ONE },
        async () => {
          await client.connect(transport);
          await client.listTools();
          await client.callTool({ name: "first", arguments: {} });
        },
      );
      await runWithCallerContext(
        { authMethod: "api_key", userId: "user-two", apiKeyUuid: KEY_TWO },
        () => client.callTool({ name: "second", arguments: {} }),
      );

      for (const r of seen.filter((r) => r.rpcMethod !== "tools/call")) {
        expect(r.caller).toBeNull();
      }
      expect(
        seen
          .filter((r) => r.rpcMethod === "tools/call")
          .map((r) => [r.toolName, pairSeen(r)]),
      ).toEqual([
        ["first", `user-one api_key:${KEY_ONE}`],
        ["second", `user-two api_key:${KEY_TWO}`],
      ]);
    } finally {
      await client.close();
    }
  });

  it("SSE: the back-channel tool call carries the caller header and replaces a supplied value", async () => {
    const { transport } = createMetaMcpClient(
      asParams({ type: "SSE", url: INTERNAL_SSE_URL }),
    );
    await runWithCallerContext(
      { authMethod: "oauth", userId: "user-1", oauthClientId: CLIENT_ONE },
      () =>
        installedFetch(transport)(
          new URL("http://10.0.0.5:3000/messages"),
          toolCallInit(SUPPLIED_BOTH),
        ),
    );
    expect(seen).toHaveLength(1);
    expect(pairSeen(seen[0])).toBe(`user-1 oauth:${CLIENT_ONE}`);
  });

  it("SSE: the stream GET carries no caller header and drops a stored value", async () => {
    const { transport } = createMetaMcpClient(
      asParams({ type: "SSE", url: INTERNAL_SSE_URL, headers: SUPPLIED_BOTH }),
    );
    await runWithCallerContext(
      { authMethod: "oauth", userId: "user-1", oauthClientId: CLIENT_ONE },
      () => streamFetch(transport)(new URL(INTERNAL_SSE_URL), {}),
    );
    expect(seen).toHaveLength(1);
    expect(seen[0].caller).toBeNull();
    expect(seen[0].userId).toBeNull();
  });

  it("a named backend at a public address receives neither header", async () => {
    const { transport } = createMetaMcpClient(
      asParams({ type: "STREAMABLE_HTTP", url: PUBLIC_URL }),
    );
    await runWithCallerContext(
      { authMethod: "oauth", userId: "user-1", oauthClientId: CLIENT_ONE },
      () => installedFetch(transport)(new URL(PUBLIC_URL), toolCallInit()),
    );
    expect(seen).toHaveLength(1);
    expect([seen[0].userId, seen[0].caller]).toEqual([null, null]);
  });

  it.each([301, 302, 303])(
    "drops both headers when a same-origin %i rewrites the tool POST to GET",
    async (status) => {
      const record = undiciFetch.getMockImplementation();
      if (!record) throw new Error("no recording fetch installed");
      undiciFetch.mockImplementationOnce(async (url, init) => {
        await record(url, init);
        return new Response(null, {
          status,
          headers: { location: "/redirected" },
        });
      });
      const { transport } = createMetaMcpClient(
        asParams({ type: "STREAMABLE_HTTP", url: INTERNAL_URL }),
      );
      await runWithCallerContext(
        { authMethod: "oauth", userId: "user-1", oauthClientId: CLIENT_ONE },
        () => installedFetch(transport)(new URL(INTERNAL_URL), toolCallInit()),
      );
      expect(seen.map((r) => [r.httpMethod, pairSeen(r)])).toEqual([
        ["POST", `user-1 oauth:${CLIENT_ONE}`],
        ["GET", null],
      ]);
      expect(seen[1].userId).toBeNull();
    },
  );

  it.each([307, 308])(
    "keeps both headers when a same-origin %i replays the same tool POST",
    async (status) => {
      const record = undiciFetch.getMockImplementation();
      if (!record) throw new Error("no recording fetch installed");
      undiciFetch.mockImplementationOnce(async (url, init) => {
        await record(url, init);
        return new Response(null, {
          status,
          headers: { location: "/redirected" },
        });
      });
      const { transport } = createMetaMcpClient(
        asParams({ type: "STREAMABLE_HTTP", url: INTERNAL_URL }),
      );
      await runWithCallerContext(
        { authMethod: "oauth", userId: "user-1", oauthClientId: CLIENT_ONE },
        () => installedFetch(transport)(new URL(INTERNAL_URL), toolCallInit()),
      );
      expect(seen.map((r) => [r.httpMethod, pairSeen(r)])).toEqual([
        ["POST", `user-1 oauth:${CLIENT_ONE}`],
        ["POST", `user-1 oauth:${CLIENT_ONE}`],
      ]);
    },
  );
});

describe("X-Umbrella-Caller: backends that are not named get none from the caller binding", () => {
  it("an unnamed backend gets no caller header from the caller binding", async () => {
    const { transport } = createMetaMcpClient(
      asParams({ name: "other", type: "STREAMABLE_HTTP", url: INTERNAL_URL }),
    );
    await runWithCallerContext(
      { authMethod: "oauth", userId: "user-1", oauthClientId: CLIENT_ONE },
      () => installedFetch(transport)(new URL(INTERNAL_URL), toolCallInit()),
    );
    expect(seen[0].caller).toBeNull();
  });

  it("m365 never gets the caller header from the caller binding", async () => {
    const { transport } = createMetaMcpClient(
      asParams({ name: "m365", type: "STREAMABLE_HTTP", url: INTERNAL_URL }),
    );
    await runWithCallerContext(
      { authMethod: "oauth", userId: "user-1", oauthClientId: CLIENT_ONE },
      () =>
        runWithM365UserContext({ userId: "m365-user" }, () =>
          installedFetch(transport)(new URL(INTERNAL_URL), toolCallInit()),
        ),
    );
    expect(seen).toHaveLength(1);
    expect(seen[0].userId).toBe("m365-user");
    expect(seen[0].caller).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Stored identity headers, on every server.
// ---------------------------------------------------------------------------

/**
 * A row that stores both identity headers, in mixed casing, beside an
 * unrelated custom header. The custom header must still be sent; the two
 * stored identity values must never be.
 */
const STORED_WITH_IDENTITY = {
  "x-UMBRELLA-user-id": "user-stored",
  "X-UMBRELLA-CALLER": "v1.c3RvcmVk",
  "X-Custom-Tenant": "tenant-a",
};

const TOOL_CALL = {
  jsonrpc: "2.0",
  id: 7,
  method: "tools/call",
  params: { name: "ask", arguments: {} },
} as const;

/**
 * Answer the next request (the SSE stream GET) with an open event stream that
 * names the message endpoint, recording it like any other request.
 */
function answerNextWithSseEndpoint(): void {
  const record = undiciFetch.getMockImplementation();
  if (!record) throw new Error("no recording fetch installed");
  undiciFetch.mockImplementationOnce(async (url, init) => {
    await record(url, init);
    return new Response(
      new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(
            new TextEncoder().encode("event: endpoint\ndata: /messages\n\n"),
          );
        },
      }),
      { status: 200, headers: { "content-type": "text/event-stream" } },
    );
  });
}

interface ExpectedToolCall {
  userId: string | null;
  pair: string | null;
  authorization: string | null;
}

describe("a stored X-Umbrella-User-Id or X-Umbrella-Caller never reaches a backend, whatever the row's name", () => {
  it.each<[string, string, "STREAMABLE_HTTP" | "SSE", ExpectedToolCall]>([
    [
      "an unnamed server",
      "other",
      "STREAMABLE_HTTP",
      { userId: null, pair: null, authorization: null },
    ],
    [
      "an unnamed server",
      "other",
      "SSE",
      { userId: null, pair: null, authorization: null },
    ],
    [
      "a named server",
      "team",
      "STREAMABLE_HTTP",
      {
        userId: "user-1",
        pair: `user-1 oauth:${CLIENT_ONE}`,
        authorization: null,
      },
    ],
    [
      "a named server",
      "team",
      "SSE",
      {
        userId: "user-1",
        pair: `user-1 oauth:${CLIENT_ONE}`,
        authorization: null,
      },
    ],
    [
      "the m365 server",
      "m365",
      "STREAMABLE_HTTP",
      {
        userId: "m365-user",
        pair: null,
        authorization: "Bearer graph-m365-user",
      },
    ],
  ])(
    "%s (%s) over %s sends only what the gateway sets, and the row's other headers",
    async (_label, name, type, expected) => {
      if (type === "SSE") answerNextWithSseEndpoint();
      const { transport } = createMetaMcpClient(
        asParams({
          name,
          type,
          url: type === "SSE" ? INTERNAL_SSE_URL : INTERNAL_URL,
          headers: STORED_WITH_IDENTITY,
        }),
      );
      if (!transport) throw new Error("no transport built");

      // The real SDK transport builds every request from the row: the SSE
      // stream GET, then the tool call, with the stored headers merged in by
      // the SDK itself rather than by this test.
      await transport.start();
      try {
        await runWithCallerContext(
          { authMethod: "oauth", userId: "user-1", oauthClientId: CLIENT_ONE },
          () =>
            runWithM365UserContext({ userId: "m365-user" }, () =>
              transport.send(TOOL_CALL),
            ),
        );
      } finally {
        await transport.close();
      }

      expect(seen.map((r) => r.httpMethod)).toEqual(
        type === "SSE" ? ["GET", "POST"] : ["POST"],
      );
      for (const r of seen) {
        expect(r.custom).toBe("tenant-a");
        expect(r.userId).not.toBe("user-stored");
        expect(r.caller).not.toBe("v1.c3RvcmVk");
      }
      const streamGet = seen.find((r) => r.httpMethod === "GET");
      if (streamGet) {
        expect([streamGet.userId, streamGet.caller]).toEqual([null, null]);
      }
      const toolCall = seen.find((r) => r.rpcMethod === "tools/call");
      if (!toolCall) throw new Error("the tool call was not sent");
      expect({
        userId: toolCall.userId,
        pair: pairSeen(toolCall),
        authorization: toolCall.authorization,
      }).toEqual(expected);
    },
  );
});
