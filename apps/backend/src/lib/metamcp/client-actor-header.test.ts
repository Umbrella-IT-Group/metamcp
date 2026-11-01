/**
 * The caller-asserted `X-MCP-Actor` on the POOLED data-plane transports.
 *
 * The defect this pins: fork #139 forwarded the header only on the admin
 * Inspector proxy (`routers/mcp-proxy/server.ts`). Operator clients connect to
 * the public endpoints, whose tool calls go through the pooled client built by
 * `createMetaMcpClient`, and that path forwarded no inbound header, so a
 * backend reading it could record fallback attribution although the client
 * sent the header on every request.
 *
 * Driven through the production wiring: `createMetaMcpClient` builds the
 * transports, undici is mocked as the network, and every URL is an IP literal
 * so no resolver is touched. The last case runs a real SDK `Client` over the
 * pooled transport against a fake Streamable-HTTP backend behind the mock.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

interface SeenRequest {
  url: string;
  httpMethod: string;
  rpcMethod?: string;
  toolName?: string;
  actor: string | null;
  authorization: string | null;
}

// `vi.mock` is hoisted above module-scope consts, so the fake network is
// created through `vi.hoisted` to be reachable inside the factory and in tests.
const { undiciFetch, seen } = vi.hoisted(() => {
  const seen: SeenRequest[] = [];
  const json = (body: unknown, extra: Record<string, string> = {}) =>
    new Response(JSON.stringify(body), {
      status: 200,
      headers: { "content-type": "application/json", ...extra },
    });
  // A minimal stateful Streamable-HTTP MCP backend that records the actor
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
      actor: headers.get("x-mcp-actor"),
      authorization: headers.get("authorization"),
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
      case "tools/call":
        return json({
          jsonrpc: "2.0",
          id: message.id,
          result: { content: [{ type: "text", text: "ok" }] },
        });
      case undefined:
        return new Response("ok", { status: 200 });
      default:
        // notifications/initialized and the rest: accepted, no body.
        return new Response(null, { status: 202 });
    }
  });
  return { undiciFetch, seen };
});
vi.mock("undici", () => ({
  fetch: undiciFetch,
  Agent: class {
    constructor(..._args: unknown[]) {}
  },
}));

// client.ts's module-load chain reaches db/index (which throws on a missing
// DATABASE_URL); stub it out to keep this a pure unit test, matching
// client-gateway-header.test.ts.
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

import { runWithCallerContext } from "./caller-context-store";
import { createMetaMcpClient } from "./client";

const ACTOR = "tech.one@example.com";
const INTERNAL_URL = "http://10.0.0.5:3000/mcp";
const INTERNAL_SSE_URL = "http://10.0.0.5:3000/sse";
const PUBLIC_URL = "http://93.184.216.34:3000/mcp";
const ORIGINAL_TRANSFORM = process.env.TRANSFORM_LOCALHOST_TO_DOCKER_INTERNAL;

const asParams = (over: Record<string, unknown>) =>
  ({
    uuid: "srv-uuid",
    name: "some-server",
    description: "",
    status: "active",
    created_at: new Date().toISOString(),
    ...over,
  }) as never;

type InstalledFetch = (url: URL, init?: RequestInit) => Promise<Response>;

/** The request fetch each transport was built with (an SDK private, as in client.test.ts). */
const installedFetch = (transport: unknown): InstalledFetch =>
  (transport as { _fetch: InstalledFetch })._fetch;

/** The SSE transport's stream fetch (`eventSourceInit.fetch`). */
const streamFetch = (transport: unknown): InstalledFetch =>
  (transport as { _eventSourceInit: { fetch: InstalledFetch } })
    ._eventSourceInit.fetch;

beforeEach(() => {
  undiciFetch.mockClear();
  seen.length = 0;
  // Leave IP literals exactly as written so the guard resolves no name.
  delete process.env.TRANSFORM_LOCALHOST_TO_DOCKER_INTERNAL;
});

afterEach(() => {
  if (ORIGINAL_TRANSFORM === undefined) {
    delete process.env.TRANSFORM_LOCALHOST_TO_DOCKER_INTERNAL;
  } else {
    process.env.TRANSFORM_LOCALHOST_TO_DOCKER_INTERNAL = ORIGINAL_TRANSFORM;
  }
});

describe("X-MCP-Actor on the pooled transports", () => {
  it("STREAMABLE_HTTP: a request made for a caller carries that caller's actor", async () => {
    const { transport } = createMetaMcpClient(
      asParams({ name: "s1", type: "STREAMABLE_HTTP", url: INTERNAL_URL }),
    );
    await runWithCallerContext({ assertedActor: ACTOR }, () =>
      installedFetch(transport)(new URL(INTERNAL_URL), {
        headers: { authorization: "Bearer row" },
      }),
    );
    expect(seen).toHaveLength(1);
    expect(seen[0].actor).toBe(ACTOR);
    expect(seen[0].authorization).toBe("Bearer row");
  });

  it("SSE: the back-channel POST carries the caller's actor", async () => {
    const { transport } = createMetaMcpClient(
      asParams({ name: "s2", type: "SSE", url: INTERNAL_SSE_URL }),
    );
    await runWithCallerContext({ assertedActor: ACTOR }, () =>
      installedFetch(transport)(new URL("http://10.0.0.5:3000/messages"), {
        method: "POST",
        headers: { authorization: "Bearer row" },
      }),
    );
    expect(seen).toHaveLength(1);
    expect(seen[0].actor).toBe(ACTOR);
  });

  it("SSE: the stream fetch goes through the same wrapper, so a stored value cannot ride it", async () => {
    const { transport } = createMetaMcpClient(
      asParams({
        name: "s3",
        type: "SSE",
        url: INTERNAL_SSE_URL,
        headers: { "X-MCP-Actor": "stored@example.com" },
      }),
    );
    await streamFetch(transport)(new URL(INTERNAL_SSE_URL), {});
    expect(seen).toHaveLength(1);
    expect(seen[0].actor).toBeNull();
  });

  it("STREAMABLE_HTTP: a request outside any caller scope carries no actor", async () => {
    const { transport } = createMetaMcpClient(
      asParams({ name: "s4", type: "STREAMABLE_HTTP", url: INTERNAL_URL }),
    );
    await installedFetch(transport)(new URL(INTERNAL_URL), {});
    expect(seen).toHaveLength(1);
    expect(seen[0].actor).toBeNull();
  });

  it("STREAMABLE_HTTP: a public backend never receives the actor", async () => {
    const { transport } = createMetaMcpClient(
      asParams({ name: "s5", type: "STREAMABLE_HTTP", url: PUBLIC_URL }),
    );
    await runWithCallerContext({ assertedActor: ACTOR }, () =>
      installedFetch(transport)(new URL(PUBLIC_URL), {}),
    );
    expect(seen).toHaveLength(1);
    expect(seen[0].actor).toBeNull();
  });

  it("STREAMABLE_HTTP: an M365-injected server still gets the actor, beside its own fetch", async () => {
    // `m365` is in the default injected-server set, so this transport's fetch
    // is the actor wrapper over the injected fetch over the guarded fetch. A
    // GET mints nothing (injected-fetch invariant 5), so no broker is needed.
    const { transport } = createMetaMcpClient(
      asParams({ name: "m365", type: "STREAMABLE_HTTP", url: INTERNAL_URL }),
    );
    await runWithCallerContext({ assertedActor: ACTOR }, () =>
      installedFetch(transport)(new URL(INTERNAL_URL), { method: "GET" }),
    );
    expect(seen).toHaveLength(1);
    expect(seen[0].actor).toBe(ACTOR);
    expect(seen[0].authorization).toBeNull();
  });

  it("a real SDK client on one pooled connection: each tool call carries its own caller's actor", async () => {
    const { client, transport } = createMetaMcpClient(
      asParams({ name: "s6", type: "STREAMABLE_HTTP", url: INTERNAL_URL }),
    );
    if (!client || !transport) throw new Error("no client built");

    // Connected outside any caller scope, as the pool's idle warm-up does.
    await client.connect(transport);

    // The tool name says which caller sent each call, so the assertion can
    // match every call to its own caller rather than only count the labels.
    const call = (toolName: string, assertedActor: string | undefined) =>
      runWithCallerContext({ apiKeyUuid: "k-1", assertedActor }, () =>
        client.callTool({ name: toolName, arguments: {} }),
      );
    const results = await Promise.all([
      call("for-tech-one", "tech.one@example.com"),
      call("for-tech-two", "tech.two@example.com"),
      call("for-nobody", undefined),
    ]);
    for (const result of results) expect(result.isError).toBeFalsy();

    const calls = seen.filter((r) => r.rpcMethod === "tools/call");
    expect(Object.fromEntries(calls.map((r) => [r.toolName, r.actor]))).toEqual(
      {
        "for-tech-one": "tech.one@example.com",
        "for-tech-two": "tech.two@example.com",
        "for-nobody": null,
      },
    );
    // The handshake ran in no caller's scope and names nobody.
    const init = seen.find((r) => r.rpcMethod === "initialize");
    expect(init?.actor).toBeNull();

    await client.close();
  });

  it("a cold connection's stream reconnect keeps its opening scope without labelling later tool calls", async () => {
    const { client, transport } = createMetaMcpClient(
      asParams({ name: "s7", type: "STREAMABLE_HTTP", url: INTERNAL_URL }),
    );
    if (!client || !transport) throw new Error("no client built");
    const network = undiciFetch.getMockImplementation();
    if (!network) throw new Error("no fake network");
    let getCount = 0;
    let resolveReconnect!: () => void;
    const reconnected = new Promise<void>((resolve) => {
      resolveReconnect = resolve;
    });
    undiciFetch.mockImplementation(async (url, init) => {
      const response = await network(url, init);
      if (init?.method === "GET") {
        getCount += 1;
        if (getCount === 1) {
          // A closed standalone stream makes the real SDK schedule a retry.
          return new Response("retry: 1\n\n", {
            headers: { "content-type": "text/event-stream" },
          });
        }
        resolveReconnect();
      }
      return response;
    });

    try {
      await runWithCallerContext({ assertedActor: ACTOR }, () =>
        client.connect(transport),
      );
      await reconnected;
      await runWithCallerContext(
        { assertedActor: "tech.two@example.com" },
        () => client.callTool({ name: "for-tech-two", arguments: {} }),
      );
      await runWithCallerContext({}, () =>
        client.callTool({ name: "for-nobody", arguments: {} }),
      );

      // Protocol traffic may retain the opening scope, so its actor must
      // never be cached by a backend as the owner of this pooled session.
      expect(seen.find((r) => r.rpcMethod === "initialize")?.actor).toBe(ACTOR);
      expect(
        seen.filter((r) => r.httpMethod === "GET").map((r) => r.actor),
      ).toEqual([ACTOR, ACTOR]);
      expect(
        seen.filter((r) => r.rpcMethod === "tools/call").map((r) => r.actor),
      ).toEqual(["tech.two@example.com", null]);
    } finally {
      await client.close();
      undiciFetch.mockImplementation(network);
    }
  });
});
