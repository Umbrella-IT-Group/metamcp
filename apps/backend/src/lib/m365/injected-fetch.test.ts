/**
 * THE INJECTION INVARIANT (design doc §4.2): the gateway only ever
 * injects genuine Graph-scoped tokens minted for the request's own
 * user, never forwards the inbound consumer credential, and sends no
 * Authorization at all when no user context exists. These tests are
 * the unit-tested guarantee the design doc references.
 *
 * Invariant 5 (below): a token is minted only for a request that can
 * execute a tool. Every other protocol request (handshake, listings,
 * the standing GET stream, the session DELETE) leaves with no
 * credential and no user-id header, so a user's grant state can never
 * fail a connect, a listing or a teardown.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";

// injected-fetch imports the mint service, whose default repo import
// pulls in the drizzle client (hard-requires DATABASE_URL at module
// load). All tests here inject mint stubs — mock the db module away.
vi.mock("../../db/index", () => ({ db: {} }));

import { M365BrokerError } from "./errors";
import {
  makeM365InjectedFetch,
  requestNeedsUserToken,
  USER_ID_HEADER,
} from "./injected-fetch";
import type { M365MintService } from "./mint-service";
import { runWithM365UserContext } from "./request-context";

function makeMintStub(result: string | Error) {
  return {
    getAccessToken: vi.fn(async (_userId: string) => {
      if (result instanceof Error) throw result;
      return result;
    }),
  } as unknown as M365MintService;
}

function makeBaseFetch() {
  const seen: { url: string; headers: Headers }[] = [];
  const baseFetch = vi.fn(async (url: string | URL, init?: RequestInit) => {
    seen.push({ url: String(url), headers: new Headers(init?.headers) });
    return new Response("{}", { status: 200 });
  });
  return { baseFetch, seen };
}

/** A JSON-RPC message body, as the SDK transport serializes one. */
function rpc(method: string, id?: number): string {
  return JSON.stringify({
    jsonrpc: "2.0",
    ...(id === undefined ? {} : { id }),
    method,
    params: {},
  });
}

/** A POST init the way the SDK transport builds one for a message. */
function post(body: unknown, headers?: RequestInit["headers"]): RequestInit {
  return {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...Object.fromEntries(new Headers(headers)),
    },
    body: body as RequestInit["body"],
  };
}

/** The one request kind that can execute a tool. */
const toolsCall = (headers?: RequestInit["headers"]) =>
  post(rpc("tools/call", 1), headers);

describe("m365 injected fetch — the injection invariant", () => {
  beforeEach(() => {
    vi.unstubAllEnvs();
  });

  it("invariant 3: no user context → NO Authorization header and no mint", async () => {
    const mint = makeMintStub("should-not-be-used");
    const { baseFetch, seen } = makeBaseFetch();
    const injected = makeM365InjectedFetch(mint, baseFetch);

    await injected("http://mcp-m365:3000/mcp", toolsCall());

    expect(mint.getAccessToken).not.toHaveBeenCalled();
    expect(seen[0].headers.has("authorization")).toBe(false);
    expect(seen[0].headers.has(USER_ID_HEADER)).toBe(false);
  });

  it("invariant 1: strips an inbound Authorization credential even without context", async () => {
    const mint = makeMintStub("unused");
    const { baseFetch, seen } = makeBaseFetch();
    const injected = makeM365InjectedFetch(mint, baseFetch);

    await injected(
      "http://mcp-m365:3000/mcp",
      toolsCall({ Authorization: "Bearer mcp_token_CONSUMER_CREDENTIAL" }),
    );

    expect(seen[0].headers.has("authorization")).toBe(false);
    // Non-credential headers survive untouched.
    expect(seen[0].headers.get("content-type")).toBe("application/json");
  });

  it("invariant 2: with context, injects exactly the token minted for that user", async () => {
    const mint = makeMintStub("graph-access-token-for-alex");
    const { baseFetch, seen } = makeBaseFetch();
    const injected = makeM365InjectedFetch(mint, baseFetch);

    await runWithM365UserContext({ userId: "user-alex" }, () =>
      injected(
        "http://mcp-m365:3000/mcp",
        toolsCall({ Authorization: "Bearer mcp_token_CONSUMER_CREDENTIAL" }),
      ),
    );

    expect(mint.getAccessToken).toHaveBeenCalledWith("user-alex");
    expect(seen[0].headers.get("authorization")).toBe(
      "Bearer graph-access-token-for-alex",
    );
    expect(seen[0].headers.get(USER_ID_HEADER)).toBe("user-alex");
  });

  it("invariant 2: the inbound consumer credential can never survive injection", async () => {
    const mint = makeMintStub("minted-token");
    const { baseFetch, seen } = makeBaseFetch();
    const injected = makeM365InjectedFetch(mint, baseFetch);

    await runWithM365UserContext({ userId: "u1" }, () =>
      injected(
        "http://mcp-m365:3000/mcp",
        toolsCall(
          new Headers({
            authorization: "Bearer mcp_token_SHOULD_DIE",
            [USER_ID_HEADER]: "spoofed-user",
            "x-test-header": "preserved",
          }),
        ),
      ),
    );

    const auth = seen[0].headers.get("authorization");
    expect(auth).toBe("Bearer minted-token");
    expect(auth).not.toContain("mcp_token_");
    expect(seen[0].headers.get(USER_ID_HEADER)).toBe("u1");
    expect(seen[0].headers.get("x-test-header")).toBe("preserved");
  });

  it("context propagates through async hops (awaits between wrap and dispatch)", async () => {
    const mint = makeMintStub("token-after-hops");
    const { baseFetch, seen } = makeBaseFetch();
    const injected = makeM365InjectedFetch(mint, baseFetch);

    await runWithM365UserContext({ userId: "hop-user" }, async () => {
      await new Promise((resolve) => setTimeout(resolve, 5));
      await new Promise((resolve) => setImmediate(resolve));
      await injected("http://mcp-m365:3000/mcp", toolsCall());
    });

    expect(seen[0].headers.get(USER_ID_HEADER)).toBe("hop-user");
  });

  it("invariant 4: a tools/call mint failure propagates as the typed broker error", async () => {
    const error = new M365BrokerError(
      "credential_missing",
      "No Microsoft 365 account is connected for your user yet.",
      "https://mcp.example.com/m365/enroll",
    );
    const mint = makeMintStub(error);
    const { baseFetch } = makeBaseFetch();
    const injected = makeM365InjectedFetch(mint, baseFetch);

    await expect(
      runWithM365UserContext({ userId: "u1" }, () =>
        injected("http://mcp-m365:3000/mcp", toolsCall()),
      ),
    ).rejects.toBe(error);
    expect(baseFetch).not.toHaveBeenCalled();
  });

  it("empty/partial context is treated as no context (fail-closed)", async () => {
    const mint = makeMintStub("unused");
    const { baseFetch, seen } = makeBaseFetch();
    const injected = makeM365InjectedFetch(mint, baseFetch);

    await runWithM365UserContext({ userId: "" }, () =>
      injected("http://mcp-m365:3000/mcp", toolsCall()),
    );

    expect(mint.getAccessToken).not.toHaveBeenCalled();
    expect(seen[0].headers.has("authorization")).toBe(false);
  });
});

const MCP_URL = "http://mcp-m365:3000/mcp";
const credentialMissing = () =>
  new M365BrokerError(
    "credential_missing",
    "No Microsoft 365 account is connected for your user yet.",
    "https://mcp.example.com/m365/enroll",
  );

describe("m365 injected fetch, invariant 5: a token is minted only for a request that can execute a tool", () => {
  // The user's grant is missing, so a mint would throw. Everything that is
  // not a tool execution must therefore still reach the backend, with nothing
  // user-specific on it: a grant problem can never fail a connect, a listing
  // or a teardown.
  const tokenFreeRequests: Array<[string, RequestInit]> = [
    ["initialize", post(rpc("initialize", 1))],
    ["notifications/initialized", post(rpc("notifications/initialized"))],
    ["notifications/cancelled", post(rpc("notifications/cancelled"))],
    ["ping", post(rpc("ping", 2))],
    ["tools/list", post(rpc("tools/list", 3))],
    ["prompts/list", post(rpc("prompts/list", 4))],
    ["resources/list", post(rpc("resources/list", 5))],
    ["resources/templates/list", post(rpc("resources/templates/list", 6))],
    [
      "a batch of listings and a notification",
      post(
        JSON.stringify([
          JSON.parse(rpc("tools/list", 7)),
          JSON.parse(rpc("notifications/initialized")),
        ]),
      ),
    ],
    ["the standing GET stream", { method: "GET" }],
    ["a GET with no init method", {}],
    ["HEAD", { method: "HEAD" }],
    ["OPTIONS", { method: "OPTIONS" }],
    ["the session DELETE", { method: "DELETE" }],
    ["a lowercase method name", { method: "delete" }],
  ];

  it.each(tokenFreeRequests)(
    "%s reaches the backend with no credential and no user id, and never asks for a token",
    async (_label, init) => {
      const mint = makeMintStub(credentialMissing());
      const { baseFetch, seen } = makeBaseFetch();
      const injected = makeM365InjectedFetch(mint, baseFetch);

      await runWithM365UserContext({ userId: "user-unenrolled" }, () =>
        injected(MCP_URL, {
          ...init,
          headers: {
            ...(init.headers as Record<string, string> | undefined),
            // The inbound consumer credential must still be stripped.
            Authorization: "Bearer mcp_token_CONSUMER_CREDENTIAL",
            [USER_ID_HEADER]: "spoofed-user",
            "mcp-session-id": "backend-session-1",
          },
        }),
      );

      expect(mint.getAccessToken).not.toHaveBeenCalled();
      expect(seen).toHaveLength(1);
      expect(seen[0].headers.has("authorization")).toBe(false);
      expect(seen[0].headers.has(USER_ID_HEADER)).toBe(false);
      // Everything else the transport put on the request survives.
      expect(seen[0].headers.get("mcp-session-id")).toBe("backend-session-1");
    },
  );

  it("tools/call mints a token for exactly that user", async () => {
    const mint = makeMintStub("graph-token-for-enrolled");
    const { baseFetch, seen } = makeBaseFetch();
    const injected = makeM365InjectedFetch(mint, baseFetch);

    await runWithM365UserContext({ userId: "user-enrolled" }, () =>
      injected(MCP_URL, post(rpc("tools/call", 9))),
    );

    expect(mint.getAccessToken).toHaveBeenCalledTimes(1);
    expect(mint.getAccessToken).toHaveBeenCalledWith("user-enrolled");
    expect(seen[0].headers.get("authorization")).toBe(
      "Bearer graph-token-for-enrolled",
    );
    expect(seen[0].headers.get(USER_ID_HEADER)).toBe("user-enrolled");
  });

  it("a tools/call for an unenrolled user throws the typed error before any byte leaves", async () => {
    const error = credentialMissing();
    const mint = makeMintStub(error);
    const { baseFetch } = makeBaseFetch();
    const injected = makeM365InjectedFetch(mint, baseFetch);

    await expect(
      runWithM365UserContext({ userId: "user-unenrolled" }, () =>
        injected(MCP_URL, post(rpc("tools/call", 10))),
      ),
    ).rejects.toBe(error);
    expect(baseFetch).not.toHaveBeenCalled();
  });

  it("a batch that contains a tools/call mints", async () => {
    const mint = makeMintStub("graph-token");
    const { baseFetch, seen } = makeBaseFetch();
    const injected = makeM365InjectedFetch(mint, baseFetch);

    await runWithM365UserContext({ userId: "user-enrolled" }, () =>
      injected(
        MCP_URL,
        post(
          JSON.stringify([
            JSON.parse(rpc("tools/list", 1)),
            JSON.parse(rpc("tools/call", 2)),
          ]),
        ),
      ),
    );

    expect(mint.getAccessToken).toHaveBeenCalledWith("user-enrolled");
    expect(seen[0].headers.get("authorization")).toBe("Bearer graph-token");
  });

  const failClosedRequests: Array<[string, RequestInit]> = [
    ["an unparseable body", post("{not json")],
    ["a non-string body", post(new TextEncoder().encode(rpc("tools/list", 1)))],
    ["no body", { method: "POST" }],
    ["a null body", post(null)],
    ["a JSON null", post("null")],
    ["a JSON number", post("42")],
    ["an empty batch", post("[]")],
    [
      "a response-shaped message with no method",
      post(JSON.stringify({ jsonrpc: "2.0", id: 1, result: {} })),
    ],
    [
      "a message whose method is not a string",
      post(JSON.stringify({ jsonrpc: "2.0", id: 1, method: 7 })),
    ],
    ["an unknown method", post(rpc("something/else", 1))],
    ["resources/read", post(rpc("resources/read", 1))],
    ["prompts/get", post(rpc("prompts/get", 1))],
    ["completion/complete", post(rpc("completion/complete", 1))],
    [
      "a method that only resembles a notification",
      post(rpc("notificationsX")),
    ],
    [
      "a batch with one unknown method",
      post(`[${rpc("ping", 1)}, ${rpc("x/y", 2)}]`),
    ],
    ["a batch holding a non-object", post(`[${rpc("ping", 1)}, 3]`)],
    ["a PUT", { method: "PUT", body: rpc("tools/list", 1) }],
    ["a PATCH", { method: "PATCH", body: rpc("tools/list", 1) }],
    [
      "a tools/list body too large to be one",
      post(
        JSON.stringify({
          ...JSON.parse(rpc("tools/list", 1)),
          pad: "x".repeat(70_000),
        }),
      ),
    ],
  ];

  it.each(failClosedRequests)(
    "%s fails closed: it mints, as before",
    async (_label, init) => {
      const mint = makeMintStub("graph-token");
      const { baseFetch, seen } = makeBaseFetch();
      const injected = makeM365InjectedFetch(mint, baseFetch);

      await runWithM365UserContext({ userId: "user-enrolled" }, () =>
        injected(MCP_URL, init),
      );

      expect(mint.getAccessToken).toHaveBeenCalledTimes(1);
      expect(seen[0].headers.get("authorization")).toBe("Bearer graph-token");
      expect(seen[0].headers.get(USER_ID_HEADER)).toBe("user-enrolled");
    },
  );

  it("two interleaved users each get their own token on tools/call and none on tools/list", async () => {
    const mint = {
      getAccessToken: vi.fn(async (userId: string) => {
        // Yield so the two requests genuinely interleave.
        await new Promise((resolve) => setTimeout(resolve, 2));
        return `token-for-${userId}`;
      }),
    } as unknown as M365MintService;
    const { baseFetch, seen } = makeBaseFetch();
    const injected = makeM365InjectedFetch(mint, baseFetch);

    const asUser = (userId: string) => ({ userId });
    await Promise.all([
      runWithM365UserContext(asUser("user-a"), async () => {
        await injected(
          MCP_URL,
          post(rpc("tools/list", 1), { "x-test": "a-list" }),
        );
        await injected(
          MCP_URL,
          post(rpc("tools/call", 2), { "x-test": "a-call" }),
        );
      }),
      runWithM365UserContext(asUser("user-b"), async () => {
        await injected(
          MCP_URL,
          post(rpc("tools/call", 1), { "x-test": "b-call" }),
        );
        await injected(
          MCP_URL,
          post(rpc("tools/list", 2), { "x-test": "b-list" }),
        );
      }),
    ]);

    const byTag = Object.fromEntries(
      seen.map((s) => [s.headers.get("x-test"), s.headers]),
    );
    expect(byTag["a-list"].has("authorization")).toBe(false);
    expect(byTag["b-list"].has("authorization")).toBe(false);
    expect(byTag["a-list"].has(USER_ID_HEADER)).toBe(false);
    expect(byTag["b-list"].has(USER_ID_HEADER)).toBe(false);
    expect(byTag["a-call"].get("authorization")).toBe(
      "Bearer token-for-user-a",
    );
    expect(byTag["a-call"].get(USER_ID_HEADER)).toBe("user-a");
    expect(byTag["b-call"].get("authorization")).toBe(
      "Bearer token-for-user-b",
    );
    expect(byTag["b-call"].get(USER_ID_HEADER)).toBe("user-b");
    // Exactly one mint per tool execution, none for a listing.
    expect(mint.getAccessToken).toHaveBeenCalledTimes(2);
  });

  it("a request with no user context sends no credential whatever it is", async () => {
    const mint = makeMintStub("unused");
    const { baseFetch, seen } = makeBaseFetch();
    const injected = makeM365InjectedFetch(mint, baseFetch);

    await injected(MCP_URL, post(rpc("tools/call", 1)));
    await injected(MCP_URL, post(rpc("tools/list", 2)));

    expect(mint.getAccessToken).not.toHaveBeenCalled();
    expect(seen.every((s) => !s.headers.has("authorization"))).toBe(true);
  });
});

describe("requestNeedsUserToken", () => {
  it("is true for the tool execution and every unclassifiable request", () => {
    expect(requestNeedsUserToken(post(rpc("tools/call", 1)))).toBe(true);
    expect(requestNeedsUserToken({ method: "POST" })).toBe(true);
    expect(requestNeedsUserToken(post("not json"))).toBe(true);
    expect(requestNeedsUserToken({ method: "PUT" })).toBe(true);
  });

  it("is false for the handshake, listings, notifications, the GET stream and the DELETE", () => {
    expect(requestNeedsUserToken(undefined)).toBe(false);
    expect(requestNeedsUserToken({})).toBe(false);
    expect(requestNeedsUserToken({ method: "DELETE" })).toBe(false);
    expect(requestNeedsUserToken(post(rpc("initialize", 1)))).toBe(false);
    expect(requestNeedsUserToken(post(rpc("tools/list", 1)))).toBe(false);
    expect(requestNeedsUserToken(post(rpc("notifications/anything")))).toBe(
      false,
    );
  });
});

describe("getInjectedFetchForServer wiring", () => {
  it("returns a fetch only for configured server names", async () => {
    vi.stubEnv("M365_INJECTED_SERVER_NAMES", "m365,m365-staging");
    const { getInjectedFetchForServer } = await import("./injected-fetch");
    expect(getInjectedFetchForServer("m365")).toBeDefined();
    expect(getInjectedFetchForServer("m365-staging")).toBeDefined();
    expect(getInjectedFetchForServer("m365-assistant")).toBeUndefined();
    expect(getInjectedFetchForServer("autotask")).toBeUndefined();
    vi.unstubAllEnvs();
  });

  it("defaults to exactly the `m365` server", async () => {
    vi.unstubAllEnvs();
    const { getInjectedFetchForServer } = await import("./injected-fetch");
    expect(getInjectedFetchForServer("m365")).toBeDefined();
    expect(getInjectedFetchForServer("m365-assistant")).toBeUndefined();
  });
});
