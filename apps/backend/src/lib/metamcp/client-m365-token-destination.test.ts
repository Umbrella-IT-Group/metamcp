/**
 * The per-user Microsoft Graph token that the m365 injection mints goes only
 * to an internal backend. A server row named in M365_INJECTED_SERVER_NAMES
 * whose URL points anywhere else gets no `Authorization`, no
 * `X-Umbrella-User-Id`, and causes no mint (lib/m365/injected-fetch.ts,
 * invariant 7). A server that is not injected keeps sending its configured
 * bearer wherever its row points, as before.
 *
 * Everything here is the production wiring: the real `createMetaMcpClient`,
 * the real SDK StreamableHTTPClientTransport and its real `send()`, the real
 * guarded fetch. Only the socket (undici) and the Entra mint are replaced, so
 * nothing leaves this process. Destinations are IP literals, so no resolver
 * runs. Guard-level cases (resolved names, mixed answers, the allowlist,
 * redirects) are in lib/m365/injected-fetch.destination.test.ts.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { undiciFetch, getAccessToken } = vi.hoisted(() => ({
  // 202 Accepted with no body: the SDK's send() returns without reading more.
  undiciFetch: vi.fn(
    async (_url: unknown, _init?: unknown) =>
      new Response(null, { status: 202 }),
  ),
  getAccessToken: vi.fn(async (userId: string) => `graph-token-for-${userId}`),
}));
vi.mock("undici", () => ({
  fetch: undiciFetch,
  Agent: class {
    constructor(..._args: unknown[]) {}
  },
}));

vi.mock("../m365/mint-service", () => ({
  m365MintService: { getAccessToken },
  M365MintService: class {},
}));

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

import logger from "@/utils/logger";

import { M365BrokerError } from "../m365/errors";
import { runWithM365UserContext } from "../m365/request-context";
import { runWithCallerContext } from "./caller-context-store";
import { createMetaMcpClient } from "./client";

const SECRET = "test-gateway-secret-0123456789abcdef0123";
// TEST-NET-3 (RFC 5737): a public, non-internal address by the guard's table.
const EXTERNAL_URL = "http://203.0.113.10:8443/mcp";
const INTERNAL_URL = "http://10.0.0.5:3000/mcp";
// The cloud metadata range: refused by the guard before any request.
const METADATA_URL = "http://169.254.169.254/mcp";

const saved = {
  secret: process.env.GATEWAY_BACKEND_SECRET,
  injected: process.env.M365_INJECTED_SERVER_NAMES,
  verified: process.env.VERIFIED_CALLER_SERVER_NAMES,
  transform: process.env.TRANSFORM_LOCALHOST_TO_DOCKER_INTERNAL,
};

const serverRow = (name: string, url: string, bearerToken?: string) =>
  ({
    uuid: "11111111-1111-4111-8111-111111111111",
    name,
    description: "",
    status: "active",
    created_at: new Date().toISOString(),
    type: "STREAMABLE_HTTP",
    url,
    ...(bearerToken ? { bearerToken } : {}),
  }) as never;

const toolCall = {
  jsonrpc: "2.0" as const,
  id: 1,
  method: "tools/call",
  params: { name: "mail_search", arguments: { query: "status" } },
};

/** Send one tools/call as `userId` through the real transport. */
async function sendAs(
  userId: string,
  row: ReturnType<typeof serverRow>,
): Promise<void> {
  const { transport } = createMetaMcpClient(row);
  if (!transport) throw new Error("no transport built");
  await transport.start();
  await runWithCallerContext(
    { userId, authMethod: "oauth", assertedActor: `${userId}@example.test` },
    () => runWithM365UserContext({ userId }, () => transport.send(toolCall)),
  );
}

/** The headers of the n-th request that reached the socket. */
const sentHeaders = (n = 0): Headers => {
  const [, init] = undiciFetch.mock.calls[n] as [URL, { headers: Headers }];
  return init.headers;
};

beforeEach(() => {
  undiciFetch.mockClear();
  getAccessToken.mockReset();
  getAccessToken.mockImplementation(
    async (userId: string) => `graph-token-for-${userId}`,
  );
  vi.mocked(logger.warn).mockClear();
  process.env.GATEWAY_BACKEND_SECRET = SECRET;
  delete process.env.M365_INJECTED_SERVER_NAMES; // production default: "m365"
  delete process.env.VERIFIED_CALLER_SERVER_NAMES;
  delete process.env.TRANSFORM_LOCALHOST_TO_DOCKER_INTERNAL;
});

afterEach(() => {
  const restore = (name: string, value: string | undefined) => {
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  };
  restore("GATEWAY_BACKEND_SECRET", saved.secret);
  restore("M365_INJECTED_SERVER_NAMES", saved.injected);
  restore("VERIFIED_CALLER_SERVER_NAMES", saved.verified);
  restore("TRANSFORM_LOCALHOST_TO_DOCKER_INTERNAL", saved.transform);
});

describe("the m365 Graph token goes only to an internal backend", () => {
  it("an internal m365 backend gets the caller's token, user id and the gateway secret", async () => {
    await sendAs("user-a", serverRow("m365", INTERNAL_URL));
    expect(undiciFetch).toHaveBeenCalledTimes(1);
    expect(String(undiciFetch.mock.calls[0][0])).toBe(INTERNAL_URL);
    const headers = sentHeaders();
    expect(headers.get("authorization")).toBe("Bearer graph-token-for-user-a");
    expect(headers.get("x-umbrella-user-id")).toBe("user-a");
    expect(headers.get("x-gateway-auth")).toBe(SECRET);
    expect(getAccessToken).toHaveBeenCalledTimes(1);
    expect(getAccessToken).toHaveBeenCalledWith("user-a");
  });

  it("an m365 row pointed at a public address gets no token, no user id, and nothing is minted", async () => {
    await sendAs("user-a", serverRow("m365", EXTERNAL_URL));
    expect(undiciFetch).toHaveBeenCalledTimes(1);
    expect(String(undiciFetch.mock.calls[0][0])).toBe(EXTERNAL_URL);
    const headers = sentHeaders();
    expect(headers.get("authorization")).toBeNull();
    expect(headers.get("x-umbrella-user-id")).toBeNull();
    expect(headers.get("x-gateway-auth")).toBeNull();
    expect(headers.get("x-mcp-actor")).toBeNull();
    expect(getAccessToken).not.toHaveBeenCalled();
    expect(logger.warn).toHaveBeenCalledWith(
      expect.stringContaining("M365 user token withheld"),
    );
  });

  it("an m365 row pointed at a public address sends no token even when minting would fail", async () => {
    getAccessToken.mockRejectedValue(
      new M365BrokerError("credential_missing", "not enrolled"),
    );
    await sendAs("user-a", serverRow("m365", EXTERNAL_URL));
    expect(getAccessToken).not.toHaveBeenCalled();
    expect(sentHeaders().get("authorization")).toBeNull();
  });

  it("a stored bearer on an m365 row is not sent to a public address either", async () => {
    await sendAs(
      "user-a",
      serverRow("m365", EXTERNAL_URL, "stored-row-bearer-value"),
    );
    expect(sentHeaders().get("authorization")).toBeNull();
    expect(getAccessToken).not.toHaveBeenCalled();
  });

  it("any server named for injection is held to the same rule", async () => {
    process.env.M365_INJECTED_SERVER_NAMES = "m365,m365-staging";
    await sendAs("user-a", serverRow("m365-staging", EXTERNAL_URL));
    expect(sentHeaders().get("authorization")).toBeNull();
    expect(getAccessToken).not.toHaveBeenCalled();
  });

  it("a metadata-range destination is refused before any request or mint", async () => {
    await expect(
      sendAs("user-a", serverRow("m365", METADATA_URL)),
    ).rejects.toThrow();
    expect(undiciFetch).not.toHaveBeenCalled();
    expect(getAccessToken).not.toHaveBeenCalled();
  });

  it("two concurrent callers each get only their own token", async () => {
    await Promise.all([
      sendAs("user-a", serverRow("m365", INTERNAL_URL)),
      sendAs("user-b", serverRow("m365", INTERNAL_URL)),
    ]);
    const seen = undiciFetch.mock.calls.map(
      ([, init]) =>
        [
          (init as { headers: Headers }).headers.get("x-umbrella-user-id"),
          (init as { headers: Headers }).headers.get("authorization"),
        ] as const,
    );
    expect(seen).toHaveLength(2);
    for (const [userId, authorization] of seen) {
      expect(authorization).toBe(`Bearer graph-token-for-${userId}`);
    }
    expect(new Set(seen.map(([userId]) => userId))).toEqual(
      new Set(["user-a", "user-b"]),
    );
  });
});

describe("a server that is not injected keeps its configured credential", () => {
  it("its stored bearer still reaches a public destination", async () => {
    await sendAs(
      "user-a",
      serverRow("vendor-api", EXTERNAL_URL, "vendor-bearer-value"),
    );
    const headers = sentHeaders();
    expect(headers.get("authorization")).toBe("Bearer vendor-bearer-value");
    expect(headers.get("x-umbrella-user-id")).toBeNull();
    expect(getAccessToken).not.toHaveBeenCalled();
  });
});
