/**
 * Issuer binding for the upstream OAuth credentials the Inspector stores
 * (GHSA-6qxp-vccf-f47h, Dependabot alerts #154, #155, #170).
 *
 * The event this guards against: an upstream MCP server starts advertising a
 * different authorization server, and the Inspector's `auth()` (on a 401, or
 * at /fe-oauth/callback) posts the stored client_secret or refresh token to
 * that server's token endpoint. SDK 1.31 closes it by stamping `issuer` on
 * what it saves and refusing a mismatched stamp on read, but only if the stamp
 * survives the round trip through `oauth.upsert` and `oauth.get`; the shared
 * zod schemas used to strip it.
 *
 * What is real here: the SDK's `auth()`, this app's provider and callback
 * code, and the tRPC `oauth` router from @repo/trpc with its real input and
 * output schemas from @repo/zod-types (so dropping `issuer` from either schema
 * fails these tests). What is faked: the backend implementation behind the
 * router (an in-memory `oauth_sessions` table with the repository's merge
 * semantics), `fetch` (an upstream MCP server and two authorization servers
 * that record every request), and browser storage.
 */

import { auth } from "@modelcontextprotocol/sdk/client/auth.js";
import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  type MockInstance,
  vi,
} from "vitest";

const h = vi.hoisted(() => {
  type Row = {
    uuid: string;
    mcp_server_uuid: string;
    client_information: unknown;
    tokens: unknown;
    code_verifier: string | null;
    created_at: Date;
    updated_at: Date;
  };
  const rows = new Map<string, Row>();
  const serialize = (row: Row) => ({
    ...row,
    created_at: row.created_at.toISOString(),
    updated_at: row.updated_at.toISOString(),
  });
  // Mirrors apps/backend/src/trpc/oauth.impl.ts over oauth-sessions.repo.ts:
  // only the fields present on the input are written, and a new row starts
  // from the column default for client_information.
  const impl = {
    get: async (input: { mcp_server_uuid: string }) => {
      const row = rows.get(input.mcp_server_uuid);
      if (!row) {
        return { success: false as const, message: "OAuth session not found" };
      }
      return {
        success: true as const,
        data: serialize(row),
        message: "OAuth session retrieved successfully",
      };
    },
    upsert: async (input: {
      mcp_server_uuid: string;
      client_information?: unknown;
      tokens?: unknown;
      code_verifier?: string | null;
    }) => {
      const existing = rows.get(input.mcp_server_uuid);
      const row: Row = existing ?? {
        uuid: "00000000-0000-4000-8000-000000000001",
        mcp_server_uuid: input.mcp_server_uuid,
        client_information: {},
        tokens: null,
        code_verifier: null,
        created_at: new Date(),
        updated_at: new Date(),
      };
      if (input.client_information) {
        row.client_information = input.client_information;
      }
      if (input.tokens) row.tokens = input.tokens;
      if (input.code_verifier) row.code_verifier = input.code_verifier;
      row.updated_at = new Date();
      rows.set(input.mcp_server_uuid, row);
      return {
        success: true as const,
        data: serialize(row),
        message: "OAuth session upserted successfully",
      };
    },
  };
  // Whether `mcpServers.get` finds the server row. While it does not, the
  // provider keeps everything in browser storage instead of the database.
  const server = { exists: true };
  return { rows, impl, server };
});

vi.mock("./trpc", async () => {
  const { createOAuthRouter } = await import("@repo/trpc");
  const caller = createOAuthRouter(h.impl as never).createCaller({
    user: { id: "admin-1", role: "admin" },
    session: { id: "session-1" },
  } as never);
  return {
    vanillaTrpcClient: {
      frontend: {
        mcpServers: {
          get: {
            query: async (input: { uuid: string }) =>
              h.server.exists
                ? { success: true, data: { uuid: input.uuid } }
                : { success: false },
          },
        },
        oauth: {
          get: { query: (input: never) => caller.get(input) },
          upsert: { mutate: (input: never) => caller.upsert(input) },
        },
      },
    },
  };
});

vi.mock("./env", () => ({
  getAppUrl: () => "https://gateway.example.test",
}));

import { getServerSpecificKey, SESSION_KEYS } from "./constants";
import { completeOAuthCallback } from "./oauth-callback";
import { createAuthProvider } from "./oauth-provider";
import { vanillaTrpcClient } from "./trpc";

const SERVER_UUID = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa";
const MCP_URL = "https://mcp.example.test/mcp";
const AS_A = "https://as-a.example.test";
const AS_B = "https://as-b.example.test";
// What the SDK stamps: String(authorizationServerUrl), i.e. the URL exactly as
// the protected-resource metadata advertised it.
const ISSUER_A = AS_A;
const ISSUER_B = AS_B;

type RecordedRequest = {
  method: string;
  url: string;
  /** Body, header values and any decoded Basic credentials, concatenated. */
  visible: string;
};

let advertisedAs = AS_A;
let requests: RecordedRequest[] = [];
let store: Map<string, string>;
let warn: MockInstance<typeof console.warn>;

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });

async function fakeFetch(
  input: string | URL | Request,
  init?: RequestInit,
): Promise<Response> {
  const url = new URL(input instanceof Request ? input.url : String(input));
  const method = (init?.method ?? "GET").toUpperCase();
  const headers = new Headers(init?.headers);
  const body =
    typeof init?.body === "string"
      ? init.body
      : init?.body instanceof URLSearchParams
        ? init.body.toString()
        : "";
  const authorization = headers.get("authorization") ?? "";
  const basic = authorization.startsWith("Basic ")
    ? Buffer.from(authorization.slice(6), "base64").toString("utf8")
    : "";
  requests.push({
    method,
    url: url.href,
    visible: [
      url.href,
      decodeURIComponent(body),
      ...Array.from(headers.values()),
      basic,
    ].join("\n"),
  });

  if (url.origin === "https://mcp.example.test") {
    if (url.pathname.startsWith("/.well-known/oauth-protected-resource")) {
      return json({ resource: MCP_URL, authorization_servers: [advertisedAs] });
    }
    return new Response("not found", { status: 404 });
  }

  const as = url.origin;
  if (as !== AS_A && as !== AS_B) {
    return new Response("not found", { status: 404 });
  }
  const tag = as === AS_A ? "A" : "B";
  if (url.pathname === "/.well-known/oauth-authorization-server") {
    return json({
      issuer: as,
      authorization_endpoint: `${as}/authorize`,
      token_endpoint: `${as}/token`,
      registration_endpoint: `${as}/register`,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      code_challenge_methods_supported: ["S256"],
      token_endpoint_auth_methods_supported: ["client_secret_post", "none"],
    });
  }
  if (url.pathname === "/register" && method === "POST") {
    return json(
      {
        client_id: `client-${tag}`,
        // Handed out even though the provider registers as a public client
        // ("none"); the SDK then authenticates with it, which is why a stored
        // registration is a secret worth binding.
        client_secret: `SECRET-${tag}`,
        client_id_issued_at: 1_700_000_000,
        redirect_uris: ["https://gateway.example.test/fe-oauth/callback"],
        client_name: "MetaMCP",
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
      },
      201,
    );
  }
  if (url.pathname === "/token" && method === "POST") {
    return json({
      access_token: `ACCESS-${tag}-NEW`,
      token_type: "Bearer",
      expires_in: 3600,
      refresh_token: `REFRESH-${tag}-NEW`,
    });
  }
  return new Response("not found", { status: 404 });
}

/** Every recorded request sent to `origin` whose text contains `needle`. */
const sentTo = (origin: string, needle: string) =>
  requests.filter(
    (r) => new URL(r.url).origin === origin && r.visible.includes(needle),
  );

const tokenRequests = () =>
  requests.filter((r) => r.method === "POST" && r.url.endsWith("/token"));

async function storedSession() {
  const result = await vanillaTrpcClient.frontend.oauth.get.query({
    mcp_server_uuid: SERVER_UUID,
  });
  if (!result.success) throw new Error("no stored OAuth session");
  return result.data;
}

/** A row as a pre-1.31 Inspector left it: nothing names its issuer. */
async function seedLegacySession() {
  await vanillaTrpcClient.frontend.oauth.upsert.mutate({
    mcp_server_uuid: SERVER_UUID,
    client_information: {
      client_id: "client-legacy",
      client_secret: "SECRET-LEGACY",
    },
    tokens: {
      access_token: "ACCESS-LEGACY",
      token_type: "Bearer",
      refresh_token: "REFRESH-LEGACY",
    },
  });
}

/** A row as this version leaves it after authorizing against server A. */
async function seedSessionBoundToA() {
  const provider = createAuthProvider(SERVER_UUID, MCP_URL);
  await provider.saveClientInformation({
    client_id: "client-A",
    client_secret: "SECRET-A",
    issuer: ISSUER_A,
  });
  await provider.saveTokens({
    access_token: "ACCESS-A",
    token_type: "Bearer",
    refresh_token: "REFRESH-A",
    issuer: ISSUER_A,
  });
}

beforeEach(() => {
  h.rows.clear();
  h.server.exists = true;
  requests = [];
  advertisedAs = AS_A;
  store = new Map<string, string>();
  vi.stubGlobal("window", { location: { href: "" } });
  vi.stubGlobal("sessionStorage", {
    getItem: (k: string) => store.get(k) ?? null,
    setItem: (k: string, v: string) => void store.set(k, v),
    removeItem: (k: string) => void store.delete(k),
  });
  vi.stubGlobal("fetch", fakeFetch);
  warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);
});

afterEach(() => {
  warn.mockRestore();
  vi.unstubAllGlobals();
});

describe("a stamped credential round-trips through oauth.upsert and oauth.get", () => {
  it("keeps the issuer on the stored client information and tokens", async () => {
    await seedSessionBoundToA();

    const row = await storedSession();
    expect(row.client_information).toEqual({
      client_id: "client-A",
      client_secret: "SECRET-A",
      issuer: ISSUER_A,
    });
    expect(row.tokens).toMatchObject({
      refresh_token: "REFRESH-A",
      issuer: ISSUER_A,
    });

    // And the provider hands the SDK exactly that, stamp included.
    const provider = createAuthProvider(SERVER_UUID, MCP_URL);
    expect(await provider.clientInformation()).toEqual({
      client_id: "client-A",
      client_secret: "SECRET-A",
      issuer: ISSUER_A,
    });
    expect(await provider.tokens()).toMatchObject({
      access_token: "ACCESS-A",
      refresh_token: "REFRESH-A",
      issuer: ISSUER_A,
    });
    expect(warn).not.toHaveBeenCalled();
  });

  it("still refreshes against the server the credential is bound to", async () => {
    await seedSessionBoundToA();

    const result = await auth(createAuthProvider(SERVER_UUID, MCP_URL), {
      serverUrl: MCP_URL,
    });

    expect(result).toBe("AUTHORIZED");
    expect(tokenRequests().map((r) => new URL(r.url).origin)).toEqual([AS_A]);
    expect(sentTo(AS_A, "REFRESH-A")).toHaveLength(1);
    expect((await storedSession()).tokens).toMatchObject({
      access_token: "ACCESS-A-NEW",
      refresh_token: "REFRESH-A-NEW",
      issuer: ISSUER_A,
    });
  });
});

describe("a credential stamped for issuer A is not sent to issuer B", () => {
  it("on a 401, registers afresh with B instead of refreshing there", async () => {
    await seedSessionBoundToA();
    advertisedAs = AS_B;

    const result = await auth(createAuthProvider(SERVER_UUID, MCP_URL), {
      serverUrl: MCP_URL,
    });

    expect(result).toBe("REDIRECT");
    for (const needle of ["SECRET-A", "REFRESH-A", "client-A"]) {
      expect(sentTo(AS_B, needle)).toEqual([]);
    }
    expect(tokenRequests()).toEqual([]);
    // The new registration is bound to B and replaces A's.
    expect((await storedSession()).client_information).toEqual({
      client_id: "client-B",
      client_secret: "SECRET-B",
      client_id_issued_at: 1_700_000_000,
      issuer: ISSUER_B,
    });
    expect(window.location.href.startsWith(`${AS_B}/authorize?`)).toBe(true);
  });
});

describe("credentials stored before issuer binding (no issuer)", () => {
  it("are refused, loudly, rather than handed to the SDK", async () => {
    await seedLegacySession();
    const provider = createAuthProvider(SERVER_UUID, MCP_URL);

    expect(await provider.clientInformation()).toBeUndefined();
    const tokens = await provider.tokens();
    // The access token goes only to the MCP server, so it stays usable.
    expect(tokens?.access_token).toBe("ACCESS-LEGACY");
    expect(tokens?.refresh_token).toBeUndefined();

    const messages = warn.mock.calls.map((call) => String(call[0]));
    expect(messages).toEqual([
      expect.stringContaining(
        `client registration for MCP server ${SERVER_UUID} was saved without the authorization server it belongs to`,
      ),
      expect.stringContaining(
        `refresh token for MCP server ${SERVER_UUID} was saved without the authorization server it belongs to`,
      ),
    ]);
  });

  it("never reach an authorization server; the flow re-registers and re-authorizes", async () => {
    await seedLegacySession();
    // The upstream MCP server now points somewhere else. Nothing recorded
    // which server issued the legacy values, so B may or may not be theirs.
    advertisedAs = AS_B;

    const result = await auth(createAuthProvider(SERVER_UUID, MCP_URL), {
      serverUrl: MCP_URL,
    });

    expect(result).toBe("REDIRECT");
    for (const needle of ["SECRET-LEGACY", "REFRESH-LEGACY", "client-legacy"]) {
      expect(requests.filter((r) => r.visible.includes(needle))).toEqual([]);
    }
    expect(tokenRequests()).toEqual([]);
    expect((await storedSession()).client_information).toMatchObject({
      client_id: "client-B",
      issuer: ISSUER_B,
    });
  });

  it("are refused the same way when read from session storage mid-flow", async () => {
    h.server.exists = false;
    const provider = createAuthProvider(SERVER_UUID, MCP_URL);
    store.set(
      getServerSpecificKey(SESSION_KEYS.CLIENT_INFORMATION, MCP_URL),
      JSON.stringify({ client_id: "client-legacy", client_secret: "S" }),
    );
    store.set(
      getServerSpecificKey(SESSION_KEYS.TOKENS, MCP_URL),
      JSON.stringify({
        access_token: "ACCESS-LEGACY",
        token_type: "Bearer",
        refresh_token: "REFRESH-LEGACY",
      }),
    );

    expect(await provider.clientInformation()).toBeUndefined();
    const tokens = await provider.tokens();
    expect(tokens?.access_token).toBe("ACCESS-LEGACY");
    expect(tokens?.refresh_token).toBeUndefined();
    expect(warn).toHaveBeenCalledTimes(2);
  });
});

describe("/fe-oauth/callback", () => {
  /** Run the pre-redirect half of the flow the way the Inspector does. */
  async function startFlow() {
    store.set(SESSION_KEYS.MCP_SERVER_UUID, SERVER_UUID);
    const result = await auth(createAuthProvider(SERVER_UUID, MCP_URL), {
      serverUrl: MCP_URL,
    });
    expect(result).toBe("REDIRECT");
  }

  it("exchanges the code with the server the registration is bound to and stores the stamps", async () => {
    await startFlow();
    requests = [];

    const destination = await completeOAuthCallback("?code=CODE-1");

    expect(destination).toBe(`/mcp-servers/${SERVER_UUID}`);
    expect(tokenRequests().map((r) => new URL(r.url).origin)).toEqual([AS_A]);
    expect(sentTo(AS_A, "CODE-1")).toHaveLength(1);
    const row = await storedSession();
    expect(row.client_information).toMatchObject({
      client_id: "client-A",
      issuer: ISSUER_A,
    });
    expect(row.tokens).toMatchObject({
      access_token: "ACCESS-A-NEW",
      refresh_token: "REFRESH-A-NEW",
      issuer: ISSUER_A,
    });
    // The callback's own write-back from session storage kept the stamps too,
    // and then cleared the flow's keys.
    expect(store.has(SESSION_KEYS.SERVER_URL)).toBe(false);
  });

  it("refuses to exchange the code when the authorization server changed mid-flow", async () => {
    await startFlow();
    advertisedAs = AS_B;
    requests = [];

    await expect(completeOAuthCallback("?code=CODE-1")).rejects.toThrow(
      "Existing OAuth client information is required when exchanging an authorization code",
    );

    for (const needle of ["SECRET-A", "CODE-1", "client-A"]) {
      expect(sentTo(AS_B, needle)).toEqual([]);
    }
    expect(tokenRequests()).toEqual([]);
  });

  it("refuses a legacy registration rather than sending its secret with the code", async () => {
    await seedLegacySession();
    await vanillaTrpcClient.frontend.oauth.upsert.mutate({
      mcp_server_uuid: SERVER_UUID,
      code_verifier: "verifier-from-an-older-tab",
    });
    store.set(SESSION_KEYS.SERVER_URL, MCP_URL);
    store.set(SESSION_KEYS.MCP_SERVER_UUID, SERVER_UUID);

    await expect(completeOAuthCallback("?code=CODE-2")).rejects.toThrow(
      "Existing OAuth client information is required when exchanging an authorization code",
    );

    expect(requests.filter((r) => r.visible.includes("SECRET-LEGACY"))).toEqual(
      [],
    );
    expect(tokenRequests()).toEqual([]);
  });
});
