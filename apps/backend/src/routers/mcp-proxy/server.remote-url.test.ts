/**
 * What the REMOTE-URL branches of the mcp-proxy actually connect to.
 *
 * The `url-guard.test.ts` suite pins the validator (given a URL, is it a
 * public destination). That is necessary and NOT sufficient, and the gap is why
 * this file exists: a validator can be flawless while the route never calls
 * it, or calls it and connects anyway. Every assertion in that suite keeps
 * passing if the guard is deleted from `createTransport`.
 *
 * So these tests drive the REAL routes — `GET /mcp-proxy/server/sse` and
 * `POST /mcp-proxy/server/mcp` — and assert on whether the CLIENT TRANSPORT
 * was constructed at all. The transport constructor is the last thing before
 * a socket is opened to the caller's chosen address, so it is the honest place
 * to ask "would this connection have happened".
 *
 * DNS is mocked at `node:dns/promises`, which is the resolver the production
 * path uses — the route calls the guard with no options, so nothing here
 * substitutes a friendlier validator than the deployed one. Hostnames are
 * `example.com` subdomains so a broken mock fails rather than resolves.
 */

import express from "express";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { loggerInfo } = vi.hoisted(() => ({ loggerInfo: vi.fn() }));

vi.mock("@/utils/logger", () => ({
  default: { info: loggerInfo, warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

const {
  sseClientConstructions,
  streamableClientConstructions,
  lookupMock,
  findAllAccessibleToUserMock,
  findOAuthSessionMock,
  undiciFetchMock,
} = vi.hoisted(() => ({
  /** Every SSEClientTransport construction, in order. */
  sseClientConstructions: [] as Array<{ url: URL; opts: any }>,
  /** Every StreamableHTTPClientTransport construction, in order. */
  streamableClientConstructions: [] as Array<{ url: URL; opts: any }>,
  lookupMock: vi.fn(),
  findAllAccessibleToUserMock: vi.fn(),
  findOAuthSessionMock: vi.fn(),
  /** The wire: what the guarded fetch hands undici, after every guard step. */
  undiciFetchMock: vi.fn(),
}));

// THE ASSERTION SURFACE. These constructors are the point of no return: past
// them the backend is holding a socket to whatever address the query named.
vi.mock("@modelcontextprotocol/sdk/client/sse.js", () => ({
  SSEClientTransport: class {
    constructor(url: URL, opts: any) {
      sseClientConstructions.push({ url, opts });
    }
    async start() {}
    async close() {}
    async send() {}
  },
  SseError: class SseError extends Error {
    constructor(
      public code: number | undefined,
      message: string,
    ) {
      super(message);
    }
  },
}));

vi.mock("@modelcontextprotocol/sdk/client/streamableHttp.js", () => ({
  StreamableHTTPClientTransport: class {
    constructor(url: URL, opts: any) {
      streamableClientConstructions.push({ url, opts });
    }
    async start() {}
    async close() {}
    async send() {}
    async terminateSession() {}
  },
}));

vi.mock("@modelcontextprotocol/sdk/server/sse.js", () => ({
  SSEServerTransport: class {
    sessionId = "test-session";
    constructor(
      public endpoint: string,
      public res: unknown,
    ) {}
    async start() {}
    async close() {}
    async send() {}
    async handlePostMessage() {}
  },
}));

vi.mock("@modelcontextprotocol/sdk/server/streamableHttp.js", () => ({
  StreamableHTTPServerTransport: class {
    constructor(public opts: unknown) {}
    async start() {}
    async close() {}
    async send() {}
    async handleRequest() {}
  },
}));

vi.mock("../../lib/stdio-transport/process-managed-transport", () => ({
  ProcessManagedStdioTransport: class {
    stderr: undefined = undefined;
    async start() {}
    async close() {}
    async send() {}
  },
}));

vi.mock("../../lib/mcp-proxy", () => ({ default: vi.fn() }));

vi.mock("../../lib/metamcp/mcp-server-pool", () => ({
  mcpServerPool: { handleServerCrashWithoutNamespace: vi.fn() },
}));

// The real localhost transform and the real pool posture: the by-uuid path
// connects under POOL_GUARD_OPTIONS, and a stand-in copy here would test the
// copy. Nothing else from the client module is used by the route.
vi.mock("../../lib/metamcp/client", async (importOriginal) => {
  const real =
    await importOriginal<typeof import("../../lib/metamcp/client")>();
  return {
    transformDockerUrl: real.transformDockerUrl,
    POOL_GUARD_OPTIONS: real.POOL_GUARD_OPTIONS,
  };
});

// `findAll` and `findByUuid` are TRIPWIRES, matching the STDIO call-site
// suite. Both ignore ownership: `findAll` returns every row in the
// installation, and a by-uuid re-fetch reaches a row the caller may not see.
// Neither belongs on a path that merges a row's stored credentials into an
// outbound request, so reaching for either is a test failure rather than a
// silently wider result.
vi.mock("../../db/repositories", () => ({
  mcpServersRepository: {
    findAll: vi.fn(async () => {
      throw new Error(
        "findAll must not resolve a remote destination: it ignores ownership",
      );
    }),
    findByUuid: vi.fn(async () => {
      throw new Error("findByUuid must not be used here: it ignores ownership");
    }),
    findAllAccessibleToUser: findAllAccessibleToUserMock,
  },
  oauthSessionsRepository: { findByMcpServerUuid: findOAuthSessionMock },
}));

// `db/index.ts` throws without DATABASE_URL.
vi.mock("../../db/index", () => ({ db: {}, pool: {} }));

// The resolver the deployed path uses. Mocked here rather than injected so the
// route keeps calling the guard exactly as production does.
vi.mock("node:dns/promises", () => ({ lookup: lookupMock }));

// The transport under the guarded fetch. Only `fetch` is replaced, so the
// guard's own pinned Agent is still built; nothing here opens a socket.
vi.mock("undici", async (importOriginal) => ({
  ...(await importOriginal<typeof import("undici")>()),
  fetch: undiciFetchMock,
}));

const { default: serverRouter } = await import("./server");
const { CROSS_ORIGIN_REDIRECT_REFUSED, NOT_A_PERMITTED_TARGET } = await import(
  "@/lib/metamcp/url-guard"
);

const PUBLIC_V4 = "93.184.216.34";

/** The signed-in admin driving every request unless a test says otherwise. */
const CALLER = { id: "user-caller", role: "admin" };

const resolvesTo = (...addresses: string[]) =>
  lookupMock.mockResolvedValue(addresses.map((address) => ({ address })));

/**
 * A three-row estate: one row the caller owns, one PUBLIC row, and one owned
 * by somebody else. All three are perfectly ordinary rows — the only thing
 * separating them is `user_id`, which is the whole point.
 *
 * `SECRET_URL` is the interesting one. It is a public internet address, so the
 * destination guard has no opinion about it; what makes it sensitive is the
 * vendor API key sitting in the private row's stored `headers`.
 */
const OWN_URL = "https://own.example.com/sse";
const PUBLIC_ROW_URL = "https://shared.example.com/sse";
const SECRET_URL = "https://secret.example.com/sse";

const estate = [
  {
    uuid: "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa",
    name: "own",
    type: "SSE",
    url: OWN_URL,
    headers: { "x-vendor-api-key": "own-key" },
    user_id: CALLER.id,
    error_status: null,
  },
  {
    uuid: "bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb",
    name: "shared",
    type: "SSE",
    url: PUBLIC_ROW_URL,
    headers: { "x-vendor-api-key": "shared-key" },
    user_id: null,
    error_status: null,
  },
  {
    uuid: "cccccccc-3333-4333-8333-cccccccccccc",
    name: "someone-elses",
    type: "SSE",
    url: SECRET_URL,
    headers: { "x-vendor-api-key": "SOMEONE-ELSES-SECRET" },
    user_id: "user-someone-else",
    error_status: null,
  },
];

/** What `findAllAccessibleToUser` answers: public rows plus the caller's own. */
const accessibleTo = (userId: string) =>
  estate.filter((row) => row.user_id === null || row.user_id === userId);

/** Header names+values the transport was actually built with. */
const sseHeaders = () => sseClientConstructions[0]?.opts?.requestInit?.headers;

/** The body of the last `res.json(...)` any route sent. */
let lastJsonBody: unknown;

/** Minimal express res double; the routes only stream, refuse or 500. */
const makeRes = () => {
  let statusCode = 200;
  const res: any = {
    get statusCode() {
      return statusCode;
    },
    status(code: number) {
      statusCode = code;
      return res;
    },
    json(body: unknown) {
      lastJsonBody = body;
      return res;
    },
    end() {
      return res;
    },
    on() {
      return res;
    },
    setHeader() {
      return res;
    },
    writeHead() {
      return res;
    },
    write() {
      return true;
    },
    flushHeaders() {},
  };
  return res;
};

/** The session user a request carries, as `betterAuthMcpMiddleware` sets it. */
type SessionUserDouble = { id?: string; role?: string; email?: string };

/** Drive one of the real routes and settle. */
async function drive(
  method: "GET" | "POST",
  path: string,
  query: Record<string, string>,
  /** `null` means the request arrives with NO session user at all. */
  user: SessionUserDouble | null = CALLER,
  /** Request headers, lowercase-keyed as Express delivers them. */
  headers: Record<string, string> = {},
): Promise<number> {
  const search = new URLSearchParams(query).toString();
  const req = {
    method,
    url: `${path}?${search}`,
    originalUrl: `/mcp-proxy/server${path}?${search}`,
    baseUrl: "",
    query: Object.fromEntries(new URLSearchParams(search)),
    headers,
    user: user ?? undefined,
  } as unknown as express.Request;

  const res = makeRes();

  await new Promise<void>((resolve, reject) => {
    (serverRouter as unknown as express.RequestHandler)(
      req,
      res as unknown as express.Response,
      (err?: unknown) => (err ? reject(err) : resolve()),
    );
    // The handlers are async and never call next() on success; settle on a
    // later macrotask, by which point the awaits above have run.
    setTimeout(resolve, 50);
  });

  return res.statusCode;
}

const getSse = (
  query: Record<string, string>,
  user: SessionUserDouble | null = CALLER,
  headers: Record<string, string> = {},
) => drive("GET", "/sse", query, user, headers);
const postMcp = (
  query: Record<string, string>,
  user: SessionUserDouble | null = CALLER,
  headers: Record<string, string> = {},
) => drive("POST", "/mcp", query, user, headers);

beforeEach(() => {
  vi.clearAllMocks();
  sseClientConstructions.length = 0;
  streamableClientConstructions.length = 0;
  lastJsonBody = undefined;
  findAllAccessibleToUserMock.mockResolvedValue([]);
  findOAuthSessionMock.mockResolvedValue(undefined);
  undiciFetchMock.mockImplementation(
    async () => new Response("{}", { status: 200 }),
  );
  resolvesTo(PUBLIC_V4);
  delete process.env.MCP_PROXY_URL_ALLOWED_HOSTS;
  // The default m365-injected list (`m365`), whatever the shell exports; the
  // rows here are not on it unless a case says so.
  vi.stubEnv("M365_INJECTED_SERVER_NAMES", "");
});

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("GET /mcp-proxy/server/sse — where the SSE branch will connect", () => {
  it.each([
    ["http://169.254.169.254/latest/meta-data/", "cloud instance metadata"],
    ["http://127.0.0.1:8080/sse", "loopback"],
    ["http://10.1.2.3/sse", "RFC 1918"],
    ["http://172.16.0.1/sse", "RFC 1918"],
    ["http://192.168.1.1/sse", "RFC 1918"],
    ["http://[::1]/sse", "IPv6 loopback"],
    ["http://[fe80::1]/sse", "IPv6 link-local"],
    ["http://2130706433/sse", "decimal-literal loopback"],
    ["http://[::ffff:127.0.0.1]/sse", "IPv4-mapped loopback"],
    ["file:///etc/passwd", "non-http scheme"],
  ])("opens NOTHING for %s (%s)", async (url) => {
    const status = await getSse({ transportType: "SSE", url });

    expect(sseClientConstructions).toEqual([]);
    expect(status).toBe(500);
  });

  it("opens NOTHING for a hostname that resolves to a private address", async () => {
    // The rebinding shape, judged through the resolver the deployed path uses.
    resolvesTo("10.0.0.5");

    await getSse({ transportType: "SSE", url: "https://mcp.example.com/sse" });

    expect(sseClientConstructions).toEqual([]);
    expect(lookupMock).toHaveBeenCalledWith("mcp.example.com", {
      all: true,
      verbatim: true,
    });
  });

  it("refuses before asking the database anything", async () => {
    // The row lookup used to run first. Nothing about a refused destination
    // should cost a query.
    await getSse({ transportType: "SSE", url: "http://169.254.169.254/" });

    expect(findAllAccessibleToUserMock).not.toHaveBeenCalled();
  });

  it("STILL connects to a public server", async () => {
    // The flow the operator asked to keep: point the Inspector at a public
    // server that is not in the database and connect.
    await getSse({ transportType: "SSE", url: "https://mcp.example.com/sse" });

    expect(sseClientConstructions).toHaveLength(1);
    expect(sseClientConstructions[0].url.href).toBe(
      "https://mcp.example.com/sse",
    );
  });

  it("hands the transport a fetch that re-checks every destination", async () => {
    // Both hooks matter: the SDK prefers `eventSourceInit.fetch` for the
    // stream and `fetch` for the POST back-channel, and the POST goes to
    // whatever endpoint the REMOTE server advertises.
    await getSse({ transportType: "SSE", url: "https://mcp.example.com/sse" });

    const { opts } = sseClientConstructions[0];
    await expect(opts.fetch("http://169.254.169.254/")).rejects.toThrow(
      NOT_A_PERMITTED_TARGET,
    );
    await expect(
      opts.eventSourceInit.fetch("http://169.254.169.254/"),
    ).rejects.toThrow(NOT_A_PERMITTED_TARGET);
  });

  it("honours MCP_PROXY_URL_ALLOWED_HOSTS for a deliberate internal host", async () => {
    process.env.MCP_PROXY_URL_ALLOWED_HOSTS = "host.docker.internal";
    resolvesTo("172.17.0.1");

    await getSse({
      transportType: "SSE",
      url: "http://host.docker.internal:3000/sse",
    });

    expect(sseClientConstructions).toHaveLength(1);
  });
});

describe("POST /mcp-proxy/server/mcp — where the streamable-HTTP branch will connect", () => {
  it.each([
    ["http://169.254.169.254/latest/meta-data/", "cloud instance metadata"],
    ["http://127.0.0.1:8080/mcp", "loopback"],
    ["http://10.1.2.3/mcp", "RFC 1918"],
    ["http://192.168.1.1/mcp", "RFC 1918"],
    ["http://[::1]/mcp", "IPv6 loopback"],
    ["http://2130706433/mcp", "decimal-literal loopback"],
  ])("opens NOTHING for %s (%s)", async (url) => {
    const status = await postMcp({ transportType: "STREAMABLE_HTTP", url });

    expect(streamableClientConstructions).toEqual([]);
    expect(status).toBe(500);
  });

  it("STILL connects to a public server", async () => {
    await postMcp({
      transportType: "STREAMABLE_HTTP",
      url: "https://mcp.example.com/mcp",
    });

    expect(streamableClientConstructions).toHaveLength(1);
    expect(streamableClientConstructions[0].url.href).toBe(
      "https://mcp.example.com/mcp",
    );
  });

  it("hands the transport a fetch that re-checks every destination", async () => {
    // This transport reconnects on its own schedule and follows redirects; the
    // one-shot check at connect time cannot reach either.
    await postMcp({
      transportType: "STREAMABLE_HTTP",
      url: "https://mcp.example.com/mcp",
    });

    const { opts } = streamableClientConstructions[0];
    await expect(opts.fetch("http://169.254.169.254/")).rejects.toThrow(
      NOT_A_PERMITTED_TARGET,
    );
  });
});

/**
 * WHOSE stored credentials a remote connection is allowed to spend.
 *
 * Distinct from the destination question above, and not solved by it: every
 * URL in this block is a perfectly legitimate public address, so the range
 * check has no opinion about any of them. What is at stake is the `headers`
 * jsonb on the matched row — vendor API keys — which is merged into the
 * outbound request. The row used to be found with `findAll()`, i.e. across the
 * whole installation, matched on the URL the CALLER sent.
 */
describe("remote transports — whose row may supply the stored headers", () => {
  beforeEach(() => {
    findAllAccessibleToUserMock.mockImplementation(async (userId: string) =>
      accessibleTo(userId),
    );
  });

  it("does NOT attach another user's private row headers, but still connects", async () => {
    // THE FINDING. Both halves matter: the connection is not the problem and
    // must still happen (an unregistered public URL is a supported flow), so a
    // fix that simply refused would be indistinguishable from a broken one.
    // What must not travel is the other user's key.
    await getSse({ transportType: "SSE", url: SECRET_URL });

    expect(sseClientConstructions).toHaveLength(1);
    expect(sseHeaders()["x-vendor-api-key"]).toBeUndefined();
    expect(JSON.stringify(sseHeaders())).not.toContain("SOMEONE-ELSES-SECRET");
  });

  it("scopes the lookup to the calling user", async () => {
    await getSse({ transportType: "SSE", url: SECRET_URL });

    expect(findAllAccessibleToUserMock).toHaveBeenCalledWith(CALLER.id);
  });

  it("treats an inaccessible row exactly like no row at all", async () => {
    // No enumeration oracle: a URL registered to somebody else and a URL
    // registered to nobody have to be indistinguishable from out here.
    await getSse({ transportType: "SSE", url: SECRET_URL });
    const inaccessible = { ...sseHeaders() };

    sseClientConstructions.length = 0;
    await getSse({
      transportType: "SSE",
      url: "https://nobody.example.com/sse",
    });

    expect({ ...sseHeaders() }).toEqual(inaccessible);
  });

  it("STILL attaches the caller's OWN row headers", async () => {
    // The scope must not be "trust nothing" — the legitimate case is the whole
    // reason the merge exists.
    await getSse({ transportType: "SSE", url: OWN_URL });

    expect(sseHeaders()["x-vendor-api-key"]).toBe("own-key");
  });

  it("STILL attaches a PUBLIC row's headers", async () => {
    await getSse({ transportType: "SSE", url: PUBLIC_ROW_URL });

    expect(sseHeaders()["x-vendor-api-key"]).toBe("shared-key");
  });

  it("refuses to resolve a row when the request carries no session user", async () => {
    // Fail closed. The old code had no user in the path at all, so this is the
    // case where a widening fallback would be easiest to reintroduce.
    const status = await getSse({ transportType: "SSE", url: OWN_URL }, null);

    expect(sseClientConstructions).toEqual([]);
    expect(status).toBe(500);
    expect(findAllAccessibleToUserMock).not.toHaveBeenCalled();
  });

  it("refuses a row the caller owns that is marked ERROR", async () => {
    findAllAccessibleToUserMock.mockResolvedValue([
      { ...estate[0], error_status: "ERROR" },
    ]);

    await getSse({ transportType: "SSE", url: OWN_URL });

    expect(sseClientConstructions).toEqual([]);
  });

  it("ignores an ERROR marking on a row the caller cannot see", async () => {
    // The other side of the same coin: another user's row must not be able to
    // block a destination either.
    findAllAccessibleToUserMock.mockResolvedValue([]);

    await getSse({ transportType: "SSE", url: SECRET_URL });

    expect(sseClientConstructions).toHaveLength(1);
  });

  it("does NOT attach another user's private row headers on STREAMABLE_HTTP", async () => {
    const secretHttpUrl = "https://secret-http.example.com/mcp";
    findAllAccessibleToUserMock.mockImplementation(async (userId: string) =>
      [
        {
          uuid: "dddddddd-4444-4444-8444-dddddddddddd",
          name: "someone-elses-http",
          type: "STREAMABLE_HTTP",
          url: secretHttpUrl,
          headers: { "x-vendor-api-key": "SOMEONE-ELSES-SECRET" },
          user_id: "user-someone-else",
          error_status: null,
        },
      ].filter((row) => row.user_id === userId),
    );

    await postMcp({
      transportType: "STREAMABLE_HTTP",
      url: secretHttpUrl,
    });

    expect(streamableClientConstructions).toHaveLength(1);
    const headers = streamableClientConstructions[0].opts.requestInit.headers;
    expect(headers["x-vendor-api-key"]).toBeUndefined();
    expect(JSON.stringify(headers)).not.toContain("SOMEONE-ELSES-SECRET");
  });
});

describe("the SSE connect log", () => {
  it("records origin and path but NEVER the query string", async () => {
    // Hosted MCP servers routinely carry the credential in the query
    // (`?api_key=`, `?token=`), so logging the full url writes a live secret
    // into app.log — the same leak this line already avoids for the header
    // VALUES by logging only header names.
    await getSse({
      transportType: "SSE",
      url: "https://mcp.example.com/sse?api_key=SUPER-SECRET&token=ALSO-SECRET",
    });

    const line = loggerInfo.mock.calls
      .map((call) => String(call[0]))
      .find((text) => text.startsWith("SSE transport:"));

    expect(line).toBeDefined();
    expect(line).toContain("https://mcp.example.com/sse");
    expect(line).not.toContain("SUPER-SECRET");
    expect(line).not.toContain("ALSO-SECRET");
    expect(line).not.toContain("api_key");
  });

  it("keeps the url JSON-escaped so a newline cannot forge a log line", async () => {
    await getSse({
      transportType: "SSE",
      url: "https://mcp.example.com/sse%0A%0Afake",
    });

    const line = loggerInfo.mock.calls
      .map((call) => String(call[0]))
      .find((text) => text.startsWith("SSE transport:"));

    expect(line).toBeDefined();
    // The escape sequence survives as TEXT rather than as a real break.
    expect(line).not.toMatch(/\n\n/);
  });
});

/**
 * X-MCP-Actor passthrough: best-effort, client-asserted attribution that lets
 * a backend MCP stamp WHO an action is on behalf of onto its audit rows and the
 * shell-broker approval page. It is NOT an auth control — that stays the
 * endpoint API-key — so the only questions here are whether a caller-set value
 * reaches the backend transport and whether the whitelist stays narrow enough
 * that nothing else rides along with it.
 */
describe("X-MCP-Actor passthrough — best-effort audit attribution", () => {
  const ACTOR = "operator@umbrellaitgroup.com";

  it("forwards x-mcp-actor to an SSE backend when the caller sets it", async () => {
    await getSse(
      { transportType: "SSE", url: "https://mcp.example.com/sse" },
      CALLER,
      { "x-mcp-actor": ACTOR },
    );

    expect(sseHeaders()["x-mcp-actor"]).toBe(ACTOR);
  });

  it("forwards x-mcp-actor to a STREAMABLE_HTTP backend when the caller sets it", async () => {
    await postMcp(
      { transportType: "STREAMABLE_HTTP", url: "https://mcp.example.com/mcp" },
      CALLER,
      { "x-mcp-actor": ACTOR },
    );

    expect(
      streamableClientConstructions[0].opts.requestInit.headers["x-mcp-actor"],
    ).toBe(ACTOR);
  });

  it("omits x-mcp-actor when the caller does not send it", async () => {
    await getSse({ transportType: "SSE", url: "https://mcp.example.com/sse" });

    expect(sseHeaders()["x-mcp-actor"]).toBeUndefined();
  });

  it("does NOT forward a header outside the whitelist", async () => {
    // Guard against over-widening: adding x-mcp-actor must not turn the
    // passthrough into a general-purpose header conduit.
    await getSse(
      { transportType: "SSE", url: "https://mcp.example.com/sse" },
      CALLER,
      { "x-not-whitelisted": "must-not-travel" },
    );

    expect(sseHeaders()["x-not-whitelisted"]).toBeUndefined();
  });
});

/**
 * `X-Umbrella-User-Id` is set by the gateway, from the verified caller, for
 * the backends named in VERIFIED_CALLER_SERVER_NAMES (`verified-caller.ts`).
 * The Inspector's `x-custom-auth-header` lets the caller name ANY header to
 * copy from the request onto the backend connection, so without a refusal it
 * is a path to hand a backend that trusts this header someone else's id. The
 * refusal applies whatever the destination: the m365 backend reads the same
 * header. A matched row's stored copy is dropped the same way, whatever the
 * row's name.
 */
describe("X-Umbrella-User-Id cannot be supplied through the Inspector", () => {
  const ORIGINAL_NAMES = process.env.VERIFIED_CALLER_SERVER_NAMES;
  afterEach(() => {
    if (ORIGINAL_NAMES === undefined) {
      delete process.env.VERIFIED_CALLER_SERVER_NAMES;
    } else {
      process.env.VERIFIED_CALLER_SERVER_NAMES = ORIGINAL_NAMES;
    }
  });

  it.each(["X-Umbrella-User-Id", "x-umbrella-user-id", "X-UMBRELLA-USER-ID"])(
    "refuses a custom auth header named %s on SSE, and opens nothing",
    async (name) => {
      const status = await getSse(
        { transportType: "SSE", url: "https://mcp.example.com/sse" },
        CALLER,
        { "x-custom-auth-header": name, "x-umbrella-user-id": "user-victim" },
      );

      expect(sseClientConstructions).toEqual([]);
      expect(status).toBe(500);
    },
  );

  it("refuses a custom auth header naming it on STREAMABLE_HTTP, and opens nothing", async () => {
    const status = await postMcp(
      { transportType: "STREAMABLE_HTTP", url: "https://mcp.example.com/mcp" },
      CALLER,
      {
        "x-custom-auth-header": "X-Umbrella-User-Id",
        "x-umbrella-user-id": "user-victim",
      },
    );

    expect(streamableClientConstructions).toEqual([]);
    expect(status).toBe(500);
  });

  it("refuses it even when the request carries no value for it", async () => {
    await getSse(
      { transportType: "SSE", url: "https://mcp.example.com/sse" },
      CALLER,
      { "x-custom-auth-header": "X-Umbrella-User-Id" },
    );

    expect(sseClientConstructions).toEqual([]);
  });

  it("STILL forwards any other custom auth header", async () => {
    await getSse(
      { transportType: "SSE", url: "https://mcp.example.com/sse" },
      CALLER,
      { "x-custom-auth-header": "X-Api-Key", "x-api-key": "vendor-key" },
    );

    expect(sseClientConstructions).toHaveLength(1);
    expect(sseHeaders()["X-Api-Key"]).toBe("vendor-key");
  });

  it("drops a value stored on a named backend's row and keeps the rest of the row", async () => {
    process.env.VERIFIED_CALLER_SERVER_NAMES = "team";
    findAllAccessibleToUserMock.mockResolvedValue([
      {
        uuid: "eeeeeeee-5555-4555-8555-eeeeeeeeeeee",
        name: "team",
        type: "STREAMABLE_HTTP",
        url: "https://team.example.com/mcp",
        headers: {
          "X-Umbrella-User-Id": "user-stored",
          "x-vendor-api-key": "team-key",
        },
        user_id: null,
        error_status: null,
      },
    ]);

    await postMcp({
      transportType: "STREAMABLE_HTTP",
      url: "https://team.example.com/mcp",
    });

    expect(streamableClientConstructions).toHaveLength(1);
    const headers = streamableClientConstructions[0].opts.requestInit.headers;
    expect(JSON.stringify(headers)).not.toContain("user-stored");
    expect(headers["x-vendor-api-key"]).toBe("team-key");
  });

  // Identity headers are gateway-set only, whatever the row's name: the
  // Inspector's transports carry the gateway trust header to an allowlisted
  // host, so a row that is not named gets no stored copy through either.
  it.each([
    ["SSE", "https://other.example.com/sse"],
    ["STREAMABLE_HTTP", "https://other.example.com/mcp"],
  ] as const)(
    "drops a value stored on a row that is not named, and keeps the rest of the row (%s)",
    async (transportType, url) => {
      process.env.VERIFIED_CALLER_SERVER_NAMES = "team";
      findAllAccessibleToUserMock.mockResolvedValue([
        {
          uuid: "ffffffff-6666-4666-8666-ffffffffffff",
          name: "other",
          type: transportType,
          url,
          headers: {
            "X-Umbrella-User-Id": "user-stored",
            "x-vendor-api-key": "other-key",
          },
          user_id: null,
          error_status: null,
        },
      ]);

      await (transportType === "SSE" ? getSse : postMcp)({
        transportType,
        url,
      });

      const built =
        transportType === "SSE"
          ? sseClientConstructions
          : streamableClientConstructions;
      expect(built).toHaveLength(1);
      const headers = built[0].opts.requestInit.headers;
      expect(JSON.stringify(headers)).not.toContain("user-stored");
      expect(headers["x-vendor-api-key"]).toBe("other-key");
    },
  );
});

/**
 * `X-Umbrella-Caller` is set by the gateway beside `X-Umbrella-User-Id`, from
 * the same verified caller, and carries the credential as well as the user.
 * The Inspector reserves it, drops it from every row's stored headers
 * whatever the row's name, and never forwards a copy the browser sent.
 */
describe("X-Umbrella-Caller cannot be supplied through the Inspector", () => {
  const ORIGINAL_NAMES = process.env.VERIFIED_CALLER_SERVER_NAMES;
  afterEach(() => {
    if (ORIGINAL_NAMES === undefined) {
      delete process.env.VERIFIED_CALLER_SERVER_NAMES;
    } else {
      process.env.VERIFIED_CALLER_SERVER_NAMES = ORIGINAL_NAMES;
    }
  });

  it.each(["X-Umbrella-Caller", "x-umbrella-caller", "X-UMBRELLA-CALLER"])(
    "refuses a custom auth header named %s on SSE, and opens nothing",
    async (name) => {
      const status = await getSse(
        { transportType: "SSE", url: "https://mcp.example.com/sse" },
        CALLER,
        { "x-custom-auth-header": name, "x-umbrella-caller": "v1.supplied" },
      );

      expect(sseClientConstructions).toEqual([]);
      expect(status).toBe(500);
    },
  );

  it("refuses a custom auth header naming it on STREAMABLE_HTTP, and opens nothing", async () => {
    const status = await postMcp(
      { transportType: "STREAMABLE_HTTP", url: "https://mcp.example.com/mcp" },
      CALLER,
      {
        "x-custom-auth-header": "X-Umbrella-Caller",
        "x-umbrella-caller": "v1.supplied",
      },
    );

    expect(streamableClientConstructions).toEqual([]);
    expect(status).toBe(500);
  });

  it.each([
    [
      "SSE",
      () =>
        getSse(
          { transportType: "SSE", url: "https://mcp.example.com/sse" },
          CALLER,
          {
            "x-umbrella-caller": "v1.supplied",
            "x-umbrella-user-id": "user-supplied",
          },
        ),
    ],
    [
      "STREAMABLE_HTTP",
      () =>
        postMcp(
          {
            transportType: "STREAMABLE_HTTP",
            url: "https://mcp.example.com/mcp",
          },
          CALLER,
          {
            "x-umbrella-caller": "v1.supplied",
            "x-umbrella-user-id": "user-supplied",
          },
        ),
    ],
  ])(
    "never forwards a copy of either identity header the browser sent (%s)",
    async (transportType, send) => {
      await send();
      const built =
        transportType === "SSE"
          ? sseClientConstructions
          : streamableClientConstructions;
      expect(built).toHaveLength(1);
      const headers = JSON.stringify(built[0].opts.requestInit.headers);
      expect(headers).not.toContain("v1.supplied");
      expect(headers).not.toContain("user-supplied");
    },
  );

  it("drops a value stored on a named backend's row and keeps the rest of the row", async () => {
    process.env.VERIFIED_CALLER_SERVER_NAMES = "team";
    findAllAccessibleToUserMock.mockResolvedValue([
      {
        uuid: "eeeeeeee-5555-4555-8555-eeeeeeeeeeee",
        name: "team",
        type: "STREAMABLE_HTTP",
        url: "https://team.example.com/mcp",
        headers: {
          "X-Umbrella-Caller": "v1.stored",
          "x-umbrella-caller": "v1.stored-lower",
          "x-vendor-api-key": "team-key",
        },
        user_id: null,
        error_status: null,
      },
    ]);

    await postMcp({
      transportType: "STREAMABLE_HTTP",
      url: "https://team.example.com/mcp",
    });

    expect(streamableClientConstructions).toHaveLength(1);
    const headers = streamableClientConstructions[0].opts.requestInit.headers;
    expect(JSON.stringify(headers)).not.toContain("v1.stored");
    expect(headers["x-vendor-api-key"]).toBe("team-key");
  });

  it.each([
    ["SSE", "https://other.example.com/sse"],
    ["STREAMABLE_HTTP", "https://other.example.com/mcp"],
  ] as const)(
    "drops a value stored on a row that is not named, and keeps the rest of the row (%s)",
    async (transportType, url) => {
      process.env.VERIFIED_CALLER_SERVER_NAMES = "team";
      findAllAccessibleToUserMock.mockResolvedValue([
        {
          uuid: "ffffffff-6666-4666-8666-ffffffffffff",
          name: "other",
          type: transportType,
          url,
          headers: {
            "X-Umbrella-Caller": "v1.stored",
            "x-umbrella-caller": "v1.stored-lower",
            "x-vendor-api-key": "other-key",
          },
          user_id: null,
          error_status: null,
        },
      ]);

      await (transportType === "SSE" ? getSse : postMcp)({
        transportType,
        url,
      });

      const built =
        transportType === "SSE"
          ? sseClientConstructions
          : streamableClientConstructions;
      expect(built).toHaveLength(1);
      const headers = built[0].opts.requestInit.headers;
      expect(JSON.stringify(headers)).not.toContain("v1.stored");
      expect(headers["x-vendor-api-key"]).toBe("other-key");
    },
  );
});

/**
 * The server page's own backends, opened by uuid.
 *
 * The admin UI opens every registered server through this proxy to list its
 * tools, and the gateway's backends live on the private container network, so
 * the strict "public destinations only" by-url posture refused every one of
 * them. A request that names a row by `mcpServerUuid` now connects to that
 * row's url (never `query.url`) under the pool's own guard posture, pinned to
 * the row's origin; a request without one keeps the strict path.
 *
 * The guard here is the real one, resolving through the mocked getaddrinfo
 * (`node:dns/promises`), and the wire is undici's fetch under it. Expected
 * values follow the guard's range table (url-guard.ts BLOCKED_IPV4_RANGES):
 * 172.16.0.0/12 is an internal-service range, 169.254.0.0/16 and
 * 100.64.0.0/10 are never a backend.
 */
describe("registered servers by uuid: the server page's own backends", () => {
  const INTERNAL_V4 = "172.18.0.7";
  const ROW_UUID = "dddddddd-4444-4444-8444-dddddddddddd";
  const OTHER_USERS_UUID = "eeeeeeee-5555-4555-8555-eeeeeeeeeeee";
  const OTHER_TYPE_UUID = "ffffffff-6666-4666-8666-ffffffffffff";
  const OWN_ROW_UUID = "a1a1a1a1-1111-4111-8111-a1a1a1a1a1a1";
  const ERROR_ROW_UUID = "abababab-7777-4777-8777-abababababab";
  const NO_URL_ROW_UUID = "cdcdcdcd-8888-4888-8888-cdcdcdcdcdcd";
  const UNKNOWN_UUID = "12121212-9999-4999-8999-121212121212";
  const BACKEND_MCP = "http://mcp-backend.example.com:3000/mcp";
  const BACKEND_SSE = "http://mcp-backend.example.com:3000/sse";
  const ELSEWHERE = "https://elsewhere.example.com/mcp";
  const SESSION = { ...CALLER, email: "admin@example.com" };
  // A test value of the minimum length the guard accepts (32 bytes).
  const GATEWAY_SECRET = "test-gateway-backend-secret-0000000000";

  const row = (over: Record<string, unknown> = {}) => ({
    uuid: ROW_UUID,
    name: "backend",
    type: "STREAMABLE_HTTP",
    url: BACKEND_MCP,
    headers: {} as Record<string, string>,
    user_id: null as string | null,
    error_status: null as string | null,
    bearerToken: null as string | null,
    ...over,
  });

  type Send = (
    query: Record<string, string>,
    user?: SessionUserDouble | null,
    headers?: Record<string, string>,
  ) => Promise<number>;
  const TRANSPORTS: Array<
    [string, string, Send, Array<{ url: URL; opts: any }>]
  > = [
    ["STREAMABLE_HTTP", BACKEND_MCP, postMcp, streamableClientConstructions],
    ["SSE", BACKEND_SSE, getSse, sseClientConstructions],
  ];

  /**
   * Send one request through the transport's own fetch the way the SDK does:
   * a POST with the constructed headers (STREAMABLE_HTTP), or the SSE stream
   * GET through `eventSourceInit.fetch`, which adds the headers itself.
   */
  const sendThroughTransport = async (
    type: string,
    built: Array<{ url: URL; opts: any }>,
  ) => {
    expect(built).toHaveLength(1);
    const { url, opts } = built[0];
    if (type === "SSE") {
      return opts.eventSourceInit.fetch(url, { method: "GET" });
    }
    return opts.fetch(url, {
      method: "POST",
      headers: opts.requestInit.headers,
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
    });
  };

  /** The headers of the last request that reached the wire. */
  const wireHeaders = (): Headers => {
    const calls = undiciFetchMock.mock.calls;
    expect(calls.length).toBeGreaterThan(0);
    return new Headers(calls[calls.length - 1][1].headers);
  };

  const ORIGINAL_NAMES = process.env.VERIFIED_CALLER_SERVER_NAMES;

  beforeEach(() => {
    resolvesTo(INTERNAL_V4);
    findAllAccessibleToUserMock.mockResolvedValue([row()]);
  });

  afterEach(() => {
    delete process.env.GATEWAY_BACKEND_SECRET;
    delete process.env.TRANSFORM_LOCALHOST_TO_DOCKER_INTERNAL;
    if (ORIGINAL_NAMES === undefined) {
      delete process.env.VERIFIED_CALLER_SERVER_NAMES;
    } else {
      process.env.VERIFIED_CALLER_SERVER_NAMES = ORIGINAL_NAMES;
    }
  });

  it.each(TRANSPORTS)(
    "connects a public row on the private network over %s, to the row's url and not query.url (real guard)",
    async (type, rowUrl, send, built) => {
      findAllAccessibleToUserMock.mockResolvedValue([
        row({ type, url: rowUrl }),
      ]);

      await send({
        transportType: type,
        mcpServerUuid: ROW_UUID,
        url: ELSEWHERE,
      });

      expect(built).toHaveLength(1);
      expect(built[0].url.href).toBe(rowUrl);
      expect(findAllAccessibleToUserMock).toHaveBeenCalledWith(CALLER.id);
      expect(lookupMock).toHaveBeenCalledWith("mcp-backend.example.com", {
        all: true,
        verbatim: true,
      });
      expect(lookupMock).not.toHaveBeenCalledWith(
        "elsewhere.example.com",
        expect.anything(),
      );
    },
  );

  it("connects the caller's own private row by uuid", async () => {
    findAllAccessibleToUserMock.mockResolvedValue([
      row({ user_id: CALLER.id }),
    ]);

    await postMcp({
      transportType: "STREAMABLE_HTTP",
      mcpServerUuid: ROW_UUID,
    });

    expect(streamableClientConstructions).toHaveLength(1);
  });

  it.each(TRANSPORTS)(
    "answers every miss on %s with the same constant 400 refusal and opens nothing",
    async (type, rowUrl, send, built) => {
      const otherType = type === "SSE" ? "STREAMABLE_HTTP" : "SSE";
      const estate = [
        row({ type, url: rowUrl }),
        row({
          uuid: OTHER_USERS_UUID,
          type,
          url: rowUrl,
          user_id: "user-someone-else",
        }),
        row({ uuid: OTHER_TYPE_UUID, type: otherType, url: rowUrl }),
        row({ uuid: ERROR_ROW_UUID, type, url: rowUrl, error_status: "ERROR" }),
        row({ uuid: NO_URL_ROW_UUID, type, url: null }),
      ];
      findAllAccessibleToUserMock.mockImplementation(async (userId: string) =>
        estate.filter((r) => r.user_id === null || r.user_id === userId),
      );

      const misses: Array<[string, SessionUserDouble | null]> = [
        [OTHER_USERS_UUID, CALLER],
        ["not-a-uuid", CALLER],
        ["undefined", CALLER],
        [OTHER_TYPE_UUID, CALLER],
        [ERROR_ROW_UUID, CALLER],
        [NO_URL_ROW_UUID, CALLER],
        [UNKNOWN_UUID, CALLER],
        [ROW_UUID, null],
      ];
      const answers: Array<{ status: number; body: unknown }> = [];
      for (const [mcpServerUuid, user] of misses) {
        lastJsonBody = undefined;
        const status = await send(
          { transportType: type, mcpServerUuid, url: rowUrl },
          user,
        );
        answers.push({ status, body: lastJsonBody });
      }

      expect(built).toEqual([]);
      expect(answers[0]).toEqual({
        status: 400,
        body: {
          jsonrpc: "2.0",
          error: { code: -32000, message: expect.any(String) },
          id: null,
        },
      });
      for (const answer of answers) expect(answer).toEqual(answers[0]);
      // The message names no row, uuid, address or url.
      const message = JSON.stringify(answers[0].body);
      expect(message).not.toContain("example.com");
      expect(message).not.toContain(OTHER_USERS_UUID);
    },
  );

  it.each(TRANSPORTS)(
    "STILL refuses an internal url with no uuid on %s, even when a visible row has that exact url",
    async (type, rowUrl, send, built) => {
      findAllAccessibleToUserMock.mockResolvedValue([
        row({ type, url: rowUrl }),
        row({ uuid: OWN_ROW_UUID, type, url: rowUrl, user_id: CALLER.id }),
      ]);

      const status = await send({ transportType: type, url: rowUrl });

      expect(built).toEqual([]);
      // The strict path, unchanged: its refusal is the generic 500.
      expect(status).toBe(500);
    },
  );

  it.each([
    ["cloud metadata", ["169.254.169.254"]],
    ["carrier-grade NAT", ["100.64.0.1"]],
    ["a mixed public and private answer", [PUBLIC_V4, INTERNAL_V4]],
    ["a mixed private and public answer", [INTERNAL_V4, PUBLIC_V4]],
  ])(
    "refuses a registered row whose host resolves to %s",
    async (_name, addresses) => {
      resolvesTo(...addresses);

      for (const [type, rowUrl, send, built] of TRANSPORTS) {
        findAllAccessibleToUserMock.mockResolvedValue([
          row({ type, url: rowUrl }),
        ]);
        lastJsonBody = undefined;

        const status = await send({
          transportType: type,
          mcpServerUuid: ROW_UUID,
        });

        expect(built).toEqual([]);
        expect(status).toBe(400);
        expect(lastJsonBody).toMatchObject({ jsonrpc: "2.0", id: null });
      }
    },
  );

  it.each(TRANSPORTS)(
    "refuses a %s request whose host answer turned mixed after the connection opened",
    async (type, rowUrl, send, built) => {
      findAllAccessibleToUserMock.mockResolvedValue([
        row({ type, url: rowUrl }),
      ]);
      // The check before the transport is built sees an internal answer;
      // every lookup after it answers internal and public at once.
      resolvesTo(INTERNAL_V4, PUBLIC_V4);
      lookupMock.mockResolvedValueOnce([{ address: INTERNAL_V4 }]);

      await send({ transportType: type, mcpServerUuid: ROW_UUID });
      expect(built).toHaveLength(1);

      await expect(sendThroughTransport(type, built)).rejects.toThrow(
        NOT_A_PERMITTED_TARGET,
      );
      expect(lookupMock).toHaveBeenCalledTimes(2);
      expect(undiciFetchMock).not.toHaveBeenCalled();
    },
  );

  it("refuses a same-origin redirect hop whose host answer turned mixed", async () => {
    // Internal for the open and for the request's first hop, mixed for the
    // hop the redirect asks for.
    resolvesTo(INTERNAL_V4, PUBLIC_V4);
    lookupMock
      .mockResolvedValueOnce([{ address: INTERNAL_V4 }])
      .mockResolvedValueOnce([{ address: INTERNAL_V4 }]);
    await postMcp({
      transportType: "STREAMABLE_HTTP",
      mcpServerUuid: ROW_UUID,
    });
    undiciFetchMock.mockResolvedValueOnce(
      new Response(null, { status: 307, headers: { location: "/mcp-moved" } }),
    );

    await expect(
      sendThroughTransport("STREAMABLE_HTTP", streamableClientConstructions),
    ).rejects.toThrow(NOT_A_PERMITTED_TARGET);
    expect(lookupMock).toHaveBeenCalledTimes(3);
    expect(undiciFetchMock).toHaveBeenCalledTimes(1);
  });

  it.each(TRANSPORTS)(
    "keeps every %s request on the row's own origin",
    async (type, rowUrl, send, built) => {
      findAllAccessibleToUserMock.mockResolvedValue([
        row({ type, url: rowUrl }),
      ]);
      await send({ transportType: type, mcpServerUuid: ROW_UUID });
      expect(built).toHaveLength(1);
      const { opts } = built[0];
      // Another host on the same private address: the row authorised one
      // origin, not the private network.
      const offOrigin = "http://mcp-other.example.com:3000/mcp";

      await expect(opts.fetch(offOrigin)).rejects.toThrow(
        NOT_A_PERMITTED_TARGET,
      );
      if (type === "SSE") {
        await expect(opts.eventSourceInit.fetch(offOrigin)).rejects.toThrow(
          NOT_A_PERMITTED_TARGET,
        );
      }
      await expect(opts.fetch("http://169.254.169.254/")).rejects.toThrow(
        NOT_A_PERMITTED_TARGET,
      );
      expect(undiciFetchMock).not.toHaveBeenCalled();
    },
  );

  it("refuses a redirect off the row's origin", async () => {
    await postMcp({
      transportType: "STREAMABLE_HTTP",
      mcpServerUuid: ROW_UUID,
    });
    undiciFetchMock.mockResolvedValueOnce(
      new Response(null, {
        status: 302,
        headers: { location: "http://mcp-other.example.com:3000/mcp" },
      }),
    );

    await expect(
      sendThroughTransport("STREAMABLE_HTTP", streamableClientConstructions),
    ).rejects.toThrow(CROSS_ORIGIN_REDIRECT_REFUSED);
    expect(undiciFetchMock).toHaveBeenCalledTimes(1);
  });

  it.each(TRANSPORTS)(
    "sends X-Gateway-Auth over %s to an internal row and not to a public one",
    async (type, rowUrl, send, built) => {
      process.env.GATEWAY_BACKEND_SECRET = GATEWAY_SECRET;
      findAllAccessibleToUserMock.mockResolvedValue([
        row({ type, url: rowUrl }),
      ]);

      await send({ transportType: type, mcpServerUuid: ROW_UUID });
      await sendThroughTransport(type, built);
      expect(wireHeaders().get("x-gateway-auth")).toBe(GATEWAY_SECRET);

      built.length = 0;
      undiciFetchMock.mockClear();
      resolvesTo(PUBLIC_V4);
      await send({ transportType: type, mcpServerUuid: ROW_UUID });
      await sendThroughTransport(type, built);
      expect(wireHeaders().has("x-gateway-auth")).toBe(false);
    },
  );

  it.each(TRANSPORTS)(
    "never puts a row's stored X-Umbrella-User-Id or X-Umbrella-Caller on the %s wire",
    async (type, rowUrl, send, built) => {
      // The row is NOT a named verified-caller backend, so nothing strips
      // these by row name; only the destination rule can.
      process.env.VERIFIED_CALLER_SERVER_NAMES = "team";
      findAllAccessibleToUserMock.mockResolvedValue([
        row({
          type,
          url: rowUrl,
          headers: {
            "X-Umbrella-User-Id": "user-stored",
            "x-umbrella-caller": "v1.stored",
            "x-vendor-api-key": "backend-key",
          },
        }),
      ]);

      await send({ transportType: type, mcpServerUuid: ROW_UUID });
      await sendThroughTransport(type, built);

      const wire = wireHeaders();
      expect(wire.has("x-umbrella-user-id")).toBe(false);
      expect(wire.has("x-umbrella-caller")).toBe(false);
      expect(wire.get("x-vendor-api-key")).toBe("backend-key");
    },
  );

  it("replaces the browser's and the row's X-MCP-Actor with the session email", async () => {
    findAllAccessibleToUserMock.mockResolvedValue([
      row({ headers: { "X-MCP-Actor": "stored@example.com" } }),
    ]);

    await postMcp(
      { transportType: "STREAMABLE_HTTP", mcpServerUuid: ROW_UUID },
      SESSION,
      { "x-mcp-actor": "browser@example.com" },
    );
    await sendThroughTransport(
      "STREAMABLE_HTTP",
      streamableClientConstructions,
    );

    expect(wireHeaders().get("x-mcp-actor")).toBe(SESSION.email);
  });

  it("sends no X-MCP-Actor when the session has no email, whatever the browser sent", async () => {
    await postMcp(
      { transportType: "STREAMABLE_HTTP", mcpServerUuid: ROW_UUID },
      CALLER,
      { "x-mcp-actor": "browser@example.com" },
    );
    await sendThroughTransport(
      "STREAMABLE_HTTP",
      streamableClientConstructions,
    );

    expect(wireHeaders().has("x-mcp-actor")).toBe(false);
  });

  it("sends no X-MCP-Actor to a public registered row", async () => {
    resolvesTo(PUBLIC_V4);

    await postMcp(
      { transportType: "STREAMABLE_HTTP", mcpServerUuid: ROW_UUID },
      SESSION,
    );
    await sendThroughTransport(
      "STREAMABLE_HTTP",
      streamableClientConstructions,
    );

    expect(wireHeaders().has("x-mcp-actor")).toBe(false);
  });

  it("connects a localhost row by uuid with the localhost transform on", async () => {
    process.env.TRANSFORM_LOCALHOST_TO_DOCKER_INTERNAL = "true";
    resolvesTo("172.17.0.1");
    findAllAccessibleToUserMock.mockResolvedValue([
      row({ url: "http://localhost:3000/mcp" }),
    ]);

    await postMcp({
      transportType: "STREAMABLE_HTTP",
      mcpServerUuid: ROW_UUID,
    });

    expect(streamableClientConstructions).toHaveLength(1);
    expect(streamableClientConstructions[0].url.href).toBe(
      "http://host.docker.internal:3000/mcp",
    );
  });

  it.each([
    [
      "the row's OAuth access token",
      { tokens: { access_token: "row-oauth-token" } },
      "row-bearer-token",
      "Bearer row-oauth-token",
    ],
    [
      "the row's stored bearer",
      undefined,
      "row-bearer-token",
      "Bearer row-bearer-token",
    ],
    [
      "the browser's, when the row has none",
      undefined,
      null,
      "Bearer browser-token",
    ],
  ])(
    "authorizes with %s",
    async (_name, oauthSession, bearerToken, expected) => {
      findOAuthSessionMock.mockResolvedValue(oauthSession);
      findAllAccessibleToUserMock.mockResolvedValue([row({ bearerToken })]);

      await postMcp(
        { transportType: "STREAMABLE_HTTP", mcpServerUuid: ROW_UUID },
        CALLER,
        { authorization: "Bearer browser-token" },
      );
      await sendThroughTransport(
        "STREAMABLE_HTTP",
        streamableClientConstructions,
      );

      expect(findOAuthSessionMock).toHaveBeenCalledWith(ROW_UUID);
      expect(wireHeaders().get("authorization")).toBe(expected);
    },
  );

  // Oracle: lib/m365/injected-fetch.ts invariants 1, 2 and 7. A backend named
  // in M365_INJECTED_SERVER_NAMES takes Authorization only as a token the
  // gateway minted for the request's user, and this path mints none.
  it.each([
    // The top-level beforeEach leaves the list unset, so the default applies.
    ["the default list", "", "m365"],
    ["a configured list", "m365, graph-broker", "graph-broker"],
  ])(
    "sends no Authorization from any source to a row on %s of m365-injected servers",
    async (_name, injectedNames, rowName) => {
      vi.stubEnv("M365_INJECTED_SERVER_NAMES", injectedNames);
      process.env.GATEWAY_BACKEND_SECRET = GATEWAY_SECRET;
      findOAuthSessionMock.mockResolvedValue({
        tokens: { access_token: "row-oauth-token" },
      });

      for (const [type, rowUrl, send, built] of TRANSPORTS) {
        findAllAccessibleToUserMock.mockResolvedValue([
          row({
            name: rowName,
            type,
            url: rowUrl,
            bearerToken: "row-bearer-token",
            headers: {
              Authorization: "Bearer stored-header-token",
              "x-vendor-api-key": "backend-key",
            },
          }),
        ]);
        undiciFetchMock.mockClear();

        await send({ transportType: type, mcpServerUuid: ROW_UUID }, SESSION, {
          authorization: "Bearer browser-token",
        });
        await sendThroughTransport(type, built);

        const wire = wireHeaders();
        expect(wire.has("authorization")).toBe(false);
        expect(wire.get("x-gateway-auth")).toBe(GATEWAY_SECRET);
        expect(wire.get("x-vendor-api-key")).toBe("backend-key");
      }
    },
  );

  it("logs the SSE connection by row name and uuid, never by url", async () => {
    findAllAccessibleToUserMock.mockResolvedValue([
      row({ type: "SSE", url: `${BACKEND_SSE}?api_key=ROW-SECRET` }),
    ]);

    await getSse({ transportType: "SSE", mcpServerUuid: ROW_UUID });

    const line = loggerInfo.mock.calls
      .map((call) => String(call[0]))
      .find((text) => text.startsWith("SSE transport:"));
    expect(line).toContain(`server=backend (${ROW_UUID})`);
    expect(line).not.toContain("mcp-backend.example.com");
    expect(line).not.toContain("ROW-SECRET");
  });
});
