/**
 * What the REMOTE-URL branches of the mcp-proxy actually connect to.
 *
 * `url-guard.test.ts` next door pins the validator — given a URL, is it a
 * public destination. That is necessary and NOT sufficient, and the gap is why
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
import { beforeEach, describe, expect, it, vi } from "vitest";

const { loggerInfo } = vi.hoisted(() => ({ loggerInfo: vi.fn() }));

vi.mock("@/utils/logger", () => ({
  default: { info: loggerInfo, warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

const {
  sseClientConstructions,
  streamableClientConstructions,
  lookupMock,
  findAllAccessibleToUserMock,
} = vi.hoisted(() => ({
  /** Every SSEClientTransport construction, in order. */
  sseClientConstructions: [] as Array<{ url: URL; opts: any }>,
  /** Every StreamableHTTPClientTransport construction, in order. */
  streamableClientConstructions: [] as Array<{ url: URL; opts: any }>,
  lookupMock: vi.fn(),
  findAllAccessibleToUserMock: vi.fn(),
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

vi.mock("../../lib/metamcp/client", () => ({
  transformDockerUrl: (url: string) => url,
}));

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
}));

// `db/index.ts` throws without DATABASE_URL.
vi.mock("../../db/index", () => ({ db: {}, pool: {} }));

// The resolver the deployed path uses. Mocked here rather than injected so the
// route keeps calling the guard exactly as production does.
vi.mock("node:dns/promises", () => ({ lookup: lookupMock }));

const { default: serverRouter } = await import("./server");
const { NOT_A_PERMITTED_TARGET } = await import("./url-guard");

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

/** Minimal express res double; the routes only stream or 500. */
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
    json() {
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

/** Drive one of the real routes and settle. */
async function drive(
  method: "GET" | "POST",
  path: string,
  query: Record<string, string>,
  /** `null` means the request arrives with NO session user at all. */
  user: { id?: string; role?: string } | null = CALLER,
): Promise<number> {
  const search = new URLSearchParams(query).toString();
  const req = {
    method,
    url: `${path}?${search}`,
    originalUrl: `/mcp-proxy/server${path}?${search}`,
    baseUrl: "",
    query: Object.fromEntries(new URLSearchParams(search)),
    headers: {},
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
  user: { id?: string; role?: string } | null = CALLER,
) => drive("GET", "/sse", query, user);
const postMcp = (
  query: Record<string, string>,
  user: { id?: string; role?: string } | null = CALLER,
) => drive("POST", "/mcp", query, user);

beforeEach(() => {
  vi.clearAllMocks();
  sseClientConstructions.length = 0;
  streamableClientConstructions.length = 0;
  findAllAccessibleToUserMock.mockResolvedValue([]);
  resolvesTo(PUBLIC_V4);
  delete process.env.MCP_PROXY_URL_ALLOWED_HOSTS;
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
