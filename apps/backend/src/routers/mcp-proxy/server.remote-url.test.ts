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

vi.mock("@/utils/logger", () => ({
  default: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

const {
  sseClientConstructions,
  streamableClientConstructions,
  lookupMock,
  findAllMock,
} = vi.hoisted(() => ({
  /** Every SSEClientTransport construction, in order. */
  sseClientConstructions: [] as Array<{ url: URL; opts: any }>,
  /** Every StreamableHTTPClientTransport construction, in order. */
  streamableClientConstructions: [] as Array<{ url: URL; opts: any }>,
  lookupMock: vi.fn(),
  findAllMock: vi.fn(),
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

vi.mock("../../db/repositories", () => ({
  mcpServersRepository: {
    findAll: findAllMock,
    findByUuid: vi.fn(),
    findAllAccessibleToUser: vi.fn(async () => []),
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

const resolvesTo = (...addresses: string[]) =>
  lookupMock.mockResolvedValue(addresses.map((address) => ({ address })));

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
): Promise<number> {
  const search = new URLSearchParams(query).toString();
  const req = {
    method,
    url: `${path}?${search}`,
    originalUrl: `/mcp-proxy/server${path}?${search}`,
    baseUrl: "",
    query: Object.fromEntries(new URLSearchParams(search)),
    headers: {},
    user: { id: "user-owner", role: "admin" },
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

const getSse = (query: Record<string, string>) => drive("GET", "/sse", query);
const postMcp = (query: Record<string, string>) => drive("POST", "/mcp", query);

beforeEach(() => {
  vi.clearAllMocks();
  sseClientConstructions.length = 0;
  streamableClientConstructions.length = 0;
  findAllMock.mockResolvedValue([]);
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

    expect(findAllMock).not.toHaveBeenCalled();
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
