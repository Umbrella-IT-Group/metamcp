/**
 * The request-body ceilings applied ahead of every router: the declared-length
 * guard (`declaredLengthGuard`, 10 MiB on every path and method) and the
 * per-surface lanes `globalBodyParser` picks (`/api/auth` 64kb, `/trpc` 1mb,
 * and the 64 KiB default lane for everything that is not a raw stream, OAuth,
 * auth or tRPC).
 *
 * Both are routing-order behaviour, which looks right in a diff and is wrong
 * on the wire, so these run over a REAL socket against the REAL middleware
 * `index.ts` mounts. The `unfixed` app reconstructs the earlier wiring (one
 * 50mb parser for everything non-raw, non-OAuth) as the control the fixed app
 * is compared against; its 50mb is written out rather than imported, because
 * it models code that no longer exists.
 *
 * WHY THE HEADERS-ONLY REQUESTS. body-parser 2.x detects an oversized declared
 * length without buffering, but it then reads the rest of the request before
 * it hands the 413 on (`read.js` dumps the stream and waits for its end), so
 * a parser limit alone answers only once the whole declared body has arrived.
 * The cases that matter therefore send the headers and nothing else, never
 * end the request, and require the 413 and the server's close inside a short
 * deadline. A limit-only implementation (a smaller `limit` with no
 * declared-length check) fails them at the deadline.
 */

import http, { type Server } from "node:http";
import net from "node:net";
import { deflateSync, gzipSync } from "node:zlib";

import express from "express";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

vi.mock("@/utils/logger", () => ({
  default: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

// The real m365 router is mounted below for its authentication outcome only;
// these are the seams `routers/m365.test.ts` mocks for the same reason.
vi.mock("@/auth", () => ({
  auth: { api: { getSession: vi.fn().mockResolvedValue(null) } },
}));
vi.mock("@/db/repositories/m365-tokens.repo", () => ({
  m365TokensRepository: {
    findByUserId: vi.fn(async () => undefined),
    upsertEnrollment: vi.fn(async () => ({})),
    deleteByUserId: vi.fn(async () => true),
  },
}));
vi.mock("@/db/repositories/users.repo", () => ({
  usersRepository: { isDisabled: vi.fn(async () => false) },
}));

process.env.APP_URL = "https://gateway.example.test";
process.env.BETTER_AUTH_SECRET = "test-secret-for-body-limit-lanes";

const bodyParserModule = await import("./global-body-parser");
const { globalBodyParser, AUTH_RELAY_BODY_LIMIT, TRPC_BODY_LIMIT } =
  bodyParserModule;
const { errorHandler, BAD_REQUEST_BODY } = await import(
  "../middleware/error-handler.middleware"
);
const { MCP_REQUEST_BODY_LIMIT_BYTES } = await import(
  "./metamcp/mcp-request-body-limit"
);
const { default: m365Router } = await import("../routers/m365");

/** Over 64kb and over 1mb respectively, both comfortably under 50mb. */
const OVER_AUTH_BYTES = 100 * 1024;
const OVER_TRPC_BYTES = 1200 * 1024;
/** Under 1mb but over 64kb: accepted on /trpc, refused on /api/auth. */
const MID_BYTES = 300 * 1024;

/** The default lane's ceiling, written out so a drift in the constant shows. */
const DEFAULT_LANE_BYTES = 64 * 1024;
/** The frontend's forwarding limit plus one byte. */
const OVER_FORWARDED_BYTES = 10 * 1024 * 1024 + 1;

/** How long a refusal may take. Generous for CI; a waiting parser never meets it. */
const DEADLINE_MS = 2000;

const NEUTRAL_413_BODY = JSON.stringify(BAD_REQUEST_BODY);

type Started = { server: Server; baseUrl: string; port: number };

async function listen(app: express.Express): Promise<Started> {
  const server = await new Promise<Server>((resolve) => {
    const s = app.listen(0, "127.0.0.1", () => resolve(s));
  });
  const address = server.address();
  const port = typeof address === "object" && address ? address.port : 0;
  return { server, port, baseUrl: `http://127.0.0.1:${port}` };
}

async function close(started: Started | undefined): Promise<void> {
  if (!started) return;
  // A test that timed out leaves its client socket destroyed but the server's
  // side may still be open; closeAllConnections keeps close() from waiting.
  started.server.closeAllConnections();
  await new Promise((resolve) => started.server.close(resolve));
}

/** Answers with whether a parser ran, so parsing is observable downstream. */
const echo = (req: express.Request, res: express.Response) => {
  const body = req.body as { blob?: unknown } | undefined;
  res.status(200).json({
    received: typeof body === "object",
    blobLength: typeof body?.blob === "string" ? body.blob.length : null,
  });
};

async function startApp(fixed: boolean): Promise<Started> {
  const app = express();

  if (fixed) {
    app.use(globalBodyParser);
  } else {
    // The earlier wiring: one generous parser for everything that is not a
    // raw stream, kept only as the control.
    app.use((req, res, next) => {
      if (
        req.path.startsWith("/mcp-proxy/") ||
        req.path.startsWith("/metamcp/")
      ) {
        next();
      } else {
        express.json({ limit: "50mb" })(req, res, next);
      }
    });
  }

  app.post("/api/auth/sign-up/email", echo);
  app.post("/api/auth/sign-in/email", echo);
  app.post("/trpc/frontend/anything", echo);
  // Default-lane stand-ins: the real handlers at these paths are GETs (and the
  // m365 POST reads no body), so an echo here shows what the lane parsed.
  app.post("/health", echo);
  app.post("/health/upstream", echo);
  app.post("/m365/disconnect", echo);
  app.post("/other/anything", echo);

  app.use(errorHandler);
  return listen(app);
}

interface RawResponse {
  status: number | undefined;
  headers: Record<string, string>;
  body: string;
  /** The server ended or reset the connection before the deadline. */
  closed: boolean;
  timedOut: boolean;
  elapsedMs: number;
}

/**
 * One HTTP/1.1 request over a bare TCP socket, so the test controls exactly
 * which bytes are sent. The request is never ended from this side: with no
 * `body`, only the head goes out. Resolves when the server closes the
 * connection, when the response is complete (if `waitForClose` is false), or
 * at the deadline. The socket is destroyed on every path.
 */
function rawRequest(
  port: number,
  options: {
    method?: string;
    path: string;
    headers: Record<string, string | number | string[]>;
    body?: Buffer;
    waitForClose?: boolean;
  },
): Promise<RawResponse> {
  const { method = "POST", path, headers, body, waitForClose = true } = options;
  const started = Date.now();

  return new Promise((resolve) => {
    const socket = net.connect({ host: "127.0.0.1", port });
    let received = Buffer.alloc(0);
    let closed = false;
    let settled = false;

    const parse = () => {
      const headEnd = received.indexOf("\r\n\r\n");
      if (headEnd === -1) return undefined;
      const [statusLine, ...lines] = received
        .subarray(0, headEnd)
        .toString("latin1")
        .split("\r\n");
      const parsedHeaders: Record<string, string> = {};
      for (const line of lines) {
        const colon = line.indexOf(":");
        parsedHeaders[line.slice(0, colon).trim().toLowerCase()] = line
          .slice(colon + 1)
          .trim();
      }
      const length = Number(parsedHeaders["content-length"] ?? 0);
      const bodyBytes = received.subarray(headEnd + 4);
      return {
        status: Number(statusLine.split(" ")[1]),
        headers: parsedHeaders,
        body: bodyBytes.subarray(0, length).toString("utf8"),
        complete: bodyBytes.length >= length,
      };
    };

    const finish = (timedOut: boolean) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      const parsed = parse();
      resolve({
        status: parsed?.status,
        headers: parsed?.headers ?? {},
        body: parsed?.body ?? "",
        closed,
        timedOut,
        elapsedMs: Date.now() - started,
      });
    };

    const timer = setTimeout(() => finish(true), DEADLINE_MS);

    socket.on("connect", () => {
      const head = [
        `${method} ${path} HTTP/1.1`,
        "Host: 127.0.0.1",
        ...Object.entries(headers).flatMap(([name, value]) =>
          (Array.isArray(value) ? value : [value]).map(
            (entry) => `${name}: ${entry}`,
          ),
        ),
        "",
        "",
      ].join("\r\n");
      socket.write(head);
      if (body) socket.write(body);
    });
    socket.on("data", (chunk: Buffer) => {
      received = Buffer.concat([received, chunk]);
      if (!waitForClose && parse()?.complete) finish(false);
    });
    socket.on("end", () => {
      closed = true;
      finish(false);
    });
    // A reset or a write after the server closed is still the server ending
    // the connection; whatever response arrived first is kept.
    socket.on("error", () => {
      closed = true;
      finish(false);
    });
  });
}

/** A JSON object whose serialised form is exactly `bytes` long. */
function jsonOfLength(bytes: number): Buffer {
  const overhead = Buffer.byteLength('{"blob":""}');
  const body = Buffer.from(
    JSON.stringify({ blob: "x".repeat(bytes - overhead) }),
  );
  expect(body.length).toBe(bytes);
  return body;
}

/** POST with no Content-Length, so Node sends the body chunked. */
function postChunked(
  port: number,
  path: string,
  chunks: Buffer[],
  headers: Record<string, string>,
): Promise<{ status: number | undefined; body: string }> {
  return new Promise((resolve, reject) => {
    const request = http.request(
      {
        host: "127.0.0.1",
        port,
        path,
        method: "POST",
        agent: false,
        headers: { ...headers, "Transfer-Encoding": "chunked" },
      },
      (response) => {
        const parts: Buffer[] = [];
        response.on("data", (part: Buffer) => parts.push(part));
        response.on("end", () =>
          resolve({
            status: response.statusCode,
            body: Buffer.concat(parts).toString("utf8"),
          }),
        );
      },
    );
    request.on("error", reject);
    for (const chunk of chunks) request.write(chunk);
    request.end();
  });
}

let fixed: Started;
let unfixed: Started;

beforeAll(async () => {
  fixed = await startApp(true);
  unfixed = await startApp(false);
});

afterAll(async () => {
  await close(fixed);
  await close(unfixed);
});

function postJson(baseUrl: string, path: string, body: unknown) {
  return fetch(`${baseUrl}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

describe("/api/auth body limit", () => {
  it("pins the limit at 64kb", () => {
    expect(AUTH_RELAY_BODY_LIMIT).toBe("64kb");
  });

  it("refuses an oversized sign-up body with 413", async () => {
    const response = await postJson(fixed.baseUrl, "/api/auth/sign-up/email", {
      password: "x".repeat(OVER_AUTH_BYTES),
    });
    expect(response.status).toBe(413);
  });

  it("refuses an oversized sign-in body with 413", async () => {
    const response = await postJson(fixed.baseUrl, "/api/auth/sign-in/email", {
      password: "x".repeat(OVER_AUTH_BYTES),
    });
    expect(response.status).toBe(413);
  });

  it("accepts a real sign-in body", async () => {
    const response = await postJson(fixed.baseUrl, "/api/auth/sign-in/email", {
      email: "user@example.test",
      password: "correct horse battery staple",
    });
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      received: true,
      blobLength: null,
    });
  });

  it("bound the 64kb limit, not the 50mb control", async () => {
    // The regression guard for the routing order. Remove the /api/auth lane
    // from globalBodyParser and this body is parsed by another parser and
    // reaches the handler with a 200 instead.
    const withLane = await postJson(fixed.baseUrl, "/api/auth/sign-in/email", {
      password: "x".repeat(OVER_AUTH_BYTES),
    });
    const withoutLane = await postJson(
      unfixed.baseUrl,
      "/api/auth/sign-in/email",
      { password: "x".repeat(OVER_AUTH_BYTES) },
    );
    expect(withLane.status).toBe(413);
    expect(withoutLane.status).not.toBe(413);
  });
});

describe("/trpc body limit", () => {
  it("pins the limit at 1mb", () => {
    expect(TRPC_BODY_LIMIT).toBe("1mb");
  });

  it("refuses an oversized tRPC body with 413", async () => {
    const response = await postJson(fixed.baseUrl, "/trpc/frontend/anything", {
      blob: "x".repeat(OVER_TRPC_BYTES),
    });
    expect(response.status).toBe(413);
  });

  it("accepts a body under 1mb that /api/auth would refuse", async () => {
    // 300kb is over the 64kb auth ceiling and under the 1mb tRPC ceiling, so a
    // 200 here can only mean the tRPC lane bound its own larger limit.
    const response = await postJson(fixed.baseUrl, "/trpc/frontend/anything", {
      blob: "x".repeat(MID_BYTES),
    });
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      received: true,
      blobLength: MID_BYTES,
    });
  });

  it("bound the 1mb limit, not the 50mb control", async () => {
    const withLane = await postJson(fixed.baseUrl, "/trpc/frontend/anything", {
      blob: "x".repeat(OVER_TRPC_BYTES),
    });
    const withoutLane = await postJson(
      unfixed.baseUrl,
      "/trpc/frontend/anything",
      { blob: "x".repeat(OVER_TRPC_BYTES) },
    );
    expect(withLane.status).toBe(413);
    expect(withoutLane.status).not.toBe(413);
  });
});

describe("the default JSON lane", () => {
  it("pins the limit at 64 KiB", () => {
    expect(bodyParserModule.DEFAULT_JSON_BODY_LIMIT_BYTES).toBe(
      DEFAULT_LANE_BYTES,
    );
  });

  const paths = [
    "/health",
    "/health/upstream",
    "/m365/disconnect",
    "/no-such-route",
  ];
  const declared = [DEFAULT_LANE_BYTES + 1, OVER_FORWARDED_BYTES];

  it.each(
    paths.flatMap((path) => declared.map((bytes) => [path, bytes] as const)),
  )(
    "answers %s declaring %i JSON bytes with 413 and closes, from the headers alone",
    async (path, bytes) => {
      const response = await rawRequest(fixed.port, {
        path,
        headers: {
          "Content-Type": "application/json",
          "Content-Length": bytes,
        },
      });

      expect(response.timedOut).toBe(false);
      expect(response.status).toBe(413);
      expect(response.body).toBe(NEUTRAL_413_BODY);
      expect(response.headers["connection"]).toBe("close");
      expect(response.closed).toBe(true);
      expect(response.elapsedMs).toBeLessThan(DEADLINE_MS);
    },
  );

  it("matches a JSON media type with parameters, as the parser does", async () => {
    const response = await rawRequest(fixed.port, {
      path: "/health",
      headers: {
        "Content-Type": "application/json; charset=utf-8",
        "Content-Length": DEFAULT_LANE_BYTES + 1,
      },
    });

    expect(response.status).toBe(413);
    expect(response.closed).toBe(true);
  });

  it("parses valid JSON of exactly 64 KiB", async () => {
    const body = jsonOfLength(DEFAULT_LANE_BYTES);
    const response = await fetch(`${fixed.baseUrl}/health`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body,
    });

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      received: true,
      blobLength: DEFAULT_LANE_BYTES - Buffer.byteLength('{"blob":""}'),
    });
  });

  it("refuses a complete JSON body one byte over 64 KiB", async () => {
    const response = await rawRequest(fixed.port, {
      path: "/other/anything",
      headers: {
        "Content-Type": "application/json",
        "Content-Length": DEFAULT_LANE_BYTES + 1,
      },
      body: jsonOfLength(DEFAULT_LANE_BYTES + 1),
      waitForClose: false,
    });

    expect(response.status).toBe(413);
    expect(response.body).toBe(NEUTRAL_413_BODY);
  });

  it("accepted the same body on the 50mb control", async () => {
    // The before half of the change, kept so the 413 above reads as the new
    // lane binding rather than something else refusing the request.
    const response = await fetch(`${unfixed.baseUrl}/other/anything`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: jsonOfLength(DEFAULT_LANE_BYTES + 1),
    });

    expect(response.status).toBe(200);
  });

  it("still parses a small chunked JSON body", async () => {
    const response = await postChunked(
      fixed.port,
      "/other/anything",
      [Buffer.from('{"blob":'), Buffer.from('"abc"}')],
      { "Content-Type": "application/json" },
    );

    expect(response.status).toBe(200);
    expect(JSON.parse(response.body)).toEqual({
      received: true,
      blobLength: 3,
    });
  });

  it("refuses a finite chunked JSON body over 64 KiB through the parser", async () => {
    // No Content-Length, so the declared-length check has nothing to read and
    // the parser's own limit is what binds.
    const body = jsonOfLength(DEFAULT_LANE_BYTES + 1024);
    const response = await postChunked(
      fixed.port,
      "/other/anything",
      [body.subarray(0, 40_000), body.subarray(40_000)],
      { "Content-Type": "application/json" },
    );

    expect(response.status).toBe(413);
    expect(response.body).toBe(NEUTRAL_413_BODY);
  });

  const encodings = [
    ["gzip", gzipSync],
    ["deflate", deflateSync],
  ] as const;

  it.each(encodings)(
    "still inflates a small %s JSON body",
    async (encoding, compress) => {
      const response = await fetch(`${fixed.baseUrl}/other/anything`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Content-Encoding": encoding,
        },
        body: compress(JSON.stringify({ blob: "abc" })),
      });

      expect(response.status).toBe(200);
      expect(await response.json()).toEqual({ received: true, blobLength: 3 });
    },
  );

  it.each(encodings)(
    "refuses %s JSON whose decoded size is over 64 KiB",
    async (encoding, compress) => {
      // A few hundred bytes on the wire, so the declared length passes; the
      // parser's decoded-size limit still binds after inflation.
      const compressed = compress(jsonOfLength(4 * DEFAULT_LANE_BYTES));
      expect(compressed.length).toBeLessThan(DEFAULT_LANE_BYTES);

      const response = await fetch(`${fixed.baseUrl}/other/anything`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Content-Encoding": encoding,
        },
        body: compressed,
      });

      expect(response.status).toBe(413);
      expect(await response.text()).toBe(NEUTRAL_413_BODY);
    },
  );

  it("leaves a small non-JSON body unparsed, as before", async () => {
    for (const app of [fixed, unfixed]) {
      const response = await fetch(`${app.baseUrl}/other/anything`, {
        method: "POST",
        headers: { "Content-Type": "text/plain" },
        body: "hello",
      });

      expect(response.status).toBe(200);
      expect(await response.json()).toEqual({
        received: false,
        blobLength: null,
      });
    }
  });

  it("does not apply the JSON check to another media type", async () => {
    // Tied to the parser's media-type match: a request the JSON parser would
    // not read reaches its handler whatever length it declares (under the
    // forwarding limit), exactly as before.
    const response = await rawRequest(fixed.port, {
      path: "/other/anything",
      headers: {
        "Content-Type": "text/plain",
        "Content-Length": DEFAULT_LANE_BYTES + 1,
      },
      waitForClose: false,
    });

    expect(response.status).toBe(200);
    expect(JSON.parse(response.body)).toEqual({
      received: false,
      blobLength: null,
    });
  });
});

describe("POST /m365/disconnect through the default lane", () => {
  let m365: Started;

  beforeAll(async () => {
    const app = express();
    app.use(globalBodyParser);
    app.use(m365Router);
    app.use(errorHandler);
    m365 = await listen(app);
  });

  afterAll(async () => {
    await close(m365);
  });

  it("keeps its authentication outcome with no body and with a small JSON body", async () => {
    const bare = await fetch(`${m365.baseUrl}/m365/disconnect`, {
      method: "POST",
    });
    const withJson = await postJson(m365.baseUrl, "/m365/disconnect", {
      confirm: true,
    });

    for (const response of [bare, withJson]) {
      expect(response.status).toBe(401);
      expect(await response.json()).toEqual({
        error: "authentication_required",
      });
    }
  });
});

describe("declaredLengthGuard", () => {
  let guarded: Started;

  beforeAll(async () => {
    // index.ts order: the guard, then the lanes, then routers. Every stand-in
    // below reads its body, so a request the guard let through would wait for
    // bytes that never come and miss the deadline.
    const app = express();
    app.use(bodyParserModule.declaredLengthGuard);
    app.use(globalBodyParser);

    // The OAuth router's own parser (globalBodyParser leaves /oauth unparsed).
    app.post(
      ["/oauth/token", "/oauth/register"],
      express.json({ limit: "256kb" }),
      echo,
    );
    app.post("/api/auth/sign-in/email", echo);
    app.post("/trpc/frontend/anything", echo);
    app.post("/health", echo);
    app.get("/health/upstream", echo);

    // Raw MCP streams read the socket themselves.
    const readToEnd = async (req: express.Request, res: express.Response) => {
      let length = 0;
      for await (const chunk of req) length += (chunk as Buffer).length;
      res.status(200).json({ length });
    };

    // The public router, in its real order: the MCP stream, the OpenAPI
    // bridge's parser, then the admin router's parser on everything that
    // falls through to it.
    const publicRouter = express.Router();
    publicRouter.all("/:endpoint_name/mcp", readToEnd);
    publicRouter.post("/:endpoint_name/api/:tool_name", express.json(), echo);
    // Answers without reading, to show what the guard lets through.
    publicRouter.post("/:endpoint_name/probe", (req, res) => {
      res.status(200).json({ reached: true });
    });
    publicRouter.use(express.json());
    publicRouter.all("/:endpoint_name/admin/error-status", echo);
    app.use("/metamcp", publicRouter);
    app.post("/mcp-proxy/server/mcp", readToEnd);

    app.use(errorHandler);
    guarded = await listen(app);
  });

  afterAll(async () => {
    await close(guarded);
  });

  it("refuses above the same 10 MiB the MCP routes and the frontend's forwarding use", () => {
    // The guard reuses MCP_REQUEST_BODY_LIMIT_BYTES. That constant is pinned
    // against the frontend's Next.js forwarding limit (10 MiB by default; the
    // config sets none) in metamcp/mcp-request-body-limit.test.ts, so the two
    // must move together: raising one without the other either refuses bodies
    // Next would carry or lets through declared lengths Next never forwards.
    expect(MCP_REQUEST_BODY_LIMIT_BYTES).toBe(10 * 1024 * 1024);
    expect(OVER_FORWARDED_BYTES).toBe(MCP_REQUEST_BODY_LIMIT_BYTES + 1);
  });

  it.each([
    ["POST", "/health", "application/json"],
    ["POST", "/oauth/token", "application/json"],
    ["POST", "/oauth/register", "application/json"],
    ["POST", "/oauth/token", "application/x-www-form-urlencoded"],
    ["POST", "/api/auth/sign-in/email", "application/json"],
    ["POST", "/trpc/frontend/anything", "application/json"],
    ["POST", "/metamcp/x/admin/error-status", "application/json"],
    ["POST", "/metamcp/x/api/x__tool", "application/json"],
    ["POST", "/metamcp/x/mcp", "application/json"],
    ["DELETE", "/metamcp/x/mcp", "application/json"],
    ["POST", "/mcp-proxy/server/mcp", "application/json"],
    ["GET", "/health/upstream", "application/json"],
    ["PUT", "/no-such-route", "application/octet-stream"],
  ])(
    "answers %s %s (%s) declaring 10 MiB + 1 with 413 and closes, from the headers alone",
    async (method, path, contentType) => {
      const response = await rawRequest(guarded.port, {
        method,
        path,
        headers: {
          "Content-Type": contentType,
          "Content-Length": OVER_FORWARDED_BYTES,
        },
      });

      expect(response.timedOut).toBe(false);
      expect(response.status).toBe(413);
      expect(response.headers["content-type"]).toMatch(/^application\/json/);
      expect(response.body).toBe(NEUTRAL_413_BODY);
      expect(response.headers["connection"]).toBe("close");
      expect(response.closed).toBe(true);
      expect(response.elapsedMs).toBeLessThan(DEADLINE_MS);
    },
  );

  it("lets a declared length of exactly 10 MiB through to the route", async () => {
    const response = await rawRequest(guarded.port, {
      path: "/metamcp/x/probe",
      headers: {
        "Content-Type": "application/json",
        "Content-Length": MCP_REQUEST_BODY_LIMIT_BYTES,
      },
      waitForClose: false,
    });

    expect(response.status).toBe(200);
    expect(JSON.parse(response.body)).toEqual({ reached: true });
  });

  it.each([
    ["leading zeros", "00010485761"],
    ["a value above Number.MAX_SAFE_INTEGER", "9007199254740993"],
  ])("refuses an oversized length with %s", async (_label, length) => {
    const response = await rawRequest(guarded.port, {
      path: "/metamcp/x/probe",
      headers: { "Content-Length": length },
    });

    expect(response.timedOut).toBe(false);
    expect(response.status).toBe(413);
    expect(response.body).toBe(NEUTRAL_413_BODY);
    expect(response.headers["connection"]).toBe("close");
    expect(response.closed).toBe(true);
  });

  it.each([["leading zeros", "00010485760"]])(
    "allows exactly 10 MiB with %s",
    async (_label, length) => {
      const response = await rawRequest(guarded.port, {
        path: "/metamcp/x/probe",
        headers: { "Content-Length": length },
        waitForClose: false,
      });

      expect(response.timedOut).toBe(false);
      expect(response.status).toBe(200);
      expect(JSON.parse(response.body)).toEqual({ reached: true });
    },
  );

  // Node's HTTP parser treats optional whitespace around Content-Length
  // differently across major versions: Node 20 (the runtime image and CI)
  // refuses the request with 400 before any route runs, while later majors
  // trim it and hand the request on. Either answer is acceptable here; what
  // must never happen is an oversized declared length reaching a handler or
  // waiting for its body.
  it("never lets an oversized length padded with HTTP whitespace through", async () => {
    const response = await rawRequest(guarded.port, {
      path: "/metamcp/x/probe",
      headers: { "Content-Length": "\t10485761 \t" },
    });

    expect(response.timedOut).toBe(false);
    expect([400, 413]).toContain(response.status);
    if (response.status === 413) {
      expect(response.body).toBe(NEUTRAL_413_BODY);
      expect(response.headers["connection"]).toBe("close");
    }
  });

  it("treats exactly 10 MiB padded with HTTP whitespace as the parser does", async () => {
    const response = await rawRequest(guarded.port, {
      path: "/metamcp/x/probe",
      headers: { "Content-Length": "\t10485760 \t" },
      waitForClose: false,
    });

    expect(response.timedOut).toBe(false);
    expect([200, 400]).toContain(response.status);
    if (response.status === 200) {
      expect(JSON.parse(response.body)).toEqual({ reached: true });
    }
  });

  const invalidFramings: Array<
    [string, Record<string, string | number | string[]>]
  > = [
    ["a non-numeric length", { "Content-Length": "not-a-number" }],
    ["a decimal length", { "Content-Length": "10485761.0" }],
    ["a negative length", { "Content-Length": "-1" }],
    ["an overflowing length", { "Content-Length": "18446744073709551616" }],
    ["comma-joined lengths", { "Content-Length": "10485761, 10485761" }],
    ["duplicate lengths", { "Content-Length": ["10485761", "10485761"] }],
    ["conflicting lengths", { "Content-Length": ["1", "10485761"] }],
    [
      "both Transfer-Encoding and Content-Length",
      { "Content-Length": "10485761", "Transfer-Encoding": "chunked" },
    ],
  ];

  // Node rejects invalid HTTP framing before Express sees a request. Keep
  // these on the wire: synthetic request objects would miss that boundary
  // and suggest the guard needs to accept headers Node never supplies.
  it.each(invalidFramings)(
    "rejects %s before reaching the route",
    async (_label, headers) => {
      const response = await rawRequest(guarded.port, {
        path: "/metamcp/x/probe",
        headers,
      });

      expect(response.timedOut).toBe(false);
      expect(response.status).toBe(400);
      expect(response.closed).toBe(true);
    },
  );

  it("lets a request with no Content-Length through to the route", async () => {
    const response = await postChunked(
      guarded.port,
      "/mcp-proxy/server/mcp",
      [Buffer.from("abc"), Buffer.from("def")],
      { "Content-Type": "application/json" },
    );

    expect(response.status).toBe(200);
    expect(JSON.parse(response.body)).toEqual({ length: 6 });
  });

  it("leaves a normal request on a named lane unchanged", async () => {
    const response = await postJson(
      guarded.baseUrl,
      "/trpc/frontend/anything",
      { blob: "x".repeat(MID_BYTES) },
    );

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      received: true,
      blobLength: MID_BYTES,
    });
  });
});
