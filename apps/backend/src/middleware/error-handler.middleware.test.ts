/**
 * Tests for the terminal error handler.
 *
 * The leak this closes was found on the LIVE gateway, not in review: a POST of
 * malformed JSON returned Express's built-in stack trace, naming `/app/`
 * container paths and the exact dependency versions in the pnpm store. So the
 * assertions that matter are the negative ones — that no response body ever
 * contains a path, a module name, a version string or the words of the
 * underlying error.
 *
 * Most of this runs over a REAL socket against an app wired the same way
 * `index.ts` wires it (the `express.json()` wrapper that skips proxy paths,
 * then routes, then this handler last). That is deliberate: `express.json()`
 * rejects the body inside the parser, before any route function runs, and only
 * a real request through a real pipeline proves the rejection lands here
 * rather than in Express's final handler.
 */

import express from "express";
import type { Server } from "http";
import {
  afterAll,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";

const loggerMock = {
  debug: vi.fn(),
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
};

vi.mock("@/utils/logger", () => ({ default: loggerMock }));

const {
  BAD_REQUEST_BODY,
  errorHandler,
  INTERNAL_ERROR_BODY,
  resolveErrorStatus,
} = await import("./error-handler.middleware");

/**
 * Substrings that must never appear in a response body.
 *
 * Every one of these was present in the live leak. `node_modules` and `.pnpm`
 * are the store layout, `/app/` is the container root, `at ` opens every stack
 * frame, and the error class names are what the default handler puts on the
 * first line.
 */
const NEVER_IN_BODY = [
  "/app/",
  "node_modules",
  ".pnpm",
  "body-parser",
  "raw-body",
  "SyntaxError",
  "Error:",
  "at ",
];

/** A dotted version like `1.20.3`, as the pnpm store path spells them. */
const VERSION_PATTERN = /\d+\.\d+\.\d+/;

function expectNoInternals(rawBody: string): void {
  for (const needle of NEVER_IN_BODY) {
    expect(rawBody).not.toContain(needle);
  }
  expect(rawBody).not.toMatch(VERSION_PATTERN);
}

describe("errorHandler — Express 5 registration contract", () => {
  it("declares exactly four parameters", () => {
    // Not a style assertion. `router@2.2.0` lib/layer.js dispatches by arity:
    // `handleError` runs only when `fn.length === 4`, and `handleRequest`
    // SKIPS any layer with `fn.length > 3`. Drop the unused `next` and this
    // stops being an error handler entirely — silently, with every other test
    // below still green if they did not go through a real pipeline.
    expect(errorHandler.length).toBe(4);
  });
});

describe("resolveErrorStatus", () => {
  it("passes a 4xx the error declares straight through", () => {
    expect(resolveErrorStatus({ statusCode: 413 })).toBe(413);
    expect(resolveErrorStatus({ status: 415 })).toBe(415);
  });

  it("reads a body-parser type even with no status attached", () => {
    expect(resolveErrorStatus({ type: "entity.parse.failed" })).toBe(400);
    expect(resolveErrorStatus({ type: "charset.unsupported" })).toBe(400);
  });

  it("treats a bare SyntaxError as a bad request", () => {
    expect(resolveErrorStatus(new SyntaxError("Unexpected token b"))).toBe(400);
  });

  it("fails to 500 for anything it does not positively recognise", () => {
    // The direction that reveals nothing: an unrecognised error must not be
    // able to talk its way into the 4xx branch and a passed-through status.
    expect(resolveErrorStatus(new Error("boom"))).toBe(500);
    expect(resolveErrorStatus(undefined)).toBe(500);
    expect(resolveErrorStatus(null)).toBe(500);
    expect(resolveErrorStatus("a string throw")).toBe(500);
    expect(resolveErrorStatus({ status: 200 })).toBe(500);
    expect(resolveErrorStatus({ statusCode: "400" })).toBe(500);
  });

  it("keeps a declared 5xx in the server-error branch", () => {
    expect(resolveErrorStatus({ statusCode: 503 })).toBe(503);
  });
});

describe("errorHandler — a response already streaming", () => {
  it("delegates to Express instead of writing a second body", () => {
    // The SSE legs write headers immediately. Once they have, there is no
    // status left to set and no body that would not corrupt the stream, so
    // the only correct move is to hand the error back and let Express destroy
    // the socket.
    const next = vi.fn();
    const res = {
      headersSent: true,
      status: vi.fn(),
      json: vi.fn(),
    } as unknown as express.Response;
    const req = { method: "GET", path: "/metamcp/x" } as express.Request;
    const err = new Error("late failure");

    errorHandler(err, req, res, next);

    expect(next).toHaveBeenCalledWith(err);
    expect(res.status).not.toHaveBeenCalled();
    expect(res.json).not.toHaveBeenCalled();
  });
});

describe("terminal error handler over a real socket", () => {
  let server: Server;
  let baseUrl = "";

  beforeAll(async () => {
    const app = express();

    // Mirrors index.ts: proxy paths bypass JSON parsing, everything else is
    // parsed, and the parser's own rejections flow to the handler below.
    app.use((req, res, next) => {
      if (
        req.path.startsWith("/mcp-proxy/") ||
        req.path.startsWith("/metamcp/")
      ) {
        next();
      } else {
        express.json({ limit: "1kb" })(req, res, next);
      }
    });

    app.post("/trpc/echo", (req, res) => {
      res.json({ ok: true, received: req.body });
    });

    app.get("/boom/sync", () => {
      throw new Error("sync failure naming /app/secret and pg://user:pw@host");
    });

    app.get("/boom/async", async () => {
      // The express-5 proof. Router 2.x attaches a rejection handler to any
      // promise a handler returns and forwards it to `next(err)` — so this
      // reaches the error handler and answers 500, rather than hanging the
      // request as it would have on express 4.
      await Promise.resolve();
      throw new Error("async failure naming /app/secret");
    });

    app.get("/boom/status", () => {
      const err = new Error("not found detail") as Error & { status: number };
      err.status = 404;
      throw err;
    });

    app.use(errorHandler);

    await new Promise<void>((resolve) => {
      server = app.listen(0, "127.0.0.1", resolve);
    });
    const address = server.address();
    if (typeof address === "object" && address) {
      baseUrl = `http://127.0.0.1:${address.port}`;
    }
  });

  afterAll(async () => {
    await new Promise((resolve) => server.close(resolve));
  });

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("answers malformed JSON with a clean 400 and no internals", async () => {
    // The exact request from the live re-verification.
    const response = await fetch(`${baseUrl}/trpc/echo`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{bad",
    });
    const raw = await response.text();

    expect(response.status).toBe(400);
    expect(JSON.parse(raw)).toEqual(BAD_REQUEST_BODY);
    expectNoInternals(raw);
  });

  it("answers an over-limit body with its own status but the same body", async () => {
    const response = await fetch(`${baseUrl}/trpc/echo`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ pad: "x".repeat(4096) }),
    });
    const raw = await response.text();

    // The status still distinguishes "too big" from "malformed" — that is the
    // one thing a caller legitimately needs — while the body stays constant.
    expect(response.status).toBe(413);
    expect(JSON.parse(raw)).toEqual(BAD_REQUEST_BODY);
    expectNoInternals(raw);
  });

  it("answers an unsupported charset with a 4xx and no internals", async () => {
    // body-parser accepts a charset only when it starts `utf-`
    // (lib/types/json.js `isValidCharset`), so this is the branch that raises
    // `charset.unsupported` — a 4xx that is NOT a SyntaxError, proving the
    // handler classifies on the error's own status rather than its class.
    const response = await fetch(`${baseUrl}/trpc/echo`, {
      method: "POST",
      headers: { "content-type": "application/json; charset=iso-8859-7" },
      body: "{}",
    });
    const raw = await response.text();

    expect(response.status).toBeGreaterThanOrEqual(400);
    expect(response.status).toBeLessThan(500);
    expect(JSON.parse(raw)).toEqual(BAD_REQUEST_BODY);
    expectNoInternals(raw);
  });

  it("passes a route's declared 4xx status through with the constant body", async () => {
    const response = await fetch(`${baseUrl}/boom/status`);
    const raw = await response.text();

    expect(response.status).toBe(404);
    expect(JSON.parse(raw)).toEqual(BAD_REQUEST_BODY);
    // The error's message ("not found detail") is not echoed.
    expect(raw).not.toContain("not found");
    expectNoInternals(raw);
  });

  it("answers a synchronous throw with a constant 500 and logs the real error", async () => {
    const response = await fetch(`${baseUrl}/boom/sync`);
    const raw = await response.text();

    expect(response.status).toBe(500);
    expect(JSON.parse(raw)).toEqual(INTERNAL_ERROR_BODY);
    expect(raw).not.toContain("pg://");
    expectNoInternals(raw);

    // The detail is not lost — it goes to the operator, not the caller.
    expect(loggerMock.error).toHaveBeenCalledTimes(1);
    const logged = loggerMock.error.mock.calls[0];
    expect(String(logged?.[0])).toContain("/boom/sync");
    expect((logged?.[1] as Error).message).toContain("pg://");
  });

  it("answers an async rejection with a constant 500 rather than hanging", async () => {
    // Pins the express-5 behaviour the fork ledger used to describe wrongly:
    // router 2.x DOES forward an async handler's rejection to the error
    // handler, so the failure direction is a fail-closed 500, not a hang.
    const response = await fetch(`${baseUrl}/boom/async`);
    const raw = await response.text();

    expect(response.status).toBe(500);
    expect(JSON.parse(raw)).toEqual(INTERNAL_ERROR_BODY);
    expectNoInternals(raw);
    expect(loggerMock.error).toHaveBeenCalledTimes(1);
  });

  it("does not log a client's malformed body at error level", async () => {
    // An unauthenticated route anyone can POST garbage to must not be a
    // log-flooding lever.
    await fetch(`${baseUrl}/trpc/echo`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{bad",
    });

    expect(loggerMock.error).not.toHaveBeenCalled();
    expect(loggerMock.debug).toHaveBeenCalledTimes(1);
  });

  it("still serves a well-formed request normally", async () => {
    // The regression guard. A handler that refused everything would satisfy
    // every assertion above and break the gateway.
    const response = await fetch(`${baseUrl}/trpc/echo`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ hello: "world" }),
    });

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      ok: true,
      received: { hello: "world" },
    });
    expect(loggerMock.error).not.toHaveBeenCalled();
  });
});
