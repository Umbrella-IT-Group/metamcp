/**
 * The Origin policy on `/metamcp/*`, driven end to end over a real loopback
 * socket: the real public router (so the guard's mount position is under test),
 * the real OAuth router (so the "other mounts are exempt" claim is), and stubs
 * only for the four transport sub-routers below the guard. A stub counts its
 * calls, so "the handler was not reached" is an assertion, and it can answer
 * with a chosen status, write a streaming head, or call `res.writeHead` with
 * custom arguments.
 *
 * Oracles. The refusal status is the MCP Streamable HTTP transport spec
 * (2025-11-25, "Security Warning"): "If the Origin header is present and
 * invalid, servers MUST respond with HTTP 403 Forbidden." The refusal body is
 * the SDK's own error shape (`createJsonErrorResponse(403, -32000, ...)` in
 * server/webStandardStreamableHttp.js), written out as a literal below rather
 * than imported. The default mode follows the operator direction of
 * 2026-11-12: shipping the guard must not change what a legitimate consumer
 * sees. The preflight statuses are what the `cors` package does (an untrusted
 * preflight is not answered by it, it falls through to Express).
 *
 * This file imports only modules that exist without the change, and resets
 * module state with `vi.resetModules()`, so it fails by assertion (no event,
 * no 403, handler reached), never by a missing import.
 */
import type { Server } from "node:http";

import express from "express";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { AuditEvent } from "../lib/audit/audit-emitter";

interface GatewayEventRow {
  category: string;
  level?: string | null;
  server_name?: string | null;
  message: string;
}

const h = vi.hoisted(() => {
  const state = {
    calls: {} as Record<string, number>,
    streams: [] as Array<() => void>,
    events: [] as GatewayEventRow[],
    audits: [] as AuditEvent[],
    logger: {
      info: vi.fn(),
      warn: vi.fn(),
      error: vi.fn(),
      debug: vi.fn(),
    },
  };

  /**
   * A transport stand-in. The status comes from `x-stub-status`, the shape from
   * `x-stub-mode`. `x-stub-patched` reports whether `res.writeHead` had been
   * replaced on this response when the handler ran, which is how a test sees
   * the guard's response-head hook without importing it.
   */
  function stub(label: string) {
    return (req: express.Request, res: express.Response) => {
      state.calls[label] = (state.calls[label] ?? 0) + 1;
      const patched = String(
        Object.prototype.hasOwnProperty.call(res, "writeHead"),
      );
      const mode = req.header("x-stub-mode");
      if (mode === "stream") {
        res.writeHead(200, {
          "content-type": "text/event-stream",
          "x-stub-patched": patched,
        });
        res.write("data: one\n\n");
        state.streams.push(() => res.end());
        return;
      }
      if (mode === "writehead") {
        res.writeHead(201, { "x-a": "1", "x-stub-patched": patched });
        res.end("ok");
        return;
      }
      res.setHeader("x-stub-patched", patched);
      res.status(Number(req.header("x-stub-status") ?? 200)).json({ ok: true });
    };
  }

  return { ...state, stub };
});

vi.mock("@/utils/logger", () => ({ default: h.logger }));

vi.mock("../db/repositories", () => ({
  oauthRepository: { cleanupExpired: vi.fn().mockResolvedValue(undefined) },
  toolCallAuditRepository: { pruneOlderThan: vi.fn().mockResolvedValue(0) },
  endpointsRepository: {
    hasOAuthEnabledEndpoint: vi.fn().mockResolvedValue(true),
    findByName: vi.fn().mockResolvedValue(undefined),
    findAllWithNamespaces: vi.fn().mockResolvedValue([]),
  },
  usersRepository: { findById: vi.fn(), isDisabled: vi.fn() },
}));
vi.mock("../db/repositories/endpoints.repo", () => ({
  endpointsRepository: { findAllWithNamespaces: vi.fn().mockResolvedValue([]) },
}));
vi.mock("../db/repositories/users.repo", () => ({
  usersRepository: { isDisabled: vi.fn().mockResolvedValue(false) },
}));
vi.mock("../auth", () => ({
  auth: {
    api: { getSession: vi.fn().mockResolvedValue(null) },
    handler: vi.fn(async () => new Response(null, { status: 200 })),
  },
}));
vi.mock("../lib/health-upstream", () => ({
  isAdminHealthRequest: vi.fn().mockResolvedValue(false),
}));

// The four transport routers, as the real ones declare their routes: explicit
// methods per path (so Express answers an OPTIONS itself, with `Allow`), the
// exact-path liveness route next to the data-plane ones.
vi.mock("./public-metamcp/streamable-http", async () => {
  const router = (await import("express")).Router();
  router.get("/health/sessions", h.stub("health.sessions"));
  router.get("/:endpoint_name/mcp", h.stub("mcp.get"));
  router.post("/:endpoint_name/mcp", h.stub("mcp.post"));
  router.delete("/:endpoint_name/mcp", h.stub("mcp.delete"));
  return { default: router };
});
vi.mock("./public-metamcp/sse", async () => {
  const router = (await import("express")).Router();
  router.get("/:endpoint_name/sse", h.stub("sse.get"));
  router.post("/:endpoint_name/message", h.stub("sse.message"));
  return { default: router };
});
vi.mock("./public-metamcp/openapi", async () => {
  const router = (await import("express")).Router();
  router.get("/:endpoint_name/api/openapi.json", h.stub("api.spec"));
  router.post("/:endpoint_name/api/:tool_name", h.stub("api.call"));
  return { openApiRouter: router };
});
vi.mock("./public-metamcp/admin", async () => {
  const router = (await import("express")).Router();
  router.post("/:endpoint_name/admin/reset-errors", h.stub("admin.reset"));
  return { default: router };
});

const APP_ORIGIN = "https://gateway.example.test";
const EXTRA_ORIGIN = "https://partner.example.test";
const ALLOWED_ORIGIN = "https://connector.example.test";
const untrusted = (n: number) => `https://untrusted-${n}.example.test`;

const ENFORCE_REFUSAL_BODY =
  '{"jsonrpc":"2.0","error":{"code":-32000,"message":"Origin not allowed"},"id":null}';
const HOUR_MS = 60 * 60 * 1000;

let server: Server;
let baseUrl: string;

async function startApp(options: { oauth?: boolean } = {}): Promise<void> {
  vi.resetModules();
  const { setGatewayEventSinkForTesting } = await import(
    "../lib/gateway-events/sink"
  );
  const { setAuditSinkForTesting } = await import("../lib/audit/audit-emitter");
  setGatewayEventSinkForTesting(async (entry) => {
    h.events.push(entry);
  });
  setAuditSinkForTesting(async (event) => {
    h.audits.push(event);
  });

  const { auditContextMiddleware } = await import(
    "../middleware/audit-context.middleware"
  );
  const { default: publicEndpointsRouter } = await import("./public-metamcp");

  // Mount order copied from ../index: audit context first, the unprefixed
  // OAuth router, then `/metamcp`.
  const app = express();
  app.use(auditContextMiddleware);
  if (options.oauth) {
    const { default: oauthRouter } = await import("./oauth");
    app.use(oauthRouter);
  }
  app.use("/metamcp", publicEndpointsRouter);

  await new Promise<void>((resolve) => {
    server = app.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  if (typeof address === "object" && address) {
    baseUrl = `http://127.0.0.1:${address.port}`;
  }
}

/** Let the detached history and audit writes (a few microtasks) land. */
async function settled(): Promise<void> {
  await new Promise<void>((resolve) => setImmediate(resolve));
}

interface Sent {
  status: number;
  headers: Headers;
  body: string;
}

async function send(
  method: string,
  route: string,
  options: { origin?: string; headers?: Record<string, string> } = {},
): Promise<Sent> {
  const headers: Record<string, string> = { ...options.headers };
  if (options.origin !== undefined) headers.Origin = options.origin;
  const response = await fetch(`${baseUrl}${route}`, { method, headers });
  const body = await response.text();
  await settled();
  return { status: response.status, headers: response.headers, body };
}

const mcp = (method: string, options?: Parameters<typeof send>[2]) =>
  send(method, "/metamcp/ep/mcp", options);

const originEvents = () =>
  h.events.filter((event) => event.server_name === "origin-policy");
const originAudits = () =>
  h.audits.filter((event) => event.detail?.reason === "origin_not_allowed");
const handlerCalls = () =>
  Object.values(h.calls).reduce((sum, n) => sum + n, 0);

beforeEach(() => {
  vi.stubEnv("APP_URL", APP_ORIGIN);
  vi.stubEnv("EXTRA_TRUSTED_ORIGINS", EXTRA_ORIGIN);
  vi.stubEnv("MCP_ALLOWED_ORIGINS", ALLOWED_ORIGIN);
  vi.stubEnv("MCP_ORIGIN_POLICY", undefined);
  // Only `Date` is faked: the window arithmetic needs a controllable clock, and
  // the real loopback sockets need real timers.
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(new Date("2026-11-12T12:00:00.000Z"));
});

afterEach(async () => {
  for (const end of h.streams.splice(0)) end();
  server.closeAllConnections();
  await new Promise((resolve) => server.close(resolve));
  vi.useRealTimers();
  vi.unstubAllEnvs();
  for (const label of Object.keys(h.calls)) delete h.calls[label];
  h.events.length = 0;
  h.audits.length = 0;
  vi.clearAllMocks();
});

describe("audit, the default (MCP_ORIGIN_POLICY unset)", () => {
  beforeEach(async () => {
    await startApp();
  });

  it("serves an untrusted Origin on POST, GET and DELETE and records one system event per method", async () => {
    const origin = untrusted(1);

    for (const method of ["POST", "GET", "DELETE"]) {
      const response = await mcp(method, { origin });
      expect(response.status, method).toBe(200);
    }

    expect(h.calls).toEqual({ "mcp.post": 1, "mcp.get": 1, "mcp.delete": 1 });
    const events = originEvents();
    expect(events).toHaveLength(3);
    for (const [index, method] of ["POST", "GET", "DELETE"].entries()) {
      expect(events[index]).toMatchObject({
        category: "system",
        level: "warn",
        server_name: "origin-policy",
      });
      expect(events[index].message).toContain(`Origin "${origin}"`);
      expect(events[index].message).toContain(`${method} mcp`);
      expect(events[index].message).toContain("served (200)");
      expect(events[index].message).toContain("credential absent");
      expect(events[index].message).toContain(
        "would be refused under MCP_ORIGIN_POLICY=enforce",
      );
    }
  });

  it("writes no audit_log row: the permanent table takes nothing from callers not yet classified", async () => {
    await mcp("POST", { origin: untrusted(2) });

    expect(originEvents()).toHaveLength(1);
    expect(h.audits).toHaveLength(0);
  });

  it("records nothing for a request with no Origin, and installs no hook", async () => {
    const response = await mcp("POST");

    expect(response.status).toBe(200);
    expect(response.headers.get("x-stub-patched")).toBe("false");
    expect(h.events).toHaveLength(0);
  });

  it("records nothing for a trusted origin, and installs no hook", async () => {
    for (const origin of [APP_ORIGIN, EXTRA_ORIGIN, ALLOWED_ORIGIN]) {
      const response = await mcp("POST", { origin });
      expect(response.headers.get("x-stub-patched"), origin).toBe("false");
    }

    expect(h.events).toHaveLength(0);
  });

  it("records the status the request was answered with, at response head", async () => {
    const origin = untrusted(3);

    // Four requests from one origin inside 60 s, each a separate event: the
    // class and the credential are part of what is being decided, and a repeat
    // of one must not swallow the others. "Served to a credentialed caller" is
    // the event that tells an operator enforcing would break a legitimate
    // client.
    const served = await mcp("POST", { origin });
    expect(served.status).toBe(200);

    const unauthenticated = await mcp("POST", {
      origin,
      headers: { "x-stub-status": "401" },
    });
    expect(unauthenticated.status).toBe(401);

    const authenticated = await mcp("POST", {
      origin,
      headers: { "x-api-key": "k" },
    });
    expect(authenticated.status).toBe(200);

    const failed = await mcp("POST", {
      origin,
      headers: { "x-stub-status": "500" },
    });
    expect(failed.status).toBe(500);

    const messages = originEvents().map((event) => event.message);
    expect(messages).toHaveLength(4);
    expect(messages[0]).toContain("served (200), credential absent");
    expect(messages[1]).toContain("denied (401), credential absent");
    expect(messages[2]).toContain("served (200), credential present");
    expect(messages[3]).toContain("error (500), credential absent");
  });

  it("records a streaming response at its status line, before it ends", async () => {
    const response = await fetch(`${baseUrl}/metamcp/ep/mcp`, {
      method: "GET",
      headers: { Origin: untrusted(4), "x-stub-mode": "stream" },
    });
    const reader = (response.body as ReadableStream<Uint8Array>).getReader();
    await reader.read();
    await settled();

    // The stub has written one chunk and has not ended the response.
    expect(h.streams).toHaveLength(1);
    expect(originEvents()).toHaveLength(1);
    expect(originEvents()[0].message).toContain("served (200)");
    await reader.cancel();
  });

  it("does not alter a head the handler writes itself", async () => {
    const response = await mcp("POST", {
      origin: untrusted(5),
      headers: { "x-stub-mode": "writehead" },
    });

    // The hook really was installed on this response...
    expect(response.headers.get("x-stub-patched")).toBe("true");
    // ...and the handler's own status, header and body arrive unchanged.
    expect(response.status).toBe(201);
    expect(response.headers.get("x-a")).toBe("1");
    expect(response.body).toBe("ok");
    expect(originEvents()).toHaveLength(1);
    expect(originEvents()[0].message).toContain("served (201)");
  });

  it("records a preflight from an untrusted origin and still gives it no grant", async () => {
    const response = await mcp("OPTIONS", {
      origin: untrusted(6),
      headers: { "Access-Control-Request-Method": "POST" },
    });

    // The cors package does not answer an untrusted preflight: it falls
    // through to Express, which answers 200 with `Allow` and no grant.
    expect(response.status).toBe(200);
    expect(response.headers.get("allow")).not.toBeNull();
    expect(response.headers.get("access-control-allow-origin")).toBeNull();
    expect(originEvents()).toHaveLength(1);
    expect(originEvents()[0].message).toContain("OPTIONS mcp");
  });

  it("answers a trusted preflight itself, unchanged", async () => {
    const response = await mcp("OPTIONS", {
      origin: APP_ORIGIN,
      headers: { "Access-Control-Request-Method": "POST" },
    });

    expect(response.status).toBe(204);
    expect(response.headers.get("access-control-allow-origin")).toBe(
      APP_ORIGIN,
    );
    expect(h.events).toHaveLength(0);
  });

  it("puts only a bounded, quoted form of the caller's Origin and User-Agent in the message", async () => {
    await mcp("POST", {
      origin: 'https://evil.example.test";x=1',
      headers: { "user-agent": 'agent"; credential present; ua "forged' },
    });

    expect(originEvents()).toHaveLength(1);
    const [event] = originEvents();
    expect(event.message).not.toMatch(/[\r\n]/);
    expect(event.message).toContain(
      'Origin "https://evil.example.test\\";x=1"',
    );
    expect(event.message).toContain(
      'ua "agent\\"; credential present; ua \\"forged"',
    );
    expect(event.message).toContain("credential absent");
  });

  it.each([
    ["X-API-Key", { "x-api-key": "SECRET-api-key-0123456789" }, ""],
    ["Authorization", { authorization: "Bearer SECRET-bearer-0123456789" }, ""],
    ["api_key query", {}, "?api_key=SECRET-query-0123456789"],
  ])(
    "records that a credential was present (%s), never its value",
    async (_label, headers, query) => {
      await send("POST", `/metamcp/ep/mcp${query}`, {
        origin: untrusted(7),
        headers,
      });

      expect(originEvents()).toHaveLength(1);
      const [event] = originEvents();
      expect(event.message).toContain("credential present");
      expect(
        JSON.stringify([h.events, h.audits, h.logger.warn.mock.calls]),
      ).not.toContain("SECRET");
    },
  );
});

describe("enforce", () => {
  beforeEach(async () => {
    vi.stubEnv("MCP_ORIGIN_POLICY", "enforce");
    await startApp();
  });

  it('refuses an Origin that is present and invalid with 403 ("If the Origin header is present and invalid, servers MUST respond with HTTP 403 Forbidden")', async () => {
    const origin = untrusted(10);

    const response = await mcp("POST", { origin });

    expect(response.status).toBe(403);
    expect(response.body).toBe(ENFORCE_REFUSAL_BODY);
    expect(response.body).not.toContain("untrusted-10");
    expect(response.headers.get("vary")?.toLowerCase()).toContain("origin");
    expect(response.headers.get("access-control-allow-origin")).toBeNull();
    expect(handlerCalls()).toBe(0);
  });

  it("writes one audit row in the existing mcp.auth.denied envelope, and an event", async () => {
    await mcp("POST", {
      origin: untrusted(11),
      headers: {
        "cf-connecting-ip": "203.0.113.7",
        "user-agent": "probe/1.0",
        "sec-fetch-site": "cross-site",
      },
    });

    expect(originAudits()).toHaveLength(1);
    expect(originAudits()[0]).toMatchObject({
      actor_type: "anonymous",
      actor_id: null,
      actor_ip: "203.0.113.7",
      actor_user_agent: "probe/1.0",
      action: "mcp.auth.denied",
      target_type: "endpoint",
      target_id: null,
      outcome: "denied",
      request_id: expect.any(String),
      http_status: 403,
      detail: {
        reason: "origin_not_allowed",
        origin: untrusted(11),
        route: "mcp",
        method: "POST",
        endpoint_name: "ep",
        credential_present: false,
        sec_fetch_site: "cross-site",
        suppressed_since_last: 0,
        dropped_by_ceiling: 0,
      },
    });
    expect(originEvents()).toHaveLength(1);
    expect(originEvents()[0].message).toContain(
      `refused Origin "${untrusted(11)}", POST mcp, 403, credential absent`,
    );
  });

  it("never lets a credential value into an audit row or an event", async () => {
    await mcp("POST", {
      origin: untrusted(12),
      headers: { "x-api-key": "SECRET-api-key-0123456789" },
    });

    expect(originAudits()).toHaveLength(1);
    expect(originAudits()[0].detail?.credential_present).toBe(true);
    expect(JSON.stringify([h.events, h.audits])).not.toContain("SECRET");
  });

  it("lets everything the origin check allows through to the handler", async () => {
    const cases: Array<[string, string | undefined]> = [
      ["no Origin header", undefined],
      ["APP_URL", APP_ORIGIN],
      ["an EXTRA_TRUSTED_ORIGINS entry", EXTRA_ORIGIN],
      ["an MCP_ALLOWED_ORIGINS entry", ALLOWED_ORIGIN],
      ["APP_URL, upper case", "HTTPS://GATEWAY.EXAMPLE.TEST"],
    ];

    for (const [label, origin] of cases) {
      const before = handlerCalls();
      const response = await mcp("POST", { origin });
      expect(response.status, label).toBe(200);
      expect(handlerCalls(), label).toBe(before + 1);
    }
    expect(h.events).toHaveLength(0);
    expect(h.audits).toHaveLength(0);
  });

  it("passes an MCP_ALLOWED_ORIGINS origin through the guard without granting it CORS", async () => {
    const response = await mcp("OPTIONS", {
      origin: ALLOWED_ORIGIN,
      headers: { "Access-Control-Request-Method": "POST" },
    });

    // Not refused (the guard allows it), and not granted either: the grant is
    // for APP_URL and EXTRA_TRUSTED_ORIGINS only.
    expect(response.status).toBe(200);
    expect(response.headers.get("access-control-allow-origin")).toBeNull();
    expect(h.audits).toHaveLength(0);
  });

  it.each([
    ["POST", "/metamcp/ep/mcp"],
    ["GET", "/metamcp/ep/mcp"],
    ["DELETE", "/metamcp/ep/mcp"],
    ["OPTIONS", "/metamcp/ep/mcp"],
    ["GET", "/metamcp/ep/sse"],
    ["POST", "/metamcp/ep/message"],
    ["POST", "/metamcp/ep/api/some_tool"],
    ["GET", "/metamcp/ep/api/openapi.json"],
    ["POST", "/metamcp/ep/admin/reset-errors"],
    ["GET", "/metamcp/health/mcp"],
    ["POST", "/metamcp/health"],
  ])(
    '"on all incoming connections": %s %s is refused',
    async (method, route) => {
      const response = await send(method, route, { origin: untrusted(13) });

      expect(response.status).toBe(403);
      expect(response.body).toBe(ENFORCE_REFUSAL_BODY);
      expect(handlerCalls()).toBe(0);
    },
  );

  it.each([
    ["GET", "/metamcp/health"],
    ["HEAD", "/metamcp/health"],
    ["GET", "/metamcp/health/sessions"],
    ["GET", "/metamcp/"],
  ])("leaves the liveness probe %s %s alone", async (method, route) => {
    const response = await send(method, route, { origin: untrusted(14) });

    expect(response.status).toBe(200);
    expect(h.audits).toHaveLength(0);
  });

  it("refuses an untrusted preflight instead of answering it", async () => {
    const response = await mcp("OPTIONS", {
      origin: untrusted(15),
      headers: { "Access-Control-Request-Method": "POST" },
    });

    expect(response.status).toBe(403);
    expect(response.headers.get("allow")).toBeNull();
  });

  it.each([
    ["the literal null", "null"],
    ["a browser-extension origin", "moz-extension://aaaa-bbbb"],
    ["a different port", "https://gateway.example.test:8443"],
    ["http instead of https", "http://gateway.example.test"],
    ["a longer host", "https://gateway.example.test.evil.example"],
    ["a userinfo lookalike", "https://gateway.example.test@evil.example"],
    ["two origins", `${APP_ORIGIN}, ${EXTRA_ORIGIN}`],
    ["two origins after a path", `${APP_ORIGIN}/path, ${EXTRA_ORIGIN}`],
    [
      "a space-separated origin list after a path",
      `${APP_ORIGIN}/path ${EXTRA_ORIGIN}`,
    ],
  ])("refuses %s", async (_label, origin) => {
    const response = await mcp("POST", { origin });

    expect(response.status).toBe(403);
    expect(handlerCalls()).toBe(0);
  });
});

describe("recording failures", () => {
  it("reports a synchronous audit failure without changing the refusal or losing its event", async () => {
    vi.stubEnv("MCP_ORIGIN_POLICY", "enforce");
    await startApp();
    const auditEmitter = await import("../lib/audit/audit-emitter");
    const emit = vi.spyOn(auditEmitter, "emit").mockImplementation(() => {
      throw new Error("SECRET audit failure");
    });

    try {
      const response = await mcp("POST", { origin: untrusted(17) });

      expect(response.status).toBe(403);
      expect(response.body).toBe(ENFORCE_REFUSAL_BODY);
      expect(originEvents()).toHaveLength(1);
      expect(h.logger.warn).toHaveBeenCalledWith(
        "[origin-policy] audit recording failed (request unaffected).",
      );
      expect(JSON.stringify(h.logger.warn.mock.calls)).not.toContain("SECRET");
    } finally {
      emit.mockRestore();
    }
  });

  it("uses the console when the logger fails and still writes the audit row", async () => {
    vi.stubEnv("MCP_ORIGIN_POLICY", "enforce");
    await startApp();
    h.logger.warn.mockImplementation(() => {
      throw new Error("SECRET logger failure");
    });
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});

    try {
      const response = await mcp("POST", { origin: untrusted(18) });

      expect(response.status).toBe(403);
      expect(originAudits()).toHaveLength(1);
      expect(warn).toHaveBeenCalledExactlyOnceWith(
        "[origin-policy] event recording failed (request unaffected).",
      );
      expect(JSON.stringify(warn.mock.calls)).not.toContain("SECRET");
    } finally {
      h.logger.warn.mockReset();
      warn.mockRestore();
    }
  });

  it.each(["audit", "enforce"])(
    "reports an event recording failure without changing the %s response or skipping its audit row",
    async (mode) => {
      vi.stubEnv("MCP_ORIGIN_POLICY", mode);
      await startApp();
      const { metamcpLogStore } = await import("../lib/metamcp/log-store");
      const record = vi
        .spyOn(metamcpLogStore, "record")
        .mockImplementation(() => {
          throw new Error("SECRET recording failure");
        });

      try {
        const response = await mcp("POST", { origin: untrusted(19) });

        expect(response.status).toBe(mode === "enforce" ? 403 : 200);
        expect(h.logger.warn).toHaveBeenCalledWith(
          "[origin-policy] event recording failed (request unaffected).",
        );
        expect(originAudits()).toHaveLength(mode === "enforce" ? 1 : 0);
        expect(JSON.stringify(h.logger.warn.mock.calls)).not.toContain(
          "SECRET",
        );
      } finally {
        record.mockRestore();
      }
    },
  );
});

describe("other mounts are exempt by construction", () => {
  beforeEach(async () => {
    vi.stubEnv("MCP_ORIGIN_POLICY", "enforce");
    await startApp({ oauth: true });
  });

  it("answers OAuth discovery and preflight with their own wildcard CORS under an untrusted Origin", async () => {
    const discovery = await send(
      "GET",
      "/.well-known/oauth-authorization-server",
      { origin: untrusted(20) },
    );
    expect(discovery.status).toBe(200);
    expect(discovery.headers.get("access-control-allow-origin")).toBe("*");

    const preflight = await send("OPTIONS", "/oauth/authorize", {
      origin: untrusted(20),
      headers: { "Access-Control-Request-Method": "GET" },
    });
    expect(preflight.status).toBeLessThan(300);
    expect(preflight.headers.get("access-control-allow-origin")).toBe("*");

    // The same Origin on the data plane in the same app is refused, so the
    // two answers above are the mount scope and not a disabled guard.
    expect((await mcp("POST", { origin: untrusted(20) })).status).toBe(403);
  });
});

describe("off", () => {
  beforeEach(async () => {
    vi.stubEnv("MCP_ORIGIN_POLICY", "off");
    await startApp();
  });

  it("serves an untrusted Origin, records nothing and installs no hook", async () => {
    const response = await mcp("POST", { origin: untrusted(30) });

    expect(response.status).toBe(200);
    expect(response.headers.get("x-stub-patched")).toBe("false");
    expect(h.events).toHaveLength(0);
    expect(h.audits).toHaveLength(0);
  });
});

describe("an unrecognised MCP_ORIGIN_POLICY", () => {
  beforeEach(async () => {
    vi.stubEnv("MCP_ORIGIN_POLICY", "enforced");
    await startApp();
  });

  it("runs as audit (served and recorded), never as off and never as a refusal, with one ERROR", async () => {
    for (let i = 0; i < 3; i += 1) {
      const response = await mcp("POST", { origin: untrusted(40 + i) });
      expect(response.status).toBe(200);
    }

    expect(originEvents()).toHaveLength(3);
    expect(h.audits).toHaveLength(0);
    expect(h.logger.error).toHaveBeenCalledTimes(1);
    expect(String(h.logger.error.mock.calls[0][0])).toContain(
      'MCP_ORIGIN_POLICY="enforced"',
    );
  });
});

describe("volume bounds", () => {
  describe("audit", () => {
    beforeEach(async () => {
      await startApp();
    });

    it.each(["/metamcp/HEALTH", "/metamcp/health/sessions/"])(
      "keeps the served-client reserve available after a flood on %s",
      async (route) => {
        // These are real Express liveness matches but are not exact-path
        // exemptions. Their unauthenticated 200s belong with other noise.
        for (let i = 0; i < 60; i += 1) {
          const response = await send("GET", route, {
            origin: untrusted(4000 + i),
          });
          expect(response.status).toBe(200);
        }
        expect(originEvents()).toHaveLength(60);

        await mcp("POST", {
          origin: untrusted(4999),
          headers: { "x-api-key": "k" },
        });

        expect(originEvents()).toHaveLength(61);
        expect(originEvents()[60].message).toContain(
          "served (200), credential present",
        );
      },
    );

    it.each([
      ["without a credential header", {}],
      ["with a caller-supplied credential header", { "x-api-key": "fake" }],
    ])(
      "keeps the served-client reserve available after a preflight flood %s",
      async (_label, headers) => {
        // Express answers OPTIONS without running authentication. Even a
        // forged credential header must not let these fill the reserve for
        // requests that were actually served by a data-plane handler.
        for (let i = 0; i < 60; i += 1) {
          const response = await mcp("OPTIONS", {
            origin: untrusted(3000 + i),
            headers: { ...headers, "Access-Control-Request-Method": "POST" },
          });
          expect(response.status).toBe(200);
        }
        expect(handlerCalls()).toBe(0);
        expect(originEvents()).toHaveLength(60);

        await mcp("POST", {
          origin: untrusted(3999),
          headers: { "x-api-key": "k" },
        });

        expect(originEvents()).toHaveLength(61);
        expect(originEvents()[60].message).toContain(
          "served (200), credential present",
        );
      },
    );

    it("collapses one origin's repeats to one event a minute and carries the count", async () => {
      const origin = untrusted(50);

      for (let i = 0; i < 50; i += 1) await mcp("POST", { origin });
      expect(originEvents()).toHaveLength(1);

      vi.setSystemTime(Date.now() + 61_000);
      await mcp("POST", { origin });

      expect(originEvents()).toHaveLength(2);
      expect(originEvents()[1].message).toContain(
        "49 similar request(s) suppressed since the last event",
      );
    });

    it("caps a flood of distinct origins at 60 events an hour, warns once, and carries the dropped count", async () => {
      const send300 = async (offset: number) => {
        for (let batch = 0; batch < 15; batch += 1) {
          await Promise.all(
            Array.from({ length: 20 }, (_, i) =>
              mcp("POST", {
                origin: untrusted(1000 + offset + batch * 20 + i),
                headers: { "x-stub-status": "401" },
              }),
            ),
          );
        }
      };

      await send300(0);

      expect(originEvents()).toHaveLength(60);
      const ceilingWarnings = h.logger.warn.mock.calls.filter((call) =>
        String(call[0]).includes("hourly ceiling"),
      );
      expect(ceilingWarnings).toHaveLength(1);

      // A genuine served event from a fresh origin is not crowded out.
      await mcp("POST", {
        origin: untrusted(9000),
        headers: { "x-api-key": "k" },
      });
      expect(originEvents()).toHaveLength(61);
      expect(originEvents()[60].message).toContain(
        "served (200), credential present",
      );

      // The next hour's first event says how many were not recorded.
      vi.setSystemTime(Date.now() + HOUR_MS + 1_000);
      await mcp("POST", {
        origin: untrusted(9001),
        headers: { "x-stub-status": "401" },
      });
      expect(originEvents()).toHaveLength(62);
      expect(originEvents()[61].message).toContain(
        "240 dropped by the hourly ceiling",
      );
    });
  });

  describe("enforce", () => {
    beforeEach(async () => {
      vi.stubEnv("MCP_ORIGIN_POLICY", "enforce");
      await startApp();
    });

    it("writes at most 20 audit rows an hour for 100 distinct origins, and the next row carries the counts", async () => {
      for (let i = 0; i < 100; i += 1) {
        const response = await mcp("POST", { origin: untrusted(2000 + i) });
        // The refusal itself is never throttled, only its recording.
        expect(response.status).toBe(403);
      }
      expect(originAudits()).toHaveLength(20);

      // Three repeats of an origin that already has a row: swallowed, counted.
      for (let i = 0; i < 3; i += 1) {
        await mcp("POST", { origin: untrusted(2000) });
      }
      expect(originAudits()).toHaveLength(20);

      vi.setSystemTime(Date.now() + HOUR_MS + 1_000);
      await mcp("POST", { origin: untrusted(2000) });

      expect(originAudits()).toHaveLength(21);
      expect(originAudits()[20].detail).toMatchObject({
        suppressed_since_last: 3,
        dropped_by_ceiling: 80,
      });
    });
  });
});
