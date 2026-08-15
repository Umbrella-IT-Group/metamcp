/**
 * Cross-router CORS policy.
 *
 * `oauthRouter` is mounted UNPREFIXED (`app.use(oauthRouter)` in ../index) so
 * that `/.well-known/*` can live at the root. Router-level middleware on an
 * unprefixed router runs for EVERY request the app receives, so the wildcard
 * CORS policy that router declared for anonymous OAuth discovery was applied to
 * paths it does not serve: `/api/auth/*` responses carried it, and because the
 * cors package answers preflights itself, so did the OPTIONS leg of every other
 * route in the app. `/api/auth/*` answers with the session cookie and had no
 * CORS policy of its own, so what it returned was whatever that neighbour left
 * behind — a policy nobody chose for it.
 *
 * A second router carried the genuinely dangerous shape: `/metamcp/*` used
 * `origin: true`, which reflects the caller's own `Origin` back, beside
 * `credentials: true`.
 *
 * The invariant these tests pin, on every route:
 *
 *   no `Access-Control-Allow-Origin: *` and no reflection of an untrusted
 *   `Origin` on any route that allows credentials; a trusted origin gets
 *   itself echoed back; an untrusted one gets no grant at all.
 *
 * plus the regression half: `/oauth/*` and `/.well-known/*` must STILL answer
 * with CORS, or every MCP client that discovers this gateway breaks.
 *
 * The real routers and the real relay are driven over a real socket, mirroring
 * `public-metamcp.estate-gate.test.ts`. Mocked seams are the ones that would
 * otherwise drag postgres in: `../db/repositories`, `../auth` (which builds the
 * drizzle adapter at import time and throws without a database), and the
 * `/metamcp` and `/mcp-proxy` sub-routers. Every CORS decision under test runs
 * for real, and so does the `/api/auth` relay — `auth.handler` is the only
 * thing standing in, so the relay's own header copying and error handling are
 * the code under test rather than a fixture that imitates them.
 *
 * A HOSTILE middleware is mounted ahead of the `/api/auth` policy, setting the
 * exact headers the OAuth router used to bleed. Without it the belt in
 * `authApiCorsMiddleware` could be deleted with every test still green, since
 * nothing else in this app writes a CORS grant onto a foreign path.
 *
 * `/trpc` is mounted here as a bare router with NO CORS of its own. The real
 * one (./trpc.ts) has its own allowlisted policy, exercised through
 * `/mcp-proxy` (same policy, same source); leaving this mount bare is the
 * stronger assertion for the bleed, because any CORS header observed on it
 * could only have come from a neighbour.
 */
import { readdirSync, readFileSync } from "node:fs";
import type { Server } from "node:http";
import path from "node:path";

import express from "express";
import {
  afterAll,
  afterEach,
  beforeAll,
  describe,
  expect,
  it,
  vi,
} from "vitest";

const APP_ORIGIN = "https://gateway.example.test";
const UNTRUSTED_ORIGIN = "https://evil.example.test";
const EXTRA_ORIGIN = "https://partner.example.test";
/**
 * A non-special scheme, whose WHATWG origin serialises as the string "null".
 * Listed as a trusted origin here on purpose: an operator who pastes a browser
 * extension id into `EXTRA_TRUSTED_ORIGINS` must not thereby trust every other
 * opaque origin in the world.
 */
const EXOTIC_SCHEME_ENTRY =
  "moz-extension://11111111-2222-3333-4444-555555555555";

// Read at import time by `getBaseUrl` in the OAuth metadata handler and, per
// request, by ../lib/cors-policy.
process.env.APP_URL = APP_ORIGIN;
process.env.EXTRA_TRUSTED_ORIGINS = `${EXTRA_ORIGIN}, ${EXOTIC_SCHEME_ENTRY}, `;

const h = vi.hoisted(() => ({
  /** Stands in for better-auth. Reassigned per test. */
  authHandler: vi.fn(async () => new Response(null, { status: 200 })),
}));

vi.mock("@/utils/logger", () => ({
  default: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

// The OAuth sub-routers and the estate listing share this barrel. Only the
// members reached by the requests below need to answer.
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
    handler: h.authHandler,
  },
}));

vi.mock("../lib/health-upstream", () => ({
  isAdminHealthRequest: vi.fn().mockResolvedValue(false),
}));

// Empty stand-ins so importing the public router does not pull in the MCP
// transports or the server pool; the CORS middleware under test runs ahead of
// all four.
vi.mock("./public-metamcp/openapi", async () => ({
  openApiRouter: (await import("express")).Router(),
}));
vi.mock("./public-metamcp/admin", async () => ({
  default: (await import("express")).Router(),
}));
vi.mock("./public-metamcp/sse", async () => ({
  default: (await import("express")).Router(),
}));
vi.mock("./public-metamcp/streamable-http", async () => ({
  default: (await import("express")).Router(),
}));

// Same treatment for the proxy's two sub-routers. Its CORS middleware runs
// ahead of the session/admin gates, which is why a preflight reaches a policy
// decision without any of them answering first.
vi.mock("./mcp-proxy/server", async () => ({
  default: (await import("express")).Router(),
}));
vi.mock("./mcp-proxy/metamcp", async () => ({
  default: (await import("express")).Router(),
}));

const { authApiCorsMiddleware, isCorsResponseHeader, resolveTrustedOrigin } =
  await import("../lib/cors-policy");
const { authApiRelay } = await import("./auth-relay");
const { INTERNAL_ERROR_BODY } = await import(
  "../middleware/error-handler.middleware"
);
const { default: oauthRouter } = await import("./oauth");
const { default: publicEndpointsRouter } = await import("./public-metamcp");
const { default: mcpProxyRouter } = await import("./mcp-proxy");

const ACAO = "access-control-allow-origin";
const ACAC = "access-control-allow-credentials";

let server: Server;
let baseUrl: string;

beforeAll(async () => {
  const app = express();

  // Mount order copied from ../index: the unprefixed OAuth router first, then
  // the `/api/auth` policy and its relay, then the prefixed routers. Order is
  // the whole point — a policy that bleeds does so onto whatever is mounted
  // after it.
  app.use(oauthRouter);

  // The bleed, reproduced deliberately. These are the two headers the
  // unprefixed OAuth CORS used to leave on `/api/auth` responses, plus an
  // `-Expose-Headers` standing in for the rest of the family. Nothing in this
  // app writes a grant onto a foreign path any more, so without a hostile
  // source the belt inside `authApiCorsMiddleware` would be dead code whose
  // removal no test could notice.
  //
  // Scoped to `/api/auth` on purpose: applying it app-wide would mask the
  // separate assertions that nothing bleeds onto `/trpc` and `/metamcp`.
  app.use("/api/auth", (_req, res, next) => {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Credentials", "true");
    res.setHeader("Access-Control-Expose-Headers", "x-leaked");
    next();
  });

  app.use(authApiCorsMiddleware);
  app.use(authApiRelay);

  app.use("/metamcp", publicEndpointsRouter);
  app.use("/mcp-proxy", mcpProxyRouter);

  app.use(
    "/trpc",
    express.Router().all("/{*splat}", (_req, res) => {
      res.status(200).json({ ok: true });
    }),
  );

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

/** One request, with an `Origin`, returning only what CORS decided. */
async function corsHeaders(
  method: string,
  path: string,
  origin: string,
): Promise<{ status: number; acao: string | null; acac: string | null }> {
  const headers: Record<string, string> = { Origin: origin };
  if (method === "OPTIONS") {
    // Without these the cors package treats the request as a normal OPTIONS,
    // not a preflight, and never short-circuits.
    headers["Access-Control-Request-Method"] = "GET";
  }
  const response = await fetch(`${baseUrl}${path}`, { method, headers });
  return {
    status: response.status,
    acao: response.headers.get(ACAO),
    acac: response.headers.get(ACAC),
  };
}

/** The whole `Response`, for the assertions that need a body or more headers. */
function probe(method: string, path: string, origin?: string) {
  const headers: Record<string, string> = {};
  if (origin) headers.Origin = origin;
  if (method === "OPTIONS") headers["Access-Control-Request-Method"] = "GET";
  return fetch(`${baseUrl}${path}`, { method, headers });
}

// ---------------------------------------------------------------------------
// The invariant, everywhere
// ---------------------------------------------------------------------------

/** Every path exercised below, as [label, method, path]. */
const ALL_SURFACES: [string, string, string][] = [
  ["auth API session read", "GET", "/api/auth/get-session"],
  ["auth API preflight", "OPTIONS", "/api/auth/sign-up/email"],
  ["tRPC preflight", "OPTIONS", "/trpc/frontend/mcpServers.list"],
  ["tRPC call", "GET", "/trpc/frontend/mcpServers.list"],
  ["MCP proxy preflight", "OPTIONS", "/mcp-proxy/metamcp/some-uuid/mcp"],
  ["MCP proxy call", "GET", "/mcp-proxy/server/mcp"],
  ["public MCP preflight", "OPTIONS", "/metamcp/some-endpoint/mcp"],
  ["public MCP listing", "GET", "/metamcp/"],
  ["OAuth authorize preflight", "OPTIONS", "/oauth/authorize"],
  ["OAuth discovery", "GET", "/.well-known/oauth-authorization-server"],
];

/** Origins that must never receive a credentialed grant anywhere. */
const HOSTILE_ORIGINS: [string, string][] = [
  ["an untrusted https origin", UNTRUSTED_ORIGIN],
  // Every non-special scheme shares one opaque origin, serialised "null" — so
  // if any of them is ever granted, ALL of them are, including the `null`
  // Origin a sandboxed iframe sends.
  [
    "a browser-extension origin",
    "moz-extension://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
  ],
  ["a packaged-app origin", "app://some.bundle.id"],
  ["a file origin", "file://"],
];

describe("no route pairs a wildcard or reflected origin with credentials", () => {
  it.each(ALL_SURFACES)(
    "%s never returns ACAO:* together with credentials",
    async (_label, method, path) => {
      const { acao, acac } = await corsHeaders(method, path, UNTRUSTED_ORIGIN);

      // Unconditional: a conditional `if (acac === "true")` passes vacuously on
      // every surface that sets no credentials header, which is most of them.
      expect([acao, acac]).not.toEqual(["*", "true"]);
    },
  );

  it.each(ALL_SURFACES)(
    "%s never reflects an untrusted Origin",
    async (_label, method, path) => {
      const { acao } = await corsHeaders(method, path, UNTRUSTED_ORIGIN);

      expect(acao).not.toBe(UNTRUSTED_ORIGIN);
    },
  );

  // The credentialed surfaces only. The OAuth paths answer `*` by design and
  // carry no credentials, which the regression block below pins.
  const CREDENTIALED_SURFACES = ALL_SURFACES.filter(
    ([, , path]) => !path.startsWith("/oauth") && !path.startsWith("/.well-"),
  );

  describe.each(HOSTILE_ORIGINS)("%s", (_originLabel, origin) => {
    it.each(CREDENTIALED_SURFACES)(
      "gets no grant on %s",
      async (_label, method, path) => {
        const { acao, acac } = await corsHeaders(method, path, origin);

        // `null` is the assertion that matters for the opaque-origin cases: an
        // allowlist that normalised an exotic scheme to the string "null"
        // would answer every one of them `Access-Control-Allow-Origin: null`
        // beside credentials — one operator typo trusting the whole class.
        expect(acao).toBeNull();
        expect(acac).toBeNull();
      },
    );
  });
});

// ---------------------------------------------------------------------------
// The bleed
// ---------------------------------------------------------------------------

describe("/api/auth has its own policy, not a neighbour's", () => {
  it("gives an untrusted origin no grant on a session read", async () => {
    const { acao, acac } = await corsHeaders(
      "GET",
      "/api/auth/get-session",
      UNTRUSTED_ORIGIN,
    );

    // The session read is the response worth stealing: it is answered from the
    // cookie and carries the account it belongs to.
    expect(acao).toBeNull();
    expect(acac).toBeNull();
  });

  it("gives an untrusted origin no grant on a preflight", async () => {
    const { acao } = await corsHeaders(
      "OPTIONS",
      "/api/auth/sign-up/email",
      UNTRUSTED_ORIGIN,
    );

    expect(acao).toBeNull();
  });

  it("echoes the app's own origin back, with credentials", async () => {
    const { acao, acac } = await corsHeaders(
      "GET",
      "/api/auth/get-session",
      APP_ORIGIN,
    );

    expect(acao).toBe(APP_ORIGIN);
    expect(acac).toBe("true");
  });

  it("answers a preflight from the app's own origin", async () => {
    const { status, acao, acac } = await corsHeaders(
      "OPTIONS",
      "/api/auth/sign-up/email",
      APP_ORIGIN,
    );

    expect(status).toBe(204);
    expect(acao).toBe(APP_ORIGIN);
    expect(acac).toBe("true");
  });

  it("honours EXTRA_TRUSTED_ORIGINS, the same variable better-auth reads", async () => {
    const { acao } = await corsHeaders(
      "GET",
      "/api/auth/get-session",
      EXTRA_ORIGIN,
    );

    expect(acao).toBe(EXTRA_ORIGIN);
  });

  it("does not trust the whole opaque-origin class for one exotic entry", async () => {
    // `EXTRA_TRUSTED_ORIGINS` really does contain an exotic-scheme entry in
    // this suite. It must resolve to nothing rather than to the shared "null"
    // origin every non-special scheme normalises to.
    expect(resolveTrustedOrigin(EXOTIC_SCHEME_ENTRY)).toBeNull();

    const { acao, acac } = await corsHeaders(
      "GET",
      "/api/auth/get-session",
      EXOTIC_SCHEME_ENTRY,
    );

    expect(acao).toBeNull();
    expect(acac).toBeNull();
  });

  it("strips every CORS header a neighbour already wrote", async () => {
    // The hostile middleware ahead of the policy sets ACAO:*, ACAC:true and an
    // -Expose-Headers on every `/api/auth` response. For an untrusted origin
    // the policy itself sets nothing, so anything observed here survived the
    // belt.
    const response = await probe(
      "GET",
      "/api/auth/get-session",
      UNTRUSTED_ORIGIN,
    );

    for (const [name, value] of response.headers) {
      expect(
        isCorsResponseHeader(name) ? [name, value] : null,
        `${name} survived onto an untrusted /api/auth response`,
      ).toBeNull();
    }
  });

  it("replaces, rather than keeps, a neighbour's grant for a trusted origin", async () => {
    const response = await probe("GET", "/api/auth/get-session", APP_ORIGIN);

    expect(response.headers.get(ACAO)).toBe(APP_ORIGIN);
    // The neighbour's `-Expose-Headers` is not part of this route's policy and
    // must not ride along with the grant that replaced its ACAO.
    expect(response.headers.get("access-control-expose-headers")).toBeNull();
  });

  it("marks the response as Origin-dependent even when it grants nothing", async () => {
    // The cors package adds `Vary: Origin` only on the granting branch, so
    // without an explicit one a shared cache could serve the untrusted
    // (grant-less) answer to the app's own origin and break it.
    const response = await probe(
      "GET",
      "/api/auth/get-session",
      UNTRUSTED_ORIGIN,
    );

    expect(response.headers.get("vary")?.toLowerCase()).toContain("origin");
  });
});

// ---------------------------------------------------------------------------
// The relay itself
// ---------------------------------------------------------------------------

describe("the /api/auth relay", () => {
  afterEach(() => {
    h.authHandler.mockReset();
    h.authHandler.mockResolvedValue(new Response(null, { status: 200 }));
  });

  it("does not copy a CORS grant out of better-auth's response", async () => {
    // better-auth emits no `Access-Control-*` header today (verified against
    // 1.6.23). This pins what happens if a future release starts: an upstream
    // default must not be able to overwrite the policy chosen for the one
    // route in this app whose responses carry the session.
    h.authHandler.mockResolvedValue(
      new Response(JSON.stringify({ session: null }), {
        status: 200,
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Credentials": "true",
          "X-Better-Auth-Passthrough": "kept",
        },
      }),
    );

    const response = await probe(
      "GET",
      "/api/auth/get-session",
      UNTRUSTED_ORIGIN,
    );

    expect(response.headers.get(ACAO)).toBeNull();
    expect(response.headers.get(ACAC)).toBeNull();
    // Non-CORS headers still cross the seam — the filter is narrow, not a
    // blanket refusal to copy.
    expect(response.headers.get("x-better-auth-passthrough")).toBe("kept");
  });

  it("answers a thrown error with the masked body, not the message", async () => {
    // This relay reaches better-auth, the drizzle adapter and postgres, and
    // `/api/auth/*` takes no credential — so an error message echoed here is
    // internal detail handed to an anonymous caller.
    const secret = "connect ECONNREFUSED internal-postgres.svc:5432";
    h.authHandler.mockRejectedValue(new Error(secret));

    const response = await probe("GET", "/api/auth/get-session", APP_ORIGIN);
    const raw = await response.text();

    expect(response.status).toBe(500);
    expect(JSON.parse(raw)).toEqual(INTERNAL_ERROR_BODY);
    expect(raw).not.toContain(secret);
    expect(raw).not.toContain("internal-postgres");
    expect(raw).not.toContain("ECONNREFUSED");
    expect(raw).not.toContain("at ");
  });

  it("keeps its CORS grant on the masked error response", async () => {
    // A 500 the frontend cannot read is a 500 nobody can act on.
    h.authHandler.mockRejectedValue(new Error("boom"));

    const response = await probe("GET", "/api/auth/get-session", APP_ORIGIN);

    expect(response.status).toBe(500);
    expect(response.headers.get(ACAO)).toBe(APP_ORIGIN);
  });
});

describe("nothing bleeds onto a router that declares no policy", () => {
  it.each([
    ["preflight", "OPTIONS"],
    ["call", "GET"],
  ])(
    "leaves a /trpc %s with no CORS headers at all",
    async (_label, method) => {
      // The `/trpc` mount in this file has no cors() of its own, so any header
      // here came from a neighbour. The real router (./trpc.ts) adds an
      // APP_URL-pinned policy on top of this baseline.
      const { acao, acac } = await corsHeaders(
        method,
        "/trpc/frontend/mcpServers.list",
        UNTRUSTED_ORIGIN,
      );

      expect(acao).toBeNull();
      expect(acac).toBeNull();
    },
  );
});

// ---------------------------------------------------------------------------
// /metamcp — reflected origin removed
// ---------------------------------------------------------------------------

describe("/metamcp allowlists instead of reflecting", () => {
  it("gives an untrusted origin no grant on a preflight", async () => {
    const { acao, acac } = await corsHeaders(
      "OPTIONS",
      "/metamcp/some-endpoint/mcp",
      UNTRUSTED_ORIGIN,
    );

    expect(acao).toBeNull();
    expect(acac).toBeNull();
  });

  it("echoes the app's own origin back, with credentials", async () => {
    const { acao, acac } = await corsHeaders(
      "OPTIONS",
      "/metamcp/some-endpoint/mcp",
      APP_ORIGIN,
    );

    expect(acao).toBe(APP_ORIGIN);
    expect(acac).toBe("true");
  });
});

// ---------------------------------------------------------------------------
// Regression: OAuth clients must keep working
// ---------------------------------------------------------------------------

describe("OAuth discovery and endpoints still answer any origin", () => {
  it.each([
    ["/.well-known/oauth-authorization-server", "GET"],
    ["/.well-known/oauth-protected-resource", "GET"],
    ["/oauth/authorize", "OPTIONS"],
    ["/oauth/token", "OPTIONS"],
    ["/oauth/register", "OPTIONS"],
    ["/oauth/userinfo", "OPTIONS"],
  ])("%s still answers with a wildcard grant", async (path, method) => {
    // Breaking this takes down every MCP client that discovers this gateway:
    // these paths are read by clients the deployment has never seen, so an
    // allowlist cannot be built for them.
    const { acao } = await corsHeaders(method, path, UNTRUSTED_ORIGIN);

    expect(acao).toBe("*");
  });

  it("does not pair that wildcard with credentials", async () => {
    // A browser refuses `*` the moment credentials are requested, so the pair
    // granted nothing; what it did do was put a credentials header on paths a
    // neighbouring router was inheriting.
    const { acac } = await corsHeaders(
      "GET",
      "/.well-known/oauth-authorization-server",
      UNTRUSTED_ORIGIN,
    );

    expect(acac).toBeNull();
  });

  it("does not apply the OAuth policy to a lookalike path", async () => {
    // `startsWith("/oauth")` alone would match `/oauthanything`; the guard
    // matches whole segments.
    const { acao } = await corsHeaders(
      "GET",
      "/oauth-not-ours",
      UNTRUSTED_ORIGIN,
    );

    expect(acao).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// The allowlist itself
// ---------------------------------------------------------------------------

describe("resolveTrustedOrigin", () => {
  it("matches APP_URL regardless of case or trailing slash", () => {
    expect(resolveTrustedOrigin("HTTPS://GATEWAY.EXAMPLE.TEST/")).toBe(
      APP_ORIGIN,
    );
  });

  it("returns the normalised origin, never the caller's own bytes", () => {
    // What comes back is echoed into a response header, so it must be a value
    // this process constructed rather than one the caller supplied.
    expect(resolveTrustedOrigin(`${APP_ORIGIN}/some/path?q=1`)).toBe(
      APP_ORIGIN,
    );
  });

  it("rejects a host that merely ends with the trusted one", () => {
    expect(
      resolveTrustedOrigin("https://gateway.example.test.evil.example"),
    ).toBeNull();
  });

  it("resolves the REAL host of a userinfo lookalike, not the readable part", () => {
    // `https://<trusted>@evil` parses to host evil.example.test; returning the
    // caller's bytes rather than the parsed origin would echo a string that
    // reads as the trusted host.
    expect(
      resolveTrustedOrigin(`https://evil@${new URL(APP_ORIGIN).host}`),
    ).toBe(APP_ORIGIN);
    expect(
      resolveTrustedOrigin("https://gateway.example.test@evil.example.test"),
    ).toBeNull();
  });

  it("rejects the backslash form of the same trick", () => {
    // WHATWG treats a backslash as a slash in special schemes, so this is
    // `https://gateway.example.test/@evil.com` — path, not host — while a
    // naive prefix comparison would read it as the trusted host followed by
    // junk. Whichever way it parses, the answer must not be a grant for a host
    // this process did not resolve.
    const resolved = resolveTrustedOrigin(
      "https://gateway.example.test\\@evil.example.test",
    );

    expect(resolved === null || resolved === APP_ORIGIN).toBe(true);
    expect(resolved).not.toContain("evil");
  });

  it("treats a port mismatch as a different origin", () => {
    expect(
      resolveTrustedOrigin("https://gateway.example.test:8443"),
    ).toBeNull();
    // ...including the explicit default port, which normalises away and so
    // must still match.
    expect(resolveTrustedOrigin("https://gateway.example.test:443")).toBe(
      APP_ORIGIN,
    );
  });

  it("rejects every non-http(s) scheme, which all share one opaque origin", () => {
    for (const exotic of [
      "moz-extension://aaaa-bbbb",
      "chrome-extension://aaaa-bbbb",
      "app://some.bundle.id",
      "file:///etc/passwd",
      "data:text/html,x",
      "ftp://gateway.example.test",
    ]) {
      expect(resolveTrustedOrigin(exotic), exotic).toBeNull();
    }
  });

  it("rejects an absent, empty or unparseable Origin", () => {
    expect(resolveTrustedOrigin(undefined)).toBeNull();
    expect(resolveTrustedOrigin("")).toBeNull();
    expect(resolveTrustedOrigin("null")).toBeNull();
    expect(resolveTrustedOrigin("not a url")).toBeNull();
  });

  it("rejects a scheme mismatch on an otherwise trusted host", () => {
    expect(resolveTrustedOrigin("http://gateway.example.test")).toBeNull();
  });

  it("rejects loopback while the deployment is not itself loopback", () => {
    // On a deployed gateway a blanket localhost allowance would let any web
    // server on the victim's own machine read their authenticated responses.
    expect(resolveTrustedOrigin("http://localhost:3000")).toBeNull();
    expect(resolveTrustedOrigin("http://127.0.0.1:5173")).toBeNull();
  });

  it("accepts loopback once the deployment is loopback too", () => {
    const previous = process.env.APP_URL;
    process.env.APP_URL = "http://localhost:12008";
    try {
      expect(resolveTrustedOrigin("http://localhost:3000")).toBe(
        "http://localhost:3000",
      );
      expect(resolveTrustedOrigin("http://127.0.0.1:5173")).toBe(
        "http://127.0.0.1:5173",
      );
      expect(resolveTrustedOrigin("http://[::1]:5173")).toBe(
        "http://[::1]:5173",
      );
      expect(resolveTrustedOrigin(UNTRUSTED_ORIGIN)).toBeNull();
    } finally {
      process.env.APP_URL = previous;
    }
  });
});

describe("isCorsResponseHeader", () => {
  it("names every CORS grant header, case-insensitively", () => {
    // The relay in ../index filters better-auth's response headers through
    // this so an upstream default can never replace the policy chosen here.
    expect(isCorsResponseHeader("Access-Control-Allow-Origin")).toBe(true);
    expect(isCorsResponseHeader("access-control-allow-credentials")).toBe(true);
    expect(isCorsResponseHeader("ACCESS-CONTROL-EXPOSE-HEADERS")).toBe(true);
  });

  it("leaves the headers the relay must copy alone", () => {
    for (const header of ["set-cookie", "content-type", "vary", "location"]) {
      expect(isCorsResponseHeader(header)).toBe(false);
    }
  });
});

// ---------------------------------------------------------------------------
// The other two credentialed routers
// ---------------------------------------------------------------------------

describe("/mcp-proxy and /trpc are on the same allowlist", () => {
  it("answers a preflight from the app's own origin with that origin", async () => {
    // Also the proof that the negative assertions above are not vacuous: if
    // this path stopped reaching the CORS middleware at all, every "no grant
    // for an untrusted origin" case would pass for the wrong reason.
    const { status, acao, acac } = await corsHeaders(
      "OPTIONS",
      "/mcp-proxy/metamcp/some-uuid/mcp",
      APP_ORIGIN,
    );

    expect(status).toBe(204);
    expect(acao).toBe(APP_ORIGIN);
    expect(acac).toBe("true");
  });

  it("grants the app's own origin even on the 401 the gate returns", async () => {
    // CORS is decided before the session and admin gates, deliberately: the
    // frontend has to be able to READ the 401 to know it must sign in.
    const response = await probe("GET", "/mcp-proxy/server/mcp", APP_ORIGIN);

    expect(response.status).toBe(401);
    expect(response.headers.get(ACAO)).toBe(APP_ORIGIN);
  });

  it("gives an untrusted origin no grant on either leg", async () => {
    for (const [method, path] of [
      ["OPTIONS", "/mcp-proxy/metamcp/some-uuid/mcp"],
      ["GET", "/mcp-proxy/server/mcp"],
    ] as [string, string][]) {
      const { acao, acac } = await corsHeaders(method, path, UNTRUSTED_ORIGIN);

      expect(acao, `${method} ${path}`).toBeNull();
      expect(acac, `${method} ${path}`).toBeNull();
    }
  });

  it("marks the preflight Origin-dependent", async () => {
    // A shared cache that ignored this would serve one origin's answer to
    // another; with an allowlist that is the difference between a working app
    // and a blocked one.
    const response = await probe(
      "OPTIONS",
      "/mcp-proxy/metamcp/some-uuid/mcp",
      APP_ORIGIN,
    );

    expect(response.headers.get("vary")?.toLowerCase()).toContain("origin");
  });
});

// ---------------------------------------------------------------------------
// Repo-wide drift guard
// ---------------------------------------------------------------------------

describe("every credentialed cors() in the backend uses the shared allowlist", () => {
  /**
   * Mounting all six routers in one test file is not practical — the tRPC
   * router alone drags the whole procedure tree and the MCP pool into the
   * import graph. So the routers this file DOES drive prove the behaviour, and
   * this reads the source of every `cors()` call site to prove none of them
   * drifted off the shared resolver. Same technique as the `app.listen()` port
   * guard in `oauth/redirect-uri-allowlist.test.ts`.
   *
   * This also catches what no mounted-router test can: a NEW credentialed
   * router added later with `origin: true` or a raw env string.
   */
  const SRC = path.resolve(import.meta.dirname, "..");

  function sourceFiles(dir: string): string[] {
    return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) return sourceFiles(full);
      if (!entry.name.endsWith(".ts")) return [];
      if (entry.name.endsWith(".test.ts")) return [];
      return [full];
    });
  }

  /** Every `cors({ ... })` options object in the backend, with its file. */
  const CORS_CALLS = sourceFiles(SRC).flatMap((file) => {
    const source = readFileSync(file, "utf8");
    return [...source.matchAll(/\bcors\(\{[\s\S]*?\n\s*\}\)/g)].map((m) => ({
      file: path.relative(SRC, file),
      options: m[0],
    }));
  });

  it("finds the call sites it is meant to be guarding", () => {
    // A regex that silently matched nothing would make every assertion below
    // pass without checking anything.
    const files = CORS_CALLS.map((c) => c.file).sort();

    expect(files).toEqual([
      "lib/cors-policy.ts",
      "routers/mcp-proxy.ts",
      "routers/oauth/index.ts",
      "routers/public-metamcp.ts",
      "routers/trpc.ts",
    ]);
  });

  it("never pairs credentials with a wildcard or a reflected origin", () => {
    for (const { file, options } of CORS_CALLS) {
      if (!/credentials:\s*true/.test(options)) continue;

      expect(options, `${file}: origin: true reflects the caller`).not.toMatch(
        /origin:\s*true/,
      );
      expect(options, `${file}: origin: "*" with credentials`).not.toMatch(
        /origin:\s*["'`]\*["'`]/,
      );
      // A raw env string is set as the ACAO for EVERY caller, and an unset or
      // empty one is falsy — which the cors package answers with `*`.
      expect(
        options,
        `${file}: raw env origin instead of the shared resolver`,
      ).not.toMatch(/origin:\s*process\.env\./);
      expect(
        options,
        `${file}: credentialed cors must use credentialedCorsOrigin`,
      ).toMatch(/origin:\s*credentialedCorsOrigin/);
    }
  });

  it("allows the wildcard only where credentials are absent", () => {
    const wildcards = CORS_CALLS.filter(({ options }) =>
      /origin:\s*["'`]\*["'`]/.test(options),
    );

    // Exactly one: OAuth discovery, read by clients this deployment has never
    // seen. If a second appears, it needs the same justification written down.
    expect(wildcards.map((w) => w.file)).toEqual(["routers/oauth/index.ts"]);
    for (const { file, options } of wildcards) {
      expect(
        options,
        `${file}: wildcard must not allow credentials`,
      ).not.toMatch(/credentials:\s*true/);
    }
  });
});
