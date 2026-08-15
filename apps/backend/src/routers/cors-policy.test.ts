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
 * The real routers are driven over a real socket, mirroring
 * `public-metamcp.estate-gate.test.ts`. Mocked seams are the ones that would
 * otherwise drag postgres in: `../db/repositories`, `../auth` (which builds the
 * drizzle adapter at import time and throws without a database), and the four
 * `/metamcp` sub-routers. Every CORS decision under test runs for real.
 *
 * `/trpc` is mounted here as a bare router with NO CORS of its own — the real
 * one (./trpc.ts) adds `cors({ origin: process.env.APP_URL })`, which is a
 * fixed string and never a reflection. Leaving it bare is the stronger
 * assertion: any CORS header observed on that path could only have bled from a
 * neighbour.
 */
import type { Server } from "node:http";

import express from "express";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

const APP_ORIGIN = "https://gateway.example.test";
const UNTRUSTED_ORIGIN = "https://evil.example.test";
const EXTRA_ORIGIN = "https://partner.example.test";

// Read at import time by `getBaseUrl` in the OAuth metadata handler and, per
// request, by ../lib/cors-policy.
process.env.APP_URL = APP_ORIGIN;
process.env.EXTRA_TRUSTED_ORIGINS = `${EXTRA_ORIGIN}, `;

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

vi.mock("../auth", () => ({
  auth: { api: { getSession: vi.fn().mockResolvedValue(null) } },
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

const { authApiCorsMiddleware, isCorsResponseHeader, resolveTrustedOrigin } =
  await import("../lib/cors-policy");
const { default: oauthRouter } = await import("./oauth");
const { default: publicEndpointsRouter } = await import("./public-metamcp");

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

  app.use(authApiCorsMiddleware);
  app.use((req, res, next) => {
    if (!req.path.startsWith("/api/auth")) return next();
    // Stands in for the better-auth relay. better-auth emits no
    // `Access-Control-*` headers of its own (verified against 1.6.23), so an
    // empty-handed handler is a faithful stand-in for what the relay copies.
    res.status(200).json({ session: null });
  });

  app.use("/metamcp", publicEndpointsRouter);

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

// ---------------------------------------------------------------------------
// The invariant, everywhere
// ---------------------------------------------------------------------------

/** Every path exercised below, as [label, method, path]. */
const ALL_SURFACES: [string, string, string][] = [
  ["auth API session read", "GET", "/api/auth/get-session"],
  ["auth API preflight", "OPTIONS", "/api/auth/sign-up/email"],
  ["tRPC preflight", "OPTIONS", "/trpc/frontend/mcpServers.list"],
  ["tRPC call", "GET", "/trpc/frontend/mcpServers.list"],
  ["public MCP preflight", "OPTIONS", "/metamcp/some-endpoint/mcp"],
  ["public MCP listing", "GET", "/metamcp/"],
  ["OAuth authorize preflight", "OPTIONS", "/oauth/authorize"],
  ["OAuth discovery", "GET", "/.well-known/oauth-authorization-server"],
];

describe("no route pairs a wildcard or reflected origin with credentials", () => {
  it.each(ALL_SURFACES)(
    "%s never returns ACAO:* together with credentials",
    async (_label, method, path) => {
      const { acao, acac } = await corsHeaders(method, path, UNTRUSTED_ORIGIN);

      if (acac === "true") {
        expect(acao).not.toBe("*");
      }
    },
  );

  it.each(ALL_SURFACES)(
    "%s never reflects an untrusted Origin",
    async (_label, method, path) => {
      const { acao } = await corsHeaders(method, path, UNTRUSTED_ORIGIN);

      expect(acao).not.toBe(UNTRUSTED_ORIGIN);
    },
  );
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

  it("honours EXTRA_TRUSTED_ORIGINS, the same list better-auth is given", async () => {
    const { acao } = await corsHeaders(
      "GET",
      "/api/auth/get-session",
      EXTRA_ORIGIN,
    );

    expect(acao).toBe(EXTRA_ORIGIN);
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
