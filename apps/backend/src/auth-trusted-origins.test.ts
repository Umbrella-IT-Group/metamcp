/**
 * Which origins better-auth trusts, pinned in the production shape.
 *
 * `trustedOrigins` in ./auth is the fixed loopback list plus
 * `EXTRA_TRUSTED_ORIGINS`, and better-auth adds the `APP_URL` origin itself. A
 * deployment sets `APP_URL` and `EXTRA_TRUSTED_ORIGINS` to the same single
 * exact https origin, with no wildcard, so this file does the same with a
 * stand-in host. Those origins gate two things: the `Origin` (or `Referer`) of
 * any POST that carries a cookie, and every `callbackURL`, `redirectTo`,
 * `errorCallbackURL` and `newUserCallbackURL` a POST names, which is what
 * keeps sign-in and sign-out from redirecting off the gateway.
 *
 * Why it is pinned. better-auth 1.7.16 and 1.7.17 rewrote wildcard matching
 * (GHSA-4wq4-2ppv-q3hg and upstream #12217). None of our entries is a
 * wildcard, so the exact-origin branch is the one that runs, and these cases
 * hold the same answers on 1.7.8 and 1.7.17. A later change to that branch,
 * to how better-auth assembles the list, or to which requests it checks
 * fails here instead of in production.
 *
 * `/sign-out` drives the real middleware with no database: a session cookie
 * that is not signed reads as no session, so the endpoint answers without a
 * query once the origin checks pass.
 */

import { afterAll, describe, expect, it, vi } from "vitest";

vi.mock("./lib/config.service", () => ({
  configService: {
    isSignupDisabled: vi.fn().mockResolvedValue(false),
    isSsoSignupDisabled: vi.fn().mockResolvedValue(false),
    isBasicAuthDisabled: vi.fn().mockResolvedValue(false),
  },
}));

vi.mock("./db/repositories/users.repo", () => ({
  usersRepository: { isDisabled: vi.fn().mockResolvedValue(false) },
}));

// db/index builds a live pg Pool at import; the drizzle adapter only needs an
// object to hold on to, since no query runs in this file.
vi.mock("./db/index", () => ({ db: {}, pool: {} }));

vi.mock("./lib/audit/auth-hook-audit", () => ({
  emitSignupDenied: vi.fn(),
  emitSignupCreated: vi.fn(),
  emitSessionCreated: vi.fn(),
  emitSessionRevoked: vi.fn(),
}));

vi.mock("./utils/logger", () => ({
  default: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

const GATEWAY = "https://gateway.example.com";

// The loopback entries ./auth hardcodes, in its order.
const LOOPBACK_ORIGINS = [
  "http://localhost",
  "http://localhost:3000",
  "http://localhost:12008",
  "http://127.0.0.1",
  "http://127.0.0.1:12008",
  "http://127.0.0.1:3000",
  "http://0.0.0.0",
  "http://0.0.0.0:3000",
  "http://0.0.0.0:12008",
];

vi.stubEnv("BETTER_AUTH_SECRET", "test-secret-not-a-real-key");
vi.stubEnv("APP_URL", GATEWAY);
vi.stubEnv("EXTRA_TRUSTED_ORIGINS", GATEWAY);
// No SSO provider here: the origin rules do not depend on one, and leaving it
// out keeps discovery fetches out of this file.
vi.stubEnv("OIDC_CLIENT_ID", "");
vi.stubEnv("OIDC_CLIENT_SECRET", "");
// better-auth appends this variable to the list; it must not leak in.
vi.stubEnv("BETTER_AUTH_TRUSTED_ORIGINS", "");
// better-auth turns its Origin and callbackURL checks OFF when it detects a
// test run (`NODE_ENV=test` or a truthy `TEST`, both of which vitest sets),
// unless `advanced.disableOriginCheck` is set. The gateway never runs that
// way, so clear both before ./auth is first imported (better-auth reads
// NODE_ENV once, at module load) and let better-auth reach the production
// decision itself. The first test below asserts it did.
vi.stubEnv("NODE_ENV", "");
vi.stubEnv("TEST", "");

afterAll(() => {
  vi.unstubAllEnvs();
});

async function loadAuth() {
  const { auth } = await import("./auth");
  const ctx = await auth.$context;
  return { auth, ctx };
}

// Spellings near a trusted origin that must not pass for it.
const UNTRUSTED = [
  ["the gateway over plain http", "http://gateway.example.com"],
  ["the gateway on another port", "https://gateway.example.com:8443"],
  ["a subdomain of the gateway", "https://evil.gateway.example.com"],
  ["the gateway name as a prefix", "https://gateway.example.com.evil.test"],
  ["the gateway name as userinfo", "https://gateway.example.com@evil.test"],
  ["an unrelated https origin", "https://evil.test"],
  ["localhost on an unlisted port", "http://localhost:3001"],
  ["localhost over https", "https://localhost"],
  ["another loopback address", "http://127.0.0.2"],
  ["IPv6 loopback", "http://[::1]:3000"],
  ["localhost as a prefix", "http://localhost.evil.test"],
  ["a custom scheme", "javascript://gateway.example.com"],
  ["a protocol-relative URL", "//evil.test"],
] as const;

describe("the origins better-auth trusts", () => {
  it("runs with the Origin and callbackURL checks on, as the gateway does", async () => {
    const { ctx } = await loadAuth();

    // With the checks off, every acceptance below would prove nothing and
    // every refusal would fail for a reason unrelated to the origin list.
    expect(ctx.skipOriginCheck).toBe(false);
    expect(ctx.skipCSRFCheck).toBe(false);
  });

  it("is exactly the loopback list, APP_URL and EXTRA_TRUSTED_ORIGINS", async () => {
    const { ctx } = await loadAuth();

    expect(new Set(ctx.trustedOrigins)).toEqual(
      new Set([GATEWAY, ...LOOPBACK_ORIGINS]),
    );
  });

  it.each([GATEWAY, ...LOOPBACK_ORIGINS])(
    "trusts %s, with or without a path",
    async (origin) => {
      const { ctx } = await loadAuth();

      expect(ctx.isTrustedOrigin(origin)).toBe(true);
      expect(ctx.isTrustedOrigin(`${origin}/admin?tab=1#top`)).toBe(true);
    },
  );

  it.each(UNTRUSTED)("does not trust %s", async (_label, url) => {
    const { ctx } = await loadAuth();

    expect(ctx.isTrustedOrigin(url)).toBe(false);
    expect(ctx.isTrustedOrigin(url, { allowRelativePaths: true })).toBe(false);
  });

  it("admits a relative path only where relative paths are allowed", async () => {
    const { ctx } = await loadAuth();

    expect(ctx.isTrustedOrigin("/mcp-servers")).toBe(false);
    expect(
      ctx.isTrustedOrigin("/mcp-servers", { allowRelativePaths: true }),
    ).toBe(true);
  });
});

function signOutRequest(headers: Record<string, string>, body: object = {}) {
  return new Request(`${GATEWAY}/api/auth/sign-out`, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
}

// Any cookie header makes better-auth check the Origin. This one is not a
// signed session token, so it reads as no session and nothing is queried.
const COOKIE = { cookie: "better-auth.session_token=not-a-signed-token" };

describe("the Origin check on a POST that carries a cookie", () => {
  it.each([GATEWAY, ...LOOPBACK_ORIGINS])(
    "accepts Origin %s",
    async (origin) => {
      const { auth } = await loadAuth();

      const res = await auth.handler(signOutRequest({ ...COOKIE, origin }));

      expect(res.status).toBe(200);
    },
  );

  it("accepts a Referer on the gateway when no Origin is sent", async () => {
    const { auth } = await loadAuth();

    const res = await auth.handler(
      signOutRequest({ ...COOKIE, referer: `${GATEWAY}/en/mcp-servers` }),
    );

    expect(res.status).toBe(200);
  });

  it.each(UNTRUSTED.filter(([, url]) => !url.startsWith("//")))(
    "refuses Origin %s",
    async (_label, origin) => {
      const { auth } = await loadAuth();

      const res = await auth.handler(signOutRequest({ ...COOKIE, origin }));

      expect(res.status).toBe(403);
      expect(await res.json()).toMatchObject({ code: "INVALID_ORIGIN" });
    },
  );

  it("refuses a cookie-bearing POST with no Origin or Referer", async () => {
    const { auth } = await loadAuth();

    const res = await auth.handler(signOutRequest(COOKIE));

    expect(res.status).toBe(403);
    expect(await res.json()).toMatchObject({
      code: "MISSING_OR_NULL_ORIGIN",
    });
  });
});

describe("the callbackURL check", () => {
  it.each([`${GATEWAY}/en/login`, "http://localhost:12008/", "/en/login"])(
    "accepts callbackURL %s",
    async (callbackURL) => {
      const { auth } = await loadAuth();

      const res = await auth.handler(
        signOutRequest({ origin: GATEWAY }, { callbackURL }),
      );

      expect(res.status).toBe(200);
    },
  );

  it.each(UNTRUSTED)("refuses callbackURL on %s", async (_label, url) => {
    const { auth } = await loadAuth();

    const res = await auth.handler(
      signOutRequest({ origin: GATEWAY }, { callbackURL: url }),
    );

    expect(res.status).toBe(403);
    expect(await res.json()).toMatchObject({ code: "INVALID_CALLBACK_URL" });
  });
});
