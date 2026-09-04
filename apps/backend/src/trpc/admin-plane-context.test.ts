/**
 * createContext — the admin-plane (control-plane) bearer branch (migration 0038).
 *
 * Pins the wiring the resolver test cannot: that createContext runs the bearer
 * path ONLY after the cookie block resolved nothing (cookie precedence), that a
 * resolved admin-plane session populates ctx.user/ctx.session, that a null
 * resolution leaves the request unauthenticated, that a non-Bearer Authorization
 * header never reaches the resolver, and — the DB-loadable invariant the lazy
 * import exists for — that this module imports with `../auth` mocked and NO
 * database, exactly as error-formatter.test.ts relies on.
 *
 * `../auth` is mocked (it throws at load without secrets and pulls a live pg
 * Pool); the disabled-account lookup and the admin-plane resolver are mocked at
 * their lazy-import seams so no repository reaches db/index.
 */

import express from "express";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { authHandlerMock, isDisabledMock, resolveMock, loggerMock } = vi.hoisted(
  () => ({
    authHandlerMock: vi.fn(),
    isDisabledMock: vi.fn(),
    resolveMock: vi.fn(),
    loggerMock: {
      debug: vi.fn(),
      info: vi.fn(),
      warn: vi.fn(),
      error: vi.fn(),
    },
  }),
);

vi.mock("../auth", () => ({ auth: { handler: authHandlerMock } }));
vi.mock("../utils/logger", () => ({ default: loggerMock }));
vi.mock("../db/repositories/users.repo", () => ({
  usersRepository: { isDisabled: isDisabledMock },
}));
vi.mock("../lib/admin-plane-auth", () => ({
  resolveAdminPlaneSession: resolveMock,
}));

const { createContext } = await import("../trpc");

const COOKIE_USER = { id: "cookie-user", email: "human@example.invalid" };
const COOKIE_SESSION = { id: "cookie-session", token: "cookie-token" };
const BEARER_USER = {
  id: "ci-user",
  email: "ci@example.invalid",
  role: "admin",
};
const BEARER_SESSION = { id: "admin-plane-x", token: "admin-plane-key" };
// Built at runtime, not as a literal, so this non-Bearer fixture never reads
// as an embedded credential to secret scanners.
const NON_BEARER_AUTH_HEADER =
  "Basic " + Buffer.from("user:pass").toString("base64");

function makeCtxArgs(headers: Record<string, string>) {
  const req = {
    headers: { host: "gateway.example.invalid", ...headers },
  } as unknown as express.Request;
  const res = {} as unknown as express.Response;
  return { req, res };
}

function cookieSessionResponse() {
  return new Response(
    JSON.stringify({ user: COOKIE_USER, session: COOKIE_SESSION }),
    { status: 200, headers: { "content-type": "application/json" } },
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  isDisabledMock.mockResolvedValue(false);
});

describe("createContext — cookie path unchanged", () => {
  it("authenticates a session cookie and never consults the bearer resolver", async () => {
    authHandlerMock.mockResolvedValue(cookieSessionResponse());

    const ctx = await createContext(
      makeCtxArgs({ cookie: "better-auth.session_token=abc" }),
    );

    expect(ctx.user?.id).toBe("cookie-user");
    expect(ctx.session).toBeTruthy();
    expect(resolveMock).not.toHaveBeenCalled();
  });

  it("cookie wins even when a bearer is also present (precedence)", async () => {
    authHandlerMock.mockResolvedValue(cookieSessionResponse());

    const ctx = await createContext(
      makeCtxArgs({
        cookie: "better-auth.session_token=abc",
        authorization: "Bearer sk_mt_some_admin_plane_key",
      }),
    );

    expect(ctx.user?.id).toBe("cookie-user");
    // The bearer path must not run when a cookie authenticated.
    expect(resolveMock).not.toHaveBeenCalled();
  });
});

describe("createContext — admin-plane bearer branch", () => {
  it("authenticates via the resolver when no cookie is present", async () => {
    resolveMock.mockResolvedValue({
      user: BEARER_USER,
      session: BEARER_SESSION,
    });

    const ctx = await createContext(
      makeCtxArgs({ authorization: "Bearer sk_mt_ci_key" }),
    );

    expect(resolveMock).toHaveBeenCalledWith("sk_mt_ci_key", expect.anything());
    expect(ctx.user?.id).toBe("ci-user");
    expect(ctx.session).toBeTruthy();
  });

  it("leaves the request unauthenticated when the resolver returns null", async () => {
    resolveMock.mockResolvedValue(null);

    const ctx = await createContext(
      makeCtxArgs({ authorization: "Bearer sk_mt_not_admin_plane" }),
    );

    expect(ctx.user).toBeUndefined();
    expect(ctx.session).toBeUndefined();
  });

  it("does not reach the resolver for a non-Bearer Authorization header", async () => {
    const ctx = await createContext(
      makeCtxArgs({ authorization: NON_BEARER_AUTH_HEADER }),
    );

    expect(resolveMock).not.toHaveBeenCalled();
    expect(ctx.user).toBeUndefined();
  });

  it("does not reach the resolver when there is no Authorization header", async () => {
    const ctx = await createContext(makeCtxArgs({}));

    expect(resolveMock).not.toHaveBeenCalled();
    expect(ctx.user).toBeUndefined();
  });
});

describe("createContext — DB-loadable invariant", () => {
  it("is a function reachable with ../auth mocked and no database", () => {
    // The bearer resolver reaches the repositories, so importing it at the top
    // of trpc.ts would make this module require a database at load. It is a
    // lazy import; this test would fail to even import the module otherwise.
    expect(typeof createContext).toBe("function");
  });
});
