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
 * their lazy-import seams so no repository reaches db/index. `../db/index`
 * itself is mocked to throw, so any import of it from this graph fails the
 * suite rather than passing because a test environment happened to carry a
 * DATABASE_URL.
 *
 * The admin-key failure budget block at the end runs the REAL resolver behind
 * the resolver spy, with only its key lookup (`validateAdminPlaneApiKey`) and
 * the audit `emit` stubbed, so failed verifications are recorded against the
 * real limiter exactly as in production.
 */

import type { Server } from "node:http";

import express from "express";
import {
  afterAll,
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";

const {
  authHandlerMock,
  isDisabledMock,
  resolveMock,
  validateAdminPlaneApiKeyMock,
  emitMock,
  loggerMock,
} = vi.hoisted(() => ({
  authHandlerMock: vi.fn(),
  isDisabledMock: vi.fn(),
  resolveMock: vi.fn(),
  validateAdminPlaneApiKeyMock: vi.fn(),
  emitMock: vi.fn(),
  loggerMock: {
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  },
}));

vi.mock("../auth", () => ({ auth: { handler: authHandlerMock } }));
vi.mock("../utils/logger", () => ({ default: loggerMock }));
vi.mock("../db/index", () => {
  throw new Error("db/index must not load in this suite");
});
vi.mock("../db/repositories/users.repo", () => ({
  usersRepository: { isDisabled: isDisabledMock },
}));
vi.mock("../db/repositories/api-keys.repo", () => ({
  ApiKeysRepository: class {
    validateAdminPlaneApiKey = validateAdminPlaneApiKeyMock;
  },
}));
vi.mock("../lib/audit/audit-emitter", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../lib/audit/audit-emitter")>()),
  emit: emitMock,
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

  it("marks a resolved admin-plane request with the verified key's origin", async () => {
    resolveMock.mockResolvedValue({
      user: BEARER_USER,
      session: BEARER_SESSION,
      keyUuid: "77777777-7777-4777-8777-777777777777",
    });

    const ctx = await createContext(
      makeCtxArgs({ authorization: "Bearer sk_mt_ci_key" }),
    );

    // A resolver answer without a scope reads as `sync`, the narrow one.
    expect(ctx.authOrigin).toEqual({
      kind: "admin_plane",
      key_uuid: "77777777-7777-4777-8777-777777777777",
      owner_user_id: "ci-user",
      scope: "sync",
    });
  });

  it.each([
    ["operator", "operator"],
    ["sync", "sync"],
    // Anything but the literal `operator` fails closed to `sync`.
    ["Operator", "sync"],
    ["admin", "sync"],
    [undefined, "sync"],
    [null, "sync"],
    [{ toString: (): string => "operator" }, "sync"],
  ])(
    "carries the resolver's verified scope %j into the origin as %s",
    async (resolved, expected) => {
      resolveMock.mockResolvedValue({
        user: BEARER_USER,
        session: BEARER_SESSION,
        keyUuid: "77777777-7777-4777-8777-777777777777",
        scope: resolved,
      });

      const ctx = await createContext(
        makeCtxArgs({ authorization: "Bearer sk_mt_ci_key" }),
      );

      expect(ctx.authOrigin?.scope).toBe(expected);
    },
  );

  it("never marks a cookie session, even one that also sends a bearer", async () => {
    authHandlerMock.mockResolvedValue(cookieSessionResponse());

    const ctx = await createContext(
      makeCtxArgs({
        cookie: "better-auth.session_token=abc",
        authorization: "Bearer sk_mt_some_admin_plane_key",
      }),
    );

    expect(ctx.user?.id).toBe("cookie-user");
    expect(ctx).not.toHaveProperty("authOrigin");
  });

  it("does not mark a request whose bearer did not resolve", async () => {
    resolveMock.mockResolvedValue(null);

    const ctx = await createContext(
      makeCtxArgs({ authorization: "Bearer sk_mt_not_admin_plane" }),
    );

    expect(ctx).not.toHaveProperty("authOrigin");
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

describe("createContext: admin-plane key refused by its IP policy (migration 0041)", () => {
  const GENERIC =
    "This credential is not currently permitted to access this gateway.";

  it("throws FORBIDDEN with the generic sentence instead of leaving the request unauthenticated", async () => {
    resolveMock.mockResolvedValue({ ipDenied: true });

    await expect(
      createContext(makeCtxArgs({ authorization: "Bearer sk_mt_ci_key" })),
    ).rejects.toMatchObject({ code: "FORBIDDEN", message: GENERIC });
  });

  it("answers HTTP 403 through the real tRPC request handler, for any procedure", async () => {
    resolveMock.mockResolvedValue({ ipDenied: true });
    const { router, protectedProcedure, publicProcedure } = await import(
      "../trpc"
    );
    const { fetchRequestHandler } = await import("@trpc/server/adapters/fetch");
    const appRouter = router({
      ping: protectedProcedure.query(() => "pong"),
      open: publicProcedure.query(() => "open"),
    });

    for (const path of ["ping", "open"]) {
      const response = await fetchRequestHandler({
        endpoint: "/trpc",
        req: new Request(`http://gateway.example.invalid/trpc/${path}`),
        router: appRouter,
        createContext: () =>
          createContext(makeCtxArgs({ authorization: "Bearer sk_mt_ci_key" })),
      });
      const body = (await response.json()) as {
        error?: { message?: string; data?: { code?: string } };
      };

      expect(response.status).toBe(403);
      expect(body.error?.message).toBe(GENERIC);
      expect(body.error?.data?.code).toBe("FORBIDDEN");
    }
  });

  it("a null resolution is still a plain unauthenticated request (401 path unchanged)", async () => {
    resolveMock.mockResolvedValue(null);

    const ctx = await createContext(
      makeCtxArgs({ authorization: "Bearer sk_mt_unknown" }),
    );

    expect(ctx.user).toBeUndefined();
  });
});

/**
 * The admin-key failure budget on the bearer path, through the real tRPC
 * express handler.
 *
 * The middleware in front of `/trpc` checks only requests with no Cookie
 * header; createContext checks the same budget once a cookie has resolved no
 * usable session. These cases mount both, in production order, on a real
 * socket, with the real limiter, the real resolver and @repo/trpc's own
 * procedures (whose unauthenticated branch writes to the tRPC denial sink).
 * Each case keys on its own edge address because the limiter is
 * module-scoped.
 */
describe("createContext: admin-key failure budget behind a cookie that resolves no session", () => {
  const BUDGET = 20;
  const UNKNOWN_KEY = "Bearer sk_mt_not_a_real_key";
  const denialSinkMock = vi.fn();

  let server: Server;
  let baseUrl: string;
  let edgeCounter = 0;
  const freshEdgeIp = () => {
    edgeCounter += 1;
    return `203.0.113.${edgeCounter}`;
  };

  beforeAll(async () => {
    const trpcExpress = await import("@trpc/server/adapters/express");
    const repoTrpc = await import("@repo/trpc");
    const { createTrpcAdminKeyRateLimitMiddleware } = await import(
      "../middleware/trpc-admin-key-rate-limit.middleware"
    );
    repoTrpc.setTrpcAuditSink(denialSinkMock);

    const appRouter = repoTrpc.router({
      ping: repoTrpc.protectedProcedure.query(() => "pong"),
    });
    const app = express();
    // Production order (routers/trpc.ts): the admin-key middleware with the
    // real module-scoped limiter, then the tRPC handler.
    app.use(
      "/trpc",
      createTrpcAdminKeyRateLimitMiddleware(),
      trpcExpress.createExpressMiddleware({ router: appRouter, createContext }),
    );
    await new Promise<void>((resolve) => {
      server = app.listen(0, "127.0.0.1", () => resolve());
    });
    const address = server.address();
    if (!address || typeof address === "string") {
      throw new Error("test server has no TCP address");
    }
    baseUrl = `http://127.0.0.1:${address.port}`;
  });

  afterAll(async () => {
    const repoTrpc = await import("@repo/trpc");
    repoTrpc.setTrpcAuditSink(null);
    await new Promise<void>((resolve, reject) =>
      server.close((error) => (error ? reject(error) : resolve())),
    );
  });

  beforeEach(async () => {
    const actual = await vi.importActual<
      typeof import("../lib/admin-plane-auth")
    >("../lib/admin-plane-auth");
    resolveMock.mockImplementation(actual.resolveAdminPlaneSession);
    validateAdminPlaneApiKeyMock.mockResolvedValue({
      valid: false,
      reason: "unknown_key",
    });
    denialSinkMock.mockClear();
  });

  afterEach(() => {
    resolveMock.mockReset();
    validateAdminPlaneApiKeyMock.mockReset();
    authHandlerMock.mockReset();
    vi.useRealTimers();
  });

  /** better-auth's answer for a cookie, built fresh per call. */
  const cookieResolves = {
    nothing: () => new Response("null", { status: 200 }),
    rejected: () => new Response(null, { status: 401 }),
    validSession: () => cookieSessionResponse(),
  };

  interface CallResult {
    status: number;
    retryAfter: string | null;
    body: {
      error?: { message?: string; data?: { code?: string } } | string;
      result?: { data?: unknown };
    };
  }

  async function call(
    edgeIp: string,
    options: { cookie?: boolean } = {},
  ): Promise<CallResult> {
    const headers: Record<string, string> = {
      authorization: UNKNOWN_KEY,
      "cf-connecting-ip": edgeIp,
    };
    if (options.cookie) headers.cookie = "better-auth.session_token=stale";
    const response = await fetch(`${baseUrl}/trpc/ping`, { headers });
    return {
      status: response.status,
      retryAfter: response.headers.get("retry-after"),
      body: (await response.json()) as CallResult["body"],
    };
  }

  /** Spend `count` failures from `edgeIp` with no cookie, each a plain 401. */
  async function spendWithoutCookie(edgeIp: string, count: number) {
    for (let i = 0; i < count; i += 1) {
      expect((await call(edgeIp)).status).toBe(401);
    }
  }

  function clearSpies() {
    resolveMock.mockClear();
    validateAdminPlaneApiKeyMock.mockClear();
    emitMock.mockClear();
    denialSinkMock.mockClear();
    authHandlerMock.mockClear();
  }

  it.each([
    ["resolves no session", "nothing"],
    ["is rejected by better-auth", "rejected"],
  ] as const)(
    "answers HTTP 429 when the cookie %s and the budget is spent, without resolving the key",
    async (_label, outcome) => {
      const edgeIp = freshEdgeIp();
      await spendWithoutCookie(edgeIp, BUDGET);
      clearSpies();
      authHandlerMock.mockImplementation(async () => cookieResolves[outcome]());

      const refused = await call(edgeIp, { cookie: true });

      expect(refused.status).toBe(429);
      expect(refused.retryAfter).toBe("60");
      // A tRPC envelope, so this was createContext's answer, not the
      // middleware's (the middleware passes cookie-carrying requests on).
      expect(refused.body.error).toMatchObject({
        message:
          "Too many failed authentication attempts. Please try again later.",
        data: { code: "TOO_MANY_REQUESTS" },
      });
      // The cookie was resolved first, as before.
      expect(authHandlerMock).toHaveBeenCalledTimes(1);
      // Nothing past the check ran: no resolver, no key lookup, no admin-key
      // denial row, no tRPC authn denial.
      expect(resolveMock).not.toHaveBeenCalled();
      expect(validateAdminPlaneApiKeyMock).not.toHaveBeenCalled();
      expect(emitMock).not.toHaveBeenCalled();
      expect(denialSinkMock).not.toHaveBeenCalled();
    },
  );

  it("answers HTTP 429 for a cookie whose account is disabled once the budget is spent", async () => {
    // A disabled account's cookie leaves the request unauthenticated, so it
    // reaches the bearer path like any cookie that resolves nothing.
    const edgeIp = freshEdgeIp();
    await spendWithoutCookie(edgeIp, BUDGET);
    clearSpies();
    authHandlerMock.mockImplementation(async () =>
      cookieResolves.validSession(),
    );
    isDisabledMock.mockResolvedValueOnce(true);

    const refused = await call(edgeIp, { cookie: true });

    expect(refused.status).toBe(429);
    expect(resolveMock).not.toHaveBeenCalled();
    expect(validateAdminPlaneApiKeyMock).not.toHaveBeenCalled();
  });

  it("serves a valid, enabled cookie carrying a stale bearer even when the budget is spent", async () => {
    const edgeIp = freshEdgeIp();
    await spendWithoutCookie(edgeIp, BUDGET);
    // The no-cookie path is refused by the middleware at this point...
    expect((await call(edgeIp)).status).toBe(429);
    clearSpies();
    authHandlerMock.mockImplementation(async () =>
      cookieResolves.validSession(),
    );

    // ...and a signed-in user from the same address is still served.
    const served = await call(edgeIp, { cookie: true });

    expect(served.status).toBe(200);
    expect(served.body.result?.data).toBe("pong");
    expect(resolveMock).not.toHaveBeenCalled();
    expect(validateAdminPlaneApiKeyMock).not.toHaveBeenCalled();
  });

  it("counts no-cookie and cookie-bearing failures once each against one per-client budget", async () => {
    const edgeIp = freshEdgeIp();
    authHandlerMock.mockImplementation(async () => cookieResolves.nothing());

    // Ten failures without a cookie and nine behind a cookie that resolves
    // nothing: nineteen, all answered as ordinary 401s.
    await spendWithoutCookie(edgeIp, 10);
    for (let i = 0; i < 9; i += 1) {
      expect((await call(edgeIp, { cookie: true })).status).toBe(401);
    }
    // The twentieth is still inside the budget...
    expect((await call(edgeIp, { cookie: true })).status).toBe(401);
    // ...and each of the twenty reached the key lookup and wrote one denial
    // row: one count per failure, none for the checks.
    expect(validateAdminPlaneApiKeyMock).toHaveBeenCalledTimes(BUDGET);
    expect(
      emitMock.mock.calls.filter(
        ([row]) => row?.action === "authn.admin_key.denied",
      ),
    ).toHaveLength(BUDGET);

    // The twenty-first is refused on either path.
    const noCookie = await call(edgeIp);
    expect(noCookie.status).toBe(429);
    // The no-cookie refusal is the middleware's own body.
    expect(noCookie.body.error).toBe("too_many_requests");
    const withCookie = await call(edgeIp, { cookie: true });
    expect(withCookie.status).toBe(429);
    expect(validateAdminPlaneApiKeyMock).toHaveBeenCalledTimes(BUDGET);
  });

  it("resumes checking the key once the window has passed", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    const edgeIp = freshEdgeIp();
    authHandlerMock.mockImplementation(async () => cookieResolves.nothing());
    await spendWithoutCookie(edgeIp, BUDGET);
    expect((await call(edgeIp, { cookie: true })).status).toBe(429);
    clearSpies();
    authHandlerMock.mockImplementation(async () => cookieResolves.nothing());

    vi.setSystemTime(Date.now() + 61 * 1000);

    const resumed = await call(edgeIp, { cookie: true });
    expect(resumed.status).toBe(401);
    expect(validateAdminPlaneApiKeyMock).toHaveBeenCalledTimes(1);
    const resumedWithoutCookie = await call(edgeIp);
    expect(resumedWithoutCookie.status).toBe(401);
    expect(validateAdminPlaneApiKeyMock).toHaveBeenCalledTimes(2);
  });

  it("keeps separate budgets for separate edge addresses", async () => {
    const spent = freshEdgeIp();
    const other = freshEdgeIp();
    authHandlerMock.mockImplementation(async () => cookieResolves.nothing());
    await spendWithoutCookie(spent, BUDGET);
    expect((await call(spent, { cookie: true })).status).toBe(429);

    expect((await call(other, { cookie: true })).status).toBe(401);
  });
});
