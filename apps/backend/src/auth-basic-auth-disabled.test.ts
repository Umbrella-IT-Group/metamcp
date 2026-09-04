/**
 * DISABLE_BASIC_AUTH enforcement: while the setting is stored true, every
 * email/password credential path is refused with a 403 and no session is
 * created; SSO/OIDC paths are untouched.
 *
 * The regression this guards is specific. The setting used to be wired through
 * a top-level `middleware: [...]` array passed to betterAuth(), which
 * better-auth 1.6.23 has no such option for and silently ignored, so a stored
 * DISABLE_BASIC_AUTH=true still handed out sessions for a valid password. The
 * fix moves the check to `hooks.before` (the request middleware this version
 * actually runs), so this file asserts two things the old wiring could not:
 *
 *   1. the hook is present at `auth.options.hooks.before` at all (the old code
 *      had nothing there, the wiring control below would have failed on it);
 *   2. driving the REAL `auth.handler` on `/api/auth/sign-in/email` returns a
 *      403 from this hook when the flag is true and does NOT when it is false,
 *      i.e. better-auth genuinely invokes the hook on the live path, which is
 *      the exact fact the `middleware` array got wrong.
 *
 * Same harness technique as the siblings `auth-disabled-login.test.ts` and
 * `auth-signup-gate.test.ts`: configService is mocked so no database is needed,
 * and `db/index` is a stub the drizzle adapter merely holds a reference to.
 */

import { APIError } from "better-auth/api";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { isBasicAuthDisabledMock } = vi.hoisted(() => ({
  isBasicAuthDisabledMock: vi.fn(),
}));

vi.mock("./lib/config.service", () => ({
  configService: {
    isSignupDisabled: vi.fn().mockResolvedValue(false),
    isSsoSignupDisabled: vi.fn().mockResolvedValue(false),
    isBasicAuthDisabled: isBasicAuthDisabledMock,
  },
}));

vi.mock("./db/repositories/users.repo", () => ({
  usersRepository: { isDisabled: vi.fn().mockResolvedValue(false) },
}));

// db/index builds a live pg Pool at import; the drizzle adapter only needs an
// object to hold on to. The flag-true paths throw in the hook before any query
// runs; the flag-false handler path deliberately fails LATER against this stub,
// which is the point, it proves the hook let the request through.
vi.mock("./db/index", () => ({ db: {}, pool: {} }));

vi.mock("./lib/audit/auth-hook-audit", () => ({
  emitSignupDenied: vi.fn(),
  emitSignupCreated: vi.fn(),
  emitSessionCreated: vi.fn(),
  emitSessionRevoked: vi.fn(),
}));

vi.mock("./utils/logger", () => ({
  default: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  },
}));

// better-auth throws at module load without these.
process.env.BETTER_AUTH_SECRET ??= "test-secret-not-a-real-key";
process.env.APP_URL ??= "http://localhost:12008";

// The endpoint paths as they appear in `ctx.path` (base `/api/auth` stripped).
const SIGN_IN_EMAIL = { path: "/sign-in/email" };
const SIGN_UP_EMAIL = { path: "/sign-up/email" };
const REQUEST_PASSWORD_RESET = { path: "/request-password-reset" };
const RESET_PASSWORD = { path: "/reset-password" };
const RESET_PASSWORD_TOKEN = { path: "/reset-password/:token" };

// SSO / non-credential paths the hook must leave alone.
const SIGN_IN_SOCIAL = { path: "/sign-in/social" };
const OIDC_CALLBACK = { path: "/oauth2/callback/oidc" };
const SIGN_OUT = { path: "/sign-out" };
const GET_SESSION = { path: "/get-session" };

type BeforeHook = (ctx: { path: string }) => Promise<unknown>;

async function getBeforeHook(): Promise<BeforeHook> {
  const { auth } = await import("./auth");
  const hook = (auth.options as unknown as { hooks?: { before?: BeforeHook } })
    .hooks?.before;

  if (!hook) {
    // The old `middleware` array left this undefined, which is exactly the
    // silent-regression shape: the setting is stored but nothing enforces it.
    throw new Error(
      "auth.options.hooks.before is not configured, DISABLE_BASIC_AUTH is not enforced at all",
    );
  }

  return hook;
}

beforeEach(() => {
  vi.clearAllMocks();
  isBasicAuthDisabledMock.mockResolvedValue(false);
});

describe("hooks.before: wiring", () => {
  it("is actually registered in the better-auth options", async () => {
    // Control: every assertion below is meaningless if the hook is not
    // registered, so failing loudly here is the point. This is also the direct
    // regression assertion against the ignored `middleware` array.
    await expect(getBeforeHook()).resolves.toBeTypeOf("function");
  });
});

describe("hooks.before: refuses credential paths while DISABLE_BASIC_AUTH is true", () => {
  beforeEach(() => {
    isBasicAuthDisabledMock.mockResolvedValue(true);
  });

  it.each([
    ["sign-in/email", SIGN_IN_EMAIL],
    ["sign-up/email", SIGN_UP_EMAIL],
    ["request-password-reset", REQUEST_PASSWORD_RESET],
    ["reset-password", RESET_PASSWORD],
    ["reset-password/:token", RESET_PASSWORD_TOKEN],
  ])("refuses %s with a 403 APIError pointing to SSO", async (_label, ctx) => {
    const hook = await getBeforeHook();

    const err = await hook(ctx).then(
      () => {
        throw new Error("hook resolved but should have thrown");
      },
      (e: unknown) => e,
    );

    expect(err).toBeInstanceOf(APIError);
    expect((err as APIError).statusCode).toBe(403);
    expect((err as APIError).status).toBe("FORBIDDEN");
    expect((err as { body?: { message?: string } }).body?.message).toMatch(
      /disabled/i,
    );
    expect((err as { body?: { message?: string } }).body?.message).toMatch(
      /SSO/i,
    );
  });
});

describe("hooks.before: leaves SSO and non-credential paths alone", () => {
  beforeEach(() => {
    // Even with basic auth disabled, SSO is the only way in and must work.
    isBasicAuthDisabledMock.mockResolvedValue(true);
  });

  it.each([
    ["sign-in/social", SIGN_IN_SOCIAL],
    ["oauth2/callback/oidc", OIDC_CALLBACK],
    ["sign-out", SIGN_OUT],
    ["get-session", GET_SESSION],
  ])("passes %s through without throwing", async (_label, ctx) => {
    const hook = await getBeforeHook();

    await expect(hook(ctx)).resolves.toBeUndefined();
    // The flag is never even consulted for a path outside the credential set.
    expect(isBasicAuthDisabledMock).not.toHaveBeenCalled();
  });
});

describe("hooks.before: proceeds on credential paths while the flag is false", () => {
  it("lets sign-in/email through when DISABLE_BASIC_AUTH is false", async () => {
    isBasicAuthDisabledMock.mockResolvedValue(false);
    const hook = await getBeforeHook();

    await expect(hook(SIGN_IN_EMAIL)).resolves.toBeUndefined();
    expect(isBasicAuthDisabledMock).toHaveBeenCalledTimes(1);
  });
});

describe("hooks.before: reads the flag live, per request", () => {
  it("blocks, then allows, then blocks as the stored flag flips", async () => {
    // The setting is DB-backed and toggled at runtime, so the hook must not
    // cache it: a flip has to take effect on the very next request.
    const hook = await getBeforeHook();

    isBasicAuthDisabledMock.mockResolvedValue(true);
    await expect(hook(SIGN_IN_EMAIL)).rejects.toBeInstanceOf(APIError);

    isBasicAuthDisabledMock.mockResolvedValue(false);
    await expect(hook(SIGN_IN_EMAIL)).resolves.toBeUndefined();

    isBasicAuthDisabledMock.mockResolvedValue(true);
    await expect(hook(SIGN_IN_EMAIL)).rejects.toBeInstanceOf(APIError);
  });
});

describe("auth.handler: better-auth actually invokes the hook on the live path", () => {
  // The `/api/auth` base is better-auth's default basePath. A trusted Origin is
  // set so the POST clears the origin check and reaches the before-hook.
  function signInRequest(): Request {
    return new Request("http://localhost:12008/api/auth/sign-in/email", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        origin: "http://localhost:12008",
      },
      body: JSON.stringify({
        email: "user@example.com",
        password: "whatever-not-checked",
      }),
    });
  }

  const BASIC_AUTH_DISABLED_MESSAGE =
    "Basic email/password authentication is disabled. Sign in with SSO/OIDC instead.";

  it("returns this hook's 403 when the flag is true (no session created)", async () => {
    isBasicAuthDisabledMock.mockResolvedValue(true);
    const { auth } = await import("./auth");

    const res = await auth.handler(signInRequest());

    expect(res.status).toBe(403);
    const body = (await res.json()) as { message?: string };
    expect(body.message).toBe(BASIC_AUTH_DISABLED_MESSAGE);
    // No session: better-auth mints the session cookie from inside the
    // sign-in endpoint, which the hook prevents from ever running.
    expect(res.headers.get("set-cookie")).toBeNull();
  });

  it("does NOT return this hook's 403 when the flag is false (request proceeds past the hook)", async () => {
    isBasicAuthDisabledMock.mockResolvedValue(false);
    const { auth } = await import("./auth");

    const res = await auth.handler(signInRequest());

    // The request gets past the hook and fails LATER against the db stub, so
    // whatever comes back, it must not be this hook's 403. Asserted narrowly:
    // it is fine for the status to be 403 for some other reason as long as the
    // body is not this hook's message (it will not be, the endpoint never
    // reaches a FORBIDDEN of its own here).
    const bodyText = await res.text();
    expect(bodyText).not.toContain(BASIC_AUTH_DISABLED_MESSAGE);
    expect(isBasicAuthDisabledMock).toHaveBeenCalled();
  });
});
