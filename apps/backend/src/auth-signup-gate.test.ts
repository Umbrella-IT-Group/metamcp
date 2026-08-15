/**
 * The registration gate and its ONE exemption, exercised against the REAL
 * `databaseHooks.user.create.before` hook better-auth will call.
 *
 * Same technique as the sibling `auth-disabled-login.test.ts`: rather than
 * standing up better-auth and a database, this reaches into the CONFIGURED
 * hook via `auth.options`, so what runs here is the wiring that ships.
 *
 * Why this file exists separately from `lib/bootstrap.order.test.ts`: that
 * suite mocks `../auth` wholesale (bootstrap cannot be driven with a live
 * better-auth instance), so it can prove bootstrap OPENS the exemption but not
 * that the gate HONOURS it. This file is the other half of that pair, and the
 * two must be changed together: a stand-in in the bootstrap suite that drifts
 * from the real hook here is the failure mode both are guarding.
 *
 * The property under test:
 *   - stored DISABLE_SIGNUP=true + exemption open  -> the account is created
 *     (this is bootstrap recreating its own administrator on boot 2+, the case
 *     where BOOTSTRAP_RECREATE_USER has already deleted the old row);
 *   - stored DISABLE_SIGNUP=true + exemption shut  -> refused, as before. This
 *     is every request that arrives over HTTP.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { isSignupDisabledMock, isSsoSignupDisabledMock } = vi.hoisted(() => ({
  isSignupDisabledMock: vi.fn(),
  isSsoSignupDisabledMock: vi.fn(),
}));

vi.mock("./lib/config.service", () => ({
  configService: {
    isSignupDisabled: isSignupDisabledMock,
    isSsoSignupDisabled: isSsoSignupDisabledMock,
    isBasicAuthDisabled: vi.fn().mockResolvedValue(false),
  },
}));

const { emitSignupDeniedMock, emitSignupCreatedMock } = vi.hoisted(() => ({
  emitSignupDeniedMock: vi.fn(),
  emitSignupCreatedMock: vi.fn(),
}));

vi.mock("./lib/audit/auth-hook-audit", () => ({
  emitSignupDenied: emitSignupDeniedMock,
  emitSignupCreated: emitSignupCreatedMock,
  emitSessionCreated: vi.fn(),
  emitSessionRevoked: vi.fn(),
}));

vi.mock("./db/repositories/users.repo", () => ({
  usersRepository: { isDisabled: vi.fn().mockResolvedValue(false) },
}));

// db/index builds a live pg Pool at import; the drizzle adapter only needs an
// object to hold on to, since no query runs in this file.
vi.mock("./db/index", () => ({ db: {}, pool: {} }));

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

// NOT mocked, deliberately: the exemption module is the thing under test, so
// the tests flip it through its real setter exactly as bootstrap does.
import { setBootstrapSignupAllowed } from "./lib/bootstrap-signup-override";

type UserCreateBefore = (
  user: Record<string, unknown>,
  context?: Record<string, unknown>,
) => Promise<unknown>;

async function getUserCreateHook(): Promise<UserCreateBefore> {
  const { auth } = await import("./auth");
  // Through `unknown`: better-auth types the argument as a full user row and
  // these tests drive it with the partial rows the real caller passes.
  const hook = (
    auth.options as unknown as {
      databaseHooks?: { user?: { create?: { before?: UserCreateBefore } } };
    }
  ).databaseHooks?.user?.create?.before;

  if (!hook) {
    // A missing hook is the silent-regression case: better-auth would create
    // accounts for anyone and nothing would look wrong.
    throw new Error(
      "databaseHooks.user.create.before is not configured — registration is not gated at all",
    );
  }

  return hook;
}

const NEW_USER = { email: "admin@example.com", name: "Admin" };
const BASIC_CONTEXT = { path: "/sign-up/email" };
const SSO_CONTEXT = { path: "/callback/oidc" };

beforeEach(() => {
  vi.clearAllMocks();
  isSignupDisabledMock.mockResolvedValue(false);
  isSsoSignupDisabledMock.mockResolvedValue(false);
});

afterEach(() => {
  // The flag is process-global. Leaking `true` out of a test would silently
  // disarm every assertion after it.
  setBootstrapSignupAllowed(false);
});

describe("user.create.before — registration gate", () => {
  it("is actually wired into the better-auth options", async () => {
    // Control: every assertion below is meaningless if the hook is not
    // registered, so failing loudly here is the point.
    await expect(getUserCreateHook()).resolves.toBeTypeOf("function");
  });

  it("REFUSES a runtime basic signup while DISABLE_SIGNUP is stored true", async () => {
    isSignupDisabledMock.mockResolvedValue(true);
    const hook = await getUserCreateHook();

    await expect(hook(NEW_USER, BASIC_CONTEXT)).rejects.toThrow(
      /registration is currently disabled/i,
    );
    expect(emitSignupDeniedMock).toHaveBeenCalledTimes(1);
    expect(emitSignupDeniedMock.mock.calls[0][2]).toBe("basic");
  });

  it("REFUSES a runtime SSO signup while DISABLE_SSO_SIGNUP is stored true", async () => {
    isSsoSignupDisabledMock.mockResolvedValue(true);
    const hook = await getUserCreateHook();

    await expect(hook(NEW_USER, SSO_CONTEXT)).rejects.toThrow(
      /SSO\/OAuth is currently disabled/i,
    );
    expect(emitSignupDeniedMock.mock.calls[0][2]).toBe("sso");
  });

  it("allows a signup when nothing is disabled", async () => {
    const hook = await getUserCreateHook();

    await expect(hook(NEW_USER, BASIC_CONTEXT)).resolves.toMatchObject({
      data: NEW_USER,
    });
    expect(emitSignupDeniedMock).not.toHaveBeenCalled();
  });
});

describe("user.create.before — the bootstrap exemption", () => {
  it("ALLOWS the signup while the exemption is open, even with DISABLE_SIGNUP stored true", async () => {
    // Boot 2+ with BOOTSTRAP_RECREATE_USER=true: the stored flag says closed,
    // bootstrap has already deleted the administrator and its API keys, and
    // this call is the one that has to put the account back. Refusing it is
    // the lockout: no admin, registration closed, connector keys gone.
    isSignupDisabledMock.mockResolvedValue(true);
    setBootstrapSignupAllowed(true);
    const hook = await getUserCreateHook();

    await expect(hook(NEW_USER, BASIC_CONTEXT)).resolves.toMatchObject({
      data: NEW_USER,
    });
    // Nothing was denied, so nothing is reported as denied.
    expect(emitSignupDeniedMock).not.toHaveBeenCalled();
  });

  it("ALLOWS an SSO-shaped signup while the exemption is open", async () => {
    // The SSO branch carries the exemption too: `isSsoRegistration` is a path
    // heuristic, so leaving that branch un-exempted would make bootstrap's
    // success depend on how better-auth labels the request.
    isSsoSignupDisabledMock.mockResolvedValue(true);
    setBootstrapSignupAllowed(true);
    const hook = await getUserCreateHook();

    await expect(hook(NEW_USER, SSO_CONTEXT)).resolves.toMatchObject({
      data: NEW_USER,
    });
    expect(emitSignupDeniedMock).not.toHaveBeenCalled();
  });

  it("closes again the moment the exemption is cleared", async () => {
    // The exemption is a window, not a mode. This is the state every request
    // that arrives over HTTP meets, because bootstrap clears the flag in a
    // `finally` before `app.listen()` is ever reached.
    isSignupDisabledMock.mockResolvedValue(true);
    const hook = await getUserCreateHook();

    setBootstrapSignupAllowed(true);
    await expect(hook(NEW_USER, BASIC_CONTEXT)).resolves.toBeDefined();

    setBootstrapSignupAllowed(false);
    await expect(hook(NEW_USER, BASIC_CONTEXT)).rejects.toThrow(
      /registration is currently disabled/i,
    );
  });

  // LAST in the file on purpose: it resets the module registry, so anything
  // after it would re-import `./auth` against a DIFFERENT instance of the
  // exemption module than the one this suite's setter writes to.
  it("defaults shut — a freshly loaded module reports the exemption closed", async () => {
    // Guards the module's INITIAL value, which nothing else in this file can
    // see: `afterEach` closes the exemption explicitly, so by the time any
    // later test runs the flag has already been written at least once. A
    // default of `true` would leave the gate open for the entire life of any
    // process that never bootstraps, and every other assertion here would
    // still pass. Only an untouched instance can catch that.
    vi.resetModules();
    const fresh = await import("./lib/bootstrap-signup-override");

    expect(fresh.isBootstrapSignupAllowed()).toBe(false);
  });
});
