/**
 * `users.disabled` enforcement, half one: a locked account cannot obtain a
 * NEW session.
 *
 * The hook is better-auth's `databaseHooks.session.create.before`, which every
 * sign-in path funnels through — email/password, the OIDC callback, account
 * linking — so one guard covers all of them without enumerating endpoints.
 * Verified in better-auth 1.6.23's own `getWithHooks`: a `create.before` hook
 * that returns `false` aborts the create, and a throw propagates. This fork
 * throws an APIError instead of returning false, so the user sees an honest
 * 403 rather than an opaque broken sign-in.
 *
 * Rather than standing up a whole better-auth instance and a database, this
 * reaches into the CONFIGURED hook: `auth.options.databaseHooks.session.create
 * .before` is the exact function better-auth will call, so exercising it
 * directly tests the real wiring. The sibling half — rejecting sessions the
 * account ALREADY holds — is covered in trpc/disabled-account-enforcement.test.ts.
 */

import { beforeEach, describe, expect, it, vi } from "vitest";

const { isDisabledMock } = vi.hoisted(() => ({ isDisabledMock: vi.fn() }));

vi.mock("./db/repositories/users.repo", () => ({
  usersRepository: { isDisabled: isDisabledMock },
}));

// db/index builds a live pg Pool at import; the drizzle adapter only needs an
// object to hold on to, since no query runs in this file.
vi.mock("./db/index", () => ({ db: {}, pool: {} }));

vi.mock("./lib/config.service", () => ({
  configService: {
    isSignupDisabled: vi.fn().mockResolvedValue(false),
    isSsoSignupDisabled: vi.fn().mockResolvedValue(false),
    isBasicAuthDisabled: vi.fn().mockResolvedValue(false),
  },
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

type SessionCreateBefore = (
  session: Record<string, unknown>,
) => Promise<unknown>;

async function getSessionCreateHook(): Promise<SessionCreateBefore> {
  const { auth } = await import("./auth");
  // Through `unknown`: better-auth types the hook's argument as a full session
  // row, and the point of these tests is to drive it with PARTIAL rows
  // (including one with no userId) that the real caller could plausibly pass.
  const hook = (
    auth.options as unknown as {
      databaseHooks?: {
        session?: { create?: { before?: SessionCreateBefore } };
      };
    }
  ).databaseHooks?.session?.create?.before;

  if (!hook) {
    // A missing hook is the silent-regression case: better-auth would simply
    // mint sessions for disabled accounts and nothing would look wrong.
    throw new Error(
      "databaseHooks.session.create.before is not configured — disabled accounts can still sign in",
    );
  }

  return hook;
}

beforeEach(() => {
  vi.clearAllMocks();
  isDisabledMock.mockResolvedValue(false);
});

describe("session.create.before — disabled accounts cannot sign in", () => {
  it("is actually wired into the better-auth options", async () => {
    // Control: every assertion below is meaningless if the hook is not
    // registered, so failing loudly here is the point.
    await expect(getSessionCreateHook()).resolves.toBeTypeOf("function");
  });

  it("allows an ENABLED account to mint a session", async () => {
    const hook = await getSessionCreateHook();

    const result = await hook({ userId: "member-1", token: "t" });

    expect(isDisabledMock).toHaveBeenCalledWith("member-1");
    // Returning `{ data }` is better-auth's "proceed with this row".
    expect(result).toMatchObject({ data: { userId: "member-1" } });
  });

  it("REFUSES to mint a session for a disabled account", async () => {
    isDisabledMock.mockResolvedValue(true);
    const hook = await getSessionCreateHook();

    await expect(hook({ userId: "attacker-1", token: "t" })).rejects.toThrow(
      /disabled/i,
    );
  });

  it("propagates a lookup failure rather than minting the session anyway", async () => {
    // Fail closed. A database that cannot answer "is this account locked?"
    // must not be read as "no" on the sign-in path.
    isDisabledMock.mockRejectedValue(new Error("database unreachable"));
    const hook = await getSessionCreateHook();

    await expect(hook({ userId: "attacker-1", token: "t" })).rejects.toThrow(
      "database unreachable",
    );
  });

  it("passes through a session row with no userId instead of throwing", async () => {
    // Defensive: better-auth owns this row's shape. An unexpected shape must
    // not turn every sign-in into a 500 — the enforcement paths in
    // createContext and the OAuth handler still stand behind this one.
    const hook = await getSessionCreateHook();

    const result = await hook({ token: "t" });

    expect(isDisabledMock).not.toHaveBeenCalled();
    expect(result).toMatchObject({ data: { token: "t" } });
  });
});
