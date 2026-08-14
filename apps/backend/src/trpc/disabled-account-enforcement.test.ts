/**
 * `users.disabled` enforcement (migration 0027) — the half that makes the
 * feature real rather than cosmetic.
 *
 * A disable button that only stops NEW logins is theatre in this deployment:
 * BETTER_AUTH_SESSION_EXPIRES_IN_SECONDS defaults to 30 days here, so an
 * attacker disabled while signed in would keep full access for a month and
 * the operator would have watched the toggle flip and believed the job was
 * done. So enforcement lives in two independent places, and this file pins
 * the one that is easy to regress silently:
 *
 *   createContext must treat a disabled user's EXISTING session as
 *   unauthenticated, on the very next request.
 *
 * The sibling half (blocking session creation at sign-in) lives in the
 * better-auth `session.create.before` hook in auth.ts; the repository-level
 * behaviour it depends on (`isDisabled`, including its fail-closed answer for
 * an unknown id) is exercised against a real postgres in
 * db/repositories/access-queries.integration.test.ts.
 *
 * `../auth` is mocked so this file can drive createContext without a live
 * better-auth instance, and the users repository is mocked so it needs no
 * database — the same pattern error-formatter.test.ts uses.
 */

import type { Request, Response } from "express";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { authHandlerMock, isDisabledMock } = vi.hoisted(() => ({
  authHandlerMock: vi.fn(),
  isDisabledMock: vi.fn(),
}));

vi.mock("../auth", () => ({
  auth: { handler: authHandlerMock },
}));

vi.mock("../db/repositories/users.repo", () => ({
  usersRepository: { isDisabled: isDisabledMock },
}));

vi.mock("../utils/logger", () => ({
  default: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  },
}));

import { createContext } from "../trpc";

const SESSION_USER = {
  id: "attacker-1",
  email: "attacker@example.invalid",
  role: "member",
};

// A request carrying a VALID, unexpired session cookie — the state an
// attacker is in at the moment an administrator disables them.
const buildReq = () =>
  ({
    headers: { cookie: "better-auth.session_token=valid", host: "localhost" },
  }) as unknown as Request;
const res = {} as Response;

const okSession = () =>
  new Response(JSON.stringify({ user: SESSION_USER, session: { id: "s-1" } }), {
    status: 200,
    headers: { "content-type": "application/json" },
  });

beforeEach(() => {
  vi.clearAllMocks();
  // mockImplementation, NOT mockResolvedValue: a Response body can only be
  // consumed once, so handing back the same instance makes every call after
  // the first throw inside createContext — which the outer catch swallows
  // into an anonymous context. That silently turns a multi-request test into
  // a one-request test.
  authHandlerMock.mockImplementation(async () => okSession());
  isDisabledMock.mockResolvedValue(false);
});

describe("createContext — disabled-account enforcement", () => {
  it("populates user/session for an ENABLED account", async () => {
    const ctx = await createContext({ req: buildReq(), res });

    // Control: without this, the assertions below would also pass if
    // createContext were simply broken and never populated anything.
    expect(ctx.user).toMatchObject({ id: "attacker-1" });
    expect(ctx.session).toMatchObject({ id: "s-1" });
    expect(isDisabledMock).toHaveBeenCalledWith("attacker-1");
  });

  it("drops a DISABLED account's still-valid session", async () => {
    isDisabledMock.mockResolvedValue(true);

    const ctx = await createContext({ req: buildReq(), res });

    // better-auth said this session is good; the disable flag overrides it.
    // Undefined user/session means protectedProcedure returns its ordinary
    // UNAUTHORIZED and the frontend's existing sign-in redirect handles it —
    // no new error path to get wrong.
    expect(ctx.user).toBeUndefined();
    expect(ctx.session).toBeUndefined();
  });

  it("re-reads the flag on EVERY request rather than trusting the session", async () => {
    // The session is minted once and lives 30 days. If the check were done at
    // sign-in and cached, disabling would not take effect until the cookie
    // expired — which is the entire failure mode this test exists to prevent.
    await createContext({ req: buildReq(), res });
    await createContext({ req: buildReq(), res });
    await createContext({ req: buildReq(), res });

    expect(isDisabledMock).toHaveBeenCalledTimes(3);
  });

  it("takes effect on the very next request after the flag flips", async () => {
    isDisabledMock.mockResolvedValueOnce(false).mockResolvedValueOnce(true);

    const before = await createContext({ req: buildReq(), res });
    const after = await createContext({ req: buildReq(), res });

    expect(before.user).toMatchObject({ id: "attacker-1" });
    expect(after.user).toBeUndefined();
  });

  it("fails CLOSED when the disabled lookup itself throws", async () => {
    isDisabledMock.mockRejectedValue(new Error("database unreachable"));

    const ctx = await createContext({ req: buildReq(), res });

    // A database that cannot answer "is this account locked?" must not be
    // read as "no". The outer catch leaves user/session undefined, which is
    // indistinguishable from an unauthenticated request.
    expect(ctx.user).toBeUndefined();
    expect(ctx.session).toBeUndefined();
  });

  it("leaves an anonymous request anonymous without a database round trip", async () => {
    const ctx = await createContext({
      req: { headers: {} } as unknown as Request,
      res,
    });

    expect(ctx.user).toBeUndefined();
    expect(isDisabledMock).not.toHaveBeenCalled();
  });
});
