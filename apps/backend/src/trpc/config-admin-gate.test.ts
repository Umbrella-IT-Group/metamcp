/**
 * MAJOR fix (independent security review, 2026-07-14): the entire global
 * gateway config write surface (signup/SSO/basic-auth toggles, session
 * lifetime, MCP timeouts/attempts, raw setConfig) was on `protectedProcedure`
 * — any authenticated member could flip auth-posture toggles for the whole
 * gateway. Moved to `adminProcedure`; reads keep their existing access level
 * (mostly public, `getAllConfigs` stays protected).
 *
 * One representative setter (`setSignupDisabled`) is exercised through the
 * real `createConfigRouter` wiring via a real tRPC caller — the same
 * approach as namespaces-curation-admin.test.ts — rather than re-deriving
 * the generic adminProcedure gate (already covered by admin-procedure.test.ts).
 */

import { createConfigRouter } from "@repo/trpc";
import { describe, expect, it, vi } from "vitest";

const buildRouter = () =>
  createConfigRouter({
    getSignupDisabled: vi.fn().mockResolvedValue(false),
    setSignupDisabled: vi.fn().mockResolvedValue({ success: true }),
    getSsoSignupDisabled: vi.fn().mockResolvedValue(false),
    setSsoSignupDisabled: vi.fn().mockResolvedValue({ success: true }),
    getBasicAuthDisabled: vi.fn().mockResolvedValue(false),
    setBasicAuthDisabled: vi.fn().mockResolvedValue({ success: true }),
    getMcpResetTimeoutOnProgress: vi.fn().mockResolvedValue(false),
    setMcpResetTimeoutOnProgress: vi.fn().mockResolvedValue({ success: true }),
    getMcpTimeout: vi.fn().mockResolvedValue(60000),
    setMcpTimeout: vi.fn().mockResolvedValue({ success: true }),
    getMcpMaxTotalTimeout: vi.fn().mockResolvedValue(60000),
    setMcpMaxTotalTimeout: vi.fn().mockResolvedValue({ success: true }),
    getMcpMaxAttempts: vi.fn().mockResolvedValue(3),
    setMcpMaxAttempts: vi.fn().mockResolvedValue({ success: true }),
    getSessionLifetime: vi.fn().mockResolvedValue(null),
    setSessionLifetime: vi.fn().mockResolvedValue({ success: true }),
    getAllConfigs: vi.fn().mockResolvedValue([]),
    setConfig: vi.fn().mockResolvedValue({ success: true }),
    getAuthProviders: vi.fn().mockResolvedValue([]),
  });

const adminCtx = {
  user: { id: "admin-1", role: "admin" },
  session: { id: "s-admin" },
};
const memberCtx = {
  user: { id: "member-1", role: "member" },
  session: { id: "s-member" },
};
/** No user, no session — what `createContext` leaves for an anonymous /trpc call. */
const anonCtx = {};

describe("config write surface — admin gate", () => {
  it("setSignupDisabled: admin allowed, member FORBIDDEN", async () => {
    const router = buildRouter();

    await expect(
      router.createCaller(adminCtx).setSignupDisabled({ disabled: true }),
    ).resolves.toEqual({ success: true });

    await expect(
      router.createCaller(memberCtx).setSignupDisabled({ disabled: true }),
    ).rejects.toMatchObject({ code: "FORBIDDEN" });
  });

  it("setConfig (raw config write): admin allowed, member FORBIDDEN", async () => {
    const router = buildRouter();

    await expect(
      router
        .createCaller(adminCtx)
        .setConfig({ key: "DISABLE_SIGNUP", value: "true" }),
    ).resolves.toEqual({ success: true });

    await expect(
      router
        .createCaller(memberCtx)
        .setConfig({ key: "DISABLE_SIGNUP", value: "true" }),
    ).rejects.toMatchObject({ code: "FORBIDDEN" });
  });

  it("getSignupDisabled read stays open to any authenticated caller (public read, unchanged)", async () => {
    const router = buildRouter();

    await expect(
      router.createCaller(memberCtx).getSignupDisabled(),
    ).resolves.toBe(false);
  });
});

/**
 * The config READ surface, split by who may read it (security review re-verification
 * 2026-08-14).
 *
 * The write surface was admin-gated in 2026-07-14 (above); the reads were all
 * left public, so an anonymous caller could pull the gateway's MCP
 * retry/timeout budget and session lifetime straight off `/trpc`. Six getters
 * are now `protectedProcedure`; three stay public because the sign-in pages
 * read them before a session exists, and gating one of those would leave a
 * login screen that cannot render itself.
 *
 * `getSsoSignupDisabled` is in the GATED list, not the public one, and the
 * reason is worth keeping: it is an auth-posture boolean sitting next to two
 * genuinely pre-auth siblings, which is why it was public — but the call-site
 * sweep found its only reader is the settings page. Public by association is
 * how a read surface grows without anyone deciding to grow it.
 *
 * Both halves are pinned. A test that only proved the gates would be
 * satisfied by gating everything — which breaks login — and a test that only
 * proved the public reads would be satisfied by gating nothing.
 */
describe("config read surface — anonymous access", () => {
  const GATED = [
    "getSessionLifetime",
    "getMcpTimeout",
    "getMcpMaxTotalTimeout",
    "getMcpMaxAttempts",
    "getMcpResetTimeoutOnProgress",
    "getSsoSignupDisabled",
  ] as const;

  const KEPT_PUBLIC = [
    "getSignupDisabled",
    "getBasicAuthDisabled",
    "getAuthProviders",
  ] as const;

  it.each(GATED)("%s: UNAUTHORIZED to an anonymous caller", async (getter) => {
    const router = buildRouter();

    await expect(router.createCaller(anonCtx)[getter]()).rejects.toMatchObject({
      code: "UNAUTHORIZED",
    });
  });

  it.each(GATED)(
    "%s: still served to an authenticated caller",
    async (getter) => {
      // The regression guard for the settings page and the MCP inspector, whose
      // useConnection hook reads three of these on every connect.
      const router = buildRouter();

      await expect(
        router.createCaller(memberCtx)[getter](),
      ).resolves.not.toBeUndefined();
    },
  );

  it.each(KEPT_PUBLIC)(
    "%s: still readable pre-auth (the login page depends on it)",
    async (getter) => {
      const router = buildRouter();

      await expect(
        router.createCaller(anonCtx)[getter](),
      ).resolves.not.toBeUndefined();
    },
  );
});
