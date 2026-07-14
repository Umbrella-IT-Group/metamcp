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
