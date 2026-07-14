/**
 * Tests for the RBAC gate shared across the frontend routers: `adminProcedure`
 * (authenticated AND role === 'admin') and its extracted pure guard
 * `requireAdmin`. adminProcedure gates create/update/delete of MCP servers,
 * namespaces and endpoints plus the api-key admin listing.
 *
 * Imported from `@repo/trpc` (the built package) — the same module the routers
 * consume — so the test exercises the exact gate that ships.
 */

import { adminProcedure, requireAdmin, router } from "@repo/trpc";
import { TRPCError } from "@trpc/server";
import { describe, expect, it } from "vitest";

// Minimal router exposing a single admin-gated query, so we can drive the
// middleware through a real tRPC caller with different session contexts.
const testRouter = router({
  ping: adminProcedure.query(() => "ok"),
});

describe("adminProcedure", () => {
  it("allows an authenticated admin", async () => {
    const caller = testRouter.createCaller({
      user: { id: "u-admin", role: "admin" },
      session: { id: "s1" },
    });
    await expect(caller.ping()).resolves.toBe("ok");
  });

  it("rejects an authenticated member with FORBIDDEN", async () => {
    const caller = testRouter.createCaller({
      user: { id: "u-member", role: "member" },
      session: { id: "s2" },
    });
    await expect(caller.ping()).rejects.toMatchObject({ code: "FORBIDDEN" });
  });

  it("rejects an unauthenticated caller with UNAUTHORIZED (auth gate runs first)", async () => {
    const caller = testRouter.createCaller({});
    await expect(caller.ping()).rejects.toMatchObject({ code: "UNAUTHORIZED" });
  });
});

describe("requireAdmin", () => {
  it("throws FORBIDDEN for a member, a missing role, or no user", () => {
    expect(() => requireAdmin({ role: "member" })).toThrow(TRPCError);
    expect(() => requireAdmin({})).toThrow(TRPCError);
    expect(() => requireAdmin(undefined)).toThrow(TRPCError);
    expect(() => requireAdmin(null)).toThrow(TRPCError);
    try {
      requireAdmin({ role: "member" });
    } catch (error) {
      expect((error as TRPCError).code).toBe("FORBIDDEN");
    }
  });

  it("passes for an admin", () => {
    expect(() => requireAdmin({ role: "admin" })).not.toThrow();
  });
});
