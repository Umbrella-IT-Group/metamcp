/**
 * RBAC gate tests for the three namespace CURATION mutations gated to
 * adminProcedure per coordinator direction (2026-07-14 follow-up on
 * PR #68's own review): updateServerStatus, updateToolStatus,
 * updateToolOverrides change which servers/tools an agent sees through a
 * namespace — the same "destructive update" class as namespace
 * create/update/delete. refreshTools (namespaces) and reconnect
 * (mcpServers) stay protectedProcedure so a non-admin OWNER can still act on
 * what they own, and are commented in-line at their router definitions. That
 * is a procedure-level statement only: both carry an impl-level admin gate
 * for the PUBLIC (unowned) case, pinned by
 * `namespaces.refresh-tools.impl.test.ts` and
 * `mcp-servers.reconnect.impl.test.ts` — the "no config mutation" reading of
 * refreshTools that this file used to carry was wrong, since it upserts
 * caller-supplied tool descriptions and schemas into the shared catalog.
 *
 * Drives the real `createNamespacesRouter` (from @repo/trpc) with a
 * minimal implementations stub, through a real tRPC caller with different
 * session contexts — same approach as admin-procedure.test.ts, scoped to
 * this router so the actual wiring (not just the generic gate) is exercised.
 */

import { createNamespacesRouter } from "@repo/trpc";
import { describe, expect, it, vi } from "vitest";

const okImpl = <T>(value: T) => vi.fn().mockResolvedValue(value);

const buildRouter = () =>
  createNamespacesRouter({
    create: okImpl({ success: true } as never),
    list: okImpl({ namespaces: [] } as never),
    get: okImpl({ namespace: null } as never),
    getTools: okImpl({ tools: [] } as never),
    delete: okImpl({ success: true } as never),
    update: okImpl({ success: true } as never),
    updateServerStatus: okImpl({ success: true }),
    updateToolStatus: okImpl({ success: true, message: "updated" }),
    updateToolOverrides: okImpl({ success: true, message: "updated" }),
    refreshTools: okImpl({ success: true, message: "refreshed" }),
  });

const adminCtx = {
  user: { id: "admin-1", role: "admin" },
  session: { id: "s-admin" },
};
const memberCtx = {
  user: { id: "member-1", role: "member" },
  session: { id: "s-member" },
};

const serverStatusInput = {
  namespaceUuid: "ns-1",
  serverUuid: "server-1",
  status: "INACTIVE" as const,
};
// Must satisfy the RFC-4122-shaped UUID regex (version nibble 1-8, variant
// nibble 8/9/a/b) — a plain repeated-digit string like "1111...1111" fails
// validation before the RBAC middleware is ever reached.
const NAMESPACE_UUID = "11111111-1111-4111-8111-111111111111";
const TOOL_UUID = "22222222-2222-4222-8222-222222222222";
const SERVER_UUID = "33333333-3333-4333-8333-333333333333";

const toolStatusInput = {
  namespaceUuid: NAMESPACE_UUID,
  toolUuid: TOOL_UUID,
  serverUuid: SERVER_UUID,
  status: "INACTIVE" as const,
};
const toolOverridesInput = {
  namespaceUuid: NAMESPACE_UUID,
  toolUuid: TOOL_UUID,
  serverUuid: SERVER_UUID,
  overrideName: "renamed-tool",
};

describe("namespaces curation mutations — admin gate", () => {
  it("updateServerStatus: admin allowed, member FORBIDDEN", async () => {
    const router = buildRouter();

    await expect(
      router.createCaller(adminCtx).updateServerStatus(serverStatusInput),
    ).resolves.toEqual({ success: true });

    await expect(
      router.createCaller(memberCtx).updateServerStatus(serverStatusInput),
    ).rejects.toMatchObject({ code: "FORBIDDEN" });
  });

  it("updateToolStatus: admin allowed, member FORBIDDEN", async () => {
    const router = buildRouter();

    await expect(
      router.createCaller(adminCtx).updateToolStatus(toolStatusInput),
    ).resolves.toEqual({ success: true, message: "updated" });

    await expect(
      router.createCaller(memberCtx).updateToolStatus(toolStatusInput),
    ).rejects.toMatchObject({ code: "FORBIDDEN" });
  });

  it("updateToolOverrides: admin allowed, member FORBIDDEN", async () => {
    const router = buildRouter();

    await expect(
      router.createCaller(adminCtx).updateToolOverrides(toolOverridesInput),
    ).resolves.toEqual({ success: true, message: "updated" });

    await expect(
      router.createCaller(memberCtx).updateToolOverrides(toolOverridesInput),
    ).rejects.toMatchObject({ code: "FORBIDDEN" });
  });

  // Procedure level only: the impl denies a non-admin on a PUBLIC namespace
  // (namespaces.refresh-tools.impl.test.ts). What this asserts is that the
  // mutation is still reachable by a member at all, so a non-admin owner
  // keeps it for their own namespace.
  it("refreshTools stays member-accessible (deliberate — owners keep it)", async () => {
    const router = buildRouter();

    await expect(
      router.createCaller(memberCtx).refreshTools({
        namespaceUuid: NAMESPACE_UUID,
        tools: [],
      }),
    ).resolves.toEqual({ success: true, message: "refreshed" });
  });
});
