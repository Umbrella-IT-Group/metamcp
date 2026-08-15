/**
 * MINOR sweep (independent security review, 2026-07-14): gate
 * tools.create/tools.sync (curation-class, same rationale as
 * namespaces.updateToolStatus — writes to the shared tools catalog),
 * logs.clear (destructive, gateway-wide), and oauth.upsert (writes upstream
 * MCP-server OAuth credentials, a server-config surface) to adminProcedure.
 * `logs.clear` has since been REMOVED outright — see its describe block
 * below, which now asserts absence.
 *
 * Pre-condition verified by code inspection: `namespaces.refreshTools`
 * (still protectedProcedure, so a non-admin owner keeps it — see
 * namespaces-curation-admin.test.ts) calls `toolsRepository.bulkUpsert`
 * directly from `apps/backend/src/trpc/namespaces.impl.ts`, never routing
 * through the `tools.create`/`tools.sync` tRPC procedures gated here.
 * Gating those two procedures therefore had no effect on the refreshTools
 * path — which is why that path needed its own gate for the PUBLIC-namespace
 * case, added in the impl and pinned by
 * `namespaces.refresh-tools.impl.test.ts`.
 */

import {
  createLogsRouter,
  createOAuthRouter,
  createToolsRouter,
} from "@repo/trpc";
import { describe, expect, it, vi } from "vitest";

const adminCtx = {
  user: { id: "admin-1", role: "admin" },
  session: { id: "s-admin" },
};
const memberCtx = {
  user: { id: "member-1", role: "member" },
  session: { id: "s-member" },
};

describe("tools.create / tools.sync — admin gate", () => {
  const buildRouter = () =>
    createToolsRouter({
      getByMcpServerUuid: vi.fn().mockResolvedValue({ tools: [] }),
      create: vi.fn().mockResolvedValue({ success: true, count: 1 }),
      sync: vi.fn().mockResolvedValue({ success: true, count: 1 }),
    });

  const toolInput = {
    mcpServerUuid: "11111111-1111-4111-8111-111111111111",
    tools: [{ name: "example_tool", inputSchema: { type: "object" as const } }],
  };

  it("tools.create: admin allowed, member FORBIDDEN", async () => {
    const router = buildRouter();

    await expect(
      router.createCaller(adminCtx).create(toolInput),
    ).resolves.toEqual({ success: true, count: 1 });

    await expect(
      router.createCaller(memberCtx).create(toolInput),
    ).rejects.toMatchObject({ code: "FORBIDDEN" });
  });

  it("tools.sync: admin allowed, member FORBIDDEN", async () => {
    const router = buildRouter();

    await expect(
      router.createCaller(adminCtx).sync(toolInput),
    ).resolves.toEqual({ success: true, count: 1 });

    await expect(
      router.createCaller(memberCtx).sync(toolInput),
    ).rejects.toMatchObject({ code: "FORBIDDEN" });
  });
});

/**
 * `logs.clear` used to be gated here. It is now GONE, and this suite asserts
 * absence rather than a gate.
 *
 * The gate was never the problem: the procedure only emptied the in-memory
 * ring buffer, but it was the one admin gesture that erased the live security
 * view mid-investigation, and it is the exact affordance the operator
 * requirement forbids — no application or admin path that clears the record.
 * An admin-gated wipe is still a wipe.
 *
 * Asserted against the router's procedure map rather than by calling
 * `caller.clear()`, because a caller for a missing procedure fails as a plain
 * TypeError, which is also what a typo in the test would produce.
 */
describe("logs.clear — removed, not gated", () => {
  // Shaped to satisfy GetLogsResponseSchema: `get` declares `.output()`, so a
  // loose stub fails output validation rather than the gate under test.
  const buildRouter = () =>
    createLogsRouter({
      getLogs: vi
        .fn()
        .mockResolvedValue({ success: true, data: [], totalCount: 0 }),
    });

  it("the procedure does not exist on the router", () => {
    const procedures = buildRouter()._def.procedures;

    expect(Object.keys(procedures)).toEqual(["get"]);
    expect("clear" in procedures).toBe(false);
  });

  it("logs.get survives and is still admin-gated", async () => {
    const router = buildRouter();

    await expect(router.createCaller(adminCtx).get({})).resolves.toMatchObject({
      success: true,
    });

    await expect(router.createCaller(memberCtx).get({})).rejects.toMatchObject({
      code: "FORBIDDEN",
    });
  });
});

describe("oauth.upsert — admin gate", () => {
  const buildRouter = () =>
    createOAuthRouter({
      get: vi.fn().mockResolvedValue({ success: false, error: "not found" }),
      upsert: vi.fn().mockResolvedValue({
        success: true,
        data: {
          uuid: "22222222-2222-4222-8222-222222222222",
          mcp_server_uuid: "11111111-1111-4111-8111-111111111111",
          client_information: null,
          tokens: null,
          code_verifier: null,
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
        },
        message: "ok",
      }),
    });

  const upsertInput = {
    mcp_server_uuid: "11111111-1111-4111-8111-111111111111",
  };

  it("admin allowed, member FORBIDDEN", async () => {
    const router = buildRouter();

    const adminResult = await router.createCaller(adminCtx).upsert(upsertInput);
    expect(adminResult.success).toBe(true);

    await expect(
      router.createCaller(memberCtx).upsert(upsertInput),
    ).rejects.toMatchObject({ code: "FORBIDDEN" });
  });
});
