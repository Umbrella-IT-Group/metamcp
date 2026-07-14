/**
 * MINOR sweep (independent security review, 2026-07-14): gate
 * tools.create/tools.sync (curation-class, same rationale as
 * namespaces.updateToolStatus — writes to the shared tools catalog),
 * logs.clear (destructive, gateway-wide), and oauth.upsert (writes upstream
 * MCP-server OAuth credentials, a server-config surface) to adminProcedure.
 *
 * Pre-condition verified by code inspection: `namespaces.refreshTools`
 * (member-accessible, kept as-is — see namespaces-curation-admin.test.ts)
 * calls `toolsRepository.bulkUpsert` directly from
 * `apps/backend/src/trpc/namespaces.impl.ts`, never routing through the
 * `tools.create`/`tools.sync` tRPC procedures gated here. Gating those two
 * procedures therefore has no effect on the refreshTools member path.
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

describe("logs.clear — admin gate", () => {
  const buildRouter = () =>
    createLogsRouter({
      getLogs: vi.fn().mockResolvedValue({ logs: [] }),
      clearLogs: vi
        .fn()
        .mockResolvedValue({ success: true, message: "cleared" }),
    });

  it("admin allowed, member FORBIDDEN", async () => {
    const router = buildRouter();

    await expect(router.createCaller(adminCtx).clear()).resolves.toEqual({
      success: true,
      message: "cleared",
    });

    await expect(router.createCaller(memberCtx).clear()).rejects.toMatchObject({
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
