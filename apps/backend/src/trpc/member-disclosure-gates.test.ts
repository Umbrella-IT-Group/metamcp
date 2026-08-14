/**
 * The router half of the FIND-004 / #98 fix.
 *
 * `redaction.test.ts` proves the serializers redact when told to. This file
 * proves the routers actually TELL them to — that `isAdmin` is derived from
 * the session role and reaches the implementation, for every procedure that
 * serializes a server. A serializer that redacts correctly is worth nothing
 * if the router hands it `true` for everyone, and that wiring is a positional
 * boolean argument, which is exactly the kind of thing a later refactor drops
 * without any type error.
 *
 * Also covers `logs.get`, which moved from protectedProcedure to
 * adminProcedure in the same change.
 *
 * Drives the real routers from @repo/trpc through a real tRPC caller with
 * admin and member sessions — same approach as
 * namespaces-curation-admin.test.ts.
 */

import {
  createLogsRouter,
  createMcpServersRouter,
  createNamespacesRouter,
} from "@repo/trpc";
import { describe, expect, it, vi } from "vitest";

const okImpl = <T>(value: T) => vi.fn().mockResolvedValue(value);

const adminCtx = {
  user: { id: "admin-1", role: "admin" },
  session: { id: "s-admin" },
};
const memberCtx = {
  user: { id: "member-1", role: "member" },
  session: { id: "s-member" },
};
// A session whose user carries no role at all. Must be treated as NOT an
// admin — the check is `role === "admin"`, never a truthiness test.
const rolelessCtx = {
  user: { id: "ghost-1" },
  session: { id: "s-ghost" },
};

const SERVER_UUID = "11111111-1111-4111-8111-111111111111";
const NAMESPACE_UUID = "22222222-2222-4222-8222-222222222222";

const buildMcpServersRouter = () => {
  const impls = {
    create: okImpl({ success: true } as never),
    list: okImpl({ success: true, data: [] } as never),
    bulkImport: okImpl({ success: true } as never),
    get: okImpl({ success: true } as never),
    delete: okImpl({ success: true } as never),
    update: okImpl({ success: true } as never),
    reconnect: okImpl({ success: true } as never),
  };
  return { router: createMcpServersRouter(impls), impls };
};

const buildNamespacesRouter = () => {
  const impls = {
    create: okImpl({ success: true } as never),
    list: okImpl({ namespaces: [] } as never),
    get: okImpl({ success: true } as never),
    getTools: okImpl({ tools: [] } as never),
    delete: okImpl({ success: true } as never),
    update: okImpl({ success: true } as never),
    updateServerStatus: okImpl({ success: true }),
    updateToolStatus: okImpl({ success: true, message: "updated" }),
    updateToolOverrides: okImpl({ success: true, message: "updated" }),
    refreshTools: okImpl({ success: true, message: "refreshed" }),
  };
  return { router: createNamespacesRouter(impls), impls };
};

describe("mcpServers.list — isAdmin reaches the implementation", () => {
  it("passes false for a member", async () => {
    const { router, impls } = buildMcpServersRouter();

    await router.createCaller(memberCtx).list();

    expect(impls.list).toHaveBeenCalledWith("member-1", false);
  });

  it("passes true for an admin", async () => {
    const { router, impls } = buildMcpServersRouter();

    await router.createCaller(adminCtx).list();

    expect(impls.list).toHaveBeenCalledWith("admin-1", true);
  });

  it("passes false when the session carries no role", async () => {
    const { router, impls } = buildMcpServersRouter();

    await router.createCaller(rolelessCtx).list();

    expect(impls.list).toHaveBeenCalledWith("ghost-1", false);
  });

  it("stays reachable by members — this is redaction, not an RBAC gate", async () => {
    // Admin-gating the list instead would blank the member dashboard.
    const { router } = buildMcpServersRouter();

    await expect(router.createCaller(memberCtx).list()).resolves.toMatchObject({
      success: true,
    });
  });
});

describe("mcpServers.get — isAdmin reaches the implementation", () => {
  it("passes the flag after the user id, not in place of it", async () => {
    const { router, impls } = buildMcpServersRouter();

    await router.createCaller(memberCtx).get({ uuid: SERVER_UUID });
    expect(impls.get).toHaveBeenCalledWith(
      { uuid: SERVER_UUID },
      "member-1",
      false,
    );

    await router.createCaller(adminCtx).get({ uuid: SERVER_UUID });
    expect(impls.get).toHaveBeenLastCalledWith(
      { uuid: SERVER_UUID },
      "admin-1",
      true,
    );
  });
});

describe("namespaces.get — isAdmin reaches the implementation", () => {
  it("passes false for a member and true for an admin", async () => {
    const { router, impls } = buildNamespacesRouter();

    await router.createCaller(memberCtx).get({ uuid: NAMESPACE_UUID });
    expect(impls.get).toHaveBeenCalledWith(
      { uuid: NAMESPACE_UUID },
      "member-1",
      false,
    );

    await router.createCaller(adminCtx).get({ uuid: NAMESPACE_UUID });
    expect(impls.get).toHaveBeenLastCalledWith(
      { uuid: NAMESPACE_UUID },
      "admin-1",
      true,
    );
  });
});

describe("logs.get — admin only", () => {
  const buildRouter = () =>
    createLogsRouter({
      getLogs: okImpl({ success: true, data: [], totalCount: 0 } as never),
      clearLogs: okImpl({ success: true } as never),
    });

  it("admin allowed", async () => {
    await expect(
      buildRouter().createCaller(adminCtx).get({}),
    ).resolves.toMatchObject({ success: true });
  });

  it("member FORBIDDEN", async () => {
    await expect(
      buildRouter().createCaller(memberCtx).get({}),
    ).rejects.toMatchObject({ code: "FORBIDDEN" });
  });

  it("unauthenticated UNAUTHORIZED — the role gate never sees a null user", async () => {
    await expect(buildRouter().createCaller({}).get({})).rejects.toMatchObject({
      code: "UNAUTHORIZED",
    });
  });
});
