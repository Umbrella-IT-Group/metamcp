/**
 * RBAC gate over the access-group surface, and the mount that makes it exist.
 *
 * THE MOUNT ASSERTION IS NOT CEREMONY. `createAppRouter` in
 * `packages/trpc/src/router.ts` enumerates its sub-routers by hand, with a
 * comment saying so: "a router that is not listed is unreachable no matter how
 * it is wired elsewhere". Wiring the implementations into `createFrontendRouter`
 * therefore type-checks on the backend while leaving every procedure
 * unreachable, and nothing on the backend notices — the failure only surfaces
 * as a missing property in the frontend's derived `AppRouter`. That happened
 * during this feature's own build. The first case below is the backend-side
 * detector for it.
 *
 * THE GATE ITSELF: every procedure here is `adminProcedure`, queries included.
 * These rows ARE the authorization policy for OAuth callers — the group list is
 * a map of which endpoints are gated and which accounts get through them —
 * so unlike api-keys there is no per-user slice a member has any business
 * reading. Both halves are asserted for every procedure: an admin gets through,
 * a member gets FORBIDDEN.
 */

import { createAccessGroupsRouter, createAppRouter } from "@repo/trpc";
import { describe, expect, it, vi } from "vitest";

const adminCtx = {
  user: { id: "admin-1", role: "admin" },
  session: { id: "s-admin" },
};
const memberCtx = {
  user: { id: "member-1", role: "member" },
  session: { id: "s-member" },
};
// No session at all: `protectedProcedure` runs first, so this must be
// UNAUTHORIZED rather than FORBIDDEN.
const anonymousCtx = {};

const GROUP_UUID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const ENDPOINT_UUID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

const GROUP = {
  uuid: GROUP_UUID,
  name: "helpdesk",
  description: null,
  created_at: new Date("2026-08-01T00:00:00Z").toISOString(),
  member_count: 0,
  endpoint_count: 0,
};

// Shaped to satisfy the declared `.output()` schemas: every procedure declares
// one, so a loose stub would fail output validation rather than the gate under
// test.
const buildRouter = () =>
  createAccessGroupsRouter({
    list: vi.fn().mockResolvedValue({ success: true, data: [GROUP] }),
    get: vi.fn().mockResolvedValue({
      success: true,
      data: { ...GROUP, members: [], endpoints: [] },
    }),
    listEndpoints: vi.fn().mockResolvedValue({ success: true, data: [] }),
    getEndpointAccess: vi.fn().mockResolvedValue({
      success: true,
      data: {
        endpoint_uuid: ENDPOINT_UUID,
        restricted: false,
        enable_oauth: true,
        enable_api_key_auth: false,
        require_scoped_api_key: false,
        groups: [],
      },
    }),
    create: vi.fn().mockResolvedValue({ success: true, data: GROUP }),
    update: vi.fn().mockResolvedValue({ success: true }),
    delete: vi.fn().mockResolvedValue({ success: true }),
    addMember: vi.fn().mockResolvedValue({ success: true }),
    removeMember: vi.fn().mockResolvedValue({ success: true }),
    addEndpoint: vi.fn().mockResolvedValue({ success: true }),
    removeEndpoint: vi.fn().mockResolvedValue({ success: true }),
    setEndpointRestricted: vi.fn().mockResolvedValue({ success: true }),
  });

/** Every procedure, with an input that satisfies its schema. */
const CALLS: Array<[string, (caller: never) => Promise<unknown>]> = [
  ["list", (c) => (c as never as { list: () => Promise<unknown> }).list()],
  [
    "get",
    (c) =>
      (c as never as { get: (i: unknown) => Promise<unknown> }).get({
        uuid: GROUP_UUID,
      }),
  ],
  [
    "listEndpoints",
    (c) =>
      (c as never as { listEndpoints: () => Promise<unknown> }).listEndpoints(),
  ],
  [
    "getEndpointAccess",
    (c) =>
      (
        c as never as { getEndpointAccess: (i: unknown) => Promise<unknown> }
      ).getEndpointAccess({ endpoint_uuid: ENDPOINT_UUID }),
  ],
  [
    "create",
    (c) =>
      (c as never as { create: (i: unknown) => Promise<unknown> }).create({
        name: "helpdesk",
      }),
  ],
  [
    "update",
    (c) =>
      (c as never as { update: (i: unknown) => Promise<unknown> }).update({
        uuid: GROUP_UUID,
        name: "helpdesk",
      }),
  ],
  [
    "delete",
    (c) =>
      (c as never as { delete: (i: unknown) => Promise<unknown> }).delete({
        uuid: GROUP_UUID,
      }),
  ],
  [
    "addMember",
    (c) =>
      (c as never as { addMember: (i: unknown) => Promise<unknown> }).addMember(
        { group_uuid: GROUP_UUID, user_id: "user-1" },
      ),
  ],
  [
    "removeMember",
    (c) =>
      (
        c as never as { removeMember: (i: unknown) => Promise<unknown> }
      ).removeMember({ group_uuid: GROUP_UUID, user_id: "user-1" }),
  ],
  [
    "addEndpoint",
    (c) =>
      (
        c as never as { addEndpoint: (i: unknown) => Promise<unknown> }
      ).addEndpoint({
        group_uuid: GROUP_UUID,
        endpoint_uuid: ENDPOINT_UUID,
      }),
  ],
  [
    "removeEndpoint",
    (c) =>
      (
        c as never as { removeEndpoint: (i: unknown) => Promise<unknown> }
      ).removeEndpoint({
        group_uuid: GROUP_UUID,
        endpoint_uuid: ENDPOINT_UUID,
      }),
  ],
  [
    "setEndpointRestricted",
    (c) =>
      (
        c as never as {
          setEndpointRestricted: (i: unknown) => Promise<unknown>;
        }
      ).setEndpointRestricted({
        endpoint_uuid: ENDPOINT_UUID,
        restricted: true,
      }),
  ],
];

describe("the router is actually mounted on the app router", () => {
  it("frontend.accessGroups exists, carrying every procedure", () => {
    // Only the sub-router under test needs real implementations; the rest are
    // never called, and `createAppRouter` only reads their shape.
    const stub = new Proxy({} as Record<string, unknown>, {
      get: () => vi.fn(),
    });
    const appRouter = createAppRouter({
      frontend: {
        mcpServers: stub,
        namespaces: stub,
        endpoints: stub,
        oauth: stub,
        oauthClients: stub,
        oauthTokens: stub,
        users: stub,
        tools: stub,
        apiKeys: stub,
        config: stub,
        logs: stub,
        accessGroups: stub,
      },
    } as never);

    const paths = Object.keys(appRouter._def.procedures).filter((path) =>
      path.startsWith("frontend.accessGroups."),
    );

    expect(paths.sort()).toEqual(
      CALLS.map(([name]) => `frontend.accessGroups.${name}`).sort(),
    );
  });
});

describe("every access-group procedure is admin-gated", () => {
  it.each(CALLS)("%s: admin allowed", async (_name, call) => {
    const router = buildRouter();
    await expect(
      call(router.createCaller(adminCtx) as never),
    ).resolves.toMatchObject({ success: true });
  });

  it.each(CALLS)("%s: member FORBIDDEN", async (_name, call) => {
    const router = buildRouter();
    await expect(
      call(router.createCaller(memberCtx) as never),
    ).rejects.toMatchObject({ code: "FORBIDDEN" });
  });

  it.each(CALLS)("%s: anonymous UNAUTHORIZED", async (_name, call) => {
    const router = buildRouter();
    await expect(
      call(router.createCaller(anonymousCtx) as never),
    ).rejects.toMatchObject({ code: "UNAUTHORIZED" });
  });
});
