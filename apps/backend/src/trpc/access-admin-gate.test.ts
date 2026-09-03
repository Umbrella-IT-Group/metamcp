/**
 * Admin gate for the Access dashboard's two NET-NEW routers.
 *
 * Self-registration abuse: an attacker's member accounts were
 * invisible because no surface listed users. The fix adds one — and a user
 * listing is itself a disclosure (every account's email, role and live
 * session count in one response), while `delete` removes an identity and
 * everything it owns and `setDisabled` locks somebody out of the product. So
 * every procedure on both routers is `adminProcedure`, and this test pins
 * that: an anonymous caller gets UNAUTHORIZED, an authenticated member gets
 * FORBIDDEN, an admin succeeds.
 *
 * Exercised through the real `createUsersRouter` / `createOAuthTokensRouter`
 * wiring via a real tRPC caller — the same approach as
 * config-admin-gate.test.ts — rather than re-deriving the generic
 * adminProcedure gate, which admin-procedure.test.ts already covers.
 */

import { createOAuthTokensRouter, createUsersRouter } from "@repo/trpc";
import { describe, expect, it, vi } from "vitest";

const listResult = { users: [], total: 0 };
const previewResult = {
  found: true,
  email: "target@example.invalid",
  impact: {
    own_namespaces: 1,
    own_endpoints: 2,
    own_mcp_servers: 0,
    own_api_keys: 1,
    other_users_endpoints: 3,
    other_users_api_keys: 4,
    sessions: 1,
    oauth_tokens: 2,
    m365_tokens: 1,
  },
};
const disabledResult = {
  success: true,
  message: "Account disabled",
  disabled: true,
};
const revokeResult = {
  success: true,
  message: "Access revoked",
  sessions_deleted: 0,
  oauth_tokens_deleted: 0,
  authorization_codes_deleted: 0,
  api_keys_deactivated: 0,
  m365_tokens_revoked: 0,
};
const deleteResult = { success: true, message: "User deleted successfully" };

const buildUsersRouter = (
  overrides: Partial<Parameters<typeof createUsersRouter>[0]> = {},
) =>
  createUsersRouter({
    list: vi.fn().mockResolvedValue(listResult),
    previewDelete: vi.fn().mockResolvedValue(previewResult),
    setDisabled: vi.fn().mockResolvedValue(disabledResult),
    revokeAccess: vi.fn().mockResolvedValue(revokeResult),
    delete: vi.fn().mockResolvedValue(deleteResult),
    ...overrides,
  });

const buildTokensRouter = () =>
  createOAuthTokensRouter({
    list: vi.fn().mockResolvedValue({ tokens: [] }),
  });

const adminCtx = {
  user: { id: "admin-1", role: "admin" },
  session: { id: "s-admin" },
};
const memberCtx = {
  user: { id: "member-1", role: "member" },
  session: { id: "s-member" },
};
// No user and no session at all — the shape createContext produces for a
// request that carried no valid cookie, and also for a request from a
// DISABLED account (createContext drops both rather than throwing).
const anonCtx = {};

describe("frontend.users — admin gate", () => {
  it("list: admin allowed, member FORBIDDEN, anonymous UNAUTHORIZED", async () => {
    const router = buildUsersRouter();

    await expect(router.createCaller(adminCtx).list()).resolves.toEqual(
      listResult,
    );
    await expect(router.createCaller(memberCtx).list()).rejects.toMatchObject({
      code: "FORBIDDEN",
    });
    await expect(router.createCaller(anonCtx).list()).rejects.toMatchObject({
      code: "UNAUTHORIZED",
    });
  });

  it("previewDelete: admin allowed, member FORBIDDEN, anonymous UNAUTHORIZED", async () => {
    const router = buildUsersRouter();
    const input = { user_id: "target-1" };

    await expect(
      router.createCaller(adminCtx).previewDelete(input),
    ).resolves.toEqual(previewResult);
    await expect(
      router.createCaller(memberCtx).previewDelete(input),
    ).rejects.toMatchObject({ code: "FORBIDDEN" });
    await expect(
      router.createCaller(anonCtx).previewDelete(input),
    ).rejects.toMatchObject({ code: "UNAUTHORIZED" });
  });

  it("setDisabled: admin allowed, member FORBIDDEN, anonymous UNAUTHORIZED", async () => {
    const router = buildUsersRouter();
    const input = { user_id: "target-1", disabled: true };

    await expect(
      router.createCaller(adminCtx).setDisabled(input),
    ).resolves.toEqual(disabledResult);
    // A member being able to lock accounts would be a privilege escalation
    // into a denial-of-service against every other user.
    await expect(
      router.createCaller(memberCtx).setDisabled(input),
    ).rejects.toMatchObject({ code: "FORBIDDEN" });
    await expect(
      router.createCaller(anonCtx).setDisabled(input),
    ).rejects.toMatchObject({ code: "UNAUTHORIZED" });
  });

  it("revokeAccess: admin allowed, member FORBIDDEN, anonymous UNAUTHORIZED", async () => {
    const router = buildUsersRouter();
    const input = { user_id: "target-1" };

    await expect(
      router.createCaller(adminCtx).revokeAccess(input),
    ).resolves.toEqual(revokeResult);
    await expect(
      router.createCaller(memberCtx).revokeAccess(input),
    ).rejects.toMatchObject({ code: "FORBIDDEN" });
    await expect(
      router.createCaller(anonCtx).revokeAccess(input),
    ).rejects.toMatchObject({ code: "UNAUTHORIZED" });
  });

  it("delete: admin allowed, member FORBIDDEN, anonymous UNAUTHORIZED", async () => {
    const router = buildUsersRouter();
    const input = { user_id: "target-1" };

    await expect(router.createCaller(adminCtx).delete(input)).resolves.toEqual(
      deleteResult,
    );
    await expect(
      router.createCaller(memberCtx).delete(input),
    ).rejects.toMatchObject({ code: "FORBIDDEN" });
    await expect(
      router.createCaller(anonCtx).delete(input),
    ).rejects.toMatchObject({ code: "UNAUTHORIZED" });
  });

  it("passes the CALLER's id to every mutation so the impl can refuse self-action", async () => {
    // The self-revoke / self-disable / self-delete refusals live in the impl,
    // and they can only work if the router actually forwards ctx.user.id. A
    // refactor that dropped the second argument would silently re-enable an
    // administrator deleting their own account (cascading their own
    // namespaces) or locking themselves out of the console.
    const revokeAccess = vi.fn().mockResolvedValue(revokeResult);
    const setDisabled = vi.fn().mockResolvedValue(disabledResult);
    const del = vi.fn().mockResolvedValue(deleteResult);
    const router = buildUsersRouter({ revokeAccess, setDisabled, delete: del });

    await router.createCaller(adminCtx).revokeAccess({ user_id: "target-1" });
    await router
      .createCaller(adminCtx)
      .setDisabled({ user_id: "target-1", disabled: true });
    await router.createCaller(adminCtx).delete({ user_id: "target-1" });

    // All three also take the audit actor bundle (Phase 1B) so the rows they
    // emit — `user.access.revoked`, `user.disabled.set`, `user.delete` — can
    // name who pressed the button. Asserted rather than loosened away,
    // because the caller id it carries is the same one the self-action
    // refusals depend on.
    expect(revokeAccess).toHaveBeenCalledWith(
      { user_id: "target-1" },
      "admin-1",
      expect.objectContaining({ actor_id: "admin-1" }),
    );
    expect(setDisabled).toHaveBeenCalledWith(
      { user_id: "target-1", disabled: true },
      "admin-1",
      expect.objectContaining({ actor_id: "admin-1" }),
    );
    expect(del).toHaveBeenCalledWith(
      { user_id: "target-1" },
      "admin-1",
      expect.objectContaining({ actor_id: "admin-1" }),
    );
  });
});

describe("Access routers — .output() is a second redaction layer", () => {
  // The serializers drop credential fields (access-redaction.test.ts covers
  // that). This asserts the INDEPENDENT second layer: even if a serializer is
  // edited carelessly — or bypassed entirely, as these deliberately broken
  // impls do — the router's `.output()` schema strips anything the contract
  // does not name, so a secret cannot ride out on an unlisted key.
  it("users.list strips fields the contract does not name", async () => {
    const router = buildUsersRouter({
      list: vi.fn().mockResolvedValue({
        total: 1,
        users: [
          {
            id: "user-1",
            email: "attacker@example.invalid",
            name: "Self Registered",
            role: "member",
            emailVerified: false,
            disabled: false,
            disabled_at: null,
            disabled_by: null,
            created_at: new Date("2026-08-13T12:00:00.000Z"),
            updated_at: new Date("2026-08-13T12:00:00.000Z"),
            last_session_refresh_at: null,
            active_session_count: 0,
            active_oauth_token_count: 0,
            active_api_key_count: 0,
            password: "$2b$10$leaked.bcrypt.hash",
            sessionToken: "sk_mt_leaked_session_token",
          },
        ],
      }),
    });

    const result = await router.createCaller(adminCtx).list();

    expect(result.users[0]).not.toHaveProperty("password");
    expect(result.users[0]).not.toHaveProperty("sessionToken");
    expect(JSON.stringify(result)).not.toMatch(/sk_|\$2[aby]\$/);
  });

  it("oauthTokens.list strips fields the contract does not name", async () => {
    const router = createOAuthTokensRouter({
      list: vi.fn().mockResolvedValue({
        tokens: [
          {
            user_id: "user-1",
            user_email: "attacker@example.invalid",
            client_id: "mcp_client_abc",
            client_name: "Claude",
            scope: "mcp",
            created_at: new Date("2026-08-13T12:00:00.000Z"),
            expires_at: new Date("2026-09-13T12:00:00.000Z"),
            has_refresh_token: true,
            refresh_token_expires_at: null,
            // The readable tail the contract now names (migration 0036); the
            // full token values below are the extras .output() must strip.
            access_token_last4: "0abc",
            access_token: "sk_mt_leaked_access_token",
            refresh_token: "sk_mt_leaked_refresh_token",
          },
        ],
      }),
    });

    const result = await router.createCaller(adminCtx).list();

    expect(result.tokens[0]).not.toHaveProperty("access_token");
    expect(result.tokens[0]).not.toHaveProperty("refresh_token");
    expect(JSON.stringify(result)).not.toMatch(/sk_/);
  });
});

describe("frontend.oauthTokens — admin gate", () => {
  it("list: admin allowed, member FORBIDDEN, anonymous UNAUTHORIZED", async () => {
    const router = buildTokensRouter();

    await expect(router.createCaller(adminCtx).list()).resolves.toEqual({
      tokens: [],
    });
    await expect(router.createCaller(memberCtx).list()).rejects.toMatchObject({
      code: "FORBIDDEN",
    });
    await expect(router.createCaller(anonCtx).list()).rejects.toMatchObject({
      code: "UNAUTHORIZED",
    });
  });
});
