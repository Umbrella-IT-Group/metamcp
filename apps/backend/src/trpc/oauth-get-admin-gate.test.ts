/**
 * `frontend.oauth.get` must be admin-only.
 *
 * The procedure was `protectedProcedure` and its impl
 * (`apps/backend/src/trpc/oauth.impl.ts`) takes only an `mcp_server_uuid`,
 * with no ownership or role check, so any member could name any upstream MCP
 * server and read back that server's raw stored credentials: `tokens`
 * (access_token + refresh_token), `client_information` (client_id +
 * client_secret) and `code_verifier`, none of them redacted by
 * `db/serializers/oauth-sessions.serializer.ts`. That is gateway-level
 * upstream credential material, not per-user data — the same records its
 * sibling `upsert` has been admin-gated for since the 2026-07-14 sweep.
 *
 * The impl is stubbed: what is under test is the procedure's gate, not the
 * repository read behind it. A member reaching the impl at all is the bug.
 */

import { createOAuthRouter } from "@repo/trpc";
import { describe, expect, it, vi } from "vitest";

const adminCtx = {
  user: { id: "admin-1", role: "admin" },
  session: { id: "s-admin" },
};
const memberCtx = {
  user: { id: "member-1", role: "member" },
  session: { id: "s-member" },
};
const roundtripCtx = {
  // A session user with no role at all — the shape a future auth change
  // could produce. Must deny, never fall through to allow.
  user: { id: "shapeless-1" },
  session: { id: "s-shapeless" },
};

const MCP_SERVER_UUID = "11111111-1111-4111-8111-111111111111";

const buildRouter = () => {
  const get = vi.fn().mockResolvedValue({
    success: true as const,
    data: {
      uuid: "22222222-2222-4222-8222-222222222222",
      mcp_server_uuid: MCP_SERVER_UUID,
      client_information: {
        client_id: "upstream-client",
        client_secret: "upstream-secret",
      },
      tokens: {
        access_token: "at-secret",
        refresh_token: "rt-secret",
        token_type: "Bearer",
      },
      code_verifier: "cv-secret",
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    },
    message: "ok",
  });
  const upsert = vi.fn().mockResolvedValue({
    success: false as const,
    error: "not used in this suite",
  });
  return { router: createOAuthRouter({ get, upsert }), get };
};

describe("oauth.get — admin gate", () => {
  it("admin allowed", async () => {
    const { router, get } = buildRouter();

    const result = await router
      .createCaller(adminCtx)
      .get({ mcp_server_uuid: MCP_SERVER_UUID });

    expect(result.success).toBe(true);
    expect(get).toHaveBeenCalledTimes(1);
  });

  it("member FORBIDDEN, and the impl is never reached", async () => {
    const { router, get } = buildRouter();

    await expect(
      router.createCaller(memberCtx).get({ mcp_server_uuid: MCP_SERVER_UUID }),
    ).rejects.toMatchObject({ code: "FORBIDDEN" });

    // No credential read may happen at all — the gate must short-circuit
    // before the repository query, not filter the response afterwards.
    expect(get).not.toHaveBeenCalled();
  });

  it("a session user carrying no role is denied (fail-closed)", async () => {
    const { router, get } = buildRouter();

    await expect(
      router
        .createCaller(roundtripCtx)
        .get({ mcp_server_uuid: MCP_SERVER_UUID }),
    ).rejects.toMatchObject({ code: "FORBIDDEN" });
    expect(get).not.toHaveBeenCalled();
  });

  it("an unauthenticated caller is UNAUTHORIZED, not FORBIDDEN", async () => {
    const { router, get } = buildRouter();

    await expect(
      router.createCaller({}).get({ mcp_server_uuid: MCP_SERVER_UUID }),
    ).rejects.toMatchObject({ code: "UNAUTHORIZED" });
    expect(get).not.toHaveBeenCalled();
  });
});
