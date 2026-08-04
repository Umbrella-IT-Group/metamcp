/**
 * Unit tests for the OAuth-clients tRPC surface:
 *  - create reuses the shared registration core (bad input is rejected with
 *    the core's own message, never persisted) and returns the freshly-minted
 *    client_secret exactly once,
 *  - list NEVER echoes a stored secret — only `has_client_secret`,
 *  - delete distinguishes "deleted" from "no such client" instead of always
 *    reporting success,
 *  - every procedure is admin-gated (a registered client is gateway-level
 *    config with no per-user ownership, so unlike api-keys there is no member
 *    path at all).
 *
 * The repository is mocked (its barrel reaches db/index, which needs a live
 * DATABASE_URL); the real serializer is used so the secret-dropping is
 * genuinely exercised rather than asserted against a stub.
 */

import { createOAuthClientsRouter } from "@repo/trpc";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@/utils/logger", () => ({
  default: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  },
}));

const { oauthRepoMock } = vi.hoisted(() => ({
  oauthRepoMock: {
    upsertClient: vi.fn(),
    listClients: vi.fn(),
    deleteClient: vi.fn(),
  },
}));

vi.mock("../db/repositories", () => ({
  oauthRepository: oauthRepoMock,
}));

import { oauthClientsImplementations } from "./oauth-clients.impl";

const CLAUDE_CALLBACKS = [
  "https://claude.ai/api/mcp/auth_callback",
  "https://claude.com/api/mcp/auth_callback",
];

const baseCreateInput = {
  client_name: "Claude",
  redirect_uris: CLAUDE_CALLBACKS,
  token_endpoint_auth_method: "none" as const,
  grant_types: ["authorization_code" as const],
  response_types: ["code" as const],
  scope: "admin",
};

beforeEach(() => {
  vi.clearAllMocks();
  oauthRepoMock.upsertClient.mockResolvedValue(undefined);
  oauthRepoMock.listClients.mockResolvedValue([]);
  oauthRepoMock.deleteClient.mockResolvedValue(true);
});

describe("oauthClientsImplementations.create", () => {
  it("persists the minted client and returns its credentials", async () => {
    const result = await oauthClientsImplementations.create(baseCreateInput);

    expect(result.client_id).toMatch(/^mcp_client_/);
    expect(result.client_name).toBe("Claude");
    expect(result.redirect_uris).toEqual(CLAUDE_CALLBACKS);

    expect(oauthRepoMock.upsertClient).toHaveBeenCalledTimes(1);
    // What is returned to the UI must be what was written, or the operator
    // copies a client_id that does not exist.
    expect(oauthRepoMock.upsertClient).toHaveBeenCalledWith(
      expect.objectContaining({
        client_id: result.client_id,
        redirect_uris: CLAUDE_CALLBACKS,
      }),
    );
  });

  it("returns a null secret for a PKCE public client", async () => {
    const result = await oauthClientsImplementations.create(baseCreateInput);
    expect(result.client_secret).toBeNull();
  });

  it("returns the secret once for a confidential client", async () => {
    const result = await oauthClientsImplementations.create({
      ...baseCreateInput,
      token_endpoint_auth_method: "client_secret_post",
    });

    expect(result.client_secret).toMatch(/^mcp_secret_/);
    // Same value that was stored — the create response is the only place it
    // is ever disclosed, so it cannot be a different generated string.
    expect(oauthRepoMock.upsertClient).toHaveBeenCalledWith(
      expect.objectContaining({ client_secret: result.client_secret }),
    );
  });

  it("rejects an invalid redirect URI WITHOUT writing anything", async () => {
    await expect(
      oauthClientsImplementations.create({
        ...baseCreateInput,
        redirect_uris: ["myapp://callback"],
      }),
    ).rejects.toMatchObject({
      code: "BAD_REQUEST",
      message: expect.stringContaining("myapp://callback"),
    });

    // The admin path must not be a way around redirect-URI validation.
    expect(oauthRepoMock.upsertClient).not.toHaveBeenCalled();
  });

  it("surfaces a repository failure as INTERNAL_SERVER_ERROR", async () => {
    oauthRepoMock.upsertClient.mockRejectedValue(new Error("db down"));

    await expect(
      oauthClientsImplementations.create(baseCreateInput),
    ).rejects.toMatchObject({ code: "INTERNAL_SERVER_ERROR" });
  });
});

describe("oauthClientsImplementations.list", () => {
  it("reports secret PRESENCE and never the secret itself", async () => {
    oauthRepoMock.listClients.mockResolvedValue([
      {
        client_id: "mcp_client_abc",
        client_secret: "mcp_secret_SUPERSECRET",
        client_name: "Confidential",
        redirect_uris: CLAUDE_CALLBACKS,
        grant_types: ["authorization_code"],
        response_types: ["code"],
        token_endpoint_auth_method: "client_secret_post",
        scope: "admin",
        created_at: new Date("2026-01-01T00:00:00Z"),
        updated_at: new Date("2026-01-02T00:00:00Z"),
      },
      {
        client_id: "mcp_client_def",
        client_secret: null,
        client_name: "Public PKCE",
        redirect_uris: CLAUDE_CALLBACKS,
        grant_types: ["authorization_code"],
        response_types: ["code"],
        token_endpoint_auth_method: "none",
        scope: "admin",
        created_at: new Date("2026-01-03T00:00:00Z"),
        updated_at: undefined,
      },
    ]);

    const result = await oauthClientsImplementations.list();

    expect(result.clients).toHaveLength(2);
    expect(result.clients[0]).toMatchObject({
      client_id: "mcp_client_abc",
      has_client_secret: true,
    });
    expect(result.clients[1]).toMatchObject({
      client_id: "mcp_client_def",
      has_client_secret: false,
      updated_at: null,
    });

    // The exfiltration guard: the raw secret must appear nowhere in the
    // serialized payload, under any key.
    expect(JSON.stringify(result)).not.toContain("SUPERSECRET");
    expect(result.clients[0]).not.toHaveProperty("client_secret");
  });

  it("returns an empty list rather than throwing when none are registered", async () => {
    await expect(oauthClientsImplementations.list()).resolves.toEqual({
      clients: [],
    });
  });

  it("surfaces a repository failure as INTERNAL_SERVER_ERROR", async () => {
    oauthRepoMock.listClients.mockRejectedValue(new Error("db down"));
    await expect(oauthClientsImplementations.list()).rejects.toMatchObject({
      code: "INTERNAL_SERVER_ERROR",
    });
  });
});

describe("oauthClientsImplementations.delete", () => {
  it("deletes by client_id", async () => {
    const result = await oauthClientsImplementations.delete({
      client_id: "mcp_client_abc",
    });

    expect(result).toEqual({
      success: true,
      message: "OAuth client deleted successfully",
    });
    expect(oauthRepoMock.deleteClient).toHaveBeenCalledWith("mcp_client_abc");
  });

  it("reports a miss instead of a false success", async () => {
    oauthRepoMock.deleteClient.mockResolvedValue(false);

    const result = await oauthClientsImplementations.delete({
      client_id: "mcp_client_gone",
    });

    // An operator who believes they revoked a live client is worse off than
    // one who is told the delete matched nothing.
    expect(result.success).toBe(false);
    expect(result.message).toBe("OAuth client not found");
  });

  it("returns a failure payload when the repository throws", async () => {
    oauthRepoMock.deleteClient.mockRejectedValue(new Error("db down"));

    const result = await oauthClientsImplementations.delete({
      client_id: "mcp_client_abc",
    });

    expect(result.success).toBe(false);
    expect(result.message).toBe("db down");
  });
});

describe("oauth-clients router RBAC", () => {
  // Stub implementations — this block tests the gate, not the behaviour.
  const router = createOAuthClientsRouter({
    create: vi.fn(async () => ({
      client_id: "mcp_client_x",
      client_secret: null,
      client_name: "x",
      redirect_uris: CLAUDE_CALLBACKS,
      grant_types: ["authorization_code"],
      response_types: ["code"],
      token_endpoint_auth_method: "none",
      scope: "admin",
      created_at: new Date(),
    })),
    list: vi.fn(async () => ({ clients: [] })),
    delete: vi.fn(async () => ({ success: true, message: "ok" })),
  });

  const admin = router.createCaller({
    user: { id: "u-admin", role: "admin" },
    session: { id: "s1" },
  });
  const member = router.createCaller({
    user: { id: "u-member", role: "member" },
    session: { id: "s2" },
  });
  const anonymous = router.createCaller({});

  it("allows an admin on every procedure", async () => {
    await expect(admin.list()).resolves.toEqual({ clients: [] });
    await expect(admin.create(baseCreateInput)).resolves.toMatchObject({
      client_id: "mcp_client_x",
    });
    await expect(
      admin.delete({ client_id: "mcp_client_x" }),
    ).resolves.toMatchObject({ success: true });
  });

  it("rejects a member with FORBIDDEN on every procedure", async () => {
    await expect(member.list()).rejects.toMatchObject({ code: "FORBIDDEN" });
    await expect(member.create(baseCreateInput)).rejects.toMatchObject({
      code: "FORBIDDEN",
    });
    await expect(
      member.delete({ client_id: "mcp_client_x" }),
    ).rejects.toMatchObject({ code: "FORBIDDEN" });
  });

  it("rejects an unauthenticated caller with UNAUTHORIZED", async () => {
    await expect(anonymous.list()).rejects.toMatchObject({
      code: "UNAUTHORIZED",
    });
    await expect(anonymous.create(baseCreateInput)).rejects.toMatchObject({
      code: "UNAUTHORIZED",
    });
    await expect(
      anonymous.delete({ client_id: "mcp_client_x" }),
    ).rejects.toMatchObject({ code: "UNAUTHORIZED" });
  });
});
