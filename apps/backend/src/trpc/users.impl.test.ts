/**
 * Unit tests for the users tRPC implementation:
 *  - an administrator cannot revoke, disable or delete THEMSELVES (each of
 *    the three would lock the responder out of the console mid-response, and
 *    self-delete can leave a deployment with no administrator at all),
 *  - a miss is reported as a miss rather than a cheerful success — believing
 *    you cut off an attacker who is still connected is the expensive failure,
 *  - `list` runs the real serializer, so the credential-dropping and the
 *    date/bigint coercion are genuinely exercised rather than stubbed,
 *  - a failed delete returns a fixed message, never the driver's (which
 *    carries table names and internal hostnames),
 *  - delete records the blast radius BEFORE destroying the rows.
 *
 * The repository is mocked — its barrel reaches db/index, which needs a live
 * DATABASE_URL. Same approach as oauth-clients.impl.test.ts. The queries
 * themselves are covered against a real postgres in
 * db/repositories/access-queries.integration.test.ts.
 */

import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@/utils/logger", () => ({
  default: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  },
}));

const { usersRepoMock } = vi.hoisted(() => ({
  usersRepoMock: {
    findById: vi.fn(),
    listAll: vi.fn(),
    deleteById: vi.fn(),
    revokeAccess: vi.fn(),
    setDisabled: vi.fn(),
    previewDeleteImpact: vi.fn(),
  },
}));

vi.mock("../db/repositories", () => ({
  usersRepository: usersRepoMock,
}));

import { usersImplementations } from "./users.impl";

const ADMIN_ID = "admin-1";
const TARGET_ID = "attacker-1";
const NO_REVOCATIONS = {
  sessions_deleted: 0,
  oauth_tokens_deleted: 0,
  authorization_codes_deleted: 0,
  api_keys_deactivated: 0,
  m365_tokens_revoked: 0,
};
const IMPACT = {
  own_namespaces: 1,
  own_endpoints: 2,
  own_mcp_servers: 0,
  own_api_keys: 1,
  other_users_endpoints: 3,
  other_users_api_keys: 4,
  sessions: 1,
  oauth_tokens: 2,
  m365_tokens: 1,
};

beforeEach(() => {
  vi.clearAllMocks();
  usersRepoMock.findById.mockResolvedValue({
    id: TARGET_ID,
    email: "attacker@example.invalid",
    name: "Self Registered",
  });
  usersRepoMock.listAll.mockResolvedValue({ users: [], total: 0 });
  usersRepoMock.deleteById.mockResolvedValue(true);
  usersRepoMock.previewDeleteImpact.mockResolvedValue(IMPACT);
  usersRepoMock.setDisabled.mockResolvedValue({
    id: TARGET_ID,
    disabled: true,
  });
  usersRepoMock.revokeAccess.mockResolvedValue({
    sessions_deleted: 2,
    oauth_tokens_deleted: 1,
    authorization_codes_deleted: 0,
    api_keys_deactivated: 3,
    m365_tokens_revoked: 1,
  });
});

describe("usersImplementations.list", () => {
  it("serializes through the real serializer and drops non-contract fields", async () => {
    usersRepoMock.listAll.mockResolvedValue({
      total: 42,
      users: [
        {
          id: "user-1",
          email: "member@example.invalid",
          name: "Member",
          role: "member",
          emailVerified: true,
          disabled: false,
          disabled_at: null,
          disabled_by: null,
          created_at: new Date("2026-08-01T00:00:00.000Z"),
          updated_at: new Date("2026-08-02T00:00:00.000Z"),
          last_session_refresh_at: new Date("2026-08-13T00:00:00.000Z"),
          active_session_count: 1,
          active_oauth_token_count: 0,
          active_api_key_count: 2,
          password: "$2b$10$must.not.appear",
        },
      ],
    });

    const result = await usersImplementations.list();

    expect(result.users).toHaveLength(1);
    // The true total travels separately from the capped page, so the UI can
    // say "showing 1 of 42" instead of silently hiding 41 accounts.
    expect(result.total).toBe(42);
    // Iterated rather than indexed: `noUncheckedIndexedAccess` makes
    // `users[0]` possibly-undefined, and the repo's redaction tests use the
    // same loop instead of a non-null assertion.
    for (const user of result.users) {
      expect(user).not.toHaveProperty("password");
      expect(user.email).toBe("member@example.invalid");
      expect(user.active_api_key_count).toBe(2);
    }
  });
});

describe("usersImplementations.previewDelete", () => {
  it("returns the blast radius including the cross-user rows", async () => {
    const result = await usersImplementations.previewDelete({
      user_id: TARGET_ID,
    });

    expect(result.found).toBe(true);
    expect(result.email).toBe("attacker@example.invalid");
    // The numbers that must stop the click: other people's endpoints and
    // production keys die with this account.
    expect(result.impact.other_users_endpoints).toBe(3);
    expect(result.impact.other_users_api_keys).toBe(4);
  });

  it("reports not-found without inventing an impact", async () => {
    usersRepoMock.findById.mockResolvedValue(undefined);

    const result = await usersImplementations.previewDelete({
      user_id: "ghost",
    });

    expect(result.found).toBe(false);
    expect(result.email).toBeNull();
    expect(result.impact.other_users_api_keys).toBe(0);
    expect(usersRepoMock.previewDeleteImpact).not.toHaveBeenCalled();
  });
});

describe("usersImplementations.setDisabled", () => {
  it("refuses self-disable", async () => {
    // Disabling yourself takes effect on your very next request, so the
    // administrator loses the console they would need to undo it.
    await expect(
      usersImplementations.setDisabled(
        { user_id: ADMIN_ID, disabled: true },
        ADMIN_ID,
      ),
    ).rejects.toMatchObject({ code: "BAD_REQUEST" });

    expect(usersRepoMock.setDisabled).not.toHaveBeenCalled();
  });

  it("locks another account and passes the actor for the audit columns", async () => {
    const result = await usersImplementations.setDisabled(
      { user_id: TARGET_ID, disabled: true },
      ADMIN_ID,
    );

    expect(usersRepoMock.setDisabled).toHaveBeenCalledWith(
      TARGET_ID,
      true,
      ADMIN_ID,
    );
    expect(result).toEqual({
      success: true,
      message: "Account disabled",
      disabled: true,
    });
  });

  it("unlocks an account (enable reverses disable)", async () => {
    usersRepoMock.setDisabled.mockResolvedValue({
      id: TARGET_ID,
      disabled: false,
    });

    const result = await usersImplementations.setDisabled(
      { user_id: TARGET_ID, disabled: false },
      ADMIN_ID,
    );

    expect(usersRepoMock.setDisabled).toHaveBeenCalledWith(
      TARGET_ID,
      false,
      ADMIN_ID,
    );
    expect(result).toEqual({
      success: true,
      message: "Account enabled",
      disabled: false,
    });
  });

  it("reports a miss instead of a successful-looking no-op", async () => {
    usersRepoMock.setDisabled.mockResolvedValue(undefined);

    const result = await usersImplementations.setDisabled(
      { user_id: "ghost", disabled: true },
      ADMIN_ID,
    );

    expect(result).toEqual({
      success: false,
      message: "User not found",
      disabled: false,
    });
  });
});

describe("usersImplementations.revokeAccess", () => {
  it("refuses self-revocation", async () => {
    await expect(
      usersImplementations.revokeAccess({ user_id: ADMIN_ID }, ADMIN_ID),
    ).rejects.toMatchObject({ code: "BAD_REQUEST" });

    // Refused BEFORE touching the database — the administrator's own session
    // must survive the mistake.
    expect(usersRepoMock.revokeAccess).not.toHaveBeenCalled();
  });

  it("severs access for another account and reports what it cut", async () => {
    const result = await usersImplementations.revokeAccess(
      { user_id: TARGET_ID },
      ADMIN_ID,
    );

    expect(usersRepoMock.revokeAccess).toHaveBeenCalledWith(TARGET_ID);
    expect(result).toEqual({
      success: true,
      message: "Access revoked",
      sessions_deleted: 2,
      oauth_tokens_deleted: 1,
      authorization_codes_deleted: 0,
      api_keys_deactivated: 3,
      m365_tokens_revoked: 1,
    });
  });

  it("reports a miss instead of a successful-looking no-op", async () => {
    usersRepoMock.findById.mockResolvedValue(undefined);

    const result = await usersImplementations.revokeAccess(
      { user_id: "ghost" },
      ADMIN_ID,
    );

    expect(result).toEqual({
      success: false,
      message: "User not found",
      ...NO_REVOCATIONS,
    });
    expect(usersRepoMock.revokeAccess).not.toHaveBeenCalled();
  });

  it("surfaces a failed revoke as an error rather than a partial success", async () => {
    usersRepoMock.revokeAccess.mockRejectedValue(new Error("deadlock"));

    // The repository wraps its statements in ONE transaction, so a throw here
    // means nothing was committed — reporting failure is honest, and the
    // caller must not be handed a success shape with zero counts (which reads
    // as "this account had no access").
    await expect(
      usersImplementations.revokeAccess({ user_id: TARGET_ID }, ADMIN_ID),
    ).rejects.toMatchObject({ code: "INTERNAL_SERVER_ERROR" });
  });
});

describe("usersImplementations.delete", () => {
  it("refuses self-deletion", async () => {
    await expect(
      usersImplementations.delete({ user_id: ADMIN_ID }, ADMIN_ID),
    ).rejects.toMatchObject({ code: "BAD_REQUEST" });

    expect(usersRepoMock.deleteById).not.toHaveBeenCalled();
  });

  it("deletes another account and records the blast radius BEFORE the delete", async () => {
    const order: string[] = [];
    usersRepoMock.previewDeleteImpact.mockImplementation(async () => {
      order.push("preview");
      return IMPACT;
    });
    usersRepoMock.deleteById.mockImplementation(async () => {
      order.push("delete");
      return true;
    });

    const result = await usersImplementations.delete(
      { user_id: TARGET_ID },
      ADMIN_ID,
    );

    expect(usersRepoMock.deleteById).toHaveBeenCalledWith(TARGET_ID);
    // Once the rows are gone the cascade cannot be reconstructed, so the
    // audit log line has to be built from a reading taken first.
    expect(order).toEqual(["preview", "delete"]);
    expect(result).toEqual({
      success: true,
      message: "User deleted successfully",
    });
  });

  it("reports a miss instead of a successful-looking no-op", async () => {
    usersRepoMock.findById.mockResolvedValue(undefined);

    const result = await usersImplementations.delete(
      { user_id: "ghost" },
      ADMIN_ID,
    );

    expect(result).toEqual({ success: false, message: "User not found" });
    expect(usersRepoMock.deleteById).not.toHaveBeenCalled();
  });

  it("never echoes the driver's error message back to the caller", async () => {
    usersRepoMock.deleteById.mockRejectedValue(
      new Error(
        'update or delete on table "users" violates foreign key constraint on host db-internal.umbrella.lan',
      ),
    );

    const result = await usersImplementations.delete(
      { user_id: TARGET_ID },
      ADMIN_ID,
    );

    expect(result.success).toBe(false);
    expect(result.message).toBe("Failed to delete user");
    // The tRPC errorFormatter masks INTERNAL_SERVER_ERROR messages, but this
    // is a SUCCESSFUL response carrying a failure string — the mask does not
    // reach it, so the impl has to do the masking itself.
    expect(result.message).not.toContain("db-internal.umbrella.lan");
  });
});
