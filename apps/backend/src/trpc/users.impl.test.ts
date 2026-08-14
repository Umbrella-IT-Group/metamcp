/**
 * Unit tests for the users tRPC implementation:
 *  - an administrator cannot revoke or delete THEMSELVES (self-revoke signs
 *    the responder out mid-incident; self-delete cascades away their own
 *    sessions, keys and owned namespaces and can leave a deployment with no
 *    administrator at all),
 *  - a miss is reported as a miss rather than a cheerful success — believing
 *    you cut off an attacker who is still connected is the expensive failure,
 *  - `list` runs the real serializer, so the credential-dropping is genuinely
 *    exercised rather than asserted against a stub,
 *  - a failed delete returns a fixed message, never the driver's (which
 *    carries table names and internal hostnames).
 *
 * The repository is mocked — its barrel reaches db/index, which needs a live
 * DATABASE_URL. Same approach as oauth-clients.impl.test.ts.
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
};

beforeEach(() => {
  vi.clearAllMocks();
  usersRepoMock.findById.mockResolvedValue({
    id: TARGET_ID,
    email: "attacker@example.invalid",
    name: "Self Registered",
  });
  usersRepoMock.listAll.mockResolvedValue([]);
  usersRepoMock.deleteById.mockResolvedValue(true);
  usersRepoMock.revokeAccess.mockResolvedValue({
    sessions_deleted: 2,
    oauth_tokens_deleted: 1,
    authorization_codes_deleted: 0,
    api_keys_deactivated: 3,
  });
});

describe("usersImplementations.list", () => {
  it("serializes through the real serializer and drops non-contract fields", async () => {
    usersRepoMock.listAll.mockResolvedValue([
      {
        id: "user-1",
        email: "member@example.invalid",
        name: "Member",
        role: "member",
        emailVerified: true,
        created_at: new Date("2026-08-01T00:00:00.000Z"),
        updated_at: new Date("2026-08-02T00:00:00.000Z"),
        last_active_at: new Date("2026-08-13T00:00:00.000Z"),
        active_session_count: 1,
        active_oauth_token_count: 0,
        active_api_key_count: 2,
        password: "$2b$10$must.not.appear",
      },
    ]);

    const result = await usersImplementations.list();

    expect(result.users).toHaveLength(1);
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
});

describe("usersImplementations.delete", () => {
  it("refuses self-deletion", async () => {
    await expect(
      usersImplementations.delete({ user_id: ADMIN_ID }, ADMIN_ID),
    ).rejects.toMatchObject({ code: "BAD_REQUEST" });

    expect(usersRepoMock.deleteById).not.toHaveBeenCalled();
  });

  it("deletes another account", async () => {
    const result = await usersImplementations.delete(
      { user_id: TARGET_ID },
      ADMIN_ID,
    );

    expect(usersRepoMock.deleteById).toHaveBeenCalledWith(TARGET_ID);
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
