/**
 * Unit tests for the api-keys tRPC implementation's RBAC + governance logic:
 *  - the mint gate (members may only create their own private keys; only
 *    admins may mint public/'everyone' keys or assign a key to another user),
 *  - the admin cross-user listing (listAll) drops the full secret and carries
 *    owner email + last_used_at,
 *  - update/delete route to the owner-scoped repo methods for members and the
 *    ownership-bypass methods for admins.
 *
 * The repository is mocked (its barrel reaches db/index, which needs a live
 * DATABASE_URL); the real serializer is used so the response shaping is
 * exercised too. The repository's own ownership WHERE clauses are verified by
 * code review — there is no live-DB test harness in this fork.
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

// One shared mock instance returned by `new ApiKeysRepository()` — the impl
// constructs it once at module load.
const { repoMock } = vi.hoisted(() => ({
  repoMock: {
    create: vi.fn(),
    findAll: vi.fn(),
    findAccessibleToUser: vi.fn(),
    update: vi.fn(),
    updateAsAdmin: vi.fn(),
    delete: vi.fn(),
    deleteAsAdmin: vi.fn(),
  },
}));

// A class (not an arrow) so `new ApiKeysRepository()` constructs — its methods
// delegate to the one shared mock object the assertions inspect.
vi.mock("../db/repositories", () => ({
  ApiKeysRepository: class {
    create = repoMock.create;
    findAll = repoMock.findAll;
    findAccessibleToUser = repoMock.findAccessibleToUser;
    update = repoMock.update;
    updateAsAdmin = repoMock.updateAsAdmin;
    delete = repoMock.delete;
    deleteAsAdmin = repoMock.deleteAsAdmin;
  },
}));

import { apiKeysImplementations } from "./api-keys.impl";

beforeEach(() => {
  vi.clearAllMocks();
});

describe("api-keys create — mint RBAC gate", () => {
  it("rejects a member minting a public ('everyone') key with FORBIDDEN and no write", async () => {
    await expect(
      apiKeysImplementations.create(
        { name: "shared", user_id: null },
        "member-1",
        false,
      ),
    ).rejects.toMatchObject({ code: "FORBIDDEN" });
    expect(repoMock.create).not.toHaveBeenCalled();
  });

  it("rejects a member assigning a key to another user (ownership spoofing)", async () => {
    await expect(
      apiKeysImplementations.create(
        { name: "sneaky", user_id: "victim-user" },
        "member-1",
        false,
      ),
    ).rejects.toMatchObject({ code: "FORBIDDEN" });
    expect(repoMock.create).not.toHaveBeenCalled();
  });

  it("lets a member mint a private key owned by themselves", async () => {
    repoMock.create.mockResolvedValue({
      uuid: "key-uuid",
      name: "mine",
      key: "sk_mt_secretsecret",
      user_id: "member-1",
      created_at: new Date(),
    });

    const result = await apiKeysImplementations.create(
      { name: "mine" },
      "member-1",
      false,
    );

    expect(repoMock.create).toHaveBeenCalledWith({
      name: "mine",
      user_id: "member-1",
      is_active: true,
    });
    expect(result.key).toBe("sk_mt_secretsecret");
  });

  it("lets an admin mint a public key", async () => {
    repoMock.create.mockResolvedValue({
      uuid: "pub-uuid",
      name: "public",
      key: "sk_mt_publicpublic",
      user_id: null,
      created_at: new Date(),
    });

    await apiKeysImplementations.create(
      { name: "public", user_id: null },
      "admin-1",
      true,
    );

    expect(repoMock.create).toHaveBeenCalledWith({
      name: "public",
      user_id: null,
      is_active: true,
    });
  });
});

describe("api-keys listAll — admin cross-user view", () => {
  it("returns every key with owner email + last_used, and never the full secret", async () => {
    repoMock.findAll.mockResolvedValue([
      {
        uuid: "1",
        name: "alice-key",
        key: "sk_mt_AAAAAAAAAAAAAAAA",
        created_at: new Date("2026-07-01T00:00:00Z"),
        last_used_at: null,
        is_active: true,
        user_id: "alice",
        owner_email: "alice@example.com",
      },
      {
        uuid: "2",
        name: "public-key",
        key: "sk_mt_BBBBBBBBBBBBBBBB",
        created_at: new Date("2026-07-02T00:00:00Z"),
        last_used_at: new Date("2026-07-10T00:00:00Z"),
        is_active: false,
        user_id: null,
        owner_email: null,
      },
    ]);

    const result = await apiKeysImplementations.listAll();

    expect(result.apiKeys).toHaveLength(2);
    // Cross-user: a key owned by "alice" is present even though listAll takes
    // no caller id — the ownership filter is gone.
    expect(result.apiKeys[0].owner_email).toBe("alice@example.com");
    expect(result.apiKeys[1].owner_email).toBeNull(); // public key
    // The full secret must NOT leak; only a non-reversible prefix is exposed.
    expect((result.apiKeys[0] as Record<string, unknown>).key).toBeUndefined();
    expect(result.apiKeys[0].key_prefix).toBe("sk_mt_AAAA…");
    expect(result.apiKeys[0].key_prefix.length).toBeLessThan(
      "sk_mt_AAAAAAAAAAAAAAAA".length,
    );
    expect(result.apiKeys[1].last_used_at).toEqual(
      new Date("2026-07-10T00:00:00Z"),
    );
  });
});

describe("api-keys update — admin ownership bypass", () => {
  it("routes an admin update through the ownership-bypass repo method", async () => {
    repoMock.updateAsAdmin.mockResolvedValue({
      uuid: "k",
      name: "renamed",
      key: "sk_mt_x",
      created_at: new Date(),
      is_active: false,
    });

    await apiKeysImplementations.update(
      { uuid: "k", is_active: false },
      "admin-1",
      true,
    );

    expect(repoMock.updateAsAdmin).toHaveBeenCalledWith("k", {
      name: undefined,
      is_active: false,
    });
    expect(repoMock.update).not.toHaveBeenCalled();
  });

  it("routes a member update through the owner-scoped repo method", async () => {
    repoMock.update.mockResolvedValue({
      uuid: "k",
      name: "renamed",
      key: "sk_mt_x",
      created_at: new Date(),
      is_active: false,
    });

    await apiKeysImplementations.update(
      { uuid: "k", is_active: false },
      "member-1",
      false,
    );

    expect(repoMock.update).toHaveBeenCalledWith("k", "member-1", {
      name: undefined,
      is_active: false,
    });
    expect(repoMock.updateAsAdmin).not.toHaveBeenCalled();
  });
});

describe("api-keys delete — member scoped vs admin bypass", () => {
  it("member revoke of another user's key is rejected (owner-scoped repo throws not-found)", async () => {
    // The owner-scoped delete() WHERE (uuid AND user_id === caller, only —
    // see api-keys.repo.member-scope.test.ts) matches no row for a foreign
    // private key, so the real repo throws not-found.
    repoMock.delete.mockRejectedValue(
      new Error("Failed to delete API key or API key not found"),
    );

    const result = await apiKeysImplementations.delete(
      { uuid: "foreign-key" },
      "member-1",
      false,
    );

    expect(result.success).toBe(false);
    expect(repoMock.delete).toHaveBeenCalledWith("foreign-key", "member-1");
    expect(repoMock.deleteAsAdmin).not.toHaveBeenCalled();
  });

  it("admin revoke of any key routes through the ownership-bypass repo method", async () => {
    repoMock.deleteAsAdmin.mockResolvedValue({
      uuid: "foreign-key",
      name: "x",
    });

    const result = await apiKeysImplementations.delete(
      { uuid: "foreign-key" },
      "admin-1",
      true,
    );

    expect(result.success).toBe(true);
    expect(repoMock.deleteAsAdmin).toHaveBeenCalledWith("foreign-key");
    expect(repoMock.delete).not.toHaveBeenCalled();
  });
});

// BLOCKER fix (independent security review, 2026-07-14): a public
// ('everyone') key's uuid is visible to any member via their own `list`
// query. Before the fix, the member-scoped update()/delete() WHERE matched
// public keys too (`isNull(user_id)` branch), so a member could deactivate
// or DELETE a key every other consumer depends on. Post-fix, the member path
// routes through the SAME owner-only repo methods as the "foreign private
// key" cases above — a public key's user_id is null, which never equals a
// caller's id, so the real repo throws not-found exactly like a foreign
// private key would. These tests pin that outcome explicitly by name so the
// public-key case can't silently regress even if the general
// foreign-key-rejection tests above are ever weakened.
describe("api-keys — public key isolation from members (BLOCKER fix)", () => {
  it("member cannot deactivate a public key (owner-scoped repo throws not-found)", async () => {
    repoMock.update.mockRejectedValue(
      new Error("Failed to update API key or API key not found"),
    );

    await expect(
      apiKeysImplementations.update(
        { uuid: "public-key", is_active: false },
        "member-1",
        false,
      ),
    ).rejects.toThrow("Failed to update API key or API key not found");
    expect(repoMock.update).toHaveBeenCalledWith("public-key", "member-1", {
      name: undefined,
      is_active: false,
    });
    expect(repoMock.updateAsAdmin).not.toHaveBeenCalled();
  });

  it("member cannot delete a public key (owner-scoped repo throws not-found, no-op response)", async () => {
    repoMock.delete.mockRejectedValue(
      new Error("Failed to delete API key or API key not found"),
    );

    const result = await apiKeysImplementations.delete(
      { uuid: "public-key" },
      "member-1",
      false,
    );

    expect(result.success).toBe(false);
    expect(repoMock.delete).toHaveBeenCalledWith("public-key", "member-1");
    expect(repoMock.deleteAsAdmin).not.toHaveBeenCalled();
  });

  it("admin can still deactivate a public key", async () => {
    repoMock.updateAsAdmin.mockResolvedValue({
      uuid: "public-key",
      name: "shared",
      key: "sk_mt_x",
      created_at: new Date(),
      is_active: false,
    });

    const result = await apiKeysImplementations.update(
      { uuid: "public-key", is_active: false },
      "admin-1",
      true,
    );

    expect(result.is_active).toBe(false);
    expect(repoMock.updateAsAdmin).toHaveBeenCalledWith("public-key", {
      name: undefined,
      is_active: false,
    });
  });

  it("admin can still delete a public key", async () => {
    repoMock.deleteAsAdmin.mockResolvedValue({
      uuid: "public-key",
      name: "shared",
    });

    const result = await apiKeysImplementations.delete(
      { uuid: "public-key" },
      "admin-1",
      true,
    );

    expect(result.success).toBe(true);
    expect(repoMock.deleteAsAdmin).toHaveBeenCalledWith("public-key");
  });
});
