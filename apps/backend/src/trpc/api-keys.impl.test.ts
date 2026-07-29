/**
 * Unit tests for the api-keys tRPC implementation's RBAC + governance logic:
 *  - the mint gate (members may only create their own private keys; only
 *    admins may mint public/'everyone' keys or assign a key to another user),
 *  - the endpoint-scope mint rules (migration 0023): every new key must
 *    either name the ONE endpoint it may reach or pass the explicit
 *    all_endpoints escape hatch; scope selection is admin-only; the scoped
 *    endpoint must exist; all_endpoints stores NULL,
 *  - scope immutability: the update schemas/paths do not carry endpoint_uuid
 *    at all — a key's scope is fixed at mint time,
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

import {
  ApiKeyUpdateInputSchema,
  CreateApiKeyRequestSchema,
  UpdateApiKeyRequestSchema,
} from "@repo/zod-types";
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
// constructs it once at module load. endpointsRepoMock backs the exported
// endpointsRepository singleton the impl uses to verify a scope target
// exists; usersRepoMock backs the usersRepository singleton it uses to
// verify an acts-as identity target exists (migration 0024).
const { repoMock, endpointsRepoMock, usersRepoMock } = vi.hoisted(() => ({
  repoMock: {
    create: vi.fn(),
    findAll: vi.fn(),
    findAccessibleToUser: vi.fn(),
    update: vi.fn(),
    updateAsAdmin: vi.fn(),
    delete: vi.fn(),
    deleteAsAdmin: vi.fn(),
  },
  endpointsRepoMock: {
    findByUuid: vi.fn(),
  },
  usersRepoMock: {
    findById: vi.fn(),
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
  endpointsRepository: endpointsRepoMock,
  usersRepository: usersRepoMock,
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

  // Pre-0023 this was "lets a member mint a private key owned by themselves".
  // Scope is now mandatory and scope selection is admin-only, so a member's
  // create is rejected either way: no scope fields → BAD_REQUEST (explicit
  // scope required), any scope field → FORBIDDEN (admin-only). Net effect:
  // key minting is an administrator operation.
  it("rejects a member minting even their own key when no scope is given (scope is mandatory)", async () => {
    await expect(
      apiKeysImplementations.create({ name: "mine" }, "member-1", false),
    ).rejects.toMatchObject({ code: "BAD_REQUEST" });
    expect(repoMock.create).not.toHaveBeenCalled();
  });

  it("rejects a member setting endpoint_uuid with FORBIDDEN and no write", async () => {
    await expect(
      apiKeysImplementations.create(
        {
          name: "mine",
          endpoint_uuid: "11111111-1111-4111-8111-111111111111",
        },
        "member-1",
        false,
      ),
    ).rejects.toMatchObject({ code: "FORBIDDEN" });
    expect(repoMock.create).not.toHaveBeenCalled();
    expect(endpointsRepoMock.findByUuid).not.toHaveBeenCalled();
  });

  it("rejects a member passing all_endpoints with FORBIDDEN and no write", async () => {
    await expect(
      apiKeysImplementations.create(
        { name: "mine", all_endpoints: true },
        "member-1",
        false,
      ),
    ).rejects.toMatchObject({ code: "FORBIDDEN" });
    expect(repoMock.create).not.toHaveBeenCalled();
  });

  it("lets an admin mint a public gateway-wide key via the explicit all_endpoints escape hatch", async () => {
    repoMock.create.mockResolvedValue({
      uuid: "pub-uuid",
      name: "public",
      key: "sk_mt_publicpublic",
      user_id: null,
      endpoint_uuid: null,
      created_at: new Date(),
    });

    await apiKeysImplementations.create(
      { name: "public", user_id: null, all_endpoints: true },
      "admin-1",
      true,
    );

    expect(repoMock.create).toHaveBeenCalledWith({
      name: "public",
      user_id: null,
      endpoint_uuid: null,
      acts_as_user_id: null,
      is_active: true,
    });
  });
});

describe("api-keys create — explicit endpoint scope (migration 0023)", () => {
  const EP = "11111111-1111-4111-8111-111111111111";

  it("rejects an admin create with neither endpoint_uuid nor all_endpoints (silent-global impossible)", async () => {
    await expect(
      apiKeysImplementations.create({ name: "unscoped" }, "admin-1", true),
    ).rejects.toMatchObject({ code: "BAD_REQUEST" });
    expect(repoMock.create).not.toHaveBeenCalled();
  });

  it("rejects an admin create passing BOTH endpoint_uuid and all_endpoints", async () => {
    await expect(
      apiKeysImplementations.create(
        { name: "both", endpoint_uuid: EP, all_endpoints: true },
        "admin-1",
        true,
      ),
    ).rejects.toMatchObject({ code: "BAD_REQUEST" });
    expect(repoMock.create).not.toHaveBeenCalled();
  });

  it("all_endpoints: true stores NULL scope (legacy gateway-wide key)", async () => {
    repoMock.create.mockResolvedValue({
      uuid: "key-uuid",
      name: "global",
      key: "sk_mt_globalglobal",
      user_id: "admin-1",
      endpoint_uuid: null,
      created_at: new Date(),
    });

    await apiKeysImplementations.create(
      { name: "global", all_endpoints: true },
      "admin-1",
      true,
    );

    expect(repoMock.create).toHaveBeenCalledWith({
      name: "global",
      user_id: "admin-1",
      endpoint_uuid: null,
      acts_as_user_id: null,
      is_active: true,
    });
    // The escape hatch never triggers an endpoint lookup.
    expect(endpointsRepoMock.findByUuid).not.toHaveBeenCalled();
  });

  it("admin create with endpoint_uuid validates the endpoint exists, then persists the scope", async () => {
    endpointsRepoMock.findByUuid.mockResolvedValue({
      uuid: EP,
      name: "autotask",
    });
    repoMock.create.mockResolvedValue({
      uuid: "key-uuid",
      name: "scoped",
      key: "sk_mt_scopedscoped",
      user_id: "admin-1",
      endpoint_uuid: EP,
      created_at: new Date(),
    });

    const result = await apiKeysImplementations.create(
      { name: "scoped", endpoint_uuid: EP },
      "admin-1",
      true,
    );

    expect(endpointsRepoMock.findByUuid).toHaveBeenCalledWith(EP);
    expect(repoMock.create).toHaveBeenCalledWith({
      name: "scoped",
      user_id: "admin-1",
      endpoint_uuid: EP,
      acts_as_user_id: null,
      is_active: true,
    });
    expect(result.key).toBe("sk_mt_scopedscoped");
  });

  it("rejects a scope pointing at a nonexistent endpoint with NOT_FOUND and no write", async () => {
    endpointsRepoMock.findByUuid.mockResolvedValue(undefined);

    await expect(
      apiKeysImplementations.create(
        { name: "dangling", endpoint_uuid: EP },
        "admin-1",
        true,
      ),
    ).rejects.toMatchObject({ code: "NOT_FOUND" });
    expect(repoMock.create).not.toHaveBeenCalled();
  });
});

describe("api-keys create — acts-as identity binding (migration 0024)", () => {
  const EP = "11111111-1111-4111-8111-111111111111";

  it("rejects a member setting acts_as_user_id with FORBIDDEN and no write, no user lookup", async () => {
    await expect(
      apiKeysImplementations.create(
        { name: "sneaky-identity", acts_as_user_id: "victim-user" },
        "member-1",
        false,
      ),
    ).rejects.toMatchObject({ code: "FORBIDDEN" });
    expect(repoMock.create).not.toHaveBeenCalled();
    expect(usersRepoMock.findById).not.toHaveBeenCalled();
  });

  it("rejects acts_as_user_id paired with all_endpoints: true — identity requires a single-endpoint scope", async () => {
    await expect(
      apiKeysImplementations.create(
        {
          name: "global-identity",
          all_endpoints: true,
          acts_as_user_id: "target-user",
        },
        "admin-1",
        true,
      ),
    ).rejects.toMatchObject({ code: "BAD_REQUEST" });
    expect(repoMock.create).not.toHaveBeenCalled();
    expect(usersRepoMock.findById).not.toHaveBeenCalled();
  });

  it("rejects acts_as_user_id without any scope at all (no silent identity-without-containment)", async () => {
    await expect(
      apiKeysImplementations.create(
        { name: "scopeless-identity", acts_as_user_id: "target-user" },
        "admin-1",
        true,
      ),
    ).rejects.toMatchObject({ code: "BAD_REQUEST" });
    expect(repoMock.create).not.toHaveBeenCalled();
    expect(usersRepoMock.findById).not.toHaveBeenCalled();
  });

  it("rejects an acts-as binding to a nonexistent user with NOT_FOUND and no write", async () => {
    endpointsRepoMock.findByUuid.mockResolvedValue({ uuid: EP, name: "m365" });
    usersRepoMock.findById.mockResolvedValue(undefined);

    // Owner = acted-as user so the ownership invariant passes and the
    // existence check is genuinely the gate under test.
    await expect(
      apiKeysImplementations.create(
        {
          name: "dangling-identity",
          user_id: "no-such-user",
          endpoint_uuid: EP,
          acts_as_user_id: "no-such-user",
        },
        "admin-1",
        true,
      ),
    ).rejects.toMatchObject({ code: "NOT_FOUND" });
    expect(usersRepoMock.findById).toHaveBeenCalledWith("no-such-user");
    expect(repoMock.create).not.toHaveBeenCalled();
  });

  it("admin + endpoint scope + existing user + owned-by-the-acted-as-user: persists the binding", async () => {
    endpointsRepoMock.findByUuid.mockResolvedValue({ uuid: EP, name: "m365" });
    usersRepoMock.findById.mockResolvedValue({
      id: "target-user",
      email: "alex@example.com",
      name: "Alex",
    });
    repoMock.create.mockResolvedValue({
      uuid: "key-uuid",
      name: "sever-m365",
      key: "sk_mt_identityidentity",
      user_id: "target-user",
      endpoint_uuid: EP,
      acts_as_user_id: "target-user",
      created_at: new Date(),
    });

    await apiKeysImplementations.create(
      {
        name: "sever-m365",
        user_id: "target-user",
        endpoint_uuid: EP,
        acts_as_user_id: "target-user",
      },
      "admin-1",
      true,
    );

    expect(repoMock.create).toHaveBeenCalledWith({
      name: "sever-m365",
      user_id: "target-user",
      endpoint_uuid: EP,
      acts_as_user_id: "target-user",
      is_active: true,
    });
  });

  it("admin acting-as-self with implicit ownership (user_id omitted → owner = caller) passes", async () => {
    endpointsRepoMock.findByUuid.mockResolvedValue({ uuid: EP, name: "m365" });
    usersRepoMock.findById.mockResolvedValue({
      id: "admin-1",
      email: "admin@example.com",
      name: "Admin",
    });
    repoMock.create.mockResolvedValue({
      uuid: "key-uuid",
      name: "self-bound",
      key: "sk_mt_selfself",
      user_id: "admin-1",
      endpoint_uuid: EP,
      acts_as_user_id: "admin-1",
      created_at: new Date(),
    });

    await apiKeysImplementations.create(
      { name: "self-bound", endpoint_uuid: EP, acts_as_user_id: "admin-1" },
      "admin-1",
      true,
    );

    expect(repoMock.create).toHaveBeenCalledWith({
      name: "self-bound",
      user_id: "admin-1",
      endpoint_uuid: EP,
      acts_as_user_id: "admin-1",
      is_active: true,
    });
  });

  // Ownership invariant (round-2 HIGH): an identity-bound key must be OWNED
  // by the identity it exercises. Public keys' RAW values are listed to
  // every member (see the `list` doc comment in the impl), so a public
  // identity-bound key would be a fleet-distributed delegated Graph
  // credential; a foreign owner is the same hazard one hop removed.
  it("rejects a public ('everyone') identity-bound key with FORBIDDEN and no DB reads or writes", async () => {
    await expect(
      apiKeysImplementations.create(
        {
          name: "public-identity",
          user_id: null,
          endpoint_uuid: EP,
          acts_as_user_id: "target-user",
        },
        "admin-1",
        true,
      ),
    ).rejects.toMatchObject({ code: "FORBIDDEN" });
    expect(repoMock.create).not.toHaveBeenCalled();
    expect(usersRepoMock.findById).not.toHaveBeenCalled();
    expect(endpointsRepoMock.findByUuid).not.toHaveBeenCalled();
  });

  it("rejects a foreign-owned identity-bound key (owner ≠ acted-as user) with FORBIDDEN and no write", async () => {
    await expect(
      apiKeysImplementations.create(
        {
          name: "foreign-identity",
          user_id: "some-other-user",
          endpoint_uuid: EP,
          acts_as_user_id: "target-user",
        },
        "admin-1",
        true,
      ),
    ).rejects.toMatchObject({ code: "FORBIDDEN" });
    expect(repoMock.create).not.toHaveBeenCalled();
    expect(usersRepoMock.findById).not.toHaveBeenCalled();
  });

  it("rejects an implicit-owner (caller) create acting as SOMEONE ELSE with FORBIDDEN", async () => {
    await expect(
      apiKeysImplementations.create(
        {
          name: "admin-owned-acting-as-other",
          endpoint_uuid: EP,
          acts_as_user_id: "target-user",
        },
        "admin-1",
        true,
      ),
    ).rejects.toMatchObject({ code: "FORBIDDEN" });
    expect(repoMock.create).not.toHaveBeenCalled();
    expect(usersRepoMock.findById).not.toHaveBeenCalled();
  });

  it("a plain admin create (no acts_as) stores a NULL binding — fail-closed by default", async () => {
    endpointsRepoMock.findByUuid.mockResolvedValue({ uuid: EP, name: "m365" });
    repoMock.create.mockResolvedValue({
      uuid: "key-uuid",
      name: "plain",
      key: "sk_mt_plainplain",
      user_id: "admin-1",
      endpoint_uuid: EP,
      acts_as_user_id: null,
      created_at: new Date(),
    });

    await apiKeysImplementations.create(
      { name: "plain", endpoint_uuid: EP },
      "admin-1",
      true,
    );

    expect(repoMock.create).toHaveBeenCalledWith({
      name: "plain",
      user_id: "admin-1",
      endpoint_uuid: EP,
      acts_as_user_id: null,
      is_active: true,
    });
    expect(usersRepoMock.findById).not.toHaveBeenCalled();
  });
});

// Schema-level pins for the identity-requires-scope invariant — the same
// rule the impl enforces, rejected one layer earlier for tRPC callers.
describe("CreateApiKeyRequestSchema — acts-as pairing rules", () => {
  const EP = "11111111-1111-4111-8111-111111111111";

  it("accepts acts_as_user_id together with a single-endpoint scope", () => {
    const parsed = CreateApiKeyRequestSchema.safeParse({
      name: "bound",
      endpoint_uuid: EP,
      acts_as_user_id: "target-user",
    });
    expect(parsed.success).toBe(true);
  });

  it("rejects acts_as_user_id with all_endpoints: true", () => {
    const parsed = CreateApiKeyRequestSchema.safeParse({
      name: "bound",
      all_endpoints: true,
      acts_as_user_id: "target-user",
    });
    expect(parsed.success).toBe(false);
  });

  it("rejects acts_as_user_id with no scope selection", () => {
    const parsed = CreateApiKeyRequestSchema.safeParse({
      name: "bound",
      acts_as_user_id: "target-user",
    });
    expect(parsed.success).toBe(false);
  });

  // Ownership invariant, schema half: public and explicit-foreign owners
  // are rejected at parse time; owner = acted-as user passes; the implicit
  // owner (user_id omitted → caller) is checked by the impl instead.
  it("rejects acts_as_user_id on a public key (user_id: null)", () => {
    const parsed = CreateApiKeyRequestSchema.safeParse({
      name: "bound",
      user_id: null,
      endpoint_uuid: EP,
      acts_as_user_id: "target-user",
    });
    expect(parsed.success).toBe(false);
  });

  it("rejects acts_as_user_id when the explicit owner is a different user", () => {
    const parsed = CreateApiKeyRequestSchema.safeParse({
      name: "bound",
      user_id: "someone-else",
      endpoint_uuid: EP,
      acts_as_user_id: "target-user",
    });
    expect(parsed.success).toBe(false);
  });

  it("accepts acts_as_user_id when the explicit owner IS the acted-as user", () => {
    const parsed = CreateApiKeyRequestSchema.safeParse({
      name: "bound",
      user_id: "target-user",
      endpoint_uuid: EP,
      acts_as_user_id: "target-user",
    });
    expect(parsed.success).toBe(true);
  });
});

// A key's endpoint scope is immutable by omission: neither the update request
// schema nor the repo update-input schema carries endpoint_uuid, so even an
// admin cannot re-point an existing key at another endpoint through the app —
// the only path is delete + re-mint. These tests pin that the field stays out
// of the update surface (zod strips it as an unknown key).
describe("api-keys update — endpoint scope is immutable by omission", () => {
  it("UpdateApiKeyRequestSchema strips a smuggled endpoint_uuid", () => {
    const parsed = UpdateApiKeyRequestSchema.parse({
      uuid: "44444444-4444-4444-8444-444444444444",
      name: "renamed",
      endpoint_uuid: "11111111-1111-4111-8111-111111111111",
    });
    expect(parsed).not.toHaveProperty("endpoint_uuid");
  });

  it("ApiKeyUpdateInputSchema strips a smuggled endpoint_uuid", () => {
    const parsed = ApiKeyUpdateInputSchema.parse({
      name: "renamed",
      endpoint_uuid: "11111111-1111-4111-8111-111111111111",
    });
    expect(parsed).not.toHaveProperty("endpoint_uuid");
  });
});

// Same immutability-by-omission contract for the acts-as identity binding
// (migration 0024): a key's identity can never be re-pointed through the
// app — not even by an admin. Re-bind = delete + re-mint.
describe("api-keys update — acts-as identity is immutable by omission", () => {
  it("UpdateApiKeyRequestSchema strips a smuggled acts_as_user_id", () => {
    const parsed = UpdateApiKeyRequestSchema.parse({
      uuid: "44444444-4444-4444-8444-444444444444",
      name: "renamed",
      acts_as_user_id: "victim-user",
    });
    expect(parsed).not.toHaveProperty("acts_as_user_id");
  });

  it("ApiKeyUpdateInputSchema strips a smuggled acts_as_user_id", () => {
    const parsed = ApiKeyUpdateInputSchema.parse({
      name: "renamed",
      acts_as_user_id: "victim-user",
    });
    expect(parsed).not.toHaveProperty("acts_as_user_id");
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
        endpoint_uuid: "11111111-1111-4111-8111-111111111111",
        acts_as_user_id: "acted-as-user",
        acts_as_email: "acted-as@example.com",
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
        endpoint_uuid: null,
        acts_as_user_id: null,
        acts_as_email: null,
        owner_email: null,
      },
    ]);

    const result = await apiKeysImplementations.listAll();

    expect(result.apiKeys).toHaveLength(2);
    // The endpoint scope survives serialization: scoped key carries its
    // endpoint uuid, legacy key carries NULL (= all endpoints).
    expect(result.apiKeys[0].endpoint_uuid).toBe(
      "11111111-1111-4111-8111-111111111111",
    );
    expect(result.apiKeys[1].endpoint_uuid).toBeNull();
    // The acts-as identity binding survives serialization (id + email for
    // the bound key, NULLs for an unbound one).
    expect(result.apiKeys[0].acts_as_user_id).toBe("acted-as-user");
    expect(result.apiKeys[0].acts_as_email).toBe("acted-as@example.com");
    expect(result.apiKeys[1].acts_as_user_id).toBeNull();
    expect(result.apiKeys[1].acts_as_email).toBeNull();
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
