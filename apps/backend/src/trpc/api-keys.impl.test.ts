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
 *  - the member-facing listing (list) drops the full secret for EVERY key,
 *    public keys included (security review fix),
 *  - the admin cross-user listing (listAll) drops the full secret and carries
 *    owner email + last_used_at,
 *  - update/delete route to the owner-scoped repo methods for members and the
 *    ownership-bypass methods for admins,
 *  - the update readback drops the full secret and carries only a prefix
 *    (security review fix), on BOTH the admin and the member branch,
 *  - `validate` refuses a key whose OWNER is disabled (migration 0027), and
 *    equally one whose acts-as identity is disabled, while a public/service
 *    key (user_id NULL) and an unscoped key's inert binding are unaffected.
 *
 * The repository is mocked (its barrel reaches db/index, which needs a live
 * DATABASE_URL); the real serializer is used so the response shaping is
 * exercised too. The repository's own ownership WHERE clauses are verified by
 * code review — there is no live-DB test harness in this fork.
 */

import {
  ApiKeyUpdateInputSchema,
  CreateApiKeyRequestSchema,
  ListApiKeysResponseSchema,
  UpdateApiKeyRequestSchema,
  UpdateApiKeyResponseSchema,
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
// verify an acts-as identity target exists (migration 0024) and to check
// whether a validated key's owner is disabled (migration 0027).
const { repoMock, endpointsRepoMock, usersRepoMock } = vi.hoisted(() => ({
  repoMock: {
    create: vi.fn(),
    findAll: vi.fn(),
    findAccessibleToUser: vi.fn(),
    update: vi.fn(),
    updateAsAdmin: vi.fn(),
    delete: vi.fn(),
    deleteAsAdmin: vi.fn(),
    validateApiKey: vi.fn(),
  },
  endpointsRepoMock: {
    findByUuid: vi.fn(),
  },
  usersRepoMock: {
    findById: vi.fn(),
    isDisabled: vi.fn(),
    // Owner-must-be-admin at admin-plane mint (migration 0038) reads the
    // effective owner's role through this.
    findRoleById: vi.fn(),
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
    validateApiKey = repoMock.validateApiKey;
  },
  endpointsRepository: endpointsRepoMock,
  usersRepository: usersRepoMock,
}));

// lib/api-key-identity deliberately needs no mock: the impl's disabled-identity
// gate resolves an acts-as binding through the REAL resolveActsAsUserId, the
// same pure function the data-plane middleware runs, so the two planes cannot
// drift on the identity-requires-scope pairing (migration 0024).
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
      admin_plane: false,
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
      admin_plane: false,
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
      admin_plane: false,
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
      admin_plane: false,
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
      admin_plane: false,
      is_active: true,
    });
  });

  // Ownership invariant (round-2 HIGH): an identity-bound key must be OWNED
  // by the identity it exercises. A public key exists to be handed to every
  // consumer, so a public identity-bound key would be a fleet-distributed
  // delegated Graph credential; a foreign owner is the same hazard one hop
  // removed.
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
      admin_plane: false,
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

// Security review fix (CRITICAL). `list` is a plain protectedProcedure and
// findAccessibleToUser deliberately returns the caller's own keys PLUS every
// public ('everyone') key — so when the serializer emitted `key` raw, any
// self-registered member could read the gateway-wide production keys in
// plaintext. Three live keys were recovered that way. These tests pin the
// masking at BOTH layers that stand between the DB row and the wire: the
// serializer, and the tRPC `.output()` schema.
describe("api-keys list — member view never returns a usable secret", () => {
  // Realistic shapes: sk_mt_ + 64 hex, the bootstrap generator's format.
  const PUBLIC_KEY = `sk_mt_${"a".repeat(64)}`;
  const PRIVATE_KEY = `sk_mt_${"b".repeat(64)}`;
  const EP = "11111111-1111-4111-8111-111111111111";

  // The repository no longer selects a key column at all (migration 0034);
  // `last4` is the stored display tail, and it is all the serializer gets.
  const accessibleRows = [
    {
      uuid: "pub-1",
      name: "gateway-wide shared",
      last4: PUBLIC_KEY.slice(-4),
      created_at: new Date("2026-07-01T00:00:00Z"),
      is_active: true,
      user_id: null, // public / 'everyone' — the leaked class
      endpoint_uuid: null,
      acts_as_user_id: null,
    },
    {
      uuid: "priv-1",
      name: "my own key",
      last4: PRIVATE_KEY.slice(-4),
      created_at: new Date("2026-07-02T00:00:00Z"),
      is_active: true,
      user_id: "member-1",
      endpoint_uuid: EP,
      acts_as_user_id: "member-1",
    },
  ];

  it("returns a prefix instead of the raw value for public AND private keys", async () => {
    repoMock.findAccessibleToUser.mockResolvedValue(accessibleRows);

    const result = await apiKeysImplementations.list("member-1");

    expect(result.apiKeys).toHaveLength(2);
    for (const row of result.apiKeys) {
      // The old field is gone entirely, not merely overwritten.
      expect((row as Record<string, unknown>).key).toBeUndefined();
      // Scheme tag, elision marker, 4 stored characters — nothing more.
      expect(row.key_prefix).toMatch(/^sk_mt_…[a-z0-9]{4}$/);
    }
  });

  it("carries NO full-length sk_mt_ token anywhere in the response payload", async () => {
    repoMock.findAccessibleToUser.mockResolvedValue(accessibleRows);

    const result = await apiKeysImplementations.list("member-1");

    // Serialize the whole response and hunt for a usable key in ANY field —
    // this is the assertion that stays true no matter which field a future
    // regression smuggles the secret through. `sk_mt_` + 16 chars is far
    // longer than the 4 characters a prefix exposes and far shorter than a
    // real key, so it fires on a leak and never on a legitimate prefix.
    const payload = JSON.stringify(result);
    expect(payload).not.toMatch(/sk_mt_[A-Za-z0-9_-]{16,}/);
    expect(payload).not.toContain(PUBLIC_KEY);
    expect(payload).not.toContain(PRIVATE_KEY);
  });

  it("exposes only a strict, non-reversible identifier for each key", async () => {
    repoMock.findAccessibleToUser.mockResolvedValue(accessibleRows);

    const result = await apiKeysImplementations.list("member-1");

    expect(result.apiKeys[0].key_prefix).toBe("sk_mt_…aaaa");
    expect(result.apiKeys[1].key_prefix).toBe("sk_mt_…bbbb");
    // The visible characters must be a genuine tail of the original, not a
    // rename — and far shorter than the key itself.
    expect(PUBLIC_KEY.endsWith(result.apiKeys[0].key_prefix.slice(-4))).toBe(
      true,
    );
    expect(result.apiKeys[0].key_prefix.length).toBeLessThan(PUBLIC_KEY.length);
  });

  it("still returns the non-secret fields the key list is for", async () => {
    repoMock.findAccessibleToUser.mockResolvedValue(accessibleRows);

    const result = await apiKeysImplementations.list("member-1");

    expect(result.apiKeys[0]).toMatchObject({
      uuid: "pub-1",
      name: "gateway-wide shared",
      is_active: true,
      user_id: null,
      endpoint_uuid: null,
      acts_as_user_id: null,
    });
    expect(result.apiKeys[1]).toMatchObject({
      uuid: "priv-1",
      user_id: "member-1",
      endpoint_uuid: EP,
      acts_as_user_id: "member-1",
    });
    expect(repoMock.findAccessibleToUser).toHaveBeenCalledWith("member-1");
  });

  // Second layer: the tRPC router declares this schema as `.output()`, so a
  // serializer that regressed and re-added `key` would still have it stripped
  // before the response leaves the server. Zod objects strip unknown keys.
  it("ListApiKeysResponseSchema strips a smuggled full key value", () => {
    const parsed = ListApiKeysResponseSchema.parse({
      apiKeys: [
        {
          uuid: "44444444-4444-4444-8444-444444444444",
          name: "regressed",
          key: PUBLIC_KEY,
          key_prefix: "sk_mt_…aaaa",
          created_at: new Date(),
          is_active: true,
          user_id: null,
          endpoint_uuid: null,
          acts_as_user_id: null,
        },
      ],
    });

    expect(parsed.apiKeys[0]).not.toHaveProperty("key");
    expect(JSON.stringify(parsed)).not.toContain(PUBLIC_KEY);
  });
});

describe("api-keys listAll — admin cross-user view", () => {
  it("returns every key with owner email + last_used, and never the full secret", async () => {
    repoMock.findAll.mockResolvedValue([
      {
        uuid: "1",
        name: "alice-key",
        last4: "AAAA",
        created_at: new Date("2026-07-01T00:00:00Z"),
        last_used_at: null,
        is_active: true,
        user_id: "alice",
        endpoint_uuid: "11111111-1111-4111-8111-111111111111",
        acts_as_user_id: "acted-as-user",
        acts_as_email: "acted-as@example.com",
        owner_email: "alice@example.com",
        admin_plane: false,
      },
      {
        uuid: "2",
        name: "public-key",
        last4: "BBBB",
        created_at: new Date("2026-07-02T00:00:00Z"),
        last_used_at: new Date("2026-07-10T00:00:00Z"),
        is_active: false,
        user_id: null,
        endpoint_uuid: null,
        acts_as_user_id: null,
        acts_as_email: null,
        owner_email: null,
        admin_plane: false,
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
    // The full secret must NOT leak; only a non-reversible identifier built
    // from the stored tail is exposed.
    expect((result.apiKeys[0] as Record<string, unknown>).key).toBeUndefined();
    expect(result.apiKeys[0].key_prefix).toBe("sk_mt_…AAAA");
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
      last4: "keyx",
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
      last4: "keyx",
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

// Security review fix. `update` is a plain protectedProcedure — a member may
// rename or revoke their OWN key through it, an admin any key — and the
// readback used to carry `key` raw. That re-disclosed on every rename a
// secret the design shows exactly once, at mint time. These tests pin the
// masking on BOTH repo branches (owner-scoped and admin bypass) and at the
// tRPC `.output()` schema, the two layers between the DB row and the wire.
describe("api-keys update — readback never returns a usable secret", () => {
  // Realistic shape: sk_mt_ + 64 chars, the generator's format.
  const RAW_KEY = `sk_mt_${"c".repeat(64)}`;

  // The readback selects `last4`, not a key — there is no key column left to
  // select (migration 0034).
  const updatedRow = {
    uuid: "k",
    name: "renamed",
    last4: RAW_KEY.slice(-4),
    created_at: new Date("2026-07-03T00:00:00Z"),
    is_active: false,
  };

  it("admin branch (updateAsAdmin) returns a prefix instead of the raw value", async () => {
    repoMock.updateAsAdmin.mockResolvedValue(updatedRow);

    const result = await apiKeysImplementations.update(
      { uuid: "k", is_active: false },
      "admin-1",
      true,
    );

    // The old field is gone entirely, not merely overwritten.
    expect((result as Record<string, unknown>).key).toBeUndefined();
    expect(result.key_prefix).toBe("sk_mt_…cccc");
  });

  it("member branch (update) returns a prefix instead of the raw value", async () => {
    repoMock.update.mockResolvedValue(updatedRow);

    const result = await apiKeysImplementations.update(
      { uuid: "k", name: "renamed" },
      "member-1",
      false,
    );

    expect((result as Record<string, unknown>).key).toBeUndefined();
    expect(result.key_prefix).toBe("sk_mt_…cccc");
  });

  it("carries NO full-length sk_mt_ token anywhere in either branch's payload", async () => {
    repoMock.updateAsAdmin.mockResolvedValue(updatedRow);
    repoMock.update.mockResolvedValue(updatedRow);

    // Same whole-payload hunt the list tests use: this assertion stays true no
    // matter which field a future regression smuggles the secret through.
    // `sk_mt_` + 16 chars is far longer than the 4 characters a prefix exposes
    // and far shorter than a real key, so it fires on a leak and never on a
    // legitimate prefix.
    for (const isAdmin of [true, false]) {
      const payload = JSON.stringify(
        await apiKeysImplementations.update(
          { uuid: "k", is_active: false },
          isAdmin ? "admin-1" : "member-1",
          isAdmin,
        ),
      );
      expect(payload).not.toMatch(/sk_mt_[A-Za-z0-9_-]{16,}/);
      expect(payload).not.toContain(RAW_KEY);
    }
  });

  it("still returns the non-secret fields the readback is for", async () => {
    repoMock.updateAsAdmin.mockResolvedValue(updatedRow);

    const result = await apiKeysImplementations.update(
      { uuid: "k", is_active: false },
      "admin-1",
      true,
    );

    expect(result).toMatchObject({
      uuid: "k",
      name: "renamed",
      created_at: new Date("2026-07-03T00:00:00Z"),
      is_active: false,
    });
    // The visible characters must be a genuine tail of the original, not a
    // rename.
    expect(RAW_KEY.endsWith(result.key_prefix.slice(-4))).toBe(true);
    expect(result.key_prefix.length).toBeLessThan(RAW_KEY.length);
  });

  // Second layer: the tRPC router declares this schema as `.output()`, so a
  // serializer that regressed and re-added `key` would still have it stripped
  // before the response leaves the server. Zod objects strip unknown keys.
  it("UpdateApiKeyResponseSchema strips a smuggled full key value", () => {
    const parsed = UpdateApiKeyResponseSchema.parse({
      uuid: "44444444-4444-4444-8444-444444444444",
      name: "regressed",
      key: RAW_KEY,
      key_prefix: "sk_mt_…cccc",
      created_at: new Date(),
      is_active: true,
    });

    expect(parsed).not.toHaveProperty("key");
    expect(JSON.stringify(parsed)).not.toContain(RAW_KEY);
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
      last4: "keyx",
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

// Migration 0027 consistency. The DATA plane already refuses a disabled
// owner's key — the api-key/OAuth middleware wraps validateApiKey in
// findDisabledIdentity and answers 403 with an account_disabled audit event
// (see middleware/api-key-disabled-account.test.ts) — but this procedure kept
// answering "valid" for the same credential. Nothing authenticates through
// it, so the gap is a low-severity oracle inconsistency rather than an
// authentication bypass; the fix lives here, in the cold path, precisely so
// the middleware's containment response and its audit event stay intact.
describe("api-keys validate — owner-disabled gate", () => {
  const OWNED_KEY = `sk_mt_${"d".repeat(64)}`;
  const PUBLIC_KEY = `sk_mt_${"e".repeat(64)}`;

  it("reports an active key as valid when its owner is enabled", async () => {
    repoMock.validateApiKey.mockResolvedValue({
      valid: true,
      user_id: "owner-1",
      key_uuid: "key-1",
    });
    usersRepoMock.isDisabled.mockResolvedValue(false);

    const result = await apiKeysImplementations.validate({ key: OWNED_KEY });

    expect(result).toEqual({
      valid: true,
      user_id: "owner-1",
      key_uuid: "key-1",
    });
    expect(usersRepoMock.isDisabled).toHaveBeenCalledWith("owner-1");
  });

  it("reports a disabled owner's key as not-valid, with no identifying detail", async () => {
    repoMock.validateApiKey.mockResolvedValue({
      valid: true,
      user_id: "owner-1",
      key_uuid: "key-1",
    });
    usersRepoMock.isDisabled.mockResolvedValue(true);

    const result = await apiKeysImplementations.validate({ key: OWNED_KEY });

    // Indistinguishable from a key that does not exist — echoing user_id or
    // key_uuid alongside valid: false would widen the oracle this procedure
    // already is.
    expect(result).toEqual({ valid: false });
    expect(usersRepoMock.isDisabled).toHaveBeenCalledWith("owner-1");
  });

  it("skips the owner check for a public/service key (user_id NULL) and still reports valid", async () => {
    repoMock.validateApiKey.mockResolvedValue({
      valid: true,
      user_id: null,
      key_uuid: "key-pub",
    });
    // Deliberately armed to answer "disabled" for ANY id. isDisabled must
    // never be reached on this path, and arming it is what makes the test
    // bite: with a bare vi.fn() (resolving undefined) dropping the NULL-owner
    // guard would still leave the key reported valid, so the regression this
    // test exists to catch would pass unnoticed.
    usersRepoMock.isDisabled.mockResolvedValue(true);

    const result = await apiKeysImplementations.validate({ key: PUBLIC_KEY });

    // A public key has no owner to disable. isDisabled(undefined) would match
    // no row and fail CLOSED, silently invalidating every public key — so the
    // skip is load-bearing, not an optimisation.
    expect(result).toEqual({ valid: true, key_uuid: "key-pub" });
    expect(usersRepoMock.isDisabled).not.toHaveBeenCalled();
  });

  it("does not look up an owner for a key that failed validation", async () => {
    repoMock.validateApiKey.mockResolvedValue({ valid: false });

    const result = await apiKeysImplementations.validate({
      key: "sk_mt_not-a-real-key",
    });

    expect(result.valid).toBe(false);
    expect(usersRepoMock.isDisabled).not.toHaveBeenCalled();
  });

  it("fails closed when the owner lookup itself throws", async () => {
    repoMock.validateApiKey.mockResolvedValue({
      valid: true,
      user_id: "owner-1",
      key_uuid: "key-1",
    });
    usersRepoMock.isDisabled.mockRejectedValue(
      new Error("database unreachable"),
    );

    const result = await apiKeysImplementations.validate({ key: OWNED_KEY });

    expect(result).toEqual({ valid: false });
  });
});

// The other half of the parity: the data plane refuses on
// findDisabledIdentity([user_id, actsAsUserId]) — BOTH legs — so checking only
// the owner here left an enabled admin's acts-as key still reported "valid"
// while impersonating an account that was just locked out, which is exactly
// the containment case migration 0027 was written for. Resolution goes
// through the middleware's own resolveActsAsUserId so the
// identity-requires-scope pairing (migration 0024) reads the same on both
// planes.
describe("api-keys validate — acts-as identity disabled gate", () => {
  const ACTS_AS_KEY = `sk_mt_${"f".repeat(64)}`;
  const ENDPOINT_UUID = "11111111-1111-4111-8111-111111111111";

  it("reports an admin's acts-as key not-valid when the impersonated identity is disabled", async () => {
    repoMock.validateApiKey.mockResolvedValue({
      valid: true,
      user_id: "admin-owner",
      key_uuid: "key-actsas",
      endpoint_uuid: ENDPOINT_UUID,
      acts_as_user_id: "locked-victim",
    });
    // The owner is a perfectly healthy admin; only the identity the key acts
    // as is locked out.
    usersRepoMock.isDisabled.mockImplementation(
      async (userId: string) => userId === "locked-victim",
    );

    const result = await apiKeysImplementations.validate({ key: ACTS_AS_KEY });

    // Same bare not-valid as the owner leg: which of the two identities is
    // disabled is not disclosed.
    expect(result).toEqual({ valid: false });
    expect(usersRepoMock.isDisabled).toHaveBeenCalledWith("admin-owner");
    expect(usersRepoMock.isDisabled).toHaveBeenCalledWith("locked-victim");
  });

  it("reports the same key valid when both identities are enabled, without echoing the binding", async () => {
    repoMock.validateApiKey.mockResolvedValue({
      valid: true,
      user_id: "admin-owner",
      key_uuid: "key-actsas",
      endpoint_uuid: ENDPOINT_UUID,
      acts_as_user_id: "delegate-1",
    });
    usersRepoMock.isDisabled.mockResolvedValue(false);

    const result = await apiKeysImplementations.validate({ key: ACTS_AS_KEY });

    // acts_as_user_id and endpoint_uuid stay server-side for the same reason
    // scope does: this procedure is a key oracle any member can call.
    expect(result).toEqual({
      valid: true,
      user_id: "admin-owner",
      key_uuid: "key-actsas",
    });
    expect(usersRepoMock.isDisabled).toHaveBeenCalledWith("delegate-1");
  });

  it("ignores an acts-as binding on an unscoped key, matching the data plane", async () => {
    repoMock.validateApiKey.mockResolvedValue({
      valid: true,
      user_id: "admin-owner",
      key_uuid: "key-unscoped",
      // Unscoped row that still carries a binding — the shape migration 0024's
      // CHECK forbids but psql / admin_cli can still write. resolveActsAsUserId
      // fail-closes it to undefined on BOTH planes, so the binding is inert
      // here too and a locked-out delegate does not invalidate the key.
      endpoint_uuid: null,
      acts_as_user_id: "locked-victim",
    });
    usersRepoMock.isDisabled.mockImplementation(
      async (userId: string) => userId === "locked-victim",
    );

    const result = await apiKeysImplementations.validate({ key: ACTS_AS_KEY });

    expect(result).toEqual({
      valid: true,
      user_id: "admin-owner",
      key_uuid: "key-unscoped",
    });
    expect(usersRepoMock.isDisabled).toHaveBeenCalledWith("admin-owner");
    expect(usersRepoMock.isDisabled).not.toHaveBeenCalledWith("locked-victim");
  });
});

describe("api-keys create — admin-plane (control-plane) mint policy (migration 0038)", () => {
  const EP = "11111111-1111-4111-8111-111111111111";

  it("lets an admin mint an admin-plane key owned by an admin (no scope, no acts-as)", async () => {
    usersRepoMock.findRoleById.mockResolvedValue("admin");
    repoMock.create.mockResolvedValue({
      uuid: "cp-uuid",
      name: "ci",
      key: "sk_mt_controlplanekey",
      user_id: "admin-1",
      endpoint_uuid: null,
      created_at: new Date(),
    });

    await apiKeysImplementations.create(
      { name: "ci", admin_plane: true },
      "admin-1",
      true,
    );

    // The mandatory-scope gate is relaxed for a control-plane key, and it is
    // persisted with no scope and no acts-as identity.
    expect(repoMock.create).toHaveBeenCalledWith({
      name: "ci",
      user_id: "admin-1",
      endpoint_uuid: null,
      acts_as_user_id: null,
      admin_plane: true,
      is_active: true,
    });
  });

  it("rejects a MEMBER minting an admin-plane key with FORBIDDEN and no write", async () => {
    await expect(
      apiKeysImplementations.create(
        { name: "ci", admin_plane: true },
        "member-1",
        false,
      ),
    ).rejects.toMatchObject({ code: "FORBIDDEN" });
    expect(repoMock.create).not.toHaveBeenCalled();
  });

  it("rejects an admin-plane key paired with endpoint_uuid", async () => {
    await expect(
      apiKeysImplementations.create(
        { name: "ci", admin_plane: true, endpoint_uuid: EP },
        "admin-1",
        true,
      ),
    ).rejects.toMatchObject({ code: "BAD_REQUEST" });
    expect(repoMock.create).not.toHaveBeenCalled();
  });

  it("rejects an admin-plane key paired with all_endpoints", async () => {
    await expect(
      apiKeysImplementations.create(
        { name: "ci", admin_plane: true, all_endpoints: true },
        "admin-1",
        true,
      ),
    ).rejects.toMatchObject({ code: "BAD_REQUEST" });
    expect(repoMock.create).not.toHaveBeenCalled();
  });

  it("rejects an admin-plane key paired with acts_as_user_id", async () => {
    await expect(
      apiKeysImplementations.create(
        { name: "ci", admin_plane: true, acts_as_user_id: "someone" },
        "admin-1",
        true,
      ),
    ).rejects.toMatchObject({ code: "BAD_REQUEST" });
    expect(repoMock.create).not.toHaveBeenCalled();
  });

  it("rejects an admin-plane key whose OWNER is not an admin (owner-must-be-admin)", async () => {
    usersRepoMock.findRoleById.mockResolvedValue("member");
    await expect(
      apiKeysImplementations.create(
        { name: "ci", admin_plane: true, user_id: "member-owner" },
        "admin-1",
        true,
      ),
    ).rejects.toMatchObject({ code: "FORBIDDEN" });
    expect(usersRepoMock.findRoleById).toHaveBeenCalledWith("member-owner");
    expect(repoMock.create).not.toHaveBeenCalled();
  });

  it("rejects a public ('everyone') admin-plane key with FORBIDDEN and no write", async () => {
    await expect(
      apiKeysImplementations.create(
        { name: "ci", admin_plane: true, user_id: null },
        "admin-1",
        true,
      ),
    ).rejects.toMatchObject({ code: "FORBIDDEN" });
    expect(repoMock.create).not.toHaveBeenCalled();
  });

  it("records admin_plane in the create audit detail path (mint succeeds)", async () => {
    // The audit event is fire-and-forget; this asserts the mint completes and
    // persists the flag, which is what the audit detail is built from.
    usersRepoMock.findRoleById.mockResolvedValue("admin");
    repoMock.create.mockResolvedValue({
      uuid: "cp-uuid-2",
      name: "ci2",
      key: "sk_mt_cp2",
      user_id: "admin-1",
      endpoint_uuid: null,
      created_at: new Date(),
    });

    const result = await apiKeysImplementations.create(
      { name: "ci2", admin_plane: true },
      "admin-1",
      true,
    );
    expect(result.key).toBe("sk_mt_cp2");
  });
});

describe("api-keys — admin_plane is immutable through update", () => {
  it("the update schemas do not carry admin_plane at all", () => {
    // Immutability by omission, the same guard acts-as and endpoint scope use:
    // a smuggled field is stripped by the schema, so a data-plane key can never
    // be silently promoted to control-plane through an update.
    const parsed = UpdateApiKeyRequestSchema.parse({
      uuid: "22222222-2222-4222-8222-222222222222",
      name: "renamed",
      admin_plane: true,
    } as Record<string, unknown>);
    expect(parsed).not.toHaveProperty("admin_plane");

    const repoParsed = ApiKeyUpdateInputSchema.parse({
      name: "renamed",
      admin_plane: true,
    } as Record<string, unknown>);
    expect(repoParsed).not.toHaveProperty("admin_plane");
  });
});

describe("api-keys listAll — admin_plane surfaced (migration 0038)", () => {
  it("labels a control-plane key and a data-plane key distinctly", async () => {
    repoMock.findAll.mockResolvedValue([
      {
        uuid: "cp",
        name: "ci-control-plane",
        last4: "CCCC",
        created_at: new Date("2026-08-01T00:00:00Z"),
        last_used_at: null,
        is_active: true,
        user_id: "ci-user",
        endpoint_uuid: null,
        acts_as_user_id: null,
        acts_as_email: null,
        owner_email: "ci@example.com",
        admin_plane: true,
      },
      {
        uuid: "dp",
        name: "data-plane",
        last4: "DDDD",
        created_at: new Date("2026-08-02T00:00:00Z"),
        last_used_at: null,
        is_active: true,
        user_id: "alice",
        endpoint_uuid: "11111111-1111-4111-8111-111111111111",
        acts_as_user_id: null,
        acts_as_email: null,
        owner_email: "alice@example.com",
        admin_plane: false,
      },
    ]);

    const result = await apiKeysImplementations.listAll();

    expect(result.apiKeys[0].admin_plane).toBe(true);
    expect(result.apiKeys[1].admin_plane).toBe(false);
    // The flag is a boolean, never credential material.
    expect((result.apiKeys[0] as Record<string, unknown>).key).toBeUndefined();
  });
});
