/**
 * Structural regression test for a BLOCKER finding from independent security
 * review (2026-07-14): `ApiKeysRepository.update()`/`delete()` previously
 * built their member-scoped ownership WHERE as
 * `or(eq(user_id, userId), isNull(user_id))` — the `isNull` branch also
 * matched PUBLIC ('everyone') keys, so any member holding a public key's
 * uuid (visible via their own `list` query) could deactivate or DELETE a key
 * every other consumer (n8n/Claude/other clients) authenticates with. The fix narrows
 * the member-scoped predicate to `eq(user_id, userId)` only; public keys are
 * now mutable exclusively through `updateAsAdmin`/`deleteAsAdmin`.
 *
 * Rather than asserting on a generated SQL string, this test spies on
 * drizzle-orm's REAL `or`/`isNull` combinators and asserts neither is
 * invoked when `update()`/`delete()` build their WHERE clause. As long as
 * that holds, the public-key bypass cannot exist — any future change that
 * reintroduces `or(eq(user_id, ...), isNull(user_id))` on the member path
 * fails this test immediately, regardless of how the surrounding code is
 * refactored.
 *
 * The DB layer itself is mocked (chain stubs) — same pattern as
 * mcp-sessions.repo.test.ts; this fork has no live-DB test harness.
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

const updateChain = {
  set: vi.fn().mockReturnThis(),
  where: vi.fn().mockReturnThis(),
  returning: vi.fn(),
};
const deleteChain = {
  where: vi.fn().mockReturnThis(),
  returning: vi.fn(),
};
// Select chain for validateApiKey's flat key lookup (the projection tests
// below): `.where()` resolves the row array directly, like drizzle does.
const selectChain = {
  from: vi.fn().mockReturnThis(),
  where: vi.fn(),
};

vi.mock("../index", () => ({
  db: {
    update: vi.fn(() => updateChain),
    delete: vi.fn(() => deleteChain),
    select: vi.fn(() => selectChain),
  },
}));

vi.mock("../schema", () => ({
  apiKeysTable: {
    uuid: { name: "uuid" },
    name: { name: "name" },
    key_hash: { name: "key_hash" },
    last4: { name: "last4" },
    user_id: { name: "user_id" },
    endpoint_uuid: { name: "endpoint_uuid" },
    acts_as_user_id: { name: "acts_as_user_id" },
    created_at: { name: "created_at" },
    is_active: { name: "is_active" },
    last_used_at: { name: "last_used_at" },
  },
  usersTable: {
    id: { name: "id" },
    email: { name: "email" },
  },
}));

// Spy on the REAL drizzle-orm combinators (not stubbed out) so the assertion
// is "isNull/or were never invoked", not "a mock returned some value". `eq` is
// wrapped the same way so the authentication lookup's predicate can be
// inspected — see the hashed-lookup suite at the bottom.
vi.mock("drizzle-orm", async (importOriginal) => {
  const actual = await importOriginal<typeof import("drizzle-orm")>();
  return {
    ...actual,
    or: vi.fn(actual.or),
    isNull: vi.fn(actual.isNull),
    eq: vi.fn(actual.eq),
  };
});

import { eq, isNull, or } from "drizzle-orm";

import { hashApiKey } from "@/lib/api-key-hash";

import { ApiKeysRepository } from "./api-keys.repo";

describe("ApiKeysRepository member-scoped update/delete — public key isolation", () => {
  const repo = new ApiKeysRepository();

  beforeEach(() => {
    vi.clearAllMocks();
    updateChain.returning.mockResolvedValue([
      {
        uuid: "k1",
        name: "x",
        last4: "aaaa",
        created_at: new Date(),
        is_active: false,
      },
    ]);
    deleteChain.returning.mockResolvedValue([{ uuid: "k1", name: "x" }]);
  });

  it("update() never calls isNull() or or() — a public-key bypass cannot exist", async () => {
    await repo.update("k1", "member-1", { is_active: false });

    expect(isNull).not.toHaveBeenCalled();
    expect(or).not.toHaveBeenCalled();
  });

  it("delete() never calls isNull() or or() — a public-key bypass cannot exist", async () => {
    await repo.delete("k1", "member-1");

    expect(isNull).not.toHaveBeenCalled();
    expect(or).not.toHaveBeenCalled();
  });

  it("updateAsAdmin()/deleteAsAdmin() stay uuid-only (no isNull/or either) — admin can still reach a public key", async () => {
    await repo.updateAsAdmin("k1", { is_active: false });
    await repo.deleteAsAdmin("k1");

    expect(isNull).not.toHaveBeenCalled();
    expect(or).not.toHaveBeenCalled();
  });
});

// validateApiKey is the SINGLE lookup every api-key-authenticated request
// funnels through; checkApiKeyAccess (endpoint scope) and the streamable-http
// m365 context gate (acts-as identity, migration 0024) can only enforce what
// this projection actually returns. These tests pin that both columns are
// selected and passed through — dropping either from the select would
// silently disable its downstream gate.
describe("ApiKeysRepository.validateApiKey — scope + acts-as projection", () => {
  const repo = new ApiKeysRepository();

  it("selects and returns endpoint_uuid + acts_as_user_id for a bound key", async () => {
    selectChain.where.mockResolvedValueOnce([
      {
        uuid: "key-uuid-1",
        user_id: "owner-1",
        endpoint_uuid: "ep-uuid-1",
        acts_as_user_id: "acted-as-user-1",
        is_active: true,
        // Fresh stamp so the fire-and-forget last-used touch stays inert.
        last_used_at: new Date(),
      },
    ]);

    const result = await repo.validateApiKey("sk_mt_bound");

    expect(result).toEqual({
      valid: true,
      user_id: "owner-1",
      key_uuid: "key-uuid-1",
      endpoint_uuid: "ep-uuid-1",
      acts_as_user_id: "acted-as-user-1",
    });
    // The projection itself names both columns — a dropped select can't
    // masquerade as a NULL-bound key.
    const dbModule = await import("../index");
    const projection = (dbModule.db.select as ReturnType<typeof vi.fn>).mock
      .calls[0][0];
    expect(projection).toHaveProperty("endpoint_uuid");
    expect(projection).toHaveProperty("acts_as_user_id");
  });

  it("returns NULL acts_as_user_id for an unbound key (m365 injection fail-closes downstream)", async () => {
    selectChain.where.mockResolvedValueOnce([
      {
        uuid: "key-uuid-2",
        user_id: null,
        endpoint_uuid: null,
        acts_as_user_id: null,
        is_active: true,
        last_used_at: new Date(),
      },
    ]);

    const result = await repo.validateApiKey("sk_mt_unbound");

    expect(result.valid).toBe(true);
    expect(result.acts_as_user_id).toBeNull();
    expect(result.endpoint_uuid).toBeNull();
  });

  it("an inactive key stays invalid with no fields leaked", async () => {
    selectChain.where.mockResolvedValueOnce([
      {
        uuid: "key-uuid-3",
        user_id: "owner-1",
        endpoint_uuid: "ep-uuid-1",
        acts_as_user_id: "acted-as-user-1",
        is_active: false,
        last_used_at: new Date(),
      },
    ]);

    const result = await repo.validateApiKey("sk_mt_inactive");

    expect(result).toEqual({ valid: false });
  });

  it("refuses an ADMIN-PLANE key as not-valid, flagging the wrong plane (migration 0038)", async () => {
    // The plane rule lives HERE so every data-plane surface that resolves a key
    // through validateApiKey refuses a control-plane key. It reports the wrong
    // plane distinctly (admin_plane: true + key_uuid) so the MCP branches can
    // name the refusal. `last_used_at` is a fresh stamp, so the fire-and-forget
    // touch would be inert anyway; the returned shape is what proves the reject.
    selectChain.where.mockResolvedValueOnce([
      {
        uuid: "key-uuid-cp",
        user_id: "ci-user",
        endpoint_uuid: null,
        acts_as_user_id: null,
        is_active: true,
        admin_plane: true,
        last_used_at: new Date(),
      },
    ]);

    const result = await repo.validateApiKey("sk_mt_admin_plane");

    expect(result).toEqual({
      valid: false,
      admin_plane: true,
      key_uuid: "key-uuid-cp",
    });
  });
});

// Migration 0034: the table stores sha256(key), not the key. If the lookup
// ever compared the presented value against the stored digest directly — or
// normalised the presented value on the way in — every key on the gateway
// would stop authenticating at once, with a 401 rather than an error to say
// why. These tests pin the predicate itself, not just the returned row, so
// the failure surfaces here instead of in production auth.
describe("ApiKeysRepository.validateApiKey — the lookup is by HASH, not by key", () => {
  const repo = new ApiKeysRepository();

  beforeEach(() => {
    vi.clearAllMocks();
    selectChain.where.mockResolvedValue([]);
  });

  it("matches on the key_hash column using the sha256 of the presented value", async () => {
    const presented = `sk_mt_${"d".repeat(64)}`;

    await repo.validateApiKey(presented);

    expect(eq).toHaveBeenCalledWith(
      { name: "key_hash" },
      hashApiKey(presented),
    );
  });

  it("never puts the presented key itself into the predicate", async () => {
    const presented = `sk_mt_${"e".repeat(64)}`;

    await repo.validateApiKey(presented);

    const eqArgs = (
      eq as unknown as ReturnType<typeof vi.fn>
    ).mock.calls.flat();
    expect(eqArgs).not.toContain(presented);
    // …and no column other than key_hash is compared on this path, so a
    // lingering plaintext column could not be reintroduced as the matcher.
    expect(eqArgs).not.toContainEqual({ name: "key" });
  });

  it("hashes the presented value EXACTLY as received — no trimming, no case folding", async () => {
    // The middleware passes the x-api-key header raw while the OAuth
    // introspection route trims it. That asymmetry decides which
    // whitespace-padded credentials authenticate, and it is the callers' to
    // own: normalising here would silently change the answer for both.
    const padded = "  sk_mt_padded  ";

    await repo.validateApiKey(padded);

    expect(eq).toHaveBeenCalledWith({ name: "key_hash" }, hashApiKey(padded));
    expect(eq).not.toHaveBeenCalledWith(
      { name: "key_hash" },
      hashApiKey(padded.trim()),
    );
  });
});
