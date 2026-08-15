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
    key: { name: "key" },
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
// is "isNull/or were never invoked", not "a mock returned some value".
vi.mock("drizzle-orm", async (importOriginal) => {
  const actual = await importOriginal<typeof import("drizzle-orm")>();
  return { ...actual, or: vi.fn(actual.or), isNull: vi.fn(actual.isNull) };
});

import { isNull, or } from "drizzle-orm";

import { ApiKeysRepository } from "./api-keys.repo";

describe("ApiKeysRepository member-scoped update/delete — public key isolation", () => {
  const repo = new ApiKeysRepository();

  beforeEach(() => {
    vi.clearAllMocks();
    updateChain.returning.mockResolvedValue([
      {
        uuid: "k1",
        name: "x",
        key: "sk_mt_x",
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
});
