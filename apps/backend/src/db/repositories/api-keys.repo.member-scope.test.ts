/**
 * Structural regression test for a BLOCKER finding from independent security
 * review (2026-07-14): `ApiKeysRepository.update()`/`delete()` previously
 * built their member-scoped ownership WHERE as
 * `or(eq(user_id, userId), isNull(user_id))` — the `isNull` branch also
 * matched PUBLIC ('everyone') keys, so any member holding a public key's
 * uuid (visible via their own `list` query) could deactivate or DELETE a key
 * every other consumer (Tara/n8n/Claude) authenticates with. The fix narrows
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

vi.mock("../index", () => ({
  db: {
    update: vi.fn(() => updateChain),
    delete: vi.fn(() => deleteChain),
  },
}));

vi.mock("../schema", () => ({
  apiKeysTable: {
    uuid: { name: "uuid" },
    name: { name: "name" },
    key: { name: "key" },
    user_id: { name: "user_id" },
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
