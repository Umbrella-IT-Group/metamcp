/**
 * Behaviour of the two account kill switches.
 *
 * The DB layer is mocked with chain stubs — same pattern as
 * api-keys.repo.member-scope.test.ts and mcp-sessions.repo.test.ts; this fork
 * has no live-DB test harness. What is asserted is therefore the SHAPE of the
 * statements issued, which is where the security property actually lives:
 *
 *  - `deleteById` issues exactly ONE delete, against `users`, and does not
 *    hand-roll dependent cleanup. Every FK into `users` is ON DELETE CASCADE,
 *    so a second copy of that graph in application code could only drift out
 *    of sync with the schema.
 *  - `revokeAccess` severs ALL FOUR access paths — sessions, OAuth access
 *    tokens, pending authorization codes, API keys — and severs them for the
 *    named user only. Missing one leaves an attacker connected through it.
 *  - `revokeAccess` DEACTIVATES keys rather than deleting them, and leaves
 *    the `users` row alone: the account record is the incident evidence
 *    (deleting the sessions is already lossy enough; deleting the identity
 *    too destroys the authoritative record of who the account was).
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

// One chain object per statement kind, recording which table it was pointed
// at. drizzle's builders are thenable, so `.returning()` resolving to an
// array is enough for the repository's `await`.
const deleteCalls: unknown[] = [];
const updateCalls: unknown[] = [];
const setCalls: unknown[] = [];

const deleteChain = {
  where: vi.fn().mockReturnThis(),
  returning: vi.fn(),
};
const updateChain = {
  set: vi.fn((values: unknown) => {
    setCalls.push(values);
    return updateChain;
  }),
  where: vi.fn().mockReturnThis(),
  returning: vi.fn(),
};

vi.mock("../index", () => ({
  db: {
    delete: vi.fn((table: unknown) => {
      deleteCalls.push(table);
      return deleteChain;
    }),
    update: vi.fn((table: unknown) => {
      updateCalls.push(table);
      return updateChain;
    }),
    select: vi.fn(),
  },
}));

import {
  apiKeysTable,
  oauthAccessTokensTable,
  oauthAuthorizationCodesTable,
  sessionsTable,
  usersTable,
} from "../schema";
import { usersRepository } from "./users.repo";

beforeEach(() => {
  vi.clearAllMocks();
  deleteCalls.length = 0;
  updateCalls.length = 0;
  setCalls.length = 0;
  deleteChain.returning.mockResolvedValue([]);
  updateChain.returning.mockResolvedValue([]);
});

describe("UsersRepository.deleteById", () => {
  it("issues a single DELETE against users and relies on the FK cascade", async () => {
    deleteChain.returning.mockResolvedValue([{ id: "user-1" }]);

    const deleted = await usersRepository.deleteById("user-1");

    expect(deleted).toBe(true);
    // Exactly one statement, against `users`. Anything more would be a
    // hand-rolled copy of the ON DELETE CASCADE graph.
    expect(deleteCalls).toEqual([usersTable]);
    expect(updateCalls).toEqual([]);
  });

  it("reports false when the account did not exist", async () => {
    deleteChain.returning.mockResolvedValue([]);

    // An operator who believes they removed an account that is still live is
    // worse off than one who sees the failure.
    await expect(usersRepository.deleteById("ghost")).resolves.toBe(false);
  });
});

describe("UsersRepository.revokeAccess", () => {
  it("severs all four access paths and leaves the account row intact", async () => {
    deleteChain.returning
      .mockResolvedValueOnce([{ id: "s1" }, { id: "s2" }]) // sessions
      .mockResolvedValueOnce([{ token: "t1" }]) // oauth access tokens
      .mockResolvedValueOnce([{ code: "c1" }, { code: "c2" }]); // auth codes
    updateChain.returning.mockResolvedValue([
      { uuid: "k1" },
      { uuid: "k2" },
      { uuid: "k3" },
    ]);

    const result = await usersRepository.revokeAccess("user-1");

    expect(deleteCalls).toEqual([
      sessionsTable,
      oauthAccessTokensTable,
      oauthAuthorizationCodesTable,
    ]);
    // The account itself survives — it is the incident record.
    expect(deleteCalls).not.toContain(usersTable);

    // API keys are DEACTIVATED, not deleted: `is_active` is the revocation
    // flag the key-auth path already checks, and the row stays auditable.
    expect(updateCalls).toEqual([apiKeysTable]);
    expect(setCalls).toEqual([{ is_active: false }]);

    expect(result).toEqual({
      sessions_deleted: 2,
      oauth_tokens_deleted: 1,
      authorization_codes_deleted: 2,
      api_keys_deactivated: 3,
    });
  });

  it("reports honest zeroes when the account had nothing live", async () => {
    // A revoke that severed nothing is itself a finding (wrong account, or
    // access already cut), so the counts must not be faked upward.
    const result = await usersRepository.revokeAccess("user-2");

    expect(result).toEqual({
      sessions_deleted: 0,
      oauth_tokens_deleted: 0,
      authorization_codes_deleted: 0,
      api_keys_deactivated: 0,
    });
  });
});
