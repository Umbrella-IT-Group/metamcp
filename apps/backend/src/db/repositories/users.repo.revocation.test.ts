/**
 * Statement-shape behaviour of the account kill switches.
 *
 * The DB layer is mocked with chain stubs — same pattern as
 * api-keys.repo.member-scope.test.ts and mcp-sessions.repo.test.ts. The
 * queries themselves run against a real postgres in
 * access-queries.integration.test.ts; what THIS file pins is the structure
 * that no amount of seeding would prove, because it is about what the code
 * refuses to do:
 *
 *  - `deleteById` issues exactly ONE delete, against `users`, and does not
 *    hand-roll dependent cleanup. Every FK into `users` is ON DELETE CASCADE,
 *    so a second copy of that graph in application code could only drift out
 *    of sync with the schema.
 *  - `revokeAccess` runs inside a TRANSACTION. Under the previous
 *    `Promise.all` a mid-flight failure could leave sessions deleted but keys
 *    still live while the caller was told the revoke failed — the reported
 *    state was a lie in both directions.
 *  - `revokeAccess` DEACTIVATES keys rather than deleting them, and leaves
 *    the `users` row alone: the account record is the incident evidence.
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

const deleteCalls: unknown[] = [];
const updateCalls: unknown[] = [];
const setCalls: unknown[] = [];
let transactionCount = 0;

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

// The transaction handle exposes the same delete/update surface, so the
// repository code under test is identical whether it runs on `db` or `tx` —
// and the counter proves it actually opened one.
const tx = {
  delete: vi.fn((table: unknown) => {
    deleteCalls.push(table);
    return deleteChain;
  }),
  update: vi.fn((table: unknown) => {
    updateCalls.push(table);
    return updateChain;
  }),
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
    transaction: vi.fn(async (fn: (t: typeof tx) => Promise<unknown>) => {
      transactionCount += 1;
      return fn(tx);
    }),
  },
}));

import {
  apiKeysTable,
  m365UserTokensTable,
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
  transactionCount = 0;
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
  it("runs every statement inside ONE transaction", async () => {
    await usersRepository.revokeAccess("user-1");

    // All-or-nothing is the whole point: a partial revoke reported as a
    // failure leaves the operator believing access is intact when it is
    // half-cut.
    expect(transactionCount).toBe(1);
    expect(tx.delete).toHaveBeenCalled();
    expect(tx.update).toHaveBeenCalled();
  });

  it("severs all five access paths and leaves the account row intact", async () => {
    deleteChain.returning
      .mockResolvedValueOnce([{ id: "s1" }, { id: "s2" }]) // sessions
      .mockResolvedValueOnce([{ token: "t1" }]) // oauth access tokens
      .mockResolvedValueOnce([{ code: "c1" }, { code: "c2" }]); // auth codes
    updateChain.returning
      .mockResolvedValueOnce([{ uuid: "k1" }, { uuid: "k2" }, { uuid: "k3" }]) // api keys
      .mockResolvedValueOnce([{ uuid: "m1" }]); // m365 delegation

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
    // The M365 delegation is pushed to `reauth_required`, which the mint path
    // already treats as missing — without it a revoked identity could still
    // be exercised against Microsoft 365.
    expect(updateCalls).toEqual([apiKeysTable, m365UserTokensTable]);
    expect(setCalls).toEqual([
      { is_active: false },
      { status: "reauth_required" },
    ]);

    expect(result).toEqual({
      sessions_deleted: 2,
      oauth_tokens_deleted: 1,
      authorization_codes_deleted: 2,
      api_keys_deactivated: 3,
      m365_tokens_revoked: 1,
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
      m365_tokens_revoked: 0,
    });
  });

  it("propagates a failure instead of returning partial counts", async () => {
    deleteChain.returning.mockRejectedValueOnce(new Error("deadlock detected"));

    // The transaction rolls back, so the honest answer is a throw. Returning
    // partial counts here would tell the operator that some paths were cut
    // when in fact none were.
    await expect(usersRepository.revokeAccess("user-1")).rejects.toThrow(
      "deadlock detected",
    );
  });
});

describe("UsersRepository.setDisabled", () => {
  it("stamps who locked the account and when", async () => {
    updateChain.returning.mockResolvedValue([{ id: "user-1", disabled: true }]);

    const result = await usersRepository.setDisabled("user-1", true, "admin-1");

    expect(updateCalls).toEqual([usersTable]);
    const [values] = setCalls as Array<{
      disabled: boolean;
      disabled_at: Date | null;
      disabled_by: string | null;
    }>;
    expect(values?.disabled).toBe(true);
    expect(values?.disabled_at).toBeInstanceOf(Date);
    expect(values?.disabled_by).toBe("admin-1");
    expect(result).toEqual({ id: "user-1", disabled: true });
  });

  it("clears the audit stamp on enable so the columns describe the CURRENT lock", async () => {
    updateChain.returning.mockResolvedValue([
      { id: "user-1", disabled: false },
    ]);

    await usersRepository.setDisabled("user-1", false, "admin-1");

    const [values] = setCalls as Array<{
      disabled: boolean;
      disabled_at: Date | null;
      disabled_by: string | null;
    }>;
    expect(values?.disabled).toBe(false);
    // Leaving a stale who/when behind on an ENABLED account would read as
    // "this account is locked" to the next person looking at the row.
    expect(values?.disabled_at).toBeNull();
    expect(values?.disabled_by).toBeNull();
  });

  it("returns undefined when no row matched", async () => {
    updateChain.returning.mockResolvedValue([]);

    await expect(
      usersRepository.setDisabled("ghost", true, "admin-1"),
    ).resolves.toBeUndefined();
  });
});
