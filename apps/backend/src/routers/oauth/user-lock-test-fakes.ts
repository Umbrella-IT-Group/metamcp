import type { Mock } from "vitest";

/**
 * Fakes for the per-user OAuth credential lock in the OAuth router unit tests.
 *
 * The routers run every credential mint and revoke inside
 * `oauthRepository.withUserLock(userId, fn)` and hand the transaction to each
 * repository call. These unit tests mock the repositories, so the fake runs
 * `fn` with a frozen sentinel transaction: a test can then assert that a write
 * went through THE transaction rather than the shared pool. The real lock and
 * its races are exercised against Postgres in
 * ../../db/repositories/oauth-user-lock.integration.test.ts.
 *
 * Imported only by tests; nothing under src/index.ts reaches it, so tsup never
 * bundles it.
 */
export const FAKE_OAUTH_TX = Object.freeze({ fakeOAuthTransaction: true });

interface LockableRepositoryMock {
  withUserLock: Mock;
  getByRefreshToken?: Mock;
  claimRefreshToken?: Mock;
  deleteByRefreshToken?: Mock;
  deleteAccessToken?: Mock;
}

/**
 * Arm the lock fakes. Call from `beforeEach` after any `vi.clearAllMocks()`.
 *
 * - `withUserLock` runs the callback with FAKE_OAUTH_TX and returns its value,
 *   or rethrows its error, like a transaction that commits or rolls back.
 * - `claimRefreshToken` behaves like the DELETE ... RETURNING it stands for:
 *   it returns the row the test's `getByRefreshToken` fake currently yields
 *   (or no rows), read through that fake's implementation so the claim is not
 *   counted as a lookup.
 * - `deleteByRefreshToken` and `deleteAccessToken` report one deleted row.
 */
export function armUserLockFakes(repo: LockableRepositoryMock): void {
  repo.withUserLock.mockImplementation(
    async (_userId: string, fn: (tx: unknown) => Promise<unknown>) =>
      fn(FAKE_OAUTH_TX),
  );
  if (repo.claimRefreshToken && repo.getByRefreshToken) {
    const lookup = repo.getByRefreshToken;
    repo.claimRefreshToken.mockImplementation(async (token: string) => {
      const impl = lookup.getMockImplementation();
      const row = impl ? await impl(token, FAKE_OAUTH_TX) : undefined;
      return row ? [row] : [];
    });
  }
  repo.deleteByRefreshToken?.mockResolvedValue(1);
  repo.deleteAccessToken?.mockResolvedValue(1);
}
