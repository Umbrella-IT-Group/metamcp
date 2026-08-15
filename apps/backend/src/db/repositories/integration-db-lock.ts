/**
 * The advisory-lock key every TEST_DATABASE_URL integration suite takes.
 *
 * WHY A LOCK. vitest runs test FILES in parallel worker processes by default,
 * and the integration suites share ONE database and TRUNCATE the tables they
 * seed. Two of them running at once is not a slow test, it is a wrong one:
 * whichever truncates second deletes the other's fixtures mid-assertion, and
 * the failure surfaces in the innocent file. `pg_advisory_lock` is the
 * coordination primitive that reaches across processes, which `describe`
 * ordering and vitest's own sequencing options do not.
 *
 * WHY IT LIVES HERE rather than in one of the suites. Both files must pass the
 * SAME key or the lock is decorative, and a constant duplicated in two test
 * files is a constant that eventually differs. Importing one `.test.ts` from
 * another is not an option: vitest would collect the imported file's tests
 * twice.
 *
 * The value is arbitrary — it only has to be stable and not collide with
 * another advisory lock in the same database. Nothing else in this codebase
 * takes one.
 *
 * Never imported by `src/index.ts`, so tsup (whose only entry is that file)
 * never bundles it into the shipped backend.
 */
export const INTEGRATION_DB_LOCK_KEY = 987_201_431;
