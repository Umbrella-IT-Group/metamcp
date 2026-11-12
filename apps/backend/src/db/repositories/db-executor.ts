import type { db } from "../index";

/**
 * The transaction handle `db.transaction` passes its callback, and the
 * executor a repository write accepts: the shared pool, or a transaction the
 * caller already holds.
 *
 * Type-only on purpose. Importing the pool here would make every module that
 * names these types load `db/index`, which throws at import time without a
 * DATABASE_URL, and the unit suites that mock a repository would then have to
 * mock the pool as well.
 *
 * A repository method that takes `executor?: DbExecutor` writes through it
 * (defaulting to the pool, so a caller outside a transaction is unchanged) and
 * opens any inner `transaction(...)` on it too: on a pool that is a real
 * transaction, on a transaction handle it is a savepoint, so the work commits
 * or rolls back with whatever else the outer transaction did.
 */
export type DbTransaction = Parameters<Parameters<typeof db.transaction>[0]>[0];
export type DbExecutor = typeof db | DbTransaction;
