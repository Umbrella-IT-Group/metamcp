import { drizzle } from "drizzle-orm/node-postgres";
import { Pool } from "pg";

import logger from "@/utils/logger";

import { resolveRuntimeConnection } from "./runtime-connection";
import * as schema from "./schema";

/**
 * A SEPARATE, deliberately tiny connection pool used by the `record()` method
 * of `gateway-events.repo.ts` and by the hourly stats read in
 * `audit-storage.repo.ts`.
 *
 * SAME PHILOSOPHY AS `./audit-db`, DELIBERATELY NOT THE SAME POOL, and the
 * distinction is the whole reason this file exists.
 *
 * `./audit-db` exists so that a flood of no-credential 401s cannot starve the
 * AUTH path of connections while it logs them. Its ceiling of two connections
 * is what bounds that blast radius. Gateway events need exactly the same
 * protection for the same reason: `log-store.record()` runs on the connect
 * retry loop and on every line a STDIO backend writes to stderr, so a
 * crash-looping backend is a write firehose that must not contend with the
 * request path.
 *
 * But putting it on `auditDb` would have bought that protection by spending
 * someone else's. `audit_log` is the control-plane SECURITY record: it has no
 * prune path at all, a row that is never written can never be recovered, and
 * its writes are fire-and-forget so a starved one is DROPPED rather than
 * delayed. Sharing two connections between it and an operational firehose
 * means a chatty backend can silently cost the gateway its record of a refused
 * credential. That inverts the priority the whole audit path was built around.
 *
 * So: same shape, same reasoning, own budget. Under load each writer can only
 * starve itself.
 *
 * `max: 2` rather than 1 for the same reason `./audit-db` gives: a single
 * connection would serialise every write behind the slowest one. Same
 * connection string and same TLS material as the other two pools: this is
 * isolation of CONNECTIONS, not of the database. It becomes isolation of
 * PRIVILEGE too once the optional NOSUPERUSER role split is configured, which
 * is what `./runtime-connection` resolves: all three request-path pools then
 * dial a role that holds INSERT, SELECT and DELETE on `gateway_events` and
 * cannot UPDATE or TRUNCATE it, so migration 0031's append-only triggers stop
 * being bypassable by the credential the gateway holds while serving. Before
 * this it built from the raw DATABASE_URL (the bootstrap superuser), so this
 * one request-path pool kept a trigger-bypassing credential the other two had
 * already given up.
 *
 * NOTE the asymmetry inside `gateway-events.repo.ts`: only `record()` uses
 * this pool. `list()`, `listServerNames()` and `pruneOlderThan()` run on the
 * main pool, because the isolation that matters runs one way. The hot write
 * path must not be able to starve anything; a periodic prune and an admin-only
 * query have no business occupying a two-connection budget the writer depends
 * on.
 *
 * THE SECOND CONSUMER IS NOT AN EXCEPTION TO THAT RULE, it is the same rule
 * read precisely. What those three methods are barred for is DURATION: a
 * DELETE across millions of rows or a filtered page of history can hold a
 * connection for as long as the table is large. `audit-storage.repo.ts` reads
 * three catalog rows once an hour and is bounded at both ends by the timeouts
 * below, so it cannot hold anything. It belongs here rather than on the main
 * pool for the opposite half of the same reasoning: the main pool sets no
 * checkout timeout, so a stats read there would queue indefinitely under
 * saturation and stall the cleanup sweep it rides.
 *
 * BOTH ENDS, because they are different exposures. `connectionTimeoutMillis`
 * bounds waiting FOR a connection; `statement_timeout` bounds holding one. On
 * a two-connection pool the second is the one that bites, and it is not a
 * property of how fast the query is: any statement here can block behind an
 * ACCESS EXCLUSIVE lock no matter how little work it does. See the comments on
 * the two settings.
 */

const { POSTGRES_CA_CERT } = process.env;

// Resolved here rather than imported from `./index` for the same reason
// `./audit-db` resolves its own: this module shares nothing with the main pool
// it does not have to, and the resolution is a pure function of the
// environment. `resolveRuntimeConnection` throws the same "DATABASE_URL is not
// set" this file used to throw directly, so the missing-URL guard moves there.
export const gatewayEventsRuntimeConnection = resolveRuntimeConnection();

export const gatewayEventsPool = new Pool({
  connectionString: gatewayEventsRuntimeConnection.connectionString,
  max: 2,
  // Fail fast instead of queueing forever. A write that cannot get a
  // connection within a second under load is better off dropped: the caller is
  // detached, so this timeout costs nothing on the request path, and an
  // unbounded queue would just relocate the pressure into memory.
  connectionTimeoutMillis: 1000,
  // The checkout timeout above bounds ACQUIRING a connection. It says nothing
  // about how long a statement holds one once acquired, and on this pool that
  // gap is the whole exposure: two connections is the entire budget, so a
  // single statement stuck on a lock takes half of it for as long as the lock
  // is held.
  //
  // Both consumers can stall that way, and neither is doing anything slow.
  // `record()` INSERTs take a ROW EXCLUSIVE lock and the stats read in
  // `audit-storage.repo` takes ACCESS SHARE; both conflict with ACCESS
  // EXCLUSIVE, which is what a boot-time migration, a `VACUUM FULL`, or the
  // README's own break-glass `ALTER TABLE ... DISABLE TRIGGER` holds. Measured:
  // `pg_total_relation_size` behind a held ACCESS EXCLUSIVE blocks for as long
  // as the lock lives, and the 1s checkout timeout never fires because the
  // connection was already checked out.
  //
  // A server-side statement timeout is what actually bounds it, and it is set
  // on the pool rather than around the one query because the writer needs the
  // same protection for the same reason. Five seconds is far past anything
  // either consumer legitimately does (a single-row INSERT, a three-row
  // catalog read), so it only ever fires on a stall. Both callers already
  // treat an error as a dropped row or a missed reading.
  options: "-c statement_timeout=5000",
  ...(POSTGRES_CA_CERT && {
    ssl: {
      ca: POSTGRES_CA_CERT,
      rejectUnauthorized: true,
    },
  }),
});

gatewayEventsPool.on("error", (err) => {
  // Same reasoning as the other two pools: an idle client erroring out
  // (database maintenance, a killed backend) emits an 'error' event on the
  // pool, and an unhandled one takes the process down. Logged and ignored;
  // pg-pool creates a fresh client on the next checkout.
  logger.error("PostgreSQL gateway-events pool error (ignored):", err);
});

export const gatewayEventsDb = drizzle(gatewayEventsPool, { schema });
