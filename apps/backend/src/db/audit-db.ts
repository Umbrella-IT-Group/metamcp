import { drizzle } from "drizzle-orm/node-postgres";
import { Pool } from "pg";

import logger from "@/utils/logger";

import * as schema from "./schema";

/**
 * A SEPARATE, deliberately tiny connection pool used ONLY by
 * `audit-log.repo.ts`.
 *
 * WHY THE AUDIT WRITER DOES NOT SHARE THE MAIN POOL. The audit emitters sit on
 * the two hottest denial paths in the gateway, and one of them is reachable
 * with no credential at all: every no-credential 401 on `/metamcp/*` emits,
 * and so does every 429. That is deliberate — unauthenticated endpoint
 * scanning is exactly the recon such an attack begins with, and not logging it
 * is how the last one stayed invisible. But it also makes an unauthenticated
 * flood a 1:1 request-to-INSERT amplifier, and the failed-attempt rate limiter
 * cannot damp it: that limiter keys on `req.ip`, which behind the
 * in-container Next.js rewrite is the same loopback address for every caller,
 * so it is one shared bucket rather than a per-attacker one.
 *
 * On the shared pool (`./index`, pg default `max: 10`, no
 * `connectionTimeoutMillis`, so checkouts queue indefinitely) that flood would
 * contend for the same ten connections the AUTH path uses for its own
 * queries — session lookups, `users.disabled` checks, API-key validation. The
 * failure mode is the worst one available: logging the attack starves the code
 * that refuses it.
 *
 * So the audit writer gets its own pool with a hard ceiling and a short
 * checkout timeout. Under flood the eleventh concurrent audit INSERT waits at
 * most ~1s and then ERRORS — which the fire-and-forget emitter swallows. That
 * is the correct trade in both directions: a dropped audit row under an active
 * flood is acceptable, a starved auth path is not, and the blast radius of the
 * audit path is now bounded by construction rather than by hoping the volume
 * stays low.
 *
 * `max: 2` rather than 1: a single connection would serialise every audit
 * write behind the slowest one, turning an ordinary slow INSERT into a
 * queue for all of them. Two gives one in flight and one arriving without
 * meaningfully widening the footprint.
 *
 * Same DATABASE_URL and same TLS material as the main pool — this is
 * isolation of CONNECTIONS, not of credentials or of the database. The
 * Phase-2 role split (a NOSUPERUSER INSERT-only runtime role) is what makes it
 * isolation of privilege too, and this pool is where that connection string
 * will land when it does.
 */

const { DATABASE_URL, POSTGRES_CA_CERT } = process.env;

if (!DATABASE_URL) {
  throw new Error("DATABASE_URL is not set");
}

export const auditPool = new Pool({
  connectionString: DATABASE_URL,
  // The ceiling that makes this pool's contention its own problem.
  max: 2,
  // Fail fast instead of queueing forever. A caller that cannot get a
  // connection within a second under load is better off dropping the row: the
  // emitter is detached, so this timeout costs nothing on the request path,
  // and an unbounded queue would just relocate the starvation into memory.
  connectionTimeoutMillis: 1000,
  ...(POSTGRES_CA_CERT && {
    ssl: {
      ca: POSTGRES_CA_CERT,
      rejectUnauthorized: true,
    },
  }),
});

auditPool.on("error", (err) => {
  // Same reasoning as the main pool: an idle client erroring out (database
  // maintenance, a killed backend) emits an 'error' event on the pool, and an
  // unhandled one takes the process down. Logged and ignored; pg-pool creates
  // a fresh client on the next checkout.
  logger.error("PostgreSQL audit pool error (ignored):", err);
});

export const auditDb = drizzle(auditPool, { schema });
