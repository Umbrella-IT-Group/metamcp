import logger from "@/utils/logger";

import { ConnectedClient } from "./client";

/** The slice of McpServerPool a recovery needs; structural so tests can fake it. */
export interface SessionRecoveryPool {
  isPooledClient(serverUuid: string, client: ConnectedClient): boolean;
  invalidateServerConnection(
    sessionId: string,
    serverUuid: string,
  ): Promise<void>;
}

interface SessionRecovery {
  promise: Promise<ConnectedClient | undefined>;
  replacement?: ConnectedClient;
}

/**
 * The recoveries started from one routing scope (one MCP session's proxy, or
 * one OpenAPI session id), keyed by the client that failed. A WeakMap, so an
 * entry lives exactly as long as something still holds the dead client.
 */
export type SessionRecoveries = WeakMap<ConnectedClient, SessionRecovery>;

export interface RecoverFailedSessionOptions {
  pool: SessionRecoveryPool;
  recoveries: SessionRecoveries;
  sessionId: string;
  serverUuid: string;
  /** The pooled client whose request just failed with a session-lost error. */
  failedClient: ConnectedClient;
  /**
   * Obtain the replacement session. Runs once per recovery, shared by calls
   * failing on the same client; normally `pool.getSession` with the server's
   * current parameters. May throw (for example when the server left the
   * namespace); every call waiting on this recovery then sees that error.
   */
  reacquire: () => Promise<ConnectedClient | undefined>;
}

/**
 * Replace a pooled backend session that just failed with a session-lost error,
 * once per failed client, however many calls fail on it.
 *
 * WHY. Parallel calls routed to one stale client all fail at about the same
 * moment. Each used to invalidate the server and then acquire a new session on
 * its own. `invalidateServerConnection` retires EVERY client of the server, in
 * every session, so the second caller's invalidation retired the connection
 * the first had just built (and cut any call already running on it, which the
 * caller then sees as a dropped connection), and each acquisition opened its
 * own connection against the per-server cap, so the last ones could get no
 * session at all. Concurrent callers on the same failed client now share one
 * recovery: one invalidation, one acquisition, one replacement for all.
 *
 * The invalidation is also skipped when the failed client no longer holds a
 * pool slot: some other recovery (another session, or this one moments ago)
 * already retired it, and a second cascade would only retire the replacement.
 * The caller then just needs a new session.
 *
 * A successful recovery stays recorded while the dead client is reachable and
 * its replacement is still pooled, so a call that fails late on that client
 * reuses the replacement instead of starting a second cascade. If another
 * recovery or cleanup already retired that replacement, reacquire instead:
 * returning it would send the retry to a closed transport and could overwrite
 * a newer live route. A recovery that produced no session, or threw, is
 * forgotten at once, so the next failure on the same client tries again.
 */
export function recoverFailedSession(
  options: RecoverFailedSessionOptions,
): Promise<ConnectedClient | undefined> {
  const { pool, recoveries, sessionId, serverUuid, failedClient } = options;

  const existing = recoveries.get(failedClient);
  if (
    existing &&
    (!existing.replacement ||
      pool.isPooledClient(serverUuid, existing.replacement))
  ) {
    return existing.promise;
  }

  const recovery = (async () => {
    if (pool.isPooledClient(serverUuid, failedClient)) {
      await pool.invalidateServerConnection(sessionId, serverUuid);
    } else {
      logger.info(
        `Skipping invalidation for server ${serverUuid} (session ${sessionId}): the failed client was already retired by another recovery; acquiring a new session only`,
      );
    }
    return await options.reacquire();
  })();

  const entry: SessionRecovery = { promise: recovery };
  recoveries.set(failedClient, entry);
  const forget = () => {
    if (recoveries.get(failedClient) === entry) {
      recoveries.delete(failedClient);
    }
  };
  recovery.then((fresh) => {
    if (fresh) entry.replacement = fresh;
    else forget();
  }, forget);

  return recovery;
}
