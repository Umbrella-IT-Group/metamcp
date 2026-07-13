import { ServerParameters } from "@repo/zod-types";

import { ConnectedClient } from "./client";

/**
 * Minimal slice of McpServerPool the warmup helper needs. Structural so
 * tests can drive it with a fake pool (same pattern as
 * list-handler-recovery.ts / mcp-server-pool.test.ts) instead of
 * mocking the real singleton.
 */
export interface ToolCallWarmupPool {
  getSession(
    sessionId: string,
    serverUuid: string,
    params: ServerParameters,
    namespaceUuid?: string,
  ): Promise<ConnectedClient | undefined>;
}

export interface AcquireSessionWithBoundedWarmupOptions {
  pool: ToolCallWarmupPool;
  sessionId: string;
  serverUuid: string;
  params: ServerParameters;
  namespaceUuid?: string;
  /**
   * Hard cap per attempt, ms. Callers source this from
   * `configService.getMcpToolCallReconnectWarmupTimeout()` rather than
   * hardcoding it here, so the primitive stays test-friendly (no
   * config/DB dependency in this module).
   */
  timeoutMs: number;
  /** Total attempts including the first. Default 2 — one shot + one retry. */
  attempts?: number;
}

/**
 * Give a server a short, BOUNDED chance to come back before the caller
 * treats a tools/call routing lookup as unresolved.
 *
 * Exists for the reconnect-window 404: `McpServerPool.invalidateServer-
 * Connection` tears a pooled client down and fires `list_changed`
 * BEFORE the replacement connection exists (mcp-server-pool.ts). A
 * `tools/call` landing in that gap sees `getSession` return `undefined`
 * even though the owning server is real and just mid-reconnect
 * (`createNewConnection` returns `undefined` on a failed/backing-off
 * attempt) — without this helper, callers fall straight through to
 * "Unknown tool", which the OpenAPI bridge maps to a literal HTTP 404.
 *
 * Each attempt races `pool.getSession` against `timeoutMs` rather than
 * waiting out the full connect, which can itself take 30s+ per hop
 * under `client.ts`'s exponential reconnect backoff schedule. If an
 * attempt's promise hasn't settled by the deadline, this stops waiting
 * on it — JS can't cancel it, so it keeps running in the background and,
 * if it later succeeds, still lands in the pool for the NEXT caller —
 * and, if attempts remain, immediately fires a fresh `getSession` call.
 * Two overlapping `getSession` calls for the same (sessionId,
 * serverUuid) are safe: `McpServerPool.getSession` already de-dupes
 * post-await (whichever resolves second discards its own connection and
 * reuses the first's), the same tolerance the pool already relies on
 * for concurrent request races.
 *
 * Bounded on purpose: a genuinely-dead upstream must fail within
 * `attempts * timeoutMs`, never hang. Callers are expected to fall
 * through to their existing "Unknown tool" error when this resolves
 * `undefined`, and to skip calling this entirely when they have no
 * last-known-good server to warm up (a tool that truly doesn't exist
 * anywhere must still 404 without paying this wait).
 */
export async function acquireSessionWithBoundedWarmup(
  opts: AcquireSessionWithBoundedWarmupOptions,
): Promise<ConnectedClient | undefined> {
  const attempts = opts.attempts ?? 2;

  for (let attempt = 0; attempt < attempts; attempt++) {
    const session = await raceWithTimeout(
      opts.pool.getSession(
        opts.sessionId,
        opts.serverUuid,
        opts.params,
        opts.namespaceUuid,
      ),
      opts.timeoutMs,
    );
    if (session) {
      return session;
    }
  }

  return undefined;
}

/**
 * Resolve with `undefined` if `promise` hasn't settled within
 * `timeoutMs`, otherwise resolve/reject with whatever `promise` did.
 * `getSession` never rejects in practice (mcp-server-pool.ts resolves
 * `undefined` on every failure path instead), but the reject branch is
 * handled defensively so a future change there can't turn this into an
 * unhandled rejection.
 */
function raceWithTimeout<T>(
  promise: Promise<T | undefined>,
  timeoutMs: number,
): Promise<T | undefined> {
  return new Promise((resolve) => {
    const timer = setTimeout(() => resolve(undefined), timeoutMs);
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      () => {
        clearTimeout(timer);
        resolve(undefined);
      },
    );
  });
}
