import { McpServerErrorStatusEnum } from "@repo/zod-types";
import express from "express";

import logger from "../utils/logger";
import {
  buildUpstreamHealthBody,
  buildUpstreamHealthErrorBody,
  isAdminHealthRequest,
  type UpstreamAdminDetail,
  type UpstreamLiveness,
} from "./health-upstream";

/**
 * The `GET /health/upstream` handler: the rollup arithmetic and the anonymous
 * cache. `index.ts` mounts the handler this module builds; ./health-upstream
 * still owns who sees what.
 *
 * It lives outside `index.ts` because that module calls `app.listen()` at
 * import, so nothing in it can be driven by a test. The tests in
 * ./health-upstream-handler.test.ts run this exact handler.
 */

/**
 * How long a successful anonymous rollup is reused, measured from the moment
 * its computation finished.
 *
 * The anonymous view is a liveness probe (external monitors poll it), and
 * every computation reads every `mcp_servers` row. Ten seconds keeps the
 * database work bounded by the clock rather than by the request rate, and is
 * well inside any monitor's polling interval, so the values it reports lag by
 * at most ten seconds.
 */
export const ANONYMOUS_UPSTREAM_HEALTH_TTL_MS = 10_000;

interface UpstreamSnapshot {
  liveness: UpstreamLiveness;
  detail: UpstreamAdminDetail;
}

/**
 * One rollup: a single `mcp_servers` read plus the pool's in-memory state.
 *
 * The error state comes from each row's own `error_status` column, with the
 * comparison `serverErrorTracker.isServerInErrorState` makes. That method
 * re-reads the row by UUID, so calling it here cost one more query per server
 * for a column `findAll()` had already returned.
 *
 * The repository and the pool are lazy imports, as they were when this body
 * sat inline in `index.ts`, so building the handler touches neither.
 */
async function computeUpstreamSnapshot(): Promise<UpstreamSnapshot> {
  const { mcpServersRepository } = await import("../db/repositories");
  const { mcpServerPool } = await import("./metamcp/mcp-server-pool");

  const servers = await mcpServersRepository.findAll();
  const pool = mcpServerPool.getPoolStatus();
  const poolConfig = mcpServerPool.getPoolConfig();
  const perServer = pool.perServerCounts ?? {};
  const lastFailureAt = pool.lastConnectFailureAt ?? {};
  const lastSuccessAt = pool.lastConnectSuccessAt ?? {};
  const pingFailures = pool.pingFailures ?? {};
  const authRejections = pool.backendAuthRejections ?? {};

  const details = servers.map((s) => {
    const inError = s.error_status === McpServerErrorStatusEnum.enum.ERROR;
    const connectionCount = perServer[s.uuid] ?? 0;
    const failedAt = lastFailureAt[s.uuid];
    const succeededAt = lastSuccessAt[s.uuid];
    // A server is "reachable" unless (a) the ERROR circuit breaker
    // tripped, or (b) it holds zero live connections AND its most
    // recent connect attempt failed (the pool clears the failure
    // stamp on every successful connect). Case (b) is how a
    // hard-down HTTP/SSE backend looks — those never trip ERROR
    // because crash counting is STDIO-only. Zero connections with
    // NO failure stamp is just lazy cold-start: not unhealthy.
    const reachable =
      !inError && !(connectionCount === 0 && failedAt !== undefined);
    return {
      uuid: s.uuid,
      name: s.name,
      in_error: inError,
      connection_count: connectionCount,
      reachable,
      last_connect_failure_at: failedAt
        ? new Date(failedAt).toISOString()
        : null,
      last_connect_success_at: succeededAt
        ? new Date(succeededAt).toISOString()
        : null,
      ping_failures: pingFailures[s.uuid] ?? 0,
      // Present only while the most recent connect was rejected with HTTP
      // 401/403 (the credentials the gateway sends), so a server without one
      // keeps exactly the shape it had. Admin view only; the anonymous body
      // never carries per-server detail. Reachability is unchanged: a
      // connect-time rejection already reads unreachable through the failure
      // stamp above.
      ...(authRejections[s.uuid]
        ? {
            auth_rejected: true,
            auth_rejected_http_status: authRejections[s.uuid].status,
            auth_rejected_at: new Date(authRejections[s.uuid].at).toISOString(),
          }
        : {}),
    };
  });

  const unreachable = details.filter((d) => !d.reachable).length;

  return {
    liveness: {
      healthy: unreachable === 0,
      total_servers: details.length,
      errored_servers: details.filter((d) => d.in_error).length,
      unreachable_servers: unreachable,
    },
    detail: {
      pool: {
        idle: pool.idle,
        active: pool.active,
        pending: pool.pending ?? 0,
        // pending-inclusive so `total` matches what
        // canCreateConnection's MAX_TOTAL_CONNECTIONS check actually
        // compares against (getTotalConnectionCount =
        // idle+active+pending) — a total that silently dropped
        // in-flight idle creations would read below the cap while the
        // pool itself refuses new connections at it (2026-07-14 audit
        // finding).
        total: pool.idle + pool.active + (pool.pending ?? 0),
        // Effective caps the pool actually enforces (from
        // getPoolConfig, the single source of truth), NOT a re-parse
        // of env with local defaults. The prior payload reported only
        // the per-server cap and never the global cap, so an operator
        // debugging saturation could not see it.
        max_connections_per_server: poolConfig.maxConnectionsPerServer,
        max_total_connections: poolConfig.maxTotalConnections,
      },
      servers: details,
    },
  };
}

/**
 * Build the `GET /health/upstream` handler. `index.ts` builds exactly one;
 * each call returns a handler with its own, empty, anonymous cache, which is
 * what lets each test start cold.
 *
 * Every request is classified with `isAdminHealthRequest` first, and the
 * classification picks the view:
 *
 * - ADMIN: a fresh computation every time (rows and pool state), answered with
 *   `servers` and `pool`, and never written to or read from the anonymous
 *   cache. Admins use this view to debug a live problem, and the cache must
 *   never hold the admin half or anything derived from an authorization
 *   decision.
 * - ANONYMOUS (and any non-admin): the five liveness fields from the cache.
 *   Only a SUCCESSFUL rollup's liveness numbers are cached, for
 *   ANONYMOUS_UPSTREAM_HEALTH_TTL_MS from completion. Concurrent requests that
 *   find no fresh entry share one in-flight computation; the in-flight
 *   reference is cleared in `finally`, so a failure leaves nothing behind. A
 *   failed refresh answers the constant HTTP 500 body, caches no rejection
 *   and does not extend the expired entry; the next request computes again.
 *
 * The anonymous body is still built per request by buildUpstreamHealthBody,
 * so its fields, their order, and the status codes are what they were.
 */
export function createUpstreamHealthHandler(): express.RequestHandler {
  let cached: { liveness: UpstreamLiveness; expiresAt: number } | null = null;
  let inFlight: Promise<UpstreamLiveness> | null = null;

  const anonymousLiveness = (): Promise<UpstreamLiveness> => {
    if (cached && Date.now() < cached.expiresAt) {
      return Promise.resolve(cached.liveness);
    }
    if (!inFlight) {
      inFlight = (async () => {
        try {
          const { liveness } = await computeUpstreamSnapshot();
          cached = {
            liveness: Object.freeze({ ...liveness }),
            expiresAt: Date.now() + ANONYMOUS_UPSTREAM_HEALTH_TTL_MS,
          };
          return cached.liveness;
        } finally {
          inFlight = null;
        }
      })();
    }
    return inFlight;
  };

  return async (req, res) => {
    try {
      if (await isAdminHealthRequest(req)) {
        const { liveness, detail } = await computeUpstreamSnapshot();
        res.json(buildUpstreamHealthBody(liveness, detail));
        return;
      }

      res.json(buildUpstreamHealthBody(await anonymousLiveness(), null));
    } catch (error) {
      // Logged here, never serialised: the body is the constant from
      // ./health-upstream, because this endpoint answers unauthenticated
      // callers and a driver error's message names internal hosts and SQL.
      logger.error("/health/upstream failed:", error);
      res.status(500).json(buildUpstreamHealthErrorBody());
    }
  };
}
