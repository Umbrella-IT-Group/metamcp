import { randomUUID } from "node:crypto";

import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import express from "express";

import { mcpSessionsRepository } from "@/db/repositories/mcp-sessions.repo";
import {
  ApiKeyAuthenticatedRequest,
  authenticateApiKey,
} from "@/middleware/api-key-oauth.middleware";
import { lookupEndpoint } from "@/middleware/lookup-endpoint-middleware";
import { rateLimitMiddleware } from "@/middleware/rate-limit.middleware";
import logger from "@/utils/logger";

import { metaMcpServerPool } from "../../lib/metamcp/metamcp-server-pool";
import {
  AuthMethod,
  hashAuthPrincipal,
  principalMatches,
} from "../../lib/metamcp/session-auth";
import { SessionLifetimeManagerImpl } from "../../lib/session-lifetime-manager";

const streamableHttpRouter = express.Router();

// Session lifetime manager for StreamableHTTP sessions
const sessionManager =
  new SessionLifetimeManagerImpl<StreamableHTTPServerTransport>(
    "StreamableHTTP",
  );

/**
 * Map the auth method recorded by the middleware (`api_key` | `oauth`)
 * back to the lazy-session-recovery AuthMethod enum. Keeps the call
 * sites tight and lets the hashing layer stay independent of express
 * request shape.
 */
function authMethodFromRequest(req: ApiKeyAuthenticatedRequest): AuthMethod {
  return req.authMethod === "oauth" ? "oauth" : "api_key";
}

/**
 * Extract the raw bearer token (or API key) the middleware authenticated
 * from. The middleware doesn't surface the matched token explicitly, so
 * we replay the same header lookup it used. Returns `null` when no
 * recognizable credential is present — the lazy-recovery path then
 * refuses recovery (a credential-less request can't reclaim a session).
 */
function extractRawTokenForPrincipal(req: express.Request): string | null {
  const apiKeyHeader = req.headers["x-api-key"];
  if (typeof apiKeyHeader === "string" && apiKeyHeader.length > 0) {
    return apiKeyHeader;
  }
  const authHeader = req.headers.authorization;
  if (
    typeof authHeader === "string" &&
    authHeader.startsWith("Bearer ") &&
    authHeader.length > 7
  ) {
    return authHeader.substring(7);
  }
  const queryToken =
    (req.query.api_key as string | undefined) ||
    (req.query.apikey as string | undefined);
  if (queryToken) {
    return queryToken;
  }
  return null;
}

/**
 * Lazy-recover an in-memory transport for a sessionId that's missing
 * from `sessionManager` but persisted in `mcp_sessions`. Used by the
 * POST + GET handlers below before returning the existing 404 / 401
 * envelopes.
 *
 * Returns:
 *   - `{ status: "recovered", transport }` — caller forwards the
 *     request to the rebuilt transport. The DB row's last_seen_at has
 *     already been touched.
 *   - `{ status: "auth_failed" }` — the stored auth principal doesn't
 *     match the incoming credential. Caller returns 401.
 *   - `{ status: "not_found" }` — no DB row OR the row's namespace
 *     doesn't match the requested endpoint (cross-namespace replay
 *     attempt). Caller returns the existing 404.
 *
 * The recovered transport is added to `sessionManager` so subsequent
 * requests in the same metamcp lifetime skip the DB hop entirely.
 */
async function recoverPersistedSession(
  sessionId: string,
  authReq: ApiKeyAuthenticatedRequest,
): Promise<
  | { status: "recovered"; transport: StreamableHTTPServerTransport }
  | { status: "auth_failed" }
  | { status: "not_found" }
> {
  let stored;
  try {
    stored = await mcpSessionsRepository.findById(sessionId);
  } catch (error) {
    // DB error during recovery is a hard miss — fall through to the
    // existing 404 path. Logged so post-mortem can correlate with
    // postgres availability events; this is operational noise, not
    // a security incident.
    logger.error(
      `mcp_sessions lookup failed for session ${sessionId}; treating as not-found.`,
      error,
    );
    return { status: "not_found" };
  }
  if (!stored) {
    return { status: "not_found" };
  }
  // Cross-namespace replay defense: the session must belong to the
  // namespace + endpoint the request is targeting. The DB row could
  // be stale-but-not-yet-pruned, and a different consumer with a
  // valid credential for endpoint B should not be able to reclaim
  // a session that was created against endpoint A.
  if (
    stored.namespace_uuid !== authReq.namespaceUuid ||
    stored.endpoint_name !== authReq.endpointName
  ) {
    return { status: "not_found" };
  }

  const rawToken = extractRawTokenForPrincipal(authReq);
  if (!rawToken) {
    return { status: "auth_failed" };
  }
  const currentMethod = authMethodFromRequest(authReq);
  // The auth method must also match — a session created with an API
  // key can't be reclaimed with a Bearer token (and vice versa).
  if (stored.auth_method !== currentMethod) {
    return { status: "auth_failed" };
  }
  const candidate = hashAuthPrincipal(rawToken, currentMethod);
  if (!principalMatches(candidate, stored.auth_principal)) {
    return { status: "auth_failed" };
  }

  // Auth + scope match. Rebuild the transport with the stored sessionId
  // so the consumer's cached id stays valid across the rebuild.
  const mcpServerInstance = await metaMcpServerPool.getServer(
    sessionId,
    stored.namespace_uuid,
  );
  if (!mcpServerInstance) {
    logger.error(
      `Lazy recovery: failed to acquire MetaMCP server instance for namespace ${stored.namespace_uuid} (session ${sessionId}).`,
    );
    return { status: "not_found" };
  }
  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: () => sessionId,
    onsessioninitialized: async (sid) => {
      logger.info(
        `Lazy-recovered session re-initialized for sessionId: ${sid}`,
      );
    },
  });
  sessionManager.addSession(sessionId, transport);
  await mcpServerInstance.server.connect(transport);
  // Best-effort touch; failure is non-fatal — pruner only deletes
  // genuinely stale rows.
  mcpSessionsRepository
    .touch(sessionId)
    .catch((error: unknown) =>
      logger.warn(
        `mcp_sessions touch failed for session ${sessionId}; pruner may reap prematurely.`,
        error,
      ),
    );
  logger.info(
    `Lazy-recovered session ${sessionId} for endpoint ${stored.endpoint_name} (namespace ${stored.namespace_uuid}); persisted state restored from DB.`,
  );
  return { status: "recovered", transport };
}

// Cleanup function for a specific session
const cleanupSession = async (
  sessionId: string,
  transport?: StreamableHTTPServerTransport,
) => {
  logger.info(`Cleaning up StreamableHTTP session ${sessionId}`);

  try {
    // Use provided transport or get from session manager
    const sessionTransport = transport || sessionManager.getSession(sessionId);

    if (sessionTransport) {
      logger.info(`Closing transport for session ${sessionId}`);
      await sessionTransport.close();
      logger.info(`Transport cleaned up for session ${sessionId}`);
    } else {
      logger.info(`No transport found for session ${sessionId}`);
    }

    // Remove from session manager
    sessionManager.removeSession(sessionId);

    // Clean up MetaMCP server pool session
    await metaMcpServerPool.cleanupSession(sessionId);

    // Drop the persisted row so a future DELETE-then-reuse can't lazy-
    // recover a session the client explicitly tore down. Best-effort —
    // pruner reaps stragglers.
    mcpSessionsRepository
      .delete(sessionId)
      .catch((error: unknown) =>
        logger.warn(
          `mcp_sessions delete failed for session ${sessionId}; will be reaped by pruner.`,
          error,
        ),
      );

    logger.info(`Session ${sessionId} cleanup completed successfully`);
  } catch (error) {
    logger.error(`Error during cleanup of session ${sessionId}:`, error);
    // Even if cleanup fails, remove the session from manager to prevent memory leaks
    sessionManager.removeSession(sessionId);
    logger.info(`Removed orphaned session ${sessionId} due to cleanup error`);
    throw error;
  }
};

/**
 * Periodic pruner for the `mcp_sessions` table. Runs on boot + every
 * `MCP_SESSION_PRUNER_INTERVAL_MS` (default 24h). Deletes rows whose
 * `last_seen_at` is older than `MCP_SESSION_TTL_DAYS` days (default 7).
 *
 * Both knobs are env-configurable so operators can dial recovery
 * window vs DB-row volume per their tolerance:
 *
 *   MCP_SESSION_TTL_DAYS=14         # generous: 2 weeks of recovery
 *   MCP_SESSION_PRUNER_INTERVAL_MS=3600000   # check hourly instead of daily
 *
 * Setting `MCP_SESSION_TTL_DAYS=0` disables pruning entirely (rows
 * accumulate forever — only useful for forensic debugging).
 */
function getSessionTtlDays(): number {
  const raw = process.env.MCP_SESSION_TTL_DAYS;
  if (!raw) return 7;
  const parsed = Number.parseInt(raw, 10);
  if (Number.isNaN(parsed) || parsed < 0) {
    logger.warn(
      `MCP_SESSION_TTL_DAYS=${raw} invalid; falling back to default 7 days.`,
    );
    return 7;
  }
  return parsed;
}

function getSessionPrunerIntervalMs(): number {
  const raw = process.env.MCP_SESSION_PRUNER_INTERVAL_MS;
  if (!raw) return 24 * 60 * 60 * 1000;
  const parsed = Number.parseInt(raw, 10);
  if (Number.isNaN(parsed) || parsed < 60_000) {
    // Sub-minute intervals would just hammer postgres for no benefit;
    // floor to 60s and warn.
    logger.warn(
      `MCP_SESSION_PRUNER_INTERVAL_MS=${raw} invalid or <60000; falling back to 24h.`,
    );
    return 24 * 60 * 60 * 1000;
  }
  return parsed;
}

async function runMcpSessionPrune(): Promise<void> {
  const ttlDays = getSessionTtlDays();
  if (ttlDays === 0) {
    logger.info("MCP_SESSION_TTL_DAYS=0; mcp_sessions pruning disabled.");
    return;
  }
  const cutoff = new Date(Date.now() - ttlDays * 24 * 60 * 60 * 1000);
  try {
    const deleted = await mcpSessionsRepository.pruneOlderThan(cutoff);
    if (deleted > 0) {
      logger.info(
        `mcp_sessions pruner: reaped ${deleted} session(s) older than ${ttlDays} day(s) (cutoff ${cutoff.toISOString()}).`,
      );
    }
  } catch (error) {
    logger.error("mcp_sessions pruner: postgres delete failed.", error);
  }
}

let mcpSessionPrunerTimer: NodeJS.Timeout | null = null;

export function startMcpSessionPruner(): void {
  if (mcpSessionPrunerTimer) return;
  // Boot run — clear out anything left from previous lifetimes.
  void runMcpSessionPrune();
  const intervalMs = getSessionPrunerIntervalMs();
  mcpSessionPrunerTimer = setInterval(
    () => void runMcpSessionPrune(),
    intervalMs,
  );
  // Don't keep the process alive on shutdown for the sake of pruning.
  if (mcpSessionPrunerTimer.unref) mcpSessionPrunerTimer.unref();
  logger.info(
    `mcp_sessions pruner armed (interval=${intervalMs}ms, ttl_days=${getSessionTtlDays()}).`,
  );
}

export function stopMcpSessionPruner(): void {
  if (mcpSessionPrunerTimer) {
    clearInterval(mcpSessionPrunerTimer);
    mcpSessionPrunerTimer = null;
  }
}

startMcpSessionPruner();

// Health check endpoint to monitor sessions
streamableHttpRouter.get("/health/sessions", (req, res) => {
  const sessionIds = sessionManager.getSessionIds();
  const poolStatus = metaMcpServerPool.getPoolStatus();

  res.json({
    timestamp: new Date().toISOString(),
    streamableHttpSessions: {
      count: sessionIds.length,
      sessionIds: sessionIds,
    },
    metaMcpPoolStatus: poolStatus,
    totalActiveSessions: sessionIds.length + poolStatus.active,
  });
});

streamableHttpRouter.get(
  "/:endpoint_name/mcp",
  lookupEndpoint,
  authenticateApiKey,
  rateLimitMiddleware,
  async (req, res) => {
    // const authReq = req as ApiKeyAuthenticatedRequest;
    // const { namespaceUuid, endpointName } = authReq;
    const sessionId = req.headers["mcp-session-id"] as string;

    // logger.info(
    //   `Received GET message for public endpoint ${endpointName} -> namespace ${namespaceUuid} sessionId ${sessionId}`,
    // );

    try {
      logger.info(`Looking up existing session: ${sessionId}`);

      const authReq = req as ApiKeyAuthenticatedRequest;
      let transport = sessionManager.getSession(sessionId);
      if (!transport) {
        logger.info(
          `Session ${sessionId} not found in session manager — attempting lazy recovery from mcp_sessions.`,
        );
        const recovery = await recoverPersistedSession(sessionId, authReq);
        if (recovery.status === "recovered") {
          transport = recovery.transport;
        } else if (recovery.status === "auth_failed") {
          res.status(401).end("Unauthorized");
          return;
        } else {
          // Stale or expired sessionId. Per MCP Streamable HTTP spec the
          // client MUST start a new session in response to HTTP 404 on a
          // sessioned request. Surface a header-flag for clients that
          // honor the contract, and keep the response body minimal
          // (the previous body dumped the full active-session list into
          // logs/clients — info leak + not actionable).
          res
            .status(404)
            .setHeader("Mcp-Session-Reinitialize-Required", "true")
            .end(
              "Session expired or unknown. Initialize a new MCP session " +
                "(send `initialize` without an `Mcp-Session-Id` header).",
            );
          return;
        }
      }
      logger.info(`Handling GET for session ${sessionId}`);
      await transport.handleRequest(req, res);
    } catch (error) {
      logger.error("Error in public endpoint /mcp route:", error);
      res.status(500).json(error);
    }
  },
);

streamableHttpRouter.post(
  "/:endpoint_name/mcp",
  lookupEndpoint,
  authenticateApiKey,
  rateLimitMiddleware,
  async (req, res) => {
    const authReq = req as ApiKeyAuthenticatedRequest;
    const { namespaceUuid, endpointName } = authReq;
    const sessionId = req.headers["mcp-session-id"] as string | undefined;

    // Log authentication information for debugging
    logger.info(`POST /mcp request for endpoint: ${endpointName}`);
    logger.info(`Authentication method: ${authReq.authMethod || "none"}`);
    logger.info(`Session ID: ${sessionId || "new session"}`);

    if (!sessionId) {
      try {
        logger.info(
          `New public endpoint StreamableHttp connection request for ${endpointName} -> namespace ${namespaceUuid}`,
        );

        // Generate session ID upfront
        const newSessionId = randomUUID();
        logger.info(
          `Generated new session ID: ${newSessionId} for endpoint: ${endpointName}`,
        );

        // Get or create MetaMCP server instance from the pool
        const mcpServerInstance = await metaMcpServerPool.getServer(
          newSessionId,
          namespaceUuid,
        );
        if (!mcpServerInstance) {
          throw new Error("Failed to get MetaMCP server instance from pool");
        }

        logger.info(
          `Using MetaMCP server instance for public endpoint session ${newSessionId} (endpoint: ${endpointName})`,
        );

        // Create transport with the predetermined session ID
        const transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: () => newSessionId,
          onsessioninitialized: async (sessionId) => {
            try {
              logger.info(`Session initialized for sessionId: ${sessionId}`);
            } catch (error) {
              logger.error(
                `Error initializing public endpoint session ${sessionId}:`,
                error,
              );
            }
          },
        });

        // Note: Cleanup is handled explicitly via DELETE requests
        // StreamableHTTP is designed to persist across multiple requests
        logger.info("Created public endpoint StreamableHttp transport");
        logger.info(
          `Session ${newSessionId} will be cleaned up when DELETE request is received`,
        );

        // Store transport reference
        sessionManager.addSession(newSessionId, transport);

        logger.info(
          `Public Endpoint Client <-> Proxy sessionId: ${newSessionId} for endpoint ${endpointName} -> namespace ${namespaceUuid}`,
        );
        logger.info(`Stored transport for sessionId: ${newSessionId}`);
        logger.info(`Current stored sessions:`, sessionManager.getSessionIds());
        logger.info(
          `Total active sessions: ${sessionManager.getSessionCount()}`,
        );

        // Connect the server to the transport before handling the request
        await mcpServerInstance.server.connect(transport);

        // Persist the session row so a later metamcp restart can lazy-
        // recover this consumer's cached sessionId. Best-effort — a DB
        // outage during init shouldn't block the consumer; they'll just
        // lose the post-restart recovery path until the next init.
        const rawToken = extractRawTokenForPrincipal(req);
        if (rawToken) {
          const authMethod = authMethodFromRequest(authReq);
          const principal = hashAuthPrincipal(rawToken, authMethod);
          mcpSessionsRepository
            .persist({
              session_id: newSessionId,
              namespace_uuid: namespaceUuid,
              endpoint_name: endpointName,
              auth_principal: principal,
              auth_method: authMethod,
              init_params: {},
            })
            .catch((error: unknown) =>
              logger.warn(
                `mcp_sessions persist failed for session ${newSessionId}; lazy-recovery will be unavailable for this consumer until next init.`,
                error,
              ),
            );
        } else {
          logger.warn(
            `Session ${newSessionId} initialized without a recognizable credential; skipping mcp_sessions persist (recovery unavailable).`,
          );
        }

        // Now handle the request - server is guaranteed to be ready
        await transport.handleRequest(req, res);
      } catch (error) {
        logger.error("Error in public endpoint /mcp POST route:", error);

        // Provide more detailed error information
        const errorMessage =
          error instanceof Error ? error.message : "Unknown error";
        res.status(500).json({
          error: "Internal server error",
          message: errorMessage,
          endpoint: endpointName,
          timestamp: new Date().toISOString(),
        });
      }
    } else {
      // logger.info(
      //   `Received POST message for public endpoint ${endpointName} -> namespace ${namespaceUuid} sessionId ${sessionId}`,
      // );
      logger.info(`Available session IDs:`, sessionManager.getSessionIds());
      logger.info(`Looking for sessionId: ${sessionId}`);
      try {
        logger.info(`Looking up existing session: ${sessionId}`);
        logger.info(`Available sessions:`, sessionManager.getSessionIds());

        let transport = sessionManager.getSession(sessionId);
        if (!transport) {
          logger.info(
            `Transport for sessionId ${sessionId} not in memory — attempting lazy recovery from mcp_sessions.`,
          );
          const recovery = await recoverPersistedSession(sessionId, authReq);
          if (recovery.status === "recovered") {
            transport = recovery.transport;
            // Bump idempotently so subsequent same-session reads hit the
            // in-memory map; touch already happened inside recovery.
          } else if (recovery.status === "auth_failed") {
            logger.warn(
              `Lazy recovery refused for session ${sessionId}: auth principal mismatch or missing credential.`,
            );
            res.status(401).json({
              error: "Unauthorized",
              message:
                "Stored auth principal does not match incoming credential.",
              timestamp: new Date().toISOString(),
            });
            return;
          } else {
            logger.error(
              `Transport not found for sessionId ${sessionId} and no recoverable persisted row.`,
            );
            // Stale or expired sessionId. The prior response embedded
            // `available_sessions: sessionManager.getSessionIds()` —
            // a mild info leak of every live session UUID into client
            // logs + zero diagnostic value to the caller (the caller
            // just learns their own ID isn't in the list, which the
            // 404 already conveyed).
            //
            // Per MCP Streamable HTTP spec the client MUST start a new
            // session in response to HTTP 404 on a sessioned request.
            // The `Mcp-Session-Reinitialize-Required` header signals
            // that explicitly for spec-conformant clients; the body
            // message guides anyone reading it manually.
            //
            // Background: 2026-05-15 sub-agent validation run on the
            // CIPP MCP namespace hit this path 100% — Claude Code's
            // MCP connector held a sessionId rotated out by the server,
            // and the harness didn't auto-reinitialize on 404. Until
            // the client side honors reinit, this is the cleanest
            // server-side signal we can hand it. Task #29 has the
            // full background.
            res
              .status(404)
              .setHeader("Mcp-Session-Reinitialize-Required", "true")
              .json({
                error: "Session not found",
                message:
                  "Session expired or unknown. Initialize a new MCP " +
                  "session (send `initialize` without an " +
                  "`Mcp-Session-Id` header).",
                timestamp: new Date().toISOString(),
              });
            return;
          }
        }
        logger.info(`Handling POST for session ${sessionId}`);
        await transport.handleRequest(req, res);
      } catch (error) {
        logger.error("Error in public endpoint /mcp route:", error);

        const errorMessage =
          error instanceof Error ? error.message : "Unknown error";
        res.status(500).json({
          error: "Internal server error",
          message: errorMessage,
          session_id: sessionId,
          endpoint: endpointName,
          timestamp: new Date().toISOString(),
        });
      }
    }
  },
);

streamableHttpRouter.delete(
  "/:endpoint_name/mcp",
  lookupEndpoint,
  authenticateApiKey,
  rateLimitMiddleware,
  async (req, res) => {
    const authReq = req as ApiKeyAuthenticatedRequest;
    const { namespaceUuid, endpointName } = authReq;
    const sessionId = req.headers["mcp-session-id"] as string | undefined;

    logger.info(
      `Received DELETE message for public endpoint ${endpointName} -> namespace ${namespaceUuid} sessionId ${sessionId}`,
    );

    if (sessionId) {
      try {
        logger.info(`Starting cleanup for session ${sessionId}`);
        logger.info(
          `Available sessions before cleanup:`,
          sessionManager.getSessionIds(),
        );

        await cleanupSession(sessionId);

        logger.info(
          `Public endpoint session ${sessionId} cleaned up successfully`,
        );
        logger.info(
          `Available sessions after cleanup:`,
          sessionManager.getSessionIds(),
        );

        res.status(200).json({
          message: "Session cleaned up successfully",
          sessionId: sessionId,
          remainingSessions: sessionManager.getSessionIds(),
        });
      } catch (error) {
        logger.error("Error in public endpoint /mcp DELETE route:", error);
        res.status(500).json({
          error: "Cleanup failed",
          message: error instanceof Error ? error.message : "Unknown error",
          sessionId: sessionId,
        });
      }
    } else {
      res.status(400).json({
        error: "Missing sessionId",
        message: "sessionId header is required for cleanup",
      });
    }
  },
);

// Initialize automatic cleanup timer using session manager
sessionManager.startCleanupTimer(async (sessionId, transport) => {
  await cleanupSession(sessionId, transport);
});

export default streamableHttpRouter;
