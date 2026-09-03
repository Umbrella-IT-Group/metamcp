import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import express from "express";

import {
  ApiKeyAuthenticatedRequest,
  authenticateApiKey,
} from "@/middleware/api-key-oauth.middleware";
import { lookupEndpoint } from "@/middleware/lookup-endpoint-middleware";
import { rateLimitMiddleware } from "@/middleware/rate-limit.middleware";
import logger from "@/utils/logger";

import {
  resolveCallerContext,
  stampCallerContext,
} from "../../lib/metamcp/caller-context";
import { runWithCallerContext } from "../../lib/metamcp/caller-context-store";
import { resolveClientIdentity } from "../../lib/metamcp/consumer-identity-resolver";
import {
  checkConcurrentSessionCeiling,
  registerSessionCounter,
} from "../../lib/metamcp/credential-session-quota";
import { metaMcpServerPool } from "../../lib/metamcp/metamcp-server-pool";
import { resolveSessionIdentity } from "../../lib/metamcp/session-auth";
import { emitSessionBindingDenial } from "../../lib/metamcp/session-binding-denial";
import {
  boundSessionMatches,
  classifyBindingDenial,
  SessionBinding,
  SessionBindingDenialReason,
  SessionLifetimeManager,
  SessionLifetimeManagerImpl,
} from "../../lib/session-lifetime-manager";

/**
 * The full binding a request presents — endpoint plus the identity
 * `authenticateApiKey` resolved for it. The SSE twin of streamable-http's
 * `requestBinding`.
 */
function requestBinding(authReq: ApiKeyAuthenticatedRequest): SessionBinding {
  return {
    namespaceUuid: authReq.namespaceUuid,
    endpointName: authReq.endpointName,
    identity: resolveSessionIdentity(authReq),
  };
}

/**
 * Pure resolver for the `/message` leg's ownership guard — the SSE twin of
 * streamable-http's `resolveBoundSession`. The message must target the SAME
 * endpoint the SSE stream was opened on AND come from the credential that
 * opened it: resolving by sessionId alone would let a caller authenticated for
 * endpoint A post messages into endpoint B's transport, and — on any endpoint
 * reachable by more than one credential — let one consumer post into another
 * consumer's stream.
 *
 * A missing session and a session owned by someone else both resolve to
 * `not_found` so the route's 404 never signals the id is live elsewhere.
 * `refusedReason` exists ONLY to drive the server-side warn log and audit row,
 * never the response shape: it is non-null exactly when a session WAS resident
 * and was refused, and null for a genuine miss. One field rather than a
 * separate boolean plus a reason, so the fact of a refusal and its recorded
 * cause cannot disagree.
 *
 * The resolver stays PURE — it emits nothing. The route below owns the audit
 * row, because that is where the authenticated request lives; keeping the
 * emission out of here is what lets `sse.test.ts` drive the guard against a
 * seeded manager with no express harness and no postgres.
 */
export function resolveSseMessageSession(
  manager: Pick<
    SessionLifetimeManager<Transport>,
    "getSession" | "getSessionBinding"
  >,
  sessionId: string,
  target: SessionBinding,
):
  | { outcome: "ok"; transport: Transport }
  | { outcome: "not_found"; refusedReason: SessionBindingDenialReason | null } {
  const transport = manager.getSession(sessionId);
  if (!transport) {
    return { outcome: "not_found", refusedReason: null };
  }
  const binding = manager.getSessionBinding(sessionId);
  if (!boundSessionMatches(binding, target)) {
    return {
      outcome: "not_found",
      refusedReason: classifyBindingDenial(binding, target),
    };
  }
  return { outcome: "ok", transport };
}

/**
 * Record a refused `/message` — one durable audit row and one warn line, both
 * under the SAME throttle decision. The streamable-http twin is
 * `refuseBoundSession`.
 *
 * A stream-hijack attempt must leave something an operator can query, not just
 * a log line: this fork treats `audit_log` as the stolen-key detector, and a
 * refusal that only warns is invisible to it. The log is throttled alongside
 * the row because this is output a REFUSED caller paces — one line per attempt
 * turns an id sweep into a flood that buries the first line, the one worth
 * reading.
 *
 * Exported so the emission can be asserted directly, and so
 * `resolveSseMessageSession` can stay pure. That alone does not pin the route:
 * a test that only calls this function is still green once the route stops
 * calling it, which is why `__seedSseSessionForTesting` below exists.
 */
export function refuseSseMessage(
  authReq: ApiKeyAuthenticatedRequest,
  sessionId: string,
  reason: SessionBindingDenialReason,
): void {
  const { emitted, suppressed } = emitSessionBindingDenial(authReq, {
    sessionId,
    reason,
  });
  if (emitted) {
    logger.warn(
      `SSE message for session ${sessionId} on endpoint ${authReq.endpointName} ` +
        `refused (${reason}). ` +
        `${suppressed} similar refusal(s) suppressed since the last line.`,
    );
  }
}

const sseRouter = express.Router();

// Session lifetime manager for SSE sessions
const sessionManager = new SessionLifetimeManagerImpl<Transport>("SSE");

// Register as a source of live-session counts for the per-credential
// concurrent-session ceiling, so a credential's budget spans SSE and
// StreamableHTTP together rather than being counted separately per transport.
registerSessionCounter(sessionManager);

/**
 * Put a bound session into the module's REAL map — tests only. The
 * streamable-http twin is `recoverPersistedSession`, which tests can drive
 * because recovery is a production entry point; SSE has no equivalent, since
 * the only production writer of this map is a live stream-open needing a real
 * transport and a real pooled server.
 *
 * Without this seam the `/message` route is unreachable from a test: the guard
 * always resolves "absent", which carries a null `refusedReason` and so skips
 * the refusal branch entirely. That left the branch's wiring unpinned — the
 * route's `refuseSseMessage` call could be deleted and the suite stayed green,
 * meaning nothing would catch the SSE leg silently going back to log-only.
 */
export function __seedSseSessionForTesting(
  sessionId: string,
  transport: Transport,
  binding?: SessionBinding,
): void {
  sessionManager.addSession(sessionId, transport, binding);
}

/** Companion seam: drop a seeded session without running cleanup side effects. */
export function __removeSseSessionForTesting(sessionId: string): void {
  sessionManager.removeSession(sessionId);
}

// Cleanup function for a specific session
const cleanupSession = async (sessionId: string, transport?: Transport) => {
  logger.info(`Cleaning up SSE session ${sessionId}`);

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

    logger.info(`Session ${sessionId} cleanup completed successfully`);
  } catch (error) {
    logger.error(`Error during cleanup of session ${sessionId}:`, error);
    // Even if cleanup fails, remove the session from manager to prevent memory leaks
    sessionManager.removeSession(sessionId);
    logger.info(`Removed orphaned session ${sessionId} due to cleanup error`);
    throw error;
  }
};

sseRouter.get(
  "/:endpoint_name/sse",
  lookupEndpoint,
  authenticateApiKey,
  rateLimitMiddleware,
  async (req, res, next) => {
    const authReq = req as ApiKeyAuthenticatedRequest;
    const { namespaceUuid, endpointName } = authReq;

    try {
      // Per-credential concurrent-session ceiling, enforced at creation: the
      // same budget the StreamableHTTP path enforces, shared across both
      // transports. Refuse before opening the stream so an over-budget
      // credential cannot keep accreting sessions that starve the backend pool.
      const ceiling = checkConcurrentSessionCeiling(
        resolveSessionIdentity(authReq),
      );
      if (!ceiling.allowed) {
        res.status(429).json({
          error: `Too many concurrent sessions for this credential (${ceiling.current}/${ceiling.ceiling}). Close idle sessions, or ask an administrator to raise MCP_MAX_SESSIONS_PER_CREDENTIAL.`,
        });
        return;
      }

      logger.info(
        `New public endpoint SSE connection request for ${endpointName} -> namespace ${namespaceUuid}`,
      );

      const webAppTransport = new SSEServerTransport(
        `/metamcp/${endpointName}/message`,
        res,
      );
      logger.info("Created public endpoint SSE transport");

      const sessionId = webAppTransport.sessionId;

      // Get or create MetaMCP server instance from the pool
      const mcpServerInstance = await metaMcpServerPool.getServer(
        sessionId,
        namespaceUuid,
      );
      if (!mcpServerInstance) {
        throw new Error("Failed to get MetaMCP server instance from pool");
      }

      logger.info(
        `Using MetaMCP server instance for public endpoint session ${sessionId}`,
      );

      // Stamp the caller onto the acquired instance so tool calls arriving on
      // the /message leg are attributable (migration 0030). Fallback carrier
      // only — the authoritative per-request binding is entered on that leg
      // itself; this covers the window before the first message and any call
      // that reaches the auditing middleware outside a request scope.
      const clientIdentity = await resolveClientIdentity(authReq);
      stampCallerContext(
        mcpServerInstance.handlerContext,
        authReq,
        clientIdentity?.name,
      );

      // Bind the session to the endpoint it was opened on AND to the
      // credential that opened it, so the message leg below can reject a
      // sessionId replayed against a different endpoint or presented by a
      // different consumer.
      sessionManager.addSession(
        sessionId,
        webAppTransport,
        requestBinding(authReq),
      );

      // Handle cleanup when connection closes
      res.on("close", async () => {
        logger.info(
          `Public endpoint SSE connection closed for session ${sessionId}`,
        );
        await cleanupSession(sessionId);
      });

      await mcpServerInstance.server.connect(webAppTransport);
    } catch (error) {
      logger.error("Error in public endpoint /sse route:", error);
      // Constant body via the terminal error handler (middleware/error-handler)
      // instead of serializing the raw error object to the client; it also
      // destroys an already streaming SSE socket correctly.
      return next(error);
    }
  },
);

sseRouter.post(
  "/:endpoint_name/message",
  lookupEndpoint,
  authenticateApiKey,
  rateLimitMiddleware,
  async (req, res, next) => {
    const authReq = req as ApiKeyAuthenticatedRequest;

    try {
      const sessionId = req.query.sessionId as string;

      // Ownership guard — see resolveSseMessageSession's doc comment.
      const resolution = resolveSseMessageSession(
        sessionManager,
        sessionId,
        requestBinding(authReq),
      );
      if (resolution.outcome === "not_found") {
        if (resolution.refusedReason) {
          refuseSseMessage(authReq, sessionId, resolution.refusedReason);
        }
        res.status(404).end("Session not found");
        return;
      }
      // This leg drives `tools/call` for every SSE consumer, so it needs the
      // same request-scoped caller binding the Streamable-HTTP dispatch
      // enters — without it these calls audited as fully un-attributed rows,
      // which is indistinguishable from a path nobody uses. `authenticateApiKey`
      // has already run above, so the identity is on the request; the instance
      // stamped at stream-open cannot serve because the SSE session is
      // long-lived and `requestId` / `callerIp` are per-message facts.
      const clientIdentity = await resolveClientIdentity(authReq);
      await runWithCallerContext(
        { ...resolveCallerContext(authReq), clientName: clientIdentity?.name },
        () =>
          (resolution.transport as SSEServerTransport).handlePostMessage(
            req,
            res,
          ),
      );
    } catch (error) {
      logger.error("Error in public endpoint /message route:", error);
      // Constant body via the terminal error handler instead of serializing
      // the raw error object to the client.
      return next(error);
    }
  },
);

// Initialize automatic cleanup timer using session manager
sessionManager.startCleanupTimer(async (sessionId, transport) => {
  await cleanupSession(sessionId, transport);
});

export default sseRouter;
