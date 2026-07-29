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

import { metaMcpServerPool } from "../../lib/metamcp/metamcp-server-pool";
import {
  bindingMatches,
  SessionBinding,
  SessionLifetimeManager,
  SessionLifetimeManagerImpl,
} from "../../lib/session-lifetime-manager";

/**
 * Pure resolver for the `/message` leg's endpoint-binding guard — the SSE
 * twin of streamable-http's `getBoundSession`. The message must target the
 * SAME endpoint the SSE stream was opened on: resolving by sessionId alone
 * would let a caller authenticated for endpoint A post messages into
 * endpoint B's transport. A missing session and a cross-endpoint session
 * both resolve to `not_found` so the route's 404 never signals the id is
 * live elsewhere; `crossEndpoint` exists ONLY to drive the server-side
 * warn log, never the response shape. Takes the manager as a parameter so
 * the guard is unit-testable against a seeded manager (`sse.test.ts`).
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
  | { outcome: "not_found"; crossEndpoint: boolean } {
  const transport = manager.getSession(sessionId);
  if (!transport || !bindingMatches(manager.getSessionBinding(sessionId), target)) {
    return { outcome: "not_found", crossEndpoint: transport !== undefined };
  }
  return { outcome: "ok", transport };
}

const sseRouter = express.Router();

// Session lifetime manager for SSE sessions
const sessionManager = new SessionLifetimeManagerImpl<Transport>("SSE");

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
  async (req, res) => {
    const authReq = req as ApiKeyAuthenticatedRequest;
    const { namespaceUuid, endpointName } = authReq;

    try {
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

      // Bind the session to the endpoint it was opened on so the message leg
      // below can reject a sessionId replayed against a different endpoint.
      sessionManager.addSession(sessionId, webAppTransport, {
        namespaceUuid,
        endpointName,
      });

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
      res.status(500).json(error);
    }
  },
);

sseRouter.post(
  "/:endpoint_name/message",
  lookupEndpoint,
  authenticateApiKey,
  rateLimitMiddleware,
  async (req, res) => {
    const authReq = req as ApiKeyAuthenticatedRequest;
    const { namespaceUuid, endpointName } = authReq;

    try {
      const sessionId = req.query.sessionId as string;

      // Endpoint-binding guard — see resolveSseMessageSession's doc comment.
      const resolution = resolveSseMessageSession(sessionManager, sessionId, {
        namespaceUuid,
        endpointName,
      });
      if (resolution.outcome === "not_found") {
        if (resolution.crossEndpoint) {
          logger.warn(
            `SSE message for session ${sessionId} on endpoint ${endpointName} ` +
              `rejected — session bound to a different endpoint.`,
          );
        }
        res.status(404).end("Session not found");
        return;
      }
      await (resolution.transport as SSEServerTransport).handlePostMessage(
        req,
        res,
      );
    } catch (error) {
      logger.error("Error in public endpoint /message route:", error);
      res.status(500).json(error);
    }
  },
);

// Initialize automatic cleanup timer using session manager
sessionManager.startCleanupTimer(async (sessionId, transport) => {
  await cleanupSession(sessionId, transport);
});

export default sseRouter;
