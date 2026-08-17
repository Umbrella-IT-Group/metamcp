import { randomUUID } from "node:crypto";

import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import express from "express";

import type { AuditAttributedRequest } from "@/lib/audit/audit-emitter";
import logger from "@/utils/logger";

import { resolveCallerContext } from "../../lib/metamcp/caller-context";
import {
  CallerContext,
  runWithCallerContext,
} from "../../lib/metamcp/caller-context-store";
import { createServer } from "../../lib/metamcp/index";
import { mcpServerPool } from "../../lib/metamcp/mcp-server-pool";

const metamcpRouter = express.Router();

/**
 * The session user, as `betterAuthMcpMiddleware` leaves it on the request —
 * same shape `requireAdminMcpMiddleware` and `mcp-proxy/server.ts` read.
 */
type SessionUser = { id?: string; role?: string };

/**
 * Caller binding for tool calls driven from the Inspector (migration 0030).
 *
 * Every route here is admin-session-gated by the parent router, so the actor
 * is a better-auth user rather than a credential: there is no api-key uuid and
 * no OAuth token to record. Without this the tool calls an admin makes while
 * testing a namespace wrote fully un-attributed audit rows, which read exactly
 * like rows from a path that lost its identity plumbing.
 *
 * `auth_method` is therefore a THIRD value, `session`, and it is the
 * discriminator for this traffic — which is why no `clientName` label is
 * invented here. That column means "the resolved consumer identity"
 * (api-key name / OAuth user email) and there is no consumer on this surface.
 * `callerIp` / `requestId` still come from `auditContextMiddleware`, which is
 * mounted app-wide ahead of every router.
 */
export function inspectorCaller(req: express.Request): CallerContext {
  const user = (req as express.Request & { user?: SessionUser }).user;
  return {
    ...resolveCallerContext(req as AuditAttributedRequest),
    authMethod: "session",
    userId: user?.id,
  };
}

// Auth (session) and authorization (admin-only) are applied once by the
// parent router in `routers/mcp-proxy.ts`, so every route below is already
// admin-gated by the time it runs. This is the Inspector's namespace-testing
// surface, NOT the production endpoint path — API-key/OAuth clients reach
// namespaces through `routers/public-metamcp` mounted at /metamcp, which is
// untouched by that gate.

const webAppTransports: Map<string, Transport> = new Map<string, Transport>(); // Web app transports by sessionId
const metamcpServers: Map<
  string,
  {
    server: Awaited<ReturnType<typeof createServer>>["server"];
    cleanup: () => Promise<void>;
  }
> = new Map(); // MetaMCP servers by sessionId

// Create a MetaMCP server instance
const createMetaMcpServer = async (
  namespaceUuid: string,
  sessionId: string,
  includeInactiveServers: boolean = false,
) => {
  const { server, cleanup } = await createServer(
    namespaceUuid,
    sessionId,
    includeInactiveServers,
  );
  return { server, cleanup };
};

// Cleanup function for a specific session
const cleanupSession = async (sessionId: string) => {
  logger.info(`Cleaning up session ${sessionId}`);

  // Clean up transport
  const transport = webAppTransports.get(sessionId);
  if (transport) {
    webAppTransports.delete(sessionId);
    await transport.close();
  }

  // Clean up server instance
  const serverInstance = metamcpServers.get(sessionId);
  if (serverInstance) {
    metamcpServers.delete(sessionId);
    await serverInstance.cleanup();
  }

  // Clean up session connections
  await mcpServerPool.cleanupSession(sessionId);
};

metamcpRouter.get("/:uuid/mcp", async (req, res) => {
  // const namespaceUuid = req.params.uuid;
  const sessionId = req.headers["mcp-session-id"] as string;
  // logger.info(
  //   `Received GET message for MetaMCP namespace ${namespaceUuid} sessionId ${sessionId}`,
  // );
  try {
    const transport = webAppTransports.get(
      sessionId,
    ) as StreamableHTTPServerTransport;
    if (!transport) {
      res.status(404).end("Session not found");
      return;
    } else {
      await transport.handleRequest(req, res);
    }
  } catch (error) {
    logger.error("Error in MetaMCP /mcp route:", error);
    res.status(500).json(error);
  }
});

metamcpRouter.post("/:uuid/mcp", async (req, res) => {
  const namespaceUuid = req.params.uuid;
  const sessionId = req.headers["mcp-session-id"] as string | undefined;
  let mcpServerInstance:
    | {
        server: Awaited<ReturnType<typeof createServer>>["server"];
        cleanup: () => Promise<void>;
      }
    | undefined;

  if (!sessionId) {
    try {
      logger.info(
        `New MetaMCP StreamableHttp connection request for namespace ${namespaceUuid}`,
      );

      const webAppTransport = new StreamableHTTPServerTransport({
        sessionIdGenerator: randomUUID,
        onsessioninitialized: async (newSessionId) => {
          try {
            // Extract includeInactiveServers from query parameters
            const includeInactiveServers =
              req.query.includeInactiveServers === "true";

            // Create MetaMCP server instance with sessionId
            mcpServerInstance = await createMetaMcpServer(
              namespaceUuid,
              newSessionId,
              includeInactiveServers,
            );
            logger.info(
              `Created MetaMCP server instance for session ${newSessionId}`,
            );

            webAppTransports.set(newSessionId, webAppTransport);
            metamcpServers.set(newSessionId, mcpServerInstance);

            logger.info(
              `MetaMCP Client <-> Proxy sessionId: ${newSessionId} for namespace ${namespaceUuid}`,
            );

            await mcpServerInstance.server.connect(webAppTransport);

            // Handle cleanup when connection closes
            res.on("close", async () => {
              logger.info(
                `MetaMCP connection closed for session ${newSessionId}`,
              );
              await cleanupSession(newSessionId);
            });
          } catch (error) {
            logger.error(`Error initializing session ${newSessionId}:`, error);
          }
        },
      });
      logger.info("Created MetaMCP StreamableHttp transport");

      await runWithCallerContext(inspectorCaller(req), () =>
        (webAppTransport as StreamableHTTPServerTransport).handleRequest(
          req,
          res,
          req.body,
        ),
      );
    } catch (error) {
      logger.error("Error in MetaMCP /mcp POST route:", error);
      res.status(500).json(error);
    }
  } else {
    // logger.info(
    //   `Received POST message for MetaMCP namespace ${namespaceUuid} sessionId ${sessionId}`,
    // );
    try {
      const transport = webAppTransports.get(
        sessionId,
      ) as StreamableHTTPServerTransport;
      if (!transport) {
        res.status(404).end("Transport not found for sessionId " + sessionId);
      } else {
        await runWithCallerContext(inspectorCaller(req), () =>
          (transport as StreamableHTTPServerTransport).handleRequest(req, res),
        );
      }
    } catch (error) {
      logger.error("Error in MetaMCP /mcp route:", error);
      res.status(500).json(error);
    }
  }
});

metamcpRouter.delete("/:uuid/mcp", async (req, res) => {
  const namespaceUuid = req.params.uuid;
  const sessionId = req.headers["mcp-session-id"] as string | undefined;
  logger.info(
    `Received DELETE message for MetaMCP namespace ${namespaceUuid} sessionId ${sessionId}`,
  );

  if (sessionId) {
    try {
      await cleanupSession(sessionId);
      logger.info(`MetaMCP session ${sessionId} cleaned up successfully`);
      res.status(200).end();
    } catch (error) {
      logger.error("Error in MetaMCP /mcp DELETE route:", error);
      res.status(500).json(error);
    }
  } else {
    res.status(400).end("Missing sessionId");
  }
});

metamcpRouter.get("/:uuid/sse", async (req, res) => {
  const namespaceUuid = req.params.uuid;
  const includeInactiveServers = req.query.includeInactiveServers === "true";

  try {
    logger.info(
      `New MetaMCP SSE connection request for namespace ${namespaceUuid}, includeInactiveServers: ${includeInactiveServers}`,
    );

    const webAppTransport = new SSEServerTransport(
      `/mcp-proxy/metamcp/${namespaceUuid}/message`,
      res,
    );
    logger.info("Created MetaMCP SSE transport");

    const sessionId = webAppTransport.sessionId;

    // Create MetaMCP server instance with sessionId and includeInactiveServers flag
    const mcpServerInstance = await createMetaMcpServer(
      namespaceUuid,
      sessionId,
      includeInactiveServers,
    );
    logger.info(`Created MetaMCP server instance for session ${sessionId}`);

    webAppTransports.set(sessionId, webAppTransport);
    metamcpServers.set(sessionId, mcpServerInstance);

    // Handle cleanup when connection closes
    res.on("close", async () => {
      logger.info(`MetaMCP SSE connection closed for session ${sessionId}`);
      await cleanupSession(sessionId);
    });

    await mcpServerInstance.server.connect(webAppTransport);
  } catch (error) {
    logger.error("Error in MetaMCP /sse route:", error);
    res.status(500).json(error);
  }
});

metamcpRouter.post("/:uuid/message", async (req, res) => {
  // const namespaceUuid = req.params.uuid;
  try {
    const sessionId = req.query.sessionId;
    // logger.info(
    //   `Received POST message for MetaMCP namespace ${namespaceUuid} sessionId ${sessionId}`,
    // );

    const transport = webAppTransports.get(
      sessionId as string,
    ) as SSEServerTransport;
    if (!transport) {
      res.status(404).end("Session not found");
      return;
    }
    await runWithCallerContext(inspectorCaller(req), () =>
      transport.handlePostMessage(req, res),
    );
  } catch (error) {
    logger.error("Error in MetaMCP /message route:", error);
    res.status(500).json(error);
  }
});

metamcpRouter.get("/health", (req, res) => {
  res.json({
    status: "ok",
    service: "metamcp",
  });
});

metamcpRouter.get("/info", (req, res) => {
  res.json({
    service: "metamcp",
    version: "1.0.0",
    description: "MetaMCP unified MCP proxy service",
  });
});

export default metamcpRouter;
