import { ListToolsRequest } from "@modelcontextprotocol/sdk/types.js";
import express from "express";

import {
  ApiKeyAuthenticatedRequest,
  authenticateApiKey,
} from "@/middleware/api-key-oauth.middleware";
import logger from "@/utils/logger";

import { metaMcpServerPool } from "../../../lib/metamcp/metamcp-server-pool";
import { lookupEndpoint } from "../../../middleware/lookup-endpoint-middleware";
import { createMiddlewareEnabledHandlers } from "./handlers";
import { generateOpenApiSchema } from "./schema-generator";
import {
  renderSwaggerUiHtml,
  swaggerUiCsp,
  swaggerUiNonce,
} from "./swagger-ui";
import { executeToolWithMiddleware } from "./tool-execution";
import { ToolExecutionRequest } from "./types";

const openApiRouter = express.Router();

// Generic API endpoint that serves the OpenAPI docs UI
openApiRouter.get(
  "/:endpoint_name/api",
  lookupEndpoint,
  authenticateApiKey,
  async (req, res) => {
    const { endpointName } = req as ApiKeyAuthenticatedRequest;

    // Build the Swagger UI page from the escaping/SRI/CSP-aware builder. The
    // endpoint name comes from the request URL, so it is escaped there; the one
    // inline script gets a per-response nonce that the CSP below authorises, and
    // the CDN assets are integrity-pinned. See ./swagger-ui.
    const nonce = swaggerUiNonce();
    res.setHeader("Content-Type", "text/html");
    res.setHeader("Content-Security-Policy", swaggerUiCsp(nonce));
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.send(renderSwaggerUiHtml(endpointName, nonce));
  },
);

// OpenAPI JSON schema endpoint (must come before tool execution routes)
openApiRouter.get(
  "/:endpoint_name/api/openapi.json",
  lookupEndpoint,
  authenticateApiKey,
  async (req, res) => {
    const { namespaceUuid, endpointName } = req as ApiKeyAuthenticatedRequest;

    try {
      // Get or create persistent OpenAPI session for this namespace
      const mcpServerInstance =
        await metaMcpServerPool.getOpenApiServer(namespaceUuid);
      if (!mcpServerInstance) {
        throw new Error("Failed to get MetaMCP server instance from pool");
      }

      // Use deterministic session ID for OpenAPI endpoints
      const sessionId = `openapi_${namespaceUuid}`;

      // Create middleware-enabled handlers
      const { handlerContext, listToolsWithMiddleware } =
        createMiddlewareEnabledHandlers(sessionId, namespaceUuid);

      // Use middleware-enabled list tools handler
      const listToolsRequest: ListToolsRequest = {
        method: "tools/list",
        params: {},
      };

      const result = await listToolsWithMiddleware(
        listToolsRequest,
        handlerContext,
      );

      const openApiSchema = await generateOpenApiSchema(
        result.tools || [],
        endpointName,
      );

      res.json(openApiSchema);
    } catch (error) {
      logger.error("Error generating OpenAPI schema:", error);
      res.status(500).json({
        error: "Internal server error",
        message: "Failed to generate OpenAPI schema",
        timestamp: new Date().toISOString(),
      });
    }
  },
);

// Tool execution endpoint for POST requests
openApiRouter.post(
  "/:endpoint_name/api/:tool_name",
  express.json(),
  lookupEndpoint,
  authenticateApiKey,
  async (req, res) => {
    await executeToolWithMiddleware(
      req as ToolExecutionRequest,
      res,
      req.body || {},
    );
  },
);

// Tool execution endpoint for GET requests (for tools with no parameters)
openApiRouter.get(
  "/:endpoint_name/api/:tool_name",
  lookupEndpoint,
  authenticateApiKey,
  async (req, res) => {
    await executeToolWithMiddleware(req as ToolExecutionRequest, res, {});
  },
);

export default openApiRouter;
