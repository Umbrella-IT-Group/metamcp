import cors from "cors";
import express from "express";

import logger from "@/utils/logger";

import { endpointsRepository } from "../db/repositories/endpoints.repo";
import { isAdminHealthRequest } from "../lib/health-upstream";
import { openApiRouter } from "./public-metamcp/openapi";
import adminRouter from "./public-metamcp/admin";
import sseRouter from "./public-metamcp/sse";
import streamableHttpRouter from "./public-metamcp/streamable-http";

const publicEndpointsRouter = express.Router();

// Enable CORS for all public endpoint routes
publicEndpointsRouter.use(
  cors({
    origin: true, // Allow all origins
    credentials: true,
    methods: ["GET", "POST", "DELETE", "OPTIONS"],
    allowedHeaders: [
      "Content-Type",
      "mcp-session-id",
      "Authorization",
      "X-API-Key",
    ],
  }),
);

// JSON parsing middleware specifically for OpenAPI routes that need it
publicEndpointsRouter.use((req, res, next) => {
  // Only apply JSON parsing for OpenAPI tool execution endpoints
  if (req.path.includes("/api/tools/") && req.method === "POST") {
    return express.json({ limit: "50mb" })(req, res, next);
  }
  next();
});

// Use StreamableHTTP router for /mcp routes
publicEndpointsRouter.use(streamableHttpRouter);

// Use SSE router for /sse and /message routes
publicEndpointsRouter.use(sseRouter);

// Use OpenAPI router for /api and /openapi.json routes
publicEndpointsRouter.use(openApiRouter);

// Use Admin router for /admin endpoints (error reset, diagnostics)
publicEndpointsRouter.use(adminRouter);

// Health check endpoint
publicEndpointsRouter.get("/health", (req, res) => {
  res.json({
    status: "ok",
    service: "public-endpoints",
  });
});

/** One endpoint as advertised by `GET /metamcp/`, admin-only. */
export interface PublicEndpointListing {
  name: string;
  description: string | null;
  namespace: string;
  endpoints: {
    mcp: string;
    sse: string;
    api: string;
    openapi: string;
  };
}

/**
 * Assemble the `GET /metamcp/` body. Pass `null` for `listing` to withhold the
 * estate map.
 *
 * That map — every endpoint's name, description, namespace and all four URL
 * forms — is a directory of the integration estate, and this router is
 * unauthenticated, so it was served to anyone who could reach the host. It is
 * the same topology disclosure `/health/upstream` was gated for (`servers[]`
 * there), reachable through a second door. The banner stays public because
 * liveness probes hit this path and a 401 would break them: withhold the
 * detail, keep the 200.
 *
 * Built additively rather than by deleting keys from a full body, matching
 * `buildUpstreamHealthBody` in ../lib/health-upstream — a field added here
 * later cannot leak by someone forgetting to add it to a redaction list.
 */
export function buildPublicEndpointsBody(
  listing: PublicEndpointListing[] | null,
): Record<string, unknown> {
  const body: Record<string, unknown> = {
    service: "public-endpoints",
    version: "1.0.0",
    description: "Public MetaMCP endpoints",
  };

  if (listing) {
    body.endpoints = listing;
  }

  return body;
}

// List all available public endpoints (admin-only — see
// buildPublicEndpointsBody; everyone else gets the service banner).
publicEndpointsRouter.get("/", async (req, res) => {
  try {
    // Gated with the same soft admin check as /health/upstream: it resolves
    // the better-auth session and fails to "not an admin" on every error
    // path, so it can never 401 or throw on this public router.
    if (!(await isAdminHealthRequest(req))) {
      res.json(buildPublicEndpointsBody(null));
      return;
    }

    // Queried only once the caller is known to be an admin — an anonymous
    // request to this path no longer reaches the database at all.
    const endpoints = await endpointsRepository.findAllWithNamespaces();
    const publicEndpoints = endpoints.map((endpoint) => ({
      name: endpoint.name,
      description: endpoint.description,
      namespace: endpoint.namespace.name,
      endpoints: {
        mcp: `/metamcp/${endpoint.name}/mcp`,
        sse: `/metamcp/${endpoint.name}/sse`,
        api: `/metamcp/${endpoint.name}/api`,
        openapi: `/metamcp/${endpoint.name}/api/openapi.json`,
      },
    }));

    res.json(buildPublicEndpointsBody(publicEndpoints));
  } catch (error) {
    logger.error("Error listing public endpoints:", error);
    res.status(500).json({
      error: "Internal server error",
      message: "Failed to list endpoints",
    });
  }
});

export default publicEndpointsRouter;
