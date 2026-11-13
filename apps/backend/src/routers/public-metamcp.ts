import cors from "cors";
import express from "express";

import { describeDbError } from "@/lib/db-error-summary";
import logger from "@/utils/logger";

import { endpointsRepository } from "../db/repositories/endpoints.repo";
import { credentialedCorsOrigin } from "../lib/cors-policy";
import { isAdminHealthRequest } from "../lib/health-upstream";
import { originPolicyMiddleware } from "../middleware/origin-policy.middleware";
import adminRouter from "./public-metamcp/admin";
import { openApiRouter } from "./public-metamcp/openapi";
import sseRouter from "./public-metamcp/sse";
import streamableHttpRouter from "./public-metamcp/streamable-http";

const publicEndpointsRouter = express.Router();

// Origin policy, FIRST on this router. The MCP Streamable HTTP transport spec
// (2025-11-25, "Security Warning") says: "Servers MUST validate the Origin
// header on all incoming connections to prevent DNS rebinding attacks. If the
// Origin header is present and invalid, servers MUST respond with HTTP 403
// Forbidden." Nothing below this line ever read `Origin` before: the CORS
// middleware only decides whether to ADD a grant. The default, `audit`, serves
// every request as before and records the ones `enforce` would refuse; see
// ../lib/origin-policy and ../middleware/origin-policy.middleware.
//
// Three choices worth keeping:
//  - It covers GET and HEAD. A guard that skipped them (the shape some
//    frameworks ship) would exempt the SSE streams and the standalone GET
//    stream on these routes, which are exactly where a rebound page reads.
//  - It is not the SDK's `enableDnsRebindingProtection`, which compares raw
//    strings, echoes the header into its error text and runs after session
//    admission, nor the SDK's `Host` validation, which checks a different
//    header against a fixed list.
//  - It does not close DNS rebinding for same-origin GETs: a browser omits
//    `Origin` there, and an absent `Origin` always passes (the module header
//    states the residual and why no Host allowlist is added).
publicEndpointsRouter.use(originPolicyMiddleware);

// `origin: true` reflected whatever `Origin` the caller sent straight back
// into `Access-Control-Allow-Origin`, next to
// `Access-Control-Allow-Credentials: true` — the pairing that lets any site a
// victim visits read a credentialed response from this host. These routes
// authenticate with `X-API-Key` rather than the session cookie, so a browser
// would not have carried anything worth stealing today; the allowlist is here
// because a reflected origin plus credentials must not be one route change
// away from mattering. Trusted origins get their own origin echoed back,
// everyone else gets no grant at all. A browser-based third-party client that
// needs to call these endpoints cross-origin belongs in
// `EXTRA_TRUSTED_ORIGINS`. See ../lib/cors-policy.
//
// The header lists are what a browser client of the transport needs. Request
// side: the 2025-11-25 spec has the client send `MCP-Protocol-Version` on every
// request after initialize and resume a stream with `Last-Event-ID`; neither is
// CORS-safelisted, so a preflight that omitted them failed such a client before
// its first call. Response side: `Mcp-Session-Id`, `WWW-Authenticate` (only the
// realm, scope and the public resource-metadata URL, see ../lib/auth-challenge)
// and `Mcp-Session-Reinitialize-Required` (the fork's lazy-recovery 404) are not
// safelisted response headers, so a trusted-origin browser client could read
// none of them without an `Access-Control-Expose-Headers` entry, and the last
// is how it learns it must re-initialize.
publicEndpointsRouter.use(
  cors({
    origin: credentialedCorsOrigin,
    credentials: true,
    methods: ["GET", "POST", "DELETE", "OPTIONS"],
    allowedHeaders: [
      "Content-Type",
      "mcp-session-id",
      "mcp-protocol-version",
      "last-event-id",
      "Authorization",
      "X-API-Key",
    ],
    exposedHeaders: [
      "Mcp-Session-Id",
      "WWW-Authenticate",
      "Mcp-Session-Reinitialize-Required",
    ],
  }),
);

// No body parser at this level. The MCP transports read the stream
// themselves, and the routers that need a parsed body carry their own parser:
// the OpenAPI bridge in front of its endpoint lookup (./public-metamcp/openapi/
// routes.ts) and the admin router (./public-metamcp/admin.ts). A parser here
// would run before every child and set the limit for all of them.

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
    logger.error("Error listing public endpoints:", describeDbError(error));
    res.status(500).json({
      error: "Internal server error",
      message: "Failed to list endpoints",
    });
  }
});

export default publicEndpointsRouter;
