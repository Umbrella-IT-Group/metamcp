import cors from "cors";
import express from "express";
import helmet from "helmet";

import { credentialedCorsOrigin } from "../lib/cors-policy";
import { betterAuthMcpMiddleware } from "../middleware/better-auth-mcp.middleware";
import { requireAdminMcpMiddleware } from "../middleware/require-admin-mcp.middleware";
import { requireEnabledMcpMiddleware } from "../middleware/require-enabled-mcp.middleware";
import metamcpRoutes from "./mcp-proxy/metamcp";
import serverRoutes from "./mcp-proxy/server";

const mcpProxyRouter = express.Router();

// Apply security middleware for MCP proxy communication
mcpProxyRouter.use(helmet());
// Session-authenticated and admin-gated (see the block below), so the origin
// is resolved against the shared allowlist rather than handed the raw
// `APP_URL`: an unset or empty APP_URL is falsy and the cors package answers a
// falsy origin with the literal `*` beside `credentials: true`, while a
// trailing slash makes the string comparison miss and drops CORS for the app's
// own frontend. See ../lib/cors-policy.
mcpProxyRouter.use(
  cors({
    origin: credentialedCorsOrigin,
    credentials: true,
    allowedHeaders: [
      "Content-Type",
      "Authorization",
      "mcp-session-id",
      "x-custom-auth-header",
      "last-event-id",
    ],
  }),
);

// Basic authentication disabled for easier OAuth integration

// Apply additional headers
mcpProxyRouter.use((req, res, next) => {
  res.header("Access-Control-Expose-Headers", "mcp-session-id");
  res.header("Access-Control-Expose-Headers", "authorization");
  res.header("Access-Control-Expose-Headers", "last-event-id");
  next();
});

// Authentication, then account validity, then authorization for the WHOLE
// proxy surface. All three live here at the parent router rather than inside
// each sub-router so no route file can ever be mounted under /mcp-proxy
// without them — the sub-routers used to apply the session check themselves,
// which left the gate one forgotten `use()` away from a hole. Order is
// load-bearing: betterAuthMcpMiddleware populates `req.user` from the session
// cookie, requireEnabledMcpMiddleware then re-reads `users.disabled` for that
// id, and requireAdminMcpMiddleware reads `req.user.role`. The admin
// restriction is not incidental hardening — the STDIO branch of
// /server/{stdio,sse,mcp} spawns a query-string-supplied command with the
// backend's environment, so session-only access was remote code execution
// for any member. See middleware/require-admin-mcp.middleware.ts.
//
// The disabled gate sits between the two because a valid cookie is not a
// valid ACCOUNT: nothing else on this router re-reads `users.disabled`, so
// without it an admin who was locked out mid-session kept that same spawn
// route for the 30-day life of the cookie they already held. See
// middleware/require-enabled-mcp.middleware.ts.
mcpProxyRouter.use(betterAuthMcpMiddleware);
mcpProxyRouter.use(requireEnabledMcpMiddleware);
mcpProxyRouter.use(requireAdminMcpMiddleware);

// Mount MCP server proxy routes under /server
mcpProxyRouter.use("/server", serverRoutes);

// Mount MetaMCP routes under /metamcp
mcpProxyRouter.use("/metamcp", metamcpRoutes);

export default mcpProxyRouter;
