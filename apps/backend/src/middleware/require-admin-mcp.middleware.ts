import express from "express";

import logger from "@/utils/logger";

/** Shape `betterAuthMcpMiddleware` leaves on the request. */
type AuthenticatedRequest = express.Request & {
  user?: { id?: string; role?: string };
};

/**
 * Admin-only gate for the ENTIRE `/mcp-proxy` surface.
 *
 * Why the whole surface, not just one route: `/mcp-proxy/*` is the MCP
 * Inspector, an operator dev tool that proxies a browser session straight at
 * an arbitrary MCP transport. Its STDIO branch reads `command`, `args` and
 * `env` from the QUERY STRING and hands them to `spawn()` with the backend's
 * full `process.env` (`routers/mcp-proxy/server.ts` `createTransport` ->
 * `ProcessManagedStdioTransport.start`), so being able to reach this router
 * at all is arbitrary command execution on the gateway host as the gateway
 * user. Until this gate the only check was `betterAuthMcpMiddleware`, which
 * proves a valid session and nothing else — every member-role account could
 * run commands on the gateway. Gating route-by-route would leave the next
 * route added to this router unprotected, so the gate sits at the parent
 * router (`routers/mcp-proxy.ts`) and covers stdio, sse, message, mcp
 * GET/POST/DELETE, health, and every future addition.
 *
 * Why `req.user.role` is trustworthy here: `betterAuthMcpMiddleware` sets
 * `req.user` from better-auth's `GET /api/auth/get-session`, and `role`
 * rides along as a better-auth `additionalFields` entry declared with
 * `input: false` (`src/auth.ts`), so no client can supply it on sign-up or
 * user-update — it comes from the DB column default plus deliberate admin
 * action. No `cookieCache` is configured on the session, so get-session
 * re-reads the user row per request and a demotion takes effect at once.
 * This is the same field, from the same call, that `adminProcedure`
 * (`packages/trpc/src/trpc.ts` `requireAdmin`) already gates the product's
 * administrative tRPC surface on.
 *
 * Fail-closed by construction: the test is positive (`role === "admin"`
 * passes), so a missing user, a missing role, an unknown role, or any future
 * change to the session payload shape all land on 403 rather than on access.
 */
export const requireAdminMcpMiddleware = (
  req: express.Request,
  res: express.Response,
  next: express.NextFunction,
) => {
  const user = (req as AuthenticatedRequest).user;

  if (user?.role !== "admin") {
    logger.warn(
      `MCP proxy admin gate denied ${req.method} ${req.path} for user ` +
        `${user?.id ?? "unknown"} (role: ${user?.role ?? "unknown"})`,
    );
    return res.status(403).json({
      error: "Forbidden",
      message:
        "The MCP Inspector proxy is restricted to administrators. " +
        "Ask a gateway administrator if you need access.",
    });
  }

  return next();
};
