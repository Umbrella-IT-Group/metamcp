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
    return res.status(403).json(buildMcpProxyForbiddenBody());
  }

  return next();
};

/**
 * The one denial body for the whole `/mcp-proxy` surface.
 *
 * Exported because the disabled-account gate
 * (`require-enabled-mcp.middleware.ts`) answers with it too: both refusals
 * are 403 with this exact body, so a caller cannot tell "not an admin" from
 * "an admin who has been locked out". The distinguishing detail is logged at
 * each gate, where the operator reads it and the caller does not — the same
 * rule the OAuth token planes follow. Sharing one builder rather than
 * copying the literal is what keeps the two indistinguishable through later
 * edits.
 *
 * A function rather than a shared constant, for the reason
 * `lib/health-upstream.ts` `buildUpstreamHealthErrorBody` gives: express
 * serialises the returned object directly, and a single shared instance is
 * an invitation for a later mutation to rewrite an earlier response.
 */
export function buildMcpProxyForbiddenBody(): Record<string, string> {
  return {
    error: "Forbidden",
    message:
      "The MCP Inspector proxy is restricted to administrators. " +
      "Ask a gateway administrator if you need access.",
  };
}
