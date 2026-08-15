import express from "express";

import logger from "@/utils/logger";

import { usersRepository } from "../db/repositories/users.repo";
import { buildMcpProxyForbiddenBody } from "./require-admin-mcp.middleware";

/** Shape `betterAuthMcpMiddleware` leaves on the request. */
type AuthenticatedRequest = express.Request & {
  user?: { id?: string; role?: string };
};

/**
 * `users.disabled` enforcement (migration 0027) for the ENTIRE `/mcp-proxy`
 * surface.
 *
 * Why none of the checks that shipped with Disable reach this router: each of
 * them sits on a different path. The sign-in hook in `auth.ts` only stops a
 * NEW session; the `trpc.ts` context guard only covers the tRPC surface; the
 * api-key/OAuth middleware only covers the endpoint data plane. `/mcp-proxy`
 * is plain express routing behind a raw better-auth session cookie and
 * touches none of them, and `requireAdminMcpMiddleware` next to it tests
 * `role` and nothing else. Sessions live 30 days in this fork
 * (BETTER_AUTH_SESSION_EXPIRES_IN_SECONDS), so a DISABLED ADMIN kept
 * `/mcp-proxy/server/stdio` — which hands a command to `spawn()` with the
 * backend's environment (see `require-admin-mcp.middleware.ts` for the full
 * chain, including why that command is now sourced from the `mcp_servers` row
 * instead of the query string) — for the remaining life of a cookie they
 * already held. That is process execution on the gateway host outliving the
 * button whose entire purpose is to end an account's access.
 *
 * Mounted at the parent router (`routers/mcp-proxy.ts`) between authentication
 * and the role gate, so it covers both sub-routers and anything mounted under
 * them later. Before the role gate rather than after: the allowed set is the
 * same either way (admin AND enabled), but this ordering means the lockout
 * does not depend on the role gate staying admin-only — if `/mcp-proxy` is
 * ever opened to another role, a disabled account is still refused. Account
 * validity belongs with authentication; role belongs with authorization.
 *
 * Fail-closed on every branch:
 *  - no resolvable user id on the request denies, rather than querying with
 *    `undefined`,
 *  - `usersRepository.isDisabled` returns `true` for an id with no row,
 *  - a lookup that throws is caught HERE and denied. It must not propagate:
 *    an async express middleware that rejects hands nothing to `next(err)`,
 *    so the request would hang until the client gave up instead of being
 *    refused — and a hang on a spawn-capable route is not a safe failure.
 */
export const requireEnabledMcpMiddleware = async (
  req: express.Request,
  res: express.Response,
  next: express.NextFunction,
) => {
  const user = (req as AuthenticatedRequest).user;
  const userId = user?.id;

  if (!userId) {
    logger.warn(
      `MCP proxy disabled gate denied ${req.method} ${req.path}: ` +
        `session carried no user id`,
    );
    return res.status(403).json(buildMcpProxyForbiddenBody());
  }

  let disabled: boolean;
  try {
    disabled = await usersRepository.isDisabled(userId);
  } catch (error) {
    logger.error(
      `MCP proxy disabled gate failed closed for ${req.method} ${req.path} ` +
        `(user ${userId}):`,
      error,
    );
    return res.status(403).json(buildMcpProxyForbiddenBody());
  }

  if (disabled) {
    logger.warn(
      `MCP proxy denied ${req.method} ${req.path} reason=disabled ` +
        `user=${userId} (role: ${user?.role ?? "unknown"})`,
    );
    return res.status(403).json(buildMcpProxyForbiddenBody());
  }

  return next();
};
