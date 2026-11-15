import { TRPCError } from "@trpc/server";
import express from "express";

import { auditRequestContext } from "@/lib/audit/audit-emitter";
import { describeDbError } from "@/lib/db-error-summary";
import { betterAuthMcpMiddleware } from "@/middleware/better-auth-mcp.middleware";
import { INTERNAL_ERROR_BODY } from "@/middleware/error-handler.middleware";
import { lookupEndpointAfterAuth } from "@/middleware/lookup-endpoint-middleware";
import { requireAdminMcpMiddleware } from "@/middleware/require-admin-mcp.middleware";
import { requireEnabledMcpMiddleware } from "@/middleware/require-enabled-mcp.middleware";
import logger from "@/utils/logger";

import { mcpServersRepository } from "../../db/repositories";
import { resetServerErrors } from "../../lib/metamcp/reset-server-errors";
import { serverErrorTracker } from "../../lib/metamcp/server-error-tracker";

const adminRouter = express.Router();

// JSON body parser for admin routes
adminRouter.use(express.json());

/**
 * The gate both routes below carry, session-authenticated and admin-only.
 *
 * These two routes are mounted on the PUBLIC `/metamcp` router next to the
 * API-key data plane, and they used to be gated by `authenticateApiKey`
 * alone — the same key any endpoint consumer holds, with no role check. That
 * made two estate-wide operations reachable by every API key on the gateway:
 * `reset-errors` with no body resets the circuit breaker for EVERY server in
 * ERROR state and triggers a re-initialization sweep, and `error-status`
 * answers with `findAll()`, the whole server inventory, not the servers
 * behind the endpoint named in the URL. Neither operation is scoped to the
 * endpoint the caller authenticated against, so scoping the key would not
 * have been enough: this is an operator control panel, and it belongs on the
 * human plane with the rest of them.
 *
 * Same three middlewares, same order, as the whole `/mcp-proxy` surface
 * (`routers/mcp-proxy.ts`): authenticate from the session cookie, re-read
 * `users.disabled` for that id, then check the role. Applied INLINE per route
 * rather than through `adminRouter.use()` on purpose — this router is
 * `use()`d by `public-metamcp.ts` ahead of the endpoint data plane's own
 * fall-through, so a router-level session middleware here would sit in front
 * of API-key traffic that must never be asked for a cookie.
 *
 * `lookupEndpointAfterAuth` now runs LAST, behind the whole gate, and that
 * reordering is a fix rather than a tidy-up. `lookupEndpoint` used to run
 * first, so an unknown endpoint
 * name answered 404 rather than 401 -- convenient for a typo, but it made
 * these two routes an endpoint-enumeration oracle for callers with no session
 * at all: 404 meant "no such name", anything else meant "that name is real".
 * The data plane's own version of that hole is closed inside
 * `lookup-endpoint-middleware` by answering unknown names with the ordinary
 * authentication challenge, which it must do because `authenticateApiKey`
 * needs `req.endpoint` to pick an auth mode. Here there is no such
 * constraint: none of the three gate middlewares reads `req.endpoint` (they
 * read cookies, `req.user.id` and `req.user.role`), and neither do these two
 * handlers, which answer estate-wide from `mcpServersRepository.findAll()`.
 * So the lookup can simply move behind them, in its `afterAuthentication`
 * form. An anonymous caller now gets the identical session 401
 * for every name, real or invented, and the honest 404 survives for the
 * authenticated administrator who is the only one who should be able to tell
 * the difference.
 *
 * Spelled out on each route below rather than hoisted into a shared array,
 * so a route added to this file later has to state its own gate instead of
 * inheriting one by accident.
 */

/**
 * POST /metamcp/admin/reset-errors
 *
 * Clears the ERROR state of one MCP server (`serverUuid`) or of every server
 * in ERROR, without a restart. The implementation is the one the tRPC
 * procedure `mcpServers.resetErrors` uses (lib/metamcp/reset-server-errors):
 * the status change and its audit row (attributed to the signed-in person)
 * commit in one transaction, an unknown server answers 404, a database
 * failure answers 500, and connection recovery runs after the commit for the
 * reset servers only and is reported in `recovery`.
 *
 * Body: { "serverUuid": "optional-specific-uuid" }
 * Auth: better-auth session cookie, enabled account, admin role — see the
 * block above. Deliberately not reachable with an admin-plane key's bearer:
 * that key reaches the same action through tRPC, where the scope sets, the
 * change reason and the change budget apply.
 */
adminRouter.post(
  "/:endpoint_name/admin/reset-errors",
  betterAuthMcpMiddleware,
  requireEnabledMcpMiddleware,
  requireAdminMcpMiddleware,
  lookupEndpointAfterAuth,
  async (req, res) => {
    try {
      const { serverUuid } = (req.body || {}) as { serverUuid?: unknown };
      const user = (req as { user?: { id?: unknown; email?: unknown } }).user;
      const result = await resetServerErrors(
        {
          serverUuid:
            serverUuid === undefined || serverUuid === null || serverUuid === ""
              ? undefined
              : String(serverUuid),
        },
        {
          actor_id: typeof user?.id === "string" ? user.id : null,
          actor_label: typeof user?.email === "string" ? user.email : null,
          ...auditRequestContext(req),
        },
      );
      const servers = result.reset.map((server) => server.name || server.uuid);
      logger.info(
        `Admin API: Reset ${servers.length} server(s) from ERROR state; recovery ${result.recovery.status}`,
      );

      res.json({
        success: true,
        reset: servers.length,
        servers,
        recovery: result.recovery,
        message:
          servers.length > 0
            ? `Reset ${servers.length} server(s). Connection recovery: ${result.recovery.status}.`
            : "No servers were in ERROR state.",
      });
    } catch (error) {
      if (error instanceof TRPCError && error.code === "NOT_FOUND") {
        res.status(404).json({ success: false, error: "MCP server not found" });
        return;
      }
      // The detail goes to the server log and nowhere else, the same rule
      // the terminal handler follows (@/middleware/error-handler.middleware,
      // whose body constant this is). The failures reachable here come from
      // the repository and the pool, so `error.message` routinely names
      // internal hosts, table names and server UUIDs.
      logger.error(
        "Admin API: Error resetting server errors:",
        describeDbError(error),
      );
      res.status(500).json(INTERNAL_ERROR_BODY);
    }
  },
);

/**
 * GET /metamcp/admin/error-status
 *
 * Returns current error status of all servers (for diagnostics). The
 * `findAll()` below is the whole inventory rather than the endpoint's own
 * servers, which is why this needs the same admin gate as the reset route
 * and not merely a scoped key.
 *
 * Auth: better-auth session cookie, enabled account, admin role.
 */
adminRouter.get(
  "/:endpoint_name/admin/error-status",
  betterAuthMcpMiddleware,
  requireEnabledMcpMiddleware,
  requireAdminMcpMiddleware,
  lookupEndpointAfterAuth,
  async (req, res) => {
    try {
      const allServers = await mcpServersRepository.findAll();
      const serverStatuses = allServers.map((s) => ({
        uuid: s.uuid,
        name: s.name,
        error_status: s.error_status,
        attempts: serverErrorTracker.getServerAttempts(s.uuid),
      }));

      const errorCount = serverStatuses.filter(
        (s) => s.error_status === "ERROR",
      ).length;

      res.json({
        timestamp: new Date().toISOString(),
        total: serverStatuses.length,
        errored: errorCount,
        servers: serverStatuses,
      });
    } catch (error) {
      logger.error(
        "Admin API: Error fetching server statuses:",
        describeDbError(error),
      );
      res.status(500).json({
        success: false,
        error: "Failed to fetch server statuses",
      });
    }
  },
);

export default adminRouter;
