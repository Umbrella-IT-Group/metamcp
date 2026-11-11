import { McpServerTypeEnum } from "@repo/zod-types";

import logger from "@/utils/logger";

/**
 * Transport policy for stdio MCP servers: refused unless ALLOW_STDIO_SERVERS
 * is exactly "true".
 *
 * A stdio server is a command the gateway runs as a child process inside its
 * own container, which also holds the gateway's database credentials, signing
 * secrets and stored upstream tokens. A deployment that only fronts HTTP and
 * SSE backends has no use for that, so the default is off and enabling it is
 * an explicit, logged choice meant for local development.
 *
 * Every gate reads this one module, so the gates cannot disagree:
 *  - tRPC `create`, `update` and `bulkImport` (`trpc/mcp-servers.impl.ts`)
 *    refuse with BAD_REQUEST before any write;
 *  - the pool's transport factory (`createMetaMcpClient` in `client.ts`)
 *    returns its skip shape before it resolves a child env or builds a
 *    transport, which covers the namespace, reconnect and lazy paths;
 *  - the admin proxy (`routers/mcp-proxy/server.ts`) throws
 *    `StdioServersDisabledError` before it resolves a row, and each route
 *    answers HTTP 400 with a constant body;
 *  - boot (`lib/startup.ts`) skips stored stdio rows before warming them.
 *
 * Stored rows are never rewritten or deleted: turning the flag on later (and
 * restarting) brings them back exactly as they were.
 *
 * Strict "true" only, the comparison ALLOW_UNAUTHENTICATED_ENDPOINTS and the
 * other security-gate env reads in this codebase use: unset, empty, "false",
 * "TRUE", "1" and "yes" all refuse, so a near-miss spelling fails safe. Read
 * per call rather than cached at import, so tests can scope it; a running
 * container's environment does not change, so a deployment changes it by
 * recreating the container.
 */
export function stdioServersAllowed(): boolean {
  return process.env.ALLOW_STDIO_SERVERS === "true";
}

/**
 * Whether a server type is, or normalizes to, stdio. A missing or empty type
 * IS stdio here: the `mcp_servers.type` column defaults to STDIO, and
 * `convertDbServerToParams`, `createMetaMcpClient` and `bulkImport` all read
 * a falsy type as STDIO. Bulk import's schema aliases (`std`, any case of
 * `stdio`) are normalized to "STDIO" by the zod transform before the
 * implementation sees them.
 */
export function isStdioServerType(type: string | null | undefined): boolean {
  return !type || type === McpServerTypeEnum.enum.STDIO;
}

/** The refusal text every gate uses. Shown to administrators as is. */
export const STDIO_SERVERS_DISABLED_MESSAGE =
  "stdio MCP servers are disabled on this gateway. Register the server as Streamable HTTP or SSE, or set ALLOW_STDIO_SERVERS=true for local development.";

/**
 * Typed refusal for code paths whose callers map errors to responses (the
 * admin proxy). A distinct class, so a caller can answer it with a fixed 400
 * instead of the 500 its catch gives an ordinary throw.
 */
export class StdioServersDisabledError extends Error {
  readonly code = "stdio_servers_disabled";

  constructor() {
    super(STDIO_SERVERS_DISABLED_MESSAGE);
    this.name = "StdioServersDisabledError";
  }
}

/** Throws `StdioServersDisabledError` unless stdio servers are allowed. */
export function assertStdioServersAllowed(): void {
  if (!stdioServersAllowed()) {
    throw new StdioServersDisabledError();
  }
}

// One boot warning when the opt-in is set, so a deployment running with stdio
// enabled says so in its boot log. Latched so "one warning at boot" holds even
// if the boot path calls it more than once, same shape as
// warnIfAdminPlaneTokenAuthDisabled.
let allowedWarned = false;
export function warnIfStdioServersAllowed(): void {
  if (allowedWarned) return;
  allowedWarned = true;
  if (stdioServersAllowed()) {
    logger.warn(
      "ALLOW_STDIO_SERVERS=true: stdio MCP servers are enabled. Administrators " +
        "can register servers that run as child processes inside this " +
        "container. Intended for local development; unset it in production.",
    );
  }
}

/** Test seam: clear the boot-warning latch so a suite can drive it twice. */
export function __resetStdioAllowedWarningForTesting(): void {
  allowedWarned = false;
}

// Servers already reported as skipped, so a refused server that the pool asks
// for on every namespace request logs once per process, not once per request.
// Bounded by the number of server rows.
const skippedWarned = new Set<string>();

/**
 * Log, once per server per process, that a stored stdio server was not
 * started. Identity only: the command, args and env are never logged, since a
 * stdio row's env is where its credentials live.
 */
export function warnStdioServerSkipped(server: {
  uuid: string;
  name: string;
}): void {
  if (skippedWarned.has(server.uuid)) return;
  skippedWarned.add(server.uuid);
  logger.warn(
    `stdio MCP server ${JSON.stringify(server.name)} (${server.uuid}) was not started: ` +
      "stdio servers are disabled on this gateway (ALLOW_STDIO_SERVERS is not " +
      '"true"). The stored server is kept unchanged.',
  );
}

/** Test seam: forget which servers were reported as skipped. */
export function __resetStdioSkipWarningsForTesting(): void {
  skippedWarned.clear();
}
