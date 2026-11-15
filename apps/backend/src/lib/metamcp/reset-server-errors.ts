import type { AuditActor } from "@repo/trpc";
import { TRPCError } from "@trpc/server";

import logger from "@/utils/logger";

import {
  mcpServersRepository,
  namespaceMappingsRepository,
} from "../../db/repositories";
import type { AdminEventInput } from "../audit/admin-event";
import { withAdminAuditTx } from "../audit/admin-write";
import { mcpServerPool } from "./mcp-server-pool";
import { metaMcpServerPool } from "./metamcp-server-pool";
import { serverErrorTracker } from "./server-error-tracker";
import { isStdioServerType, stdioServersAllowed } from "./stdio-policy";
import { convertDbServerToParams } from "./utils";

/**
 * Clear the ERROR status of MCP servers: the one implementation behind the
 * tRPC procedure `mcpServers.resetErrors` (operator scope) and the cookie-only
 * REST route `POST /metamcp/:endpoint_name/admin/reset-errors`.
 *
 * WHY NOT THE ERROR TRACKER'S RESET. `serverErrorTracker.resetServerErrorState`
 * clears the in-memory crash counter before its database write and logs a
 * failed write instead of raising it, and `initializeIdleServers` (what the
 * REST route ran afterwards) starts by clearing the ERROR status of every
 * server. A reset an operator's key can make has to be exactly the change
 * its audit row describes, so it is built from these steps instead:
 *
 *  1. The status change and its one `mcpserver.errors.reset` audit row run in
 *     one transaction (`withAdminAuditTx`: for an admin-plane key the row is
 *     written in the transaction and charged to its change budget; for a
 *     person's session the transaction is real and the row is written right
 *     after it commits). An unknown server is NOT_FOUND. A database or audit
 *     failure reaches the caller and nothing below runs.
 *  2. Only after the commit: the in-memory crash counters of the servers that
 *     were reset are cleared, and connection recovery starts for those
 *     servers only (an idle session for each, then the idle aggregate of every
 *     namespace that mounts one). No other server's status or counter is
 *     touched.
 *  3. Recovery is reported apart from the reset: waited for up to
 *     `recoveryWaitMs`, then `succeeded`, `failed` or `pending` per server. A
 *     recovery failure never turns the committed reset into a failure, is
 *     never retried here, and the reset is never rolled back for it.
 *
 * A call that resets nothing (the named server is not in ERROR, or no server
 * is) writes no audit row, charges no budget and starts nothing.
 */

/** How long a call waits for recovery before answering `pending`. */
export const RESET_RECOVERY_WAIT_MS = 5_000;

const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export const MCP_SERVER_NOT_FOUND_MESSAGE = "MCP server not found";

export type ServerRecoveryStatus =
  | "connected"
  | "failed"
  | "pending"
  | "skipped";

export interface ResetServerErrorsResult {
  /** Committed: the servers whose ERROR status was cleared. */
  reset: Array<{ uuid: string; name: string }>;
  /** After the commit: what reconnecting them came to. */
  recovery: {
    status: "not_needed" | "succeeded" | "failed" | "pending";
    servers: Array<{
      uuid: string;
      name: string;
      status: ServerRecoveryStatus;
    }>;
  };
}

/** The audit event a reset writes, or null when it reset nothing. */
function resetEvent(
  selection: "one" | "all_in_error",
  written:
    | { status: "not_found" }
    | { status: "ok"; reset: Array<{ uuid: string; name: string }> },
): AdminEventInput | null {
  if (written.status !== "ok" || written.reset.length === 0) return null;
  return {
    action: "mcpserver.errors.reset",
    target_type: "mcp_server",
    target_id: selection === "one" ? (written.reset[0]?.uuid ?? null) : null,
    detail: {
      selection,
      server_uuids: written.reset.map((server) => server.uuid),
      server_names: written.reset.map((server) => server.name),
      reset_count: written.reset.length,
    },
  };
}

/** Is there a pooled connection for this server now? */
function poolHasConnection(serverUuid: string): boolean {
  const status = mcpServerPool.getPoolStatus() as {
    idleServerUuids?: string[];
    perServerCounts?: Record<string, number>;
  };
  return (
    (status.idleServerUuids ?? []).includes(serverUuid) ||
    (status.perServerCounts?.[serverUuid] ?? 0) > 0
  );
}

/** Rebuild one reset server's idle session; never throws. */
async function recoverOne(server: {
  uuid: string;
  name: string;
}): Promise<ServerRecoveryStatus> {
  try {
    const row = await mcpServersRepository.findByUuid(server.uuid);
    // Deleted since the reset, or a stored stdio row while stdio servers are
    // disabled: nothing to connect, which is not a failure of the reset.
    if (!row) return "skipped";
    if (isStdioServerType(row.type) && !stdioServersAllowed()) {
      return "skipped";
    }
    const params = await convertDbServerToParams(row);
    if (!params) return "skipped";
    await mcpServerPool.ensureIdleSessionForNewServer(server.uuid, params);
    return poolHasConnection(server.uuid) ? "connected" : "failed";
  } catch (error) {
    // The type only: a connection error can carry an upstream URL.
    logger.warn(
      `Recovery after an error reset could not reconnect server ${server.uuid} (${error instanceof Error ? error.name : typeof error})`,
    );
    return "failed";
  }
}

/** Recover every reset server, then the idle aggregates over them. */
async function recoverServers(
  servers: Array<{ uuid: string; name: string }>,
  report: Map<string, ServerRecoveryStatus>,
): Promise<void> {
  await Promise.all(
    servers.map(async (server) => {
      report.set(server.uuid, await recoverOne(server));
    }),
  );
  try {
    const namespaceUuids = new Set<string>();
    for (const server of servers) {
      for (const namespaceUuid of await namespaceMappingsRepository.findNamespacesByServerUuid(
        server.uuid,
      )) {
        namespaceUuids.add(namespaceUuid);
      }
    }
    if (namespaceUuids.size > 0) {
      // false: never warm an aggregate that serves inactive servers (see
      // lib/startup initializeIdleServers).
      await metaMcpServerPool.ensureIdleServers([...namespaceUuids], false);
    }
  } catch (error) {
    logger.warn(
      `Recovery after an error reset could not refresh the idle namespace servers (${error instanceof Error ? error.name : typeof error})`,
    );
  }
}

export async function resetServerErrors(
  input: { serverUuid?: string },
  actor: AuditActor | undefined | null,
  options: { recoveryWaitMs?: number } = {},
): Promise<ResetServerErrorsResult> {
  const serverUuid = input.serverUuid;
  if (serverUuid !== undefined && !UUID_PATTERN.test(serverUuid)) {
    // The tRPC schema refuses this first; the REST route has no schema, and a
    // value Postgres cannot read as a uuid names no server.
    throw new TRPCError({
      code: "NOT_FOUND",
      message: MCP_SERVER_NOT_FOUND_MESSAGE,
    });
  }
  const selection = serverUuid !== undefined ? "one" : "all_in_error";

  const written = await withAdminAuditTx(
    actor,
    (tx) =>
      mcpServersRepository.clearErrorStatus(
        tx,
        serverUuid !== undefined ? { serverUuid } : {},
      ),
    (result) => resetEvent(selection, result),
  );
  if (written.status === "not_found") {
    throw new TRPCError({
      code: "NOT_FOUND",
      message: MCP_SERVER_NOT_FOUND_MESSAGE,
    });
  }
  const reset = written.reset;
  if (reset.length === 0) {
    return { reset, recovery: { status: "not_needed", servers: [] } };
  }

  // Committed. Everything from here on is a side effect of the reset, never a
  // condition of it.
  for (const server of reset)
    serverErrorTracker.resetServerAttempts(server.uuid);

  const report = new Map<string, ServerRecoveryStatus>();
  const recovery = recoverServers(reset, report).catch(() => undefined);
  let timer: NodeJS.Timeout | undefined;
  const waited = await Promise.race([
    recovery.then(() => "done" as const),
    new Promise<"timeout">((resolve) => {
      timer = setTimeout(
        () => resolve("timeout"),
        options.recoveryWaitMs ?? RESET_RECOVERY_WAIT_MS,
      );
    }),
  ]);
  if (timer) clearTimeout(timer);
  // On a timeout the recovery keeps running on its own and logs what fails;
  // the servers it has not finished are reported `pending`.
  if (waited === "timeout") {
    logger.info(
      `Recovery after an error reset is still running for ${reset.length - report.size} server(s)`,
    );
  }

  const servers = reset.map((server) => ({
    uuid: server.uuid,
    name: server.name,
    status: report.get(server.uuid) ?? ("pending" as const),
  }));
  const status = servers.some((server) => server.status === "failed")
    ? "failed"
    : servers.some((server) => server.status === "pending")
      ? "pending"
      : "succeeded";
  return { reset, recovery: { status, servers } };
}
