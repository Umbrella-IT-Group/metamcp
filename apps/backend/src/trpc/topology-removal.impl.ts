import type { AuditActor } from "@repo/trpc";
import type {
  RemoveTopologyRequest,
  RemoveTopologyResponse,
  TopologyRemovalImpactRequest,
  TopologyRemovalImpactResponse,
  TopologyRemovalKind,
} from "@repo/zod-types";
import { TRPCError } from "@trpc/server";

import { describeDbError } from "@/lib/db-error-summary";
import logger from "@/utils/logger";

import { topologyRemovalRepository } from "../db/repositories/topology-removal.repo";
import {
  ADMIN_AUDIT_WRITE_FAILED_MESSAGE,
  AdminAuditWriteError,
  AdminRuleRefusal,
  runAuditedTransaction,
} from "../lib/audit/admin-write";
import {
  cascadeCounts,
  hiddenDependents,
  removalBlockers,
  topologyRemovalFingerprint,
  TopologyRemovalRefusal,
  topologySnapshot,
  visibleDependents,
} from "../lib/topology-removal-rules";

/**
 * `endpoints.removalImpact` / `endpoints.remove`, `namespaces.removalImpact` /
 * `namespaces.remove` and `mcpServers.removalImpact` / `mcpServers.remove`:
 * the leaf-only removals (lib/topology-removal-rules says what they refuse and
 * why). One implementation per operation, bound to each kind below.
 *
 * A removal runs in `runAuditedTransaction` for every caller, as
 * `apiKeys.remove` does: the delete, its cascades and its audit row (action
 * `<kind>.delete`, `detail.via = "remove"`, with the snapshot and the
 * fingerprint) commit together or not at all, charged to an admin-plane
 * caller's budget as `destroy`. A refusal rolls back and leaves a `denied` row
 * naming the rule.
 *
 * After the commit, the in-memory work the broad delete does: a namespace's
 * idle MetaMCP server and override cache, a server's idle session and its
 * Inspector sessions. A failure there is logged and reported as
 * `cleanup: "failed"`; it never turns a committed removal into an error.
 */

// Written as `action:` literals so the budget classification test's source
// scan (admin-plane-classification.test.ts) finds the actions this file writes.
const AUDIT: Record<TopologyRemovalKind, { action: string }> = {
  endpoint: { action: "endpoint.delete" },
  namespace: { action: "namespace.delete" },
  mcp_server: { action: "mcpserver.delete" },
};

const NOT_FOUND: Record<TopologyRemovalKind, string> = {
  endpoint: "Endpoint not found",
  namespace: "Namespace not found",
  mcp_server: "MCP server not found",
};

/** A rule's refusal as the coded error that records its `denied` row. */
async function refusalWrite<T>(
  kind: TopologyRemovalKind,
  uuid: string,
  write: () => Promise<T>,
): Promise<T> {
  try {
    return await write();
  } catch (error) {
    if (error instanceof TopologyRemovalRefusal) {
      throw new AdminRuleRefusal(error.code, error.message, {
        action: AUDIT[kind].action,
        target_type: kind,
        target_id: uuid,
        detail: { via: "remove", rule: error.rule },
      });
    }
    throw error;
  }
}

/** The in-memory cleanup after a committed removal; never throws. */
async function cleanupAfterCommit(
  kind: TopologyRemovalKind,
  uuid: string,
): Promise<"ok" | "failed" | "not_needed"> {
  if (kind === "endpoint") return "not_needed";
  // Lazy: the connection pools load the server repository and its database
  // pool, and the routers that host these procedures are imported by suites
  // that have neither.
  let modules;
  try {
    modules = await Promise.all([
      import("../lib/metamcp/metamcp-server-pool"),
      import("../lib/metamcp/metamcp-middleware/tool-overrides.functional"),
      import("../lib/metamcp/mcp-server-pool"),
      import("../lib/metamcp/inspector-sessions"),
    ]);
  } catch (error) {
    logger.error(
      "Cleanup after a committed removal could not start:",
      describeDbError(error),
    );
    return "failed";
  }
  const [
    { metaMcpServerPool },
    { clearOverrideCache },
    { mcpServerPool },
    { closeInspectorSessionsForServer },
  ] = modules;
  let failed = false;
  if (kind === "namespace") {
    try {
      await metaMcpServerPool.cleanupIdleServer(uuid);
    } catch (error) {
      failed = true;
      logger.error(
        "Idle MetaMCP server cleanup failed after a namespace removal:",
        describeDbError(error),
      );
    }
    try {
      clearOverrideCache(uuid);
    } catch (error) {
      failed = true;
      logger.error(
        "Override cache clear failed after a namespace removal:",
        describeDbError(error),
      );
    }
    return failed ? "failed" : "ok";
  }
  try {
    await mcpServerPool.cleanupIdleSession(uuid);
  } catch (error) {
    failed = true;
    logger.error(
      "Idle session cleanup failed after a server removal:",
      describeDbError(error),
    );
  }
  // Attempted even when the idle cleanup failed: the row is gone either way.
  try {
    await closeInspectorSessionsForServer(uuid);
  } catch (error) {
    failed = true;
    logger.error(
      "Inspector session closure failed after a server removal:",
      describeDbError(error),
    );
  }
  return failed ? "failed" : "ok";
}

function readFailure(error: unknown): TRPCError {
  logger.error("Error reading a removal target:", describeDbError(error));
  return new TRPCError({
    code: "INTERNAL_SERVER_ERROR",
    message: "Internal server error",
  });
}

export function topologyRemovalImplementations(kind: TopologyRemovalKind) {
  return {
    /**
     * The read a removal is prepared from: whether `remove` would accept the
     * row now (every rule that stops it), what depends on it and what goes
     * with it, its snapshot and the fingerprint of its current state.
     */
    removalImpact: async (
      input: TopologyRemovalImpactRequest,
      userId: string,
    ): Promise<TopologyRemovalImpactResponse> => {
      let state;
      try {
        state = await topologyRemovalRepository.readImpact(
          kind,
          input.uuid,
          userId,
        );
      } catch (error) {
        throw readFailure(error);
      }
      if (!state) {
        throw new TRPCError({ code: "NOT_FOUND", message: NOT_FOUND[kind] });
      }
      const blockedBy = removalBlockers(state);
      return {
        kind,
        uuid: state.uuid,
        name: state.name,
        removable: blockedBy.length === 0,
        blocked_by: blockedBy,
        dependents: visibleDependents(state, userId),
        hidden_dependents: hiddenDependents(state, userId),
        cascades: cascadeCounts(state),
        live_sessions: state.live_sessions,
        impact_fingerprint: topologyRemovalFingerprint(state),
        snapshot: topologySnapshot(state),
      };
    },

    /** Remove the row, leaf-only, confirmed by name and fingerprint. */
    remove: async (
      input: RemoveTopologyRequest,
      userId: string,
      actor?: AuditActor,
    ): Promise<RemoveTopologyResponse> => {
      const uuid = input.uuid.toLowerCase();
      let outcome: Awaited<ReturnType<typeof topologyRemovalRepository.remove>>;
      try {
        outcome = await runAuditedTransaction(
          actor,
          (tx) =>
            refusalWrite(kind, uuid, () =>
              topologyRemovalRepository.remove(
                tx,
                kind,
                uuid,
                userId,
                input.confirm_name,
                input.impact_fingerprint,
              ),
            ),
          (written) =>
            written.status === "removed"
              ? {
                  action: AUDIT[kind].action,
                  target_type: kind,
                  target_id: written.state.uuid,
                  detail: {
                    via: "remove",
                    name: written.state.name,
                    impact_fingerprint: input.impact_fingerprint,
                    snapshot: topologySnapshot(written.state),
                  },
                }
              : null,
        );
      } catch (error) {
        if (error instanceof AdminAuditWriteError) {
          throw new TRPCError({
            code: "INTERNAL_SERVER_ERROR",
            message: ADMIN_AUDIT_WRITE_FAILED_MESSAGE,
          });
        }
        throw error;
      }
      if (outcome.status === "not_found") {
        throw new TRPCError({ code: "NOT_FOUND", message: NOT_FOUND[kind] });
      }
      const cleanup = await cleanupAfterCommit(kind, outcome.state.uuid);
      return {
        kind,
        uuid: outcome.state.uuid,
        name: outcome.state.name,
        removed: true as const,
        snapshot: topologySnapshot(outcome.state),
        cleanup,
      };
    },
  };
}
