import {
  McpServerErrorStatusEnum,
  McpServerStatusEnum,
  type NamespaceToolPolicy,
  ServerParameters,
} from "@repo/zod-types";

import logger from "@/utils/logger";

import { namespacesRepository } from "../../db/repositories/namespaces.repo";
import { configService } from "../config.service";
import {
  BackendUnavailableError,
  BackendUnavailableReason,
} from "./backend-unavailable";
import { ConnectedClient } from "./client";
import { getNamespaceServerStates } from "./fetch-metamcp";
import {
  acquireSessionWithBoundedWarmup,
  ToolCallWarmupPool,
} from "./tool-call-warmup";
import { sanitizeName } from "./utils";

/**
 * tools/call routing for a name the caller's routing map does not hold, shared
 * by the Streamable-HTTP proxy (metamcp-proxy.ts) and the OpenAPI bridge
 * (routers/public-metamcp/openapi/handlers.ts) so the two cannot drift.
 *
 * THE DEFECT THIS REPLACES. Both paths walked every server in the namespace,
 * opened (or waited on) a session for each one, and only then compared the
 * server's name with the tool's prefix. When the owning server had no session
 * at that moment (a connection cap, a reconnect or teardown in flight, the
 * error gate) the only rescue was a fallback that resolves the server from the
 * namespace's ACTIVE tool mapping rows. A namespace with no mapping rows (the
 * `allow_all` default, never curated) could never be rescued, and every one of
 * those misses answered `Unknown tool: <name>`, the text a typo gets. Under
 * parallel calls a real tool intermittently "did not exist".
 *
 * NOW:
 *   1. Only the servers whose configured name sanitizes to the prefix are
 *      touched (`findPrefixCandidates`). An unrelated slow or capped server can
 *      no longer delay or fail the call, and no session is opened on it.
 *   2. Each candidate gets one session attempt and a `probe` (the proxy lists
 *      the server's tools; the bridge routes by prefix, as it always has).
 *   3. The reconnect-window fallback is unchanged: an ACTIVE mapping row for
 *      the tool on a prefix-matched, routable server gets the bounded warm-up
 *      and is routed without a listing.
 *   4. NEW: under the `allow_all` tool policy, when no mapping row resolved
 *      the tool and a prefix-matched server had no session, that server gets
 *      the same bounded warm-up and is probed again. Under `allowlist` nothing
 *      is routed without an ACTIVE row, so curation holds exactly as before
 *      (the filter refuses a row-less tool there before routing runs anyway).
 *   5. A miss on a mounted server answers `BackendUnavailableError` (the tool
 *      was not run, retry); `Unknown tool` is kept for a prefix no mounted
 *      server carries and for a server that listed its tools without this one.
 */

/** A server that may own the tool, by its prefix. */
export interface PrefixCandidate {
  uuid: string;
  params: ServerParameters;
  /**
   * True when the server's configured name sanitizes to the prefix. False for
   * a server stored with no name, which only its backend-reported name can
   * identify after connecting (the old post-session check, kept for it). The
   * API refuses an empty name, so this is a database-only edge; such a server
   * is probed but never reported as the unavailable owner of a prefix.
   */
  named: boolean;
}

/**
 * The routable servers (from `getMcpServers`) that may own a tool with this
 * prefix, named matches first, filtered by the servers the call's filter
 * judged.
 */
export function findPrefixCandidates(
  serverParams: Record<string, ServerParameters>,
  serverPrefix: string,
  isAllowedServer: (uuid: string) => boolean,
): PrefixCandidate[] {
  const named: PrefixCandidate[] = [];
  const nameless: PrefixCandidate[] = [];
  for (const [uuid, params] of Object.entries(serverParams)) {
    if (!isAllowedServer(uuid)) continue;
    if (!params.name) {
      nameless.push({ uuid, params, named: false });
    } else if (sanitizeName(params.name) === serverPrefix) {
      named.push({ uuid, params, named: true });
    }
  }
  return [...named, ...nameless];
}

/** What a probe of one acquired session found. */
export type ProbeOutcome =
  /** The server serves the tool; route the call to `session`. */
  | { kind: "found"; session: ConnectedClient }
  /** Authoritative: this server does not serve the tool (or is not the prefix's server). */
  | { kind: "absent" }
  /** The session was lost while probing and no replacement could be acquired. */
  | { kind: "no_session" }
  /** The server did not answer the lookup (a timeout, an error). */
  | { kind: "lookup_failed" };

export type ToolCallProbe = (
  session: ConnectedClient,
  candidate: PrefixCandidate,
) => Promise<ProbeOutcome>;

export interface RouteUnmappedToolCallOptions {
  namespaceUuid: string;
  sessionId: string;
  /** The full name as called, for the error text. */
  toolName: string;
  serverPrefix: string;
  originalToolName: string;
  /** The routable servers, from getMcpServers. */
  serverParams: Record<string, ServerParameters>;
  isAllowedServer: (uuid: string) => boolean;
  /** The policy the filter judged this call under; undefined never widens. */
  toolPolicy: NamespaceToolPolicy | undefined;
  /** Whether INACTIVE mounts are routable for this caller (getMcpServers' flag). */
  includeInactiveServers: boolean;
  /** The caller's own `Unknown tool` text (the two paths quote differently). */
  unknownToolMessage: string;
  pool: ToolCallWarmupPool;
  probe: ToolCallProbe;
  /** Prefix for log lines ("" or "OpenAPI bridge: "). */
  logPrefix?: string;
}

export interface ToolCallRoute {
  session: ConnectedClient;
  serverUuid: string;
}

interface UnavailableOwner {
  candidate: PrefixCandidate;
  serverName: string;
  reason: BackendUnavailableReason;
}

const reasonFor = (
  outcome: Exclude<ProbeOutcome, { kind: "found" } | { kind: "absent" }>,
): BackendUnavailableReason =>
  outcome.kind === "no_session" ? "no_session" : "tool_lookup_failed";

/**
 * Resolve the server for a tool name the routing map does not hold, or throw
 * the error the caller should see: `Unknown tool` (no such tool) or
 * `BackendUnavailableError` (a mounted server could not be used; the tool was
 * not run). Never throws anything else for a routing miss: an unexpected fault
 * in the fallback is logged and the verdict falls to the same decision.
 */
export async function routeUnmappedToolCall(
  options: RouteUnmappedToolCallOptions,
): Promise<ToolCallRoute> {
  const {
    namespaceUuid,
    sessionId,
    toolName,
    serverPrefix,
    originalToolName,
    serverParams,
    isAllowedServer,
    pool,
    probe,
  } = options;
  const logPrefix = options.logPrefix ?? "";
  const display = JSON.stringify(toolName);

  const candidates = findPrefixCandidates(
    serverParams,
    serverPrefix,
    isAllowedServer,
  );
  // Two mounted servers can share a name (for example, a public server and
  // the namespace owner's server). A negative listing from one does not rule
  // out the other: retain every failed owner until that owner answers.
  // A nameless candidate may not own the prefix, so it cannot be reported.
  const unavailableOwners = new Map<string, UnavailableOwner>();
  const noteUnavailable = (
    candidate: PrefixCandidate,
    reason: BackendUnavailableReason,
  ): void => {
    if (candidate.named) {
      unavailableOwners.set(candidate.uuid, {
        candidate,
        serverName: candidate.params.name || serverPrefix,
        reason,
      });
    }
  };

  const safeProbe = async (
    session: ConnectedClient,
    candidate: PrefixCandidate,
  ): Promise<ProbeOutcome> => {
    try {
      return await probe(session, candidate);
    } catch (error) {
      logger.error(
        `${logPrefix}tool lookup on server ${candidate.uuid} failed while routing ${display}:`,
        error,
      );
      return { kind: "lookup_failed" };
    }
  };

  for (const candidate of candidates) {
    let session: ConnectedClient | undefined;
    try {
      session = await pool.getSession(
        sessionId,
        candidate.uuid,
        candidate.params,
        namespaceUuid,
      );
    } catch (error) {
      // getSession resolves undefined on every failure path today; a future
      // rejection must still read as "no session", not escape the router.
      logger.error(
        `${logPrefix}session acquisition for server ${candidate.uuid} failed while routing ${display}:`,
        error,
      );
    }
    if (!session) {
      noteUnavailable(candidate, "no_session");
      continue;
    }
    const outcome = await safeProbe(session, candidate);
    if (outcome.kind === "found") {
      return { session: outcome.session, serverUuid: candidate.uuid };
    }
    if (outcome.kind !== "absent") {
      noteUnavailable(candidate, reasonFor(outcome));
    }
  }

  try {
    // Reconnect-window fallback, unchanged: the DB's ACTIVE mapping rows
    // (written by the last successful tools/list sync) name the owning server
    // without a live session. Give that one server a short, bounded chance to
    // come back and route to it. ACTIVE rows only, so this never routes a
    // server whose row for the tool is switched off, nor, under `allowlist`,
    // one with no row (findServersForNamespaceToolName).
    const rows = await namespacesRepository.findServersForNamespaceToolName(
      namespaceUuid,
      originalToolName,
    );
    const match = rows.find(
      (row) =>
        isAllowedServer(row.serverUuid) &&
        sanitizeName(row.serverName || "") === serverPrefix,
    );
    // No params means the server is not routable right now (removed, an
    // INACTIVE mount, or error-gated); the decision below tells those apart.
    const paramsForMatch = match ? serverParams[match.serverUuid] : undefined;

    if (match && paramsForMatch) {
      const warmed = await acquireSessionWithBoundedWarmup({
        pool,
        sessionId,
        serverUuid: match.serverUuid,
        params: paramsForMatch,
        namespaceUuid,
        timeoutMs: await configService.getMcpToolCallReconnectWarmupTimeout(),
      });
      if (warmed && warmed.client.getServerCapabilities()?.tools) {
        return { session: warmed, serverUuid: match.serverUuid };
      }
      if (warmed) {
        unavailableOwners.delete(match.serverUuid);
      } else {
        noteUnavailable(
          { uuid: match.serverUuid, params: paramsForMatch, named: true },
          "no_session",
        );
      }
    } else if (options.toolPolicy === "allow_all") {
      // The zero-mapping-rows gap: no row resolved the tool, so the fallback
      // above had nothing to warm, and the owner by prefix had no session.
      // Under `allow_all` a tool with no row is served, so warm that server the
      // same bounded way and probe it again. Only `allow_all`: under
      // `allowlist` a tool is routed only on an ACTIVE row.
      for (const owner of unavailableOwners.values()) {
        if (owner.reason !== "no_session") continue;
        const warmed = await acquireSessionWithBoundedWarmup({
          pool,
          sessionId,
          serverUuid: owner.candidate.uuid,
          params: owner.candidate.params,
          namespaceUuid,
          timeoutMs: await configService.getMcpToolCallReconnectWarmupTimeout(),
        });
        if (warmed) {
          const outcome = await safeProbe(warmed, owner.candidate);
          if (outcome.kind === "found") {
            return {
              session: outcome.session,
              serverUuid: owner.candidate.uuid,
            };
          }
          if (outcome.kind === "absent") {
            unavailableOwners.delete(owner.candidate.uuid);
          } else {
            noteUnavailable(owner.candidate, reasonFor(outcome));
          }
        }
      }
    }
  } catch (error) {
    // Logged, then decided like any other miss: an unavailable owner already
    // noted still answers as unavailable rather than as an unknown tool.
    logger.error(
      `${logPrefix}routing fallback failed for tool ${display}:`,
      error,
    );
  }

  throw await unroutedToolError({
    namespaceUuid,
    toolName,
    serverPrefix,
    isAllowedServer,
    includeInactiveServers: options.includeInactiveServers,
    unknownToolMessage: options.unknownToolMessage,
    candidates,
    unavailable: unavailableOwners.values().next().value,
    logPrefix,
  });
}

/**
 * The error for a call that could not be routed. A noted unavailable owner
 * answers unavailable. Before answering `Unknown tool`, the namespace's
 * mounted servers are read once more, error-gated ones included: a gated
 * server under the prefix answers unavailable (`error_gated`); a routable,
 * ungated one the first read missed answers unavailable
 * (`routing_lookup_failed`); anything else `Unknown tool`. A failed read also
 * answers `routing_lookup_failed` rather than calling a possibly real tool
 * unknown. A successful negative listing rules out only its own server, not
 * another mounted server with the same name that the routable read omitted.
 */
async function unroutedToolError(options: {
  namespaceUuid: string;
  toolName: string;
  serverPrefix: string;
  isAllowedServer: (uuid: string) => boolean;
  includeInactiveServers: boolean;
  unknownToolMessage: string;
  candidates: PrefixCandidate[];
  unavailable: UnavailableOwner | undefined;
  logPrefix: string;
}): Promise<Error> {
  const { toolName, serverPrefix, unavailable } = options;

  if (unavailable) {
    return new BackendUnavailableError(
      toolName,
      unavailable.serverName,
      unavailable.reason,
    );
  }
  let states;
  try {
    states = await getNamespaceServerStates(options.namespaceUuid);
  } catch (error) {
    logger.error(
      `${options.logPrefix}could not read the servers of namespace ${options.namespaceUuid} while routing ${JSON.stringify(toolName)}:`,
      error,
    );
    return new BackendUnavailableError(
      toolName,
      serverPrefix,
      "routing_lookup_failed",
    );
  }

  const owners = states.filter(
    (state) =>
      options.isAllowedServer(state.uuid) &&
      sanitizeName(state.name) === serverPrefix &&
      !options.candidates.some((candidate) => candidate.uuid === state.uuid) &&
      (options.includeInactiveServers ||
        state.mountStatus === McpServerStatusEnum.enum.ACTIVE),
  );
  const gated = owners.find(
    (state) => state.errorStatus !== McpServerErrorStatusEnum.enum.NONE,
  );
  if (gated) {
    return new BackendUnavailableError(toolName, gated.name, "error_gated");
  }
  // Mounted, routable and not gated, yet absent from the routable set this
  // call read moments ago: that read failed (getMcpServers answers an empty
  // set on a database error, it does not throw) or the server was mounted in
  // between. Either way the name is not unknown, so it must not read as one.
  // (getMcpServers also skips an SSE or Streamable-HTTP server stored with no
  // url, a database-only edge the API refuses; that one lands here too.)
  const unread = owners[0];
  if (unread) {
    return new BackendUnavailableError(
      toolName,
      unread.name,
      "routing_lookup_failed",
    );
  }
  return new Error(options.unknownToolMessage);
}
