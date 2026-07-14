import {
  ListToolsResultSchema,
  Tool,
} from "@modelcontextprotocol/sdk/types.js";
import { ServerParameters } from "@repo/zod-types";
import { z } from "zod";

import logger from "@/utils/logger";

// Import the specific repo file (not the ../../db/repositories barrel): the
// barrel pulls in sibling repos whose module-load reaches db/index, which the
// pool unit test can't satisfy (no DATABASE_URL). server-error-tracker is
// fully mocked in that test, so this is the only live db import the pool has.
import { mcpServersRepository } from "../../db/repositories/mcp-servers.repo";
import { configService } from "../config.service";
import { ConnectedClient, connectMetaMcpClient } from "./client";
import { serverErrorTracker } from "./server-error-tracker";
import { toolsSyncCache } from "./tools-sync-cache";

// Per-server tools/list timeout for the periodic sweep. Bounds a single
// backend's re-list so a slow or mid-restart server can't stall the sweep;
// the sweep already isolates per-server failures, this just caps the wait.
const TOOLS_SWEEP_REQUEST_TIMEOUT_MS = 10000;

// Hard backstop on tools/list pagination during a sweep. Paired with the
// non-advancing-cursor check in listToolsForSweep: that check catches a
// backend replaying the SAME cursor, this catches any other shape of
// infinite/very-long pagination. Without a cap, an unbounded loop here
// would wedge the sweep permanently — toolsSweepInProgress only clears in
// sweepToolDefinitions's `finally`, so every future tick would be skipped
// by the in-flight guard forever.
const TOOLS_SWEEP_MAX_PAGES = 50;

export interface McpServerPoolStatus {
  idle: number;
  active: number;
  // In-flight idle-session creations (this.creatingIdleSessions.size) — the
  // SAME count getTotalConnectionCount() adds to idle+active for the
  // MAX_TOTAL_CONNECTIONS cap check. Exposed so /health/upstream's `total`
  // can match what the cap logic actually compares against, instead of
  // silently undercounting by the in-flight set (2026-07-14 audit finding).
  pending?: number;
  activeSessionIds: string[];
  idleServerUuids: string[];
  perServerCounts?: Record<string, number>;
  maxConnectionsPerServer?: number;
  // Per-server connect/health telemetry for /health/upstream. A serverUuid
  // present in lastConnectFailureAt means its MOST RECENT connect attempt
  // failed (the stamp is cleared on every successful connect), so
  // "zero connections + a failure stamp" distinguishes a down backend
  // from one that simply hasn't been needed yet.
  lastConnectFailureAt?: Record<string, number>;
  lastConnectSuccessAt?: Record<string, number>;
  pingFailures?: Record<string, number>;
}

export class McpServerPool {
  // Singleton instance
  private static instance: McpServerPool | null = null;

  // Idle sessions: serverUuid -> ConnectedClient (no sessionId assigned yet)
  private idleSessions: Record<string, ConnectedClient> = {};

  // Active sessions: sessionId -> Record<serverUuid, ConnectedClient>
  private activeSessions: Record<string, Record<string, ConnectedClient>> = {};

  // Mapping: sessionId -> Set<serverUuid> for cleanup tracking
  private sessionToServers: Record<string, Set<string>> = {};

  // Session creation timestamps: sessionId -> timestamp
  private sessionTimestamps: Record<string, number> = {};

  // Server parameters cache: serverUuid -> ServerParameters
  private serverParamsCache: Record<string, ServerParameters> = {};

  // Track ongoing idle session creation to prevent duplicates
  private creatingIdleSessions: Set<string> = new Set();

  // Generation counter per server UUID: incremented by invalidateIdleSession() so
  // any in-flight createIdleSession / createIdleSessionAsync that resolves with a
  // stale generation knows to discard its result instead of storing it.
  private idleSessionGenerations: Record<string, number> = {};

  // Session cleanup timer
  private cleanupTimer: NodeJS.Timeout | null = null;

  // Health check timer for idle sessions
  private healthCheckTimer: NodeJS.Timeout | null = null;

  // Periodic tool-definition drift sweep timer. Re-lists tools over an
  // existing pooled connection and fires the invalidation cascade when the
  // full-definition hash has changed. Null when disabled
  // (TOOLS_SWEEP_INTERVAL_SECONDS <= 0).
  private toolsSweepTimer: NodeJS.Timeout | null = null;

  // Re-entrancy guard: at most one sweep runs at a time. An interval tick
  // that fires while the previous sweep is still awaiting backends is
  // skipped rather than overlapped.
  private toolsSweepInProgress = false;

  // Sweep-owned per-server baseline: the full-definition hash (Track A3's
  // toolsSyncCache.hashTools, used here as a pure function only — never the
  // shared cache's stateful hasChanged/update) that the SWEEP itself last
  // observed for each serverUuid. Deliberately independent of
  // toolsSyncCache's own state (review findings, 2026-07-14):
  //   - An idle-only server has zero listChangedSubscribers, so the
  //     invalidation fan-out reaches no one and nothing downstream ever
  //     touches toolsSyncCache. Comparing against that frozen cache would
  //     re-detect the SAME already-handled change every tick, forever.
  //   - tools.impl.sync overwrites toolsSyncCache with the
  //     NAMESPACE-FILTERED tool set whenever filterOutOverrideTools drops a
  //     tool, while the sweep always lists the UNFILTERED set — a
  //     permanent false-drift mismatch even for servers with active
  //     consumers.
  // Owning a separate baseline makes both impossible: always
  // unfiltered-vs-unfiltered, and updating it the moment a change is
  // observed makes the invalidate fire exactly ONCE per real change.
  private toolsSweepLastHash: Record<string, string> = {};

  // Sweep interval in ms. <= 0 disables the sweep entirely (no timer).
  private readonly toolsSweepIntervalMs: number;

  // Background idle sessions by namespace: namespaceUuid -> any
  private backgroundIdleSessionsByNamespace: Map<string, any> = new Map();

  // Consecutive health-sweep ping failures for ACTIVE pooled
  // connections, keyed by serverUuid. Eviction requires 2 consecutive
  // failed sweeps so one slow ping (e.g. a backend briefly saturated
  // by a long tool call) can't tear down a healthy connection set.
  // Cleared on any successful sweep and on eviction.
  private activePingFailures: Record<string, number> = {};

  // Env kill-switch for the active-session health sweep
  // (`MCP_ACTIVE_HEALTH_CHECK=false`). Default on. Same posture as
  // MCP_AUTO_NUKE_ON_CAPABILITY_CHANGE: disable only for forensic
  // debugging of a live pool.
  private readonly activeHealthCheckEnabled: boolean;

  // Last half-open probe per ERROR-gated server, keyed by serverUuid.
  // The ERROR circuit breaker (DB error_status) is otherwise sticky
  // forever: nothing on the request path resets it once the pool holds
  // any live connection for any OTHER server (the cold-start warmup's
  // idle===0 && active===0 guard never fires), so an ERROR-gated
  // backend stays excluded until an admin reset or a process restart.
  private lastErrorProbeAt: Record<string, number> = {};

  // Half-open probe interval (ms) for ERROR-gated servers, env
  // `MCP_ERROR_PROBE_INTERVAL_MS`; default 5 min; <= 0 disables.
  private readonly errorProbeIntervalMs: number;

  // Per-server timestamp of the most recent successful connection.
  // Used by the recovery-reset path: if a transport drop produces a
  // SUCCESSFUL reconnect within `MCP_RECOVERY_RESET_THRESHOLD_MS` of
  // the last success, we treat the drop as transient (watchtower
  // bounce / network blip) and clear the error tracker count so the
  // sticky circuit breaker doesn't accumulate against legitimate
  // bounces. If the gap exceeds the threshold, the bounce is treated
  // as a genuine failure cluster and the tracker count is preserved.
  private serverLastSuccessAt: Record<string, number> = {};

  // Per-server timestamp of the most recent FAILED connect attempt.
  // Cleared on every successful connect, so an entry here means the
  // latest attempt to reach this backend failed. HTTP/SSE backends
  // never trip the ERROR circuit breaker (crash counting is
  // STDIO-only), so without this stamp a hard-down HTTP backend reads
  // "reachable" on /health/upstream forever — the endpoint's only
  // signal was `!in_error`. Surfaced via getPoolStatus for the
  // external uptime probe.
  private lastConnectFailureAt: Record<string, number> = {};

  // Time-since-success threshold (ms) for the recovery reset path.
  // Tunable via `MCP_RECOVERY_RESET_THRESHOLD_MS`; default 5 min.
  private readonly recoveryResetThresholdMs: number;

  // Default number of idle sessions per server UUID
  private readonly defaultIdleCount: number;

  // Maximum total connections (idle + active) to prevent runaway process spawning
  private readonly maxTotalConnections: number;

  // Maximum connections per individual server UUID (prevents per-server process explosion)
  private readonly maxConnectionsPerServer: number;

  private constructor(
    defaultIdleCount: number = 1,
    maxTotalConnections: number = parseInt(
      process.env.MAX_TOTAL_CONNECTIONS || "100",
      10,
    ),
    maxConnectionsPerServer: number = parseInt(
      process.env.MAX_CONNECTIONS_PER_SERVER || "5",
      10,
    ),
  ) {
    this.defaultIdleCount = defaultIdleCount;
    this.maxTotalConnections = maxTotalConnections;
    this.maxConnectionsPerServer = maxConnectionsPerServer;
    this.recoveryResetThresholdMs = parseInt(
      process.env.MCP_RECOVERY_RESET_THRESHOLD_MS || "300000",
      10,
    );
    this.activeHealthCheckEnabled =
      (process.env.MCP_ACTIVE_HEALTH_CHECK || "true").toLowerCase() !== "false";
    this.errorProbeIntervalMs = parseInt(
      process.env.MCP_ERROR_PROBE_INTERVAL_MS || "300000",
      10,
    );
    this.toolsSweepIntervalMs =
      parseInt(process.env.TOOLS_SWEEP_INTERVAL_SECONDS || "60", 10) * 1000;
    this.startCleanupTimer();
    this.startHealthCheckTimer();
    this.startToolsSweepTimer();
  }

  /**
   * Get the singleton instance
   */
  static getInstance(
    defaultIdleCount: number = 1,
    maxConnectionsPerServer: number = 5,
  ): McpServerPool {
    if (!McpServerPool.instance) {
      McpServerPool.instance = new McpServerPool(
        defaultIdleCount,
        100,
        maxConnectionsPerServer,
      );
    }
    return McpServerPool.instance;
  }

  /**
   * Count all connections (idle + active + pending) for a specific server UUID
   */
  private countConnectionsForServer(serverUuid: string): number {
    let count = 0;

    // Count idle session
    if (this.idleSessions[serverUuid]) {
      count += 1;
    }

    // Count active sessions across all sessionIds
    for (const sessionServers of Object.values(this.activeSessions)) {
      if (sessionServers[serverUuid]) {
        count += 1;
      }
    }

    // Count pending idle creation
    if (this.creatingIdleSessions.has(serverUuid)) {
      count += 1;
    }

    return count;
  }

  /**
   * Check if we can create another connection for a specific server
   */
  private canCreateConnectionForServer(serverUuid: string): boolean {
    const count = this.countConnectionsForServer(serverUuid);
    if (count >= this.maxConnectionsPerServer) {
      logger.warn(
        `Per-server connection limit reached for ${serverUuid}: ${count}/${this.maxConnectionsPerServer}`,
      );
      return false;
    }
    return true;
  }

  /**
   * Find the oldest active connection for a server UUID (for reuse when at cap)
   */
  private findOldestActiveConnectionForServer(
    serverUuid: string,
  ): ConnectedClient | undefined {
    let oldestSessionId: string | undefined;
    let oldestTimestamp = Infinity;

    for (const [sessionId, sessionServers] of Object.entries(
      this.activeSessions,
    )) {
      if (sessionServers[serverUuid]) {
        const timestamp = this.sessionTimestamps[sessionId] || Infinity;
        if (timestamp < oldestTimestamp) {
          oldestTimestamp = timestamp;
          oldestSessionId = sessionId;
        }
      }
    }

    if (oldestSessionId) {
      return this.activeSessions[oldestSessionId]?.[serverUuid];
    }
    return undefined;
  }

  /**
   * Get or create a session for a specific MCP server
   */
  async getSession(
    sessionId: string,
    serverUuid: string,
    params: ServerParameters,
    namespaceUuid?: string,
  ): Promise<ConnectedClient | undefined> {
    // Update server params cache
    this.serverParamsCache[serverUuid] = params;

    // Check if we already have an active session for this sessionId and server
    if (this.activeSessions[sessionId]?.[serverUuid]) {
      // Touch timestamp on every access so SESSION_LIFETIME acts as idle timeout, not hard TTL
      this.sessionTimestamps[sessionId] = Date.now();
      return this.activeSessions[sessionId][serverUuid];
    }

    // Initialize session if it doesn't exist
    if (!this.activeSessions[sessionId]) {
      this.activeSessions[sessionId] = {};
      this.sessionToServers[sessionId] = new Set();
      this.sessionTimestamps[sessionId] = Date.now();
    }

    // Check if we have an idle session for this server that we can convert
    const idleClient = this.idleSessions[serverUuid];
    if (idleClient) {
      // Convert idle session to active session
      delete this.idleSessions[serverUuid];
      this.activeSessions[sessionId][serverUuid] = idleClient;
      this.sessionToServers[sessionId].add(serverUuid);

      logger.info(
        `Converted idle session to active for server ${serverUuid}, session ${sessionId}`,
      );

      // Create a new idle session to replace the one we just used (ASYNC - NON-BLOCKING)
      this.createIdleSessionAsync(serverUuid, params, namespaceUuid);

      return idleClient;
    }

    // No idle session available — check per-server cap before spawning
    if (!this.canCreateConnectionForServer(serverUuid)) {
      // At cap: reuse the oldest active connection instead of spawning
      const reusable = this.findOldestActiveConnectionForServer(serverUuid);
      if (reusable) {
        logger.info(
          `Reusing existing connection for server ${serverUuid} (at per-server cap ${this.maxConnectionsPerServer})`,
        );
        this.activeSessions[sessionId][serverUuid] = reusable;
        this.sessionToServers[sessionId].add(serverUuid);
        return reusable;
      }
    }

    const newClient = await this.createNewConnection(params, namespaceUuid);
    if (!newClient) {
      return undefined;
    }

    // Re-check after the async gap: a concurrent getSession() call for the same
    // (sessionId, serverUuid) pair may have stored a connection while we were awaiting
    // createNewConnection(). If so, discard ours to avoid leaking the spawned process.
    if (this.activeSessions[sessionId]?.[serverUuid]) {
      newClient.cleanup().catch((error) => {
        logger.error(
          `Error cleaning up duplicate connection for server ${params.uuid}:`,
          error,
        );
      });
      return this.activeSessions[sessionId][serverUuid];
    }

    this.activeSessions[sessionId][serverUuid] = newClient;
    this.sessionToServers[sessionId].add(serverUuid);

    logger.info(
      `Created new active session for server ${serverUuid}, session ${sessionId}`,
    );

    // Also create an idle session for future use (ASYNC - NON-BLOCKING)
    this.createIdleSessionAsync(serverUuid, params, namespaceUuid);

    return newClient;
  }

  /**
   * Create a new connection for a server
   */
  private async createNewConnection(
    params: ServerParameters,
    namespaceUuid?: string,
  ): Promise<ConnectedClient | undefined> {
    // Check connection limit before attempting to create. At the cap,
    // evict the least-valuable slot (oldest idle, else oldest active) and
    // retry instead of hard-refusing — a hard refuse permanently locks out
    // a backend that needs to reconnect after a restart and deadlocks the
    // pool until a manual `docker restart metamcp`. See evictOneForCapacity.
    if (!this.canCreateConnection()) {
      const freed = await this.evictOneForCapacity(params.uuid);
      if (!freed || !this.canCreateConnection()) {
        logger.warn(
          `Skipping connection for server ${params.name} (${params.uuid}) - connection limit reached`,
        );
        return undefined;
      }
    }

    logger.info(
      `Creating new connection for server ${params.name} (${params.uuid}) with namespace: ${namespaceUuid || "none"}`,
    );

    const connectedClient = await connectMetaMcpClient(
      params,
      (exitCode, signal) => {
        logger.info(
          `Crash handler callback called for server ${params.name} (${params.uuid}) with namespace: ${namespaceUuid || "none"}`,
        );

        // Handle process crash - always set up crash handler
        if (namespaceUuid) {
          // If we have a namespace context, use it
          this.handleServerCrash(
            params.uuid,
            namespaceUuid,
            exitCode,
            signal,
          ).catch((error) => {
            logger.error(
              `Error handling server crash for ${params.uuid} in ${namespaceUuid}:`,
              error,
            );
          });
        } else {
          // If no namespace context, still track the crash globally
          this.handleServerCrashWithoutNamespace(
            params.uuid,
            exitCode,
            signal,
          ).catch((error) => {
            logger.error(
              `Error handling server crash for ${params.uuid} (no namespace):`,
              error,
            );
          });
        }
      },
      (reason, dropError) => {
        // HTTP/SSE parity with STDIO's `onProcessCrash`. Watchtower
        // restarts of the backend container leave our pooled
        // ConnectedClient with a dead socket; this callback fires
        // when the SDK Transport reports the drop (`onclose` or
        // `onerror`). We schedule the same cascade invalidation
        // PR #16 wired for the request-path recovery — fan out
        // `list_changed` (PR #19) and drop every pool slot for this
        // serverUuid so the next getSession spawns a fresh
        // connection. The async wrapper avoids blocking the SDK's
        // notification dispatcher on cleanup latency.
        this.handleTransportDrop(params.uuid, reason, dropError).catch(
          (error) => {
            logger.error(
              `Error handling transport drop for ${params.uuid}:`,
              error,
            );
          },
        );
      },
    );
    if (!connectedClient) {
      // connectMetaMcpClient swallows its own errors and resolves
      // undefined, so this is the single chokepoint where every
      // failed connect attempt (cold start, sweep-triggered rebuild,
      // half-open probe) lands. Stamp it for /health/upstream.
      this.lastConnectFailureAt[params.uuid] = Date.now();
      return undefined;
    }

    // Mark this serverUuid as having a recent successful connection.
    // Used by the recovery-reset threshold: if the next failure-then-
    // success cycle lands within the threshold, we'll clear the
    // circuit breaker accumulation.
    this.markServerSuccess(params.uuid);

    return connectedClient;
  }

  /**
   * Record that a server connection successfully established. Used
   * by the recovery-reset path: a drop followed by a quick success
   * means watchtower / network bounce, not real failure.
   */
  private markServerSuccess(serverUuid: string): void {
    this.serverLastSuccessAt[serverUuid] = Date.now();
    delete this.lastConnectFailureAt[serverUuid];
    serverErrorTracker.markSuccess(serverUuid);
  }

  /**
   * Handle an HTTP/SSE transport drop callback. Mirrors the recovery
   * path used by `metamcp-proxy.ts`'s on-request recovery: cascade
   * invalidate every pool slot for the affected serverUuid (which
   * also fires `listChangedSubscribers` from PR #19) and, if we had
   * a recent success, reset the error tracker so a transient bounce
   * doesn't accumulate the circuit breaker count.
   */
  private async handleTransportDrop(
    serverUuid: string,
    reason: "close" | "error",
    error?: Error,
  ): Promise<void> {
    logger.warn(
      `Transport drop for server ${serverUuid}: reason=${reason}`,
      error,
    );

    // Recovery-reset: if the most recent success was within the
    // threshold, this is a transient bounce — clear the accumulated
    // crash attempts so the sticky circuit breaker can't refuse
    // future reconnects after a few bounces in a row. If the gap
    // exceeds the threshold (sustained failure), preserve the count.
    const lastSuccess = this.serverLastSuccessAt[serverUuid];
    if (
      lastSuccess !== undefined &&
      Date.now() - lastSuccess <= this.recoveryResetThresholdMs
    ) {
      logger.info(
        `Resetting error tracker attempts for ${serverUuid} (transient drop within ${this.recoveryResetThresholdMs}ms of last success)`,
      );
      serverErrorTracker.resetServerAttempts(serverUuid);
    }

    // Cascade invalidate across every session's slot for this
    // serverUuid. The `<transport-drop>` sentinel session-id is for
    // log readability — invalidateServerConnection iterates ALL
    // sessions, the parameter is only used in the log line.
    await this.invalidateServerConnection("<transport-drop>", serverUuid);
  }

  /**
   * Create an idle session for a server (blocking version for initial setup)
   */
  private async createIdleSession(
    serverUuid: string,
    params: ServerParameters,
    namespaceUuid?: string,
  ): Promise<void> {
    // Don't create if we already have an idle session or are already creating one.
    // Both checks are synchronous (before any await) so they act as a pre-await
    // mutex, matching the pattern used by createIdleSessionAsync.
    if (
      this.idleSessions[serverUuid] ||
      this.creatingIdleSessions.has(serverUuid)
    ) {
      return;
    }

    // Don't create if at per-server cap (#260) — happens before the
    // generation-tracking guard from #273 to short-circuit cap-blocked
    // calls without entering the concurrency-protected critical section.
    if (!this.canCreateConnectionForServer(serverUuid)) {
      return;
    }

    this.creatingIdleSessions.add(serverUuid);
    const generation = this.idleSessionGenerations[serverUuid] ?? 0;

    try {
      const newClient = await this.createNewConnection(params, namespaceUuid);
      if (newClient) {
        const currentGeneration = this.idleSessionGenerations[serverUuid] ?? 0;
        if (
          !this.idleSessions[serverUuid] &&
          currentGeneration === generation
        ) {
          this.idleSessions[serverUuid] = newClient;
          logger.info(`Created idle session for server ${serverUuid}`);
        } else {
          // Either a concurrent call already stored an idle session, or
          // invalidateIdleSession() bumped the generation while we were awaiting,
          // meaning our result is stale. Discard it.
          newClient.cleanup().catch((error) => {
            logger.error(
              `Error cleaning up duplicate idle session for ${serverUuid}:`,
              error,
            );
          });
        }
      }
    } finally {
      // Only release the guard if we're still the current creation for this
      // server. If the generation was bumped while we were awaiting (e.g. by
      // invalidateIdleSession), the guard now belongs to the newer creation
      // and must not be removed here.
      if ((this.idleSessionGenerations[serverUuid] ?? 0) === generation) {
        this.creatingIdleSessions.delete(serverUuid);
      }
    }
  }

  /**
   * Create an idle session for a server asynchronously (non-blocking)
   */
  private createIdleSessionAsync(
    serverUuid: string,
    params: ServerParameters,
    namespaceUuid?: string,
  ): void {
    // Don't create if we already have an idle session or are already creating one
    if (
      this.idleSessions[serverUuid] ||
      this.creatingIdleSessions.has(serverUuid)
    ) {
      return;
    }

    // Check per-server cap before spawning a background idle
    if (!this.canCreateConnectionForServer(serverUuid)) {
      return;
    }

    // Mark that we're creating an idle session for this server
    this.creatingIdleSessions.add(serverUuid);
    const generation = this.idleSessionGenerations[serverUuid] ?? 0;

    // Create the session in the background (fire and forget)
    this.createNewConnection(params, namespaceUuid)
      .then((newClient) => {
        const currentGeneration = this.idleSessionGenerations[serverUuid] ?? 0;
        if (
          newClient &&
          !this.idleSessions[serverUuid] &&
          currentGeneration === generation
        ) {
          this.idleSessions[serverUuid] = newClient;
          logger.info(
            `Created background idle session for server [${params.name}] ${serverUuid}`,
          );
          if (namespaceUuid) {
            this.setBackgroundIdleSessionsByNamespace(
              namespaceUuid,
              new Map().set("status", "created"),
            );
          }
        } else if (newClient) {
          // Either we already have an idle session, or invalidateIdleSession()
          // bumped the generation while we were awaiting (stale result). Discard it.
          newClient.cleanup().catch((error) => {
            logger.error(
              `Error cleaning up extra idle session for ${serverUuid}:`,
              error,
            );
          });
        }
      })
      .catch((error) => {
        logger.error(
          `Error creating background idle session for ${serverUuid}:`,
          error,
        );
      })
      .finally(() => {
        // Only release the guard if we're still the current creation for this
        // server. If the generation was bumped while we were awaiting (e.g. by
        // invalidateIdleSession), the guard now belongs to the newer creation
        // and must not be removed here.
        if ((this.idleSessionGenerations[serverUuid] ?? 0) === generation) {
          this.creatingIdleSessions.delete(serverUuid);
        }
      });
  }

  /**
   * Ensure idle sessions exist for all servers
   */
  async ensureIdleSessions(
    serverParams: Record<string, ServerParameters>,
    namespaceUuid?: string,
  ): Promise<void> {
    const promises = Object.entries(serverParams).map(
      async ([uuid, params]) => {
        if (!this.idleSessions[uuid]) {
          await this.createIdleSession(uuid, params, namespaceUuid);
        }
      },
    );

    await Promise.allSettled(promises);
  }

  /**
   * Cleanup a session by sessionId.
   * Recycles healthy connections back to the idle pool instead of destroying them.
   */
  async cleanupSession(sessionId: string): Promise<void> {
    const activeSession = this.activeSessions[sessionId];
    if (!activeSession) {
      return;
    }

    let recycled = 0;
    let destroyed = 0;

    // Try to recycle each connection back to idle pool
    for (const [serverUuid, client] of Object.entries(activeSession)) {
      if (!this.idleSessions[serverUuid]) {
        // No idle session for this server — recycle the connection
        this.idleSessions[serverUuid] = client;
        recycled++;
        logger.info(
          `Recycled active connection for server ${serverUuid} to idle pool (session ${sessionId})`,
        );
      } else {
        // Already have an idle session — destroy the extra
        try {
          await client.cleanup();
        } catch (error) {
          logger.error(
            `Error cleaning up extra connection for server ${serverUuid}:`,
            error,
          );
        }
        destroyed++;
      }
    }

    // Remove from active sessions
    delete this.activeSessions[sessionId];

    // Clean up session timestamp
    delete this.sessionTimestamps[sessionId];

    // Clean up session to servers mapping
    delete this.sessionToServers[sessionId];

    logger.info(
      `Cleaned up session ${sessionId} (recycled: ${recycled}, destroyed: ${destroyed})`,
    );
  }

  /**
   * Cleanup all sessions
   */
  async cleanupAll(): Promise<void> {
    // Cleanup all active sessions
    const activeSessionIds = Object.keys(this.activeSessions);
    await Promise.allSettled(
      activeSessionIds.map((sessionId) => this.cleanupSession(sessionId)),
    );

    // Cleanup all idle sessions
    await Promise.allSettled(
      Object.entries(this.idleSessions).map(async ([_uuid, client]) => {
        await client.cleanup();
      }),
    );

    // Clear all state
    this.idleSessions = {};
    this.activeSessions = {};
    this.sessionToServers = {};
    this.sessionTimestamps = {};
    this.serverParamsCache = {};

    // Bump all known generations (never reset to {}) so any in-flight idle
    // creation that started before cleanupAll() resolves with a stale value
    // and discards itself. Cover both tracked entries and UUIDs that are only
    // in creatingIdleSessions (which default to 0 and have no map entry yet).
    for (const uuid of new Set([
      ...Object.keys(this.idleSessionGenerations),
      ...this.creatingIdleSessions,
    ])) {
      this.idleSessionGenerations[uuid] =
        (this.idleSessionGenerations[uuid] ?? 0) + 1;
    }
    this.creatingIdleSessions.clear();

    // Clear cleanup timer
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;
    }

    // Clear health check timer
    if (this.healthCheckTimer) {
      clearInterval(this.healthCheckTimer);
      this.healthCheckTimer = null;
    }

    // Clear tool-definition sweep timer
    if (this.toolsSweepTimer) {
      clearInterval(this.toolsSweepTimer);
      this.toolsSweepTimer = null;
    }

    logger.info("Cleaned up all MCP server pool sessions");
  }

  /**
   * Get pool status for monitoring
   */
  getPoolStatus(): McpServerPoolStatus {
    const idle = Object.keys(this.idleSessions).length;
    const active = Object.keys(this.activeSessions).reduce(
      (total, sessionId) =>
        total + Object.keys(this.activeSessions[sessionId]).length,
      0,
    );

    // Calculate per-server breakdown
    const perServerCounts: Record<string, number> = {};
    for (const serverUuid of Object.keys(this.serverParamsCache)) {
      perServerCounts[serverUuid] = this.countConnectionsForServer(serverUuid);
    }

    return {
      idle,
      active,
      pending: this.creatingIdleSessions.size,
      activeSessionIds: Object.keys(this.activeSessions),
      idleServerUuids: Object.keys(this.idleSessions),
      perServerCounts,
      maxConnectionsPerServer: this.maxConnectionsPerServer,
      lastConnectFailureAt: { ...this.lastConnectFailureAt },
      lastConnectSuccessAt: { ...this.serverLastSuccessAt },
      pingFailures: { ...this.activePingFailures },
    };
  }

  /**
   * Read-only view of the pool's EFFECTIVE connection caps, for
   * /health/upstream. Returns exactly what this running pool enforces —
   * the single source of truth — so the health endpoint never re-parses env
   * with its own (possibly divergent) defaults. Note: the singleton is
   * constructed via getInstance(), which currently passes hardcoded caps and
   * bypasses the constructor's env-parse; this getter faithfully reports the
   * value in effect regardless of how it was set.
   */
  getPoolConfig(): {
    maxConnectionsPerServer: number;
    maxTotalConnections: number;
  } {
    return {
      maxConnectionsPerServer: this.maxConnectionsPerServer,
      maxTotalConnections: this.maxTotalConnections,
    };
  }

  /**
   * Get total connection count (idle + active + pending)
   */
  private getTotalConnectionCount(): number {
    const idle = Object.keys(this.idleSessions).length;
    const active = Object.keys(this.activeSessions).reduce(
      (total, sessionId) =>
        total + Object.keys(this.activeSessions[sessionId]).length,
      0,
    );
    const pending = this.creatingIdleSessions.size;
    return idle + active + pending;
  }

  /**
   * Check if we can create a new connection (respects maxTotalConnections limit)
   */
  private canCreateConnection(): boolean {
    const total = this.getTotalConnectionCount();
    if (total >= this.maxTotalConnections) {
      logger.warn(
        `Connection limit reached: ${total}/${this.maxTotalConnections}. Refusing to create new connection.`,
      );
      return false;
    }
    return true;
  }

  /**
   * Free ONE pool slot when at the global cap, so a server that needs a
   * fresh connection is never permanently locked out.
   *
   * Why this exists: `maxTotalConnections` was a HARD refuse. Under
   * persistent sessions (`sessionLifetime === null`) `cleanupExpiredSessions`
   * no-ops, and `cleanupSession` RECYCLES active connections back into the
   * idle pool rather than destroying them — so the idle pool grows
   * unbounded until `getTotalConnectionCount` hits the cap. Once full,
   * `canCreateConnection` refused EVERY new connection, including the
   * recreation a backend needs after its container restarts (Watchtower).
   * The pool then deadlocked until a manual `docker restart metamcp`
   * (observed 2026-05-27: autotask wedged on "connection limit reached"
   * for 8+ minutes after a redeploy).
   *
   * Eviction reclaims capacity by DESTROYING (not recycling) the
   * least-valuable slot: an idle session first (no upstream client depends
   * on it — and idle is where the recycled surplus accumulates), else the
   * oldest-touched active connection. Returns true if a slot was freed.
   * Note: we destroy directly here; `cleanupSession` would recycle the
   * connection back to idle and free nothing.
   */
  private async evictOneForCapacity(forServerUuid: string): Promise<boolean> {
    // 1. Prefer an idle session. Avoid evicting the server we're about to
    //    (re)connect; fall back to any idle slot if it's the only one.
    const idleUuids = Object.keys(this.idleSessions);
    const idleTarget =
      idleUuids.find((uuid) => uuid !== forServerUuid) ?? idleUuids[0];
    if (idleTarget) {
      const client = this.idleSessions[idleTarget];
      // Drop the map entry synchronously so the slot is freed before the
      // (async) cleanup and a concurrent count sees the reduced total.
      delete this.idleSessions[idleTarget];
      logger.warn(
        `Pool at cap (${this.maxTotalConnections}); destroying idle session for ${idleTarget} to admit ${forServerUuid}`,
      );
      try {
        await client?.cleanup();
      } catch (error) {
        logger.error(
          `Error destroying idle session ${idleTarget} during capacity eviction:`,
          error,
        );
      }
      return true;
    }

    // 2. No idle slots — every slot is an in-use active connection. Destroy
    //    the oldest-touched active connection for some OTHER server (LRU by
    //    session timestamp). Disruptive, but bounded to one slot, and the
    //    evicted session re-establishes on its next request.
    let oldestSid: string | undefined;
    let oldestUuid: string | undefined;
    let oldestTs = Infinity;
    for (const [sid, servers] of Object.entries(this.activeSessions)) {
      const ts = this.sessionTimestamps[sid] ?? Infinity;
      if (ts >= oldestTs) continue;
      for (const uuid of Object.keys(servers)) {
        if (uuid === forServerUuid) continue;
        oldestTs = ts;
        oldestSid = sid;
        oldestUuid = uuid;
        break;
      }
    }
    if (oldestSid && oldestUuid) {
      const client = this.activeSessions[oldestSid]?.[oldestUuid];
      if (client) {
        delete this.activeSessions[oldestSid][oldestUuid];
        this.sessionToServers[oldestSid]?.delete(oldestUuid);
        logger.warn(
          `Pool at cap (${this.maxTotalConnections}) with no idle slots; ` +
            `destroying oldest active connection ${oldestSid}/${oldestUuid} to admit ${forServerUuid}`,
        );
        try {
          await client.cleanup();
        } catch (error) {
          logger.error(
            `Error destroying active connection ${oldestSid}/${oldestUuid} during capacity eviction:`,
            error,
          );
        }
        return true;
      }
    }

    return false;
  }

  /**
   * Get active session connections for a specific session (for debugging/monitoring)
   */
  getSessionConnections(
    sessionId: string,
  ): Record<string, ConnectedClient> | undefined {
    return this.activeSessions[sessionId];
  }

  /**
   * Get all active session IDs (for debugging/monitoring)
   */
  getActiveSessionIds(): string[] {
    return Object.keys(this.activeSessions);
  }

  /**
   * Get background idle sessions by namespace
   */
  getBackgroundIdleSessionsByNamespace(): Map<string, any> {
    return this.backgroundIdleSessionsByNamespace;
  }

  /**
   * Set background idle sessions by namespace
   */
  setBackgroundIdleSessionsByNamespace(
    namespaceUuid: string,
    options: any,
  ): void {
    this.backgroundIdleSessionsByNamespace.set(namespaceUuid, options);
  }

  /**
   * Invalidate and refresh idle session for a specific server
   * This should be called when a server's parameters (command, args, etc.) change
   */
  async invalidateIdleSession(
    serverUuid: string,
    params: ServerParameters,
    namespaceUuid?: string,
  ): Promise<void> {
    logger.info(`Invalidating idle session for server ${serverUuid}`);

    // Update server params cache
    this.serverParamsCache[serverUuid] = params;

    // Cleanup existing idle session if it exists
    const existingIdleSession = this.idleSessions[serverUuid];
    if (existingIdleSession) {
      try {
        await existingIdleSession.cleanup();
        logger.info(
          `Cleaned up existing idle session for server ${serverUuid}`,
        );
      } catch (error) {
        logger.error(
          `Error cleaning up existing idle session for server ${serverUuid}:`,
          error,
        );
      }
      delete this.idleSessions[serverUuid];
    }

    // Bump the generation before clearing the in-progress guard so any
    // in-flight createIdleSession / createIdleSessionAsync that resolves
    // after this point will see a stale generation and discard its result.
    this.idleSessionGenerations[serverUuid] =
      (this.idleSessionGenerations[serverUuid] ?? 0) + 1;
    this.creatingIdleSessions.delete(serverUuid);

    // Create a new idle session with updated parameters
    await this.createIdleSession(serverUuid, params, namespaceUuid);
  }

  /**
   * Invalidate and refresh idle sessions for multiple servers
   */
  async invalidateIdleSessions(
    serverParams: Record<string, ServerParameters>,
    namespaceUuid?: string,
  ): Promise<void> {
    const promises = Object.entries(serverParams).map(([serverUuid, params]) =>
      this.invalidateIdleSession(serverUuid, params, namespaceUuid),
    );

    await Promise.allSettled(promises);
  }

  /**
   * Clean up idle session for a specific server without creating a new one
   * This should be called when a server is being deleted
   */
  async cleanupIdleSession(serverUuid: string): Promise<void> {
    logger.info(`Cleaning up idle session for server ${serverUuid}`);

    // Cleanup existing idle session if it exists
    const existingIdleSession = this.idleSessions[serverUuid];
    if (existingIdleSession) {
      try {
        await existingIdleSession.cleanup();
        logger.info(`Cleaned up idle session for server ${serverUuid}`);
      } catch (error) {
        logger.error(
          `Error cleaning up idle session for server ${serverUuid}:`,
          error,
        );
      }
      delete this.idleSessions[serverUuid];
    }

    // Bump rather than delete the generation entry. Deleting would reset the
    // effective value to 0 (via the ?? 0 default), which could spuriously match
    // an in-flight creation that also captured 0 before this cleanup ran,
    // allowing a stale subprocess to repopulate idleSessions after the server
    // was removed.
    this.idleSessionGenerations[serverUuid] =
      (this.idleSessionGenerations[serverUuid] ?? 0) + 1;
    this.creatingIdleSessions.delete(serverUuid);

    // Remove from server params cache
    delete this.serverParamsCache[serverUuid];
  }

  /**
   * Ensure idle session exists for a newly created server
   * This should be called when a new server is created
   */
  async ensureIdleSessionForNewServer(
    serverUuid: string,
    params: ServerParameters,
    namespaceUuid?: string,
  ): Promise<void> {
    logger.info(`Ensuring idle session exists for new server ${serverUuid}`);

    // Update server params cache
    this.serverParamsCache[serverUuid] = params;

    // Only create if we don't already have one
    if (
      !this.idleSessions[serverUuid] &&
      !this.creatingIdleSessions.has(serverUuid)
    ) {
      await this.createIdleSession(serverUuid, params, namespaceUuid);
    }
  }

  /**
   * Drop the pooled backend connection(s) for a given (sessionId, serverUuid).
   *
   * Used when the backend MCP server reports our Mcp-Session-Id is unknown
   * (e.g. after the backend container restarts and loses its in-memory session
   * registry). Both the active session and the paired idle session share the
   * backend's session registry, so both are closed — if the backend forgot
   * the active session, it has forgotten the idle one too. No replacement is
   * created here; the next `getSession` call will establish a fresh
   * connection (and therefore a fresh backend session) on demand.
   */
  async invalidateServerConnection(
    sessionId: string,
    serverUuid: string,
  ): Promise<void> {
    // When a backend MCP container restarts, EVERY cached ConnectedClient
    // for that serverUuid is dead — not just the slot owned by the
    // sessionId that surfaced the error. The original implementation
    // only invalidated `activeSessions[sessionId][serverUuid]` plus the
    // single `idleSessions[serverUuid]` slot, which left stale clients
    // sitting in OTHER session's slots for the same backend.
    //
    // Once the cap-reuse branch in `getSession` engages
    // (`findOldestActiveConnectionForServer`), the recovery path would
    // hand back one of those stale clients to satisfy the recovery
    // request — and the retry would immediately fail with the same
    // "Not connected" envelope that triggered the recovery to begin
    // with. Production observation 2026-05-14T17:29Z (Captain): detector
    // fired correctly, recovery attempted re-init, recovery's retry call
    // ALSO got "Not connected", forcing a manual `docker restart metamcp`.
    //
    // Fix: cascade the invalidation to every session's slot for the
    // affected serverUuid. The next `getSession` call then has no stale
    // candidates to reuse and must `createNewConnection`, producing the
    // fresh transport the recovery path expects.
    // Collect every doomed ConnectedClient FIRST (before any cleanup
    // call) so we can snapshot + fire their `listChangedSubscribers`
    // BEFORE cleanup wipes the subscriber set. This catches the
    // watchtower-restart cycle: backend container restarts → existing
    // connection produces a recoverable error → we land here → fire
    // subscribers before tearing down so every upstream consumer
    // (Claude Code, Claude.ai) learns the tool list is suspect and
    // re-fetches on next interaction. Without this, a fresh
    // ConnectedClient appears in the pool but no upstream notification
    // is ever emitted (backend FastMCP doesn't emit on its own startup;
    // that's a separate, future PR).
    const doomedClients: { client: ConnectedClient; sid: string }[] = [];

    for (const [sid, sessionServers] of Object.entries(this.activeSessions)) {
      const cachedClient = sessionServers[serverUuid];
      if (!cachedClient) {
        continue;
      }
      doomedClients.push({ client: cachedClient, sid });
    }

    const idleClient = this.idleSessions[serverUuid];
    if (idleClient) {
      doomedClients.push({ client: idleClient, sid: "<idle>" });
    }

    // Fire `list_changed` subscribers on every doomed client BEFORE we
    // start any cleanup. `cleanup()` clears the subscriber set, so we
    // MUST snapshot first or the fan-out targets would already be gone
    // by the time the cleanup promise's first synchronous frame runs.
    // Errors from individual subscribers are isolated by the proxy-side
    // try/catch; we additionally guard here so a misbehaving subscriber
    // can't break the invalidation cascade.
    for (const { client: doomed } of doomedClients) {
      const subscribers = Array.from(doomed.listChangedSubscribers);
      // Clear immediately so the upcoming cleanup() can't double-fire
      // a subscriber that we already invoked here.
      doomed.listChangedSubscribers.clear();
      for (const subscriber of subscribers) {
        try {
          // Don't await — these emit upstream notifications and we
          // don't want to block the invalidation/cleanup cascade on
          // upstream-client send latency. The proxy-side handler is
          // already async and wraps its own errors.
          Promise.resolve(subscriber()).catch((error) => {
            logger.warn(
              `list_changed subscriber threw during invalidation of ${serverUuid}:`,
              error,
            );
          });
        } catch (error) {
          logger.warn(
            `list_changed subscriber threw synchronously during invalidation of ${serverUuid}:`,
            error,
          );
        }
      }
    }

    // Now run cleanup. Each cleanup is wrapped so one cleanup failure
    // doesn't short-circuit the rest — we WANT every stale slot dropped
    // from the map.
    const cleanupPromises: Promise<void>[] = [];

    for (const { client: cachedClient, sid } of doomedClients) {
      if (sid === "<idle>") {
        cleanupPromises.push(
          (async () => {
            try {
              await cachedClient.cleanup();
            } catch (error) {
              logger.error(
                `Error cleaning up invalidated idle session for ${serverUuid}:`,
                error,
              );
            }
          })(),
        );
        delete this.idleSessions[serverUuid];
      } else {
        cleanupPromises.push(
          (async () => {
            try {
              await cachedClient.cleanup();
            } catch (error) {
              logger.error(
                `Error cleaning up invalidated active session ${sid}/${serverUuid}:`,
                error,
              );
            }
          })(),
        );
        const sessionServers = this.activeSessions[sid];
        if (sessionServers) {
          delete sessionServers[serverUuid];
        }
        this.sessionToServers[sid]?.delete(serverUuid);
      }
    }

    // Drop the in-flight idle-creation guard. Any pending
    // `createNewConnection` for this server captures the generation
    // counter at await time and discards its result if the counter has
    // bumped — so an in-flight stale creation can't sneak a dead
    // client back into the map between the invalidation and the
    // recovery's getSession call. (See createIdleSessionAsync.)
    this.creatingIdleSessions.delete(serverUuid);

    await Promise.all(cleanupPromises);

    if (cleanupPromises.length > 0) {
      logger.warn(
        `Invalidated ${cleanupPromises.length} pooled backend connection(s) for server ${serverUuid} ` +
          `(triggered by session ${sessionId}; cascaded across every active + idle slot for this serverUuid)`,
      );
    } else {
      logger.warn(
        `Invalidated pooled backend connection for server ${serverUuid} (session ${sessionId}) — no clients were cached`,
      );
    }
  }

  /**
   * Handle server process crash
   */
  async handleServerCrash(
    serverUuid: string,
    namespaceUuid: string,
    exitCode: number | null,
    signal: string | null,
  ): Promise<void> {
    logger.warn(
      `Handling server crash for ${serverUuid} in namespace ${namespaceUuid}`,
    );

    // Record the crash in the error tracker
    await serverErrorTracker.recordServerCrash(serverUuid, exitCode, signal);

    // Clean up any existing sessions for this server
    await this.cleanupServerSessions(serverUuid);
  }

  /**
   * Handle server process crash without namespace context
   * This is used when servers are created without a specific namespace
   */
  async handleServerCrashWithoutNamespace(
    serverUuid: string,
    exitCode: number | null,
    signal: string | null,
  ): Promise<void> {
    logger.warn(
      `Handling server crash for ${serverUuid} (no namespace context)`,
    );

    // Record the crash in the error tracker
    logger.info(`Recording crash for server ${serverUuid}`);
    await serverErrorTracker.recordServerCrash(serverUuid, exitCode, signal);

    // Clean up any existing sessions for this server
    await this.cleanupServerSessions(serverUuid);
  }

  /**
   * Clean up all sessions for a specific server
   */
  private async cleanupServerSessions(serverUuid: string): Promise<void> {
    // Bump generation and release the guard FIRST — before any await — so that
    // an in-flight idle creation that resolves during the cleanup loop below
    // (e.g. while we await an active-session cleanup) sees a stale generation
    // and discards its result instead of storing it into the now-empty slot.
    this.idleSessionGenerations[serverUuid] =
      (this.idleSessionGenerations[serverUuid] ?? 0) + 1;
    this.creatingIdleSessions.delete(serverUuid);

    // Clean up idle session
    const idleSession = this.idleSessions[serverUuid];
    if (idleSession) {
      try {
        await idleSession.cleanup();
        logger.info(`Cleaned up idle session for crashed server ${serverUuid}`);
      } catch (error) {
        logger.error(
          `Error cleaning up idle session for crashed server ${serverUuid}:`,
          error,
        );
      }
      delete this.idleSessions[serverUuid];
    }

    // Clean up active sessions that use this server
    for (const [sessionId, sessionServers] of Object.entries(
      this.activeSessions,
    )) {
      if (sessionServers[serverUuid]) {
        try {
          await sessionServers[serverUuid].cleanup();
          logger.info(
            `Cleaned up active session ${sessionId} for crashed server ${serverUuid}`,
          );
        } catch (error) {
          logger.error(
            `Error cleaning up active session ${sessionId} for crashed server ${serverUuid}:`,
            error,
          );
        }
        delete sessionServers[serverUuid];
        this.sessionToServers[sessionId]?.delete(serverUuid);
      }
    }
  }

  /**
   * Check if a server is in error state
   */
  async isServerInErrorState(serverUuid: string): Promise<boolean> {
    return await serverErrorTracker.isServerInErrorState(serverUuid);
  }

  /**
   * Reset error state for a server (e.g., after manual recovery)
   */
  async resetServerErrorState(serverUuid: string): Promise<void> {
    // Reset crash attempts and error status
    await serverErrorTracker.resetServerErrorState(serverUuid);

    logger.info(`Reset error state for server ${serverUuid}`);
  }

  /**
   * Start the automatic cleanup timer for expired sessions
   */
  private startCleanupTimer(): void {
    // Check for expired sessions every 5 minutes
    this.cleanupTimer = setInterval(
      async () => {
        await this.cleanupExpiredSessions();
      },
      5 * 60 * 1000,
    ); // 5 minutes
  }

  /**
   * Clean up expired sessions based on session lifetime setting
   */
  private async cleanupExpiredSessions(): Promise<void> {
    try {
      const sessionLifetime = await configService.getSessionLifetime();

      // If session lifetime is null, sessions are infinite - skip cleanup
      if (sessionLifetime === null) {
        return;
      }

      const now = Date.now();
      const expiredSessionIds: string[] = [];

      // Find expired sessions
      for (const [sessionId, timestamp] of Object.entries(
        this.sessionTimestamps,
      )) {
        if (now - timestamp > sessionLifetime) {
          expiredSessionIds.push(sessionId);
        }
      }

      // Clean up expired sessions
      if (expiredSessionIds.length > 0) {
        logger.info(
          `Cleaning up ${expiredSessionIds.length} expired MCP server pool sessions: ${expiredSessionIds.join(", ")}`,
        );

        await Promise.allSettled(
          expiredSessionIds.map((sessionId) => this.cleanupSession(sessionId)),
        );
      }
    } catch (error) {
      logger.error("Error during automatic session cleanup:", error);
    }
  }

  /**
   * Start the health check timer for idle sessions
   */
  private startHealthCheckTimer(): void {
    // Check idle session health every 60 seconds
    this.healthCheckTimer = setInterval(async () => {
      await this.checkIdleSessionHealth();
    }, 60 * 1000); // 60 seconds
  }

  /**
   * Start the periodic tool-definition drift sweep.
   *
   * `TOOLS_SWEEP_INTERVAL_SECONDS <= 0` disables the sweep — no timer is
   * scheduled. `NaN > 0` is false, so a malformed value also disables it
   * rather than scheduling a broken interval.
   */
  private startToolsSweepTimer(): void {
    if (!(this.toolsSweepIntervalMs > 0)) {
      logger.info(
        "Tool-definition sweep disabled (TOOLS_SWEEP_INTERVAL_SECONDS <= 0)",
      );
      return;
    }
    this.toolsSweepTimer = setInterval(async () => {
      await this.sweepToolDefinitions();
    }, this.toolsSweepIntervalMs);
  }

  /**
   * Check health of idle sessions by pinging them.
   * Dead sessions are cleaned up and recreated.
   * Servers in ERROR state whose crash counters have been reset are retried.
   */
  private async checkIdleSessionHealth(): Promise<void> {
    // NOTE: no early return on an empty idle map. Zero idle sessions is
    // precisely the state a fully-zombied or fully-capped pool is in -
    // bailing here would skip the ERROR-state recreation loop and the
    // active-session sweep below, i.e. the health check would go blind
    // exactly when the pool is at its sickest.

    // PRUNE deleted servers FIRST. A server removed from the registry (rename,
    // UI delete, CI-sync prune, direct DB) leaves its serverParamsCache entry
    // behind; the ERROR-gated recreation loop below then reconnects to a
    // backend that no longer exists — a zombie reconnect every sweep, forever
    // (observed 2026-06-29: the renamed `endpoints` server logged 297 failed
    // reconnects in 40 min, flooding the Live Logs view). The registry is the
    // source of truth; any pooled uuid absent from it is dead. One indexed
    // findAll() per 60s sweep. Guarded so a unit-test repo mock (no findAll)
    // or a transient DB blip can't take the health sweep down.
    if (typeof mcpServersRepository.findAll === "function") {
      try {
        const registered = new Set(
          (await mcpServersRepository.findAll()).map((s) => s.uuid),
        );
        const pooled = new Set<string>([
          ...Object.keys(this.serverParamsCache),
          ...Object.keys(this.idleSessions),
        ]);
        for (const serverUuid of pooled) {
          if (registered.has(serverUuid)) continue;
          logger.info(
            `Pruning pool state for server ${serverUuid} — no longer in the registry`,
          );
          // Evicts idle session + params cache + creation guards and bumps the
          // generation so an in-flight create can't repopulate it.
          await this.cleanupIdleSession(serverUuid);
          delete this.lastErrorProbeAt[serverUuid];
          delete this.activePingFailures[serverUuid];
          // Same per-server-telemetry cleanup category as the two maps
          // above: a deregistered server's sweep baseline must not linger
          // and be compared against if the serverUuid is ever reused.
          delete this.toolsSweepLastHash[serverUuid];
          await serverErrorTracker
            .resetServerErrorState(serverUuid)
            .catch(() => {});
        }
      } catch (error) {
        logger.warn(
          "Pool prune (registry reconciliation) skipped this sweep:",
          error,
        );
      }
    }

    const serverUuids = Object.keys(this.idleSessions);

    for (const serverUuid of serverUuids) {
      const client = this.idleSessions[serverUuid];
      if (!client) continue;

      try {
        // Ping with a 5-second timeout
        await client.client.ping({ timeout: 5000 });
      } catch {
        logger.warn(
          `Idle session health check failed for server ${serverUuid}, recreating...`,
        );

        // Clean up the dead session
        try {
          await client.cleanup();
        } catch {
          // Already dead, ignore cleanup errors
        }
        delete this.idleSessions[serverUuid];

        // Reset error state so we can retry
        await serverErrorTracker.resetServerErrorState(serverUuid);

        // Recreate if we have cached params
        const params = this.serverParamsCache[serverUuid];
        if (params) {
          this.createIdleSessionAsync(serverUuid, params);
        }
      }
    }

    // Also check for servers in ERROR state that have cached params but no idle session.
    // If they were reset (e.g., on startup), we should try to recreate them.
    for (const [serverUuid, params] of Object.entries(this.serverParamsCache)) {
      if (
        !this.idleSessions[serverUuid] &&
        !this.creatingIdleSessions.has(serverUuid)
      ) {
        const isError =
          await serverErrorTracker.isServerInErrorState(serverUuid);
        if (!isError) {
          // Not in error and no idle session - try to create one
          this.createIdleSessionAsync(serverUuid, params);
        } else if (this.errorProbeIntervalMs > 0) {
          // Half-open probe. The ERROR gate (DB error_status) blocks
          // every connectMetaMcpClient attempt and nothing on the
          // request path resets it while other servers keep the pool
          // non-empty — observed as the unkillable
          // `No session for: autotask` loop (incident 2026-06-11).
          // Instead of staying open forever, let one reconnect attempt
          // through per probe interval: reset the gate and warm an
          // idle session. If the backend is genuinely back this heals
          // the server; if it's still down, STDIO crash-counting
          // re-trips the breaker after maxAttempts, and HTTP/SSE
          // connect failures leave the server unconnected for the next
          // probe — bounded retries either way.
          const lastProbe = this.lastErrorProbeAt[serverUuid] ?? 0;
          if (Date.now() - lastProbe >= this.errorProbeIntervalMs) {
            this.lastErrorProbeAt[serverUuid] = Date.now();
            logger.warn(
              `Half-open probe for ERROR-gated server ${serverUuid}: resetting error state and attempting reconnect (probe interval ${this.errorProbeIntervalMs}ms)`,
            );
            await serverErrorTracker.resetServerErrorState(serverUuid);
            this.createIdleSessionAsync(serverUuid, params);
          }
        }
      }
    }

    // ACTIVE connections need the sweep too. Idle StreamableHTTP
    // transports hold no socket between requests, so a Watchtower swap
    // of the backend container kills every pooled client WITHOUT firing
    // the onclose/onerror drop detectors from PR #20. At the per-server
    // cap every slot is active: the idle loop above sees nothing, the
    // cap can block idle recreation, and getSession's cap-reuse branch
    // hands the zombies out blind — indefinitely (incident 2026-06-11,
    // Umbrella-MCP-Server#229).
    if (this.activeHealthCheckEnabled) {
      await this.checkActiveSessionHealth();
    }
  }

  /**
   * Ping every distinct ACTIVE pooled connection (the cap-reuse branch
   * shares one ConnectedClient across many sessionIds — ping each
   * object once, not once per session). A server whose connections fail
   * ping on TWO consecutive sweeps gets the full PR #16 cascade:
   * invalidateServerConnection (fires PR #19 list_changed subscribers),
   * error-state reset, and an async idle-session rebuild — the same
   * treatment the idle health check has always given dead idle slots.
   */
  private async checkActiveSessionHealth(): Promise<void> {
    const clientsByServer: Record<string, Set<ConnectedClient>> = {};
    for (const sessionServers of Object.values(this.activeSessions)) {
      for (const [serverUuid, client] of Object.entries(sessionServers)) {
        (clientsByServer[serverUuid] ??= new Set()).add(client);
      }
    }

    for (const [serverUuid, clientSet] of Object.entries(clientsByServer)) {
      const clients = Array.from(clientSet);
      const results = await Promise.allSettled(
        clients.map((c) => c.client.ping({ timeout: 5000 })),
      );
      const deadCount = results.filter((r) => r.status === "rejected").length;

      if (deadCount === 0) {
        delete this.activePingFailures[serverUuid];
        continue;
      }

      const failures = (this.activePingFailures[serverUuid] ?? 0) + 1;
      this.activePingFailures[serverUuid] = failures;

      if (failures < 2) {
        logger.warn(
          `Active session health check: ${deadCount}/${clients.length} connection(s) for server ${serverUuid} failed ping (strike 1 of 2; evicting on the next consecutive failure)`,
        );
        continue;
      }

      delete this.activePingFailures[serverUuid];
      logger.warn(
        `Active session health check failed on two consecutive sweeps for server ${serverUuid} (${deadCount}/${clients.length} dead); cascade-invalidating every pooled connection and rebuilding`,
      );

      await this.invalidateServerConnection("<health-check>", serverUuid);

      // Mirror the dead-idle path: clear the error gate so the rebuild
      // isn't refused, then warm a fresh idle session in the background.
      await serverErrorTracker.resetServerErrorState(serverUuid);
      const params = this.serverParamsCache[serverUuid];
      if (params) {
        this.createIdleSessionAsync(serverUuid, params);
      }
    }
  }

  /**
   * Periodic PULL sweep for tool-definition drift.
   *
   * For every backend that already has a live pooled connection, re-list
   * its tools over that existing connection and compare the full-definition
   * hash (Track A3's `hashTools`) against the SWEEP's OWN prior observation
   * for that server (`toolsSweepLastHash`) — not `toolsSyncCache`. On a
   * genuine change, run the SAME invalidation cascade a transport drop uses
   * (`invalidateServerConnection` → `list_changed` fan-out → consumer
   * re-list → DB resync). No new propagation mechanism.
   *
   * Why the sweep owns its own baseline instead of reading `toolsSyncCache`
   * (review findings, 2026-07-14 — see the field doc on `toolsSweepLastHash`
   * for the full detail): that cache is shared with, and can be silently
   * frozen or overwritten by, the consumer-driven proxy/tools.impl DB-sync
   * path. Comparing against it directly made the sweep either re-fire the
   * same detected change forever (idle-only servers, whose invalidation
   * fan-out reaches no subscribers) or never fire at all (servers where
   * `tools.impl.sync` cached a namespace-FILTERED hash against the sweep's
   * UNFILTERED list). Owning a separate baseline — seeded on first sight,
   * updated on every tick, compared only to its own prior value — makes
   * both failure modes structurally impossible: the invalidate fires
   * exactly once per real change, independent of whether anything
   * downstream reacts to it.
   *
   * Why a pull sweep exists at all: prod backends deliver tool updates as
   * container REPLACES that kill the process, and the SDK's standalone GET
   * stream — the only push channel — dies and exhausts its auto-reconnect
   * before the replacement container finishes booting, so no push
   * notification survives an update. A periodic re-list is the only
   * reliable signal, and Track A3's full-definition hash is what lets it
   * detect a schema/description change that kept every tool name identical
   * (name-only hashing missed exactly that).
   *
   * Guard rails: at most one sweep runs at a time (an overlapping tick is
   * skipped); a per-server failure (tools/list OR the invalidate cascade)
   * is logged and never aborts the loop or crashes the timer; we never open
   * a NEW connection just to sweep — a server with no live connection gets
   * fresh tools at its next connect anyway.
   */
  private async sweepToolDefinitions(): Promise<void> {
    if (this.toolsSweepInProgress) {
      logger.debug(
        "Tool-definition sweep skipped: previous sweep still in progress",
      );
      return;
    }
    this.toolsSweepInProgress = true;

    try {
      // One existing pooled client per server. Active slots are preferred
      // because they carry the `listChangedSubscribers` a detected change
      // can fan out to; an idle slot is a valid fallback for detection —
      // the sweep-owned baseline (not the subscriber fan-out) is what makes
      // detection correct even when there's no one to notify. Every
      // connection to a backend serves the same tool list, so one client
      // per server is enough and cheapest.
      const clientByServer = new Map<string, ConnectedClient>();
      for (const sessionServers of Object.values(this.activeSessions)) {
        for (const [serverUuid, client] of Object.entries(sessionServers)) {
          if (!clientByServer.has(serverUuid)) {
            clientByServer.set(serverUuid, client);
          }
        }
      }
      for (const [serverUuid, client] of Object.entries(this.idleSessions)) {
        if (!clientByServer.has(serverUuid)) {
          clientByServer.set(serverUuid, client);
        }
      }

      let swept = 0;
      let changed = 0;

      for (const [serverUuid, client] of clientByServer) {
        try {
          const tools = await this.listToolsForSweep(client);
          swept++;

          // Pure hashing utility only — deliberately not toolsSyncCache's
          // stateful hasChanged/update (see the class-field doc above).
          const newHash = toolsSyncCache.hashTools(tools);
          const priorHash = this.toolsSweepLastHash[serverUuid];
          // Update on EVERY tick, seed included, so the baseline always
          // reflects what the sweep itself last observed. Doing this before
          // the invalidate call below is what makes the fan-out exactly-
          // once per change: the NEXT tick's comparison is against the
          // hash we just observed, not the (possibly still-stale) hash a
          // downstream consumer may or may not have picked up.
          this.toolsSweepLastHash[serverUuid] = newHash;

          if (priorHash === undefined) {
            // First observation of this server since the sweep started (or
            // since it was pruned on deregistration) — nothing to compare
            // against yet. Seed only; firing here would treat "the sweep
            // just started watching this server" as if it just changed.
            continue;
          }

          if (newHash !== priorHash) {
            changed++;
            const serverName =
              this.serverParamsCache[serverUuid]?.name || serverUuid;
            // One INFO line per detected change (prod LOG_LEVEL=info
            // surfaces INFO in docker logs).
            logger.info(
              `tool definitions changed for ${serverName}, resyncing`,
            );
            // Fire even when this client has zero listChangedSubscribers
            // (idle-only server, no consumer currently attached) — it still
            // primes a fresh connection for whenever a consumer shows up,
            // and the baseline update above already guarantees this can't
            // refire on the next tick regardless of whether anyone reacted.
            await this.invalidateServerConnection("<tools-sweep>", serverUuid);
          }
        } catch (error) {
          // A single backend's failure — tools/list OR the invalidate
          // cascade — must never abort the sweep or crash the interval
          // callback.
          logger.debug(
            `Tool-definition sweep: iteration failed for ${serverUuid}, skipping this tick:`,
            error,
          );
        }
      }

      logger.debug(
        `Tool-definition sweep: ${swept} server(s) checked, ${changed} changed`,
      );
    } catch (error) {
      // Defensive: the sweep body should never throw, but the timer callback
      // must survive it if it does.
      logger.warn(
        "Tool-definition sweep aborted with an unexpected error:",
        error,
      );
    } finally {
      this.toolsSweepInProgress = false;
    }
  }

  /**
   * Fetch the FULL tool list (all pages) over an existing pooled client,
   * bounded by a per-request timeout. Pagination mirrors metamcp-proxy's
   * tools/list loop so the hash input matches what a consumer would see —
   * a first-page-only read would diverge from a multi-page baseline and
   * false-positive every sweep. Runs as an ordinary JSON-RPC request over
   * the shared transport, so it multiplexes with in-flight tool calls
   * rather than blocking them.
   *
   * Guarded against a misbehaving backend that never terminates pagination:
   * a `nextCursor` identical to the cursor just requested stops the loop
   * immediately (the exact "returns a constant nextCursor" failure shape),
   * and TOOLS_SWEEP_MAX_PAGES is a backstop for any other infinite/very-long
   * pagination shape. Without this, `toolsSweepInProgress` only clears in
   * `sweepToolDefinitions`'s `finally` — an unbounded loop here would wedge
   * the sweep permanently, with every future tick skipped by the in-flight
   * guard.
   */
  private async listToolsForSweep(client: ConnectedClient): Promise<Tool[]> {
    const pages: Tool[] = [];
    let cursor: string | undefined = undefined;
    let pageCount = 0;

    do {
      const result: z.infer<typeof ListToolsResultSchema> =
        await client.client.request(
          { method: "tools/list", params: { cursor } },
          ListToolsResultSchema,
          { timeout: TOOLS_SWEEP_REQUEST_TIMEOUT_MS },
        );

      if (result.tools && result.tools.length > 0) {
        pages.push(...result.tools);
      }
      pageCount++;

      const nextCursor = result.nextCursor;
      if (nextCursor !== undefined && nextCursor === cursor) {
        logger.warn(
          "Tool-definition sweep: backend returned a non-advancing tools/list cursor, stopping pagination early",
        );
        break;
      }
      if (pageCount >= TOOLS_SWEEP_MAX_PAGES) {
        logger.warn(
          `Tool-definition sweep: hit the ${TOOLS_SWEEP_MAX_PAGES}-page cap while paginating tools/list, stopping pagination early`,
        );
        break;
      }

      cursor = nextCursor;
    } while (cursor);

    return pages;
  }

  /**
   * Get session age in milliseconds
   */
  getSessionAge(sessionId: string): number | undefined {
    const timestamp = this.sessionTimestamps[sessionId];
    return timestamp ? Date.now() - timestamp : undefined;
  }

  /**
   * Check if a session is expired
   */
  async isSessionExpired(sessionId: string): Promise<boolean> {
    const age = this.getSessionAge(sessionId);
    if (age === undefined) return false;

    const sessionLifetime = await configService.getSessionLifetime();
    if (sessionLifetime === null) return false; // infinite sessions
    return age > sessionLifetime;
  }
}

// Create a singleton instance
export const mcpServerPool = McpServerPool.getInstance();
