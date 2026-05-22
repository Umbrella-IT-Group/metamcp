import { ServerParameters } from "@repo/zod-types";

import logger from "@/utils/logger";

import { configService } from "../config.service";
import { ConnectedClient, connectMetaMcpClient } from "./client";
import { serverErrorTracker } from "./server-error-tracker";

export interface McpServerPoolStatus {
  idle: number;
  active: number;
  activeSessionIds: string[];
  idleServerUuids: string[];
  perServerCounts?: Record<string, number>;
  maxConnectionsPerServer?: number;
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

  // Background idle sessions by namespace: namespaceUuid -> any
  private backgroundIdleSessionsByNamespace: Map<string, any> = new Map();

  // Per-server timestamp of the most recent successful connection.
  // Used by the recovery-reset path: if a transport drop produces a
  // SUCCESSFUL reconnect within `MCP_RECOVERY_RESET_THRESHOLD_MS` of
  // the last success, we treat the drop as transient (watchtower
  // bounce / network blip) and clear the error tracker count so the
  // sticky circuit breaker doesn't accumulate against legitimate
  // bounces. If the gap exceeds the threshold, the bounce is treated
  // as a genuine failure cluster and the tracker count is preserved.
  private serverLastSuccessAt: Record<string, number> = {};

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
    this.startCleanupTimer();
    this.startHealthCheckTimer();
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
    // Check connection limit before attempting to create
    if (!this.canCreateConnection()) {
      logger.warn(
        `Skipping connection for server ${params.name} (${params.uuid}) - connection limit reached`,
      );
      return undefined;
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
      activeSessionIds: Object.keys(this.activeSessions),
      idleServerUuids: Object.keys(this.idleSessions),
      perServerCounts,
      maxConnectionsPerServer: this.maxConnectionsPerServer,
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
              console.error(
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
              console.error(
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
      console.warn(
        `Invalidated ${cleanupPromises.length} pooled backend connection(s) for server ${serverUuid} ` +
          `(triggered by session ${sessionId}; cascaded across every active + idle slot for this serverUuid)`,
      );
    } else {
      console.warn(
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
   * Check health of idle sessions by pinging them.
   * Dead sessions are cleaned up and recreated.
   * Servers in ERROR state whose crash counters have been reset are retried.
   */
  private async checkIdleSessionHealth(): Promise<void> {
    const serverUuids = Object.keys(this.idleSessions);
    if (serverUuids.length === 0) {
      return;
    }

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
        }
      }
    }
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
