import { Server } from "@modelcontextprotocol/sdk/server/index.js";

import logger from "@/utils/logger";

import { configService } from "../config.service";
import { mcpServerPool } from "./mcp-server-pool";
import { MetaMCPHandlerContext } from "./metamcp-middleware/functional-middleware";
import { createServer } from "./metamcp-proxy";

export interface MetaMcpServerInstance {
  server: Server;
  cleanup: () => Promise<void>;
  // The proxy's handler context. The router stamps `clientName` onto it after
  // acquiring the instance so the audit middleware can attribute tool calls to
  // the calling consumer (see metamcp-proxy.createServer return).
  handlerContext: MetaMCPHandlerContext;
}

export interface MetaMcpServerPoolStatus {
  idle: number;
  active: number;
  activeSessionIds: string[];
  idleNamespaceUuids: string[];
}

export class MetaMcpServerPool {
  // Singleton instance
  private static instance: MetaMcpServerPool | null = null;

  // Idle MetaMCP servers: namespaceUuid -> MetaMcpServerInstance (no sessionId assigned yet)
  private idleServers: Record<string, MetaMcpServerInstance> = {};

  // Active MetaMCP servers: sessionId -> MetaMcpServerInstance
  private activeServers: Record<string, MetaMcpServerInstance> = {};

  // Mapping: sessionId -> namespaceUuid for cleanup tracking
  private sessionToNamespace: Record<string, string> = {};

  // Session creation timestamps: sessionId -> timestamp
  private sessionTimestamps: Record<string, number> = {};

  // Track ongoing idle server creation to prevent duplicates
  private creatingIdleServers: Set<string> = new Set();

  // Generation counter per namespace UUID: bumped by invalidateIdleServer /
  // cleanupIdleServer / cleanupAll so an in-flight idle creation that
  // straddles an invalidation discards its (pre-change-config) result
  // instead of storing it. Same pattern as mcp-server-pool.ts's
  // idleSessionGenerations.
  private idleServerGenerations: Record<string, number> = {};

  // Session cleanup timer
  private cleanupTimer: NodeJS.Timeout | null = null;

  // Default number of idle servers per namespace UUID
  private readonly defaultIdleCount: number;

  private constructor(defaultIdleCount: number = 1) {
    this.defaultIdleCount = defaultIdleCount;
    this.startCleanupTimer();
  }

  /**
   * Get the singleton instance
   */
  static getInstance(defaultIdleCount: number = 1): MetaMcpServerPool {
    if (!MetaMcpServerPool.instance) {
      MetaMcpServerPool.instance = new MetaMcpServerPool(defaultIdleCount);
    }
    return MetaMcpServerPool.instance;
  }

  /**
   * Get or create a MetaMCP server for a namespace
   */
  async getServer(
    sessionId: string,
    namespaceUuid: string,
    includeInactiveServers: boolean = false,
  ): Promise<MetaMcpServerInstance | undefined> {
    // Check if we already have an active server for this sessionId
    if (this.activeServers[sessionId]) {
      return this.activeServers[sessionId];
    }

    // Check if we have an idle server for this namespace that we can convert
    const idleServer = this.idleServers[namespaceUuid];
    if (idleServer) {
      // Convert idle server to active server
      delete this.idleServers[namespaceUuid];
      this.activeServers[sessionId] = idleServer;
      this.sessionToNamespace[sessionId] = namespaceUuid;
      this.sessionTimestamps[sessionId] = Date.now();

      logger.info(
        `Converted idle MetaMCP server to active for namespace ${namespaceUuid}, session ${sessionId}`,
      );

      // Create a new idle server to replace the one we just used (ASYNC - NON-BLOCKING)
      this.createIdleServerAsync(namespaceUuid, includeInactiveServers);

      return idleServer;
    }

    // No idle server available, create a new one
    const newServer = await this.createNewServer(
      sessionId,
      namespaceUuid,
      includeInactiveServers,
    );
    if (!newServer) {
      return undefined;
    }

    this.activeServers[sessionId] = newServer;
    this.sessionToNamespace[sessionId] = namespaceUuid;
    this.sessionTimestamps[sessionId] = Date.now();

    logger.info(
      `Created new active MetaMCP server for namespace ${namespaceUuid}, session ${sessionId}`,
    );

    // Also create an idle server for future use (ASYNC - NON-BLOCKING)
    this.createIdleServerAsync(namespaceUuid, includeInactiveServers);

    return newServer;
  }

  /**
   * Create a new MetaMCP server instance
   */
  private async createNewServer(
    sessionId: string,
    namespaceUuid: string,
    includeInactiveServers: boolean = false,
  ): Promise<MetaMcpServerInstance | undefined> {
    try {
      // Create the MetaMCP server - MCP server pool is pre-warmed during startup
      const serverInstance = await createServer(
        namespaceUuid,
        sessionId,
        includeInactiveServers,
      );

      return serverInstance;
    } catch (error) {
      logger.error(
        `Error creating MetaMCP server for namespace ${namespaceUuid}:`,
        error,
      );
      return undefined;
    }
  }

  /**
   * Create an idle MetaMCP server for a namespace (blocking version for initial setup)
   */
  private async createIdleServer(
    namespaceUuid: string,
    includeInactiveServers: boolean = false,
  ): Promise<void> {
    // Don't create if we already have an idle server for this namespace
    // or one is already being created (by this method or the async
    // variant). Without this guard, the concurrent invalidateIdleServer
    // + invalidateOpenApiSessions fire-and-forget pair that every tRPC
    // config edit launches both reached createNewServer, and the second
    // assignment silently orphaned the first instance — leaking its
    // backend ConnectedClients under a temp `idle_<ns>_<ts>` sessionId
    // forever (persistent sessions never expire), ratcheting the
    // backend pool toward cap exhaustion: the incident-#229 end state
    // via the admin-edit route.
    if (
      this.idleServers[namespaceUuid] ||
      this.creatingIdleServers.has(namespaceUuid)
    ) {
      return;
    }
    this.creatingIdleServers.add(namespaceUuid);
    const generation = this.idleServerGenerations[namespaceUuid] ?? 0;

    try {
      // Create a temporary sessionId for the idle server
      const tempSessionId = `idle_${namespaceUuid}_${Date.now()}`;

      const newServer = await this.createNewServer(
        tempSessionId,
        namespaceUuid,
        includeInactiveServers,
      );
      if (!newServer) {
        return;
      }

      // Discard (don't store) if an invalidation happened while we were
      // connecting — this instance was built from the pre-change config —
      // or if someone else landed an idle server first.
      if (
        (this.idleServerGenerations[namespaceUuid] ?? 0) !== generation ||
        this.idleServers[namespaceUuid]
      ) {
        await newServer.cleanup().catch((error) => {
          logger.error(
            `Error cleaning up superseded idle MetaMCP server for ${namespaceUuid}:`,
            error,
          );
        });
        return;
      }

      this.idleServers[namespaceUuid] = {
        server: newServer.server,
        cleanup: newServer.cleanup,
        handlerContext: newServer.handlerContext,
      };
      logger.info(`Created idle MetaMCP server for namespace ${namespaceUuid}`);
    } finally {
      this.creatingIdleServers.delete(namespaceUuid);
    }
  }

  /**
   * Create an idle MetaMCP server for a namespace asynchronously (non-blocking)
   */
  private createIdleServerAsync(
    namespaceUuid: string,
    includeInactiveServers: boolean = false,
  ): void {
    // Don't create if we already have an idle server or are already creating one
    if (
      this.idleServers[namespaceUuid] ||
      this.creatingIdleServers.has(namespaceUuid)
    ) {
      return;
    }

    // Mark that we're creating an idle server for this namespace
    this.creatingIdleServers.add(namespaceUuid);
    const generation = this.idleServerGenerations[namespaceUuid] ?? 0;

    // Create the server in the background (fire and forget)
    const tempSessionId = `idle_${namespaceUuid}_${Date.now()}`;

    this.createNewServer(tempSessionId, namespaceUuid, includeInactiveServers)
      .then((newServer) => {
        const stale =
          (this.idleServerGenerations[namespaceUuid] ?? 0) !== generation;
        if (newServer && !stale && !this.idleServers[namespaceUuid]) {
          const wrappedServer: MetaMcpServerInstance = {
            server: newServer.server,
            cleanup: newServer.cleanup,
            handlerContext: newServer.handlerContext,
          };
          this.idleServers[namespaceUuid] = wrappedServer;
          logger.info(
            `Created background idle MetaMCP server for namespace ${namespaceUuid}`,
          );
        } else if (newServer) {
          // We already have an idle server (or an invalidation made this
          // pre-change-config instance stale) — cleanup the extra one
          newServer.cleanup().catch((error) => {
            logger.error(
              `Error cleaning up extra idle MetaMCP server for ${namespaceUuid}:`,
              error,
            );
          });
        }
      })
      .catch((error) => {
        logger.error(
          `Error creating background idle MetaMCP server for ${namespaceUuid}:`,
          error,
        );
      })
      .finally(() => {
        // Remove from creating set
        this.creatingIdleServers.delete(namespaceUuid);
      });
  }

  /**
   * Ensure idle servers exist for all namespaces
   */
  async ensureIdleServers(
    namespaceUuids: string[],
    includeInactiveServers: boolean = false,
  ): Promise<void> {
    const promises = namespaceUuids.map(async (namespaceUuid) => {
      if (!this.idleServers[namespaceUuid]) {
        await this.createIdleServer(namespaceUuid, includeInactiveServers);
      }
    });

    await Promise.allSettled(promises);
  }

  /**
   * Cleanup a session by sessionId
   */
  async cleanupSession(sessionId: string): Promise<void> {
    const activeServer = this.activeServers[sessionId];
    if (!activeServer) {
      return;
    }

    // Drop the maps FIRST. The two cleanup awaits below can reject, and
    // when the deletes ran after them a single throw left a permanent
    // zombie entry: getServer kept handing the half-cleaned instance to
    // any client reusing the sessionId, and the expiry sweep retried
    // (and failed) on it forever. Cleanup is best-effort; map
    // consistency is not.
    const namespaceUuid = this.sessionToNamespace[sessionId];
    delete this.activeServers[sessionId];
    delete this.sessionTimestamps[sessionId];
    delete this.sessionToNamespace[sessionId];

    // Cleanup the MetaMCP server
    try {
      await activeServer.cleanup();
    } catch (error) {
      logger.error(
        `Error cleaning up MetaMCP server for session ${sessionId}:`,
        error,
      );
    }

    // Also cleanup the corresponding MCP server pool session — in its
    // own try/catch so a namespace-layer failure can't strand the
    // backend-pool layer (and vice versa).
    try {
      await mcpServerPool.cleanupSession(sessionId);
    } catch (error) {
      logger.error(
        `Error cleaning up backend pool session ${sessionId}:`,
        error,
      );
    }

    if (namespaceUuid) {
      // Create a new idle server to replace capacity (ASYNC - NON-BLOCKING)
      this.createIdleServerAsync(namespaceUuid);
    }

    logger.info(`Cleaned up MetaMCP server pool session ${sessionId}`);
  }

  /**
   * Cleanup all servers
   */
  async cleanupAll(): Promise<void> {
    // Invalidate every in-flight idle creation first so none of them
    // stores a result into the maps we're about to clear.
    for (const namespaceUuid of new Set([
      ...Object.keys(this.idleServers),
      ...this.creatingIdleServers,
    ])) {
      this.idleServerGenerations[namespaceUuid] =
        (this.idleServerGenerations[namespaceUuid] ?? 0) + 1;
    }

    // Cleanup all active servers
    const activeSessionIds = Object.keys(this.activeServers);
    await Promise.allSettled(
      activeSessionIds.map((sessionId) => this.cleanupSession(sessionId)),
    );

    // Cleanup all idle servers
    await Promise.allSettled(
      Object.entries(this.idleServers).map(async ([_uuid, server]) => {
        await server.cleanup();
      }),
    );

    // Cleanup all MCP server pool sessions
    await mcpServerPool.cleanupAll();

    // Clear all state
    this.idleServers = {};
    this.activeServers = {};
    this.sessionToNamespace = {};
    this.sessionTimestamps = {};
    this.creatingIdleServers.clear();

    // Clear cleanup timer
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;
    }

    logger.info("Cleaned up all MetaMCP server pool sessions");
  }

  /**
   * Get pool status for monitoring
   */
  getPoolStatus(): MetaMcpServerPoolStatus {
    const idle = Object.keys(this.idleServers).length;
    const active = Object.keys(this.activeServers).length;

    return {
      idle,
      active,
      activeSessionIds: Object.keys(this.activeServers),
      idleNamespaceUuids: Object.keys(this.idleServers),
    };
  }

  /**
   * Get active server instance for a specific session (for debugging/monitoring)
   */
  getServerInstance(sessionId: string): MetaMcpServerInstance | undefined {
    return this.activeServers[sessionId];
  }

  /**
   * Get all active session IDs (for debugging/monitoring)
   */
  getActiveSessionIds(): string[] {
    return Object.keys(this.activeServers);
  }

  /**
   * Get MCP server pool status
   */
  getMcpServerPoolStatus() {
    return mcpServerPool.getPoolStatus();
  }

  /**
   * Invalidate and refresh idle server for a specific namespace
   * This should be called when a namespace's MCP servers list changes
   */
  async invalidateIdleServer(
    namespaceUuid: string,
    includeInactiveServers: boolean = false,
  ): Promise<void> {
    logger.info(`Invalidating idle server for namespace ${namespaceUuid}`);

    // Invalidate any in-flight idle creation: a server being built from
    // the PRE-change config must not land in the map after this point.
    this.idleServerGenerations[namespaceUuid] =
      (this.idleServerGenerations[namespaceUuid] ?? 0) + 1;

    // Cleanup existing idle server if it exists
    const existingIdleServer = this.idleServers[namespaceUuid];
    if (existingIdleServer) {
      try {
        await existingIdleServer.cleanup();
        logger.info(
          `Cleaned up existing idle server for namespace ${namespaceUuid}`,
        );
      } catch (error) {
        logger.error(
          `Error cleaning up existing idle server for namespace ${namespaceUuid}:`,
          error,
        );
      }
      delete this.idleServers[namespaceUuid];
    }

    // Remove from creating set if it's in progress
    this.creatingIdleServers.delete(namespaceUuid);

    // Create a new idle server with updated configuration
    await this.createIdleServer(namespaceUuid, includeInactiveServers);
  }

  /**
   * Invalidate and refresh idle servers for multiple namespaces
   */
  async invalidateIdleServers(
    namespaceUuids: string[],
    includeInactiveServers: boolean = false,
  ): Promise<void> {
    const promises = namespaceUuids.map((namespaceUuid) =>
      this.invalidateIdleServer(namespaceUuid, includeInactiveServers),
    );

    await Promise.allSettled(promises);
  }

  /**
   * Clean up idle server for a specific namespace without creating a new one
   * This should be called when a namespace is being deleted
   */
  async cleanupIdleServer(namespaceUuid: string): Promise<void> {
    logger.info(`Cleaning up idle server for namespace ${namespaceUuid}`);

    // Invalidate any in-flight idle creation so it discards its result
    // (the namespace is going away).
    this.idleServerGenerations[namespaceUuid] =
      (this.idleServerGenerations[namespaceUuid] ?? 0) + 1;

    // Cleanup existing idle server if it exists
    const existingIdleServer = this.idleServers[namespaceUuid];
    if (existingIdleServer) {
      try {
        await existingIdleServer.cleanup();
        logger.info(`Cleaned up idle server for namespace ${namespaceUuid}`);
      } catch (error) {
        logger.error(
          `Error cleaning up idle server for namespace ${namespaceUuid}:`,
          error,
        );
      }
      delete this.idleServers[namespaceUuid];
    }

    // Remove from creating set if it's in progress
    this.creatingIdleServers.delete(namespaceUuid);
  }

  /**
   * Ensure idle server exists for a newly created namespace
   * This should be called when a new namespace is created
   */
  async ensureIdleServerForNewNamespace(
    namespaceUuid: string,
    includeInactiveServers: boolean = false,
  ): Promise<void> {
    logger.info(
      `Ensuring idle server exists for new namespace ${namespaceUuid}`,
    );

    // Only create if we don't already have one
    if (
      !this.idleServers[namespaceUuid] &&
      !this.creatingIdleServers.has(namespaceUuid)
    ) {
      await this.createIdleServer(namespaceUuid, includeInactiveServers);
    }
  }

  /**
   * Get or create a persistent MetaMCP server for OpenAPI endpoints
   * These sessions are never cleaned up automatically and persist until invalidation
   */
  async getOpenApiServer(
    namespaceUuid: string,
    includeInactiveServers: boolean = false,
  ): Promise<MetaMcpServerInstance | undefined> {
    // Use a deterministic session ID for OpenAPI endpoints
    const sessionId = `openapi_${namespaceUuid}`;

    // Check if we already have an active server for this OpenAPI session
    if (this.activeServers[sessionId]) {
      return this.activeServers[sessionId];
    }

    // Check if we have an idle server for this namespace that we can convert
    const idleServer = this.idleServers[namespaceUuid];
    if (idleServer) {
      // Convert idle server to active OpenAPI server
      delete this.idleServers[namespaceUuid];
      this.activeServers[sessionId] = idleServer;
      this.sessionToNamespace[sessionId] = namespaceUuid;
      this.sessionTimestamps[sessionId] = Date.now();

      logger.info(
        `Converted idle MetaMCP server to OpenAPI server for namespace ${namespaceUuid}, session ${sessionId}`,
      );

      // Create a new idle server to replace the one we just used (SYNC - BLOCKING)
      await this.createIdleServer(namespaceUuid, includeInactiveServers);

      return idleServer;
    }

    // No idle server available, create a new one
    const newServer = await this.createNewServer(
      sessionId,
      namespaceUuid,
      includeInactiveServers,
    );
    if (!newServer) {
      return undefined;
    }

    this.activeServers[sessionId] = newServer;
    this.sessionToNamespace[sessionId] = namespaceUuid;
    this.sessionTimestamps[sessionId] = Date.now();

    logger.info(
      `Created new OpenAPI MetaMCP server for namespace ${namespaceUuid}, session ${sessionId}`,
    );

    // Also create an idle server for future use (SYNC - BLOCKING)
    await this.createIdleServer(namespaceUuid, includeInactiveServers);

    return newServer;
  }

  /**
   * Invalidate OpenAPI sessions for specific namespaces
   * This is called when namespace configurations change
   */
  async invalidateOpenApiSessions(
    namespaceUuids: string[],
    includeInactiveServers: boolean = false,
  ): Promise<void> {
    logger.info(
      `Invalidating OpenAPI sessions for namespaces: ${namespaceUuids.join(", ")}`,
    );

    const promises = namespaceUuids.map(async (namespaceUuid) => {
      const sessionId = `openapi_${namespaceUuid}`;

      // Clean up existing OpenAPI session if it exists
      const existingServer = this.activeServers[sessionId];
      if (existingServer) {
        try {
          await existingServer.cleanup();
          logger.info(
            `Cleaned up existing OpenAPI session for namespace ${namespaceUuid}`,
          );
        } catch (error) {
          logger.error(
            `Error cleaning up OpenAPI session for namespace ${namespaceUuid}:`,
            error,
          );
        }
        delete this.activeServers[sessionId];
        delete this.sessionToNamespace[sessionId];
        delete this.sessionTimestamps[sessionId];
      }

      // The instance's closure cleanup above tears down the backend-pool
      // sessions it was CREATED under — for a converted idle server
      // that's the temp `idle_<ns>_<ts>` id, NOT this session's
      // `openapi_<ns>` id, which is what the OpenAPI request path
      // actually keys backend sessions under (routes.ts /
      // tool-execution.ts pass `openapi_${namespaceUuid}` to
      // mcpServerPool.getSession). Without this explicit layer cleanup,
      // the next OpenAPI request's getSession hit the active-session
      // fast path and reused stale pre-change ConnectedClients
      // indefinitely — "I updated the server, the MCP endpoint sees the
      // change but the OpenAPI endpoint doesn't."
      try {
        await mcpServerPool.cleanupSession(sessionId);
      } catch (error) {
        logger.error(
          `Error cleaning up backend pool session ${sessionId}:`,
          error,
        );
      }

      // Create a new OpenAPI session with updated configuration
      await this.getOpenApiServer(namespaceUuid, includeInactiveServers);
    });

    await Promise.allSettled(promises);
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
          `Cleaning up ${expiredSessionIds.length} expired MetaMCP server pool sessions: ${expiredSessionIds.join(", ")}`,
        );

        await Promise.allSettled(
          expiredSessionIds.map((sessionId) => this.cleanupSession(sessionId)),
        );
      }
    } catch (error) {
      logger.error("Error during automatic MetaMCP session cleanup:", error);
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
    // null lifetime = persistent sessions (the default). Without this
    // guard `age > null` coerces to `age > 0` and every session reads
    // as expired the moment it's a millisecond old.
    if (sessionLifetime === null) return false;
    return age > sessionLifetime;
  }
}

// Create a singleton instance
export const metaMcpServerPool = MetaMcpServerPool.getInstance();
