import logger from "@/utils/logger";

import { configService } from "./config.service";

/**
 * Endpoint binding stored alongside a public-endpoint session so a
 * session-id-keyed transport lookup can be re-checked against the endpoint
 * the request is actually targeting. Without this, the in-memory session
 * map is keyed by `Mcp-Session-Id` ALONE — a caller authenticated for
 * endpoint A could drive endpoint B's pooled namespace by presenting B's
 * session id. Mirrors the cross-namespace replay predicate the DB-backed
 * `recoverPersistedSession` already enforces (namespace_uuid +
 * endpoint_name must both match). See `getBoundSession` in
 * `streamable-http.ts` and the message-leg guard in `sse.ts`.
 */
export interface SessionBinding {
  namespaceUuid: string;
  endpointName: string;
}

/**
 * True only when a stored session binding matches the endpoint a request is
 * targeting — BOTH the namespace uuid and the endpoint name must agree. A
 * missing binding (`undefined`) never matches, so a session with no recorded
 * binding is treated as non-existent for the requesting endpoint rather than
 * blindly served. This is the single predicate both public-endpoint legs
 * (streamable-http `getBoundSession`, sse message route) and the DELETE guard
 * use, mirroring the cross-namespace replay check in `recoverPersistedSession`.
 */
export function bindingMatches(
  binding: SessionBinding | undefined,
  target: SessionBinding,
): boolean {
  return (
    binding !== undefined &&
    binding.namespaceUuid === target.namespaceUuid &&
    binding.endpointName === target.endpointName
  );
}

export interface SessionLifetimeManager<T> {
  addSession(sessionId: string, session: T, binding?: SessionBinding): void;
  removeSession(sessionId: string): void;
  getSession(sessionId: string): T | undefined;
  getSessionBinding(sessionId: string): SessionBinding | undefined;
  getAllSessions(): Map<string, T>;
  getSessionAge(sessionId: string): number | undefined;
  isSessionExpired(sessionId: string): Promise<boolean>;
  cleanupExpiredSessions(
    cleanupCallback: (sessionId: string, session: T) => Promise<void>,
  ): Promise<void>;
  startCleanupTimer(
    cleanupCallback: (sessionId: string, session: T) => Promise<void>,
    intervalMs?: number,
  ): void;
  stopCleanupTimer(): void;
}

export class SessionLifetimeManagerImpl<T>
  implements SessionLifetimeManager<T>
{
  private sessions: Map<string, T> = new Map();
  private sessionTimestamps: Map<string, number> = new Map();
  private sessionBindings: Map<string, SessionBinding> = new Map();
  private cleanupTimer: NodeJS.Timeout | null = null;
  private readonly name: string;

  constructor(name: string) {
    this.name = name;
  }

  addSession(sessionId: string, session: T, binding?: SessionBinding): void {
    this.sessions.set(sessionId, session);
    this.sessionTimestamps.set(sessionId, Date.now());
    if (binding) {
      this.sessionBindings.set(sessionId, binding);
    }
  }

  removeSession(sessionId: string): void {
    this.sessions.delete(sessionId);
    this.sessionTimestamps.delete(sessionId);
    this.sessionBindings.delete(sessionId);
  }

  getSession(sessionId: string): T | undefined {
    return this.sessions.get(sessionId);
  }

  // The endpoint this session was created against, if one was recorded.
  // Used by the public-endpoint routers to reject a session id presented on
  // an endpoint other than the one it belongs to (cross-endpoint replay).
  getSessionBinding(sessionId: string): SessionBinding | undefined {
    return this.sessionBindings.get(sessionId);
  }

  getAllSessions(): Map<string, T> {
    return new Map(this.sessions);
  }

  getSessionAge(sessionId: string): number | undefined {
    const timestamp = this.sessionTimestamps.get(sessionId);
    return timestamp ? Date.now() - timestamp : undefined;
  }

  async isSessionExpired(sessionId: string): Promise<boolean> {
    const age = this.getSessionAge(sessionId);
    if (age === undefined) return false;

    const sessionLifetime = await configService.getSessionLifetime();
    // If session lifetime is null, sessions are infinite and never expire
    if (sessionLifetime === null) return false;

    return age > sessionLifetime;
  }

  async cleanupExpiredSessions(
    cleanupCallback: (sessionId: string, session: T) => Promise<void>,
  ): Promise<void> {
    try {
      const sessionLifetime = await configService.getSessionLifetime();

      // If session lifetime is null, sessions are infinite - skip cleanup
      if (sessionLifetime === null) {
        return;
      }

      const now = Date.now();
      const expiredSessions: Array<{ sessionId: string; session: T }> = [];

      // Find expired sessions
      for (const [sessionId, timestamp] of this.sessionTimestamps.entries()) {
        if (now - timestamp > sessionLifetime) {
          const session = this.sessions.get(sessionId);
          if (session) {
            expiredSessions.push({ sessionId, session });
          }
        }
      }

      // Clean up expired sessions
      if (expiredSessions.length > 0) {
        logger.info(
          `Cleaning up ${expiredSessions.length} expired ${this.name} sessions: ${expiredSessions.map((s) => s.sessionId).join(", ")}`,
        );

        await Promise.allSettled(
          expiredSessions.map(({ sessionId, session }) =>
            cleanupCallback(sessionId, session),
          ),
        );
      }
    } catch (error) {
      logger.error(
        `Error during automatic ${this.name} session cleanup:`,
        error,
      );
    }
  }

  startCleanupTimer(
    cleanupCallback: (sessionId: string, session: T) => Promise<void>,
    intervalMs: number = 5 * 60 * 1000, // Default: 5 minutes
  ): void {
    this.cleanupTimer = setInterval(async () => {
      await this.cleanupExpiredSessions(cleanupCallback);
    }, intervalMs);
  }

  stopCleanupTimer(): void {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;
    }
  }

  // Utility methods for getting session counts and IDs
  getSessionCount(): number {
    return this.sessions.size;
  }

  getSessionIds(): string[] {
    return Array.from(this.sessions.keys());
  }

  getSessionTimestamps(): Map<string, number> {
    return new Map(this.sessionTimestamps);
  }
}
