import logger from "@/utils/logger";

import { configService } from "./config.service";
import { identityMatches, type SessionIdentity } from "./metamcp/session-auth";

/**
 * The endpoint half of a session's binding: which namespace + public endpoint
 * a session-id-keyed transport lookup must be targeting. Without this, the
 * in-memory session map is keyed by `Mcp-Session-Id` ALONE — a caller
 * authenticated for endpoint A could drive endpoint B's pooled namespace by
 * presenting B's session id. Mirrors the cross-namespace replay predicate the
 * DB-backed `recoverPersistedSession` already enforces (namespace_uuid +
 * endpoint_name must both match).
 *
 * Split out from `SessionBinding` below so the DB-backed guards can keep
 * comparing a persisted `mcp_sessions` row — which carries the endpoint pair
 * but not the in-memory identity — through the same predicate.
 */
export interface EndpointBinding {
  namespaceUuid: string;
  endpointName: string;
}

/**
 * What is stored alongside a live public-endpoint session: its endpoint AND
 * the identity of the credential that created it.
 *
 * The endpoint half alone was not enough. Every endpoint that accepts more
 * than one credential — a gateway-wide api key plus a scoped one, two keys for
 * two consumers, any OAuth user with access — had a pool in which ANY of those
 * credentials could present ANY live session id for that endpoint and be
 * handed the transport, because the lookup never re-checked WHO created it.
 * The DB-backed recovery path had guarded exactly this since it shipped
 * (`auth_principal` + `auth_method`); the in-memory fast path, which serves
 * every request after the first, had not. See `resolveBoundSession` in
 * `streamable-http.ts` and the message-leg guard in `sse.ts`.
 */
export interface SessionBinding extends EndpointBinding {
  identity: SessionIdentity;
}

/**
 * True only when a stored binding matches the endpoint a request is
 * targeting — BOTH the namespace uuid and the endpoint name must agree. A
 * missing binding (`undefined`) never matches, so a session with no recorded
 * binding is treated as non-existent for the requesting endpoint rather than
 * blindly served.
 *
 * This is the ENDPOINT-ONLY predicate, used where the thing being compared is
 * a persisted `mcp_sessions` row: `recoverPersistedSession` and the
 * not-resident branch of `resolveDeletableSession`, both of which verify the
 * credential separately against the row's `auth_principal` hash. In-memory
 * lookups use `boundSessionMatches` below instead.
 */
export function bindingMatches(
  binding: EndpointBinding | undefined,
  target: EndpointBinding,
): boolean {
  return (
    binding !== undefined &&
    binding.namespaceUuid === target.namespaceUuid &&
    binding.endpointName === target.endpointName
  );
}

/**
 * The predicate every IN-MEMORY session lookup funnels through: the request
 * must target the session's endpoint AND present the identity the session was
 * created under. One function so the check cannot drift between the three
 * legs that need it (streamable-http's request lookup and DELETE guard, sse's
 * message leg), which is the same reason `bindingMatches` was extracted.
 *
 * Callers treat `false` as "no such session" rather than as a distinct
 * refusal: per the MCP Streamable HTTP session model an unknown session id is
 * answered 404 so a well-behaved client re-initializes, and collapsing the
 * foreign-credential case into that one answer is also what stops the response
 * from confirming that someone else's session id is live.
 */
export function boundSessionMatches(
  binding: SessionBinding | undefined,
  target: SessionBinding,
): boolean {
  return (
    bindingMatches(binding, target) &&
    identityMatches(binding?.identity, target.identity)
  );
}

/**
 * Which half of the binding a refused lookup actually failed.
 *
 * The response never learns this — every refusal answers the same 404 — but
 * the audit row does, and `detail.reason` is the field an operator queries to
 * separate the classes. One hardcoded reason would report a credential
 * mismatch for a plain cross-endpoint replay, i.e. record an event that did
 * not happen, in a table migration 0028 makes append-only.
 *
 * Lives here, next to the predicate whose `false` it explains, so the two
 * cannot drift: the ordering below mirrors `boundSessionMatches` exactly.
 * PRECONDITION: only meaningful when `boundSessionMatches` already returned
 * false for the same pair.
 */
export type SessionBindingDenialReason =
  | "session_binding_absent"
  | "session_endpoint_mismatch"
  | "session_credential_mismatch";

export function classifyBindingDenial(
  binding: SessionBinding | undefined,
  target: SessionBinding,
): SessionBindingDenialReason {
  // A resident session carrying no binding at all. Unreachable today — every
  // `addSession` call site passes one — which is why it gets its own reason
  // rather than being folded into the endpoint case it would otherwise
  // misreport as.
  if (binding === undefined) return "session_binding_absent";
  if (!bindingMatches(binding, target)) return "session_endpoint_mismatch";
  return "session_credential_mismatch";
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

  // The endpoint AND creating credential this session was recorded against.
  // Used by the public-endpoint routers to reject a session id presented on
  // an endpoint other than the one it belongs to, or under a credential other
  // than the one that opened it.
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
        // Count at info, ids at debug only: a live session-id list in a
        // request-path log undoes the fork's session-id log hygiene. Dormant
        // in prod (sessionLifetime is null there), but this timer fires the
        // moment an operator sets a finite lifetime.
        logger.info(
          `Cleaning up ${expiredSessions.length} expired ${this.name} sessions`,
        );
        logger.debug(
          `Expired ${this.name} session ids: ${expiredSessions.map((s) => s.sessionId).join(", ")}`,
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
