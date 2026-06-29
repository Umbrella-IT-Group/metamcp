/**
 * Session → consumer-identity registry.
 *
 * Bridges the authenticated consumer (resolved at the endpoint auth layer,
 * where the API key / OAuth user is in scope) to the tool-call audit middleware
 * (which only sees `{ namespaceUuid, sessionId }`). The Streamable-HTTP path
 * builds its handler context at idle-warm time — before any client exists — so
 * the identity can't ride in the context there; it rides here, keyed by the
 * per-consumer sessionId (unique per session, so no cross-consumer races).
 *
 * Pure in-memory + DB-free ON PURPOSE: the audit middleware imports this, and
 * the middleware must not pull a DB import into its module graph (unit tests
 * run without DATABASE_URL). The name RESOLUTION (DB lookups) lives in
 * `consumer-identity-resolver.ts`, imported only by the router layer.
 */

export interface ClientIdentity {
  /** Human-readable label: api-key name (e.g. "Tara connector") or OAuth user email. */
  name: string;
  /** Stable id: api_keys.uuid or the OAuth user_id. */
  id?: string;
  method?: "api_key" | "oauth";
}

// Insertion-ordered; bounded so a long-lived process can't grow it without end.
// Sessions are few (≤ connection cap + one openapi key per namespace), so this
// cap is a backstop, not a working limit.
const MAX_ENTRIES = 2000;
const sessionIdentities = new Map<string, ClientIdentity>();

export function setSessionClientIdentity(
  sessionId: string | undefined,
  identity: ClientIdentity,
): void {
  if (!sessionId) return;
  // Re-set moves it to newest (delete+set) so the LRU-ish eviction keeps
  // active sessions and drops the stalest.
  sessionIdentities.delete(sessionId);
  sessionIdentities.set(sessionId, identity);
  if (sessionIdentities.size > MAX_ENTRIES) {
    const oldest = sessionIdentities.keys().next().value;
    if (oldest !== undefined) sessionIdentities.delete(oldest);
  }
}

export function getSessionClientIdentity(
  sessionId: string | undefined,
): ClientIdentity | undefined {
  if (!sessionId) return undefined;
  return sessionIdentities.get(sessionId);
}

export function clearSessionClientIdentity(sessionId: string): void {
  sessionIdentities.delete(sessionId);
}
