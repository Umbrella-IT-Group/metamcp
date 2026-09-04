import logger from "@/utils/logger";

import { SessionIdentity } from "./session-auth";

/**
 * Per-credential concurrent-session ceiling for the public MCP data plane.
 *
 * WHY THIS EXISTS. Without a cap, one authenticated credential can open
 * sessions in a burst; once the shared backend pool saturates, its
 * capacity-eviction destroys other namespaces' live connections, degrading
 * every other consumer (the availability class of the July 2026 pool-cap
 * outage). This bounds how many concurrent sessions a single credential can
 * hold, enforced at session CREATION.
 *
 * WHY THE COUNT IS DERIVED, NOT MAINTAINED. Sessions live in two managers
 * (streamable-http + sse), each private to its router. Rather than each
 * creation/cleanup path incrementing and decrementing a counter here, where a
 * single missed decrement would leak the count upward and eventually LOCK OUT
 * a legitimate credential, turning an abuse guard into an availability bug,
 * the count is summed on demand across whatever managers register as counters.
 * The managers delete a session's binding on removeSession, so the derived
 * count is self-healing: it falls the moment a session ends, through every
 * cleanup path, without this module having to be told.
 */
export interface IdentitySessionCounter {
  countSessionsForIdentity(identity: SessionIdentity): number;
}

// Chosen well above real single-credential concurrency. A desktop connector
// holds one or two sessions; an SSE stream one; an automation host a handful.
// Even with the 24h idle-retention window (PUBLIC_SESSION_TTL_SECONDS) and a
// client that reconnects without a clean DELETE, a legitimate consumer stays in
// the low tens, so 100 leaves large headroom while still bounding a runaway
// credential to a fraction of what unbounded creation would reach. The 80%
// WARN surfaces a consumer approaching the ceiling in the logs so an operator
// can raise MCP_MAX_SESSIONS_PER_CREDENTIAL before any request is refused.
export const DEFAULT_MAX_SESSIONS_PER_CREDENTIAL = 100;

const counters: IdentitySessionCounter[] = [];

/**
 * Register a session manager as a source of live-session counts. Idempotent so
 * a module that is imported more than once does not double-count.
 */
export function registerSessionCounter(counter: IdentitySessionCounter): void {
  if (!counters.includes(counter)) {
    counters.push(counter);
  }
}

/** TEST-ONLY: clear the registered counters so a test starts from a known set. */
export function resetSessionCountersForTests(): void {
  counters.length = 0;
}

/**
 * Resolve the ceiling from the environment. `0` (or any non-negative integer)
 * is honored; `0` disables the ceiling entirely. A malformed value falls back
 * to the default with a WARN so a typo is visible rather than silently opening
 * the gate.
 */
export function resolveSessionCeiling(): number {
  const raw = process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL;
  if (raw === undefined || raw.trim() === "") {
    return DEFAULT_MAX_SESSIONS_PER_CREDENTIAL;
  }
  const parsed = Number.parseInt(raw, 10);
  if (Number.isNaN(parsed) || parsed < 0) {
    logger.warn(
      `MCP_MAX_SESSIONS_PER_CREDENTIAL=${raw} invalid; falling back to default ${DEFAULT_MAX_SESSIONS_PER_CREDENTIAL}.`,
    );
    return DEFAULT_MAX_SESSIONS_PER_CREDENTIAL;
  }
  return parsed;
}

/** Total live sessions across all registered managers for one identity. */
export function countLiveSessionsForIdentity(
  identity: SessionIdentity,
): number {
  return counters.reduce(
    (sum, counter) => sum + counter.countSessionsForIdentity(identity),
    0,
  );
}

export interface CeilingDecision {
  allowed: boolean;
  current: number;
  ceiling: number;
  // True once a credential is at or above the 80% WARN threshold, whether or
  // not it was refused (a refused credential is by definition past 80%). The
  // threshold is derived here so the observability helper keys its
  // "approaching" event off this flag rather than recomputing 0.8*ceiling and
  // letting the two definitions drift.
  approaching: boolean;
}

/**
 * Decide whether a credential may open one more session, WITHOUT mutating any
 * state: the new session is added to a manager by the caller on the allow
 * path, which is what the next call will count. Call this at session creation.
 *
 * Anonymous callers are exempt: an ALLOW_UNAUTHENTICATED_ENDPOINTS endpoint has
 * no per-caller identity (every caller shares one), so a ceiling there would be
 * a global cap masquerading as per-credential. A ceiling of 0 disables it.
 *
 * WARNs at 80% of the ceiling so an operator sees a credential approaching the
 * limit before it is ever refused.
 *
 * `options.label` is a DISPLAY NAME for the credential (an api-key name or the
 * OAuth user's email), resolved by the caller and threaded through only so the
 * WARN lines name WHICH credential is at the ceiling instead of just its
 * method. It is NEVER a token, key value, hash, or Authorization header: a
 * pinned credential's WARN reaches the same logs a broad audience can read, so
 * only the operator-facing name belongs here. When absent the text is
 * identical to the label-less form.
 */
export function checkConcurrentSessionCeiling(
  identity: SessionIdentity,
  options?: { label?: string },
): CeilingDecision {
  const ceiling = resolveSessionCeiling();
  if (
    ceiling === 0 ||
    identity.method === "anonymous" ||
    identity.credentialId === null
  ) {
    return { allowed: true, current: 0, ceiling, approaching: false };
  }

  const current = countLiveSessionsForIdentity(identity);
  const allowed = current < ceiling;
  const approaching = current >= Math.floor(ceiling * 0.8);

  // Rendered as ` "<name>"` when present so the WARN reads
  // `... for api_key credential "<name>": 101/100 ...`, and collapses to the
  // original `... for api_key credential: 101/100 ...` when it is not.
  const labelSuffix = options?.label ? ` "${options.label}"` : "";

  if (!allowed) {
    logger.warn(
      `Concurrent-session ceiling reached for ${identity.method} credential${labelSuffix}: ` +
        `${current}/${ceiling} live sessions; refusing a new session. Raise ` +
        `MCP_MAX_SESSIONS_PER_CREDENTIAL if this is a legitimate consumer.`,
    );
  } else if (approaching) {
    logger.warn(
      `Concurrent-session usage high for ${identity.method} credential${labelSuffix}: ` +
        `${current}/${ceiling} live sessions (>=80%). Approaching the ceiling; ` +
        `raise MCP_MAX_SESSIONS_PER_CREDENTIAL before it refuses new sessions.`,
    );
  }

  return { allowed, current, ceiling, approaching };
}
