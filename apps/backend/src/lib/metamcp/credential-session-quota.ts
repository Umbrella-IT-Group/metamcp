import logger from "@/utils/logger";

import type { SessionListing } from "../session-lifetime-manager";
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
  /**
   * Optional: the live sessions behind that count, with their endpoints. Used
   * only to say WHAT is filling a credential that is approaching or at its
   * ceiling. A counter that cannot list simply contributes nothing to the
   * summary; the ceiling decision never depends on it.
   */
  listSessionsForIdentity?(identity: SessionIdentity): SessionListing[];
}

/**
 * Read-only activity of one session, from whichever component tracks it.
 * Undefined means "not tracked here" (an SSE session, or one already gone).
 */
export type SessionActivityProbe = (
  sessionId: string,
) => { idleMs: number; inFlight: boolean } | undefined;

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
const activityProbes: SessionActivityProbe[] = [];

/**
 * Register a session manager as a source of live-session counts. Idempotent so
 * a module that is imported more than once does not double-count.
 */
export function registerSessionCounter(counter: IdentitySessionCounter): void {
  if (!counters.includes(counter)) {
    counters.push(counter);
  }
}

/**
 * Register a source of per-session activity (idle time, in-flight) for the
 * ceiling summary. Idempotent. A probe must be a cheap read-only lookup; the
 * summary guards each call, but only runs on the rare ceiling path.
 */
export function registerSessionActivityProbe(
  probe: SessionActivityProbe,
): void {
  if (!activityProbes.includes(probe)) {
    activityProbes.push(probe);
  }
}

/** TEST-ONLY: clear the registered counters so a test starts from a known set. */
export function resetSessionCountersForTests(): void {
  counters.length = 0;
  activityProbes.length = 0;
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
  // What is filling the credential, rendered as one short clause (see
  // `formatCredentialSessionSummary`). Present only when the credential is
  // approaching or at the ceiling and the summary could be built; purely
  // descriptive, so the four fields above are identical with or without it.
  liveSummary?: string;
}

/** What a credential's live sessions look like at the moment of a decision. */
export interface CredentialSessionSummary {
  total: number;
  /** Sessions per endpoint, highest first, at most SUMMARY_TOP_ENDPOINTS. */
  byEndpoint: Array<[string, number]>;
  /** How many distinct endpoints hold at least one session. */
  endpoints: number;
  /** Tracked sessions with a request in flight (an open stream counts). */
  inFlight: number;
  /** Tracked sessions with nothing in flight. */
  idle: number;
  /** Longest idle time among idle sessions, whole seconds; null when none. */
  oldestIdleSeconds: number | null;
  /** Sessions no probe tracks (SSE, or untracked): neither idle nor in flight. */
  untracked: number;
}

const SUMMARY_TOP_ENDPOINTS = 5;
/** Hard cap on one endpoint name in the summary; longer is truncated. */
const SUMMARY_NAME_MAX = 32;
/** Hard cap on the whole rendered clause, so the log line stays short. */
const SUMMARY_MAX_CHARS = 180;

/**
 * Summarize the live sessions a credential holds: how many per endpoint, how
 * many are in flight or idle, and how long the oldest idle one has been quiet.
 *
 * WHY. The ceiling WARN and the refusal event said a credential was full but
 * not what filled it, and a credential can sit pinned for days before anyone
 * works out whether the sessions are busy or abandoned. This gives the next
 * occurrence a one-line answer in the log.
 *
 * Counts and endpoint names ONLY. A session id never leaves this function: it
 * is used to ask the probes about activity and is not part of the result, so it
 * cannot reach a log line or an event.
 *
 * Called ONLY when a credential is approaching or at the ceiling (the rare
 * path), never per request. Never throws: a counter or probe that faults is
 * skipped, and the ceiling decision does not depend on this.
 */
export function summarizeCredentialSessions(
  identity: SessionIdentity,
): CredentialSessionSummary {
  const perEndpoint = new Map<string, number>();
  let total = 0;
  let inFlight = 0;
  let idle = 0;
  let untracked = 0;
  let oldestIdleMs = -1;

  for (const counter of counters) {
    let sessions: SessionListing[] = [];
    try {
      sessions = counter.listSessionsForIdentity?.(identity) ?? [];
    } catch {
      continue;
    }
    for (const session of sessions) {
      total += 1;
      perEndpoint.set(
        session.endpointName,
        (perEndpoint.get(session.endpointName) ?? 0) + 1,
      );

      let activity: ReturnType<SessionActivityProbe>;
      for (const probe of activityProbes) {
        try {
          activity = probe(session.sessionId);
        } catch {
          activity = undefined;
        }
        if (activity !== undefined) break;
      }
      if (activity === undefined) {
        untracked += 1;
      } else if (activity.inFlight) {
        inFlight += 1;
      } else {
        idle += 1;
        if (activity.idleMs > oldestIdleMs) oldestIdleMs = activity.idleMs;
      }
    }
  }

  const byEndpoint = [...perEndpoint.entries()]
    // Highest count first; ties broken by name so the output is stable.
    .sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0))
    .slice(0, SUMMARY_TOP_ENDPOINTS);

  return {
    total,
    byEndpoint,
    endpoints: perEndpoint.size,
    inFlight,
    idle,
    oldestIdleSeconds:
      oldestIdleMs >= 0 ? Math.floor(oldestIdleMs / 1000) : null,
    untracked,
  };
}

// Endpoint names come from operator configuration. Keep only characters that
// are safe in a log line and cannot forge a second one.
function safeEndpointName(name: string): string {
  const cleaned = name.replace(/[^A-Za-z0-9_.-]/g, "?");
  return cleaned.length > SUMMARY_NAME_MAX
    ? `${cleaned.slice(0, SUMMARY_NAME_MAX - 1)}~`
    : cleaned;
}

/**
 * Render a summary as one short clause, for example
 * `live: autotask=21, itglue=21, ninja=21 (top 5 of 14 endpoints); in-flight 187, idle 113, oldest idle 1710s`.
 * Empty when there is nothing to say. Bounded to SUMMARY_MAX_CHARS by dropping
 * trailing endpoints, never by cutting mid-token.
 */
export function formatCredentialSessionSummary(
  summary: CredentialSessionSummary,
): string {
  if (summary.total === 0) return "";

  const tail: string[] = [];
  if (summary.inFlight > 0 || summary.idle > 0) {
    tail.push(`in-flight ${summary.inFlight}`, `idle ${summary.idle}`);
    if (summary.oldestIdleSeconds !== null) {
      tail.push(`oldest idle ${summary.oldestIdleSeconds}s`);
    }
  }
  if (summary.untracked > 0) tail.push(`untracked ${summary.untracked}`);
  const tailText = tail.length > 0 ? `; ${tail.join(", ")}` : "";

  const render = (shown: Array<[string, number]>): string => {
    const names = shown
      .map(([name, count]) => `${safeEndpointName(name)}=${count}`)
      .join(", ");
    const scope =
      shown.length < summary.endpoints
        ? ` (top ${shown.length} of ${summary.endpoints} endpoints)`
        : "";
    return `live: ${names}${scope}${tailText}`;
  };

  let shown = summary.byEndpoint;
  let text = render(shown);
  while (text.length > SUMMARY_MAX_CHARS && shown.length > 1) {
    shown = shown.slice(0, -1);
    text = render(shown);
  }
  return text;
}

/** The clause for a credential, or "" when it cannot be built. Never throws. */
function liveSummaryFor(identity: SessionIdentity): string {
  try {
    return formatCredentialSessionSummary(
      summarizeCredentialSessions(identity),
    );
  } catch {
    return "";
  }
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

  // Only when the credential is refused or approaching: the rare path, never a
  // healthy credential's request. Appended AFTER the existing text, so every
  // line a log rule already matches on keeps its prefix and shape.
  const liveSummary = !allowed || approaching ? liveSummaryFor(identity) : "";
  const summarySuffix = liveSummary ? ` ${liveSummary}` : "";

  if (!allowed) {
    logger.warn(
      `Concurrent-session ceiling reached for ${identity.method} credential${labelSuffix}: ` +
        `${current}/${ceiling} live sessions; refusing a new session. Raise ` +
        `MCP_MAX_SESSIONS_PER_CREDENTIAL if this is a legitimate consumer.` +
        summarySuffix,
    );
  } else if (approaching) {
    logger.warn(
      `Concurrent-session usage high for ${identity.method} credential${labelSuffix}: ` +
        `${current}/${ceiling} live sessions (>=80%). Approaching the ceiling; ` +
        `raise MCP_MAX_SESSIONS_PER_CREDENTIAL before it refuses new sessions.` +
        summarySuffix,
    );
  }

  return {
    allowed,
    current,
    ceiling,
    approaching,
    ...(liveSummary && { liveSummary }),
  };
}
