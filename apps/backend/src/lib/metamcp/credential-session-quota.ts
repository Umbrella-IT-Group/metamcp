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
 * cleanup path, without this module having to be told. The one maintained
 * term is the short-lived slot reservation an opt-in admission holds before
 * registering its own session (see
 * `admissionReservations`); it is released by the admitting request itself,
 * in a `finally`, never by a cleanup path (or, if the decision faults before
 * it can hand the eviction over, by the decision code on its way out).
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
  /**
   * Optional: evict one of this counter's sessions so a new session can be
   * admitted at the ceiling (see `checkConcurrentSessionCeiling`'s
   * `evictIdle`). Only a counter that has this hook AND a lister can ever have
   * a session chosen; the SSE manager has neither eviction nor idle tracking,
   * so its sessions are never candidates.
   *
   * Contract, which the admission path depends on:
   *  - Before returning, the session is gone from `countSessionsForIdentity`
   *    and `listSessionsForIdentity`. That is what lets the next concurrent
   *    admission see the freed slot as taken (by the reservation) and pick a
   *    DIFFERENT victim, instead of evicting the same session twice.
   *  - The returned promise settles when the teardown has finished and never
   *    rejects; a failure is logged by the counter.
   *  - `undefined` means nothing was evicted (the session is no longer
   *    resident, or is busy after all); the caller then refuses as before.
   */
  evictSessionForAdmission?(sessionId: string): Promise<void> | undefined;
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

// A session must have been quiet this long before the ceiling may evict it.
// Two minutes is longer than any gap inside one live exchange (a client's
// request, the model's turn, the next request), so a session that is merely
// between calls is not chosen, and far shorter than the idle sweeper's TTL,
// which is the whole point: a credential pinned by abandoned sessions gets a
// slot back now instead of at the next sweep.
export const DEFAULT_CEILING_EVICT_MIN_IDLE_SECONDS = 120;

// Hard floor for the idle threshold. Enabled initial connects are marked in flight;
// keep a conservative floor after they settle too, so a freshly negotiated
// session is not immediately evictable while its client prepares the next call.
export const MIN_CEILING_EVICT_MIN_IDLE_SECONDS = 10;

// Longest an evicting admission waits for its victim's teardown before going
// ahead anyway. The wait exists so the victim hands its backend connections
// back before the new session takes its own; it must not turn a slow or hung
// backend into a stalled initialize, because the backend pool releases a
// session's extra connections one after another, each bounded only by its own
// DELETE timeout. Going ahead is safe: the new session has a fresh id, so it
// shares nothing with the victim's half-finished teardown, and the teardown
// carries on in the background. Recovery of the victim's own id still waits
// for the whole teardown (see `recoverPersistedSession`), since that rebuild
// reuses the id.
export const EVICTION_ADMISSION_WAIT_MS = 5_000;
let evictionAdmissionWaitMs = EVICTION_ADMISSION_WAIT_MS;

const counters: IdentitySessionCounter[] = [];
const activityProbes: SessionActivityProbe[] = [];

/**
 * Slots held by enabled opt-in admissions that have not yet registered
 * their own sessions. Keyed per credential identity (method + id, the same pair
 * `identityMatches` compares) and summed into `countLiveSessionsForIdentity`.
 *
 * WHY. The new session is added to its manager only after an await (the pool
 * hands out a server instance first). Without a reservation, concurrent
 * initializes can all claim the same free slot, including one just freed by
 * eviction. Each enabled admission reserves synchronously, so the next one
 * sees the correct capacity. The router releases on registration, failure or
 * disconnection and refuses to register a late result after cancellation.
 */
const admissionReservations = new Map<string, number>();

/** NUL cannot appear in a method name or a credential id. */
const RESERVATION_KEY_SEPARATOR = "\u0000";

function reservationKey(identity: SessionIdentity): string {
  return `${identity.method}${RESERVATION_KEY_SEPARATOR}${identity.credentialId ?? ""}`;
}

/** Reserve one slot for `identity`; the returned release is idempotent. */
function reserveAdmissionSlot(identity: SessionIdentity): () => void {
  const key = reservationKey(identity);
  admissionReservations.set(key, (admissionReservations.get(key) ?? 0) + 1);
  let released = false;
  return () => {
    if (released) return;
    released = true;
    const remaining = (admissionReservations.get(key) ?? 0) - 1;
    if (remaining > 0) {
      admissionReservations.set(key, remaining);
    } else {
      admissionReservations.delete(key);
    }
  };
}

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
  admissionReservations.clear();
  evictionAdmissionWaitMs = EVICTION_ADMISSION_WAIT_MS;
}

/**
 * TEST-ONLY: shorten the admission's bounded wait on a victim's teardown, so a
 * route test over real sockets (real timers) can exercise the timeout without
 * sleeping for the production bound. `undefined` restores the default.
 */
export function setEvictionAdmissionWaitMsForTests(
  ms: number | undefined,
): void {
  evictionAdmissionWaitMs = ms ?? EVICTION_ADMISSION_WAIT_MS;
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

export interface CeilingEvictionConfig {
  /** `MCP_SESSION_CEILING_EVICT_IDLE`; on by default. */
  enabled: boolean;
  /** `MCP_SESSION_CEILING_EVICT_MIN_IDLE_SECONDS`, in milliseconds. */
  minIdleMs: number;
}

const EVICT_ENABLED_VALUES = ["true", "1", "on", "yes", "enable", "enabled"];
// `disable` and `disabled` are accepted because this is an emergency lever: an
// operator reaching for it under pressure is likely to type either, and an
// unrecognised value leaves eviction ON (with a WARN), the wrong way for a
// kill switch to fail.
const EVICT_DISABLED_VALUES = [
  "false",
  "0",
  "off",
  "no",
  "disable",
  "disabled",
];

/**
 * Resolve the ceiling-eviction settings from the environment. The enabled
 * setting is read for each opt-in admission, the idle floor at the ceiling, but that environment is fixed
 * when the gateway process starts: a changed value takes effect only when the
 * gateway restarts with it (a compose recreate), never on a live process.
 *
 * `MCP_SESSION_CEILING_EVICT_IDLE` is the kill switch: `false`, `0`, `off`,
 * `no`, `disable` or `disabled` (any case) restores the plain refusal. Unset
 * or empty means on. Any other value falls back to on with a WARN, the same
 * treatment `resolveSessionCeiling` gives a malformed ceiling, so a typo is
 * visible.
 *
 * `MCP_SESSION_CEILING_EVICT_MIN_IDLE_SECONDS` (default 120) is how long a
 * session must have been idle to be chosen. Malformed or negative falls back
 * to the default with a WARN; a value under `MIN_CEILING_EVICT_MIN_IDLE_SECONDS`
 * is raised to it with a WARN (see that constant for the conservative floor).
 */
export function resolveEvictionConfig(): CeilingEvictionConfig {
  return {
    enabled: resolveEvictionEnabled(),
    minIdleMs: resolveEvictionMinIdleSeconds() * 1000,
  };
}

function resolveEvictionEnabled(): boolean {
  const raw = process.env.MCP_SESSION_CEILING_EVICT_IDLE;
  if (raw === undefined || raw.trim() === "") {
    return true;
  }
  const normalised = raw.trim().toLowerCase();
  if (EVICT_ENABLED_VALUES.includes(normalised)) return true;
  if (EVICT_DISABLED_VALUES.includes(normalised)) return false;
  logger.warn(
    `MCP_SESSION_CEILING_EVICT_IDLE=${raw} invalid; falling back to default true.`,
  );
  return true;
}

function resolveEvictionMinIdleSeconds(): number {
  const raw = process.env.MCP_SESSION_CEILING_EVICT_MIN_IDLE_SECONDS;
  if (raw === undefined || raw.trim() === "") {
    return DEFAULT_CEILING_EVICT_MIN_IDLE_SECONDS;
  }
  // Partial parses (e.g. "1e2") can silently lower a destructive eviction
  // threshold. Require a whole decimal integer and safe millisecond arithmetic.
  const parsed = Number(raw.trim());
  if (!/^\d+$/.test(raw.trim()) || !Number.isSafeInteger(parsed * 1000)) {
    logger.warn(
      `MCP_SESSION_CEILING_EVICT_MIN_IDLE_SECONDS=${raw} invalid; falling back to default ${DEFAULT_CEILING_EVICT_MIN_IDLE_SECONDS}.`,
    );
    return DEFAULT_CEILING_EVICT_MIN_IDLE_SECONDS;
  }
  if (parsed < MIN_CEILING_EVICT_MIN_IDLE_SECONDS) {
    logger.warn(
      `MCP_SESSION_CEILING_EVICT_MIN_IDLE_SECONDS=${raw} is below the minimum; using ${MIN_CEILING_EVICT_MIN_IDLE_SECONDS}.`,
    );
    return MIN_CEILING_EVICT_MIN_IDLE_SECONDS;
  }
  return parsed;
}

/**
 * Live sessions across all registered managers for one identity, plus any
 * slots reserved by enabled admissions that have not yet registered their own (see `admissionReservations`). This is the number the
 * ceiling compares against.
 */
export function countLiveSessionsForIdentity(
  identity: SessionIdentity,
): number {
  return (
    counters.reduce(
      (sum, counter) => sum + counter.countSessionsForIdentity(identity),
      0,
    ) + (admissionReservations.get(reservationKey(identity)) ?? 0)
  );
}

/** Ask the probes about one session; the first that tracks it answers. */
function probeSessionActivity(sessionId: string): {
  activity: ReturnType<SessionActivityProbe>;
  faults: number;
} {
  let activity: ReturnType<SessionActivityProbe>;
  let faults = 0;
  for (const probe of activityProbes) {
    try {
      activity = probe(sessionId);
    } catch {
      faults += 1;
      activity = undefined;
    }
    if (activity !== undefined) break;
  }
  return { activity, faults };
}

/** One session the ceiling may evict, and the counter that can evict it. */
export interface EvictionCandidate {
  sessionId: string;
  /** Operator-configured name, unsanitized; render through the summary rules. */
  endpointName: string;
  idleMs: number;
  counter: IdentitySessionCounter;
}

/**
 * Pick the session to evict so `identity` can open a new one: among the
 * credential's OWN sessions held by a counter that can evict, the one with
 * nothing in flight that has been idle longest, provided it has been idle for
 * at least `minIdleMs`. Ties go to the lower session id so the choice is
 * deterministic.
 *
 * Excluded, each for a reason the admission path depends on:
 *  - another credential's sessions (the lister is per identity): one key at
 *    its ceiling must never cost a different consumer its session;
 *  - in-flight sessions: a request is running, or an open standalone GET
 *    stream is held, which is how a live Claude Code process looks;
 *  - sessions no probe tracks, and every session of a counter without an
 *    evictor (SSE): with no activity there is nothing to say they are idle;
 *  - sessions idle for less than `minIdleMs`.
 *
 * Read-only and synchronous: it decides, the caller evicts. Never throws; a
 * faulting lister or probe is skipped and counted in one WARN.
 */
export function selectEvictionCandidate(
  identity: SessionIdentity,
  { minIdleMs }: { minIdleMs: number },
): EvictionCandidate | undefined {
  if (identity.method === "anonymous" || identity.credentialId === null) {
    return undefined;
  }

  let best: EvictionCandidate | undefined;
  let listerFaults = 0;
  let probeFaults = 0;

  for (const counter of counters) {
    if (
      typeof counter.evictSessionForAdmission !== "function" ||
      typeof counter.listSessionsForIdentity !== "function"
    ) {
      continue;
    }
    let sessions: SessionListing[];
    try {
      sessions = counter.listSessionsForIdentity(identity);
    } catch {
      listerFaults += 1;
      continue;
    }
    for (const session of sessions) {
      const { activity, faults } = probeSessionActivity(session.sessionId);
      probeFaults += faults;
      if (
        activity === undefined ||
        activity.inFlight ||
        activity.idleMs < minIdleMs
      ) {
        continue;
      }
      if (
        best === undefined ||
        activity.idleMs > best.idleMs ||
        (activity.idleMs === best.idleMs && session.sessionId < best.sessionId)
      ) {
        best = {
          sessionId: session.sessionId,
          endpointName: session.endpointName,
          idleMs: activity.idleMs,
          counter,
        };
      }
    }
  }

  if (listerFaults > 0 || probeFaults > 0) {
    // Counts only: a fault object can carry a session id or a credential.
    logger.warn(
      `Session ceiling eviction scan degraded: ${listerFaults} lister faults, ${probeFaults} activity probe faults.`,
    );
  }
  return best;
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
  // Present only when the credential was at its ceiling and an idle session
  // was evicted to admit this one (`allowed` is then true). The caller owns
  // `release()`: see `CeilingEviction`.
  eviction?: CeilingEviction;
  /** Every opt-in admission reserves a slot, including below the ceiling.
   * Release synchronously when registered and in a finally on other exits. */
  releaseAdmission?: () => void;
}

/**
 * An idle session evicted so a new one could be admitted at the ceiling.
 *
 * The CALLER of `checkConcurrentSessionCeiling({ evictIdle: true })` must call
 * `release()` once its new session is registered with a manager, and again in
 * a `finally` on every other exit (it is idempotent). Until then the slot the
 * victim left is reserved for this admission, so a concurrent admission keeps
 * seeing the credential at its ceiling and evicts its own victim instead of
 * slipping in over the limit.
 */
export interface CeilingEviction {
  /** The evicted session's endpoint, reduced to log-safe characters. */
  endpointName: string;
  /** How long the evicted session had been idle, whole seconds. */
  idleSeconds: number;
  /**
   * What the admitting request awaits before taking its own pool state:
   * settles when the victim's teardown has finished, or after
   * `EVICTION_ADMISSION_WAIT_MS` (with a WARN) if it has not, whichever comes
   * first. Never rejects. A timed-out teardown keeps running.
   */
  teardownWait: Promise<void>;
  /** Give back the reserved slot. Idempotent. */
  release: () => void;
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
  /** A lister fault omitted sessions; do not publish the remaining counts as complete. */
  incomplete?: true;
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
  let listerFaults = 0;
  let probeFaults = 0;

  for (const counter of counters) {
    let sessions: SessionListing[] = [];
    try {
      sessions = counter.listSessionsForIdentity?.(identity) ?? [];
    } catch {
      listerFaults += 1;
      continue;
    }
    for (const session of sessions) {
      total += 1;
      perEndpoint.set(
        session.endpointName,
        (perEndpoint.get(session.endpointName) ?? 0) + 1,
      );

      const { activity, faults } = probeSessionActivity(session.sessionId);
      probeFaults += faults;
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

  if (listerFaults > 0 || probeFaults > 0) {
    // Fault objects can contain credentials or session IDs. Log counts only,
    // once per summary, while preserving the independent admission decision.
    logger.warn(
      `Session ceiling summary degraded: ${listerFaults} lister faults, ${probeFaults} activity probe faults.`,
    );
  }

  return {
    total,
    byEndpoint,
    endpoints: perEndpoint.size,
    inFlight,
    idle,
    oldestIdleSeconds:
      oldestIdleMs >= 0 ? Math.floor(oldestIdleMs / 1000) : null,
    untracked,
    ...(listerFaults > 0 && { incomplete: true as const }),
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
  if (summary.total === 0 || summary.incomplete) return "";

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
    logger.warn(
      "Session ceiling summary could not be rendered; continuing admission check.",
    );
    return "";
  }
}

/**
 * Evict one idle session of `identity` so a new one can be admitted, or return
 * undefined and leave everything as it was. Only reached when the credential
 * is at its ceiling and the caller opted in.
 *
 * Never throws: a fault anywhere here must end in today's refusal, not in a
 * failed request, so it is caught, reported (without the fault object, which
 * can carry a session id) and turned into "nothing evicted".
 */
function evictForAdmission(
  identity: SessionIdentity,
): CeilingEviction | undefined {
  let release: (() => void) | undefined;
  try {
    const config = resolveEvictionConfig();
    if (!config.enabled) {
      return undefined;
    }
    const candidate = selectEvictionCandidate(identity, {
      minIdleMs: config.minIdleMs,
    });
    if (candidate === undefined) {
      return undefined;
    }
    // Everything that could fault is computed BEFORE the eviction, so that
    // once a session has been evicted and a slot reserved, nothing between
    // here and the caller can throw and strand the reservation.
    const endpointName = safeEndpointName(candidate.endpointName);
    const idleSeconds = Math.floor(candidate.idleMs / 1000);
    const teardown = candidate.counter.evictSessionForAdmission?.(
      candidate.sessionId,
    );
    if (teardown === undefined) {
      return undefined;
    }
    // Reserve in the same synchronous step as the eviction: the victim has
    // already left the count, and no other admission may run between the two.
    release = reserveAdmissionSlot(identity);
    // The counter contract says this never rejects; hold it to that here
    // as well, loudly, so an awaiting admission can never be failed by it.
    const settled = Promise.resolve(teardown).then(
      () => undefined,
      () => {
        logger.warn(
          "Session ceiling eviction: the evicted session's teardown rejected; admitting the new session anyway.",
        );
      },
    );
    return {
      endpointName,
      idleSeconds,
      teardownWait: boundedTeardownWait(settled, endpointName),
      release,
    };
  } catch {
    // Unreachable in practice (see the ordering above); if it ever happens
    // after a reservation, give the slot back rather than hold it until a
    // restart.
    release?.();
    logger.warn(
      "Session ceiling eviction faulted; refusing the new session as before.",
    );
    return undefined;
  }
}

/**
 * Settle when `teardown` does or after `evictionAdmissionWaitMs`, whichever is
 * first; see `EVICTION_ADMISSION_WAIT_MS` for why the admission's wait is
 * bounded. The timer is cleared as soon as the teardown wins, and unref'd so
 * it never holds the process open.
 */
function boundedTeardownWait(
  teardown: Promise<void>,
  endpointName: string,
): Promise<void> {
  const waitMs = evictionAdmissionWaitMs;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timedOut = new Promise<void>((resolve) => {
    timer = setTimeout(() => {
      logger.warn(
        `Session ceiling eviction: the evicted session's teardown on ${endpointName} ` +
          `has not finished after ${waitMs} ms; admitting the new session without ` +
          `waiting for it. The teardown continues in the background.`,
      );
      resolve();
    }, waitMs);
    timer.unref?.();
  });
  return Promise.race([teardown, timedOut]).finally(() => clearTimeout(timer));
}

/**
 * Decide whether a credential may open one more session. Call this at session
 * creation: the new session is added to a manager by the caller on the allow
 * path, which is what the next call will count.
 *
 * Without `options.evictIdle` this mutates nothing. When enabled, every
 * opted-in allowed admission reserves its slot until registration. A credential at
 * its ceiling that holds an idle session (see `selectEvictionCandidate`) has
 * that session evicted and is ALLOWED, with the eviction on the decision; the
 * caller must honour `CeilingEviction.release`. When nothing can be evicted,
 * or eviction is switched off (`MCP_SESSION_CEILING_EVICT_IDLE`), the refusal,
 * its WARN text and the decision are exactly what they are without the option.
 *
 * WHY EVICT. Idle sessions are reaped only by the sweeper, on its TTL and its
 * interval, so a credential filled by sessions its clients opened and never
 * closed (a restart loop opening a session per server on every start) stayed
 * refused for most of that TTL even though most of what it held was idle.
 * Evicting preserves the session's `mcp_sessions` row (the counter's teardown
 * is the sweeper's row-preserving variant), so a client that does come back
 * with the id lazily recovers it, exactly as after a sweep.
 *
 * Anonymous callers are exempt: an ALLOW_UNAUTHENTICATED_ENDPOINTS endpoint has
 * no per-caller identity (every caller shares one), so a ceiling there would be
 * a global cap masquerading as per-credential. A ceiling of 0 disables it.
 *
 * WARNs at 80% of the ceiling so an operator sees a credential approaching the
 * limit before it is ever refused. An eviction logs one INFO line instead of
 * the refusal WARN, so a log rule that matches the refusal line fires only
 * when a request was actually refused.
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
  options?: { label?: string; evictIdle?: boolean },
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
    const eviction = options?.evictIdle
      ? evictForAdmission(identity)
      : undefined;
    if (eviction) {
      // The summary was taken before the eviction, so it still describes what
      // filled the credential at the moment it hit the ceiling.
      try {
        logger.info(
          `Concurrent-session ceiling: evicted idle session on ${eviction.endpointName} ` +
            `(idle ${eviction.idleSeconds}s) for ${identity.method} credential${labelSuffix} ` +
            `to admit a new session (${current}/${ceiling})` +
            summarySuffix,
        );
      } catch (error) {
        // The caller only learns of the eviction from the return value, so if
        // this throws it can never release the slot reserved for it. Release
        // it here and let the failure surface as before.
        eviction.release();
        throw error;
      }
      return {
        allowed: true,
        current,
        ceiling,
        approaching,
        ...(liveSummary && { liveSummary }),
        eviction,
        releaseAdmission: eviction.release,
      };
    }
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

  // A free slot must also be reserved before the router awaits its pool.
  // Otherwise a burst starting BELOW the ceiling can all claim that same slot.
  // Keep the old behavior for non-opt-in callers and with the kill switch off.
  const releaseAdmission =
    allowed && options?.evictIdle && resolveEvictionEnabled()
      ? reserveAdmissionSlot(identity)
      : undefined;

  return {
    allowed,
    current,
    ceiling,
    approaching,
    ...(liveSummary && { liveSummary }),
    ...(releaseAdmission && { releaseAdmission }),
  };
}
