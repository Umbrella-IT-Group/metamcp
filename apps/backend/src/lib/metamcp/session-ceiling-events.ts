/**
 * Durable, throttled observability for the per-credential session ceiling.
 *
 * WHY THIS EXISTS. When a credential pins itself at the ceiling, the only
 * server-side trace was a WARN naming the auth METHOD but not WHICH credential,
 * so identifying the leaking key meant break-glass access to the session store.
 * This records a `client`-category gateway event — the same durable sink the
 * History view queries (`log-store.record` → `gateway_events`) — carrying the
 * credential's DISPLAY NAME, so the next leak is answerable from the admin UI
 * in seconds instead of from a database prompt.
 *
 * WHY IT IS THROTTLED. A pinned credential refuses on every new-session attempt
 * — hundreds per hour observed. One event per refusal would be the noise
 * problem this fork has spent weeks removing, and (unlike the audit throttle
 * next door) would also flood the in-memory Live Logs ring. So emission is
 * collapsed PER (credential id, endpoint, kind) to one event per interval, with
 * the number of suppressed occurrences folded into the next event that is
 * written — mirroring `recordSessionBindingDenial`'s map + interval +
 * clear-on-overflow exactly rather than inventing a second throttle style.
 *
 * WHY IT NEVER THROWS. Emission runs on the session-creation request path,
 * immediately before a 429 is returned or a session is opened. A throw here
 * would turn a visibility improvement into an availability regression, so the
 * whole body is guarded and returns void — the event is fire-and-forget, and a
 * failed record still advances the throttle window (same trade as
 * `emitSessionBindingDenial`: a refusal is answered whether or not it is
 * recorded).
 */

import type { CeilingDecision } from "./credential-session-quota";
import { metamcpLogStore } from "./log-store";
import type { SessionIdentity } from "./session-auth";

/** Which ceiling condition an event describes. Part of the throttle key. */
type SessionCeilingEventKind = "refused" | "approaching";

/**
 * One event per (credential, endpoint, kind) per interval; suppressed
 * occurrences ride the next emitted message. Same interval and same reasoning
 * as `SESSION_DENIAL_REPORT_INTERVAL_MS`.
 */
export const SESSION_CEILING_EVENT_INTERVAL_MS = 60 * 1000;

/** Same clear-on-overflow ceiling as the session-denial throttle next door. */
export const SESSION_CEILING_EVENT_THROTTLE_MAX_ENTRIES = 10_000;

/**
 * Separator for the composite throttle key. Same character and same purpose as
 * the one in `session-binding-denial`: NUL cannot appear in a uuid, an endpoint
 * name, or a kind, so the parts can never run together into a key two different
 * triples both produce. Written as the escape, never a literal NUL byte, so the
 * file stays text to git and reviewable in a diff.
 */
const KEY_SEPARATOR = "\u0000";

interface CeilingThrottleEntry {
  reportedAt: number;
  suppressed: number;
}

const ceilingThrottle = new Map<string, CeilingThrottleEntry>();

/**
 * Should this occurrence be written, and how many were swallowed since the last
 * one that was? Stateful: calling it RECORDS the occurrence. Keyed on the
 * credential, the endpoint, and the kind — a noisy refusing credential must not
 * swallow the first "approaching" of a different credential, nor hide the first
 * refusal of a different endpoint.
 */
function recordSessionCeilingOccurrence(
  credentialKey: string,
  endpointKey: string,
  kind: SessionCeilingEventKind,
): { emit: boolean; suppressed: number } {
  const key = `${credentialKey}${KEY_SEPARATOR}${endpointKey}${KEY_SEPARATOR}${kind}`;
  const now = Date.now();
  const entry = ceilingThrottle.get(key);

  if (entry && now - entry.reportedAt < SESSION_CEILING_EVENT_INTERVAL_MS) {
    entry.suppressed += 1;
    return { emit: false, suppressed: entry.suppressed };
  }

  if (ceilingThrottle.size >= SESSION_CEILING_EVENT_THROTTLE_MAX_ENTRIES) {
    ceilingThrottle.clear();
  }
  const suppressed = entry?.suppressed ?? 0;
  ceilingThrottle.set(key, { reportedAt: now, suppressed: 0 });
  return { emit: true, suppressed };
}

/** Test seam for the throttle map. */
export function __resetSessionCeilingThrottleForTesting(): void {
  ceilingThrottle.clear();
}

function buildMessage(
  kind: SessionCeilingEventKind,
  current: number,
  ceiling: number,
  suppressed: number,
): string {
  const base =
    kind === "refused"
      ? `session refused: concurrent-session ceiling reached (${current}/${ceiling})`
      : `concurrent sessions at ${current}/${ceiling}, approaching the ceiling`;
  if (suppressed <= 0) {
    return base;
  }
  const noun = kind === "refused" ? "refusals" : "warnings";
  return `${base} (${suppressed} more ${noun} suppressed in the last 60s)`;
}

/**
 * Record a durable, throttled ceiling event for one session-creation decision.
 *
 * Call once per decision at each refusal site, right after
 * `checkConcurrentSessionCeiling`. Emits a `refused` event when the decision
 * refused, an `approaching` event when it allowed but the credential is at or
 * past the 80% WARN threshold, and nothing otherwise. `label` is the
 * credential's DISPLAY NAME (api-key name or OAuth user email) — never a token,
 * key value, or header — and rides `clientName` so the History view names WHICH
 * credential without exposing a secret. The 429 response body is unaffected;
 * the label never reaches the client.
 */
export function recordSessionCeilingEvent(params: {
  identity: SessionIdentity;
  endpointName: string;
  label?: string;
  decision: CeilingDecision;
}): void {
  try {
    const { identity, endpointName, label, decision } = params;

    const kind: SessionCeilingEventKind | null = !decision.allowed
      ? "refused"
      : decision.approaching
        ? "approaching"
        : null;
    if (kind === null) {
      return;
    }

    // The refusal path only reaches an authenticated credential (anonymous is
    // exempt from the ceiling), so credentialId is populated here; fall back
    // defensively rather than key on `null`.
    const credentialKey = identity.credentialId ?? "unknown";
    const { emit, suppressed } = recordSessionCeilingOccurrence(
      credentialKey,
      endpointName,
      kind,
    );
    if (!emit) {
      return;
    }

    metamcpLogStore.record({
      category: "client",
      serverName: endpointName,
      level: "warn",
      message: buildMessage(
        kind,
        decision.current,
        decision.ceiling,
        suppressed,
      ),
      clientName: label,
    });
  } catch {
    // A visibility write must never fail the session-creation path it runs on.
    // Swallowed, not logged: `metamcpLogStore.record` already logs its own
    // failures, and this guard exists for the pathological case where the store
    // itself throws — there is nothing further this layer can usefully do.
  }
}
