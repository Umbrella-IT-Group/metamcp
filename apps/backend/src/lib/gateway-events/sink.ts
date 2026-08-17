import logger from "@/utils/logger";

import {
  clampGatewayMetadata,
  clampGatewayText,
  GATEWAY_EVENT_MESSAGE_MAX,
} from "./bounds";

/**
 * Fire-and-forget writer for the gateway activity history (`gateway_events`,
 * migration 0031).
 *
 * THE SAFETY PROPERTY, and it outranks everything else in this file: a history
 * write must NEVER block, delay, or fail the thing it describes. The single
 * caller is `lib/metamcp/log-store.record()`, which runs on the connect path,
 * the transport error handler, the client-session open, and every backend
 * stderr line. A throw escaping `recordGatewayEvent()` would not lose a log
 * line — it would take down a reconnect handler, or a session initialiser, or
 * the gateway itself. So this returns `void`, never a promise a caller can
 * await into a hot path, and swallows every failure at every layer:
 *
 *   1. building the row is inside the try — a malformed entry must not throw
 *      at the call site;
 *   2. resolving the repository is lazy and failure-tolerant (no DATABASE_URL
 *      in unit tests / tooling disables the sink for the process lifetime
 *      rather than re-attempting the import per event);
 *   3. the write itself is a detached promise with a `.catch`.
 *
 * Same shape, and deliberately the same shape, as
 * `lib/metamcp/metamcp-middleware/auditing.functional.ts` and
 * `lib/audit/audit-emitter.ts`. The lazy import is what keeps `log-store`'s
 * STATIC module graph database-free: a dozen unit suites import modules that
 * import the log store, and none of them have a database.
 *
 * BACKPRESSURE IS DESIGNED, NOT ACCIDENTAL. The repository writes through its
 * own two-connection pool with a 1s checkout timeout
 * (`db/gateway-events-db` — deliberately not the audit pool, so an operational
 * firehose cannot cost the gateway a security-audit row), so under a reconnect
 * storm the third concurrent insert errors instead of queueing. Dropping a row
 * there is the correct trade — a starved request path is not — but dropping it
 * INVISIBLY is not. Failures are rate-limited WARNs
 * carrying a running total, for exactly the reasons `audit-emitter`'s
 * `reportAuditWriteFailure` spells out: production runs at LOG_LEVEL=info so a
 * debug line never reaches the console an operator watches, and one line per
 * failure during an outage buries its own cause.
 *
 * TOOL CALLS ARE FILTERED OUT HERE. `log-store` records a `tool_call` entry
 * for every proxied call, and those are already persisted per call to
 * `tool_call_audit` (migration 0019) with more detail than this envelope
 * carries. Mirroring them would double the busiest write path in the gateway
 * to store a strictly poorer copy. The filter lives at the sink rather than at
 * the call site so it cannot be forgotten by a future emitter.
 */

/**
 * Categories `log-store` can produce that belong in the durable history.
 *
 * Exported so a test can pin it against `GatewayEventCategorySchema` in
 * `@repo/zod-types`: the reader's filter enum and the writer's allow-list
 * describe the same four categories, and a category added to one but not the
 * other is either an unfilterable row or an always-empty filter.
 */
export const PERSISTED_CATEGORIES = new Set([
  "connection",
  "client",
  "server",
  "system",
]);

export interface GatewayEventInput {
  category: string;
  level?: string | null;
  serverUuid?: string | null;
  serverName?: string | null;
  clientName?: string | null;
  sessionId?: string | null;
  message: string;
  metadata?: Record<string, unknown> | null;
}

type GatewayEventSink = (entry: {
  category: string;
  level?: string | null;
  server_uuid?: string | null;
  server_name?: string | null;
  client_name?: string | null;
  session_id?: string | null;
  message: string;
  metadata?: Record<string, unknown> | null;
}) => Promise<void>;

let gatewayEventSink: GatewayEventSink | null | undefined;

async function resolveSink(): Promise<GatewayEventSink | null> {
  if (gatewayEventSink !== undefined) return gatewayEventSink;
  try {
    const { gatewayEventsRepository } = await import(
      "../../db/repositories/gateway-events.repo"
    );
    gatewayEventSink = (entry) => gatewayEventsRepository.record(entry);
  } catch {
    // No database in this process (unit tests, tooling) — disable for the
    // process lifetime rather than re-attempting the import per event.
    gatewayEventSink = null;
  }
  return gatewayEventSink;
}

/** Test seam: override or disable the persistence sink (undefined = re-resolve). */
export function setGatewayEventSinkForTesting(
  sink: GatewayEventSink | null | undefined,
): void {
  gatewayEventSink = sink;
}

/** How long one reported failure suppresses the next report. */
const GATEWAY_EVENT_FAILURE_REPORT_INTERVAL_MS = 60 * 1000;

let gatewayEventFailuresTotal = 0;
let lastGatewayEventFailureReportAt = 0;

/** Test seam: forget the counter and the throttle window. */
export function resetGatewayEventFailureReportingForTesting(): void {
  gatewayEventFailuresTotal = 0;
  lastGatewayEventFailureReportAt = 0;
}

/** Current dropped-row count, for assertions and for operator diagnostics. */
export function gatewayEventFailureCount(): number {
  return gatewayEventFailuresTotal;
}

/**
 * Make a dropped history row detectable without making an outage unreadable.
 *
 * A RUNNING TOTAL since startup, not a per-window delta: a delta is stranded
 * whenever the burst that produced it stops before the next report fires, and
 * silent loss is the exact thing this exists to end. The first failure reports
 * immediately, so that first line necessarily says 1 and the throttle holds
 * the next one back.
 *
 * WARN rather than ERROR, for the same reason the audit emitter chose WARN: a
 * lost history row is a degraded record, not a failed request, and a history
 * sink that pages on a database blip is a history sink someone turns off.
 */
function reportGatewayEventDrop(stage: "write" | "emit", error: unknown): void {
  gatewayEventFailuresTotal += 1;
  const now = Date.now();
  // The `!== 0` half matters under a mocked clock: a suite that pins Date to
  // the epoch would otherwise have its very first failure silently swallowed.
  if (
    lastGatewayEventFailureReportAt !== 0 &&
    now - lastGatewayEventFailureReportAt <
      GATEWAY_EVENT_FAILURE_REPORT_INTERVAL_MS
  ) {
    return;
  }
  lastGatewayEventFailureReportAt = now;
  logger.warn(
    `[gateway-events] ${stage} failed, ${gatewayEventFailuresTotal} event row(s) lost since startup (request unaffected):`,
    error,
  );
}

/**
 * Persist one gateway activity event. Returns immediately; the write is
 * detached.
 *
 * Callers do not need (and must not add) a try/catch of their own, and must
 * not await this.
 */
export function recordGatewayEvent(entry: GatewayEventInput): void {
  try {
    if (!PERSISTED_CATEGORIES.has(entry.category)) return;

    // Clamped HERE, before the row is handed to a detached promise, so the
    // bound is applied by the code that knows the entry is caller-supplied
    // rather than left to the repository to remember. The repository clamps
    // again — belt and braces on a table nothing can trim for 30 days.
    const row = {
      category: entry.category,
      level: entry.level ?? null,
      server_uuid: entry.serverUuid ?? null,
      server_name: clampGatewayText(entry.serverName),
      client_name: clampGatewayText(entry.clientName),
      session_id: clampGatewayText(entry.sessionId),
      message: String(entry.message ?? "").slice(0, GATEWAY_EVENT_MESSAGE_MAX),
      metadata: clampGatewayMetadata(entry.metadata),
    };

    void resolveSink()
      .then((sink) => sink?.(row))
      .catch((error) => {
        reportGatewayEventDrop("write", error);
      });
  } catch (error) {
    // Defence in depth: nothing above should throw synchronously, but a future
    // refactor must not be able to turn a history-write failure into a broken
    // reconnect handler.
    reportGatewayEventDrop("emit", error);
  }
}
