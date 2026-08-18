import type { AuditTableStats } from "@/db/repositories/audit-storage.repo";
import { metamcpLogStore } from "@/lib/metamcp/log-store";
import logger from "@/utils/logger";

/**
 * Growth tripwire for the three audit tables (`audit_log`, `gateway_events`,
 * `tool_call_audit`).
 *
 * WHAT THIS IS FOR. `gateway_events` (migration 0031) and `tool_call_audit`
 * (migration 0032) are immutable for their first 30 days at the database
 * level, and that guarantee is the reason a size problem here is different
 * from a size problem anywhere else in the gateway: no application path can
 * reclaim in-window space, not even the retention sweeps, so lowering a
 * retention variable does nothing until the window passes. Reclaiming early is
 * a superuser break-glass act (see README). The only useful defence is knowing
 * early, which is what this does.
 *
 * IT IS DELIBERATELY NOT A RATE LIMITER. Capping the write side would mean
 * choosing, at write time, which security records to drop, and a dropped
 * record is unrecoverable in exactly the tables that exist to be complete. The
 * accepted position is that growth is monitored rather than throttled.
 *
 * THE FAILURE MODE THIS IS BUILT AGAINST is a monitor whose own signal nobody
 * sees, so the signal is layered and each layer covers the previous one's blind
 * spot:
 *
 *   1. Every check logs an INFO line per table with the numbers, in a flat
 *      `key=value` shape that greps and parses. This is the layer that answers
 *      "was it already growing last week?", and it fires whether or not
 *      anything is wrong, so a silent tripwire and a healthy estate are
 *      distinguishable.
 *   2. Crossing the threshold escalates to a WARN written through
 *      `metamcpLogStore.record()`, which mirrors to the console AND persists a
 *      `system` row to `gateway_events`. Reporting through the surface it
 *      monitors is the point: the operator meets the tripwire in the same
 *      History view they already use, rather than in a log stack they have to
 *      remember to open.
 *
 * WHERE EACH LAYER ACTUALLY LANDS DEPENDS ON `LOG_LEVEL`, and the difference
 * matters enough to state rather than imply. `utils/logger` mirrors to stdout
 * only at or above the floor for the configured mode, and the floor when
 * `LOG_LEVEL` is unset is WARN. So on a default-configured deployment the
 * heartbeat reaches the in-container app log but NOT stdout, which means it
 * does not reach anything shipping container logs; `LOG_LEVEL=info` (what this
 * fork's own deployment sets) is what puts layer 1 in front of a log shipper.
 * Layer 2 is a WARN, so it clears the floor at every mode except `none`.
 *
 * That asymmetry is the reason layer 2 does not rely on the log at all. Its
 * database half is written by the same call and is level-independent, so the
 * one signal an operator must not miss survives a logging configuration nobody
 * revisited. One row per table per day is not a contributor to the problem it
 * reports on, and a warning that only exists somewhere nobody looks is not a
 * warning. The hourly INFO line deliberately does NOT go through the log store
 * for the same reason inverted: a heartbeat has no escalation value in the
 * history and would add rows on every check forever.
 */

/** Default: every 12th sweep of the 5-minute cleanup interval, so hourly. */
export const AUDIT_STORAGE_CHECK_INTERVAL_SWEEPS_DEFAULT = 12;

/**
 * Ceiling on the configured interval: 288 sweeps is 24 hours at the cleanup
 * interval's 5 minutes.
 *
 * A ceiling exists because the alternative is an off switch. A value of 0, a
 * negative, or a number large enough that the check never realistically fires
 * would leave a monitor installed, configured, and mute, which is the precise
 * failure this module was written to avoid. Whatever is configured, the
 * numbers land in the log at least once a day.
 */
export const AUDIT_STORAGE_CHECK_INTERVAL_SWEEPS_MAX = 288;

/** Default warn threshold per table, in megabytes. */
export const AUDIT_STORAGE_WARN_MB_DEFAULT = 2048;

/**
 * Ceiling on the configured threshold: 1 TiB per table.
 *
 * A ceiling here for the same reason the interval has one. Without it, an
 * absurd value is an off switch for the escalation layer, and the escalation
 * layer is the half that does not depend on how logging happens to be
 * configured. Leaving the heartbeat as the only guard would not cover it: at
 * the default `LOG_LEVEL` the heartbeat does not reach stdout at all (see the
 * module header), so muting layer 2 on such a deployment mutes everything an
 * external log stack could see.
 *
 * 1 TiB is far past any threshold a deployment would set on purpose and far
 * past the point at which these tables are a problem worth a warning, so the
 * cap refuses only values that were already meaningless.
 */
export const AUDIT_STORAGE_WARN_MB_MAX = 1024 * 1024;

/** One reported crossing suppresses the next for this long, per table. */
export const AUDIT_STORAGE_WARN_REPEAT_MS = 24 * 60 * 60 * 1000;

/**
 * Falling to this fraction of the threshold re-arms a table for an immediate
 * warning on its next crossing.
 *
 * Below 1 rather than at it because a table sitting exactly on the boundary
 * would otherwise re-arm and re-warn on alternating checks as it wobbled
 * across, which is the flapping the repeat window exists to prevent. Ten
 * percent of the threshold is a wide enough gap that only a real reclaim
 * crosses it.
 */
export const AUDIT_STORAGE_REARM_FRACTION = 0.9;

const BYTES_PER_MB = 1024 * 1024;

/**
 * Resolve the sweep interval from a raw env value.
 *
 * Pure and exported so the parse is testable without booting the oauth router
 * the check runs in, which starts intervals and opens a pool at import. Same
 * reason `lib/gateway-events/retention` and `lib/tool-audit-retention` export
 * their resolvers.
 */
export function resolveAuditStorageCheckIntervalSweeps(
  raw: string | undefined,
): number {
  if (raw === undefined || raw.trim() === "") {
    return AUDIT_STORAGE_CHECK_INTERVAL_SWEEPS_DEFAULT;
  }

  // Shape-checked BEFORE parsing, matching the two retention resolvers.
  // `Number.parseInt` is not a validator: it reads a leading integer and
  // discards the rest, so "12abc" becomes 12 and "1e9" becomes 1, a typo
  // taking effect as a number nobody wrote.
  const parsed = /^-?\d+$/.test(raw.trim())
    ? Number.parseInt(raw, 10)
    : Number.NaN;
  if (!Number.isFinite(parsed)) {
    logger.warn(
      `[audit-storage] AUDIT_STORAGE_CHECK_INTERVAL_SWEEPS="${raw}" is not a number; using the ${AUDIT_STORAGE_CHECK_INTERVAL_SWEEPS_DEFAULT}-sweep default`,
    );
    return AUDIT_STORAGE_CHECK_INTERVAL_SWEEPS_DEFAULT;
  }

  if (parsed < 1) {
    logger.warn(
      `[audit-storage] AUDIT_STORAGE_CHECK_INTERVAL_SWEEPS=${parsed} would disable the storage check; using the ${AUDIT_STORAGE_CHECK_INTERVAL_SWEEPS_DEFAULT}-sweep default instead. There is deliberately no off switch: a mute monitor is the failure this check exists to prevent.`,
    );
    return AUDIT_STORAGE_CHECK_INTERVAL_SWEEPS_DEFAULT;
  }

  if (parsed > AUDIT_STORAGE_CHECK_INTERVAL_SWEEPS_MAX) {
    logger.warn(
      `[audit-storage] AUDIT_STORAGE_CHECK_INTERVAL_SWEEPS=${parsed} is longer than a day and has been capped to ${AUDIT_STORAGE_CHECK_INTERVAL_SWEEPS_MAX} sweeps (24h), so the audit tables are always measured at least daily`,
    );
    return AUDIT_STORAGE_CHECK_INTERVAL_SWEEPS_MAX;
  }

  return parsed;
}

/** Resolve the per-table warn threshold in megabytes from a raw env value. */
export function resolveAuditStorageWarnMb(raw: string | undefined): number {
  if (raw === undefined || raw.trim() === "") {
    return AUDIT_STORAGE_WARN_MB_DEFAULT;
  }

  const parsed = /^-?\d+$/.test(raw.trim())
    ? Number.parseInt(raw, 10)
    : Number.NaN;
  if (!Number.isFinite(parsed)) {
    logger.warn(
      `[audit-storage] AUDIT_STORAGE_WARN_MB="${raw}" is not a number; using the ${AUDIT_STORAGE_WARN_MB_DEFAULT} MB default`,
    );
    return AUDIT_STORAGE_WARN_MB_DEFAULT;
  }

  if (parsed < 1) {
    // Zero would put every table permanently over the line, which reads as an
    // alert but carries no information, and negatives are meaningless. Both
    // are far more likely to be a typo than an intent.
    logger.warn(
      `[audit-storage] AUDIT_STORAGE_WARN_MB=${parsed} is not a usable threshold; using the ${AUDIT_STORAGE_WARN_MB_DEFAULT} MB default`,
    );
    return AUDIT_STORAGE_WARN_MB_DEFAULT;
  }

  if (parsed > AUDIT_STORAGE_WARN_MB_MAX) {
    logger.warn(
      `[audit-storage] AUDIT_STORAGE_WARN_MB=${parsed} would mute the escalation entirely and has been capped to ${AUDIT_STORAGE_WARN_MB_MAX} MB (1 TiB); there is deliberately no value that turns the warning off`,
    );
    return AUDIT_STORAGE_WARN_MB_MAX;
  }

  return parsed;
}

/**
 * The values the check actually uses. Parsed once, at module load, so an
 * invalid setting is reported at boot rather than every hour thereafter.
 */
export const AUDIT_STORAGE_CHECK_INTERVAL_SWEEPS =
  resolveAuditStorageCheckIntervalSweeps(
    process.env.AUDIT_STORAGE_CHECK_INTERVAL_SWEEPS,
  );

export const AUDIT_STORAGE_WARN_MB = resolveAuditStorageWarnMb(
  process.env.AUDIT_STORAGE_WARN_MB,
);

type AuditStorageStatsReader = () => Promise<AuditTableStats[]>;

let statsReader: AuditStorageStatsReader | null | undefined;

async function resolveStatsReader(): Promise<AuditStorageStatsReader | null> {
  if (statsReader !== undefined) return statsReader;
  try {
    const { auditStorageRepository } = await import(
      "../../db/repositories/audit-storage.repo"
    );
    statsReader = () => auditStorageRepository.tableStats();
  } catch (error) {
    // Almost always "no database in this process" (unit tests, tooling), and
    // disabling for the process lifetime is right for that case: re-attempting
    // the import every hour would achieve nothing. But it is not the ONLY case
    // that lands here, and the others are a real defect quietly turning the
    // monitor off for as long as the process lives. Saying so once is what
    // keeps the no-off-switch rule this module argues for from having an
    // accidental exception inside its own error handling. Once rather than
    // hourly because the result is cached; there is no second attempt to warn
    // about.
    logger.warn(
      "[audit-storage] storage checks are disabled for this process: the stats repository could not be loaded",
      error,
    );
    statsReader = null;
  }
  return statsReader;
}

/** Test seam: override or disable the stats source (undefined = re-resolve). */
export function setAuditStorageStatsReaderForTesting(
  next: AuditStorageStatsReader | null | undefined,
): void {
  statsReader = next;
}

/**
 * Sweeps observed since process start.
 *
 * Starts at 0 so the FIRST sweep after boot is a check, five minutes in,
 * rather than the twelfth an hour later. A monitor that says nothing for the
 * first hour after every restart is missing its reading at the one moment a
 * deployment is most likely to have changed something.
 */
let sweepsSeen = 0;

/**
 * When each table last had a crossing reported. Absent means armed: the next
 * crossing warns immediately.
 *
 * Process-local and deliberately not persisted, which is what makes "re-arm on
 * restart" true by construction. A restart is when an operator is most likely
 * to be looking, and re-stating a live condition then costs one line.
 */
const lastWarnedAt = new Map<string, number>();

function formatMb(bytes: number | null): string {
  if (bytes === null) return "unknown";
  return (bytes / BYTES_PER_MB).toFixed(1);
}

function formatNumber(value: number | null): string {
  return value === null ? "unknown" : String(value);
}

/**
 * Report one table: the heartbeat always, the escalation only on a crossing
 * this table is armed for.
 */
function report(stats: AuditTableStats, thresholdBytes: number): void {
  logger.info(
    `[audit-storage] table=${stats.table} est_rows=${formatNumber(stats.est_rows)} total_bytes=${formatNumber(stats.total_bytes)} total_mb=${formatMb(stats.total_bytes)} threshold_mb=${AUDIT_STORAGE_WARN_MB}`,
  );

  // A table with no size is one `to_regclass` could not resolve, which means
  // the migrations have not been applied in this schema. That is a real
  // condition but not a growth condition, and warning about it hourly on a
  // half-migrated development box would train the operator to ignore this
  // exact WARN. The `unknown` in the line above is the honest signal, and the
  // integration suite is what pins all three names to real tables.
  if (stats.total_bytes === null) return;

  const rearmBytes = thresholdBytes * AUDIT_STORAGE_REARM_FRACTION;
  const warnedAt = lastWarnedAt.get(stats.table);

  if (stats.total_bytes < thresholdBytes) {
    // Re-arm only once genuinely back below the band, so a table hovering on
    // the boundary does not alternate between armed and warned.
    if (warnedAt !== undefined && stats.total_bytes < rearmBytes) {
      lastWarnedAt.delete(stats.table);
    }
    return;
  }

  const now = Date.now();
  if (warnedAt !== undefined && now - warnedAt < AUDIT_STORAGE_WARN_REPEAT_MS) {
    // Still over, already reported, and inside the repeat window. Holding here
    // is what keeps a five-minute sweep from producing a five-minute alarm.
    return;
  }
  lastWarnedAt.set(stats.table, now);

  // Through the log store rather than `logger.warn` directly, so this single
  // call both mirrors to stdout for the log stack and persists a `system` row
  // the operator will find in the History view.
  metamcpLogStore.record({
    category: "system",
    serverName: "audit-storage",
    level: "warn",
    message: `${stats.table} is ${formatMb(stats.total_bytes)} MB (${stats.total_bytes} bytes, est_rows=${formatNumber(stats.est_rows)}), at or above AUDIT_STORAGE_WARN_MB=${AUDIT_STORAGE_WARN_MB}. Rows inside the 30-day immutability window cannot be reclaimed by lowering retention; see the break-glass note in README.`,
  });
}

/**
 * Run the storage check if this sweep is due. Never throws.
 *
 * Called once per tick of the cleanup interval in `routers/oauth/index.ts`,
 * AFTER the retention prunes on the same tick, so the figures describe the
 * estate as it stands rather than as it stood before the sweep that was about
 * to shrink it.
 *
 * Errors are logged and swallowed for the same reason every other sweep on
 * that interval swallows its own: one failing sweep must not stop the ones
 * queued behind it, and this one is a diagnostic, so it has the least claim of
 * any of them on the interval it rides.
 */
export async function checkAuditStorage(): Promise<void> {
  const due = sweepsSeen % AUDIT_STORAGE_CHECK_INTERVAL_SWEEPS === 0;
  sweepsSeen += 1;
  if (!due) return;

  try {
    const read = await resolveStatsReader();
    if (!read) return;

    const thresholdBytes = AUDIT_STORAGE_WARN_MB * BYTES_PER_MB;
    for (const stats of await read()) {
      report(stats, thresholdBytes);
    }
  } catch (error) {
    logger.error("Error checking audit table storage:", error);
  }
}
