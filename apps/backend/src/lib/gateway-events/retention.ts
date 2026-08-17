import logger from "@/utils/logger";

/**
 * Retention policy for the gateway activity history (`gateway_events`,
 * migration 0031).
 *
 * TWO NUMBERS, AND ONLY ONE OF THEM IS A KNOB.
 *
 * The floor of 30 days is the requirement: at least 30 days of history that
 * cannot be rewritten or quietly trimmed. Migration 0031 enforces it from
 * underneath with an age-gated DELETE trigger, so it is not a policy this
 * module could relax even if it wanted to — a sweep that asked for anything
 * inside the window would raise rather than delete. Clamping here means the
 * application never asks.
 *
 * The retention period itself IS a knob (`GATEWAY_EVENTS_RETENTION_DAYS`,
 * default 90), because this table is high-volume operational history and a
 * deployment with a chatty estate has a legitimate reason to keep less of it.
 * What it does not have is a reason to keep less than the floor, so a value
 * below 30 is clamped UP with a WARN rather than honoured or rejected:
 * refusing to boot over a log-retention setting would be a worse failure than
 * keeping more history than asked, and honouring it silently would let a
 * config typo quietly delete the guarantee.
 *
 * NOTE THE ASYMMETRY WITH `TOOL_AUDIT_RETENTION_DAYS`, which treats `<= 0` as
 * "retain forever". There is no such value here. Zero and negative numbers
 * clamp to the floor like any other under-range value, because "keep forever"
 * on a table with this write rate is an unbounded-growth setting, and the one
 * thing the floor must not permit is a way to end up with LESS than 30 days.
 */

/** Immutability window in migration 0031. Retention can never go below it. */
export const GATEWAY_EVENTS_RETENTION_FLOOR_DAYS = 30;

export const GATEWAY_EVENTS_RETENTION_DEFAULT_DAYS = 90;

/**
 * Resolve the effective retention period from a raw env value.
 *
 * Pure and exported so the clamp is testable without booting the express
 * routers the sweeper actually runs in — the same reason
 * `lib/audit/audit-emitter` exports its helpers rather than burying them.
 */
export function resolveGatewayEventsRetentionDays(
  raw: string | undefined,
): number {
  if (raw === undefined || raw.trim() === "") {
    return GATEWAY_EVENTS_RETENTION_DEFAULT_DAYS;
  }

  const parsed = Number.parseInt(raw, 10);
  if (!Number.isFinite(parsed)) {
    logger.warn(
      `[gateway-events] GATEWAY_EVENTS_RETENTION_DAYS="${raw}" is not a number; using the ${GATEWAY_EVENTS_RETENTION_DEFAULT_DAYS}-day default`,
    );
    return GATEWAY_EVENTS_RETENTION_DEFAULT_DAYS;
  }

  if (parsed < GATEWAY_EVENTS_RETENTION_FLOOR_DAYS) {
    logger.warn(
      `[gateway-events] GATEWAY_EVENTS_RETENTION_DAYS=${parsed} is below the ${GATEWAY_EVENTS_RETENTION_FLOOR_DAYS}-day immutability window and has been raised to ${GATEWAY_EVENTS_RETENTION_FLOOR_DAYS}; rows inside that window cannot be deleted (migration 0031)`,
    );
    return GATEWAY_EVENTS_RETENTION_FLOOR_DAYS;
  }

  return parsed;
}

/**
 * The value the sweeper actually uses. Parsed once, at module load, so the WARN
 * above fires at boot rather than every five minutes on the cleanup interval.
 */
export const GATEWAY_EVENTS_RETENTION_DAYS = resolveGatewayEventsRetentionDays(
  process.env.GATEWAY_EVENTS_RETENTION_DAYS,
);

type GatewayEventsPruner = (days: number) => Promise<void>;

let pruner: GatewayEventsPruner | null | undefined;

async function resolvePruner(): Promise<GatewayEventsPruner | null> {
  if (pruner !== undefined) return pruner;
  try {
    const { gatewayEventsRepository } = await import(
      "../../db/repositories/gateway-events.repo"
    );
    pruner = (days) => gatewayEventsRepository.pruneOlderThan(days);
  } catch {
    pruner = null;
  }
  return pruner;
}

/** Test seam: override or disable the prune target (undefined = re-resolve). */
export function setGatewayEventsPrunerForTesting(
  next: GatewayEventsPruner | null | undefined,
): void {
  pruner = next;
}

/**
 * Prune history past the effective retention period. Never throws.
 *
 * Errors are logged and swallowed for the same reason the neighbouring sweeps
 * in `routers/oauth/index.ts` swallow theirs: this rides a shared five-minute
 * interval, and one failing sweep must not stop the ones queued behind it.
 */
export async function pruneGatewayEvents(): Promise<void> {
  try {
    const prune = await resolvePruner();
    await prune?.(GATEWAY_EVENTS_RETENTION_DAYS);
  } catch (error) {
    logger.error("Error pruning gateway_events:", error);
  }
}
