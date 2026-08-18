import logger from "@/utils/logger";

/**
 * Retention policy for the tool-call audit log (`tool_call_audit`, migration
 * 0019; immutability window from migration 0032).
 *
 * WHY THIS CLAMP EXISTS, and why it is not merely tidiness. Migration 0032
 * refuses a DELETE of any row whose `called_at` is inside 30 days. The pruner
 * issues ONE statement covering everything older than its cutoff, so with
 * retention set between 1 and 29 that statement spans the boundary: the
 * trigger raises on the first in-window row, and the raise rolls back the
 * WHOLE statement. The aged rows the sweep was supposed to reclaim are not
 * deleted either. Retention does not merely become shorter than asked, it
 * stops working altogether, behind an error logged every five minutes. The
 * table then grows without bound while the logs say something is wrong.
 *
 * Clamping means the application never asks for a range it cannot have, so a
 * misconfiguration costs extra retained history rather than all pruning.
 *
 * A value below the floor is raised with a WARN rather than honoured or
 * rejected, for the reason the sibling policy in `lib/gateway-events/retention`
 * gives: refusing to boot over a log-retention setting is a worse failure than
 * keeping more history than asked, and honouring it silently would let a typo
 * quietly delete the guarantee.
 *
 * THE ASYMMETRY WITH `GATEWAY_EVENTS_RETENTION_DAYS` IS DELIBERATE. There,
 * `<= 0` clamps to the floor like any other under-range value, because that
 * table is high-volume operational history and "keep forever" is an
 * unbounded-growth setting. Here `<= 0` keeps its long-standing meaning of
 * "retain forever": this table is the audit trail, its write rate is one row
 * per tool call rather than per connection event, and keeping MORE of it is
 * the safe direction. The floor exists to stop retention going below 30, and
 * "forever" is not below 30.
 */

/** Immutability window in migration 0032. Retention can never sit inside it. */
export const TOOL_AUDIT_RETENTION_FLOOR_DAYS = 30;

export const TOOL_AUDIT_RETENTION_DEFAULT_DAYS = 90;

/**
 * Resolve the effective retention period from a raw env value.
 *
 * Pure and exported so the clamp is testable without booting the oauth router
 * the sweep actually runs in, which starts intervals and opens a pool at
 * import. Same reason `lib/gateway-events/retention` exports its resolver.
 *
 * Returns `<= 0` unchanged; the caller treats that as "never prune".
 */
export function resolveToolAuditRetentionDays(raw: string | undefined): number {
  if (raw === undefined || raw.trim() === "") {
    return TOOL_AUDIT_RETENTION_DEFAULT_DAYS;
  }

  // Shape-checked BEFORE parsing, because `Number.parseInt` is not a
  // validator: it reads a leading integer and discards whatever follows, so
  // "30abc" becomes 30 and "1e9" becomes 1, a typo taking effect as a number
  // nobody wrote. The pattern admits a leading `-` so the retain-forever
  // values still parse rather than falling through to the default.
  const parsed = /^-?\d+$/.test(raw.trim())
    ? Number.parseInt(raw, 10)
    : Number.NaN;
  if (!Number.isFinite(parsed)) {
    logger.warn(
      `[tool-audit] TOOL_AUDIT_RETENTION_DAYS="${raw}" is not a number; using the ${TOOL_AUDIT_RETENTION_DEFAULT_DAYS}-day default`,
    );
    return TOOL_AUDIT_RETENTION_DEFAULT_DAYS;
  }

  // Checked before the floor, so "retain forever" is never mistaken for an
  // under-range value and raised to 30, which would start deleting rows on a
  // deployment that asked for none to be deleted.
  if (parsed <= 0) {
    return parsed;
  }

  if (parsed < TOOL_AUDIT_RETENTION_FLOOR_DAYS) {
    logger.warn(
      `[tool-audit] TOOL_AUDIT_RETENTION_DAYS=${parsed} is below the ${TOOL_AUDIT_RETENTION_FLOOR_DAYS}-day immutability window and has been raised to ${TOOL_AUDIT_RETENTION_FLOOR_DAYS}; rows inside that window cannot be deleted, and a prune spanning the boundary would roll back and delete nothing at all (migration 0032)`,
    );
    return TOOL_AUDIT_RETENTION_FLOOR_DAYS;
  }

  return parsed;
}

/**
 * The value the sweep actually uses. Parsed once, at module load, so the WARN
 * above fires at boot rather than every five minutes on the cleanup interval.
 */
export const TOOL_AUDIT_RETENTION_DAYS = resolveToolAuditRetentionDays(
  process.env.TOOL_AUDIT_RETENTION_DAYS,
);
