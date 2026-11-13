import { describeDbError } from "@/lib/db-error-summary";
import logger from "@/utils/logger";

import { oauthRepository } from "../../db/repositories";
import { CIMD_UNUSED_RETENTION_DAYS } from "./cimd-config";

/**
 * Retention sweep for self-registered OAuth clients that no administrator
 * approved.
 *
 * WHY THIS IS NEEDED. `POST /oauth/register` is anonymous by RFC 7591 design,
 * so `oauth_clients` is a table an unauthenticated caller can INSERT into. The
 * input caps in ./client-registration.ts bound how BIG each row can be; this
 * bounds how MANY there are.
 *
 * WHAT IS SWEPT (migration 0042). Since self-registered clients wait for an
 * administrator, the approval state says which rows are disposable, and the
 * sweep reads it instead of guessing from usage:
 *   - a self-registration still PENDING more than DCR_CLIENT_RETENTION_DAYS
 *     after it was created (default 7: the time an administrator has to act);
 *   - a self-registration REJECTED more than one day ago, counted from the
 *     rejection, not from registration, so an old registration rejected today
 *     is still visible tomorrow.
 *
 * WHAT IS NEVER SWEPT. Any APPROVED row, used or not; admin-created rows
 * (`registration_source = 'admin'`), which are often unused on purpose
 * because they were pre-provisioned for someone who has not connected yet; and
 * legacy rows whose provenance is NULL because they predate migration 0029.
 * The previous rule ("dcr, older than the window, no code or token rows")
 * would have deleted an approved self-registration that had not connected
 * yet, which is why it was replaced rather than extended.
 *
 * The window is a reasonable initial response time for an administrator, not
 * a judgment that a pending client is safe and not a global storage bound;
 * the registration body and rate limits remain the per-request bounds.
 */

/** Env override for the window, in days. `<= 0` disables the sweep entirely. */
export const DCR_CLIENT_RETENTION_DAYS_ENV = "DCR_CLIENT_RETENTION_DAYS";

/** Days a pending self-registration is kept before it is swept. */
export const DEFAULT_DCR_CLIENT_RETENTION_DAYS = 7;

/** How long a rejected self-registration is kept after its rejection. */
export const REJECTED_DCR_CLIENT_RETENTION_MS = 24 * 60 * 60 * 1000;

/**
 * Resolve the effective window.
 *
 * Read per call rather than at module load so a test can exercise more than
 * one value in a file, matching resolveDcrAllowedHosts in ./utils. An
 * unparseable value falls back to the default instead of disabling the sweep:
 * a typo in an env var should not silently switch a retention control off.
 */
export function resolveDcrClientRetentionDays(): number {
  const raw = process.env[DCR_CLIENT_RETENTION_DAYS_ENV];
  if (raw === undefined || raw.trim() === "") {
    return DEFAULT_DCR_CLIENT_RETENTION_DAYS;
  }

  const parsed = Number.parseInt(raw, 10);
  if (!Number.isFinite(parsed)) {
    logger.warn(
      `[oauth] ${DCR_CLIENT_RETENTION_DAYS_ENV}=${raw} is not an integer; using default ${DEFAULT_DCR_CLIENT_RETENTION_DAYS}`,
    );
    return DEFAULT_DCR_CLIENT_RETENTION_DAYS;
  }

  return parsed;
}

/**
 * Run one sweep. Returns the number of client rows removed.
 *
 * `<= 0` for DCR_CLIENT_RETENTION_DAYS disables the whole sweep, pending and
 * rejected rows alike, as it always has.
 *
 * Never throws: it is called from the shared 5-minute cleanup interval, where
 * an unhandled rejection would be an unhandled rejection in a timer callback
 * rather than a failed request anyone can see. Same contract as the
 * `cleanupExpired` and tool-audit prunes it rides beside.
 */
export async function sweepUnapprovedDcrClients(): Promise<number> {
  const retentionDays = resolveDcrClientRetentionDays();
  if (retentionDays <= 0) return 0;

  try {
    const removed = await oauthRepository.pruneUnapprovedDcrClients(
      retentionDays,
      REJECTED_DCR_CLIENT_RETENTION_MS,
    );
    if (removed > 0) {
      // Logged only when it does something. A line every five minutes saying
      // "removed 0" is what makes an operator stop reading this log.
      logger.info(
        `[oauth] swept ${removed} self-registered OAuth client(s) left pending over ${retentionDays}d or rejected over 1d ago`,
      );
    }
    return removed;
  } catch (error) {
    logger.error(
      "Error sweeping unapproved OAuth clients:",
      describeDbError(error),
    );
    return 0;
  }
}

/**
 * Run one sweep of client metadata document rows (source `cimd`, migration
 * 0046). Returns the number of rows removed.
 *
 * What goes: a `cimd` row not refreshed for CIMD_UNUSED_RETENTION_DAYS that
 * has no access token, authorization code or rotated-token marker. What
 * stays: every row of any other source (this never touches the DCR sweep's
 * rows, nor an admin-created or legacy row), and any `cimd` row somebody is
 * connected through, because deleting its client would revoke those sessions.
 * The sweep is only housekeeping: a still-listed client's row is written again
 * by its next authorize, so nothing is lost by deleting an unused one.
 *
 * Not switched off by an empty allowlist: rows can outlive the entry that
 * created them, and those are exactly the ones worth reaping.
 *
 * Never throws, for the reason sweepUnapprovedDcrClients gives.
 */
export async function sweepUnusedCimdClients(): Promise<number> {
  try {
    const removed = await oauthRepository.pruneUnusedCimdClients(
      CIMD_UNUSED_RETENTION_DAYS,
    );
    if (removed > 0) {
      logger.info(
        `[oauth] swept ${removed} unused client metadata document client(s) not refreshed for ${CIMD_UNUSED_RETENTION_DAYS}d`,
      );
    }
    return removed;
  } catch (error) {
    logger.error(
      "Error sweeping unused client metadata document rows:",
      describeDbError(error),
    );
    return 0;
  }
}
