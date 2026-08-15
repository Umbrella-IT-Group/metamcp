import logger from "@/utils/logger";

import { oauthRepository } from "../../db/repositories";

/**
 * Retention sweep for dynamically-registered OAuth clients that were never
 * used.
 *
 * WHY THIS IS NEEDED. `POST /oauth/register` is anonymous by RFC 7591 design,
 * so `oauth_clients` is a table an unauthenticated caller can INSERT into and
 * nothing could ever DELETE from except an administrator clicking through the
 * admin UI one row at a time. 45 junk rows had accumulated that way. The input
 * caps in ./client-registration.ts bound how BIG each row can be; this bounds
 * how MANY there are.
 *
 * WHAT COUNTS AS "NEVER USED", and why that is a safe test on this deployment.
 * A client is swept only when it has zero authorization codes AND zero access
 * tokens AND was created longer ago than the retention window. The second
 * condition is what makes this safe: `oauthRepository.cleanupExpired` deletes
 * an access-token row only once the access token AND the refresh token are
 * both expired, and the fork's default refresh TTL is 365 days
 * (OAUTH_REFRESH_TOKEN_TTL_SECONDS in ./token.ts). So a client that has ever
 * completed one token exchange keeps a row for about a year of total
 * inactivity, while a client that registered and never came back has neither
 * child row from the moment it was written. A real connector pairing runs DCR
 * and authorize seconds apart, never days.
 *
 * THE COUPLING TO STATE OUT LOUD, because it is the thing that would make this
 * sweep wrong: it depends on the refresh-token TTL being much longer than this
 * window. Lower OAUTH_REFRESH_TOKEN_TTL_SECONDS below
 * DCR_CLIENT_RETENTION_DAYS and a paired-but-dormant client can lose its row
 * and have to register again. Anyone shortening that TTL must revisit this
 * number.
 */

/** Env override for the window, in days. `<= 0` disables the sweep entirely. */
export const DCR_CLIENT_RETENTION_DAYS_ENV = "DCR_CLIENT_RETENTION_DAYS";

/** Days a never-used client is kept before it is swept. */
export const DEFAULT_DCR_CLIENT_RETENTION_DAYS = 7;

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
 * Never throws: it is called from the shared 5-minute cleanup interval, where
 * an unhandled rejection would be an unhandled rejection in a timer callback
 * rather than a failed request anyone can see. Same contract as the
 * `cleanupExpired` and tool-audit prunes it rides beside.
 */
export async function sweepUnusedDcrClients(): Promise<number> {
  const retentionDays = resolveDcrClientRetentionDays();
  if (retentionDays <= 0) return 0;

  try {
    const removed = await oauthRepository.pruneUnusedClients(retentionDays);
    if (removed > 0) {
      // Logged only when it does something. A line every five minutes saying
      // "removed 0" is what makes an operator stop reading this log.
      logger.info(
        `[oauth] swept ${removed} never-used OAuth client(s) older than ${retentionDays}d`,
      );
    }
    return removed;
  } catch (error) {
    logger.error("Error sweeping never-used OAuth clients:", error);
    return 0;
  }
}
