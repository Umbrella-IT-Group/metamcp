/**
 * Boot-time converge of `m365_user_tokens.rt_ciphertext` toward an EXPLICIT
 * target envelope version, plus the boot line that makes the envelope posture
 * legible.
 *
 * WHAT IT DOES. Reads every row's envelope, and for each row not already at the
 * target re-seals the SAME refresh token at the target version bound to that
 * row's own user, then swaps it in with a compare-and-swap on the ciphertext it
 * read. It redeems nothing, makes no Entra call, and touches no status or
 * timestamp column (a rewrap is not a rotation, and a `reauth_required` row stays
 * exactly that). Idempotent and safe to interrupt: a row either swaps or is left
 * as it was.
 *
 * THE TARGET comes from `M365_ENVELOPE_WRITE_VERSION` (see `./envelope`):
 *  - `2` rewraps v1 rows to v2;
 *  - `1` rewraps v2 rows to v1, the explicit rollback path;
 *  - unset or invalid (`keep`) makes NO write at all. It lists the rows and logs
 *    the version counts, which is the baseline `v1=N v2=M` an operator reads
 *    before flipping anything. A typo or a dropped variable therefore can never
 *    lower a bound row.
 * Strict (`M365_ENVELOPE_STRICT`) forces the target to v2, so a strict boot
 * binds whatever is still v1 instead of leaving it for a user to re-enroll.
 *
 * TRUST ON FIRST BINDING. Binding a v1 row binds WHATEVER ciphertext sits in it
 * to that row's user. A swap by a database writer that predates the converge
 * (user A's ciphertext copied into user B's row) becomes permanent and cannot be
 * detected without an Entra call, because the converge faithfully rewraps what it
 * finds. Strict plus the converge closes LATER swaps only. An operator who
 * suspects an earlier swap has the affected users re-enroll.
 *
 * NEVER THROWS, and never blocks the gateway from starting: a missing or
 * malformed KEK, a failed list and a failed row are each logged and the pass
 * moves on. The one-line summary prints `strict=on|off` and the effective write
 * version, and a boot WARN names the case where new envelopes would be written
 * unbound while bound rows already exist (the flag was dropped after binding, or
 * an explicit rollback is in progress).
 *
 * LOGS carry a user id and an error NAME at most: never a ciphertext, a refresh
 * token or key bytes.
 *
 * SINGLE-PROCESS. Like the mint path's in-process single-flight, this assumes
 * one gateway process per database. It runs before the server listens, so no
 * request of THIS process races it; the compare-and-swap covers a mint in an
 * older process still running during a deploy overlap.
 */
import logger from "@/utils/logger";

import { getTokenKek } from "./config";
import type { EnvelopeVersion } from "./crypto";
import {
  describeEnvelopePolicy,
  effectiveWriteVersion,
  peekEnvelopeVersion,
  resolveEnvelopePolicy,
  rewrapUserEnvelope,
} from "./envelope";

/** The repository surface the converge needs; the real one is resolved lazily. */
export interface EnvelopeConvergeRepo {
  listEnvelopes(): Promise<{ user_id: string; rt_ciphertext: string }[]>;
  replaceCiphertextIfUnchanged(
    userId: string,
    expectedCiphertext: string,
    nextCiphertext: string,
    kekId: string,
  ): Promise<boolean>;
}

/** Same lazy, type-only doctrine as the mint service: keep this module DB-free. */
async function defaultRepo(): Promise<EnvelopeConvergeRepo> {
  const module = await import("../../db/repositories/m365-tokens.repo");
  return module.m365TokensRepository;
}

/** An error's NAME only: a message can echo input, a name cannot. */
function errorName(error: unknown): string {
  return error instanceof Error ? error.name : typeof error;
}

export async function convergeM365Envelopes(
  repoOverride?: EnvelopeConvergeRepo,
): Promise<void> {
  try {
    await converge(repoOverride);
  } catch (error) {
    // Defence in depth: every step below handles its own failure. This keeps a
    // future refactor from turning a converge defect into a boot failure.
    logger.error(
      `[m365] envelope converge: unexpected error (ignored): ${errorName(error)}`,
    );
  }
}

async function converge(repoOverride?: EnvelopeConvergeRepo): Promise<void> {
  // Resolved first so an unrecognised flag value is logged at boot even when
  // the converge goes on to skip (no KEK, nothing enrolled).
  const policy = resolveEnvelopePolicy();
  const posture = describeEnvelopePolicy(policy);

  let keyMaterial: ReturnType<typeof getTokenKek>;
  try {
    keyMaterial = getTokenKek();
  } catch (error) {
    logger.error(
      `[m365] envelope converge: skipped, M365_TOKEN_KEK is malformed (${errorName(error)}); ${posture}`,
    );
    return;
  }
  if (!keyMaterial) {
    logger.info(
      `[m365] envelope converge: skipped, M365_TOKEN_KEK is not configured; ${posture}`,
    );
    return;
  }
  const { kek, kekId } = keyMaterial;

  let repo: EnvelopeConvergeRepo;
  let rows: { user_id: string; rt_ciphertext: string }[];
  try {
    repo = repoOverride ?? (await defaultRepo());
    rows = await repo.listEnvelopes();
  } catch (error) {
    logger.error(
      `[m365] envelope converge: skipped, could not list the stored envelopes (${errorName(error)}); ${posture}`,
    );
    return;
  }

  const target: EnvelopeVersion | null =
    policy.mode === "keep" ? null : policy.mode;

  let v1 = 0;
  let v2 = 0;
  let unreadable = 0;
  let rewrapped = 0;
  let already = 0;
  let skippedChanged = 0;
  let failed = 0;

  for (const row of rows) {
    const version = peekEnvelopeVersion(row.rt_ciphertext);
    if (version === "v1") v1 += 1;
    else if (version === "v2") v2 += 1;
    else unreadable += 1;

    if (target === null) continue;
    if (version === target) {
      already += 1;
      continue;
    }
    // An unrecognisable envelope falls through to the rewrap, which throws and
    // is counted as a failure below rather than silently ignored.
    try {
      const next = rewrapUserEnvelope(
        row.rt_ciphertext,
        kek,
        kekId,
        row.user_id,
        target,
      );
      const swapped = await repo.replaceCiphertextIfUnchanged(
        row.user_id,
        row.rt_ciphertext,
        next,
        kekId,
      );
      if (swapped) {
        rewrapped += 1;
        if (version === "v1") v1 -= 1;
        else if (version === "v2") v2 -= 1;
        if (target === "v1") v1 += 1;
        else v2 += 1;
      } else {
        skippedChanged += 1;
      }
    } catch (error) {
      failed += 1;
      logger.warn(
        `[m365] envelope converge: row for user ${row.user_id} not rewrapped (${errorName(error)})`,
      );
    }
  }

  logger.info(
    `[m365] envelope converge: ${posture} scanned=${rows.length} rewrapped=${rewrapped} already=${already} skipped_changed=${skippedChanged} failed=${failed} v1_remaining=${v1} v2_remaining=${v2} unreadable=${unreadable}`,
  );

  if (target === null && rows.length === 0) {
    // Nothing enrolled: nothing further to say.
    return;
  }

  // New envelopes would be written unbound while bound rows exist: either the
  // write-version flag was dropped after binding (rows keep v2, new enrollments
  // do not get it) or an explicit rollback to v1 is under way.
  if (effectiveWriteVersion(policy) === "v1" && v2 > 0) {
    logger.warn(
      policy.mode === "v1"
        ? `[m365] envelope converge: M365_ENVELOPE_WRITE_VERSION=1 with ${v2} bound (v2) row(s) remaining: the rollback to v1 is incomplete, and new envelopes are written unbound. ${posture}`
        : `[m365] envelope converge: ${v2} bound (v2) row(s) exist but the effective write version is v1: new enrollments are sealed unbound. Set M365_ENVELOPE_WRITE_VERSION=2 to keep binding new rows, or 1 to confirm a rollback. ${posture}`,
    );
  }

  if (policy.strict && v1 > 0) {
    logger.warn(
      `[m365] envelope converge: M365_ENVELOPE_STRICT is on and ${v1} v1 row(s) could not be bound; those users will be asked to re-enroll. ${posture}`,
    );
  }
  if (unreadable > 0) {
    logger.warn(
      `[m365] envelope converge: ${unreadable} row(s) hold an envelope this version cannot read; a converge with failures is not clearance for strict or a rollback. ${posture}`,
    );
  }
}
