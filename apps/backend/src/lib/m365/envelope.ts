/**
 * Policy for the M365 refresh-token envelope: which version is written, whether
 * a v1 envelope is still accepted, and the row-bound seal and open helpers the
 * mint path, the enrollment callback and the boot converge share. The primitive
 * (AES-GCM, both versions) is `./crypto`; this is the one place that decides
 * HOW it is used for `m365_user_tokens`, so the rules cannot drift between
 * callers.
 *
 * TWO ENV FLAGS, both read per call (like `cors-policy`) so tests stub env and
 * an operator change takes effect on restart without a code deploy:
 *
 *  - `M365_ENVELOPE_WRITE_VERSION`: unset or empty KEEPS each row's version (a
 *    new row is v1), `2` seals v2 bound to the owning user, `1` is the explicit
 *    rollback that seals v1. Any other value (`v2`, `2 `, `3`) keeps and warns.
 *    ONLY an explicit `1` ever lowers a row's version: a typo or a dropped
 *    variable must never silently strip the binding from rows that already have
 *    it, because an image rollback after binding is what forces every enrolled
 *    user to re-enroll.
 *  - `M365_ENVELOPE_STRICT`: `1` refuses a v1 envelope on every read and forces
 *    v2 writes. `0`, unset or empty is off. UNLIKE the write version, any other
 *    value resolves to STRICT, with an ERROR line: strict is the safe direction,
 *    and a typo that quietly left it off would leave the downgrade path open
 *    while the operator believes it is closed. The cost of a typo is that v1
 *    rows are refused (the user re-enrolls), which is bounded to the M365 path:
 *    nothing here can stop the gateway from starting or serving anything else.
 *
 * The write path never produces a row this gateway's own strict read refuses:
 * strict forces `v2`. Strict also turns the boot converge into a read-only
 * census (`./envelope-converge`): a v1 ciphertext is never rewrapped into a
 * bound v2 envelope while strict is on, because that would bind an unproven
 * ciphertext to whichever row holds it. Legacy rows are bound in the migration
 * window (strict off, write version 2) and strict is turned on afterwards.
 */
import logger from "@/utils/logger";

import {
  decryptRefreshToken,
  encryptRefreshToken,
  type EnvelopeVersion,
  envelopeVersion,
} from "./crypto";

export type EnvelopeMode = "keep" | "v1" | "v2";

export interface EnvelopePolicy {
  mode: EnvelopeMode;
  strict: boolean;
}

/** Purpose prefix, so a future bound use elsewhere cannot collide with this one. */
const CONTEXT_PREFIX = "m365-refresh-token:";

/** The context a refresh token's v2 envelope is bound to: the owning user. */
export function refreshTokenContext(userId: string): string {
  return CONTEXT_PREFIX + userId;
}

// Each distinct warning is logged once per process: the policy is resolved on
// every mint and every converge row, and a misconfigured value must be visible
// without becoming a log flood.
const logged = new Set<string>();

function logOnce(level: "warn" | "error", key: string, message: string): void {
  if (logged.has(key)) return;
  logged.add(key);
  logger[level](message);
}

/** Test-only: forget which warnings were already logged. */
export function __resetEnvelopePolicyLogsForTesting(): void {
  logged.clear();
}

/** Bounded, quoted rendering of an operator-supplied value for a log line. */
function quote(value: string): string {
  return JSON.stringify(value.slice(0, 32));
}

export function resolveEnvelopePolicy(
  env: NodeJS.ProcessEnv = process.env,
): EnvelopePolicy {
  const rawWrite = env.M365_ENVELOPE_WRITE_VERSION;
  let mode: EnvelopeMode;
  if (rawWrite === undefined || rawWrite === "") {
    mode = "keep";
  } else if (rawWrite === "2") {
    mode = "v2";
  } else if (rawWrite === "1") {
    mode = "v1";
  } else {
    mode = "keep";
    logOnce(
      "warn",
      `write:${rawWrite}`,
      `[m365] M365_ENVELOPE_WRITE_VERSION=${quote(rawWrite)} is not recognised (expected 1 or 2); keeping each row's current envelope version. Only an explicit 1 lowers a row.`,
    );
  }

  const rawStrict = env.M365_ENVELOPE_STRICT;
  let strict: boolean;
  if (rawStrict === undefined || rawStrict === "" || rawStrict === "0") {
    strict = false;
  } else if (rawStrict === "1") {
    strict = true;
  } else {
    strict = true;
    logOnce(
      "error",
      `strict:${rawStrict}`,
      `[m365] M365_ENVELOPE_STRICT=${quote(rawStrict)} is not recognised (expected 0 or 1); treating it as STRICT, so v1 refresh-token envelopes are refused and those users must re-enroll. Fix or unset the variable.`,
    );
  }

  if (strict && mode !== "v2") {
    if (mode === "v1") {
      logOnce(
        "warn",
        "strict-over-v1",
        "[m365] M365_ENVELOPE_STRICT is on and M365_ENVELOPE_WRITE_VERSION=1: strict wins. No rollback to v1 is performed (the boot converge makes no write while strict is on) and envelopes are written as v2, because a strict gateway never writes rows it would refuse. To roll back, clear M365_ENVELOPE_STRICT first.",
      );
    }
    mode = "v2";
  }
  return { mode, strict };
}

/**
 * The version a NEW envelope (no existing row to keep) is sealed at under this
 * policy: v2 only when binding is on. In `keep` mode this is v1 even though an
 * existing v2 row is rewritten as v2, which is exactly the gap the boot
 * warning in the converge flags when v2 rows already exist.
 */
export function effectiveWriteVersion(policy: EnvelopePolicy): EnvelopeVersion {
  return policy.mode === "v2" ? "v2" : "v1";
}

/** `mode=keep strict=off write_version=v1`, shared by every boot and converge line. */
export function describeEnvelopePolicy(policy: EnvelopePolicy): string {
  return `mode=${policy.mode} strict=${policy.strict ? "on" : "off"} write_version=${effectiveWriteVersion(policy)}`;
}

/** The version of an envelope, or null when it is not a recognisable envelope. Never throws. */
export function peekEnvelopeVersion(
  envelope: string | null | undefined,
): EnvelopeVersion | null {
  if (typeof envelope !== "string") return null;
  try {
    return envelopeVersion(envelope);
  } catch {
    return null;
  }
}

/** Seal at an explicit version. The converge and the reconcile use this directly. */
export function sealUserRefreshTokenAt(
  version: EnvelopeVersion,
  plaintext: string,
  kek: Buffer,
  kekId: string,
  userId: string,
): string {
  return version === "v2"
    ? encryptRefreshToken(plaintext, kek, kekId, refreshTokenContext(userId))
    : encryptRefreshToken(plaintext, kek, kekId);
}

/**
 * Seal a refresh token for `userId` under the current policy: `v2` binds it to
 * the user, `v1` writes the legacy shape, and `keep` writes at `current` (the
 * version of the row being replaced, v1 when there is no row).
 */
export function sealUserRefreshToken(
  plaintext: string,
  kek: Buffer,
  kekId: string,
  userId: string,
  current?: EnvelopeVersion | null,
): string {
  const { mode } = resolveEnvelopePolicy();
  const version: EnvelopeVersion = mode === "keep" ? (current ?? "v1") : mode;
  return sealUserRefreshTokenAt(version, plaintext, kek, kekId, userId);
}

/**
 * Open an envelope for `userId`. `allowV1` defaults to `!strict`: in strict mode
 * a v1 envelope is refused BEFORE any decrypt. The boot converge passes
 * `allowV1: true` so it can rewrap what is still v1. A v2 envelope opens only
 * under this user's context, so another row's ciphertext fails authentication.
 */
export function openUserRefreshToken(
  envelope: string,
  kek: Buffer,
  userId: string,
  opts: { allowV1?: boolean } = {},
): { plaintext: string; version: EnvelopeVersion } {
  const allowV1 = opts.allowV1 ?? !resolveEnvelopePolicy().strict;
  const version = envelopeVersion(envelope);
  if (version === "v1" && !allowV1) {
    throw new Error(
      "A v1 refresh-token envelope is refused: M365_ENVELOPE_STRICT is on",
    );
  }
  const plaintext =
    version === "v2"
      ? decryptRefreshToken(envelope, kek, refreshTokenContext(userId))
      : decryptRefreshToken(envelope, kek);
  return { plaintext, version };
}

/**
 * Re-seal an envelope at `target` for `userId`: open it (v1 allowed), seal it,
 * open the RESULT and require the same plaintext at the target version before
 * returning it. The round trip is what lets the converge write a rewrapped
 * envelope without ever having proved it decrypts, and it is the guard a
 * corrupted seal would otherwise slip past.
 */
export function rewrapUserEnvelope(
  envelope: string,
  kek: Buffer,
  kekId: string,
  userId: string,
  target: EnvelopeVersion,
): string {
  const opened = openUserRefreshToken(envelope, kek, userId, {
    allowV1: true,
  });
  const next = sealUserRefreshTokenAt(
    target,
    opened.plaintext,
    kek,
    kekId,
    userId,
  );
  const verified = openUserRefreshToken(next, kek, userId, { allowV1: true });
  if (verified.version !== target || verified.plaintext !== opened.plaintext) {
    throw new Error("Rewrapped envelope failed its round-trip verification");
  }
  return next;
}
