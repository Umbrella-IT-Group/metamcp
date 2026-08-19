import { createHash } from "crypto";

/**
 * The ONE at-rest encoding for an API key. `api_keys` stores this hash plus
 * the key's last 4 characters; the plaintext is returned exactly once, at
 * mint time, and is never written anywhere.
 *
 * Every writer of `api_keys.key_hash` and the single authentication lookup
 * (`ApiKeysRepository.validateApiKey`) must go through this function —
 * two encodings mean a key minted by one path can never authenticate
 * through the other, and the failure is a silent 401 rather than an error.
 *
 * The encoding is byte-identical to `credentialFingerprint()` in
 * lib/audit/audit-emitter.ts (utf8 input, unsalted sha256, lowercase hex),
 * and that is a deliberate property rather than a coincidence: the audit log
 * records the fingerprint of every credential presented on a DENIED request,
 * so a stored `key_hash` joins directly against `detail.credential.sha256`.
 * An operator can answer "which key was this rejected request presenting"
 * without either table holding the secret. Changing the encoding here
 * silently breaks that join — change both, or neither. Unsalted is what
 * makes the join possible at all; it is acceptable here because the input is
 * a 256-bit-plus random token, not a human-chosen password, so there is no
 * dictionary to precompute against.
 */
export function hashApiKey(key: string): string {
  return createHash("sha256").update(key).digest("hex");
}

/**
 * The display tail stored alongside the hash. Four characters of a
 * high-entropy token let a human match a row against a key they already
 * hold, and are useless to anyone who does not.
 */
export function apiKeyLast4(key: string): string {
  return key.slice(-4);
}
