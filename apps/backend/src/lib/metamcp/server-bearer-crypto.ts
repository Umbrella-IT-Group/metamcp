/**
 * At-rest encryption for `mcp_servers.bearer_token`.
 *
 * The bearer token is the credential the gateway presents when it connects to
 * an MCP server (auto-minted for UI-created endpoints, operator-supplied for
 * manual ones). Unlike the OAuth tokens and API keys, this value must stay
 * RECOVERABLE, `client.ts` reads it back to build the upstream Authorization
 * header, so hashing is out. It is instead ENCRYPTED at rest, reusing the
 * exact AES-256-GCM envelope and KEK the M365 delegated-token custody already
 * uses (`lib/m365/crypto.ts` + `M365_TOKEN_KEK`); no second crypto scheme and
 * no second key are introduced.
 *
 * WIRE SHAPE. The ciphertext is stored in the same text column, tagged with an
 * `enc:v1:` prefix so the shape is self-describing without a schema change:
 *
 *   enc:v1:<m365 envelope>   where the envelope is v1.<kekId>.<iv>.<tag>.<ct>
 *
 * The prefix is how the read path and the boot converge tell an encrypted row
 * from a legacy plaintext one. A plaintext gateway credential is always
 * base64url with an `mcp_`/`sk_mt_` shape, never `enc:v1:`, so the two never
 * collide.
 *
 * CONVERGE WINDOW, and why the read path has a flag. Legacy rows written before
 * this change hold plaintext. A boot-time converge encrypts them once (see
 * server-bearer-converge.ts). Until that converge completes, the read path
 * accepts an untagged (plaintext) value so nothing breaks mid-rollout; AFTER it
 * completes, an untagged value is treated as an error and is NOT used, a
 * credential that the converge should have encrypted but did not is a fault to
 * surface, not a plaintext to trust. The census found zero rows carrying a
 * bearer token, so in practice the converge has nothing to do, but the window
 * is handled correctly regardless.
 */
import { getTokenKek } from "@/lib/m365/config";
import { decryptRefreshToken, encryptRefreshToken } from "@/lib/m365/crypto";
import logger from "@/utils/logger";

/** Tag identifying a ciphertext row in the shared text column. */
export const BEARER_ENVELOPE_PREFIX = "enc:v1:";

// Set true once the boot converge has encrypted every legacy row. Module-level
// because the read path (client.ts, per connection) has to know whether an
// untagged value is a tolerated legacy row (pre-converge) or a fault
// (post-converge). Process-lifetime state, reset only by the test helper.
let convergeComplete = false;

export function markServerBearerConvergeComplete(): void {
  convergeComplete = true;
}

export function isServerBearerConvergeComplete(): boolean {
  return convergeComplete;
}

/** Test-only: reset the module converge flag between cases. */
export function __resetServerBearerConvergeForTests(): void {
  convergeComplete = false;
}

/** True when a stored value is already an `enc:v1:` ciphertext. */
export function isEncryptedBearerToken(stored: string): boolean {
  return stored.startsWith(BEARER_ENVELOPE_PREFIX);
}

/**
 * Encrypt a plaintext bearer token for storage. Throws (fail-closed) when no
 * KEK is configured: a gateway credential must never be written in the clear,
 * so a create/update that would embed one refuses rather than degrade. Callers
 * that only sometimes carry a bearer (server create/update) must call this only
 * for a non-empty value.
 */
export function encryptServerBearerToken(plaintext: string): string {
  const kek = getTokenKek();
  if (!kek) {
    throw new Error(
      "Cannot store an MCP server bearer token: M365_TOKEN_KEK is not configured, and a gateway credential must not be written in plaintext.",
    );
  }
  return (
    BEARER_ENVELOPE_PREFIX + encryptRefreshToken(plaintext, kek.kek, kek.kekId)
  );
}

/**
 * Resolve a stored bearer token to the plaintext the gateway presents upstream,
 * or null when there is nothing usable to present (fail-closed, so the connection
 * carries no Authorization header rather than a broken one). Never throws, so a
 * single bad row cannot crash the connection machinery; every fail-closed path
 * logs.
 */
export function resolveServerBearerToken(
  stored: string | null | undefined,
): string | null {
  if (!stored) {
    return null;
  }
  if (stored.startsWith(BEARER_ENVELOPE_PREFIX)) {
    const kek = getTokenKek();
    if (!kek) {
      logger.error(
        "MCP server bearer token is encrypted but M365_TOKEN_KEK is not configured; refusing to present a credential.",
      );
      return null;
    }
    try {
      return decryptRefreshToken(
        stored.slice(BEARER_ENVELOPE_PREFIX.length),
        kek.kek,
      );
    } catch (err) {
      logger.error("Failed to decrypt an MCP server bearer token:", err);
      return null;
    }
  }
  // Untagged (legacy plaintext). Tolerated only until the converge has run; a
  // value still untagged afterwards is a fault, not a credential to use.
  if (convergeComplete) {
    logger.error(
      "MCP server bearer token is not encrypted after the boot converge; refusing to use it.",
    );
    return null;
  }
  return stored;
}
