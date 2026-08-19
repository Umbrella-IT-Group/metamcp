/**
 * The at-rest encoding for API keys (migration 0034), pinned.
 *
 * Two properties are load-bearing and neither is visible from a type:
 *
 * 1. `hashApiKey` must be byte-identical to the audit log's
 *    `credentialFingerprint`, because the audit row for a DENIED request
 *    stores the fingerprint of the credential that was presented. Identical
 *    encoding means a stored `key_hash` joins straight against
 *    `detail.credential.sha256` — an operator can answer "which key was that
 *    rejected request presenting" without either table holding the secret.
 *    A salt, a different digest, or uppercase hex breaks the join silently:
 *    nothing errors, the answers just stop matching. `credentialFingerprint`
 *    now DELEGATES here rather than repeating the digest, so this case is no
 *    longer guarding two implementations against drift — it guards that the
 *    delegation stays wired, which is the thing a future edit could undo.
 *
 * 2. The hash must be computed over the input EXACTLY as given. The
 *    middleware passes the API-key header raw and the OAuth introspection
 *    route trims it; that asymmetry decides which whitespace-padded
 *    credentials authenticate, and normalising it here would change the
 *    answer for both callers at once.
 */
import { describe, expect, it } from "vitest";

import { apiKeyLast4, hashApiKey } from "./api-key-hash";
import { credentialFingerprint } from "./audit/audit-emitter";

const KEY = `sk_mt_${"a1B2".repeat(16)}`;

describe("hashApiKey", () => {
  it("matches credentialFingerprint's sha256 byte for byte", () => {
    // The join property: same input, same digest, no salt, both directions.
    expect(hashApiKey(KEY)).toBe(credentialFingerprint(KEY).sha256);
  });

  it("emits lowercase hex of the expected sha256 length", () => {
    expect(hashApiKey(KEY)).toMatch(/^[0-9a-f]{64}$/);
  });

  it("is a known-answer match for the digest of a fixed string", () => {
    // Pinned against an independently computable value rather than against
    // the implementation, so a change of digest or encoding cannot pass by
    // agreeing with itself. This is sha256("sk_mt_test").
    expect(hashApiKey("sk_mt_test")).toBe(
      "b6462456324716b3994715c20f320e386ea730e13bb0f740f42605bdcc3c4d6f",
    );
  });

  it("never returns the input, and differs for inputs differing by one character", () => {
    expect(hashApiKey(KEY)).not.toContain(KEY);
    expect(hashApiKey(`${KEY}x`)).not.toBe(hashApiKey(KEY));
  });

  it("does NOT normalise whitespace or case — the caller owns that decision", () => {
    expect(hashApiKey(` ${KEY} `)).not.toBe(hashApiKey(KEY));
    expect(hashApiKey(KEY.toUpperCase())).not.toBe(hashApiKey(KEY));
  });
});

describe("apiKeyLast4", () => {
  it("returns the final four characters, matching credentialFingerprint", () => {
    expect(apiKeyLast4(KEY)).toBe("a1B2");
    expect(apiKeyLast4(KEY)).toBe(credentialFingerprint(KEY).last4);
  });
});
