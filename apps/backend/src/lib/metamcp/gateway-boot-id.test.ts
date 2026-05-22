/**
 * Sanity tests for the per-process gateway boot id + capability hash
 * (PR #22 + PR #23). Both constants are generated/computed at module
 * load and used by the lazy-recovery path
 * (`routers/public-metamcp/streamable-http.ts`) to refuse recovering
 * sessions whose stored capability set diverges from what the current
 * process advertises — see the comment block in `gateway-boot-id.ts`
 * for the why.
 */

import { createHash } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  GATEWAY_BOOT_ID,
  GATEWAY_CAPABILITY_HASH,
  shouldRefuseRecovery,
  shouldRefuseRecoveryForBootIdMismatch,
  shouldRefuseRecoveryForCapabilityMismatch,
} from "./gateway-boot-id";
import { GATEWAY_CAPABILITIES } from "./gateway-capabilities";

const UUID_V4_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SHA256_HEX_RE = /^[0-9a-f]{64}$/i;

describe("GATEWAY_BOOT_ID", () => {
  it("is a valid UUID v4 string", () => {
    expect(typeof GATEWAY_BOOT_ID).toBe("string");
    expect(GATEWAY_BOOT_ID).toMatch(UUID_V4_RE);
  });

  it("is stable across multiple reads within the same process", () => {
    // Re-reading the export must return the same value — the constant
    // is captured at module load and never rotates. The lazy-recovery
    // path relies on this stability: every persist + every recovery
    // check observes the same id for the lifetime of the process.
    const first = GATEWAY_BOOT_ID;
    const second = GATEWAY_BOOT_ID;
    expect(second).toBe(first);
  });
});

describe("GATEWAY_CAPABILITY_HASH", () => {
  it("is a SHA-256 hex string (64 lowercase hex chars)", () => {
    expect(typeof GATEWAY_CAPABILITY_HASH).toBe("string");
    expect(GATEWAY_CAPABILITY_HASH).toMatch(SHA256_HEX_RE);
    expect(GATEWAY_CAPABILITY_HASH.length).toBe(64);
  });

  it("is stable across multiple reads within the same process", () => {
    // The hash is captured once at module load; rereading must return
    // the same digest. Lazy-recovery relies on this stability — every
    // persist + every recovery check observes the same hash for the
    // lifetime of the process.
    const first = GATEWAY_CAPABILITY_HASH;
    const second = GATEWAY_CAPABILITY_HASH;
    expect(second).toBe(first);
  });

  it("matches a fresh SHA-256 of the same capability object (determinism)", () => {
    // Sanity: the hash function is deterministic for the canonical
    // JSON of the shared capability object. If a future PR forks the
    // hash computation away from `JSON.stringify(GATEWAY_CAPABILITIES)`
    // this test surfaces the drift in CI rather than at runtime.
    const expected = createHash("sha256")
      .update(JSON.stringify(GATEWAY_CAPABILITIES))
      .digest("hex");
    expect(GATEWAY_CAPABILITY_HASH).toBe(expected);
  });

  it("differs when the input capability object differs (sanity)", () => {
    // A different capability set must hash to a different digest —
    // confirms the hash actually reflects the input, not a constant.
    const alternate = createHash("sha256")
      .update(JSON.stringify({ prompts: {}, resources: {} }))
      .digest("hex");
    expect(alternate).not.toBe(GATEWAY_CAPABILITY_HASH);
    expect(alternate).toMatch(SHA256_HEX_RE);
  });
});

describe("shouldRefuseRecoveryForBootIdMismatch", () => {
  const A = "aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa";
  const B = "bbbbbbbb-bbbb-4bbb-bbbb-bbbbbbbbbbbb";

  it("returns true when stored boot id differs from current (cross-restart row)", () => {
    expect(shouldRefuseRecoveryForBootIdMismatch(A, B)).toBe(true);
  });

  it("returns false when stored boot id matches current (same-process row)", () => {
    expect(shouldRefuseRecoveryForBootIdMismatch(A, A)).toBe(false);
  });

  it("returns false when stored boot id is null (pre-PR-22 row)", () => {
    expect(shouldRefuseRecoveryForBootIdMismatch(null, A)).toBe(false);
  });
});

describe("shouldRefuseRecoveryForCapabilityMismatch", () => {
  const HASH_A = "a".repeat(64);
  const HASH_B = "b".repeat(64);

  it("returns true when stored hash differs from current", () => {
    expect(shouldRefuseRecoveryForCapabilityMismatch(HASH_A, HASH_B)).toBe(
      true,
    );
  });

  it("returns false when stored hash matches current", () => {
    expect(shouldRefuseRecoveryForCapabilityMismatch(HASH_A, HASH_A)).toBe(
      false,
    );
  });

  it("returns false when stored hash is null (pre-PR-23 row)", () => {
    expect(shouldRefuseRecoveryForCapabilityMismatch(null, HASH_A)).toBe(false);
  });
});

describe("shouldRefuseRecovery (combined PR #23 predicate)", () => {
  const BOOT_A = "aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa";
  const BOOT_B = "bbbbbbbb-bbbb-4bbb-bbbb-bbbbbbbbbbbb";
  const HASH_A = "a".repeat(64);
  const HASH_B = "b".repeat(64);
  const current = { bootId: BOOT_A, capabilityHash: HASH_A };

  it("allows when boot_id matches (same process — capabilities cannot have changed)", () => {
    // Capability hash is irrelevant in this branch — within a single
    // process lifetime capabilities are baked into `new Server({...})`
    // and cannot drift. Even a hash mismatch here would indicate the
    // stored hash is wrong, not that capabilities changed.
    expect(
      shouldRefuseRecovery(
        { gateway_boot_id: BOOT_A, capability_hash: HASH_B },
        current,
      ),
    ).toBe(false);
  });

  it("allows when boot_id differs but capability_hash matches (same code, restart only)", () => {
    // This is the entire point of PR #23 — same-image redeploys with
    // matching capability hashes don't trigger a client re-initialize.
    expect(
      shouldRefuseRecovery(
        { gateway_boot_id: BOOT_B, capability_hash: HASH_A },
        current,
      ),
    ).toBe(false);
  });

  it("refuses when boot_id differs AND capability_hash differs (real capability change)", () => {
    // The scenario PR #22 was actually trying to catch — different
    // process built from different source. Client's cached capability
    // set is stale; fresh `initialize` required.
    expect(
      shouldRefuseRecovery(
        { gateway_boot_id: BOOT_B, capability_hash: HASH_B },
        current,
      ),
    ).toBe(true);
  });

  it("allows when both stored fields are null (pre-PR-22 row, backward-compat)", () => {
    // No metadata to compare. Pruner reaps these within
    // `MCP_SESSION_TTL_DAYS` (default 7) so the null branch is finite
    // and self-clearing. Without this branch we'd reject every legacy
    // row on the deploy-day transition.
    expect(
      shouldRefuseRecovery(
        { gateway_boot_id: null, capability_hash: null },
        current,
      ),
    ).toBe(false);
  });

  it("refuses when stored capability_hash is null but boot_id differs (PR #22-only row, conservative)", () => {
    // PR #22 row persisted before PR #23 landed. The boot_id mismatch
    // already triggered PR #22's refusal; missing capability_hash
    // can't downgrade that. Match PR #22's behavior — refuse.
    expect(
      shouldRefuseRecovery(
        { gateway_boot_id: BOOT_B, capability_hash: null },
        current,
      ),
    ).toBe(true);
  });

  it("allows when stored capability_hash is null but boot_id matches (PR #22 same-process row)", () => {
    // PR #22 row from the current process (boot_id stamped, hash not
    // yet). Boot_id match means capabilities can't have changed.
    expect(
      shouldRefuseRecovery(
        { gateway_boot_id: BOOT_A, capability_hash: null },
        current,
      ),
    ).toBe(false);
  });
});
