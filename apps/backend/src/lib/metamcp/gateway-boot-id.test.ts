/**
 * Sanity tests for the per-process gateway boot id (PR #22). The boot
 * id is generated at module load and used by the lazy-recovery path
 * (`routers/public-metamcp/streamable-http.ts`) to refuse recovering
 * sessions that crossed a metamcp restart — see the comment block in
 * `gateway-boot-id.ts` for the why.
 */

import { describe, expect, it } from "vitest";

import {
  GATEWAY_BOOT_ID,
  shouldRefuseRecoveryForBootIdMismatch,
} from "./gateway-boot-id";

const UUID_V4_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

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

describe("shouldRefuseRecoveryForBootIdMismatch", () => {
  const A = "aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa";
  const B = "bbbbbbbb-bbbb-4bbb-bbbb-bbbbbbbbbbbb";

  it("returns true when stored boot id differs from current (cross-restart row)", () => {
    // Production scenario this guards: PR #19 ships, gateway restarts,
    // pre-restart `mcp_sessions` rows still stamped with the old boot
    // id. Recovery must be refused so the client sees a 404 +
    // `Mcp-Session-Reinitialize-Required` and re-negotiates capabilities.
    expect(shouldRefuseRecoveryForBootIdMismatch(A, B)).toBe(true);
  });

  it("returns false when stored boot id matches current (same-process row)", () => {
    // Same-process row: capabilities are baked into `new Server({...})`
    // and cannot have drifted within a single process lifetime. Safe to
    // recover — this is the entire reason PR #15's recovery path exists.
    expect(shouldRefuseRecoveryForBootIdMismatch(A, A)).toBe(false);
  });

  it("returns false when stored boot id is null (pre-PR-22 row)", () => {
    // Backwards-compat: rows persisted by metamcp versions prior to
    // PR #22 have a null `gateway_boot_id`. There's no metadata to
    // compare — treat as "allow" so we don't reject every legacy row
    // on the deploy-day transition. The pruner reaps these within
    // `MCP_SESSION_TTL_DAYS` (default 7), so the null branch is finite
    // and self-clearing.
    expect(shouldRefuseRecoveryForBootIdMismatch(null, A)).toBe(false);
  });
});
