/**
 * Regression test for the BOOTSTRAP_RECREATE_USER + preserveApiKeysOnRecreate
 * path (PR #84 review round, HIGH): a scoped API key (migration 0023) must
 * survive a container recreate WITH its endpoint scope intact. The pre-fix
 * preserve projection selected only {name, key, is_active}, so every scoped
 * key silently came back as NULL/gateway-wide — a silent privilege
 * escalation. `buildPreservedApiKeyInsert` is the pure seam the recreate
 * path threads each preserved key through; this pins that endpoint_uuid is
 * carried, not dropped.
 */
import { describe, expect, it, vi } from "vitest";

// auth.ts throws without BETTER_AUTH_SECRET and connects to postgres; db is
// the live connection. Neither is exercised by the pure builder under test.
vi.mock("../auth", () => ({ auth: { handler: vi.fn() } }));
vi.mock("../db", () => ({ db: {} }));

import {
  buildPreservedApiKeyInsert,
  PreservedApiKey,
} from "./bootstrap.service";

describe("buildPreservedApiKeyInsert — endpoint scope survives user recreate", () => {
  it("carries a scoped key's endpoint_uuid through unchanged (the regression)", () => {
    const scoped: PreservedApiKey = {
      name: "tara-autotask",
      key: "sk_mt_scoped",
      is_active: true,
      endpoint_uuid: "endpoint-abc",
    };

    const row = buildPreservedApiKeyInsert(scoped, "user-1");

    expect(row).toEqual({
      name: "tara-autotask",
      key: "sk_mt_scoped",
      user_id: "user-1",
      is_active: true,
      endpoint_uuid: "endpoint-abc",
    });
    // The scope is NOT promoted to NULL.
    expect(row.endpoint_uuid).toBe("endpoint-abc");
  });

  it("preserves NULL (grandfathered/unscoped) scope as NULL — no accidental binding", () => {
    const unscoped: PreservedApiKey = {
      name: "legacy-global",
      key: "sk_mt_global",
      is_active: false,
      endpoint_uuid: null,
    };

    const row = buildPreservedApiKeyInsert(unscoped, "user-2");

    expect(row.endpoint_uuid).toBeNull();
    expect(row.is_active).toBe(false);
    expect(row.user_id).toBe("user-2");
  });
});
