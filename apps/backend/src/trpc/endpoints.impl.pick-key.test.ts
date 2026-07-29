/**
 * Unit test for the auto-mint key-reuse fix (PR #84 review round, MEDIUM):
 * the createMcpServer convenience reuses an existing active key as the new
 * MCP server's bearer token. Since migration 0023 a key scoped to a
 * DIFFERENT endpoint would 403 on first use, so the picker must only reuse a
 * key that actually authenticates on THIS endpoint (scoped to it, or
 * unscoped), preferring the exact-scope match — otherwise the caller mints a
 * fresh scoped key.
 */
import { describe, expect, it, vi } from "vitest";

vi.mock("@/utils/logger", () => ({
  default: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

// endpoints.impl constructs `new ApiKeysRepository()` and imports the repo
// barrel (reaches db/index) + serializers at module load; mock them so the
// pure picker can be imported without a live DB.
vi.mock("../db/repositories", () => ({
  ApiKeysRepository: class {},
  endpointsRepository: {},
  mcpServersRepository: {},
  namespacesRepository: {},
}));
vi.mock("../db/serializers", () => ({ EndpointsSerializer: class {} }));

import { pickReusableApiKey } from "./endpoints.impl";

type Key = { key: string; is_active: boolean; endpoint_uuid: string | null };

describe("pickReusableApiKey — safe bearer-token reuse for the new endpoint", () => {
  const EP = "endpoint-target";

  it("prefers an active key already scoped to THIS endpoint", () => {
    const keys: Key[] = [
      { key: "unscoped", is_active: true, endpoint_uuid: null },
      { key: "exact", is_active: true, endpoint_uuid: EP },
    ];
    expect(pickReusableApiKey(keys, EP)?.key).toBe("exact");
  });

  it("falls back to an active unscoped (gateway-wide) key when no exact scope exists", () => {
    const keys: Key[] = [
      { key: "other-ep", is_active: true, endpoint_uuid: "endpoint-other" },
      { key: "unscoped", is_active: true, endpoint_uuid: null },
    ];
    expect(pickReusableApiKey(keys, EP)?.key).toBe("unscoped");
  });

  it("NEVER reuses a key scoped to a different endpoint (the bug: it 403s on first use)", () => {
    const keys: Key[] = [
      { key: "other-ep", is_active: true, endpoint_uuid: "endpoint-other" },
    ];
    expect(pickReusableApiKey(keys, EP)).toBeUndefined();
  });

  it("ignores inactive keys even when scoped to this endpoint", () => {
    const keys: Key[] = [
      { key: "inactive-exact", is_active: false, endpoint_uuid: EP },
      { key: "inactive-unscoped", is_active: false, endpoint_uuid: null },
    ];
    expect(pickReusableApiKey(keys, EP)).toBeUndefined();
  });

  it("returns undefined for an empty key set (caller then mints a scoped key)", () => {
    expect(pickReusableApiKey([], EP)).toBeUndefined();
  });
});
