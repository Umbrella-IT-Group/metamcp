/**
 * Regression tests for the BOOTSTRAP_RECREATE_USER + preserveApiKeysOnRecreate
 * path (PR #84 review rounds 1-2, HIGH → BLOCKER): a scoped API key
 * (migration 0023) must survive a container recreate WITH its endpoint scope
 * intact — and "survive" is subtle, because deleting the user CASCADES away
 * every user-owned endpoint and `bootstrapEndpoints` recreates them with
 * FRESH uuids:
 *
 * - Round 1's bug: the preserve projection dropped `endpoint_uuid`, so a
 *   scoped key silently came back gateway-wide (privilege escalation).
 * - Round 2's bug: restoring the PRESERVED uuid is FK-invalid once the
 *   endpoint has been recreated under a new uuid — the insert failed, the
 *   catch swallowed it, and the log claimed success (silent credential LOSS
 *   reported as restored).
 *
 * `planPreservedApiKeyRestores` is the pure seam the deferred restore pass
 * threads each preserved key through; these tests pin that scope survives
 * via NAME re-resolution, that an endpoint-gone key is skipped (never
 * NULL-promoted), and that the restored/skipped counts are correct.
 */
import { describe, expect, it, vi } from "vitest";

// auth.ts throws without BETTER_AUTH_SECRET and connects to postgres; db is
// the live connection. Neither is exercised by the pure planner under test.
vi.mock("../auth", () => ({ auth: { handler: vi.fn() } }));
vi.mock("../db", () => ({ db: {} }));

import {
  planPreservedApiKeyRestores,
  PreservedApiKey,
} from "./bootstrap.service";

describe("planPreservedApiKeyRestores — endpoint scope survives user recreate", () => {
  it("re-resolves a scoped key to the endpoint's CURRENT uuid by name (uuid changed across recreate)", () => {
    const scoped: PreservedApiKey = {
      name: "tara-autotask",
      key: "sk_mt_scoped",
      is_active: true,
      // The uuid captured BEFORE the recreate — stale by restore time.
      endpoint_uuid: "old-uuid-cascaded-away",
      endpoint_name: "autotask",
    };

    const { restores, skipped } = planPreservedApiKeyRestores(
      [scoped],
      "user-1",
      new Map([["autotask", "fresh-uuid-after-recreate"]]),
    );

    expect(skipped).toEqual([]);
    expect(restores).toEqual([
      {
        name: "tara-autotask",
        key: "sk_mt_scoped",
        user_id: "user-1",
        is_active: true,
        endpoint_uuid: "fresh-uuid-after-recreate",
      },
    ]);
    // The stale uuid is NEVER inserted (it would violate the FK), and the
    // scope is NOT promoted to NULL.
    expect(restores[0].endpoint_uuid).not.toBe("old-uuid-cascaded-away");
    expect(restores[0].endpoint_uuid).not.toBeNull();
  });

  it("SKIPS a scoped key whose endpoint no longer exists — never widens it to gateway-wide", () => {
    const orphaned: PreservedApiKey = {
      name: "key-to-deleted-endpoint",
      key: "sk_mt_orphan",
      is_active: true,
      endpoint_uuid: "old-uuid",
      endpoint_name: "endpoint-not-in-bootstrap-config",
    };

    const { restores, skipped } = planPreservedApiKeyRestores(
      [orphaned],
      "user-1",
      new Map([["some-other-endpoint", "uuid-x"]]),
    );

    // Not restored at all — and specifically not restored with NULL scope.
    expect(restores).toEqual([]);
    expect(skipped).toEqual([
      {
        keyName: "key-to-deleted-endpoint",
        endpointName: "endpoint-not-in-bootstrap-config",
        endpointUuid: "old-uuid",
      },
    ]);
  });

  it("SKIPS a scoped key whose endpoint name could not be captured (defensive: join miss)", () => {
    const nameless: PreservedApiKey = {
      name: "scoped-but-nameless",
      key: "sk_mt_nameless",
      is_active: true,
      endpoint_uuid: "some-uuid",
      endpoint_name: null,
    };

    const { restores, skipped } = planPreservedApiKeyRestores(
      [nameless],
      "user-1",
      new Map([["anything", "uuid-y"]]),
    );

    expect(restores).toEqual([]);
    expect(skipped).toHaveLength(1);
    expect(skipped[0].keyName).toBe("scoped-but-nameless");
  });

  it("preserves NULL (grandfathered/unscoped) scope as NULL — no accidental binding, no skip", () => {
    const unscoped: PreservedApiKey = {
      name: "legacy-global",
      key: "sk_mt_global",
      is_active: false,
      endpoint_uuid: null,
      endpoint_name: null,
    };

    const { restores, skipped } = planPreservedApiKeyRestores(
      [unscoped],
      "user-2",
      new Map(),
    );

    expect(skipped).toEqual([]);
    expect(restores).toHaveLength(1);
    expect(restores[0].endpoint_uuid).toBeNull();
    expect(restores[0].is_active).toBe(false);
    expect(restores[0].user_id).toBe("user-2");
  });

  it("counts are correct on a mixed batch (restored vs skipped is loud, not a blanket success)", () => {
    const keys: PreservedApiKey[] = [
      {
        name: "survives-rename",
        key: "k1",
        is_active: true,
        endpoint_uuid: "old-a",
        endpoint_name: "ep-a",
      },
      {
        name: "endpoint-gone",
        key: "k2",
        is_active: true,
        endpoint_uuid: "old-b",
        endpoint_name: "ep-b",
      },
      {
        name: "gateway-wide",
        key: "k3",
        is_active: true,
        endpoint_uuid: null,
        endpoint_name: null,
      },
    ];

    const { restores, skipped } = planPreservedApiKeyRestores(
      keys,
      "user-1",
      new Map([["ep-a", "new-a"]]),
    );

    expect(restores).toHaveLength(2);
    expect(skipped).toHaveLength(1);
    expect(restores.map((r) => r.name).sort()).toEqual([
      "gateway-wide",
      "survives-rename",
    ]);
    expect(skipped[0].keyName).toBe("endpoint-gone");
    // Every preserved key is accounted for exactly once.
    expect(restores.length + skipped.length).toBe(keys.length);
  });
});
