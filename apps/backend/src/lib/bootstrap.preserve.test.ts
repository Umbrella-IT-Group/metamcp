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
 *
 * Round-2 additions (PR #85 review): the acts-as identity binding
 * (migration 0024) survives the recreate by the SAME pattern — the user id
 * minted by the recreate's sign-up is fresh, so the binding re-resolves by
 * EMAIL; an unresolvable acted-as identity SKIPS the key loudly (never
 * restored unbound — silent degradation — and never bound to a guess).
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
      acts_as_user_id: null,
      acts_as_email: null,
    };

    const { restores, skipped } = planPreservedApiKeyRestores(
      [scoped],
      "user-1",
      new Map([["autotask", "fresh-uuid-after-recreate"]]),
      new Map(),
    );

    expect(skipped).toEqual([]);
    expect(restores).toEqual([
      {
        name: "tara-autotask",
        key: "sk_mt_scoped",
        user_id: "user-1",
        is_active: true,
        endpoint_uuid: "fresh-uuid-after-recreate",
        acts_as_user_id: null,
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
      acts_as_user_id: null,
      acts_as_email: null,
    };

    const { restores, skipped } = planPreservedApiKeyRestores(
      [orphaned],
      "user-1",
      new Map([["some-other-endpoint", "uuid-x"]]),
      new Map(),
    );

    // Not restored at all — and specifically not restored with NULL scope.
    expect(restores).toEqual([]);
    expect(skipped).toEqual([
      {
        keyName: "key-to-deleted-endpoint",
        reason: "endpoint_missing",
        endpointName: "endpoint-not-in-bootstrap-config",
        endpointUuid: "old-uuid",
        actsAsEmail: null,
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
      acts_as_user_id: null,
      acts_as_email: null,
    };

    const { restores, skipped } = planPreservedApiKeyRestores(
      [nameless],
      "user-1",
      new Map([["anything", "uuid-y"]]),
      new Map(),
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
      acts_as_user_id: null,
      acts_as_email: null,
    };

    const { restores, skipped } = planPreservedApiKeyRestores(
      [unscoped],
      "user-2",
      new Map(),
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
        acts_as_user_id: null,
        acts_as_email: null,
      },
      {
        name: "endpoint-gone",
        key: "k2",
        is_active: true,
        endpoint_uuid: "old-b",
        endpoint_name: "ep-b",
        acts_as_user_id: null,
        acts_as_email: null,
      },
      {
        name: "gateway-wide",
        key: "k3",
        is_active: true,
        endpoint_uuid: null,
        endpoint_name: null,
        acts_as_user_id: null,
        acts_as_email: null,
      },
    ];

    const { restores, skipped } = planPreservedApiKeyRestores(
      keys,
      "user-1",
      new Map([["ep-a", "new-a"]]),
      new Map(),
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

describe("planPreservedApiKeyRestores — acts-as identity binding survives user recreate (migration 0024)", () => {
  it("re-binds an identity-bound key to the acted-as user's CURRENT id by EMAIL (id changed across recreate)", () => {
    const bound: PreservedApiKey = {
      name: "alex-m365",
      key: "sk_mt_bound",
      is_active: true,
      endpoint_uuid: "old-ep-uuid",
      endpoint_name: "m365",
      // The user id captured BEFORE the recreate — better-auth sign-up
      // mints a FRESH id, so this one is stale by restore time.
      acts_as_user_id: "old-alex-id",
      acts_as_email: "alex@example.com",
    };

    const { restores, skipped } = planPreservedApiKeyRestores(
      [bound],
      "new-alex-id",
      new Map([["m365", "fresh-ep-uuid"]]),
      new Map([["alex@example.com", "new-alex-id"]]),
    );

    expect(skipped).toEqual([]);
    expect(restores).toEqual([
      {
        name: "alex-m365",
        key: "sk_mt_bound",
        user_id: "new-alex-id",
        is_active: true,
        endpoint_uuid: "fresh-ep-uuid",
        acts_as_user_id: "new-alex-id",
      },
    ]);
    // The stale id is NEVER inserted, and the binding is NOT dropped.
    expect(restores[0].acts_as_user_id).not.toBe("old-alex-id");
    expect(restores[0].acts_as_user_id).not.toBeNull();
  });

  it("SKIPS a bound key whose acted-as email resolves to no current user — never restored unbound", () => {
    const orphanedIdentity: PreservedApiKey = {
      name: "bound-to-departed-user",
      key: "sk_mt_departed",
      is_active: true,
      endpoint_uuid: "old-ep-uuid",
      endpoint_name: "m365",
      acts_as_user_id: "old-user-id",
      acts_as_email: "departed@example.com",
    };

    const { restores, skipped } = planPreservedApiKeyRestores(
      [orphanedIdentity],
      "new-owner-id",
      new Map([["m365", "fresh-ep-uuid"]]),
      new Map([["someone-else@example.com", "someone-else-id"]]),
    );

    // Not restored at all — specifically NOT restored with a NULL binding
    // (the key would authenticate while m365 injection silently
    // fail-closes — the silent-degradation class this round targets).
    expect(restores).toEqual([]);
    expect(skipped).toEqual([
      {
        keyName: "bound-to-departed-user",
        reason: "acts_as_unresolvable",
        endpointName: "m365",
        endpointUuid: "old-ep-uuid",
        actsAsEmail: "departed@example.com",
      },
    ]);
  });

  it("SKIPS a bound key whose acted-as email could not be captured (defensive: join miss)", () => {
    const emaillessBinding: PreservedApiKey = {
      name: "bound-but-emailless",
      key: "sk_mt_emailless",
      is_active: true,
      endpoint_uuid: "old-ep-uuid",
      endpoint_name: "m365",
      acts_as_user_id: "some-user-id",
      acts_as_email: null,
    };

    const { restores, skipped } = planPreservedApiKeyRestores(
      [emaillessBinding],
      "new-owner-id",
      new Map([["m365", "fresh-ep-uuid"]]),
      new Map([["alex@example.com", "new-alex-id"]]),
    );

    expect(restores).toEqual([]);
    expect(skipped).toHaveLength(1);
    expect(skipped[0].reason).toBe("acts_as_unresolvable");
    expect(skipped[0].keyName).toBe("bound-but-emailless");
  });

  it("an unbound key restores with a NULL binding — no accidental identity", () => {
    const unbound: PreservedApiKey = {
      name: "plain-scoped",
      key: "sk_mt_plain",
      is_active: true,
      endpoint_uuid: "old-ep-uuid",
      endpoint_name: "m365",
      acts_as_user_id: null,
      acts_as_email: null,
    };

    const { restores, skipped } = planPreservedApiKeyRestores(
      [unbound],
      "user-1",
      new Map([["m365", "fresh-ep-uuid"]]),
      // Even with a resolvable email present in the map, an unbound key
      // must stay unbound.
      new Map([["alex@example.com", "new-alex-id"]]),
    );

    expect(skipped).toEqual([]);
    expect(restores).toHaveLength(1);
    expect(restores[0].acts_as_user_id).toBeNull();
  });
});
