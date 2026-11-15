import { afterEach, describe, expect, it } from "vitest";

import {
  ApiKeyLifecycleRefusal,
  apiKeyRemovalFingerprint,
  apiKeySnapshot,
  assertLifecycleTarget,
  assertReactivationPolicy,
  assertRemovalConfirmed,
  assertRenameName,
  KEY_LIFECYCLE_REFUSALS,
  type LifecycleKeyRow,
  removalBlocker,
} from "./api-key-lifecycle-rules";

const base: LifecycleKeyRow = {
  uuid: "6f1d2c3b-4a5e-4f60-8a7b-9c0d1e2f3a4b",
  name: "poller",
  last4: "wxyz",
  is_active: false,
  admin_plane: false,
  user_id: "user-1",
  endpoint_uuid: "11111111-1111-4111-8111-111111111111",
  acts_as_user_id: null,
  allowed_cidrs: ["203.0.113.0/24"],
  ip_policy_mode: "enforce",
  created_at: new Date("2026-11-01T10:00:00.123Z"),
  last_used_at: null,
};

function ruleOf(fn: () => void): string | null {
  try {
    fn();
    return null;
  } catch (error) {
    if (error instanceof ApiKeyLifecycleRefusal) return error.rule;
    throw error;
  }
}

describe("the refusal table", () => {
  it("gives every rule a code and one fixed sentence that names no value", () => {
    for (const [rule, refusal] of Object.entries(KEY_LIFECYCLE_REFUSALS)) {
      expect(["FORBIDDEN", "BAD_REQUEST", "CONFLICT"]).toContain(refusal.code);
      expect(refusal.message.length).toBeGreaterThan(20);
      expect(refusal.message).not.toContain(base.uuid);
      expect(rule).toMatch(/^[a-z_]+$/);
    }
  });

  it("carries the rule's code on the thrown refusal", () => {
    const refusal = new ApiKeyLifecycleRefusal("key_active");
    expect(refusal.code).toBe("CONFLICT");
    expect(refusal.message).toBe(KEY_LIFECYCLE_REFUSALS.key_active.message);
  });
});

describe("assertLifecycleTarget", () => {
  it("refuses an admin-plane key for every operation", () => {
    for (const op of ["reactivate", "rename", "remove"] as const) {
      expect(
        ruleOf(() => assertLifecycleTarget({ ...base, admin_plane: true }, op)),
      ).toBe("target_admin_plane");
    }
  });

  it("refuses a key that acts as a user for reactivation only", () => {
    const actsAs = { ...base, acts_as_user_id: "user-1" };
    expect(ruleOf(() => assertLifecycleTarget(actsAs, "reactivate"))).toBe(
      "target_acts_as",
    );
    expect(ruleOf(() => assertLifecycleTarget(actsAs, "rename"))).toBeNull();
    expect(ruleOf(() => assertLifecycleTarget(actsAs, "remove"))).toBeNull();
  });
});

describe("assertReactivationPolicy", () => {
  afterEach(() => {
    delete process.env.API_KEY_IP_POLICY_DISABLED;
  });

  it("accepts the key's own narrow enforce list", () => {
    expect(ruleOf(() => assertReactivationPolicy(base))).toBeNull();
    expect(
      ruleOf(() =>
        assertReactivationPolicy({
          ...base,
          allowed_cidrs: ["2001:db8:1::/48", "198.51.100.7/32"],
        }),
      ),
    ).toBeNull();
  });

  it.each([
    ["the global policy", { allowed_cidrs: null, ip_policy_mode: "off" }],
    ["audit mode", { ip_policy_mode: "audit" }],
    ["off mode", { ip_policy_mode: "off" }],
    ["an empty list", { allowed_cidrs: [] }],
    ["a /16", { allowed_cidrs: ["10.0.0.0/16"] }],
    ["an IPv6 /32", { allowed_cidrs: ["2001:db8::/32"] }],
    ["the any-IP exemption", { allowed_cidrs: ["0.0.0.0/0", "::/0"] }],
    [
      "nine entries",
      {
        allowed_cidrs: Array.from({ length: 9 }, (_v, i) => `198.51.${i}.0/24`),
      },
    ],
  ])("refuses %s", (_label, over) => {
    expect(ruleOf(() => assertReactivationPolicy({ ...base, ...over }))).toBe(
      "ip_policy_not_narrow",
    );
  });

  it("refuses while the IP-policy kill switch is on, whatever the policy", () => {
    process.env.API_KEY_IP_POLICY_DISABLED = "true";
    expect(ruleOf(() => assertReactivationPolicy(base))).toBe(
      "ip_policy_disabled",
    );
  });
});

describe("assertRenameName", () => {
  it("accepts the mint's name shape", () => {
    expect(ruleOf(() => assertRenameName("n8n poller_2-b"))).toBeNull();
  });

  it.each(["", "x".repeat(101), "semi;colon", "slash/name", "dot.name"])(
    "refuses %j",
    (name) => {
      expect(ruleOf(() => assertRenameName(name))).toBe("name_invalid");
    },
  );
});

describe("removal", () => {
  it("is blocked for an admin-plane key and for an active key, admin-plane first", () => {
    expect(removalBlocker(base)).toBeNull();
    expect(removalBlocker({ ...base, is_active: true })).toBe("key_active");
    expect(removalBlocker({ ...base, admin_plane: true })).toBe(
      "target_admin_plane",
    );
    expect(
      removalBlocker({ ...base, admin_plane: true, is_active: true }),
    ).toBe("target_admin_plane");
  });

  it("needs the current name and the current fingerprint", () => {
    const fingerprint = apiKeyRemovalFingerprint(base);
    expect(
      ruleOf(() => assertRemovalConfirmed(base, base.name, fingerprint)),
    ).toBeNull();
    expect(
      ruleOf(() => assertRemovalConfirmed(base, "Poller", fingerprint)),
    ).toBe("confirm_name_mismatch");
    expect(
      ruleOf(() =>
        assertRemovalConfirmed(base, base.name, `sha256:${"0".repeat(64)}`),
      ),
    ).toBe("impact_changed");
  });
});

describe("apiKeyRemovalFingerprint", () => {
  it("is a sha256 that is stable for the same row", () => {
    const value = apiKeyRemovalFingerprint(base);
    expect(value).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(apiKeyRemovalFingerprint({ ...base })).toBe(value);
  });

  it.each([
    ["uuid", { uuid: "7f1d2c3b-4a5e-4f60-8a7b-9c0d1e2f3a4b" }],
    ["name", { name: "poller2" }],
    ["active flag", { is_active: true }],
    ["plane", { admin_plane: true }],
    ["owner", { user_id: "user-2" }],
    ["endpoint", { endpoint_uuid: null }],
    ["acts-as", { acts_as_user_id: "user-1" }],
    ["list", { allowed_cidrs: ["203.0.113.0/25"] }],
    ["mode", { ip_policy_mode: "audit" }],
    ["created", { created_at: new Date("2026-11-01T10:00:00.124Z") }],
    ["last used", { last_used_at: new Date("2026-11-02T10:00:00Z") }],
  ])("changes when the %s changes", (_label, over) => {
    expect(apiKeyRemovalFingerprint({ ...base, ...over })).not.toBe(
      apiKeyRemovalFingerprint(base),
    );
  });
});

describe("apiKeySnapshot", () => {
  it("keeps identifying metadata and drops anything else on the row", () => {
    const snapshot = apiKeySnapshot({
      ...base,
      // A caller that passes a wider row must not get it into the snapshot.
      ...({ key_hash: "deadbeef", key: "sk_mt_secret" } as object),
    } as LifecycleKeyRow);
    expect(snapshot).toEqual({
      name: "poller",
      key_prefix: "sk_mt_…wxyz",
      owner_user_id: "user-1",
      endpoint_uuid: base.endpoint_uuid,
      acts_as_user_id: null,
      is_active: false,
      admin_plane: false,
      allowed_cidrs: ["203.0.113.0/24"],
      ip_policy_mode: "enforce",
      created_at: "2026-11-01T10:00:00.123Z",
      last_used_at: null,
    });
    expect(JSON.stringify(snapshot)).not.toContain("deadbeef");
    expect(JSON.stringify(snapshot)).not.toContain("sk_mt_secret");
  });
});
