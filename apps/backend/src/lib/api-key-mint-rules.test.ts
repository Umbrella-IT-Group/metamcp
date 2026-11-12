/**
 * The rules for a data-plane key an admin-plane key creates
 * (lib/api-key-mint-rules.ts), tested without a database.
 *
 * What is pinned, and why it is a credential boundary: a key created through
 * this path must never be an admin-plane key, an acts-as key or a public key;
 * must always name one existing enabled owner and exactly one scope; must be
 * locked to a short network list that cannot reach more than an IPv4 /24 by any
 * spelling; and a refusal must say one fixed sentence that echoes nothing of
 * the request. The oracle for every expected value is the mint amendment's
 * rules 1 to 6 (private plan, admin-plane-mint, "What agents may mint") and its
 * foreman decision 1; the CIDR cases are checked against node:net BlockList,
 * the code that evaluates a stored list at request time.
 */

import { BlockList } from "node:net";

import { afterEach, describe, expect, it } from "vitest";

import { parseCidr } from "./api-key-ip-policy";
import { agentCidrTooWide, mappedIpv4Prefix } from "./api-key-ip-policy";
import {
  ApiKeyMintRefusal,
  assertEndpointEligible,
  assertGatewayWideOwnerAllowed,
  MINT_REFUSALS,
  type MintRule,
  validateAgentIpPolicy,
  validateAgentMintRequest,
} from "./api-key-mint-rules";

const ENDPOINT_UUID = "11111111-1111-4111-8111-111111111111";
const POLICY = { mode: "enforce", allowed_cidrs: ["203.0.113.0/24"] };

/** A request that satisfies every rule, for the cases to break one field of. */
const valid = (): Record<string, unknown> => ({
  name: "metrics poller",
  user_id: "owner-user-1",
  endpoint_uuid: ENDPOINT_UUID,
  ip_policy: { ...POLICY },
});

function refusalOf(input: Record<string, unknown>): MintRule | null {
  try {
    validateAgentMintRequest(input);
    return null;
  } catch (error) {
    if (error instanceof ApiKeyMintRefusal) return error.rule;
    throw error;
  }
}

const savedKillSwitch = process.env.API_KEY_IP_POLICY_DISABLED;
afterEach(() => {
  if (savedKillSwitch === undefined) {
    delete process.env.API_KEY_IP_POLICY_DISABLED;
  } else {
    process.env.API_KEY_IP_POLICY_DISABLED = savedKillSwitch;
  }
});

describe("a request that satisfies every rule", () => {
  it("is accepted for one endpoint, with the policy canonicalised", () => {
    expect(
      validateAgentMintRequest({
        ...valid(),
        ip_policy: {
          mode: "enforce",
          allowed_cidrs: ["203.0.113.7", "203.0.113.0/24", "203.0.113.7/32"],
        },
      }),
    ).toEqual({
      name: "metrics poller",
      ownerUserId: "owner-user-1",
      endpointUuid: ENDPOINT_UUID,
      allEndpoints: false,
      // A bare address is a /32, and a repeat after canonicalisation collapses.
      allowedCidrs: ["203.0.113.7/32", "203.0.113.0/24"],
    });
  });

  it("is accepted gateway-wide with all_endpoints: true", () => {
    const { endpoint_uuid: _omitted, ...rest } = valid();
    expect(
      validateAgentMintRequest({ ...rest, all_endpoints: true }),
    ).toMatchObject({ endpointUuid: null, allEndpoints: true });
  });

  it("accepts admin_plane: false, which is the data-plane value", () => {
    expect(refusalOf({ ...valid(), admin_plane: false })).toBeNull();
  });

  it("accepts a name the usual shape allows, spaces included", () => {
    expect(
      refusalOf({ ...valid(), name: "Vendor health_poller-2" }),
    ).toBeNull();
  });
});

describe("rule 1: never an admin-plane key of either scope", () => {
  it.each([
    ["admin_plane true", { admin_plane: true }],
    ["admin_plane the string true", { admin_plane: "true" }],
    ["admin_plane null", { admin_plane: null }],
    ["admin_plane a number", { admin_plane: 1 }],
    ["a sync scope", { admin_plane_scope: "sync" }],
    ["an operator scope", { admin_plane_scope: "operator" }],
    ["a null scope", { admin_plane_scope: null }],
    ["an empty scope", { admin_plane_scope: "" }],
    [
      "the flag and a scope",
      { admin_plane: true, admin_plane_scope: "operator" },
    ],
  ])("refuses %s", (_label, extra) => {
    expect(refusalOf({ ...valid(), ...extra })).toBe("admin_plane_field");
  });
});

describe("rule 2: never an acts-as identity", () => {
  it.each([
    ["an id", "owner-user-1"],
    ["another user's id", "someone-else"],
    ["an empty string", ""],
    ["null", null],
  ])("refuses %s", (_label, value) => {
    expect(refusalOf({ ...valid(), acts_as_user_id: value })).toBe(
      "acts_as_field",
    );
  });
});

describe("rule 3: one named owner, never the public key and never the caller by default", () => {
  it.each([
    ["omitted (which would default to the caller)", undefined],
    ["null (the public, everyone key)", null],
    ["an empty string", ""],
    ["whitespace only", "   "],
    ["a number", 7],
    ["an object", { id: "x" }],
  ])("refuses a user_id that is %s", (_label, value) => {
    expect(refusalOf({ ...valid(), user_id: value })).toBe("owner_required");
  });
});

describe("rule 4: exactly one scope, in its exact form", () => {
  it.each([
    ["neither", { endpoint_uuid: undefined }],
    ["both", { all_endpoints: true }],
    [
      "all_endpoints false and no endpoint",
      {
        endpoint_uuid: undefined,
        all_endpoints: false,
      },
    ],
    [
      "all_endpoints the string true",
      {
        endpoint_uuid: undefined,
        all_endpoints: "true",
      },
    ],
    ["all_endpoints null", { endpoint_uuid: undefined, all_endpoints: null }],
    ["an endpoint that is not a uuid", { endpoint_uuid: "gateway" }],
    ["an endpoint that is a number", { endpoint_uuid: 5 }],
    ["an endpoint that is null", { endpoint_uuid: null }],
    ["an endpoint and all_endpoints false", { all_endpoints: false }],
  ])("refuses %s", (_label, extra) => {
    expect(refusalOf({ ...valid(), ...extra })).toBe("scope_choice");
  });
});

describe("rule 6: a name of the usual shape", () => {
  it.each([
    ["omitted", undefined],
    ["empty", ""],
    ["101 characters", "a".repeat(101)],
    ["with a slash", "bad/name"],
    ["with a dot", "bad.name"],
    ["a number", 7],
  ])("refuses a name that is %s", (_label, value) => {
    expect(refusalOf({ ...valid(), name: value })).toBe("name_invalid");
  });

  it("accepts exactly 100 characters", () => {
    expect(refusalOf({ ...valid(), name: "a".repeat(100) })).toBeNull();
  });
});

describe("rule 5: the IP policy", () => {
  it.each([
    ["omitted", undefined],
    ["null", null],
    ["an array", []],
    ["mode follow-global (no mode)", { allowed_cidrs: ["203.0.113.0/24"] }],
    ["mode off", { mode: "off", allowed_cidrs: ["203.0.113.0/24"] }],
    ["mode audit", { mode: "audit", allowed_cidrs: ["203.0.113.0/24"] }],
    [
      "mode in capitals",
      { mode: "ENFORCE", allowed_cidrs: ["203.0.113.0/24"] },
    ],
    ["no list", { mode: "enforce" }],
    [
      "a list that is not an array",
      { mode: "enforce", allowed_cidrs: "203.0.113.0/24" },
    ],
    ["an empty list", { mode: "enforce", allowed_cidrs: [] }],
    [
      "nine entries",
      {
        mode: "enforce",
        allowed_cidrs: Array.from(
          { length: 9 },
          (_v, i) => `203.0.113.${i}/32`,
        ),
      },
    ],
    ["an entry that is not a string", { mode: "enforce", allowed_cidrs: [5] }],
  ])("refuses a policy that is %s", (_label, policy) => {
    expect(refusalOf({ ...valid(), ip_policy: policy })).toBe(
      "ip_policy_shape",
    );
  });

  it("accepts eight entries", () => {
    expect(
      refusalOf({
        ...valid(),
        ip_policy: {
          mode: "enforce",
          allowed_cidrs: Array.from(
            { length: 8 },
            (_v, i) => `203.0.113.${i}/32`,
          ),
        },
      }),
    ).toBeNull();
  });

  it("counts the submitted entries, so nine spellings of two networks are refused", () => {
    // Nine submitted entries is nine, whatever they collapse to.
    const submitted = [
      "203.0.113.1",
      "203.0.113.1/32",
      "203.0.113.1",
      "203.0.113.1/32",
      "203.0.113.1",
      "203.0.113.1/32",
      "203.0.113.2",
      "203.0.113.2/32",
      "203.0.113.2",
    ];
    expect(
      refusalOf({
        ...valid(),
        ip_policy: { mode: "enforce", allowed_cidrs: submitted },
      }),
    ).toBe("ip_policy_shape");
  });

  it.each([
    ["not an address", "not-a-cidr"],
    ["host bits set", "203.0.113.5/24"],
    ["an out-of-range prefix", "203.0.113.0/33"],
    ["a zone id", "fe80::1%eth0/128"],
    ["two slashes", "203.0.113.0/24/24"],
    ["an empty entry", " "],
  ])("refuses an entry that is %s", (_label, entry) => {
    expect(
      refusalOf({
        ...valid(),
        ip_policy: { mode: "enforce", allowed_cidrs: [entry] },
      }),
    ).toBe("ip_policy_entries");
  });

  it.each([
    ["IPv4 /23", "203.0.112.0/23"],
    ["IPv4 /0", "0.0.0.0/0"],
    ["IPv4 /8", "10.0.0.0/8"],
    ["IPv6 /47", "2001:db8::/47"],
    ["IPv6 /0", "::/0"],
    ["IPv6 /32", "2001:db8::/32"],
    // The mapped-width bypasses: each of these admits IPv4 space wider than a
    // /24 through the IPv4-mapped form, whatever its own prefix looks like.
    ["::/48, which contains the whole mapped range", "::/48"],
    ["::ffff:0:0/96, the whole mapped range", "::ffff:0:0/96"],
    ["a mapped /119, two IPv4 /24s", "::ffff:203.0.112.0/119"],
    ["a mapped /104, an IPv4 /8", "::ffff:10.0.0.0/104"],
    ["::/1", "::/1"],
  ])("refuses %s", (_label, entry) => {
    expect(
      refusalOf({
        ...valid(),
        ip_policy: { mode: "enforce", allowed_cidrs: [entry] },
      }),
    ).toBe("ip_policy_too_wide");
  });

  it("refuses the whole policy when one entry among several is too wide", () => {
    expect(
      refusalOf({
        ...valid(),
        ip_policy: {
          mode: "enforce",
          allowed_cidrs: ["203.0.113.0/24", "198.51.100.0/22"],
        },
      }),
    ).toBe("ip_policy_too_wide");
  });

  it.each([
    ["IPv4 /24", "203.0.113.0/24"],
    ["IPv4 /32", "203.0.113.7/32"],
    ["a bare IPv4 address", "203.0.113.7"],
    ["IPv6 /48", "2001:db8:1::/48"],
    ["IPv6 /128", "2001:db8::1/128"],
    ["IPv6 /64", "2001:db8:1:2::/64"],
    ["a mapped /120, the width of an IPv4 /24", "::ffff:203.0.113.0/120"],
    ["a mapped /128", "::ffff:203.0.113.5/128"],
    ["a native /96 outside the mapped range", "2001:db8::/96"],
  ])("accepts %s", (_label, entry) => {
    expect(
      refusalOf({
        ...valid(),
        ip_policy: { mode: "enforce", allowed_cidrs: [entry] },
      }),
    ).toBeNull();
  });

  it("refuses everything while the global kill switch is on, before any other check", () => {
    process.env.API_KEY_IP_POLICY_DISABLED = "true";

    // A fully valid request is refused...
    expect(refusalOf(valid())).toBe("ip_policy_disabled");
    // ...and so is one with a malformed policy, with the same sentence.
    expect(refusalOf({ ...valid(), ip_policy: undefined })).toBe(
      "ip_policy_disabled",
    );
    expect(() => validateAgentIpPolicy(POLICY)).toThrow(
      MINT_REFUSALS.ip_policy_disabled.message,
    );
  });

  it("reads the kill switch strictly: only the exact string true", () => {
    for (const value of ["1", "yes", "TRUE", "True", ""]) {
      process.env.API_KEY_IP_POLICY_DISABLED = value;
      expect(refusalOf(valid())).toBeNull();
    }
  });
});

describe("every refusal is one fixed sentence that echoes nothing of the request", () => {
  const SENTINEL = "zz-sentinel-9f3a";
  const cases: Array<[MintRule, Record<string, unknown>]> = [
    ["admin_plane_field", { ...valid(), admin_plane_scope: SENTINEL }],
    ["acts_as_field", { ...valid(), acts_as_user_id: SENTINEL }],
    ["owner_required", { ...valid(), user_id: 5 }],
    ["scope_choice", { ...valid(), endpoint_uuid: SENTINEL }],
    ["name_invalid", { ...valid(), name: `${SENTINEL}/` }],
    [
      "ip_policy_shape",
      { ...valid(), ip_policy: { mode: SENTINEL, allowed_cidrs: [SENTINEL] } },
    ],
    [
      "ip_policy_entries",
      { ...valid(), ip_policy: { mode: "enforce", allowed_cidrs: [SENTINEL] } },
    ],
    [
      "ip_policy_too_wide",
      {
        ...valid(),
        ip_policy: { mode: "enforce", allowed_cidrs: ["198.51.100.0/22"] },
      },
    ],
  ];

  it.each(cases)("%s", (rule, input) => {
    let caught: unknown;
    try {
      validateAgentMintRequest(input);
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(ApiKeyMintRefusal);
    const refusal = caught as ApiKeyMintRefusal;
    expect(refusal.rule).toBe(rule);
    expect(refusal.message).toBe(MINT_REFUSALS[rule].message);
    expect(refusal.code).toBe(MINT_REFUSALS[rule].code);
    // No request value, and no CIDR from the request, in the sentence.
    expect(refusal.message).not.toContain(SENTINEL);
    expect(refusal.message).not.toContain("198.51.100");
    expect(refusal.message).not.toContain("owner-user-1");
    expect(refusal.message).not.toContain(ENDPOINT_UUID);
  });

  it("gives every rule its own sentence", () => {
    const messages = Object.values(MINT_REFUSALS).map((r) => r.message);
    expect(new Set(messages).size).toBe(messages.length);
  });
});

describe("rule 4 against an endpoint row", () => {
  // Oracle: the settled mint contract (private plan, tool-collections-rollout,
  // "Foreman decisions after the Sol plan review", decision 1): an endpoint
  // scoped mint needs a public endpoint, and a restricted one only for an owner
  // who is an explicit member of a mapped group.
  it("allows a public, unrestricted endpoint with or without membership", () => {
    for (const member of [false, true]) {
      expect(() =>
        assertEndpointEligible({ user_id: null, restricted: false }, member),
      ).not.toThrow();
    }
  });

  it("allows a public restricted endpoint only for an explicit member of a mapped group", () => {
    expect(() =>
      assertEndpointEligible({ user_id: null, restricted: true }, true),
    ).not.toThrow();
    expect(() =>
      assertEndpointEligible({ user_id: null, restricted: true }, false),
    ).toThrow(MINT_REFUSALS.endpoint_not_eligible.message);
  });

  it.each([
    ["private", { user_id: "someone", restricted: false }],
    ["private and restricted", { user_id: "someone", restricted: true }],
  ])(
    "refuses a %s endpoint even for a member, with the one sentence",
    (_label, endpoint) => {
      expect(() => assertEndpointEligible(endpoint, true)).toThrow(
        MINT_REFUSALS.endpoint_not_eligible.message,
      );
    },
  );

  it("treats a restricted flag that is not exactly false as restricted", () => {
    expect(() =>
      assertEndpointEligible(
        {
          user_id: null,
          restricted: undefined as unknown as boolean,
        },
        false,
      ),
    ).toThrow(MINT_REFUSALS.endpoint_not_eligible.message);
  });
});

describe("rule 4 for a gateway-wide key against its owner's role", () => {
  it("refuses an administrator-role owner with its own sentence", () => {
    expect(() => assertGatewayWideOwnerAllowed({ role: "admin" })).toThrow(
      MINT_REFUSALS.gateway_wide_admin_owner.message,
    );
  });

  it.each(["member", "", null])(
    "allows an owner whose role is %j, because the request-time rule decides its reach",
    (role) => {
      expect(() => assertGatewayWideOwnerAllowed({ role })).not.toThrow();
    },
  );

  it("does not honour a near-miss spelling of the role as an administrator", () => {
    // The request-time gate compares to exactly "admin"; this must agree, so
    // that no role is refused here that the gate would not treat as admin.
    expect(() =>
      assertGatewayWideOwnerAllowed({ role: "Admin" }),
    ).not.toThrow();
  });
});

describe("the effective-width rule against node:net BlockList", () => {
  // Distinct /24s of IPv4 space, so "admits more than one /24" can be read off
  // which of these a list matches.
  const SAMPLES = [
    "203.0.113.5",
    "203.0.112.5",
    "203.0.114.5",
    "8.8.8.8",
    "0.0.0.1",
    "255.255.255.254",
    "10.20.30.40",
    "10.99.1.1",
  ];

  function ipv4Matches(entry: string): string[] {
    const parsed = parseCidr(entry);
    if (!parsed.ok) throw new Error(parsed.error);
    const list = new BlockList();
    list.addSubnet(
      parsed.value.address,
      parsed.value.prefix,
      parsed.value.family,
    );
    return SAMPLES.filter((address) => list.check(address, "ipv4"));
  }

  const REFUSED = [
    "::/48",
    "::ffff:0:0/96",
    "::ffff:203.0.112.0/119",
    "::ffff:10.0.0.0/104",
    "::/1",
    "0.0.0.0/0",
    "203.0.112.0/23",
  ];
  const ACCEPTED_REACH: Array<[string, number]> = [
    ["::ffff:203.0.113.0/120", 1],
    ["::ffff:203.0.113.5/128", 1],
    ["2001:db8::/48", 0],
    ["2001:db8::/96", 0],
    ["203.0.113.0/24", 1],
    ["203.0.113.5/32", 1],
  ];

  it.each(REFUSED)("%s is refused, and the real matcher shows why", (entry) => {
    const parsed = parseCidr(entry);
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    expect(agentCidrTooWide(parsed.value)).toBe(true);
    // It admits IPv4 addresses from more than one /24 (or none of the samples
    // is in the first /24 alone: at least two distinct /24s are matched).
    const prefixes = new Set(
      ipv4Matches(entry).map((a) => a.split(".").slice(0, 3).join(".")),
    );
    expect(prefixes.size).toBeGreaterThan(1);
  });

  it.each(ACCEPTED_REACH)(
    "%s is accepted and admits IPv4 addresses from at most one /24",
    (entry, expectedPrefixes) => {
      const parsed = parseCidr(entry);
      expect(parsed.ok).toBe(true);
      if (!parsed.ok) return;
      expect(agentCidrTooWide(parsed.value)).toBe(false);
      const prefixes = new Set(
        ipv4Matches(entry).map((a) => a.split(".").slice(0, 3).join(".")),
      );
      expect(prefixes.size).toBe(expectedPrefixes);
    },
  );

  it("measures the IPv4 width an IPv6 entry admits through the mapped range", () => {
    const width = (entry: string) => {
      const parsed = parseCidr(entry);
      if (!parsed.ok) throw new Error(parsed.error);
      return mappedIpv4Prefix(parsed.value);
    };
    expect(width("::ffff:0:0/96")).toBe(0);
    expect(width("::/48")).toBe(0);
    expect(width("::ffff:203.0.112.0/119")).toBe(23);
    expect(width("::ffff:203.0.113.0/120")).toBe(24);
    expect(width("::ffff:203.0.113.5/128")).toBe(32);
    // Not overlapping the mapped range: no IPv4 admitted at all.
    expect(width("2001:db8::/48")).toBeNull();
    expect(width("::/96")).toBeNull();
    expect(width("203.0.113.0/24")).toBeNull();
  });
});
