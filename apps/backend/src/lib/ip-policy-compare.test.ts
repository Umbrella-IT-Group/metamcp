/**
 * The address-set comparison behind the admin-plane IP rail
 * (lib/ip-policy-compare): an admin-plane key may only narrow an admin-plane
 * key's policy and may not weaken the global one, judged on the addresses
 * each policy admits, never on list text.
 *
 * The oracle for IPv4-mapped IPv6 is node:net BlockList, the matcher the
 * request-time gate uses: a case that says "admits" is checked against it.
 */
import { BlockList } from "node:net";

import { describe, expect, it } from "vitest";

import {
  admitsNoMoreThan,
  admittedAddresses,
  isNoWeakerPolicy,
} from "./ip-policy-compare";

const enforce = (...cidrs: string[]) => ({ mode: "enforce", cidrs });
const narrower = (inner: string[], outer: string[]) =>
  admitsNoMoreThan(
    admittedAddresses(enforce(...inner)),
    admittedAddresses(enforce(...outer)),
  );

describe("admittedAddresses", () => {
  it.each(["off", "audit"])(
    "reads mode %s as admitting every request, a missing address included",
    (mode) => {
      expect(admittedAddresses({ mode, cidrs: ["203.0.113.0/24"] })).toEqual({
        everything: true,
        ranges: [],
      });
    },
  );

  it("reads the any-IP exemption as admitting every request", () => {
    expect(admittedAddresses(enforce("0.0.0.0/0", "::/0")).everything).toBe(
      true,
    );
  });

  it("does not read ::/0 alone as the exemption: a missing address is still refused", () => {
    const set = admittedAddresses(enforce("::/0"));
    expect(set.everything).toBe(false);
    // But every address is inside it.
    expect(narrower(["0.0.0.0/0"], ["::/0"])).toBe(true);
  });

  it("reads an unknown stored mode as enforce, like the gate", () => {
    expect(
      admittedAddresses({ mode: "bogus", cidrs: ["203.0.113.0/24"] })
        .everything,
    ).toBe(false);
  });

  it("ignores an entry that does not parse (it admits nothing at request time)", () => {
    expect(narrower(["203.0.113.0/24"], ["not-a-cidr", "203.0.113.0/24"])).toBe(
      true,
    );
    expect(narrower(["198.51.100.0/24"], ["not-a-cidr"])).toBe(false);
  });
});

describe("admitsNoMoreThan, as address sets", () => {
  it.each([
    ["a /32 inside a /24", ["203.0.113.7/32"], ["203.0.113.0/24"], true],
    ["the same list", ["203.0.113.0/24"], ["203.0.113.0/24"], true],
    ["a /23 over a /24", ["203.0.112.0/23"], ["203.0.113.0/24"], false],
    ["a disjoint /24", ["198.51.100.0/24"], ["203.0.113.0/24"], false],
    [
      "a /24 covered only by two adjacent /25s",
      ["203.0.113.0/24"],
      ["203.0.113.0/25", "203.0.113.128/25"],
      true,
    ],
    [
      "a /24 over two /25s with a gap",
      ["203.0.113.0/24"],
      ["203.0.113.0/25", "203.0.113.192/26"],
      false,
    ],
    ["an IPv6 /64 in a /48", ["2001:db8:1:1::/64"], ["2001:db8:1::/48"], true],
    ["an IPv6 /47 over a /48", ["2001:db8::/47"], ["2001:db8::/48"], false],
    [
      "IPv4 inside the mapped IPv6 form of its network",
      ["203.0.113.0/24"],
      ["::ffff:203.0.113.0/120"],
      true,
    ],
    [
      "the mapped form inside the IPv4 network",
      ["::ffff:203.0.113.0/120"],
      ["203.0.113.0/24"],
      true,
    ],
    [
      "all of IPv4 through ::ffff:0:0/96 is wider than one /24",
      ["::ffff:0:0/96"],
      ["203.0.113.0/24"],
      false,
    ],
    ["an empty list inside anything", [], ["203.0.113.0/24"], true],
  ] as const)("%s: %s", (_label, inner, outer, expected) => {
    expect(narrower([...inner], [...outer])).toBe(expected);
  });

  it("agrees with BlockList on a mapped address against an IPv4 rule", () => {
    const list = new BlockList();
    list.addSubnet("203.0.113.0", 24, "ipv4");
    // The gate admits the mapped spelling, so the comparison must treat the
    // two as one network.
    expect(list.check("::ffff:203.0.113.5", "ipv6")).toBe(true);
    expect(narrower(["::ffff:203.0.113.5/128"], ["203.0.113.0/24"])).toBe(true);
  });

  it("never lets a list be narrower than everything-but-missing unless the outer admits everything", () => {
    const anyIp = admittedAddresses(enforce("0.0.0.0/0", "::/0"));
    const all = admittedAddresses(enforce("::/0"));
    expect(admitsNoMoreThan(anyIp, all)).toBe(false);
    expect(admitsNoMoreThan(all, anyIp)).toBe(true);
  });
});

describe("isNoWeakerPolicy (the global rule)", () => {
  const p = (mode: string, ...cidrs: string[]) => ({ mode, cidrs });

  it.each([
    [
      "enforce to audit",
      p("enforce", "203.0.113.0/24"),
      p("audit", "203.0.113.0/24"),
      false,
    ],
    ["enforce to off", p("enforce", "203.0.113.0/24"), p("off"), false],
    ["audit to off", p("audit", "203.0.113.0/24"), p("off"), false],
    ["off to audit", p("off"), p("audit", "203.0.113.0/24"), true],
    ["off to enforce", p("off"), p("enforce", "203.0.113.0/24"), true],
    [
      "audit to enforce with any list",
      p("audit", "10.0.0.0/8"),
      p("enforce", "198.51.100.0/24"),
      true,
    ],
    [
      "enforce, narrower",
      p("enforce", "203.0.113.0/24"),
      p("enforce", "203.0.113.0/25"),
      true,
    ],
    [
      "enforce, wider",
      p("enforce", "203.0.113.0/24"),
      p("enforce", "203.0.112.0/23"),
      false,
    ],
    [
      "enforce, to the any-IP exemption",
      p("enforce", "203.0.113.0/24"),
      p("enforce", "0.0.0.0/0", "::/0"),
      false,
    ],
    [
      "enforce, the same",
      p("enforce", "203.0.113.0/24"),
      p("enforce", "203.0.113.0/24"),
      true,
    ],
    [
      "audit, a wider list (hides would-deny rows)",
      p("audit", "203.0.113.0/24"),
      p("audit", "203.0.112.0/23"),
      false,
    ],
    [
      "audit, a narrower list",
      p("audit", "203.0.113.0/24"),
      p("audit", "203.0.113.0/25"),
      true,
    ],
    ["off to off", p("off"), p("off"), true],
  ] as const)("%s", (_label, before, after, expected) => {
    expect(isNoWeakerPolicy(before, after)).toBe(expected);
  });
});
