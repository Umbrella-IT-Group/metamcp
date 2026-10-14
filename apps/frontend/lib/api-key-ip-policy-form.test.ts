import { describe, expect, it } from "vitest";

import {
  cidrsToText,
  describeKeyPolicy,
  keyPolicyRequest,
  parseCidrText,
  selectionForKey,
} from "./api-key-ip-policy-form";

const UUID = "44444444-4444-4444-8444-444444444444";

describe("parseCidrText", () => {
  it("splits on newlines, commas and spaces and drops blanks", () => {
    expect(
      parseCidrText(
        "203.0.113.0/24\n\n 2001:db8::/32, 198.51.100.7\t192.0.2.0/24",
      ),
    ).toEqual([
      "203.0.113.0/24",
      "2001:db8::/32",
      "198.51.100.7",
      "192.0.2.0/24",
    ]);
  });

  it("an empty textarea is an empty list", () => {
    expect(parseCidrText("  \n ")).toEqual([]);
  });

  it("round-trips the stored list", () => {
    const stored = ["203.0.113.0/24", "2001:db8::/32"];
    expect(parseCidrText(cidrsToText(stored))).toEqual(stored);
    expect(cidrsToText(null)).toBe("");
  });
});

describe("selectionForKey / keyPolicyRequest", () => {
  it("a key with no list shows as following the global policy", () => {
    expect(selectionForKey(null, "off")).toBe("global");
    expect(selectionForKey([], "enforce")).toBe("enforce");
  });

  it("'global' sends allowed_cidrs null with mode off, whatever was typed", () => {
    expect(keyPolicyRequest(UUID, "global", "203.0.113.0/24")).toEqual({
      uuid: UUID,
      allowed_cidrs: null,
      ip_policy_mode: "off",
    });
  });

  it("a mode sends the typed list with that mode", () => {
    expect(
      keyPolicyRequest(UUID, "audit", "203.0.113.0/24\n2001:db8::/32"),
    ).toEqual({
      uuid: UUID,
      allowed_cidrs: ["203.0.113.0/24", "2001:db8::/32"],
      ip_policy_mode: "audit",
    });
  });
});

describe("describeKeyPolicy", () => {
  it("labels each state", () => {
    expect(describeKeyPolicy(null, "off").label).toBe("Global");
    expect(describeKeyPolicy(["0.0.0.0/0", "::/0"], "enforce").label).toBe(
      "Any IP (enforce)",
    );
    expect(describeKeyPolicy(["203.0.113.0/24"], "enforce")).toEqual({
      label: "Enforce, 1 CIDR",
      tone: "success",
    });
    expect(
      describeKeyPolicy(["203.0.113.0/24", "2001:db8::/32"], "audit"),
    ).toEqual({
      label: "Audit, 2 CIDRs",
      tone: "warning",
    });
    expect(describeKeyPolicy([], "off").label).toBe("Off, 0 CIDRs");
  });

  it("a list with only one of the two any-IP entries is not the exemption", () => {
    expect(describeKeyPolicy(["0.0.0.0/0"], "enforce").label).toBe(
      "Enforce, 1 CIDR",
    );
  });
});
