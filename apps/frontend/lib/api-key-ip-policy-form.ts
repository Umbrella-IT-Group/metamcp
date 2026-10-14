/**
 * Pure helpers for the API-key IP allowlist controls on the API keys admin
 * page (migration 0041). Kept out of the component so the form's translation
 * between what an administrator types and what the server stores is
 * unit-tested. The SERVER validates every CIDR (node:net, the same code that
 * matches them); nothing here decides whether an entry is valid.
 */

export type IpPolicyMode = "off" | "audit" | "enforce";

/** The per-key selector: "global" means allowed_cidrs NULL. */
export type KeyPolicySelection = "global" | IpPolicyMode;

export const ANY_IP_EXEMPTION = ["0.0.0.0/0", "::/0"] as const;

/**
 * Split a textarea into entries: one per line, commas and spaces also
 * separate, blanks dropped. Order is kept; the server canonicalises and
 * de-duplicates.
 */
export function parseCidrText(text: string): string[] {
  return text
    .split(/[\s,]+/)
    .map((entry) => entry.trim())
    .filter((entry) => entry !== "");
}

/** The stored list as textarea text, one entry per line. */
export function cidrsToText(cidrs: readonly string[] | null): string {
  return (cidrs ?? []).join("\n");
}

export function isAnyIpExemption(cidrs: readonly string[] | null): boolean {
  return (
    cidrs !== null &&
    cidrs.includes(ANY_IP_EXEMPTION[0]) &&
    cidrs.includes(ANY_IP_EXEMPTION[1])
  );
}

/** What the per-key dialog should show selected for a stored key. */
export function selectionForKey(
  allowedCidrs: readonly string[] | null,
  mode: IpPolicyMode,
): KeyPolicySelection {
  return allowedCidrs === null ? "global" : mode;
}

/**
 * The setIpPolicy request for a dialog state. "global" sends allowed_cidrs
 * null with mode off (the server refuses a per-key mode without a per-key
 * list); every other selection sends the typed list with that mode.
 */
export function keyPolicyRequest(
  uuid: string,
  selection: KeyPolicySelection,
  text: string,
): {
  uuid: string;
  allowed_cidrs: string[] | null;
  ip_policy_mode: IpPolicyMode;
} {
  if (selection === "global") {
    return { uuid, allowed_cidrs: null, ip_policy_mode: "off" };
  }
  return {
    uuid,
    allowed_cidrs: parseCidrText(text),
    ip_policy_mode: selection,
  };
}

/**
 * A short label and badge tone for the admin list. "Global" for a key that
 * follows the global policy, "Any IP" for the explicit exemption, otherwise
 * the mode and the entry count.
 */
export function describeKeyPolicy(
  allowedCidrs: readonly string[] | null,
  mode: IpPolicyMode,
): { label: string; tone: "outline" | "secondary" | "warning" | "success" } {
  if (allowedCidrs === null) return { label: "Global", tone: "outline" };
  if (isAnyIpExemption(allowedCidrs)) {
    return { label: `Any IP (${mode})`, tone: "secondary" };
  }
  const count = `${allowedCidrs.length} ${allowedCidrs.length === 1 ? "CIDR" : "CIDRs"}`;
  if (mode === "enforce")
    return { label: `Enforce, ${count}`, tone: "success" };
  if (mode === "audit") return { label: `Audit, ${count}`, tone: "warning" };
  return { label: `Off, ${count}`, tone: "outline" };
}
