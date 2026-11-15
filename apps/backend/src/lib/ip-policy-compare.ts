import {
  type IpPolicyMode,
  isAnyIpExemption,
  parseCidr,
  readMode,
} from "./api-key-ip-policy";

/**
 * Is one IP policy no weaker than another? The comparison the admin-plane IP
 * rail makes: an admin-plane key may narrow an admin-plane key's policy and
 * may not weaken the global one, so a change is judged by the set of addresses
 * each policy admits, never by comparing list text.
 *
 * THE ADDRESS SPACE. Every entry is placed in one 128-bit space: an IPv6
 * entry as it is, an IPv4 entry as its IPv4-mapped IPv6 range
 * (`::ffff:a.b.c.d/96+p`). That is how the request-time gate evaluates a
 * policy (node:net BlockList matches an IPv4 address against an IPv6 rule
 * through its mapped form, see api-key-ip-policy `mappedIpv4Prefix`), so an
 * IPv6 entry covering the mapped range is understood to admit IPv4 addresses
 * here too, and `10.0.0.0/24` and `::ffff:10.0.0.0/120` are one set.
 *
 * WHAT A POLICY ADMITS.
 *  - mode off or audit: every request (audit only logs), including one whose
 *    address is missing or unreadable;
 *  - enforce with the any-IP exemption (both 0.0.0.0/0 and ::/0): the same;
 *  - enforce otherwise: the union of its entries' ranges, and never a request
 *    whose address is missing or unreadable. A stored entry that does not
 *    parse admits nothing, as at request time.
 *
 * Pure: no database, no logger.
 */

/** One closed range of the unified space, inclusive at both ends. */
type Range = readonly [bigint, bigint];

/** The addresses a policy admits. */
export interface AdmittedAddresses {
  /** Every address, and a request with no readable address too. */
  everything: boolean;
  /** Sorted, merged ranges; empty when `everything`. */
  ranges: Range[];
}

const MAPPED_PREFIX = 0xffffn << 32n;

function bytesToBigint(bytes: readonly number[]): bigint {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value;
}

function ipv4Value(address: string): bigint {
  return bytesToBigint(address.split(".").map(Number));
}

/** Expand a canonical IPv6 address to its 128-bit value, or null. */
function ipv6Value(address: string): bigint | null {
  let text = address;
  let tail: bigint | null = null;
  const lastColon = text.lastIndexOf(":");
  const lastGroup = text.slice(lastColon + 1);
  if (lastGroup.includes(".")) {
    tail = ipv4Value(lastGroup);
    text = `${text.slice(0, lastColon + 1)}0:0`;
  }
  const halves = text.split("::");
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(":") : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const missing = 8 - left.length - right.length;
  if (halves.length === 1 && missing !== 0) return null;
  if (halves.length === 2 && missing < 1) return null;
  const groups = [
    ...left,
    ...Array.from({ length: halves.length === 2 ? missing : 0 }, () => "0"),
    ...right,
  ];
  let value = 0n;
  for (const group of groups) {
    if (!/^[0-9a-f]{1,4}$/i.test(group)) return null;
    value = (value << 16n) | BigInt(parseInt(group, 16));
  }
  if (tail !== null) value = (value & ~0xffffffffn) | tail;
  return value;
}

/** The range of one stored entry in the unified space, or null if unreadable. */
function entryRange(entry: string): Range | null {
  const parsed = parseCidr(entry);
  if (!parsed.ok) return null;
  const { family, address, prefix } = parsed.value;
  if (family === "ipv4") {
    const start = MAPPED_PREFIX | ipv4Value(address);
    const size = 1n << BigInt(32 - prefix);
    return [start, start + size - 1n];
  }
  const start = ipv6Value(address);
  if (start === null) return null;
  const size = 1n << BigInt(128 - prefix);
  return [start, start + size - 1n];
}

function merge(ranges: Range[]): Range[] {
  const sorted = [...ranges].sort((a, b) =>
    a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0,
  );
  const merged: Array<[bigint, bigint]> = [];
  for (const [start, end] of sorted) {
    const last = merged[merged.length - 1];
    if (last && start <= last[1] + 1n) {
      if (end > last[1]) last[1] = end;
    } else {
      merged.push([start, end]);
    }
  }
  return merged;
}

/** The addresses a policy admits (see the module comment). */
export function admittedAddresses(policy: {
  mode: IpPolicyMode | string;
  cidrs: readonly string[];
}): AdmittedAddresses {
  const mode = readMode(policy.mode);
  if (mode !== "enforce" || isAnyIpExemption(policy.cidrs)) {
    return { everything: true, ranges: [] };
  }
  const ranges: Range[] = [];
  for (const entry of policy.cidrs) {
    const range = entryRange(entry);
    if (range) ranges.push(range);
  }
  const merged = merge(ranges);
  // A list covering the whole space still refuses a request with no readable
  // address, so it is not `everything`.
  return { everything: false, ranges: merged };
}

/** Does `inner` admit nothing that `outer` does not? */
export function admitsNoMoreThan(
  inner: AdmittedAddresses,
  outer: AdmittedAddresses,
): boolean {
  if (outer.everything) return true;
  if (inner.everything) return false;
  // Both are merged and sorted: walk them together.
  let j = 0;
  for (const [start, end] of inner.ranges) {
    while (j < outer.ranges.length && outer.ranges[j][1] < start) j += 1;
    const cover = outer.ranges[j];
    if (!cover || cover[0] > start || cover[1] < end) return false;
  }
  return true;
}

const MODE_RANK: Record<IpPolicyMode, number> = {
  off: 0,
  audit: 1,
  enforce: 2,
};

/**
 * Is `after` no weaker than `before`, in mode and in admitted addresses? The
 * rule for an admin-plane key's change to the GLOBAL policy.
 *
 *  - The mode may not fall (enforce to audit or off, audit to off).
 *  - Under enforce, `after` may admit no address `before` did not, judged on
 *    the admitted sets; from off or audit (which admit everything) any enforce
 *    list is narrower.
 *  - Under audit on both sides the list decides which requests are logged as
 *    would-be refusals, so it may only narrow as well: a wider audit list
 *    hides requests the old one reported.
 */
export function isNoWeakerPolicy(
  before: { mode: IpPolicyMode | string; cidrs: readonly string[] },
  after: { mode: IpPolicyMode | string; cidrs: readonly string[] },
): boolean {
  const beforeMode = readMode(before.mode);
  const afterMode = readMode(after.mode);
  if (MODE_RANK[afterMode] < MODE_RANK[beforeMode]) return false;
  if (afterMode === "enforce" && beforeMode === "enforce") {
    return admitsNoMoreThan(
      admittedAddresses(after),
      admittedAddresses(before),
    );
  }
  if (afterMode === "audit" && beforeMode === "audit") {
    // Read the two lists as if enforced, which is the set each would report.
    return admitsNoMoreThan(
      admittedAddresses({ mode: "enforce", cidrs: after.cidrs }),
      admittedAddresses({ mode: "enforce", cidrs: before.cidrs }),
    );
  }
  return true;
}
