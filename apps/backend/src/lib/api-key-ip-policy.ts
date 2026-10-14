import { BlockList, isIP, SocketAddress } from "node:net";

import logger from "@/utils/logger";

import { type AuditRequestContext, emit } from "./audit/audit-emitter";

/**
 * API-key IP allowlists (migration 0040).
 *
 * WHAT THIS CLOSES. An API key used to work from any address on earth, so a key
 * copied out of a config file, a log or a laptop worked for whoever held it.
 * An allowlist binds a key to the networks its real caller uses. OAuth callers
 * (claude.ai connectors, Claude Code logins) are NOT touched: nothing in this
 * file is reached on an OAuth path, because the only callers are the two key
 * validators in db/repositories/api-keys.repo.ts.
 *
 * EFFECTIVE POLICY for a key, in this order:
 *   1. the env kill switch API_KEY_IP_POLICY_DISABLED=true turns every check off;
 *   2. api_keys.allowed_cidrs non-NULL (even an empty array): the key's own
 *      list and its own ip_policy_mode apply;
 *   3. otherwise the GLOBAL list and mode (config rows API_KEY_IP_ALLOWED_CIDRS
 *      and API_KEY_IP_POLICY_MODE) apply. Unset reads as mode off.
 * Mode off evaluates nothing. Mode audit serves the request and writes a
 * throttled `apikey.ip.would_deny` row. Mode enforce refuses it (the call site
 * answers 403) and writes a throttled `apikey.ip.denied` row. Both rows carry
 * `detail.reason = "api_key_ip_not_allowed"`.
 *
 * CLIENT IP. The caller passes the value lib/client-ip.ts resolves from
 * CF-Connecting-IP. Cloudflare overwrites that header at the edge, so it is not
 * forgeable through the tunnel; `req.ip` and X-Forwarded-For are never used
 * (see middleware/audit-context.middleware for why `trust proxy` stays off).
 * A missing or unparsable address is not in any list, so it is refused under
 * enforce, EXCEPT under the any-IP exemption, which short-circuits before the
 * address is parsed.
 *
 * THE ANY-IP EXEMPTION is a list holding BOTH 0.0.0.0/0 and ::/0. It exists for
 * a caller with no stable address (GitHub-hosted CI runners rotate through
 * thousands), so it must also accept a request whose address cannot be read;
 * a list with only one of the two is an ordinary list and does not.
 *
 * Kept free of database imports so the policy is unit-testable without
 * Postgres, the same doctrine as db/repositories/api-keys.last-used.ts. The
 * global policy reaches it through a reader function the repository injects.
 */

export const IP_POLICY_MODES = ["off", "audit", "enforce"] as const;
export type IpPolicyMode = (typeof IP_POLICY_MODES)[number];

/** Which authentication surface asked, recorded on every audit row. */
export type ApiKeyIpSurface = "data_plane" | "oauth_introspect" | "admin_plane";

/**
 * The explicit opt-in a validator call passes to have the key's IP policy
 * evaluated. Its PRESENCE is the opt-in, not the IP: `clientIp` may be
 * undefined (no CF-Connecting-IP on the request), and that has to be
 * distinguishable from "this caller never asked", because the first fails
 * closed under enforce and the second must not evaluate at all. The tRPC
 * `apiKeys.validate` oracle deliberately passes nothing: it is an admin UI
 * helper, not an authentication, and it has no caller address to judge.
 */
export interface ApiKeyIpCheck {
  clientIp: string | undefined;
  surface: ApiKeyIpSurface;
  /** Attribution for the audit row (request id, user agent, actor ip). */
  audit: AuditRequestContext;
  /** What the request was for (an endpoint, an OAuth route, /trpc). */
  target?: { type: string; id: string | null; label?: string | null };
}

/**
 * The one sentence a refused caller sees, shared with the account-disabled
 * refusal on the data plane, so an IP refusal is indistinguishable from any
 * other "credential not permitted" answer and names nothing about the policy.
 */
export const CREDENTIAL_NOT_PERMITTED_MESSAGE =
  "This credential is not currently permitted to access this gateway.";

/** The audit `detail.reason` for both the would-deny and the deny row. */
export const IP_POLICY_AUDIT_REASON = "api_key_ip_not_allowed";

export const ANY_IPV4_CIDR = "0.0.0.0/0";
export const ANY_IPV6_CIDR = "::/0";

/** Per-list ceiling, far above any real allowlist; mirrored in zod-types. */
export const MAX_CIDRS_PER_LIST = 100;

// ---------------------------------------------------------------------------
// Kill switch
// ---------------------------------------------------------------------------

/**
 * API_KEY_IP_POLICY_DISABLED=true turns every IP check off, process-wide, for
 * every key and every surface, including keys with their own enforce list. It
 * is the recovery lever when a policy locks out a caller that cannot be fixed
 * through the admin plane (for example the operator's own admin-plane key).
 * Strict `"true"` only, like ADMIN_PLANE_TOKEN_AUTH_DISABLED and
 * ALLOW_UNAUTHENTICATED_ENDPOINTS, so a near-miss spelling cannot flip a
 * security posture. Read per request so the check costs nothing when it is
 * the stored policy, not the env, that changed.
 */
export function apiKeyIpPolicyDisabled(): boolean {
  return process.env.API_KEY_IP_POLICY_DISABLED === "true";
}

let killSwitchWarned = false;

/** One boot warning when the kill switch is set, latched like its siblings. */
export function warnIfApiKeyIpPolicyDisabled(): void {
  if (killSwitchWarned) return;
  killSwitchWarned = true;
  if (apiKeyIpPolicyDisabled()) {
    logger.warn(
      "API_KEY_IP_POLICY_DISABLED=true: API-key IP allowlists are OFF. No key's " +
        "IP policy (per-key or global) is evaluated and nothing is refused or " +
        "audited for its address until this is unset. OAuth is unaffected.",
    );
  }
}

/** Test seam: clear the boot-warn latch. */
export function __resetIpPolicyKillSwitchWarningForTesting(): void {
  killSwitchWarned = false;
}

// ---------------------------------------------------------------------------
// CIDR parsing
// ---------------------------------------------------------------------------

export interface ParsedCidr {
  /** Canonical text: canonical address, explicit prefix. */
  cidr: string;
  family: "ipv4" | "ipv6";
  address: string;
  prefix: number;
}

export type CidrParseResult =
  | { ok: true; value: ParsedCidr }
  | { ok: false; error: string };

function ipv4ToBytes(address: string): number[] {
  return address.split(".").map((octet) => Number(octet));
}

/**
 * Expand a canonical IPv6 address (as SocketAddress prints it) to 16 bytes.
 * Handles `::` compression and an embedded dotted IPv4 tail
 * (`::ffff:203.0.113.5`). Returns null on anything it cannot read, which the
 * caller turns into a parse error rather than a guess.
 */
function ipv6ToBytes(address: string): number[] | null {
  let text = address;
  let tail: number[] = [];
  const lastColon = text.lastIndexOf(":");
  const lastGroup = text.slice(lastColon + 1);
  if (lastGroup.includes(".")) {
    if (isIP(lastGroup) !== 4) return null;
    tail = ipv4ToBytes(lastGroup);
    // Stand two zero groups in for the dotted tail, expand as usual, then
    // overwrite the last four bytes with the IPv4 octets below.
    text = text.slice(0, lastColon + 1) + "0:0";
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
  const bytes: number[] = [];
  for (const group of groups) {
    if (!/^[0-9a-f]{1,4}$/i.test(group)) return null;
    const value = parseInt(group, 16);
    bytes.push(value >> 8, value & 0xff);
  }
  if (tail.length === 4) {
    bytes.splice(12, 4, ...tail);
  }
  return bytes.length === 16 ? bytes : null;
}

function bytesToIpv6(bytes: number[]): string {
  const groups: string[] = [];
  for (let i = 0; i < 16; i += 2) {
    groups.push(((bytes[i] << 8) | bytes[i + 1]).toString(16));
  }
  return new SocketAddress({ address: groups.join(":"), family: "ipv6" })
    .address;
}

function maskBytes(bytes: number[], prefix: number): number[] {
  return bytes.map((byte, index) => {
    const bitsBefore = index * 8;
    if (prefix >= bitsBefore + 8) return byte;
    if (prefix <= bitsBefore) return 0;
    const keep = prefix - bitsBefore;
    return byte & (0xff << (8 - keep)) & 0xff;
  });
}

/**
 * Parse one allowlist entry STRICTLY.
 *
 * Accepted: an IPv4 or IPv6 address with an optional `/prefix` (a bare address
 * means a single host: /32 or /128). The stored form is canonical: lowercase,
 * compressed IPv6 and an explicit prefix, so two spellings of one network are
 * one entry.
 *
 * Refused, each with a message that says what to write instead:
 *  - anything node:net's isIP does not call an address (it also refuses
 *    leading-zero octets such as 203.0.113.05, which some tools read as octal);
 *  - an IPv6 zone id (`fe80::1%eth0`): it names an interface on the gateway's
 *    host, not a network a caller comes from;
 *  - a prefix that is not a plain integer in range;
 *  - HOST BITS set (`203.0.113.5/24`). BlockList would silently treat that as
 *    the whole /24, but the person who typed it more likely meant /32, and
 *    allowing 256 addresses instead of one is the wrong direction to guess in.
 */
export function parseCidr(raw: string): CidrParseResult {
  if (typeof raw !== "string") {
    return { ok: false, error: "entry is not a string" };
  }
  const text = raw.trim();
  if (text === "") return { ok: false, error: "entry is empty" };
  const parts = text.split("/");
  if (parts.length > 2) {
    return { ok: false, error: `"${text}" has more than one "/"` };
  }
  const [addressText, prefixText] = parts;
  if (addressText.includes("%")) {
    return {
      ok: false,
      error: `"${text}" carries an IPv6 zone id, which is not a network`,
    };
  }
  const version = isIP(addressText);
  if (version === 0) {
    return {
      ok: false,
      error: `"${text}" is not an IPv4 or IPv6 address or CIDR`,
    };
  }
  const family = version === 4 ? "ipv4" : "ipv6";
  const maxPrefix = version === 4 ? 32 : 128;
  let prefix = maxPrefix;
  if (prefixText !== undefined) {
    if (!/^\d{1,3}$/.test(prefixText) || Number(prefixText) > maxPrefix) {
      return {
        ok: false,
        error: `"${text}" has an invalid prefix length (0 to ${maxPrefix})`,
      };
    }
    prefix = Number(prefixText);
  }
  const address =
    family === "ipv4"
      ? addressText
      : new SocketAddress({ address: addressText, family }).address;
  const bytes = family === "ipv4" ? ipv4ToBytes(address) : ipv6ToBytes(address);
  if (!bytes) {
    return { ok: false, error: `"${text}" could not be read as an address` };
  }
  const masked = maskBytes(bytes, prefix);
  if (masked.some((byte, index) => byte !== bytes[index])) {
    const network = family === "ipv4" ? masked.join(".") : bytesToIpv6(masked);
    return {
      ok: false,
      error: `"${text}" has host bits set; write ${network}/${prefix} for the network, or a /${maxPrefix} for one address`,
    };
  }
  return {
    ok: true,
    value: { cidr: `${address}/${prefix}`, family, address, prefix },
  };
}

/**
 * Validate and canonicalise a whole list for a WRITE. Every invalid entry is
 * reported (not just the first), duplicates after canonicalisation collapse to
 * one, and order is preserved so the stored list reads the way it was typed.
 */
export function normalizeCidrList(
  entries: readonly string[],
): { ok: true; cidrs: string[] } | { ok: false; errors: string[] } {
  if (entries.length > MAX_CIDRS_PER_LIST) {
    return {
      ok: false,
      errors: [`at most ${MAX_CIDRS_PER_LIST} entries per list`],
    };
  }
  const errors: string[] = [];
  const cidrs: string[] = [];
  for (const entry of entries) {
    const parsed = parseCidr(entry);
    if (!parsed.ok) {
      errors.push(parsed.error);
      continue;
    }
    if (!cidrs.includes(parsed.value.cidr)) cidrs.push(parsed.value.cidr);
  }
  return errors.length > 0 ? { ok: false, errors } : { ok: true, cidrs };
}

/** True for the explicit any-IP exemption: BOTH 0.0.0.0/0 and ::/0 present. */
export function isAnyIpExemption(cidrs: readonly string[]): boolean {
  return cidrs.includes(ANY_IPV4_CIDR) && cidrs.includes(ANY_IPV6_CIDR);
}

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------

export type IpStatus =
  | "in_list"
  | "any_ip_exemption"
  | "not_in_list"
  | "missing"
  | "unparsable";

/**
 * Stored entries the evaluator could not parse, named once each per process.
 * A stored list is validated on every write through the app, so an entry that
 * fails here was written outside it (psql). It is IGNORED, which can only
 * narrow the list (fail closed for the addresses it would have admitted), and
 * the warning names it so the operator can fix the row. Bounded so a
 * pathological list cannot grow this without limit.
 */
const warnedInvalidEntries = new Set<string>();

function warnInvalidStoredEntry(entry: string, error: string): void {
  if (warnedInvalidEntries.has(entry) || warnedInvalidEntries.size > 1000) {
    return;
  }
  warnedInvalidEntries.add(entry);
  logger.warn(
    `[api-key-ip-policy] ignoring an unreadable stored allowlist entry (${error}); fix it through apiKeys.setIpPolicy or setGlobalIpPolicy`,
  );
}

/**
 * Is `clientIp` inside `cidrs`? Pure apart from the warning above.
 *
 * Matching is node:net BlockList, which also matches an IPv4-mapped IPv6
 * address (`::ffff:203.0.113.5`) against an IPv4 rule. The exemption check
 * runs first and never looks at the address.
 */
export function matchClientIp(
  cidrs: readonly string[],
  clientIp: string | undefined,
): IpStatus {
  if (isAnyIpExemption(cidrs)) return "any_ip_exemption";
  if (clientIp === undefined || clientIp === "") return "missing";
  const version = isIP(clientIp);
  if (version === 0) return "unparsable";

  const list = new BlockList();
  for (const entry of cidrs) {
    const parsed = parseCidr(entry);
    if (!parsed.ok) {
      warnInvalidStoredEntry(entry, parsed.error);
      continue;
    }
    list.addSubnet(
      parsed.value.address,
      parsed.value.prefix,
      parsed.value.family,
    );
  }
  try {
    return list.check(clientIp, version === 4 ? "ipv4" : "ipv6")
      ? "in_list"
      : "not_in_list";
  } catch {
    // isIP accepted it but BlockList could not (an IPv6 zone id, for one).
    // Not an address any list can contain: fail closed.
    return "unparsable";
  }
}

export interface EffectiveIpPolicy {
  source: "key" | "global";
  mode: IpPolicyMode;
  cidrs: string[];
}

export interface GlobalIpPolicy {
  mode: IpPolicyMode;
  cidrs: string[];
}

/**
 * Read a mode value. A value outside the three known modes can only come from
 * outside the app (the per-key column has a CHECK; the global row is written
 * through a validated procedure), and it is read as ENFORCE: if what was meant
 * cannot be known, the safe reading is the one that does not leave a hole open
 * while an administrator believes it is closed. The kill switch is the way
 * back if that reading locks out a caller.
 */
export function readMode(raw: unknown): IpPolicyMode {
  if (raw === undefined || raw === null || raw === "") return "off";
  const value = String(raw).trim().toLowerCase();
  return (IP_POLICY_MODES as readonly string[]).includes(value)
    ? (value as IpPolicyMode)
    : "enforce";
}

/**
 * Parse the two global config rows into a policy plus a list of problems.
 *
 * Missing rows read as mode off with an empty list (the inert default). An
 * unreadable mode reads as enforce (see readMode). An unreadable CIDR value
 * (not a JSON array of strings) reads as an EMPTY list: under enforce that
 * refuses every key that follows the global policy, which is fail closed, and
 * the problem is reported so the administrator sees why.
 */
export function parseStoredGlobalPolicy(
  modeRaw: string | undefined,
  cidrsRaw: string | undefined,
): GlobalIpPolicy & { problems: string[] } {
  const problems: string[] = [];
  const mode = readMode(modeRaw);
  if (
    modeRaw !== undefined &&
    modeRaw !== "" &&
    !(IP_POLICY_MODES as readonly string[]).includes(modeRaw)
  ) {
    problems.push(
      `stored API_KEY_IP_POLICY_MODE is not off, audit or enforce; read as ${mode}`,
    );
  }
  let cidrs: string[] = [];
  if (cidrsRaw !== undefined && cidrsRaw !== "") {
    try {
      const parsed: unknown = JSON.parse(cidrsRaw);
      if (
        Array.isArray(parsed) &&
        parsed.every((entry) => typeof entry === "string")
      ) {
        cidrs = parsed as string[];
      } else {
        problems.push(
          "stored API_KEY_IP_ALLOWED_CIDRS is not a JSON array of strings; read as an empty list",
        );
      }
    } catch {
      problems.push(
        "stored API_KEY_IP_ALLOWED_CIDRS is not valid JSON; read as an empty list",
      );
    }
  }
  for (const entry of cidrs) {
    const parsed = parseCidr(entry);
    if (!parsed.ok) {
      problems.push(`stored global entry ignored: ${parsed.error}`);
    }
  }
  return { mode, cidrs, problems };
}

// ---------------------------------------------------------------------------
// Audit throttle
// ---------------------------------------------------------------------------

/**
 * One audit row per (decision, key, client IP) per window.
 *
 * WHY. `audit_log` is append-only with no prune path (migration 0028) and its
 * writer pool is `max: 2` (db/audit-db). A refused caller does not stop, and
 * a STOLEN key's holder controls the request rate, so a row per attempt would
 * hand them a write-amplification primitive against the one table nobody can
 * clean up, and enough load to crowd out every other audit row. The same
 * reasoning as recordAccessDenial in lib/endpoint-access-control, with a longer
 * window because an allowlist decision does not change between two requests
 * from the same address.
 *
 * WHAT IS NOT LOST. Suppressed attempts are counted and the count rides on the
 * next row for that pair (`suppressed_since_last`), so volume survives.
 *
 * THE PER-KEY BUDGET. A per-pair throttle alone does not bound a holder who
 * rotates source addresses (an IPv6 /64 is 2^64 of them): each new address is
 * a new pair. So each (decision, key) may also write at most
 * IP_POLICY_AUDIT_PER_KEY_BUDGET rows per window; past that, attempts are
 * counted into `key_suppressed_since_last` on the key's next row. Only a key
 * that ALREADY resolved to a row reaches this code (an unknown key never
 * does), so the number of keys is the number of minted keys, and the total
 * write rate this path can produce is bounded by keys x budget per window.
 */
export const IP_POLICY_AUDIT_INTERVAL_MS = 10 * 60 * 1000;
export const IP_POLICY_AUDIT_PER_KEY_BUDGET = 20;
const IP_POLICY_THROTTLE_MAX_ENTRIES = 10_000;

interface PairEntry {
  reportedAt: number;
  suppressed: number;
}

interface KeyBudgetEntry {
  windowStart: number;
  emitted: number;
  suppressed: number;
}

const pairThrottle = new Map<string, PairEntry>();
const keyBudget = new Map<string, KeyBudgetEntry>();

/**
 * Should this decision be written down? Stateful: calling it RECORDS the
 * attempt. Returns the two suppressed counts the row should carry.
 */
export function recordIpPolicyDecision(
  decision: "would_deny" | "deny",
  keyUuid: string,
  clientIp: string | undefined,
  now: number = Date.now(),
): { emit: boolean; suppressed: number; keySuppressed: number } {
  // JSON-encoded so an address containing a separator character cannot make
  // two different pairs share a key.
  const pairKey = JSON.stringify([decision, keyUuid, clientIp ?? null]);
  const pair = pairThrottle.get(pairKey);
  if (pair && now - pair.reportedAt < IP_POLICY_AUDIT_INTERVAL_MS) {
    pair.suppressed += 1;
    return { emit: false, suppressed: pair.suppressed, keySuppressed: 0 };
  }

  const budgetKey = JSON.stringify([decision, keyUuid]);
  let budget = keyBudget.get(budgetKey);
  if (!budget || now - budget.windowStart >= IP_POLICY_AUDIT_INTERVAL_MS) {
    budget = {
      windowStart: now,
      emitted: 0,
      // Carried across the window boundary so a count accrued at the end of
      // one window still reaches a row.
      suppressed: budget?.suppressed ?? 0,
    };
    if (keyBudget.size >= IP_POLICY_THROTTLE_MAX_ENTRIES) keyBudget.clear();
    keyBudget.set(budgetKey, budget);
  }
  if (budget.emitted >= IP_POLICY_AUDIT_PER_KEY_BUDGET) {
    budget.suppressed += 1;
    return { emit: false, suppressed: 0, keySuppressed: budget.suppressed };
  }
  budget.emitted += 1;
  const keySuppressed = budget.suppressed;
  budget.suppressed = 0;

  if (pairThrottle.size >= IP_POLICY_THROTTLE_MAX_ENTRIES) pairThrottle.clear();
  const suppressed = pair?.suppressed ?? 0;
  pairThrottle.set(pairKey, { reportedAt: now, suppressed: 0 });
  return { emit: true, suppressed, keySuppressed };
}

/** Test seam: forget both throttle maps and the invalid-entry warnings. */
export function __resetIpPolicyStateForTesting(): void {
  pairThrottle.clear();
  keyBudget.clear();
  warnedInvalidEntries.clear();
}

// ---------------------------------------------------------------------------
// The one entry point the validators call
// ---------------------------------------------------------------------------

export interface ApiKeyIpPolicyRow {
  uuid: string;
  allowed_cidrs: string[] | null;
  ip_policy_mode: string;
}

/**
 * Evaluate a resolved key's IP policy for one request, write the throttled
 * audit row if the address is not allowed, and say whether to refuse.
 *
 * Never throws for a policy reason. It CAN throw if `readGlobal` throws (the
 * config read failed); the validator lets that propagate, so the call site
 * answers the way it answers any database failure (500, or unauthenticated on
 * /trpc), which refuses rather than serving a request whose policy could not
 * be read.
 */
export async function applyApiKeyIpPolicy(
  key: ApiKeyIpPolicyRow,
  check: ApiKeyIpCheck,
  readGlobal: () => Promise<GlobalIpPolicy>,
): Promise<{ denied: boolean }> {
  if (apiKeyIpPolicyDisabled()) return { denied: false };

  let effective: EffectiveIpPolicy;
  if (key.allowed_cidrs !== null && key.allowed_cidrs !== undefined) {
    effective = {
      source: "key",
      mode: readMode(key.ip_policy_mode),
      cidrs: key.allowed_cidrs,
    };
  } else {
    const global = await readGlobal();
    effective = { source: "global", mode: global.mode, cidrs: global.cidrs };
  }

  if (effective.mode === "off") return { denied: false };

  const status = matchClientIp(effective.cidrs, check.clientIp);
  if (status === "in_list" || status === "any_ip_exemption") {
    return { denied: false };
  }

  const decision = effective.mode === "enforce" ? "deny" : "would_deny";
  const throttle = recordIpPolicyDecision(decision, key.uuid, check.clientIp);
  if (throttle.emit) {
    emitIpPolicyEvent(decision, key.uuid, check, effective, status, throttle);
  }
  return { denied: decision === "deny" };
}

function emitIpPolicyEvent(
  decision: "would_deny" | "deny",
  keyUuid: string,
  check: ApiKeyIpCheck,
  effective: EffectiveIpPolicy,
  status: IpStatus,
  throttle: { suppressed: number; keySuppressed: number },
): void {
  try {
    emit({
      actor_type: "api_key",
      actor_id: keyUuid,
      actor_label: null,
      actor_ip: check.audit.actor_ip,
      actor_user_agent: check.audit.actor_user_agent,
      action: decision === "deny" ? "apikey.ip.denied" : "apikey.ip.would_deny",
      target_type: check.target?.type ?? null,
      target_id: check.target?.id ?? null,
      // A would-deny request WAS served, so its outcome is success; the row
      // exists to say it would not have been under enforce.
      outcome: decision === "deny" ? "denied" : "success",
      request_id: check.audit.request_id,
      http_status: decision === "deny" ? 403 : null,
      detail: {
        reason: IP_POLICY_AUDIT_REASON,
        surface: check.surface,
        policy_source: effective.source,
        mode: effective.mode,
        // in_list never reaches here; the other four say WHY the address
        // failed, which is what decides the fix: not_in_list means add a CIDR,
        // missing means the caller does not come through Cloudflare.
        ip_status: status,
        client_ip: check.clientIp ?? null,
        target_label: check.target?.label ?? null,
        suppressed_since_last: throttle.suppressed,
        key_suppressed_since_last: throttle.keySuppressed,
      },
    });
    // One log line per audit row, so the container log shows the same event
    // at the same throttled rate.
    logger.warn(
      `[api-key-ip-policy] ${decision === "deny" ? "refused" : "would refuse"} key=${keyUuid} surface=${check.surface} source=${effective.source} mode=${effective.mode} ip_status=${status}`,
    );
  } catch {
    // An audit failure must never change the answer. Same contract as
    // emitMcpAuthDenial in middleware/api-key-oauth.middleware.
  }
}
