import { createHash } from "node:crypto";
import { isIP } from "node:net";

import {
  mappedIpv4Prefix,
  matchClientIp,
  parseCidr,
} from "@/lib/api-key-ip-policy";
import logger from "@/utils/logger";

import {
  DEFAULT_CLIENT_NAME,
  MAX_REDIRECT_URI_LENGTH,
} from "./client-registration";

/**
 * Policy approval of matching self-registrations (`POST /oauth/register`).
 *
 * WHAT IT DOES. A deployment may name, in OAUTH_DCR_AUTO_APPROVE_POLICY, the
 * exact registrations it is willing to approve without an administrator: an
 * exact client name, one exact loopback callback shape, and the networks the
 * registering caller must come from. In `pending` mode a registration that
 * matches an entry, and fits that entry's hourly budget, is stored approved
 * in its initial insert, with a time and no approving person. Everything else
 * stays pending exactly as before. `off` refuses first as always; `open`
 * (development only) never consults this.
 *
 * WHAT IT DOES NOT ESTABLISH. `/oauth/register` is anonymous (RFC 7591), so
 * the name and callback are a caller's claim, and the caller address
 * (CF-Connecting-IP, see lib/client-ip) identifies an egress network, not a
 * person or a program. A caller inside an allowed network can copy an allowed
 * name and callback and obtain an approved public client. Approval mints no
 * code or token: every person still signs in, consents, and proves PKCE S256.
 *
 * DECIDED ON EXACT VALUES, FAIL CLOSED. Every rule below compares exact
 * strings or integers. A policy that is not exactly valid turns the whole
 * feature off with one boot warning; nothing is salvaged from a bad document
 * and no earlier policy is kept.
 *
 * LIMITS, PLAINLY. The policy is resolved and latched at startup (like
 * OAUTH_DCR_MODE): changing it means recreating the process. The hourly
 * budget is an in-process count: it resets on restart and each backend
 * process has its own, so it is not a durable quota. Removing the policy
 * stops future policy approvals only; it revokes nothing already approved.
 *
 * A neutral conformance vector file (dcr-auto-approval.vectors.json, beside
 * this module) pins these rules so a second implementation (a deploy-side
 * validator) can replay them.
 */

export const OAUTH_DCR_AUTO_APPROVE_POLICY_ENV =
  "OAUTH_DCR_AUTO_APPROVE_POLICY";

/** Raw document cap, in UTF-8 bytes. */
export const MAX_POLICY_BYTES = 64 * 1024;
export const MAX_POLICY_ENTRIES = 20;
export const MAX_CIDRS_PER_ENTRY = 20;
export const MAX_CLIENT_NAME_UNITS = 255;
export const MIN_POLICY_PORT = 1024;
export const MAX_POLICY_PORT = 65535;
export const MAX_PER_HOUR_LIMIT = 1000;
/** Narrowest permitted reach, as prefix lengths. */
export const MIN_IPV4_PREFIX = 16;
export const MIN_IPV6_PREFIX = 32;
export const CAP_WINDOW_MS = 60 * 60 * 1000;

export const POLICY_HOSTS = ["localhost", "127.0.0.1", "[::1]"] as const;
export type PolicyHost = (typeof POLICY_HOSTS)[number];

const ENTRY_ID = /^[a-z0-9][a-z0-9_-]{0,63}$/;

/**
 * A policy path: "/" alone, or "/"-separated non-empty segments with an
 * optional trailing "/". Segment characters are RFC 3986 unreserved and
 * sub-delims plus ":" and "@", so the set excludes "%", "?", "#", "\",
 * space, controls and non-ASCII. No character here is one the WHATWG path
 * serializer re-encodes, so an accepted path is already in canonical form;
 * "." and ".." segments are refused separately.
 */
const POLICY_PATH =
  /^\/(?:[A-Za-z0-9\-._~!$&'()*+,;=:@]+(?:\/[A-Za-z0-9\-._~!$&'()*+,;=:@]+)*\/?)?$/;

/**
 * The whitespace set a whitespace-only name is made of: exactly the characters
 * ECMAScript's String.prototype.trim removes (WhiteSpace and LineTerminator),
 * written out so the rule does not depend on a runtime's Unicode tables.
 */
const WHITESPACE_ONLY =
  /^[\t\n\v\f\r \u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff]+$/;

/**
 * A lone UTF-16 surrogate: under the `u` flag a well-formed pair reads as one
 * astral code point, so only an unpaired half is in category Cs. A name that
 * is not well-formed Unicode has no NFC form two implementations agree on.
 */
const LONE_SURROGATE = /\p{Cs}/u;

const ROOT_FIELDS = ["version", "entries"] as const;
const ENTRY_FIELDS = [
  "id",
  "client_name",
  "redirect",
  "allowed_cidrs",
  "max_per_hour",
] as const;
const REDIRECT_FIELDS = ["host", "path", "port_min", "port_max"] as const;

const ALLOWED_GRANTS: ReadonlySet<string> = new Set([
  "authorization_code",
  "refresh_token",
]);

export interface DcrAutoApprovalEntry {
  id: string;
  /** NFC-normalised. */
  client_name: string;
  redirect: {
    host: PolicyHost;
    path: string;
    port_min: number;
    port_max: number;
  };
  /** Canonical (parseCidr) spellings, sorted. */
  allowed_cidrs: string[];
  max_per_hour: number;
}

export interface DcrAutoApprovalPolicy {
  version: 1;
  entries: DcrAutoApprovalEntry[];
  /**
   * `policy_version` in audit rows and the boot line: the SHA-256 (64 lower
   * hex characters) of `canonicalPolicyJson`. Distinct from the schema
   * `version` field.
   */
  hash: string;
}

/**
 * Why a policy document was refused. A fixed vocabulary, so the boot warning
 * can say what is wrong without echoing any policy value.
 */
export type PolicyRejectionReason =
  | "too_large"
  | "not_json"
  | "non_integer_number"
  | "duplicate_key"
  | "not_object"
  | "unknown_field"
  | "missing_field"
  | "bad_version"
  | "bad_entries"
  | "too_many_entries"
  | "bad_id"
  | "duplicate_id"
  | "bad_client_name"
  | "bad_redirect"
  | "bad_host"
  | "bad_path"
  | "bad_port"
  | "bad_port_range"
  | "callback_too_long"
  | "bad_cidrs"
  | "bad_cidr"
  | "cidr_too_wide"
  | "duplicate_cidr"
  | "bad_max_per_hour"
  | "internal_error";

export type PolicyParseResult =
  | { ok: true; policy: DcrAutoApprovalPolicy }
  | { ok: false; reason: PolicyRejectionReason; at: string | null };

class PolicyRejection extends Error {
  constructor(
    readonly reason: PolicyRejectionReason,
    readonly at: string | null,
  ) {
    super(reason);
  }
}

function reject(reason: PolicyRejectionReason, at: string | null): never {
  throw new PolicyRejection(reason, at);
}

/**
 * Two facts JSON.parse hides, read from the raw text of a document that has
 * already parsed: a number written with a fraction or exponent (`1.0`, `1e0`),
 * which JSON.parse turns into an integer, and a key repeated within one
 * object, which JSON.parse resolves silently to the last value. Every number
 * in a policy is an integer field, and a repeated key is a document two
 * readers can disagree about, so either refuses the policy.
 *
 * Only correct for valid JSON, which is why it runs after JSON.parse. Outside
 * strings, valid JSON holds structural characters, whitespace, the literals
 * true/false/null (which start with a letter) and numbers (which start with
 * "-" or a digit), so a number token is the run of number characters from
 * such a start.
 */
export function scanJsonText(
  text: string,
): "ok" | "non_integer_number" | "duplicate_key" {
  const stack: Array<{ keys: Set<string> | null; expectKey: boolean }> = [];
  let i = 0;
  while (i < text.length) {
    const ch = text[i];
    if (ch === '"') {
      let j = i + 1;
      while (j < text.length && text[j] !== '"') {
        j += text[j] === "\\" ? 2 : 1;
      }
      const top = stack[stack.length - 1];
      if (top?.keys && top.expectKey) {
        const key = JSON.parse(text.slice(i, j + 1)) as string;
        if (top.keys.has(key)) return "duplicate_key";
        top.keys.add(key);
        top.expectKey = false;
      }
      i = j + 1;
      continue;
    }
    if (ch === "-" || (ch >= "0" && ch <= "9")) {
      let j = i;
      while (j < text.length && /[0-9eE+\-.]/.test(text[j])) j += 1;
      if (/[.eE]/.test(text.slice(i, j))) return "non_integer_number";
      i = j;
      continue;
    }
    if (ch === "{") stack.push({ keys: new Set(), expectKey: true });
    else if (ch === "[") stack.push({ keys: null, expectKey: false });
    else if (ch === "}" || ch === "]") stack.pop();
    else if (ch === ",") {
      const top = stack[stack.length - 1];
      if (top?.keys) top.expectKey = true;
    }
    i += 1;
  }
  return "ok";
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Exactly these own keys, no more and no fewer. Unknown keys are checked first. */
function requireFields(
  value: unknown,
  fields: readonly string[],
  at: string,
): Record<string, unknown> {
  if (!isPlainObject(value)) reject("not_object", at || null);
  const keys = Object.keys(value);
  if (keys.some((key) => !fields.includes(key))) {
    reject("unknown_field", at || null);
  }
  for (const field of fields) {
    if (!Object.prototype.hasOwnProperty.call(value, field)) {
      reject("missing_field", at ? `${at}.${field}` : field);
    }
  }
  return value;
}

function isIntegerInRange(value: unknown, min: number, max: number): boolean {
  return (
    typeof value === "number" &&
    Number.isInteger(value) &&
    value >= min &&
    value <= max
  );
}

function checkName(raw: unknown, at: string): string {
  if (typeof raw !== "string" || LONE_SURROGATE.test(raw)) {
    reject("bad_client_name", at);
  }
  const name = raw.normalize("NFC");
  if (
    name.length < 1 ||
    name.length > MAX_CLIENT_NAME_UNITS ||
    WHITESPACE_ONLY.test(name) ||
    name === DEFAULT_CLIENT_NAME
  ) {
    reject("bad_client_name", at);
  }
  return name;
}

function checkPath(raw: unknown, at: string): string {
  if (typeof raw !== "string" || !POLICY_PATH.test(raw)) {
    reject("bad_path", at);
  }
  if (raw.split("/").some((segment) => segment === "." || segment === "..")) {
    reject("bad_path", at);
  }
  return raw;
}

function checkRedirect(
  raw: unknown,
  at: string,
): DcrAutoApprovalEntry["redirect"] {
  if (!isPlainObject(raw)) reject("bad_redirect", at);
  const redirect = requireFields(raw, REDIRECT_FIELDS, at);
  const host = redirect.host;
  if (
    typeof host !== "string" ||
    !(POLICY_HOSTS as readonly string[]).includes(host)
  ) {
    reject("bad_host", `${at}.host`);
  }
  const path = checkPath(redirect.path, `${at}.path`);
  for (const field of ["port_min", "port_max"] as const) {
    if (!isIntegerInRange(redirect[field], MIN_POLICY_PORT, MAX_POLICY_PORT)) {
      reject("bad_port", `${at}.${field}`);
    }
  }
  const portMin = redirect.port_min as number;
  const portMax = redirect.port_max as number;
  if (portMin > portMax) reject("bad_port_range", at);
  if (`http://${host}:${portMax}${path}`.length > MAX_REDIRECT_URI_LENGTH) {
    reject("callback_too_long", at);
  }
  return {
    host: host as PolicyHost,
    path,
    port_min: portMin,
    port_max: portMax,
  };
}

/**
 * Validate one network. parseCidr's own rules apply (no zone id, no host bits,
 * a plain prefix), with no surrounding whitespace, and the reach is bounded:
 * at least an IPv4 /16, a native IPv6 /32, and an IPv6 entry that admits IPv4
 * addresses through the mapped range (node:net BlockList matches those, see
 * mappedIpv4Prefix) at most an IPv4 /16 of them. `::/32` and `::ffff:0:0/96`
 * each admit all of IPv4 and are refused.
 */
function checkCidr(raw: unknown, at: string): string {
  if (typeof raw !== "string" || raw.trim() !== raw) reject("bad_cidr", at);
  const parsed = parseCidr(raw);
  if (!parsed.ok) reject("bad_cidr", at);
  const { family, prefix } = parsed.value;
  if (family === "ipv4" && prefix < MIN_IPV4_PREFIX) {
    reject("cidr_too_wide", at);
  }
  if (family === "ipv6") {
    if (prefix < MIN_IPV6_PREFIX) reject("cidr_too_wide", at);
    const mapped = mappedIpv4Prefix(parsed.value);
    if (mapped !== null && mapped < MIN_IPV4_PREFIX) {
      reject("cidr_too_wide", at);
    }
  }
  return parsed.value.cidr;
}

function checkEntry(raw: unknown, index: number): DcrAutoApprovalEntry {
  const at = `entries[${index}]`;
  const entry = requireFields(raw, ENTRY_FIELDS, at);
  if (typeof entry.id !== "string" || !ENTRY_ID.test(entry.id)) {
    reject("bad_id", `${at}.id`);
  }
  const clientName = checkName(entry.client_name, `${at}.client_name`);
  const redirect = checkRedirect(entry.redirect, `${at}.redirect`);
  const cidrs = entry.allowed_cidrs;
  if (
    !Array.isArray(cidrs) ||
    cidrs.length < 1 ||
    cidrs.length > MAX_CIDRS_PER_ENTRY
  ) {
    reject("bad_cidrs", `${at}.allowed_cidrs`);
  }
  const canonical: string[] = [];
  cidrs.forEach((cidr, cidrIndex) => {
    const value = checkCidr(cidr, `${at}.allowed_cidrs[${cidrIndex}]`);
    if (canonical.includes(value)) {
      reject("duplicate_cidr", `${at}.allowed_cidrs[${cidrIndex}]`);
    }
    canonical.push(value);
  });
  if (!isIntegerInRange(entry.max_per_hour, 1, MAX_PER_HOUR_LIMIT)) {
    reject("bad_max_per_hour", `${at}.max_per_hour`);
  }
  return {
    id: entry.id,
    client_name: clientName,
    redirect,
    allowed_cidrs: [...canonical].sort(),
    max_per_hour: entry.max_per_hour as number,
  };
}

/**
 * The canonical text the policy hash is taken over: fixed key order, entries
 * in policy order (order is precedence), names NFC, CIDRs canonical and
 * sorted (their order decides nothing), no whitespace. Two documents that
 * differ only in key order, CIDR spelling or CIDR order hash the same.
 */
export function canonicalPolicyJson(entries: DcrAutoApprovalEntry[]): string {
  return JSON.stringify({
    version: 1,
    entries: entries.map((entry) => ({
      id: entry.id,
      client_name: entry.client_name,
      redirect: {
        host: entry.redirect.host,
        path: entry.redirect.path,
        port_min: entry.redirect.port_min,
        port_max: entry.redirect.port_max,
      },
      allowed_cidrs: entry.allowed_cidrs,
      max_per_hour: entry.max_per_hour,
    })),
  });
}

/**
 * Parse and validate a policy document as a whole. Pure; never throws. Any
 * fault refuses the entire document with a reason from the fixed vocabulary
 * and, where it helps, the location as known field names and indexes only.
 */
export function parseDcrAutoApprovalPolicy(raw: string): PolicyParseResult {
  try {
    if (Buffer.byteLength(raw, "utf8") > MAX_POLICY_BYTES) {
      reject("too_large", null);
    }
    let doc: unknown;
    try {
      doc = JSON.parse(raw);
    } catch {
      reject("not_json", null);
    }
    const scan = scanJsonText(raw);
    if (scan !== "ok") reject(scan, null);

    const root = requireFields(doc, ROOT_FIELDS, "");
    if (root.version !== 1) reject("bad_version", "version");
    if (!Array.isArray(root.entries)) reject("bad_entries", "entries");
    if (root.entries.length > MAX_POLICY_ENTRIES) {
      reject("too_many_entries", "entries");
    }
    const entries = root.entries.map((entry, index) =>
      checkEntry(entry, index),
    );
    const ids = new Set<string>();
    entries.forEach((entry, index) => {
      if (ids.has(entry.id)) reject("duplicate_id", `entries[${index}].id`);
      ids.add(entry.id);
    });
    const hash = createHash("sha256")
      .update(canonicalPolicyJson(entries), "utf8")
      .digest("hex");
    return { ok: true, policy: { version: 1, entries, hash } };
  } catch (error) {
    if (error instanceof PolicyRejection) {
      return { ok: false, reason: error.reason, at: error.at };
    }
    return { ok: false, reason: "internal_error", at: null };
  }
}

export interface DcrAutoApprovalResolution {
  /** Null when unset, refused, or valid with no entries. */
  policy: DcrAutoApprovalPolicy | null;
  /** The one line logged at startup. Never contains a policy value. */
  log: { level: "info" | "warn"; message: string };
}

/**
 * Pure resolution from an environment, for startup and for tests. Unset means
 * no policy approval (the default). A refused document gives no policy and a
 * warning naming only the reason and location.
 */
export function resolveDcrAutoApprovalPolicy(
  env: NodeJS.ProcessEnv = process.env,
): DcrAutoApprovalResolution {
  const raw = env[OAUTH_DCR_AUTO_APPROVE_POLICY_ENV];
  if (raw === undefined) {
    return {
      policy: null,
      log: {
        level: "info",
        message: `[oauth] policy approval of matching registrations: inactive (${OAUTH_DCR_AUTO_APPROVE_POLICY_ENV} unset)`,
      },
    };
  }
  const result = parseDcrAutoApprovalPolicy(raw);
  if (!result.ok) {
    const where = result.at ? ` at ${result.at}` : "";
    return {
      policy: null,
      log: {
        level: "warn",
        message:
          `[oauth] ${OAUTH_DCR_AUTO_APPROVE_POLICY_ENV} refused (${result.reason}${where}); ` +
          `policy approval is OFF and every self-registration stays pending.`,
      },
    };
  }
  const { policy } = result;
  const count = policy.entries.length;
  const state = count > 0 ? "active" : "inactive";
  return {
    policy: count > 0 ? policy : null,
    log: {
      level: "info",
      message: `[oauth] policy approval of matching registrations: ${state}, ${count} ${count === 1 ? "entry" : "entries"}, policy_version ${policy.hash}`,
    },
  };
}

// ---------------------------------------------------------------------------
// Latch and hourly budget
// ---------------------------------------------------------------------------

let latched: { policy: DcrAutoApprovalPolicy | null } | null = null;

/**
 * Reservation times per entry id, from the injected monotonic clock. Only a
 * match that fits its entry's budget adds a time, and expired times are
 * pruned before each check, so an entry holds at most `max_per_hour` times
 * and the whole map at most entries x cap. Nothing clears a live reservation
 * except a new policy (startup) or the test reset.
 */
const reservations = new Map<string, number[]>();

const defaultClock = () => performance.now();
let clock: () => number = defaultClock;

/**
 * Resolve, log and latch the policy. Called once at module scope in
 * apps/backend/src/index.ts beside initOAuthDcrMode, before routes mount.
 * Never throws; every call replaces the previous policy (a refused document
 * leaves none) and empties the hourly budget.
 */
export function initDcrAutoApproval(
  env: NodeJS.ProcessEnv = process.env,
): DcrAutoApprovalPolicy | null {
  let resolution: DcrAutoApprovalResolution;
  try {
    resolution = resolveDcrAutoApprovalPolicy(env);
  } catch {
    resolution = {
      policy: null,
      log: {
        level: "warn",
        message: `[oauth] ${OAUTH_DCR_AUTO_APPROVE_POLICY_ENV} refused (internal_error); policy approval is OFF and every self-registration stays pending.`,
      },
    };
  }
  reservations.clear();
  latched = { policy: resolution.policy };
  if (resolution.log.level === "warn") logger.warn(resolution.log.message);
  else logger.info(resolution.log.message);
  return resolution.policy;
}

/**
 * The effective policy for a request: the one latched at startup, or, in a
 * process that never ran initDcrAutoApproval (a unit test importing a router
 * directly), one resolved and latched here on first use.
 */
export function getDcrAutoApprovalPolicy(): DcrAutoApprovalPolicy | null {
  if (latched === null) initDcrAutoApproval();
  return latched?.policy ?? null;
}

/** Test seam: forget the latched policy, the hourly budget and the clock. */
export function resetDcrAutoApprovalForTests(): void {
  latched = null;
  reservations.clear();
  clock = defaultClock;
}

/** Test seam: a monotonic clock in milliseconds. */
export function setDcrAutoApprovalClockForTests(next: () => number): void {
  clock = next;
}

/** Test seam: how many reservation times are held, per entry id. */
export function dcrAutoApprovalReservationCountsForTests(): Record<
  string,
  number
> {
  return Object.fromEntries(
    [...reservations].map(([id, times]) => [id, times.length]),
  );
}

/**
 * Check and reserve one slot of an entry's hourly budget, synchronously. A
 * time reserved at t expires at exactly t + one hour.
 */
function reserveSlot(entry: DcrAutoApprovalEntry, now: number): boolean {
  const live = (reservations.get(entry.id) ?? []).filter(
    (at) => now - at < CAP_WINDOW_MS,
  );
  if (live.length >= entry.max_per_hour) {
    reservations.set(entry.id, live);
    return false;
  }
  live.push(now);
  reservations.set(entry.id, live);
  return true;
}

// ---------------------------------------------------------------------------
// Matching
// ---------------------------------------------------------------------------

/**
 * The fields of a registration the matcher reads: the client the shared
 * registration core produced, so omitted optional fields already carry their
 * effective defaults. Never a raw request body.
 */
export interface DcrRegistrationForPolicy {
  client_name: unknown;
  redirect_uris: unknown;
  grant_types?: unknown;
  response_types?: unknown;
  token_endpoint_auth_method?: unknown;
  client_secret?: unknown;
}

function isPublicCodeClient(registration: DcrRegistrationForPolicy): boolean {
  if (registration.token_endpoint_auth_method !== "none") return false;
  if (registration.client_secret !== null) return false;
  const grants = registration.grant_types;
  if (!Array.isArray(grants) || grants.length === 0) return false;
  if (new Set(grants).size !== grants.length) return false;
  if (!grants.every((grant) => ALLOWED_GRANTS.has(grant))) return false;
  if (!grants.includes("authorization_code")) return false;
  const responses = registration.response_types;
  return (
    Array.isArray(responses) &&
    responses.length === 1 &&
    responses[0] === "code"
  );
}

/**
 * Does one callback have exactly the entry's shape? The raw string must equal
 * `http://<host>:<port><path>` with the port written as canonical decimal
 * inside the entry's range. Comparing parsed URL components alone is not
 * enough: the WHATWG parser maps `LOCALHOST`, `0x7f.1`, escaped hostnames,
 * surrounding whitespace and dot segments onto the same components, and gives
 * a bare `?` or `#` an empty search or hash. The parse is a second check.
 */
export function callbackMatchesEntry(
  uri: unknown,
  redirect: DcrAutoApprovalEntry["redirect"],
): boolean {
  if (typeof uri !== "string") return false;
  const prefix = `http://${redirect.host}:`;
  if (!uri.startsWith(prefix)) return false;
  const rest = uri.slice(prefix.length);
  const slash = rest.indexOf("/");
  if (slash < 1) return false;
  const portText = rest.slice(0, slash);
  if (!/^[1-9][0-9]{0,4}$/.test(portText)) return false;
  const port = Number(portText);
  if (port < redirect.port_min || port > redirect.port_max) return false;
  if (uri !== `http://${redirect.host}:${port}${redirect.path}`) return false;
  let parsed: URL;
  try {
    parsed = new URL(uri);
  } catch {
    return false;
  }
  return (
    parsed.protocol === "http:" &&
    parsed.username === "" &&
    parsed.password === "" &&
    parsed.hostname === redirect.host &&
    parsed.port === portText &&
    parsed.pathname === redirect.path &&
    parsed.search === "" &&
    parsed.hash === ""
  );
}

/** A caller address any entry could match: present, an IP, no zone id. */
function usableCallerIp(callerIp: unknown): callerIp is string {
  return (
    typeof callerIp === "string" &&
    callerIp !== "" &&
    !callerIp.includes("%") &&
    isIP(callerIp) !== 0
  );
}

/**
 * The id of the first entry, in policy order, that a registration matches,
 * or null. Pure. All must hold: the NFC client name equals the entry's
 * exactly; exactly one callback, of the entry's exact shape; a public client
 * (auth method `none`, no secret); grant types a non-empty, duplicate-free
 * subset of authorization_code and refresh_token that includes
 * authorization_code; response types exactly ["code"]; and a caller address
 * inside one of the entry's networks (matchClientIp's `in_list` only).
 */
export function matchDcrAutoApproval(
  policy: DcrAutoApprovalPolicy | null,
  registration: DcrRegistrationForPolicy,
  callerIp: string | undefined,
): string | null {
  if (!policy || policy.entries.length === 0) return null;
  if (!isPublicCodeClient(registration)) return null;
  const uris = registration.redirect_uris;
  if (!Array.isArray(uris) || uris.length !== 1) return null;
  if (typeof registration.client_name !== "string") return null;
  if (!usableCallerIp(callerIp)) return null;
  const name = registration.client_name.normalize("NFC");
  for (const entry of policy.entries) {
    if (name !== entry.client_name) continue;
    if (!callbackMatchesEntry(uris[0], entry.redirect)) continue;
    if (matchClientIp(entry.allowed_cidrs, callerIp) !== "in_list") continue;
    return entry.id;
  }
  return null;
}

export type DcrAutoApprovalDecision =
  | { outcome: "approved"; entryId: string; policyVersion: string }
  | { outcome: "cap"; entryId: string }
  | { outcome: "none" };

/**
 * Decide a `pending`-mode registration against the latched policy, reserving
 * a budget slot synchronously when it matches. The caller runs this before
 * its first `await`, so two concurrent requests cannot both take an entry's
 * last slot. A matched entry whose budget is spent leaves the registration
 * pending; it never falls through to a later entry.
 */
export function decideDcrAutoApproval(
  registration: DcrRegistrationForPolicy,
  callerIp: string | undefined,
): DcrAutoApprovalDecision {
  const policy = getDcrAutoApprovalPolicy();
  const entryId = matchDcrAutoApproval(policy, registration, callerIp);
  if (!policy || entryId === null) return { outcome: "none" };
  const entry = policy.entries.find((candidate) => candidate.id === entryId);
  if (!entry || !reserveSlot(entry, clock())) {
    return { outcome: "cap", entryId };
  }
  return { outcome: "approved", entryId, policyVersion: policy.hash };
}

// ---------------------------------------------------------------------------
// Provenance for the client list
// ---------------------------------------------------------------------------

/**
 * Whether the client list may say a client was approved by policy. True only
 * with positive evidence (`hasPolicyMarker`: the client's successful
 * `oauth.dcr.register` audit row carries a valid `auto_approval` marker and
 * records an approval in pending mode) AND a row that is still an approved
 * self-registration with no approving person. A null approver alone proves
 * nothing: `open`-mode approvals and grandfathered rows look the same. No
 * evidence means unconfirmed provenance, shown as plain "Approved". The flag
 * is display only and never controls authorization.
 */
export function isApprovedByPolicy(
  client: {
    registration_source?: string | null;
    approval_status?: string | null;
    approved_by?: string | null;
  },
  hasPolicyMarker: boolean,
): boolean {
  return (
    hasPolicyMarker === true &&
    client.registration_source === "dcr" &&
    client.approval_status === "approved" &&
    (client.approved_by ?? null) === null
  );
}
