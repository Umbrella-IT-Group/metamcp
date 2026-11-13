import { isIP } from "node:net";

import logger from "@/utils/logger";

/**
 * Client ID Metadata Documents (CIMD): which clients the gateway will resolve,
 * and the one grammar a client id must satisfy to be resolved at all.
 *
 * Adapted from the client allowlist in mcp-use
 * `libraries/typescript/packages/server/src/oauth/proxy/clients.ts`
 * (commit 546081e8242da1e066417cfec7f8816bb018a14d, `isCimdClientId`,
 * `httpsOrigin` and the allowlist admission rule). The upstream project is
 * MIT licensed, Copyright (c) 2025 pietrozullo. What changed: entries must be
 * canonical (an entry that is not written exactly as the URL parser would
 * print it is dropped, never widened), the id grammar is the strict form used
 * for every fetch (see `checkCimdClientId`), and the allowlist is read from the
 * environment per call.
 *
 * THE DEFAULT IS OFF. `OAUTH_CIMD_ALLOWED_CLIENTS` is empty, so no URL client
 * id is ever resolved, the authorization server metadata does not advertise
 * `client_id_metadata_document_supported`, and every code path below this
 * module is unreachable. Advertising the flag steers every CIMD-capable
 * client to a URL client id instead of registering (the MCP SDK client does
 * not fall back to registration when a URL client id is refused), which is why
 * the flag follows the allowlist and is never a switch of its own.
 */

/** Comma-separated exact client metadata URLs and https origins. */
export const OAUTH_CIMD_ALLOWED_CLIENTS_ENV = "OAUTH_CIMD_ALLOWED_CLIENTS";

/** Longest `client_id` URL the gateway resolves. */
export const CIMD_CLIENT_ID_MAX_LENGTH = 512;
/** Response cap for a metadata document, counted after any decoding. */
export const CIMD_MAX_BODY_BYTES = 5120;
/** Total deadline for one fetch, DNS and body read included. */
export const CIMD_FETCH_TIMEOUT_MS = 10_000;
/** A stored row is served without a fetch for this long after its last fetch. */
export const CIMD_REFRESH_AFTER_MS = 3_600_000;
/** Longest a row is served stale while the document cannot be fetched. */
export const CIMD_MAX_STALE_MS = 86_400_000;
/** A redirect URI missing from a fresh row forces at most one refresh per client in this window. */
export const CIMD_REDIRECT_REFRESH_MIN_INTERVAL_MS = 60_000;
/** A failed id is not fetched again for this long. */
export const CIMD_NEGATIVE_CACHE_MS = 60_000;
/** Bound for every in-memory map in the resolver. */
export const CIMD_STATE_MAX_ENTRIES = 1000;
/** Concurrent fetches, process-wide. */
export const CIMD_MAX_IN_FLIGHT = 16;
/** Fetches per rolling minute, process-wide. */
export const CIMD_MAX_FETCHES_PER_MINUTE = 60;
/** Rows of source `cimd`; a new id past this is refused, a refresh never is. */
export const CIMD_MAX_CLIENT_ROWS = 500;
/** A cimd row with no token, code or marker is swept after this many days. */
export const CIMD_UNUSED_RETENTION_DAYS = 30;
/** Refusal audit rows per hour, shared by `denied` and `failure` rows. */
export const CIMD_REFUSAL_AUDIT_MAX_PER_HOUR = 50;

/**
 * The one body every authorize-time CIMD refusal answers with, whatever the
 * reason. Distinct texts would be an oracle for allowlist membership and for
 * which addresses this host can reach; the reason goes to the audit row and
 * the log instead.
 */
export const CIMD_CLIENT_REFUSED_ERROR = {
  error: "invalid_client",
  error_description: "The client could not be verified.",
} as const;

export type CimdClientIdRefusal =
  | "not_a_string"
  | "length"
  | "unparsable"
  | "not_https"
  | "userinfo"
  | "query_or_fragment"
  | "root_path"
  | "not_canonical"
  | "ip_literal";

export type CimdClientIdCheck =
  | { ok: true; host: string; origin: string }
  | { ok: false; reason: CimdClientIdRefusal };

/**
 * Whether a value is shaped like a client metadata URL: a string that parses
 * as https with a non-root path. Deliberately as broad as the MCP SDK client's
 * own test (`isHttpsUrl` in `client/auth.js`), because it only decides whether
 * the authorize handler considers resolving the id; every id that is resolved
 * then passes `checkCimdClientId`. Never throws.
 */
export function looksLikeCimdClientId(value: unknown): value is string {
  if (typeof value !== "string") return false;
  try {
    const url = new URL(value);
    return url.protocol === "https:" && url.pathname !== "/";
  } catch {
    return false;
  }
}

/**
 * The strict grammar for a client id the gateway will fetch. The id must be
 * exactly what the URL parser would print for it, so a spelling that names the
 * same resource two ways (dot segments, an uppercase host, a default port,
 * unencoded characters, a Unicode host) is one id and not several, and an
 * allowlisted origin cannot be used to mint unlimited ids.
 *
 * Refused: anything over 512 characters, anything but https, userinfo, a
 * query (the draft says SHOULD NOT; refused so `?x=<random>` cannot make
 * unlimited ids under one allowlisted origin), a fragment, the root path, a
 * non-canonical spelling, and an IP-literal host (the document must live on a
 * DNS name).
 *
 * `?` and `#` are tested on the raw string because the URL parser serializes
 * an empty query or fragment (`https://h/x?`, `https://h/x#`) with the mark
 * still present while reporting it as empty.
 */
export function checkCimdClientId(value: unknown): CimdClientIdCheck {
  const refuse = (reason: CimdClientIdRefusal): CimdClientIdCheck => ({
    ok: false,
    reason,
  });
  if (typeof value !== "string") return refuse("not_a_string");
  if (value.length === 0 || value.length > CIMD_CLIENT_ID_MAX_LENGTH) {
    return refuse("length");
  }
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return refuse("unparsable");
  }
  if (url.protocol !== "https:") return refuse("not_https");
  if (url.username !== "" || url.password !== "") return refuse("userinfo");
  if (value.includes("?") || value.includes("#")) {
    return refuse("query_or_fragment");
  }
  if (url.pathname === "/") return refuse("root_path");
  if (url.href !== value) return refuse("not_canonical");
  if (isIP(url.hostname.replace(/^\[|\]$/g, "")) !== 0) {
    return refuse("ip_literal");
  }
  return { ok: true, host: url.host, origin: url.origin };
}

export interface CimdAllowlist {
  /** Exact client metadata URLs (canonical, https, non-root path). */
  urls: ReadonlySet<string>;
  /** https origins: every canonical client id under the origin is admitted. */
  origins: ReadonlySet<string>;
  /** Entries that were not understood and so admit nothing. */
  dropped: readonly string[];
}

/**
 * Parse the allowlist. An entry is an exact client metadata URL or an https
 * origin (with an optional trailing slash). An entry that is not understood is
 * dropped, never widened to something it might have meant: `claude.ai` without
 * a scheme, `http://x`, `https://x/y?z` and a non-canonical spelling all admit
 * nothing.
 *
 * Pure: the caller decides what to log about `dropped`.
 */
export function parseCimdAllowlist(raw: string | undefined): CimdAllowlist {
  const urls = new Set<string>();
  const origins = new Set<string>();
  const dropped: string[] = [];

  for (const entry of (raw ?? "").split(",").map((part) => part.trim())) {
    if (entry === "") continue;
    if (!admitEntry(entry, urls, origins)) dropped.push(entry);
  }
  return { urls, origins, dropped };
}

function admitEntry(
  entry: string,
  urls: Set<string>,
  origins: Set<string>,
): boolean {
  if (entry.length > CIMD_CLIENT_ID_MAX_LENGTH) return false;
  let url: URL;
  try {
    url = new URL(entry);
  } catch {
    return false;
  }
  if (url.protocol !== "https:") return false;
  if (url.username !== "" || url.password !== "") return false;
  if (entry.includes("?") || entry.includes("#")) return false;
  if (isIP(url.hostname.replace(/^\[|\]$/g, "")) !== 0) return false;

  if (url.pathname === "/") {
    // An origin entry: written exactly as the parser prints the origin, once
    // a single trailing slash is set aside.
    if (entry.replace(/\/$/, "") !== url.origin) return false;
    origins.add(url.origin);
    return true;
  }
  if (!checkCimdClientId(entry).ok) return false;
  urls.add(entry);
  return true;
}

let memo: { raw: string; list: CimdAllowlist } | undefined;

/**
 * The allowlist in effect. Read per call and memoized on the raw string, like
 * `resolveDcrAllowedHosts` in ./utils: an operator-set process value that a
 * test can still vary inside one file, parsed (and its dropped entries
 * logged) once per distinct value rather than on every authorize request.
 */
export function getCimdAllowlist(): CimdAllowlist {
  const raw = process.env[OAUTH_CIMD_ALLOWED_CLIENTS_ENV] ?? "";
  if (memo === undefined || memo.raw !== raw) {
    const list = parseCimdAllowlist(raw);
    for (const entry of list.dropped) {
      // JSON-stringified and clamped: the value is operator-set, but it is
      // written to a log line, and an unescaped newline forges whole lines.
      logger.warn(
        `[oauth] ${OAUTH_CIMD_ALLOWED_CLIENTS_ENV} entry ignored (not a canonical https client metadata URL or origin): ${JSON.stringify(entry.slice(0, 200))}`,
      );
    }
    memo = { raw, list };
  }
  return memo.list;
}

/** True when at least one entry is understood. Drives the metadata flag. */
export function isCimdEnabled(): boolean {
  const list = getCimdAllowlist();
  return list.urls.size + list.origins.size > 0;
}

/**
 * Whether a client id is admitted by the allowlist. A pure string comparison:
 * the exact URL, or the id's origin among the origin entries. A non-canonical
 * id is never admitted, whatever origin it names.
 */
export function isCimdClientAdmitted(clientId: unknown): boolean {
  const check = checkCimdClientId(clientId);
  if (!check.ok) return false;
  const list = getCimdAllowlist();
  return list.urls.has(clientId as string) || list.origins.has(check.origin);
}

/**
 * The single kill-switch predicate. A stored `cimd` row whose client id the
 * allowlist no longer admits (the entry was removed, or the list was cleared)
 * is refused by the authorize, consent, decision and token endpoints. Rows of
 * any other source are never judged here.
 */
export function isCimdRowBlocked(
  row: { client_id: string; registration_source?: string | null } | null,
): boolean {
  return (
    row !== null &&
    row.registration_source === "cimd" &&
    !isCimdClientAdmitted(row.client_id)
  );
}

/**
 * The host (with any port) of a client metadata URL, for the consent screen.
 * A row's id was checked when it was stored; the empty string stands in for
 * the impossible unparsable id rather than throwing in a request handler.
 */
export function cimdClientIdHost(clientId: string): string {
  try {
    return new URL(clientId).host;
  } catch {
    return "";
  }
}

/** Forget the memoized allowlist (test seam). */
export function resetCimdConfigForTesting(): void {
  memo = undefined;
}

// The effective state at boot, so an operator can confirm the setting was read
// (not only set) from the startup log.
function logCimdBootState(): void {
  const list = getCimdAllowlist();
  logger.info(
    list.urls.size + list.origins.size === 0
      ? "[oauth] client metadata documents: disabled"
      : `[oauth] client metadata documents: enabled (${list.urls.size} exact, ${list.origins.size} origins)`,
  );
}
logCimdBootState();
