import { AsyncLocalStorage } from "node:async_hooks";
import { createHash } from "node:crypto";

import type { OAuthClient } from "@repo/zod-types";
import type express from "express";

import {
  auditRequestContext,
  clampAuditText,
  clampAuditTextList,
  emit,
} from "@/lib/audit/audit-emitter";
import { describeDbError } from "@/lib/db-error-summary";
import {
  createGuardedFetch,
  type McpUrlGuardOptions,
  NOT_A_PERMITTED_TARGET,
  resolveHost,
  RESPONSE_TOO_LARGE,
} from "@/lib/metamcp/url-guard";
import logger from "@/utils/logger";

import { oauthRepository } from "../../db/repositories";
import {
  checkCimdClientId,
  CIMD_FETCH_TIMEOUT_MS,
  CIMD_MAX_BODY_BYTES,
  CIMD_MAX_CLIENT_ROWS,
  CIMD_MAX_FETCHES_PER_MINUTE,
  CIMD_MAX_IN_FLIGHT,
  CIMD_MAX_STALE_MS,
  CIMD_NEGATIVE_CACHE_MS,
  CIMD_REDIRECT_REFRESH_MIN_INTERVAL_MS,
  CIMD_REFRESH_AFTER_MS,
  CIMD_REFUSAL_AUDIT_MAX_PER_HOUR,
  CIMD_STATE_MAX_ENTRIES,
  isCimdClientAdmitted,
} from "./cimd-config";
import { decodeCimdBody, parseCimdDocument } from "./cimd-document";

/**
 * The client metadata document (CIMD) resolver: turns an allowlisted https
 * client id into an approved `oauth_clients` row of source `cimd`, by fetching
 * the document the id names.
 *
 * Adapted from the fetcher in mcp-use
 * `libraries/typescript/packages/server/src/oauth/proxy/clients.ts` (MIT,
 * Copyright (c) 2025 pietrozullo; same constants: 5 KiB, 10 s, no redirects,
 * a status other than 200 refused). Differences: the fetch goes through this
 * gateway's own guarded transport (pinned addresses, private ranges refused),
 * the cache is the database row, and failures are bounded in every direction.
 *
 * WHO CALLS THIS. Only the authorize endpoint, which reads the client row
 * first and hands it in, so this module never reads the table. The token
 * endpoint never calls it: resolving there would let an unauthenticated token
 * POST trigger a fetch. The token endpoint only re-checks the allowlist.
 *
 * ORDER, AND WHY. The id grammar and the allowlist are decided first, by pure
 * string comparison: an id that is not listed makes no DNS lookup, no
 * connection, no database write and no change to any in-memory state, so an
 * anonymous caller cannot use the authorize endpoint to make this host reach
 * anywhere. Everything after that is cost control for ids that ARE listed: a
 * row is served from the database for an hour, a failure is remembered for a
 * minute, concurrent callers share one fetch, and the process fetches at most
 * 16 at a time and 60 a minute.
 *
 * NO NEW GATE FOR ANYONE. There is no pending queue and no prompt: a listed
 * client is approved by being listed, and an unlisted one is refused.
 */

/** Why a resolution was refused. Fixed strings: audit rows and logs only. */
export type CimdRefusalReason =
  | "invalid_client_id"
  | "not_allowlisted"
  | "busy"
  | "too_many_clients"
  | "http_status"
  | "too_large"
  | "blocked_address"
  | "timeout"
  | "fetch_failed"
  | "not_json"
  | "invalid_document"
  | "not_public_client"
  | "client_id_mismatch"
  | "invalid_redirect_uri"
  | "non_hosted_redirect_uri"
  | "conflict"
  | "store_failed";

export type CimdResolveResult =
  | { ok: true; client: OAuthClient; source: "cache" | "fetched" | "stale" }
  | { ok: false; reason: CimdRefusalReason };

export interface CimdResolveOptions {
  /** The row the caller already read for this client id, or null. */
  existing: OAuthClient | null;
  /** The redirect URI the authorization request asked for. */
  redirectUri: string;
  /** For the audit row's attribution only. */
  req: express.Request;
}

/** Sent so a CDN or WAF that refuses a request with no User-Agent still answers. */
const CIMD_USER_AGENT = "metamcp-oauth-client-metadata-fetcher";
const HOUR_MS = 3_600_000;
const MINUTE_MS = 60_000;

interface Failure {
  reason: CimdRefusalReason;
  /** A later attempt may succeed: a stale stored row may stand in meanwhile. */
  transient: boolean;
  httpStatus?: number;
  detail?: string;
}

type FlightResult =
  | {
      ok: true;
      client: OAuthClient;
      change: "created" | "updated" | "unchanged";
    }
  | { ok: false; failure: Failure };

// ---------------------------------------------------------------------------
// Process state. Every map is bounded; every window uses the injected clock.
// ---------------------------------------------------------------------------

let clock: () => number = () => Date.now();

const negativeCache = new Map<string, { failure: Failure; until: number }>();
const redirectRefreshAt = new Map<string, number>();
const inFlight = new Map<string, Promise<FlightResult>>();
const fetchStartedAt: number[] = [];
const refusalAuditedAt = new Map<string, number>();
let refusalAuditWindow = { start: 0, count: 0 };

/** Insert or refresh, evicting the oldest entries past the bound. */
function setBounded<V>(map: Map<string, V>, key: string, value: V): void {
  map.delete(key);
  map.set(key, value);
  while (map.size > CIMD_STATE_MAX_ENTRIES) {
    const oldest = map.keys().next();
    if (oldest.done) break;
    map.delete(oldest.value);
  }
}

// ---------------------------------------------------------------------------
// Transport: the guarded fetch, built once so pinned agents are reused.
// ---------------------------------------------------------------------------

interface CimdTransport {
  lookup?: McpUrlGuardOptions["lookup"];
  baseFetch?: McpUrlGuardOptions["baseFetch"];
}

let transport: CimdTransport = {};
let guardedFetch: ReturnType<typeof createGuardedFetch> | undefined;

/** Set by the lookup wrapper so a DNS error can be told from a blocked range. */
const dnsOutcome = new AsyncLocalStorage<{ dnsFailed: boolean }>();

function getGuardedFetch(): ReturnType<typeof createGuardedFetch> {
  guardedFetch ??= createGuardedFetch({
    // An EMPTY allowlist, not an omitted one: omitted falls back to
    // MCP_PROXY_URL_ALLOWED_HOSTS, which trusts a listed host by name without
    // resolving or pinning it. A metadata fetch targets an address a document
    // publisher controls and must be checked like any public destination.
    allowedHosts: [],
    // `allowPrivateAddresses` is never set: private, loopback, link-local and
    // metadata ranges are refused, and the socket is pinned to the addresses
    // that were checked.
    maxResponseBytes: CIMD_MAX_BODY_BYTES,
    // This fetcher lives for the whole process. Changing DNS answers must not
    // retain a dispatcher per address set forever, including failed fetches
    // that never create a row and therefore do not count toward the row cap.
    maxPinnedAgents: CIMD_STATE_MAX_ENTRIES,
    followRedirects: false,
    requestTimeoutMs: CIMD_FETCH_TIMEOUT_MS,
    lookup: async (hostname) => {
      try {
        return await (transport.lookup ?? resolveHost)(hostname);
      } catch (error) {
        const state = dnsOutcome.getStore();
        if (state) state.dnsFailed = true;
        throw error;
      }
    },
    baseFetch: transport.baseFetch,
  });
  return guardedFetch;
}

/**
 * Test seams. They sit BELOW the guard (the resolver and the socket), so the
 * guard's own validation always runs on whatever a test feeds it.
 */
export function setCimdTransportForTesting(next: CimdTransport): void {
  transport = next;
  guardedFetch = undefined;
}

export function setCimdClockForTesting(fn: (() => number) | undefined): void {
  clock = fn ?? (() => Date.now());
}

export function resetCimdStateForTesting(): void {
  negativeCache.clear();
  redirectRefreshAt.clear();
  inFlight.clear();
  fetchStartedAt.length = 0;
  refusalAuditedAt.clear();
  refusalAuditWindow = { start: 0, count: 0 };
  transport = {};
  guardedFetch = undefined;
  clock = () => Date.now();
}

/** Entries currently held by each bounded map (test visibility only). */
export function cimdStateSizesForTesting(): {
  negativeCache: number;
  redirectRefreshAt: number;
  refusalAudited: number;
  inFlight: number;
} {
  return {
    negativeCache: negativeCache.size,
    redirectRefreshAt: redirectRefreshAt.size,
    refusalAudited: refusalAuditedAt.size,
    inFlight: inFlight.size,
  };
}

// ---------------------------------------------------------------------------
// The fetch
// ---------------------------------------------------------------------------

type Fetched =
  | { ok: true; bytes: Uint8Array }
  | { ok: false; failure: Failure };

function failureFromError(
  error: unknown,
  state: { dnsFailed: boolean },
): Fetched {
  const message = error instanceof Error ? error.message : "";
  if (message === RESPONSE_TOO_LARGE) {
    return { ok: false, failure: { reason: "too_large", transient: false } };
  }
  if (message === NOT_A_PERMITTED_TARGET) {
    // The guard answers with one oracle-free message for a name that did not
    // resolve and for one that resolved into a refused range. Only the first
    // can heal on its own, so only it is transient.
    return {
      ok: false,
      failure: { reason: "blocked_address", transient: state.dnsFailed },
    };
  }
  if (error instanceof Error && error.name === "AbortError") {
    return { ok: false, failure: { reason: "timeout", transient: true } };
  }
  return { ok: false, failure: { reason: "fetch_failed", transient: true } };
}

async function attemptFetch(
  clientId: string,
  signal: AbortSignal,
  state: { dnsFailed: boolean },
): Promise<Fetched> {
  let response: Response;
  try {
    response = await getGuardedFetch()(clientId, {
      method: "GET",
      headers: { accept: "application/json", "user-agent": CIMD_USER_AGENT },
      signal,
    });
  } catch (error) {
    return failureFromError(error, state);
  }
  try {
    if (response.status !== 200) {
      // Includes every 3xx: a redirect is a refusal, never followed.
      await response.body?.cancel().catch(() => {});
      return {
        ok: false,
        failure: {
          reason: "http_status",
          transient: response.status >= 500 || response.status === 429,
          httpStatus: response.status,
        },
      };
    }
    const declared = Number(response.headers.get("content-length") ?? "0");
    if (Number.isFinite(declared) && declared > CIMD_MAX_BODY_BYTES) {
      await response.body?.cancel().catch(() => {});
      return { ok: false, failure: { reason: "too_large", transient: false } };
    }
    const bytes = new Uint8Array(await response.arrayBuffer());
    // The guard's byte cap errors the stream past the limit; this only guards
    // against a transport that returned more without erroring.
    if (bytes.byteLength > CIMD_MAX_BODY_BYTES) {
      return { ok: false, failure: { reason: "too_large", transient: false } };
    }
    return { ok: true, bytes };
  } catch (error) {
    return failureFromError(error, state);
  }
}

/**
 * One fetch under a total deadline. `requestTimeoutMs` on the transport is an
 * idle timeout (reset on every chunk), so a server that dribbles bytes would
 * hold a slot forever without this. The race also covers DNS, which the
 * abort signal does not reach. Deliberately not `AbortSignal.timeout`, so the
 * deadline can be driven by fake timers.
 */
async function fetchDocument(clientId: string): Promise<Fetched> {
  const state = { dnsFailed: false };
  return dnsOutcome.run(state, async () => {
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const deadline = new Promise<Fetched>((resolve) => {
      timer = setTimeout(() => {
        controller.abort();
        resolve({ ok: false, failure: { reason: "timeout", transient: true } });
      }, CIMD_FETCH_TIMEOUT_MS);
    });
    // attemptFetch never rejects; if the deadline wins the race, its late
    // result is simply dropped.
    const attempt = attemptFetch(clientId, controller.signal, state);
    try {
      return await Promise.race([attempt, deadline]);
    } finally {
      clearTimeout(timer);
    }
  });
}

// ---------------------------------------------------------------------------
// Audit and logging
// ---------------------------------------------------------------------------

function hostOf(clientId: string): string {
  try {
    return new URL(clientId).host;
  } catch {
    return "";
  }
}

function logId(clientId: string): string {
  return JSON.stringify(clientId.slice(0, 200));
}

function emitResolve(
  req: express.Request,
  clientId: string,
  outcome: "success" | "failure" | "denied",
  detail: Record<string, unknown>,
): void {
  const audit = auditRequestContext(req);
  emit({
    actor_type: "anonymous",
    actor_id: null,
    actor_label: null,
    actor_ip: audit.actor_ip,
    actor_user_agent: audit.actor_user_agent,
    action: "oauth.cimd.resolve",
    target_type: "oauth_client",
    target_id: clampAuditText(clientId, 512),
    outcome,
    request_id: audit.request_id,
    http_status: outcome === "success" ? null : 400,
    detail,
  });
}

/**
 * Whether a refusal row may be written now: one per (client id, reason) per
 * hour, and at most CIMD_REFUSAL_AUDIT_MAX_PER_HOUR per hour in the process.
 * `audit_log` has no prune path and the client id is an attacker-chosen
 * string, so both bounds are needed; a refusal past either is logged only.
 */
function mayAuditRefusal(
  clientId: string,
  reason: CimdRefusalReason,
  now: number,
): boolean {
  const key = `${reason}\n${clientId}`;
  const last = refusalAuditedAt.get(key);
  if (last !== undefined && now - last < HOUR_MS) return false;
  if (now - refusalAuditWindow.start >= HOUR_MS) {
    refusalAuditWindow = { start: now, count: 0 };
  }
  if (refusalAuditWindow.count >= CIMD_REFUSAL_AUDIT_MAX_PER_HOUR) return false;
  refusalAuditWindow.count += 1;
  setBounded(refusalAuditedAt, key, now);
  return true;
}

function reportRefusal(
  req: express.Request,
  clientId: string,
  failure: Failure,
  servedStale: boolean,
  now: number,
): void {
  logger.warn(
    `[oauth] client metadata document refused reason=${failure.reason} client=${logId(clientId)}${
      failure.httpStatus === undefined
        ? ""
        : ` upstream_status=${failure.httpStatus}`
    }${servedStale ? " served_stale=true" : ""}`,
  );
  if (!mayAuditRefusal(clientId, failure.reason, now)) return;
  emitResolve(
    req,
    clientId,
    failure.reason === "not_allowlisted" ? "denied" : "failure",
    {
      reason: failure.reason,
      host: hostOf(clientId),
      ...(failure.httpStatus === undefined
        ? {}
        : { http_status: failure.httpStatus }),
      ...(failure.detail === undefined ? {} : { detail: failure.detail }),
      served_stale: servedStale,
    },
  );
}

// ---------------------------------------------------------------------------
// Fetch, validate, store
// ---------------------------------------------------------------------------

function takeFetchSlot(now: number): boolean {
  while (fetchStartedAt.length > 0 && now - fetchStartedAt[0] >= MINUTE_MS) {
    fetchStartedAt.shift();
  }
  if (fetchStartedAt.length >= CIMD_MAX_FETCHES_PER_MINUTE) return false;
  fetchStartedAt.push(now);
  return true;
}

function sameStringList(a: readonly string[], b: readonly string[]): boolean {
  return a.length === b.length && a.every((value, index) => value === b[index]);
}

/** Whether the stored fields that come from the document differ from a fresh draft. */
function documentChanged(
  stored: OAuthClient,
  draft: {
    client_name: string;
    redirect_uris: string[];
    grant_types: string[];
    response_types: string[];
    client_uri?: string | null;
    logo_uri?: string | null;
    tos_uri?: string | null;
    policy_uri?: string | null;
  },
): boolean {
  return (
    stored.client_name !== draft.client_name ||
    !sameStringList(stored.redirect_uris, draft.redirect_uris) ||
    !sameStringList(stored.grant_types, draft.grant_types) ||
    !sameStringList(stored.response_types, draft.response_types) ||
    (stored.client_uri ?? null) !== (draft.client_uri ?? null) ||
    (stored.logo_uri ?? null) !== (draft.logo_uri ?? null) ||
    (stored.tos_uri ?? null) !== (draft.tos_uri ?? null) ||
    (stored.policy_uri ?? null) !== (draft.policy_uri ?? null)
  );
}

async function fetchAndStore(
  clientId: string,
  cimdRow: OAuthClient | null,
  req: express.Request,
  startedAt: number,
): Promise<FlightResult> {
  const fail = (failure: Failure): FlightResult => ({ ok: false, failure });

  // A new id is counted against the row cap BEFORE the fetch, so a refused id
  // costs the third party nothing. The count and the insert are not atomic: a
  // burst of up to CIMD_MAX_IN_FLIGHT new ids can overshoot the cap by that
  // many rows, which is a soft bound by design. Refreshing a row that exists
  // is never blocked by the cap.
  if (cimdRow === null) {
    try {
      if ((await oauthRepository.countCimdClients()) >= CIMD_MAX_CLIENT_ROWS) {
        return fail({ reason: "too_many_clients", transient: false });
      }
    } catch (error) {
      logger.error(
        "[oauth] client metadata row count failed:",
        describeDbError(error),
      );
      return fail({ reason: "store_failed", transient: true });
    }
  }

  if (!takeFetchSlot(startedAt)) {
    return fail({ reason: "busy", transient: true });
  }
  const fetched = await fetchDocument(clientId);
  if (!fetched.ok) return fail(fetched.failure);

  const text = decodeCimdBody(fetched.bytes);
  if (text === null) return fail({ reason: "not_json", transient: false });
  const parsed = parseCimdDocument(text, clientId);
  if (!parsed.ok) {
    return fail({
      reason: parsed.reason,
      transient: false,
      detail: parsed.detail,
    });
  }

  const now = new Date(clock());
  let row: OAuthClient | null;
  try {
    row = await oauthRepository.upsertCimdClient(parsed.client, now);
  } catch (error) {
    // The usual cause is a database that has not applied the migration that
    // admits the 'cimd' source (the CHECK refuses the insert). Nothing was
    // created; the caller is refused with the same generic body as any other
    // failure, and the operator reads this line.
    logger.error(
      `[oauth] client metadata row could not be stored client=${logId(clientId)}:`,
      describeDbError(error),
    );
    return fail({ reason: "store_failed", transient: true });
  }
  if (row === null) {
    // A row of another source owns this id (written between the caller's read
    // and this write). It is never overwritten.
    return fail({ reason: "conflict", transient: false });
  }

  const change: "created" | "updated" | "unchanged" =
    cimdRow === null
      ? "created"
      : documentChanged(cimdRow, parsed.client)
        ? "updated"
        : "unchanged";
  if (change === "unchanged") {
    logger.debug(
      `[oauth] client metadata document unchanged client=${logId(clientId)}`,
    );
  } else {
    // A success row only for a real change, so success rows are bounded by
    // how often a document actually changes. The body is never stored.
    emitResolve(req, clientId, "success", {
      result: change,
      host: hostOf(clientId),
      document_sha256: createHash("sha256").update(fetched.bytes).digest("hex"),
      document_bytes: fetched.bytes.byteLength,
      redirect_uris: clampAuditTextList(parsed.client.redirect_uris, 10, 512),
    });
    logger.info(
      `[oauth] client metadata document ${change} client=${logId(clientId)}`,
    );
  }
  return { ok: true, client: row, change };
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/**
 * Resolve an allowlisted client id to its stored row, fetching the document
 * only when the row is missing, stale, or lacks the requested redirect.
 */
export async function resolveCimdClient(
  clientId: string,
  options: CimdResolveOptions,
): Promise<CimdResolveResult> {
  const { existing, redirectUri, req } = options;
  const now = clock();
  const refused = (reason: CimdRefusalReason): CimdResolveResult => ({
    ok: false,
    reason,
  });

  // 1. The id grammar. Nothing is emitted for an id that is not even
  //    CIMD-shaped.
  if (!checkCimdClientId(clientId).ok) return refused("invalid_client_id");

  // 2. The allowlist, by string comparison alone. Nothing below this line runs
  //    for an unlisted id: no lookup, no connection, no write, no state.
  if (!isCimdClientAdmitted(clientId)) {
    reportRefusal(
      req,
      clientId,
      { reason: "not_allowlisted", transient: false },
      false,
      now,
    );
    return refused("not_allowlisted");
  }

  // A row of another source is never ours to refresh or replace. The
  // authorize handler does not call this for one; kept so a caller that does
  // gets the row back untouched.
  if (existing !== null && existing.registration_source !== "cimd") {
    return { ok: true, client: existing, source: "cache" };
  }

  const cimdRow = existing;
  const updatedAt = cimdRow?.updated_at?.getTime();
  // A row with no recorded update time counts as stale: it is refetched, and
  // is never served stale.
  const ageMs =
    cimdRow !== null && updatedAt !== undefined
      ? now - updatedAt
      : Number.POSITIVE_INFINITY;
  const fresh = cimdRow !== null && ageMs < CIMD_REFRESH_AFTER_MS;
  const canServeStale = cimdRow !== null && ageMs < CIMD_MAX_STALE_MS;

  // 3. A fresh row that already carries the requested redirect needs no fetch.
  if (fresh && cimdRow.redirect_uris.includes(redirectUri)) {
    return { ok: true, client: cimdRow, source: "cache" };
  }

  // 4. A recent failure for this id. A fresh row is still served (authorize
  //    then refuses the redirect itself); a stale one stands in for a
  //    transient failure and never for a hard one.
  const remembered = negativeCache.get(clientId);
  if (remembered !== undefined) {
    if (remembered.until > now) {
      if (fresh) return { ok: true, client: cimdRow, source: "cache" };
      if (remembered.failure.transient && canServeStale) {
        return { ok: true, client: cimdRow, source: "stale" };
      }
      return refused(remembered.failure.reason);
    }
    negativeCache.delete(clientId);
  }

  // 5. A fresh row missing the redirect: refresh at most once per minute per
  //    client, so a client that keeps asking for a callback its document does
  //    not list cannot turn into a fetch per request. A caller arriving during
  //    that refresh must join it below, rather than fail authorization against
  //    the old callback list while the first caller gets the new one.
  if (fresh && !inFlight.has(clientId)) {
    const last = redirectRefreshAt.get(clientId);
    if (
      last !== undefined &&
      now - last < CIMD_REDIRECT_REFRESH_MIN_INTERVAL_MS
    ) {
      return { ok: true, client: cimdRow, source: "cache" };
    }
    setBounded(redirectRefreshAt, clientId, now);
  }

  // 6. Fetch, single-flight per client id.
  let flight = inFlight.get(clientId);
  if (flight === undefined) {
    if (inFlight.size >= CIMD_MAX_IN_FLIGHT) {
      const failure: Failure = { reason: "busy", transient: true };
      const stale = canServeStale;
      reportRefusal(req, clientId, failure, stale, now);
      return stale && cimdRow !== null
        ? { ok: true, client: cimdRow, source: "stale" }
        : refused("busy");
    }
    const started = fetchAndStore(clientId, cimdRow, req, now).then(
      (result) => {
        if (result.ok) {
          negativeCache.delete(clientId);
        } else {
          const failure = result.failure;
          reportRefusal(
            req,
            clientId,
            failure,
            failure.transient && canServeStale,
            now,
          );
          // `busy` describes this process's momentary load, not the document:
          // remembering it would refuse a client for a minute after capacity
          // came back.
          if (failure.reason !== "busy") {
            setBounded(negativeCache, clientId, {
              failure,
              until: clock() + CIMD_NEGATIVE_CACHE_MS,
            });
          }
        }
        return result;
      },
    );
    flight = started.finally(() => {
      inFlight.delete(clientId);
    });
    inFlight.set(clientId, flight);
  }

  const result = await flight;
  if (result.ok) {
    return { ok: true, client: result.client, source: "fetched" };
  }
  if (result.failure.transient && canServeStale && cimdRow !== null) {
    return { ok: true, client: cimdRow, source: "stale" };
  }
  return refused(result.failure.reason);
}
