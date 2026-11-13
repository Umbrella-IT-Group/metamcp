import type { DatabaseEndpoint } from "@repo/zod-types";

import { accessGroupsRepository } from "../db/repositories/access-groups.repo";
import { usersRepository } from "../db/repositories/users.repo";

/**
 * Per-endpoint access groups (migration 0033), applied to OAuth sign-ins and to
 * API keys by their owner.
 *
 * WHAT THIS GATE IS FOR. `checkOAuthAccess` in
 * `middleware/api-key-oauth.middleware` admits any authenticated user to any
 * PUBLIC endpoint — that is the whole of its policy for the public case. On an
 * estate that publishes one connector per business system, "you completed an
 * OAuth flow once" therefore meant "you can reach every system on the gateway".
 * This module is the opt-in that narrows it: an endpoint with `restricted` set
 * admits a caller only when that caller is an administrator or belongs to at
 * least one access group mapped to that endpoint.
 *
 * WHO "THAT CALLER" IS. For an OAuth sign-in it is the signed-in user. For an
 * API key it is the key's OWNER: a key held by a person is that person's
 * credential, so it reaches what the person reaches and no more, whether it is
 * scoped to one endpoint or valid gateway-wide. A key that has no owner (a
 * public key, `user_id` null) has nobody whose membership could admit it and is
 * refused on a restricted endpoint. A key owned by an administrator passes, like
 * the administrator would; that is how the service accounts that run
 * automation keep working. Both caller kinds go through the one decision below
 * and share its cache, so an owner's answer is computed once whichever
 * credential asked.
 *
 * `require_scoped_api_key` is a separate switch and is NOT implied by
 * `restricted`. It still refuses gateway-wide keys where an operator turns it
 * on; restricting an endpoint no longer turns it on, because group membership
 * now decides what a key reaches and one key per person has to keep working
 * across every endpoint that person may use.
 *
 * WHY PER-REQUEST AND NOT AT AUTHORIZE TIME. Tokens this gateway issues are
 * gateway-wide: the authorize handler reads no RFC 8707 `resource` and no
 * `audience` (`routers/oauth/authorization.ts`), the granted scope is the fixed
 * string `GRANTED_OAUTH_SCOPE`, and neither `oauth_authorization_codes` nor
 * `oauth_access_tokens` has a column that could hold an endpoint. There is
 * nothing in the flow that knows which endpoint a token will be used against,
 * so a connect-time refusal would have to be invented rather than enforced —
 * and inventing it would mean making the 401 challenge endpoint-specific, which
 * `lib/auth-challenge` deliberately made uniform to close an endpoint-
 * enumeration oracle. The request is the first moment the pair (caller,
 * endpoint) exists, so the request is where the decision is made. A key is no
 * different: its owner is known at validation, the endpoint at routing, and the
 * pair only together.
 *
 * TOOL-LEVEL SCOPING IS OUT OF SCOPE. A group grants or denies a whole
 * endpoint. The supported way to give an audience a narrower tool set is to
 * curate a second namespace and publish a second endpoint over it, which this
 * platform already does — see the README.
 */

/**
 * The refusal, verbatim and deliberately singular.
 *
 * Exported as a constant because it is asserted byte-for-byte in the tests and
 * is the only sentence a denied user ever sees. It names no endpoint, no group
 * and no reason: a caller learns that THIS connector is not theirs, and
 * nothing about what else exists on the gateway or what would have admitted
 * them. Same reasoning as the uniform challenge in `lib/auth-challenge`.
 */
export const ENDPOINT_ACCESS_DENIED_MESSAGE =
  "Permission denied, this connector is not available for you. Please reach out to your administrator.";

/**
 * How long one (user, endpoint) decision is reused.
 *
 * The gate sits on every OAuth-authenticated and every API-key MCP request to a
 * restricted endpoint, and an MCP session is chatty — tools/list, then a call per tool use — so an uncached decision would
 * add two database round trips to each of them. 60 seconds is short enough that
 * an operator who removes someone from a group sees it take effect while they
 * are still watching, and long enough that the steady-state cost of the gate is
 * effectively zero.
 *
 * The TTL is the CEILING on staleness, not the mechanism: every mutation on
 * this surface invalidates immediately (see `invalidateEndpointAccessCache`).
 * The TTL is what still bounds staleness when the mutation happened in a
 * DIFFERENT process — a second replica, or a row changed straight in psql —
 * neither of which can be told to drop an in-memory map.
 */
export const ACCESS_DECISION_TTL_MS = 60 * 1000;

/**
 * Hard ceiling on cached decisions.
 *
 * The key space is (authenticated user) x (endpoint), so it is bounded by the
 * estate rather than by traffic — but "bounded" is not "small" on a gateway
 * with a large directory, and an unbounded Map on the auth path is a memory
 * growth vector that only shows up in production. On overflow the map is
 * cleared outright rather than evicted one entry at a time: losing the cache
 * costs a round trip per key, LRU bookkeeping costs complexity on the hot path,
 * and this ceiling is high enough that reaching it at all is the signal.
 */
export const ACCESS_DECISION_MAX_ENTRIES = 10_000;

interface CachedDecision {
  allowed: boolean;
  expiresAt: number;
  generation: number;
}

const decisionCache = new Map<string, CachedDecision>();

/**
 * Bumped by every mutation that can change an answer. A cached entry carries
 * the generation it was computed at and is ignored once that number moves.
 *
 * A COUNTER RATHER THAN TARGETED EVICTION, and the reason is that targeting is
 * where this kind of cache goes wrong. Deleting the keys a mutation affects
 * means enumerating the cross product of a group's members and its endpoints —
 * a query, at mutation time, whose result is exactly the set that is about to
 * change underneath it, and any member of that set the query misses stays
 * cached as `true` for the rest of the TTL. Over-invalidating cannot be wrong
 * in the direction that matters: the worst case is a cold cache and one extra
 * round trip per key.
 */
let cacheGeneration = 0;

/**
 * Drop every cached decision. Call after ANY access-group or endpoint-gate
 * mutation, on the success path, from the tRPC implementations.
 *
 * SINGLE PROCESS ONLY, stated because it is the honest limit: this clears the
 * map belonging to the process that served the mutation. A second backend
 * replica keeps its own map and converges within `ACCESS_DECISION_TTL_MS`,
 * which is the bound this feature actually promises. Propagating eagerly across
 * replicas needs a shared channel (LISTEN/NOTIFY or a bus) and is not worth
 * standing one up for a 60-second worst case.
 */
export function invalidateEndpointAccessCache(): void {
  cacheGeneration += 1;
  decisionCache.clear();
}

/** Test seam: forget both the entries and the generation counter. */
export function __resetEndpointAccessCacheForTesting(): void {
  decisionCache.clear();
  cacheGeneration = 0;
}

/** Test seam: how many decisions are currently held. */
export function __endpointAccessCacheSizeForTesting(): number {
  return decisionCache.size;
}

/**
 * NUL as the key separator, written as an escape rather than as a literal
 * byte so this file stays plain text and stays reviewable as a diff.
 *
 * It cannot occur in a better-auth user id or in a uuid, which is the
 * property that matters. A printable separator such as `:` would let a
 * crafted id straddle the boundary, so ("a", "b:c") and ("a:b", "c") would
 * produce one key and one user's cached admission would answer for another
 * user's request. That is the classic way a cache key becomes a confused
 * deputy, and on this path it would be an authorization bypass rather than a
 * stale read.
 */
const KEY_SEPARATOR = "\u0000";

function decisionKey(userId: string, endpointUuid: string): string {
  return `${userId}${KEY_SEPARATOR}${endpointUuid}`;
}

function readCachedDecision(key: string): boolean | undefined {
  const entry = decisionCache.get(key);
  if (!entry) return undefined;
  if (entry.generation !== cacheGeneration) {
    decisionCache.delete(key);
    return undefined;
  }
  if (entry.expiresAt <= Date.now()) {
    decisionCache.delete(key);
    return undefined;
  }
  return entry.allowed;
}

/**
 * Store a decision, unless an invalidation landed while it was being computed.
 *
 * `generation` is the value captured BEFORE the queries were issued, and
 * comparing it here is the whole point of the parameter. Stamping
 * `cacheGeneration` as read at write time instead would defeat invalidation in
 * the one window where it matters most: a decision that began before a
 * revocation, and resolved after it, would be written under the NEW generation
 * and would therefore look current for the full TTL. The revoked user would
 * keep being served for a minute by the very mechanism meant to cut them off,
 * and only a request that raced an admin mutation would show it.
 *
 * Discarding the write is the correct remedy rather than a partial one: the
 * next request for this pair misses the cache and re-decides against the
 * committed state. The IN-FLIGHT request still returns the value it computed —
 * it was authorized before the revocation landed and there is nothing to
 * un-decide — which is the same bound any check-then-act authorization has.
 *
 * Same generation-capture guard the connection pools use for their idle
 * sessions (`idleSessionGenerations` in `lib/metamcp/mcp-server-pool.ts`),
 * where an invalidation mid-create means the created client is thrown away
 * rather than stored.
 */
function writeCachedDecision(
  key: string,
  allowed: boolean,
  generation: number,
): void {
  if (generation !== cacheGeneration) return;
  if (decisionCache.size >= ACCESS_DECISION_MAX_ENTRIES) {
    decisionCache.clear();
  }
  decisionCache.set(key, {
    allowed,
    expiresAt: Date.now() + ACCESS_DECISION_TTL_MS,
    generation,
  });
}

/**
 * May this user be served by this endpoint? The user is the signed-in user of
 * an OAuth token, or the owner of an API key (see the header).
 *
 * Returns `true` immediately for an endpoint that has not opted in, WITHOUT
 * touching the cache or the database. That early return is what makes this
 * feature inert at cutover: with no endpoint flagged, the gate costs one
 * boolean read per request and changes nothing.
 *
 * ADMINISTRATORS BYPASS. An administrator can already flip `restricted` off,
 * create a group and add themselves to it, so refusing them here would protect
 * nothing and would lock the operator out of their own gateway while they were
 * still drawing the groups up — the exact failure this feature was required not
 * to have. The role is read fresh from the database rather than from the token,
 * for the same reason `usersRepository.isDisabled` is: a token minted before a
 * demotion must not keep carrying the old role. "Fresh" is bounded by the
 * decision cache: a role change does not invalidate it (only access-group and
 * endpoint-gate writes do), so a demoted administrator's token or key keeps
 * passing a restricted endpoint for up to `ACCESS_DECISION_TTL_MS` in each
 * backend process. That bound is stated, tested, and not an instant revocation;
 * a disabled account is a separate check made on every request and is not
 * affected by it.
 *
 * FAILS CLOSED. A database error while deciding produces a refusal, not an
 * admission. That is the opposite of the choice made for `restricted` itself
 * (whose default is false, i.e. open), and the two are consistent: an endpoint
 * nobody switched on should behave as it always has, but an endpoint an
 * operator DID switch on must not fall open because a query failed. The throw
 * is not swallowed here — it propagates to the middleware's own catch, which
 * answers 500 rather than serving the request.
 */
export async function isUserAllowedOnEndpoint(
  userId: string,
  endpoint: Pick<DatabaseEndpoint, "uuid" | "restricted">,
): Promise<boolean> {
  if (!endpoint.restricted) return true;

  const key = decisionKey(userId, endpoint.uuid);
  const cached = readCachedDecision(key);
  if (cached !== undefined) return cached;

  // Captured BEFORE the queries are issued, never after: an invalidation that
  // lands while they are in flight has to be able to discard the result. See
  // writeCachedDecision.
  const generation = cacheGeneration;

  // Concurrent rather than sequential: neither answer depends on the other, and
  // this runs on a request that is otherwise idle waiting on the database.
  const [role, hasGrant] = await Promise.all([
    usersRepository.findRoleById(userId),
    accessGroupsRepository.hasEndpointGrant(userId, endpoint.uuid),
  ]);

  const allowed = role === "admin" || hasGrant;
  writeCachedDecision(key, allowed, generation);
  return allowed;
}

/**
 * The name this decision had while it governed OAuth sign-ins only. Kept as an
 * alias so the OAuth call sites and their tests keep reading as they did.
 */
export const isOAuthUserAllowedOnEndpoint = isUserAllowedOnEndpoint;

/**
 * How long one reported denial suppresses the next report for the same
 * (principal, endpoint) pair. The principal is a user id for an OAuth caller
 * and `key:<key uuid>` for an API key, so a key is throttled on its own and a
 * key id can never be mistaken for a user id (`:` does not occur in either id
 * format).
 *
 * WHY THROTTLE AT ALL. `audit_log` has BEFORE UPDATE / DELETE / TRUNCATE
 * triggers and deliberately no prune path (migration 0028), so every row
 * written to it is permanent. A refused MCP client does not stop — connectors
 * retry, and a misconfigured one retries in a tight loop — which makes a
 * per-attempt emit on this path a write-amplification primitive that the
 * REFUSED caller controls the rate of. That is the same reasoning
 * `reportAuditWriteFailure` and `warnUnauthenticatedEndpoint` already apply to
 * their log lines; the difference is that this one writes to a table nobody can
 * delete from.
 *
 * WHAT IS NOT LOST. Suppressed attempts are COUNTED and the count rides on the
 * next row that is written, so volume survives the throttle even though
 * per-attempt timestamps do not. "Denied once" and "denied 4,000 times in the
 * last minute" remain distinguishable, which is the question a responder
 * actually asks of this event.
 *
 * PER PAIR, not global: one caller hammering one endpoint must not suppress the
 * first denial of a different caller on a different endpoint, which would be
 * exactly the row worth seeing. Two keys of one owner are two callers here.
 */
export const ACCESS_DENIAL_REPORT_INTERVAL_MS = 60 * 1000;

/** Same ceiling reasoning as the decision cache; same clear-on-overflow. */
export const ACCESS_DENIAL_THROTTLE_MAX_ENTRIES = 10_000;

interface DenialThrottleEntry {
  reportedAt: number;
  suppressed: number;
}

const denialThrottle = new Map<string, DenialThrottleEntry>();

/**
 * Should this denial be written down, and how many were swallowed since the
 * last one that was?
 *
 * Stateful: calling it RECORDS the attempt. The caller emits when `emit` is
 * true and does nothing otherwise. Kept here rather than in the middleware so
 * the policy is unit-testable without an express harness, while the audit
 * envelope stays with the other emitters in `middleware/api-key-oauth`.
 */
export function recordAccessDenial(
  principal: string,
  endpointUuid: string,
): { emit: boolean; suppressed: number } {
  const key = decisionKey(principal, endpointUuid);
  const now = Date.now();
  const entry = denialThrottle.get(key);

  if (entry && now - entry.reportedAt < ACCESS_DENIAL_REPORT_INTERVAL_MS) {
    entry.suppressed += 1;
    return { emit: false, suppressed: entry.suppressed };
  }

  if (denialThrottle.size >= ACCESS_DENIAL_THROTTLE_MAX_ENTRIES) {
    denialThrottle.clear();
  }
  const suppressed = entry?.suppressed ?? 0;
  denialThrottle.set(key, { reportedAt: now, suppressed: 0 });
  return { emit: true, suppressed };
}

/** Test seam for the throttle map. */
export function __resetAccessDenialThrottleForTesting(): void {
  denialThrottle.clear();
}
