import { randomUUID } from "node:crypto";

import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import express from "express";

import { mcpSessionsRepository } from "@/db/repositories/mcp-sessions.repo";
import {
  ApiKeyAuthenticatedRequest,
  authenticateApiKey,
} from "@/middleware/api-key-oauth.middleware";
import { lookupEndpoint } from "@/middleware/lookup-endpoint-middleware";
import { rateLimitMiddleware } from "@/middleware/rate-limit.middleware";
import logger from "@/utils/logger";

import { isAdminHealthRequest } from "../../lib/health-upstream";
import { runWithM365UserContext } from "../../lib/m365/request-context";
import {
  resolveCallerContext,
  stampCallerContext,
} from "../../lib/metamcp/caller-context";
import { runWithCallerContext } from "../../lib/metamcp/caller-context-store";
import { resolveClientIdentity } from "../../lib/metamcp/consumer-identity-resolver";
import {
  checkConcurrentSessionCeiling,
  registerSessionCounter,
} from "../../lib/metamcp/credential-session-quota";
import {
  GATEWAY_BOOT_ID,
  GATEWAY_CAPABILITY_HASH,
  shouldRefuseRecovery,
} from "../../lib/metamcp/gateway-boot-id";
import { metamcpLogStore } from "../../lib/metamcp/log-store";
import { metaMcpServerPool } from "../../lib/metamcp/metamcp-server-pool";
import {
  AuthMethod,
  hashAuthPrincipal,
  principalMatches,
  resolveSessionIdentity,
} from "../../lib/metamcp/session-auth";
import {
  emitSessionBindingDenial,
  extractPresentedCredential,
  type SessionDenialReason,
} from "../../lib/metamcp/session-binding-denial";
import {
  assertRecoveryHydrationContract,
  hydrateRecoveredTransport,
} from "../../lib/metamcp/transport-recovery-hydration";
import {
  bindingMatches,
  boundSessionMatches,
  classifyBindingDenial,
  SessionBinding,
  SessionLifetimeManagerImpl,
} from "../../lib/session-lifetime-manager";
import { PublicSessionSweeper } from "./public-session-sweeper";

/**
 * The full binding a request presents: the endpoint it is targeting plus the
 * identity of the credential `authenticateApiKey` resolved for it. Built once
 * per guard so the endpoint pair and the identity can never be read from two
 * different requests.
 */
function requestBinding(authReq: ApiKeyAuthenticatedRequest): SessionBinding {
  return {
    namespaceUuid: authReq.namespaceUuid,
    endpointName: authReq.endpointName,
    identity: resolveSessionIdentity(authReq),
  };
}

/**
 * Resolve a session's transport ONLY for the endpoint the session belongs to
 * AND the credential that created it. The in-memory `sessionManager` is keyed
 * by `Mcp-Session-Id` alone, so a bare `getSession(sessionId)` will happily
 * hand one caller's transport to another — endpoint A's transport to a key
 * authenticated for endpoint B, or, on any endpoint reachable by more than one
 * credential, consumer A's live session to consumer B. `/health/sessions` used
 * to publish every live session id, making the id trivially guessable.
 *
 * This is the request-path twin of the defenses `recoverPersistedSession` has
 * always applied to the DB row: namespace_uuid + endpoint_name must match, and
 * the credential must be the one the session was opened with. The in-memory
 * fast path — which serves every request after the first — checked only the
 * first half.
 *
 * THREE outcomes, and the split between the last two is the load-bearing part:
 *
 *  - `ok` — serve it.
 *  - `absent` — nothing resident under this id. The caller falls through to
 *    lazy recovery, which may legitimately rebuild the session from
 *    `mcp_sessions`.
 *  - `refused` — a session IS resident but is not this caller's. The caller
 *    answers 404 DIRECTLY and never attempts recovery. Falling through would
 *    reach `recoverPersistedSession`, whose principal check fails and returns
 *    `auth_failed` -> 401, which both breaks the spec's re-initialize contract
 *    (a client is told to fix its credential, not to start a new session) and
 *    tells the caller that the id it presented is real and belongs to someone
 *    else. The route funnels `refused` into the same 404 statement as a
 *    genuine miss, so the response CONTENT cannot distinguish them.
 *
 * Content, not timing: `refused` returns from memory while a genuine miss
 * spends a `mcpSessionsRepository.findById` round trip, so the two remain
 * separable by latency. That is left open on purpose — closing it would mean
 * burning a pointless query on every refusal, and the oracle it leaves is
 * worth nothing against `randomUUID` session ids, which an attacker has to
 * hold before the timing difference tells them anything.
 */
export type BoundSessionResolution =
  | { outcome: "ok"; transport: StreamableHTTPServerTransport }
  | { outcome: "absent" }
  | { outcome: "refused" };

export function resolveBoundSession(
  sessionId: string,
  authReq: ApiKeyAuthenticatedRequest,
): BoundSessionResolution {
  const transport = sessionManager.getSession(sessionId);
  if (!transport) {
    return { outcome: "absent" };
  }
  const binding = sessionManager.getSessionBinding(sessionId);
  const target = requestBinding(authReq);
  if (!boundSessionMatches(binding, target)) {
    refuseBoundSession(
      sessionId,
      authReq,
      classifyBindingDenial(binding, target),
    );
    return { outcome: "refused" };
  }
  return { outcome: "ok", transport };
}

/**
 * Record a refused session reuse — one durable audit row and one warn line,
 * both under the SAME throttle decision.
 *
 * The log line is throttled alongside the row rather than written per attempt
 * for the reason the row is: this is output a REFUSED caller paces, and a warn
 * per attempt turns an id-enumeration sweep into a log flood that buries the
 * first line, which is the one worth reading. The suppressed count rides along
 * so volume survives.
 *
 * Every refusal leg funnels through here so the reason recorded and the reason
 * logged cannot disagree.
 */
function refuseBoundSession(
  sessionId: string,
  authReq: ApiKeyAuthenticatedRequest,
  reason: SessionDenialReason,
): void {
  const { emitted, suppressed } = emitSessionBindingDenial(authReq, {
    sessionId,
    reason,
  });
  if (emitted) {
    logger.warn(
      `Session ${sessionId} presented on endpoint ${authReq.endpointName} ` +
        `refused (${reason}) — treating as not found. ` +
        `${suppressed} similar refusal(s) suppressed since the last line.`,
    );
  }
}

/**
 * Ownership guard for the DELETE leg, extracted as a pure resolver (the
 * teardown twin of `resolveBoundSession`): only the endpoint AND the
 * credential that own a session may tear it down. Without it a key scoped to
 * endpoint A could DELETE endpoint B's live session AND its persisted recovery
 * row (`cleanupSession` deletes the row), and any second credential on the
 * SAME endpoint could do the same to a sibling consumer — a denial of service
 * that needs nothing but a session id.
 *
 * Checks the in-memory binding first through `boundSessionMatches` (endpoint +
 * creating identity). If the session isn't resident, the persisted row is the
 * only evidence, so the check is the one that row can support: the endpoint
 * pair via `bindingMatches`, plus the same `auth_method` + `auth_principal`
 * comparison `recoverPersistedSession` makes. Verifying the endpoint alone
 * there would leave the hole open for exactly the sessions the idle sweeper
 * has already reaped, whose rows survive by design.
 *
 * A lookup failure is treated as absent — fail-closed, never delete on unknown
 * state. Every non-deletable case collapses into the ONE `not_found` outcome,
 * so the route's single 404 response cannot reveal that the id is live and
 * owned by someone else.
 *
 * THE TWO BRANCHES DEFINE "SAME PRINCIPAL" DIFFERENTLY, and that asymmetry is
 * accepted rather than accidental. In memory an OAuth session is bound to the
 * USER id, so a connector that refreshed its 24h access token still owns its
 * session. The persisted row cannot offer that: `mcp_sessions` stores only
 * `auth_principal` (a one-way hash of the token) and `auth_method` — there is
 * no user column to compare, and a user id is not recoverable from a SHA-256
 * digest. So a rotated OAuth token cannot tear down its own session once the
 * idle sweeper has reaped it: the DELETE answers 404 and the row survives to
 * the `MCP_SESSION_TTL_DAYS` pruner. That is the same rule
 * `recoverPersistedSession` has always applied — token rotation invalidates
 * the recovery path, by design, so a revoked token cannot survive a restart —
 * and the cost here is a lingering row plus a 404 on a teardown, never a live
 * session left reachable by the wrong caller. Widening it would mean storing
 * the user id alongside the hash, which is a schema change and a new thing to
 * keep in sync, for a case whose worst outcome is one row aging out.
 */
export async function resolveDeletableSession(
  sessionId: string,
  authReq: ApiKeyAuthenticatedRequest,
): Promise<{ outcome: "deletable" } | { outcome: "not_found" }> {
  const target = requestBinding(authReq);
  const inMemoryTransport = sessionManager.getSession(sessionId);
  if (inMemoryTransport) {
    const binding = sessionManager.getSessionBinding(sessionId);
    if (!boundSessionMatches(binding, target)) {
      refuseBoundSession(
        sessionId,
        authReq,
        classifyBindingDenial(binding, target),
      );
      return { outcome: "not_found" };
    }
    return { outcome: "deletable" };
  }

  let stored;
  try {
    stored = await mcpSessionsRepository.findById(sessionId);
  } catch (lookupError) {
    logger.warn(
      `mcp_sessions lookup failed during DELETE for session ${sessionId}; treating as not found.`,
      lookupError,
    );
    stored = null;
  }
  if (
    !stored ||
    !bindingMatches(
      {
        namespaceUuid: stored.namespace_uuid,
        endpointName: stored.endpoint_name,
      },
      target,
    )
  ) {
    return { outcome: "not_found" };
  }
  const rawToken = extractPresentedCredential(authReq, authReq.endpoint);
  if (
    !rawToken ||
    stored.auth_method !== authMethodFromRequest(authReq) ||
    !principalMatches(
      hashAuthPrincipal(rawToken, authMethodFromRequest(authReq)),
      stored.auth_principal,
    )
  ) {
    refuseBoundSession(
      sessionId,
      authReq,
      "session_persisted_credential_mismatch",
    );
    return { outcome: "not_found" };
  }
  return { outcome: "deletable" };
}

const streamableHttpRouter = express.Router();

// Session lifetime manager for StreamableHTTP sessions
const sessionManager =
  new SessionLifetimeManagerImpl<StreamableHTTPServerTransport>(
    "StreamableHTTP",
  );

// Register as a source of live-session counts for the per-credential
// concurrent-session ceiling. The ceiling sums across every registered manager
// (this one plus the SSE manager), so a credential's session budget spans both
// transports rather than being per-transport.
registerSessionCounter(sessionManager);

// Idle-TTL sweeper for public-endpoint sessions. This reaps on a DIFFERENT
// axis than the age-based `sessionManager.startCleanupTimer` below: last
// request IDLE time, not session CREATION age. The age-based timer keys off
// `configService.getSessionLifetime()`, which is null in prod (persistent
// sessions never expire) so it never fires — that is exactly why public
// sessions accumulated to backend-pool exhaustion (the 2026-07-14 pool-cap
// outage). The sweeper reuses `reapIdleSession` (defined below) — a
// ROW-PRESERVING cleanup variant, NOT the same variant a client DELETE uses
// (`cleanupSession`, which also drops the `mcp_sessions` row). See
// `reapIdleSession`'s own doc comment for why that distinction is load-
// bearing. `measureActiveConnections` samples the backend pool's active
// count so a sweep can report how many connections it released.
// Exported for testing — `streamable-http.test.ts` uses this to seed/
// inspect tracking state directly (e.g. asserting `dispatchTracked` holds
// a session in-flight for the duration of a simulated open GET stream).
// The router itself never imports this from outside the module.
export const publicSessionSweeper = PublicSessionSweeper.fromEnv(
  "StreamableHTTP",
  {
    reapSession: (sessionId: string) => reapIdleSession(sessionId),
    measureActiveConnections: () =>
      metaMcpServerPool.getMcpServerPoolStatus().active,
  },
);

/**
 * Run the transport dispatch while marking the session in-flight so the
 * idle-TTL sweeper never reaps it mid-request (a long tool call that
 * outlives the idle TTL is live use, not idleness). markInFlight /
 * markSettled also stamp last-activity at request arrival + completion,
 * which is how "any request updates the stamp" is satisfied.
 *
 * Known blind spot (NARROWED by the SDK 1.30.0 bump, not proven closed):
 * the GET handler below uses this same wrapper to serve a standalone SSE
 * stream (a client opens a long-lived GET with no body to receive
 * server-initiated notifications per the MCP Streamable HTTP spec).
 * `handleRequestWithUserContext`'s promise doesn't resolve until that
 * stream closes, so `markInFlight` is called once at stream-open and
 * `markSettled` only fires when the stream ends — for as long as the
 * promise is pending, the sweeper's in-flight guard correctly treats the
 * session as live. If the CLIENT dies without a clean TCP close (process
 * killed, network path silently drops packets — no FIN/RST reaches this
 * process), Node cannot know the peer is gone without OS-level keepalive
 * probing or an app-level heartbeat.
 *
 * SDK 1.30.0 ships the app-level half: `WebStandardStreamableHTTPServerTransport`
 * arms an unref'd interval per SSE stream that writes a `: keepalive`
 * comment frame every `keepAliveMs` (public transport option, DEFAULT
 * 15000; values < 1 disable it). We inherit that default at every
 * construction site — see `sdk-sse-keepalive.test.ts` for the tripwire
 * that fails if a later SDK bump changes or drops it. Because those writes
 * push bytes at a peer that is gone, the kernel's retransmit timer
 * eventually errors the socket, which cancels the stream, settles the
 * pending dispatch, and lets the sweeper reap.
 *
 * Why "narrowed" and not "fixed": that chain is inferred from the SDK
 * source, NOT runtime-verified against a real half-open connection, and it
 * only fires on the kernel retransmit timescale (`tcp_retries2`, order of
 * 15 minutes) rather than on a heartbeat-miss threshold. A write that
 * merely buffers in the stream's internal queue without reaching the
 * socket would still surface nothing. Residual follow-up (not this PR):
 * `SO_KEEPALIVE` on the underlying socket, or a fork-side missed-heartbeat
 * threshold that force-settles the dispatch on our own clock instead of
 * the kernel's.
 */
export async function dispatchTracked(
  authReq: ApiKeyAuthenticatedRequest,
  transport: StreamableHTTPServerTransport,
  req: express.Request,
  res: express.Response,
  sessionId: string,
  clientName?: string,
): Promise<void> {
  publicSessionSweeper.markInFlight(sessionId);
  try {
    // Enter the request-scoped caller binding for the whole dispatch, so the
    // auditing middleware attributes this call to THIS request rather than to
    // whichever request last stamped the pooled handler context. Every
    // Streamable-HTTP tool call reaches the transport through here, which is
    // what makes the store the authoritative source rather than a best-effort
    // one. See `lib/metamcp/caller-context-store`.
    await runWithCallerContext(
      { ...resolveCallerContext(authReq), clientName },
      () => handleRequestWithUserContext(authReq, transport, req, res),
    );
  } finally {
    publicSessionSweeper.markSettled(sessionId);
  }
}

/**
 * Dispatch a transport request inside the M365 request-scoped user
 * context (AsyncLocalStorage). The context carries a better-auth user id
 * down through the proxy and pooled backend client into the M365
 * injected fetch, which mints and stamps that user's Graph access token
 * onto the backend request. No-op for servers without delegated
 * injection. See `lib/m365/request-context.ts`.
 *
 * Identity sources, in precedence order:
 *  1. OAuth — the authenticated human's own id (unchanged behavior; a
 *     token is user-bound, so the gateway knows exactly who is calling).
 *  2. API key with an admin-bound acts-as identity
 *     (`api_keys.acts_as_user_id`, migration 0024) — the request runs as
 *     that user. This is an EXPLICIT, admin-set, creation-time binding,
 *     and the create path enforces its pairing with PR #84's endpoint
 *     scoping (an identity-bound key must be scoped to exactly one
 *     endpoint), which is what contains the acted-as identity.
 *  3. Anything else — including every API key WITHOUT a binding — runs
 *     with NO context, so the injected fetch fail-closes (no
 *     Authorization header) rather than ever acting as someone.
 *
 * DELIBERATE non-goal: this gate exists ONLY on the streamable-http
 * transport. `sse.ts` and the OpenAPI bridge never populate an m365 user
 * context — delegated identity over SSE/OpenAPI stays fail-closed BY
 * DESIGN (pinned by test); do not add an acts-as branch there without a
 * new security review.
 */
function handleRequestWithUserContext(
  authReq: ApiKeyAuthenticatedRequest,
  transport: StreamableHTTPServerTransport,
  req: express.Request,
  res: express.Response,
): Promise<void> {
  const context =
    authReq.authMethod === "oauth" && authReq.oauthUserId
      ? { userId: authReq.oauthUserId }
      : authReq.authMethod === "api_key" && authReq.apiKeyActsAsUserId
        ? { userId: authReq.apiKeyActsAsUserId }
        : undefined;
  return runWithM365UserContext(context, () =>
    transport.handleRequest(req, res),
  );
}

/**
 * Map the auth method recorded by the middleware (`api_key` | `oauth`)
 * back to the lazy-session-recovery AuthMethod enum. Keeps the call
 * sites tight and lets the hashing layer stay independent of express
 * request shape.
 */
function authMethodFromRequest(req: ApiKeyAuthenticatedRequest): AuthMethod {
  return req.authMethod === "oauth" ? "oauth" : "api_key";
}

// Fail-loud at boot if the SDK internals the recovery hydration depends
// on changed shape across an upgrade. See transport-recovery-hydration.ts.
assertRecoveryHydrationContract();

/**
 * Lazy-recover an in-memory transport for a sessionId that's missing
 * from `sessionManager` but persisted in `mcp_sessions`. Used by the
 * POST + GET handlers below before returning the existing 404 / 401
 * envelopes.
 *
 * Returns:
 *   - `{ status: "recovered", transport }` — caller forwards the
 *     request to the rebuilt transport. The DB row's last_seen_at has
 *     already been touched.
 *   - `{ status: "auth_failed" }` — the stored auth principal doesn't
 *     match the incoming credential. Caller returns 401.
 *   - `{ status: "not_found" }` — no DB row OR the row's namespace
 *     doesn't match the requested endpoint (cross-namespace replay
 *     attempt). Caller returns the existing 404.
 *
 * The recovered transport is added to `sessionManager` so subsequent
 * requests in the same metamcp lifetime skip the DB hop entirely.
 */
export async function recoverPersistedSession(
  sessionId: string,
  authReq: ApiKeyAuthenticatedRequest,
): Promise<
  | { status: "recovered"; transport: StreamableHTTPServerTransport }
  | { status: "auth_failed" }
  | { status: "not_found" }
> {
  let stored;
  try {
    stored = await mcpSessionsRepository.findById(sessionId);
  } catch (error) {
    // DB error during recovery is a hard miss — fall through to the
    // existing 404 path. Logged so post-mortem can correlate with
    // postgres availability events; this is operational noise, not
    // a security event.
    logger.error(
      `mcp_sessions lookup failed for session ${sessionId}; treating as not-found.`,
      error,
    );
    return { status: "not_found" };
  }
  if (!stored) {
    return { status: "not_found" };
  }
  // Cross-namespace replay defense: the session must belong to the
  // namespace + endpoint the request is targeting. The DB row could
  // be stale-but-not-yet-pruned, and a different consumer with a
  // valid credential for endpoint B should not be able to reclaim
  // a session that was created against endpoint A. Routed through
  // `bindingMatches` — the SAME endpoint predicate `boundSessionMatches`
  // is built on and `resolveDeletableSession`'s persisted branch uses —
  // so the endpoint check exists exactly once file-wide and cannot drift
  // between the legs. The credential half of this path's guard is the
  // `auth_method` + `auth_principal` comparison further down.
  if (
    !bindingMatches(
      {
        namespaceUuid: stored.namespace_uuid,
        endpointName: stored.endpoint_name,
      },
      {
        namespaceUuid: authReq.namespaceUuid,
        endpointName: authReq.endpointName,
      },
    )
  ) {
    return { status: "not_found" };
  }

  // PR #22 + PR #23: capability-cache mismatch defense across gateway
  // restarts. MCP `initialize` negotiates server capabilities once per
  // session. When metamcp is upgraded with new capabilities (e.g., PR
  // #19's `tools: { listChanged: true }`), pre-upgrade rows in
  // `mcp_sessions` carry stamps from the prior process. Recovering
  // them hands the client a transport whose negotiated capability set
  // doesn't match what the current process advertises — clients with
  // cached `listChanged: false` silently ignore the new
  // `notifications/tools/list_changed` we now emit, leaving stale tool
  // surfaces.
  //
  // PR #22 used `gateway_boot_id` alone as the refusal trigger. That
  // forced a client re-initialize on every metamcp restart, including
  // capability-neutral restarts (OAuth fixes, dep bumps, transport
  // tweaks). The Anthropic MCP connector doesn't honor the spec's
  // HTTP-404 → start-new-session contract (already documented in
  // UMBRELLA_FORK.md for PR #18); it wraps the 404 +
  // `Mcp-Session-Reinitialize-Required` response as
  // `-32600 "Anthropic Proxy: Invalid content from server"` and breaks
  // claude.ai sessions until manual `/mcp reconnect`.
  //
  // PR #23 narrows the refusal: refuse only when the stored boot_id
  // differs AND the stored capability_hash also differs. Two metamcp
  // processes built from the same source declare identical capabilities
  // (baked into `new Server({...})`) and therefore produce identical
  // hashes — recovery is safe across same-image restarts.
  // `shouldRefuseRecovery` encodes the full truth table (see
  // `gateway-boot-id.ts` for the decision matrix and null-branch
  // handling for pre-PR-22 / PR #22-only rows).
  if (
    shouldRefuseRecovery(
      {
        gateway_boot_id: stored.gateway_boot_id,
        capability_hash: stored.capability_hash,
      },
      { bootId: GATEWAY_BOOT_ID, capabilityHash: GATEWAY_CAPABILITY_HASH },
    )
  ) {
    logger.info(
      `Lazy recovery: refusing recovery for session ${sessionId} — ` +
        `stored boot_id=${stored.gateway_boot_id} (current ${GATEWAY_BOOT_ID}), ` +
        `stored capability_hash=${stored.capability_hash} (current ${GATEWAY_CAPABILITY_HASH}). ` +
        `Capability set changed across restart; client must re-initialize.`,
    );
    return { status: "not_found" };
  }

  const rawToken = extractPresentedCredential(authReq, authReq.endpoint);
  if (!rawToken) {
    return { status: "auth_failed" };
  }
  const currentMethod = authMethodFromRequest(authReq);
  // The auth method must also match — a session created with an API
  // key can't be reclaimed with a Bearer token (and vice versa).
  if (stored.auth_method !== currentMethod) {
    return { status: "auth_failed" };
  }
  const candidate = hashAuthPrincipal(rawToken, currentMethod);
  if (!principalMatches(candidate, stored.auth_principal)) {
    return { status: "auth_failed" };
  }

  // Auth + scope match. Rebuild the transport with the stored sessionId
  // so the consumer's cached id stays valid across the rebuild.
  const mcpServerInstance = await metaMcpServerPool.getServer(
    sessionId,
    stored.namespace_uuid,
  );
  if (!mcpServerInstance) {
    logger.error(
      `Lazy recovery: failed to acquire MetaMCP server instance for namespace ${stored.namespace_uuid} (session ${sessionId}).`,
    );
    return { status: "not_found" };
  }
  // Re-stamp the consumer identity onto the rebuilt instance's context so
  // post-restart tool calls stay attributed (the registry/in-memory state is
  // gone after a restart; authReq is the re-validated current caller).
  const recoveredIdentity = await resolveClientIdentity(authReq);
  stampCallerContext(
    mcpServerInstance.handlerContext,
    authReq,
    recoveredIdentity?.name,
  );
  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: () => sessionId,
    onsessioninitialized: async (sid) => {
      logger.info(
        `Lazy-recovered session re-initialized for sessionId: ${sid}`,
      );
    },
  });
  await mcpServerInstance.server.connect(transport);

  // Restore the SDK session state the (skipped) `initialize` handshake
  // would have set. Without this the rebuilt transport stays
  // `_initialized=false` and rejects the client's first request with
  // 400 {-32000 "Server not initialized"} → relayed as -32600. See
  // `hydrateRecoveredTransport` for the full rationale.
  if (!hydrateRecoveredTransport(transport, sessionId)) {
    // SDK internal shape changed — don't cache a transport we can't
    // prove is serviceable. Fall back to the 404 reinit path.
    await transport
      .close()
      .catch((error: unknown) =>
        logger.warn(
          `Failed to close un-hydratable recovered transport for session ${sessionId}.`,
          error,
        ),
      );
    return { status: "not_found" };
  }
  // Bind the recovered session to its endpoint and to the caller. The row
  // already passed the namespace_uuid + endpoint_name match AND the
  // auth_method + auth_principal comparison above, so this request's endpoint
  // and identity ARE the session's true binding — record them so subsequent
  // in-memory lookups go through the same check as the fresh-session path.
  // Recording the recovering caller's identity is not a rebind: recovery is
  // only reached with the credential whose hash the row already stores.
  sessionManager.addSession(sessionId, transport, requestBinding(authReq));
  // Resume idle-TTL tracking for the recovered session. Required whether
  // this recovery followed a sweep reap (the reap's forget() dropped
  // tracking; without this the recovered session would never be
  // TTL-swept again if abandoned a second time) or a gateway restart (the
  // sweeper's in-memory map is empty after boot regardless of cause).
  // beginTracking() is the unconditional seed — see its doc comment for
  // why touch()/markInFlight() further down (in dispatchTracked) are
  // deliberately guarded and would no-op here without this call.
  publicSessionSweeper.beginTracking(sessionId);
  // Best-effort touch; failure is non-fatal — pruner only deletes
  // genuinely stale rows.
  mcpSessionsRepository
    .touch(sessionId)
    .catch((error: unknown) =>
      logger.warn(
        `mcp_sessions touch failed for session ${sessionId}; pruner may reap prematurely.`,
        error,
      ),
    );
  logger.info(
    `Lazy-recovered session ${sessionId} for endpoint ${stored.endpoint_name} (namespace ${stored.namespace_uuid}); persisted state restored from DB.`,
  );
  return { status: "recovered", transport };
}

/**
 * Shared teardown for a StreamableHTTP session: close the transport, drop
 * it from `sessionManager` + the idle-TTL sweeper's tracking, and release
 * its MetaMCP/backend pool connections. `deleteRow` controls whether the
 * persisted `mcp_sessions` row is ALSO dropped — this is the one axis on
 * which the two public wrappers below (`cleanupSession`, `reapIdleSession`)
 * differ, and the distinction is load-bearing (code review, PR #72
 * fixes round):
 *
 *   - `deleteRow: true` (client DELETE, the age-based `sessionLifetime`
 *     cleanup timer) — the session is explicitly over. A later reuse of
 *     the same sessionId must NOT lazy-recover, so the row goes too.
 *
 *   - `deleteRow: false` (idle-TTL sweep reap) — the ROW MUST SURVIVE.
 *     An earlier version of this sweeper reaped via the row-deleting
 *     variant, which made a reaped session's next request 404 instead of
 *     lazily recovering. Spec-conformant SDK clients handle that cleanly
 *     (they just re-`initialize`), but the Anthropic/claude.ai connector
 *     wraps the 404 as `-32600 "Anthropic Proxy: Invalid content from
 *     server"` and stays broken until a manual `/mcp reconnect` — the
 *     exact failure mode PR #22/#23's capability-hash refusal narrowing
 *     exists to avoid (see `recoverPersistedSession` above). Preserving
 *     the row lets `recoverPersistedSession` rebuild the transport
 *     transparently on the consumer's next request. Accepted tradeoff:
 *     reaped rows linger in `mcp_sessions` until the age-based
 *     `MCP_SESSION_TTL_DAYS` pruner (`runMcpSessionPrune`, default 7
 *     days) catches them — rows are tiny (session_id / namespace /
 *     endpoint / a principal hash, no session state), so that lingering
 *     window is a storage non-issue, not a security concern (the
 *     principal hash still gates recovery). A dedicated shorter purge for
 *     specifically sweep-reaped rows is a named follow-up, not this PR.
 */
const cleanupSessionInternal = async (
  sessionId: string,
  transport: StreamableHTTPServerTransport | undefined,
  { deleteRow }: { deleteRow: boolean },
): Promise<void> => {
  logger.info(`Cleaning up StreamableHTTP session ${sessionId}`);

  try {
    // Use provided transport or get from session manager
    const sessionTransport = transport || sessionManager.getSession(sessionId);

    if (sessionTransport) {
      logger.info(`Closing transport for session ${sessionId}`);
      await sessionTransport.close();
      logger.info(`Transport cleaned up for session ${sessionId}`);
    } else {
      logger.info(`No transport found for session ${sessionId}`);
    }

    // Remove from session manager
    sessionManager.removeSession(sessionId);

    // Drop idle-TTL tracking so a reaped/DELETEd session isn't re-selected
    // by a later sweep.
    publicSessionSweeper.forget(sessionId);

    // Clean up MetaMCP server pool session
    await metaMcpServerPool.cleanupSession(sessionId);

    if (deleteRow) {
      // Drop the persisted row so a future DELETE-then-reuse can't lazy-
      // recover a session the client explicitly tore down. Best-effort —
      // pruner reaps stragglers.
      mcpSessionsRepository
        .delete(sessionId)
        .catch((error: unknown) =>
          logger.warn(
            `mcp_sessions delete failed for session ${sessionId}; will be reaped by pruner.`,
            error,
          ),
        );
    }

    logger.info(
      `Session ${sessionId} cleanup completed successfully` +
        (deleteRow ? "" : " (mcp_sessions row preserved for lazy recovery)"),
    );
  } catch (error) {
    logger.error(`Error during cleanup of session ${sessionId}:`, error);
    // Even if cleanup fails, remove the session from manager to prevent memory leaks
    sessionManager.removeSession(sessionId);
    publicSessionSweeper.forget(sessionId);
    logger.info(`Removed orphaned session ${sessionId} due to cleanup error`);
    throw error;
  }
};

// Explicit client DELETE + the age-based sessionLifetime cleanup timer:
// the session is genuinely over, so the persisted row goes too.
export const cleanupSession = async (
  sessionId: string,
  transport?: StreamableHTTPServerTransport,
): Promise<void> =>
  cleanupSessionInternal(sessionId, transport, { deleteRow: true });

// Idle-TTL sweep reap: row-PRESERVING variant. See
// `cleanupSessionInternal`'s doc comment for why this must not delete the
// `mcp_sessions` row.
export const reapIdleSession = async (sessionId: string): Promise<void> =>
  cleanupSessionInternal(sessionId, undefined, { deleteRow: false });

/**
 * Periodic pruner for the `mcp_sessions` table. Runs on boot + every
 * `MCP_SESSION_PRUNER_INTERVAL_MS` (default 24h). Deletes rows whose
 * `last_seen_at` is older than `MCP_SESSION_TTL_DAYS` days (default 7).
 *
 * Both knobs are env-configurable so operators can dial recovery
 * window vs DB-row volume per their tolerance:
 *
 *   MCP_SESSION_TTL_DAYS=14         # generous: 2 weeks of recovery
 *   MCP_SESSION_PRUNER_INTERVAL_MS=3600000   # check hourly instead of daily
 *
 * Setting `MCP_SESSION_TTL_DAYS=0` disables pruning entirely (rows
 * accumulate forever — only useful for forensic debugging).
 */
function getSessionTtlDays(): number {
  const raw = process.env.MCP_SESSION_TTL_DAYS;
  if (!raw) return 7;
  const parsed = Number.parseInt(raw, 10);
  if (Number.isNaN(parsed) || parsed < 0) {
    logger.warn(
      `MCP_SESSION_TTL_DAYS=${raw} invalid; falling back to default 7 days.`,
    );
    return 7;
  }
  return parsed;
}

function getSessionPrunerIntervalMs(): number {
  const raw = process.env.MCP_SESSION_PRUNER_INTERVAL_MS;
  if (!raw) return 24 * 60 * 60 * 1000;
  const parsed = Number.parseInt(raw, 10);
  if (Number.isNaN(parsed) || parsed < 60_000) {
    // Sub-minute intervals would just hammer postgres for no benefit;
    // floor to 60s and warn.
    logger.warn(
      `MCP_SESSION_PRUNER_INTERVAL_MS=${raw} invalid or <60000; falling back to 24h.`,
    );
    return 24 * 60 * 60 * 1000;
  }
  return parsed;
}

async function runMcpSessionPrune(): Promise<void> {
  const ttlDays = getSessionTtlDays();
  if (ttlDays === 0) {
    logger.info("MCP_SESSION_TTL_DAYS=0; mcp_sessions pruning disabled.");
    return;
  }
  const cutoff = new Date(Date.now() - ttlDays * 24 * 60 * 60 * 1000);
  try {
    const deleted = await mcpSessionsRepository.pruneOlderThan(cutoff);
    if (deleted > 0) {
      logger.info(
        `mcp_sessions pruner: reaped ${deleted} session(s) older than ${ttlDays} day(s) (cutoff ${cutoff.toISOString()}).`,
      );
    }
  } catch (error) {
    logger.error("mcp_sessions pruner: postgres delete failed.", error);
  }
}

let mcpSessionPrunerTimer: NodeJS.Timeout | null = null;

export function startMcpSessionPruner(): void {
  if (mcpSessionPrunerTimer) return;
  // Boot run — clear out anything left from previous lifetimes.
  void runMcpSessionPrune();
  const intervalMs = getSessionPrunerIntervalMs();
  mcpSessionPrunerTimer = setInterval(
    () => void runMcpSessionPrune(),
    intervalMs,
  );
  // Don't keep the process alive on shutdown for the sake of pruning.
  if (mcpSessionPrunerTimer.unref) mcpSessionPrunerTimer.unref();
  logger.info(
    `mcp_sessions pruner armed (interval=${intervalMs}ms, ttl_days=${getSessionTtlDays()}).`,
  );
}

export function stopMcpSessionPruner(): void {
  if (mcpSessionPrunerTimer) {
    clearInterval(mcpSessionPrunerTimer);
    mcpSessionPrunerTimer = null;
  }
}

startMcpSessionPruner();

/**
 * Assemble the `GET /health/sessions` body. Pass `false` for `isAdmin` to
 * withhold the operational half.
 *
 * The route stays UNAUTHENTICATED and must — external monitors probe it and a
 * 401 would break them — so what it PUBLISHES is split by role instead. Every
 * caller gets `status: "ok"`, which is all a liveness probe consumes; the
 * detail is admin-only.
 *
 * That detail is live operational intel about this gateway. The session count
 * and the pool's idle/active split are its current scale and load; the
 * `publicSessionSweeper` block publishes the reap TTL, the sweep interval and
 * the running reap counters — i.e. precisely how long an abandoned session
 * survives, how often the gateway looks, and how many it is carrying right
 * now. Together those size a resource-exhaustion attempt against the backend
 * pool cap (the failure mode of the 2026-07-14 pool-cap outage) and
 * time it to land between sweeps. Served to anyone who could reach the host,
 * it was reconnaissance.
 *
 * Built additively rather than by deleting keys from a full body, matching
 * `buildUpstreamHealthBody` in ../../lib/health-upstream: a field added to
 * the block below cannot leak by someone forgetting to add it to a redaction
 * list. The early return also means an anonymous request never reads the
 * session manager, the pool or the sweeper at all.
 *
 * The admin half still never carries live session ids. An earlier version
 * returned `sessionIds: [...]` — every consumer's `Mcp-Session-Id` — and,
 * after that removal, re-published the same ids one level down by spreading
 * `getPoolStatus()` whole (it returns `activeSessionIds` +
 * `idleNamespaceUuids` alongside the counts). Both are projected out field by
 * field here so a field added to MetaMcpServerPoolStatus later cannot land in
 * this payload by default; `getPoolStatus` itself is deliberately left
 * intact.
 */
export function buildSessionsHealthPayload(
  isAdmin: boolean,
): Record<string, unknown> {
  const body: Record<string, unknown> = {
    status: "ok",
  };

  if (!isAdmin) {
    return body;
  }

  const sessionCount = sessionManager.getSessionCount();
  const poolStatus = metaMcpServerPool.getPoolStatus();

  body.timestamp = new Date().toISOString();
  body.streamableHttpSessions = {
    count: sessionCount,
  };
  body.metaMcpPoolStatus = {
    idle: poolStatus.idle,
    active: poolStatus.active,
  };
  body.totalActiveSessions = sessionCount + poolStatus.active;
  body.publicSessionSweeper = publicSessionSweeper.getStats();

  return body;
}

streamableHttpRouter.get("/health/sessions", async (req, res) => {
  // Gated with the same soft admin check as /health/upstream and GET
  // /metamcp/: it resolves the better-auth session and fails to "not an
  // admin" on every error path, so it can never 401 or throw on this
  // unauthenticated route.
  //
  // The catch enforces that same invariant one level out. `isAdminHealthRequest`
  // is contractually non-throwing, but express 4 does not catch an async
  // handler's rejection — if the gate ever regressed to throwing, the request
  // would hang with no response at all and take every liveness probe down
  // with it. Falling back to `false` keeps the 200 and keeps the failure
  // direction safe: a broken auth check withholds detail, it never exposes it.
  let isAdmin = false;
  try {
    isAdmin = await isAdminHealthRequest(req);
  } catch (error) {
    logger.error("Admin check failed for /health/sessions:", error);
  }

  res.json(buildSessionsHealthPayload(isAdmin));
});

streamableHttpRouter.get(
  "/:endpoint_name/mcp",
  lookupEndpoint,
  authenticateApiKey,
  rateLimitMiddleware,
  async (req, res, next) => {
    // const authReq = req as ApiKeyAuthenticatedRequest;
    // const { namespaceUuid, endpointName } = authReq;
    const sessionId = req.headers["mcp-session-id"] as string;

    // logger.info(
    //   `Received GET message for public endpoint ${endpointName} -> namespace ${namespaceUuid} sessionId ${sessionId}`,
    // );

    try {
      logger.info(`Looking up existing session: ${sessionId}`);

      const authReq = req as ApiKeyAuthenticatedRequest;
      // Endpoint- and credential-bound lookup. A session id presented on
      // another endpoint, or under a credential that did not create it, is
      // `refused` and skips recovery entirely — recovery would answer 401 and
      // confirm the id belongs to someone else. Both that case and a genuine
      // miss end at the single 404 below.
      let transport: StreamableHTTPServerTransport | undefined;
      const resolved = resolveBoundSession(sessionId, authReq);
      if (resolved.outcome === "ok") {
        transport = resolved.transport;
      } else {
        if (resolved.outcome === "absent") {
          logger.info(
            `Session ${sessionId} not found in session manager — attempting lazy recovery from mcp_sessions.`,
          );
          const recovery = await recoverPersistedSession(sessionId, authReq);
          if (recovery.status === "recovered") {
            transport = recovery.transport;
          } else if (recovery.status === "auth_failed") {
            res.status(401).end("Unauthorized");
            return;
          }
        }
        if (!transport) {
          // Stale, expired, or not this caller's sessionId. Per MCP
          // Streamable HTTP spec the client MUST start a new session in
          // response to HTTP 404 on a sessioned request. Surface a
          // header-flag for clients that honor the contract, and keep the
          // response body minimal (the previous body dumped the full
          // active-session list into logs/clients — info leak + not
          // actionable). ONE response statement for every non-servable
          // case, so a refused reuse is indistinguishable from a miss.
          res
            .status(404)
            .setHeader("Mcp-Session-Reinitialize-Required", "true")
            .end(
              "Session expired or unknown. Initialize a new MCP session " +
                "(send `initialize` without an `Mcp-Session-Id` header).",
            );
          return;
        }
      }
      logger.info(`Handling GET for session ${sessionId}`);
      // No clientName resolved for the standalone GET stream: it carries only
      // server-initiated notifications, never a tools/call, so nothing on this
      // leg reaches the auditing middleware. The identity half of the binding
      // still rides the store via dispatchTracked, which costs no lookup.
      await dispatchTracked(authReq, transport, req, res, sessionId);
    } catch (error) {
      logger.error("Error in public endpoint /mcp route:", error);
      // Defer to the terminal error handler (middleware/error-handler): it
      // returns the constant INTERNAL_ERROR_BODY and destroys an already
      // streaming socket. Client-facing bodies here previously serialized the
      // raw error object (message, and on the branches below the session id
      // and endpoint name); detail stays in the server log above.
      return next(error);
    }
  },
);

streamableHttpRouter.post(
  "/:endpoint_name/mcp",
  lookupEndpoint,
  authenticateApiKey,
  rateLimitMiddleware,
  async (req, res, next) => {
    const authReq = req as ApiKeyAuthenticatedRequest;
    const { namespaceUuid, endpointName } = authReq;
    const sessionId = req.headers["mcp-session-id"] as string | undefined;

    // Log authentication information for debugging
    logger.info(`POST /mcp request for endpoint: ${endpointName}`);
    logger.info(`Authentication method: ${authReq.authMethod || "none"}`);
    logger.info(`Session ID: ${sessionId || "new session"}`);

    // Resolve the calling consumer once (api-key name / OAuth user email) so
    // the audit middleware + client-connect event can show WHO. Registered
    // against the per-consumer sessionId below (per branch) for the middleware
    // to read via the session-client registry.
    const clientIdentity = await resolveClientIdentity(authReq);

    if (!sessionId) {
      try {
        // Per-credential concurrent-session ceiling, enforced at creation. A
        // credential already holding the maximum is refused here rather than
        // being allowed to mint another session that, once the shared backend
        // pool saturates, would evict other consumers' live connections.
        const ceiling = checkConcurrentSessionCeiling(
          resolveSessionIdentity(authReq),
        );
        if (!ceiling.allowed) {
          res.status(429).json({
            error: `Too many concurrent sessions for this credential (${ceiling.current}/${ceiling.ceiling}). Close idle sessions, or ask an administrator to raise MCP_MAX_SESSIONS_PER_CREDENTIAL.`,
          });
          return;
        }

        logger.info(
          `New public endpoint StreamableHttp connection request for ${endpointName} -> namespace ${namespaceUuid}`,
        );

        // Generate session ID upfront
        const newSessionId = randomUUID();
        logger.info(
          `Generated new session ID: ${newSessionId} for endpoint: ${endpointName}`,
        );

        // Get or create MetaMCP server instance from the pool
        const mcpServerInstance = await metaMcpServerPool.getServer(
          newSessionId,
          namespaceUuid,
        );
        if (!mcpServerInstance) {
          throw new Error("Failed to get MetaMCP server instance from pool");
        }

        // Stamp the calling consumer + caller binding onto the (possibly
        // idle-warmed) instance's handler context. Idle servers carry a
        // placeholder sessionId, so we can't key by sessionId — we set it
        // directly on the instance we just acquired.
        //
        // This is the FALLBACK carrier (migration 0030). The row an audit
        // write actually uses comes from the request-scoped store entered in
        // dispatchTracked; see `lib/metamcp/caller-context-store` for why a
        // per-instance object cannot be the source of truth.
        stampCallerContext(
          mcpServerInstance.handlerContext,
          authReq,
          clientIdentity?.name,
        );

        logger.info(
          `Using MetaMCP server instance for public endpoint session ${newSessionId} (endpoint: ${endpointName})`,
        );

        // Create transport with the predetermined session ID
        const transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: () => newSessionId,
          onsessioninitialized: async (sessionId) => {
            try {
              logger.info(`Session initialized for sessionId: ${sessionId}`);
              // Client-facing session open — distinct from the gateway→backend
              // connection events in client.ts. This is the "who connected".
              metamcpLogStore.record({
                category: "client",
                serverName: endpointName,
                level: "info",
                message: "client connected",
                clientName: clientIdentity?.name,
                // Carried into `gateway_events.session_id` so the history says
                // WHICH session a client opened, not merely that one was
                // opened. Deliberately not described as a join key onto
                // `tool_call_audit`: that column is filled from
                // `handlerContext.sessionId`, which on the warm path still
                // holds the pool's placeholder id for an idle-promoted server.
                sessionId,
              });
            } catch (error) {
              logger.error(
                `Error initializing public endpoint session ${sessionId}:`,
                error,
              );
            }
          },
        });

        // Note: Cleanup is handled explicitly via DELETE requests
        // StreamableHTTP is designed to persist across multiple requests
        logger.info("Created public endpoint StreamableHttp transport");
        logger.info(
          `Session ${newSessionId} will be cleaned up when DELETE request is received`,
        );

        // Store transport reference, bound to the endpoint it was created
        // against AND to the credential that created it, so a later request
        // carrying this id on a different endpoint or under a different
        // credential is rejected (see resolveBoundSession).
        sessionManager.addSession(
          newSessionId,
          transport,
          requestBinding(authReq),
        );
        // Seed idle-TTL tracking for the new session (dispatchTracked's
        // markInFlight/touch calls are guarded to no-op on an untracked
        // session — see their doc comments — so this unconditional seed is
        // required before the first dispatch, not just a convenience).
        publicSessionSweeper.beginTracking(newSessionId);

        logger.info(
          `Public Endpoint Client <-> Proxy sessionId: ${newSessionId} for endpoint ${endpointName} -> namespace ${namespaceUuid}`,
        );
        logger.info(`Stored transport for sessionId: ${newSessionId}`);
        // Deliberately count-only: dumping getSessionIds() here leaked every
        // live Mcp-Session-Id into the logs on each new session (the exact
        // class the round-1 commit stripped from the HTTP payloads).
        logger.info(
          `Total active sessions: ${sessionManager.getSessionCount()}`,
        );

        // Connect the server to the transport before handling the request
        await mcpServerInstance.server.connect(transport);

        // Persist the session row so a later metamcp restart can lazy-
        // recover this consumer's cached sessionId. Best-effort — a DB
        // outage during init shouldn't block the consumer; they'll just
        // lose the post-restart recovery path until the next init.
        const rawToken = extractPresentedCredential(req, authReq.endpoint);
        if (rawToken) {
          const authMethod = authMethodFromRequest(authReq);
          const principal = hashAuthPrincipal(rawToken, authMethod);
          mcpSessionsRepository
            .persist({
              session_id: newSessionId,
              namespace_uuid: namespaceUuid,
              endpoint_name: endpointName,
              auth_principal: principal,
              auth_method: authMethod,
              init_params: {},
              gateway_boot_id: GATEWAY_BOOT_ID,
              capability_hash: GATEWAY_CAPABILITY_HASH,
            })
            .catch((error: unknown) =>
              logger.warn(
                `mcp_sessions persist failed for session ${newSessionId}; lazy-recovery will be unavailable for this consumer until next init.`,
                error,
              ),
            );
        } else {
          logger.warn(
            `Session ${newSessionId} initialized without a recognizable credential; skipping mcp_sessions persist (recovery unavailable).`,
          );
        }

        // Now handle the request - server is guaranteed to be ready
        await dispatchTracked(
          authReq,
          transport,
          req,
          res,
          newSessionId,
          clientIdentity?.name,
        );
      } catch (error) {
        logger.error("Error in public endpoint /mcp POST route:", error);
        // Constant body via the terminal error handler; no error message or
        // endpoint name in the client-facing response (detail is logged above).
        return next(error);
      }
    } else {
      // logger.info(
      //   `Received POST message for public endpoint ${endpointName} -> namespace ${namespaceUuid} sessionId ${sessionId}`,
      // );
      // Count only — session-id lists never belong in request-path logs
      // (see the round-1 payload/DELETE-log sweep this completes).
      logger.debug(`Active sessions: ${sessionManager.getSessionCount()}`);
      try {
        logger.info(`Looking up existing session: ${sessionId}`);

        let transport: StreamableHTTPServerTransport | undefined;
        const resolved = resolveBoundSession(sessionId, authReq);
        if (resolved.outcome === "ok") {
          transport = resolved.transport;
        } else {
          if (resolved.outcome === "absent") {
            logger.info(
              `Transport for sessionId ${sessionId} not in memory — attempting lazy recovery from mcp_sessions.`,
            );
            const recovery = await recoverPersistedSession(sessionId, authReq);
            if (recovery.status === "recovered") {
              transport = recovery.transport;
              // Bump idempotently so subsequent same-session reads hit the
              // in-memory map; touch already happened inside recovery.
            } else if (recovery.status === "auth_failed") {
              logger.warn(
                `Lazy recovery refused for session ${sessionId}: auth principal mismatch or missing credential.`,
              );
              res.status(401).json({
                error: "Unauthorized",
                message:
                  "Stored auth principal does not match incoming credential.",
                timestamp: new Date().toISOString(),
              });
              return;
            }
          }
          if (!transport) {
            logger.error(
              `No servable transport for sessionId ${sessionId} — absent, unrecoverable, or bound to another caller.`,
            );
            // Stale or expired sessionId. The prior response embedded
            // `available_sessions: sessionManager.getSessionIds()` —
            // a mild info leak of every live session UUID into client
            // logs + zero diagnostic value to the caller (the caller
            // just learns their own ID isn't in the list, which the
            // 404 already conveyed).
            //
            // Per MCP Streamable HTTP spec the client MUST start a new
            // session in response to HTTP 404 on a sessioned request.
            // The `Mcp-Session-Reinitialize-Required` header signals
            // that explicitly for spec-conformant clients; the body
            // message guides anyone reading it manually.
            //
            // Background: 2026-05-15 sub-agent validation run on the
            // CIPP MCP namespace hit this path 100% — Claude Code's
            // MCP connector held a sessionId rotated out by the server,
            // and the harness didn't auto-reinitialize on 404. Until
            // the client side honors reinit, this is the cleanest
            // server-side signal we can hand it. Task #29 has the
            // full background.
            //
            // A session resident under ANOTHER caller lands here too, on
            // the same statement, so the response says nothing about
            // which of the two it was.
            res
              .status(404)
              .setHeader("Mcp-Session-Reinitialize-Required", "true")
              .json({
                error: "Session not found",
                message:
                  "Session expired or unknown. Initialize a new MCP " +
                  "session (send `initialize` without an " +
                  "`Mcp-Session-Id` header).",
                timestamp: new Date().toISOString(),
              });
            return;
          }
        }
        // Refresh the pooled instance's fallback binding to THIS request.
        //
        // The authoritative binding for the audit row is the request-scoped
        // store `dispatchTracked` enters below; this keeps the fallback from
        // describing an older request. It matters because the handler context
        // is per-INSTANCE while the facts on it are per-REQUEST: `requestId`
        // and `callerIp` change on every call, and the instance is reached by
        // an in-memory session lookup that resolves on namespace + endpoint
        // rather than by re-deriving the caller from the credential presented
        // now. Neither property makes the pooled object safe to audit from,
        // which is exactly why the store exists — see
        // `lib/metamcp/caller-context-store`.
        //
        // A pure map read, never a create: an instance the pool no longer
        // holds means the transport is being served from lazy recovery, which
        // stamps its own binding. Nothing is keyed on the handler context's
        // own sessionId here — that is a placeholder on an idle-converted
        // instance — only on the transport session id the pool itself
        // assigned.
        const activeInstance = metaMcpServerPool.getServerInstance(sessionId);
        if (activeInstance) {
          stampCallerContext(
            activeInstance.handlerContext,
            authReq,
            clientIdentity?.name,
          );
        }

        logger.info(`Handling POST for session ${sessionId}`);
        await dispatchTracked(
          authReq,
          transport,
          req,
          res,
          sessionId,
          clientIdentity?.name,
        );
      } catch (error) {
        logger.error("Error in public endpoint /mcp route:", error);
        // Constant body via the terminal error handler; no error message,
        // session id or endpoint name in the client-facing response.
        return next(error);
      }
    }
  },
);

streamableHttpRouter.delete(
  "/:endpoint_name/mcp",
  lookupEndpoint,
  authenticateApiKey,
  rateLimitMiddleware,
  async (req, res, next) => {
    const authReq = req as ApiKeyAuthenticatedRequest;
    const { namespaceUuid, endpointName } = authReq;
    const sessionId = req.headers["mcp-session-id"] as string | undefined;

    logger.info(
      `Received DELETE message for public endpoint ${endpointName} -> namespace ${namespaceUuid} sessionId ${sessionId}`,
    );

    if (sessionId) {
      try {
        // Endpoint-binding guard — see resolveDeletableSession's doc
        // comment. Single 404 site: absent, cross-endpoint, and
        // lookup-failure all collapse into the same response shape.
        const resolution = await resolveDeletableSession(sessionId, authReq);
        if (resolution.outcome === "not_found") {
          res.status(404).json({
            error: "Session not found",
            message: "Session expired or unknown.",
            timestamp: new Date().toISOString(),
          });
          return;
        }

        logger.info(`Starting cleanup for session ${sessionId}`);

        await cleanupSession(sessionId);

        logger.info(
          `Public endpoint session ${sessionId} cleaned up successfully`,
        );

        // Response deliberately omits the live session-id list the prior
        // version returned (`remainingSessions`) — that leaked every other
        // consumer's session id to any authenticated caller.
        res.status(200).json({
          message: "Session cleaned up successfully",
          sessionId: sessionId,
        });
      } catch (error) {
        logger.error("Error in public endpoint /mcp DELETE route:", error);
        // Constant body via the terminal error handler; no error message or
        // session id in the client-facing response.
        return next(error);
      }
    } else {
      res.status(400).json({
        error: "Missing sessionId",
        message: "sessionId header is required for cleanup",
      });
    }
  },
);

// Initialize automatic cleanup timer using session manager
sessionManager.startCleanupTimer(async (sessionId, transport) => {
  await cleanupSession(sessionId, transport);
});

// Arm the idle-TTL sweeper (structural fix for the 2026-07-14 pool-cap
// saturation — see the sweeper's file header). No-op when either env knob
// disables it.
publicSessionSweeper.start();

export function stopPublicSessionSweeper(): void {
  publicSessionSweeper.stop();
}

export default streamableHttpRouter;
