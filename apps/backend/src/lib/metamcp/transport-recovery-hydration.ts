/**
 * Session-state hydration for lazy-recovered StreamableHTTP transports.
 *
 * Background — the bug this fixes:
 *
 * Lazy session recovery (PR #15) rebuilds a `StreamableHTTPServerTransport`
 * for a sessionId a client cached in a PRIOR metamcp process (so the
 * client's `Mcp-Session-Id` survives a gateway restart). The rebuild
 * connects a pooled `Server` to a fresh transport — but the MCP
 * `initialize` handshake is never replayed, because the MCP lifecycle
 * sends `initialize` exactly ONCE per client session and a reconnecting
 * client won't send it again.
 *
 * In `@modelcontextprotocol/sdk` 1.16.0 the transport flips
 * `_initialized=true` and assigns `sessionId` ONLY inside the
 * initialize-request branch (`server/streamableHttp.js:337-338`). A
 * rebuilt-but-not-initialized transport therefore rejects the client's
 * first real request in `validateSession`:
 *
 *     if (!this._initialized) -> 400 {-32000 "Bad Request: Server not
 *     initialized"}   (server/streamableHttp.js:442)
 *
 * The Anthropic claude.ai MCP connector relays that 400 as
 * `-32600 "Anthropic Proxy: Invalid content from server"`, wedging the
 * connector until a full client refresh (which drops the cached
 * sessionId and forces a fresh `initialize`). A `/mcp` reconnect does
 * NOT clear it — it reuses the same cached sessionId and hits the same
 * dead transport. (Root-caused on mcp-host-prod 2026-05-27: every
 * stored `mcp_sessions` row carried the current capability_hash, so the
 * PR #22/#23/#24 capability machinery was never the cause — recovery was
 * "succeeding" and then 400-ing on the first call.)
 *
 * The caller checks `shouldRefuseRecovery` (capability_hash match) before
 * rebuilding, which proves the client's cached protocol + capability
 * negotiation still matches what this process advertises. Replaying the
 * handshake would therefore be redundant; we just restore the two fields
 * it would have set.
 *
 * Remove this shim if the SDK ever exposes a public API to construct a
 * transport in an already-initialized state for an existing sessionId.
 */
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";

import logger from "@/utils/logger";

/** SDK-internal fields the hydration depends on (private in the SDK). */
interface TransportInternals {
  _initialized?: unknown;
  sessionId?: unknown;
}

/**
 * Restore a freshly-rebuilt transport into the "already initialized"
 * state for `sessionId`, without replaying the `initialize` handshake.
 *
 * Returns `true` on success. Returns `false` if the SDK's internal shape
 * changed across an upgrade (the `_initialized` field is no longer a
 * boolean on a fresh transport) — the caller then refuses recovery
 * rather than cache a transport it can't prove is serviceable.
 */
export function hydrateRecoveredTransport(
  transport: StreamableHTTPServerTransport,
  sessionId: string,
): boolean {
  const internals = transport as unknown as TransportInternals;
  // A fresh transport has `_initialized === false`. Anything else means
  // the SDK renamed/removed the field — bail loudly.
  if (typeof internals._initialized !== "boolean") {
    logger.error(
      "SDK shape change: StreamableHTTPServerTransport._initialized is not a " +
        "boolean on a fresh transport; cannot hydrate recovered session " +
        `${sessionId}. Update hydrateRecoveredTransport for the new SDK shape.`,
    );
    return false;
  }
  internals._initialized = true;
  internals.sessionId = sessionId;
  return true;
}

/**
 * Fail-loud contract check, run once at router module load. Asserts the
 * SDK internals `hydrateRecoveredTransport` depends on still exist on a
 * fresh transport, so an SDK bump that renames them surfaces in boot
 * logs rather than silently breaking every restart-recovery.
 *
 * Returns `true` when the contract holds. Pure log on violation — does
 * not throw, since a broken contract degrades to the pre-existing 404
 * reinit path (recovery refused), which is safe.
 */
export function assertRecoveryHydrationContract(): boolean {
  const probe = new StreamableHTTPServerTransport({
    sessionIdGenerator: () => "contract-probe",
  });
  const internals = probe as unknown as Record<string, unknown>;
  // `_initialized` is the gate field validateSession checks and the SDK
  // sets it (=false) in the constructor, so it must be a boolean on a
  // fresh transport. `sessionId` is NOT declared until an `initialize`
  // request assigns it, so it's legitimately absent here — we only ever
  // assign it (always valid on a JS object), never read the SDK's value,
  // so it isn't part of the contract.
  const ok = typeof internals._initialized === "boolean";
  if (!ok) {
    logger.error(
      "STARTUP CONTRACT VIOLATION: StreamableHTTPServerTransport no longer " +
        "exposes a boolean `_initialized` internal. Lazy session recovery will " +
        "refuse all recoveries until hydrateRecoveredTransport is updated for " +
        "the new SDK shape (currently pinned @modelcontextprotocol/sdk 1.16.0).",
    );
  }
  return ok;
}
