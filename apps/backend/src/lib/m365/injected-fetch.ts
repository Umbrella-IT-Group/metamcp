/**
 * Per-request Graph token injection for M365-delegated backend servers.
 *
 * `client.ts` passes the fetch built here as the SDK transport's custom
 * `fetch` for any server whose name is in `M365_INJECTED_SERVER_NAMES`
 * (default: `m365`). Injection therefore rides the REQUEST, not the
 * connection — the only design that survives the pool's idle-warmup
 * handoff, per-server cap reuse and global params cache without ever
 * leaking one user's token into another user's traffic.
 *
 * THE INJECTION INVARIANT (unit-tested in `injected-fetch.test.ts`):
 *  1. The inbound consumer credential (MetaMCP-issued `mcp_token_*` or
 *     API key) is NEVER forwarded upstream — any Authorization header
 *     present on the outgoing request is stripped before injection.
 *     (MCP spec 2025-11-25 token-passthrough prohibition.)
 *  2. An Authorization header is set ONLY when a request-scoped user
 *     context exists (ALS, `request-context.ts`) AND the mint service
 *     returned a token for exactly that user. The mint service's sole
 *     token source is the Entra token endpoint for the configured
 *     tenant — the gateway only ever injects genuine Graph-scoped
 *     tokens (design doc §4.2 guarantee).
 *  3. No user context (idle warmup, health ping, API-key consumer,
 *     OpenAPI bridge) → the request goes out with NO Authorization at
 *     all. Fail-closed on identity; the backend's Graph call then
 *     fails per its own contract instead of acting as someone.
 *  4. Mint failures propagate as typed `M365BrokerError` so the proxy
 *     layer can answer the consumer with the enrollment elicitation.
 */
import { FetchLike } from "@modelcontextprotocol/sdk/shared/transport.js";

import { getInjectedServerNames } from "./config";
import { M365MintService, m365MintService } from "./mint-service";
import { getM365UserContext } from "./request-context";

export const USER_ID_HEADER = "X-Umbrella-User-Id";

/**
 * Build an injected fetch. Exported with an injectable mint service +
 * base fetch for unit tests; production callers use
 * `getInjectedFetchForServer` below.
 */
export function makeM365InjectedFetch(
  mintService: M365MintService = m365MintService,
  baseFetch: FetchLike = fetch,
): FetchLike {
  return async (url, init) => {
    const headers = new Headers(init?.headers);
    // Invariant 1: never forward whatever credential the transport (or
    // a future server-row misconfiguration) put on this request.
    headers.delete("authorization");
    headers.delete(USER_ID_HEADER);

    const context = getM365UserContext();
    if (context?.userId) {
      // Invariant 2: token minted for exactly the request's user.
      // Mint failures throw typed M365BrokerError — deliberately not
      // caught here so they surface through the SDK client call into
      // the proxy layer's typed-error mapping.
      const accessToken = await mintService.getAccessToken(context.userId);
      headers.set("authorization", `Bearer ${accessToken}`);
      headers.set(USER_ID_HEADER, context.userId);
    }
    // Invariant 3: no context → request leaves with no Authorization.

    return baseFetch(url, { ...init, headers });
  };
}

/** Singleton used for every injected server (context does the per-user work). */
const injectedFetchSingleton: FetchLike = makeM365InjectedFetch();

/**
 * The `client.ts` wiring hook: returns the injected fetch when (and
 * only when) `serverName` is configured for M365 delegated injection.
 * Env is read per call — cheap, and keeps tests deterministic.
 */
export function getInjectedFetchForServer(
  serverName: string,
): FetchLike | undefined {
  return getInjectedServerNames().has(serverName)
    ? injectedFetchSingleton
    : undefined;
}
