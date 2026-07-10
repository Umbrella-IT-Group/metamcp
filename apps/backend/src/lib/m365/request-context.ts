/**
 * Request-scoped user identity for per-user Graph token injection.
 *
 * The backend-connection pool shares `ConnectedClient`s in three ways
 * that make connect-time credentials unsafe for PER-USER tokens: idle
 * warmup connections are created with no user and handed to whichever
 * session asks first; the per-server cap branch reuses another
 * session's connection; and `serverParamsCache` is global per server.
 * So user identity must ride the REQUEST, not the connection.
 *
 * `AsyncLocalStorage` carries the authenticated OAuth user from the
 * public-endpoint router (`streamable-http.ts`, where the auth
 * middleware stamped `oauthUserId`) through the proxy layer and the
 * pooled MCP client down into the injected `fetch` (`injected-fetch.ts`)
 * that dispatches the backend HTTP request. Node propagates ALS across
 * awaits, timers and (synchronous) EventEmitter dispatch, which covers
 * the SDK's request path.
 *
 * Fail-closed contract: when no context is present (idle warmup, health
 * pings, API-key consumers, OpenAPI bridge), the injected fetch sends
 * NO Authorization header at all — never a cached or foreign user's
 * token. See `injected-fetch.ts` for the invariant tests.
 */
import { AsyncLocalStorage } from "node:async_hooks";

export interface M365UserContext {
  /** better-auth user id of the OAuth-authenticated MCP consumer. */
  userId: string;
}

const storage = new AsyncLocalStorage<M365UserContext>();

export function runWithM365UserContext<T>(
  context: M365UserContext | undefined,
  fn: () => T,
): T {
  if (!context?.userId) {
    // No identity — run outside any context so the injected fetch
    // fail-closes. Never propagate an empty/partial context.
    return fn();
  }
  return storage.run(context, fn);
}

export function getM365UserContext(): M365UserContext | undefined {
  return storage.getStore();
}
