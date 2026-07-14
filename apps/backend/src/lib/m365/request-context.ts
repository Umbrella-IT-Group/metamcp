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

import { M365BrokerError } from "./errors";

/** A cold-connect broker rejection latched for the outer request handler. */
export interface ConnectBrokerFailure {
  /** Configured backend server name whose connect minted-and-rejected. */
  serverName: string;
  /** The typed broker error (code + message + enroll URL). */
  error: M365BrokerError;
}

export interface M365UserContext {
  /** better-auth user id of the OAuth-authenticated MCP consumer. */
  userId: string;
  /**
   * Mutable per-request sink for a broker error caught during a COLD
   * backend connect — the token mint on the `initialize` handshake. That
   * throw is swallowed by the pool's connect path (it resolves
   * `undefined`, never re-throwing) and by the proxy's dynamic-find
   * catch-and-continue, so it can't reach the tools/call handler's catch
   * on its own the way a WARM-path mint failure does. Connect latches it
   * here; the outer request handler drains it and answers the consumer
   * with the enrollment prompt instead of a generic "Unknown tool". A
   * plain field on the request-scoped context object — same ALS store, so
   * connect (deep in the stack) and the handler read/write the same slot.
   */
  connectBroker?: ConnectBrokerFailure;
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

/**
 * Latch a broker error caught during a cold backend connect. Fail-open:
 * a no-op when there is no request-scoped context (idle warmup, health
 * ping, API-key consumer) — those paths never mint per-user tokens, so
 * they can't produce a broker error anyway, and the connect just resolves
 * `undefined` as before. Last write wins if two servers were probed in
 * one request (only the injected m365 server can produce this, and the
 * outer handler gates delivery on the requested tool's owner). The slot
 * is a SINGLE field, not keyed by server — fine today because
 * `M365_INJECTED_SERVER_NAMES` names exactly one server (`m365`) in
 * prod; if that env var ever grows to inject more than one server, this
 * needs to become a map keyed by `serverName` so two servers probed in
 * the same request can't clobber each other's latched failure.
 */
export function recordConnectBrokerFailure(
  failure: ConnectBrokerFailure,
): void {
  const context = storage.getStore();
  if (context) {
    context.connectBroker = failure;
  }
}

/**
 * Read and clear any latched cold-connect broker failure for this
 * request. The outer tools/call handler drains this when the call
 * otherwise failed, to answer with the enrollment prompt.
 */
export function takeConnectBrokerFailure(): ConnectBrokerFailure | undefined {
  const context = storage.getStore();
  if (!context?.connectBroker) {
    return undefined;
  }
  const failure = context.connectBroker;
  context.connectBroker = undefined;
  return failure;
}
