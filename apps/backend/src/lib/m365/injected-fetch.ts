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
 *  4. A mint failure on a request that needs a token propagates as a
 *     typed `M365BrokerError`, before any byte leaves, so the proxy
 *     layer can answer the consumer with the enrollment elicitation.
 *     It surfaces on the `tools/call` that needed the token, never on
 *     a connect or a listing (invariant 5).
 *  5. A token is minted only for a request that can execute a tool
 *     (`requestNeedsUserToken`). The handshake (`initialize`,
 *     `notifications/*`, `ping`), the listings (`tools/list`,
 *     `prompts/list`, `resources/list`, `resources/templates/list`),
 *     the standing GET stream and the session DELETE never carry a user
 *     token or user-id header, so a user's grant state can never fail a
 *     connect, a listing or a teardown. The backend answers those from
 *     a static registry that does not read the Authorization header, so
 *     the answer is identical for every caller and nothing
 *     user-specific is sent. Anything the gate cannot positively
 *     classify as one of those mints, as before.
 *  6. A reply to a request the backend sent (a strictly shaped JSON-RPC
 *     response: a ping answer, an elicitation result, a method-not-found
 *     error) carries no user token or user-id header either. The SDK
 *     sends such a reply from the async scope it is reading the
 *     backend's stream in: for the standing GET stream that is the scope
 *     that OPENED the connection, which on a pooled connection need not
 *     be the caller whose tool call is in flight. A reply only completes
 *     a request the backend correlates by id within its own session; it
 *     is not a new tool invocation, so no scope's identity belongs on it.
 *     Tool-call POSTs keep invariant 2 unchanged.
 *  7. The token and the user id go only to an INTERNAL backend, proven by
 *     address. The injection runs inside the pool's guarded fetch
 *     (`metamcp/url-guard.ts`, `InternalOnlyCredentials`), which resolves the
 *     server row's host, validates and pins every address, and only then
 *     asks for the credential, for a hop whose addresses are all internal.
 *     A public, mixed or allowlisted-by-name destination gets neither header
 *     and causes no mint, so repointing a server named in
 *     `M365_INJECTED_SERVER_NAMES` at an outside host cannot collect anyone's
 *     token. The guard re-decides on every redirect hop and refuses a
 *     cross-origin one. Before this the injection wrapped the guard from
 *     outside, minted from the URL text alone, and the guard's internal-only
 *     list did not cover `Authorization`.
 *
 * WHY THIS IS HERE AND NOT AT THE CALL SITES. Before invariant 5 every
 * request minted, so a user with no grant failed their own `initialize`
 * and `tools/list` and the failure ran the pool's backend-drop cascade
 * (pooled-connection invalidation for every session, a re-notify loop,
 * a teardown DELETE that threw the same error and left the backend
 * session behind). The connect, the listing, the probe, the sweep, the
 * dynamic tool lookup and the teardown are separate call sites that each
 * inherit whatever user context is ambient (AsyncLocalStorage reaches
 * into timers), so one decision at the single fetch choke point covers
 * them all.
 */
import { FetchLike } from "@modelcontextprotocol/sdk/shared/transport.js";

import logger from "@/utils/logger";

import {
  createGuardedFetch,
  type InternalOnlyCredentials,
  type McpUrlGuardOptions,
} from "../metamcp/url-guard";
import { getInjectedServerNames } from "./config";
import { M365MintService, m365MintService } from "./mint-service";
import { getM365UserContext } from "./request-context";

export const USER_ID_HEADER = "X-Umbrella-User-Id";

/**
 * JSON-RPC methods that never execute a tool or read a user's data: the
 * handshake and the registry listings. `notifications/*` is matched by
 * prefix below. `resources/read`, `prompts/get` and the rest are NOT here:
 * they run backend code, so they keep minting.
 */
const TOKEN_FREE_RPC_METHODS: ReadonlySet<string> = new Set([
  "initialize",
  "ping",
  "tools/list",
  "prompts/list",
  "resources/list",
  "resources/templates/list",
]);
const TOKEN_FREE_RPC_METHOD_PREFIX = "notifications/";

/** HTTP methods that carry no JSON-RPC request: stream, probe and teardown. */
const TOKEN_FREE_HTTP_METHODS: ReadonlySet<string> = new Set([
  "GET",
  "HEAD",
  "OPTIONS",
  "DELETE",
]);

/** A JSON object that is not an array: the only shape a single message has. */
function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * A handshake, listing or notification REQUEST (invariant 5). A message
 * that also carries `result` or `error` is not a request, whatever its
 * method says, so it can never pass here as one: a reply has to qualify on
 * its own strict shape below.
 */
function isTokenFreeRpcRequest(message: unknown): boolean {
  if (!isPlainObject(message)) return false;
  if (Object.hasOwn(message, "result") || Object.hasOwn(message, "error")) {
    return false;
  }
  const method = message.method;
  return (
    typeof method === "string" &&
    (TOKEN_FREE_RPC_METHODS.has(method) ||
      method.startsWith(TOKEN_FREE_RPC_METHOD_PREFIX))
  );
}

/**
 * A reply to a request the backend sent (invariant 6), recognized STRICTLY:
 * a plain object with `jsonrpc: "2.0"`, an `id` that is a string or a
 * finite number (null and a missing id are refused), exactly one of
 * `result` and `error`, and no `method` key at all. Fields are checked by
 * presence, never truthiness, so `id: 0`, `id: ""` and a `null`, `false` or
 * `0` result all qualify. Anything looser falls through to the fail-closed
 * mint.
 */
function isJsonRpcReply(message: unknown): boolean {
  if (!isPlainObject(message)) return false;
  if (message.jsonrpc !== "2.0") return false;
  if (Object.hasOwn(message, "method")) return false;
  if (!Object.hasOwn(message, "id")) return false;
  const id = message.id;
  if (
    typeof id !== "string" &&
    !(typeof id === "number" && Number.isFinite(id))
  ) {
    return false;
  }
  return Object.hasOwn(message, "result") !== Object.hasOwn(message, "error");
}

function isTokenFreeRpcMessage(message: unknown): boolean {
  return isTokenFreeRpcRequest(message) || isJsonRpcReply(message);
}

/**
 * Whether this outgoing request may execute a tool, and so needs the
 * user's token (invariants 5 and 6). FAIL-CLOSED: `true` (mint, the
 * behavior before this gate) unless the request is positively one of the
 * token-free kinds. A POST is token-free only when its body is a string
 * that parses to one message, or a non-empty batch, in which EVERY message
 * is a token-free request (a string method from the lists above, with no
 * `result` or `error`) or a strictly shaped reply. A parse failure, a
 * non-string body, an empty batch, a malformed reply, any other method and
 * any other HTTP method (PUT and the rest) all need a token.
 *
 * Every string body is parsed, whatever its size, as `verified-caller.ts`
 * does: a size cut-off would leave a large reply minting the token of
 * whichever scope sent it. The cost is bounded, because only the
 * m365-injected servers' requests come through here and the gateway caps
 * an inbound MCP request body (`metamcp/mcp-request-body-limit.ts`), so
 * the worst case is one extra parse of a rare large tool call.
 */
export function requestNeedsUserToken(init?: RequestInit): boolean {
  const httpMethod = (init?.method ?? "GET").toUpperCase();
  if (TOKEN_FREE_HTTP_METHODS.has(httpMethod)) return false;
  if (httpMethod !== "POST") return true;

  const body = init?.body;
  if (typeof body !== "string") return true;
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    return true;
  }
  const messages: unknown[] = Array.isArray(parsed) ? parsed : [parsed];
  return messages.length === 0 || !messages.every(isTokenFreeRpcMessage);
}

/**
 * The per-user Graph credential as a guard credential source
 * (`InternalOnlyCredentials` in `metamcp/url-guard.ts`). The guard calls
 * `forInternalHop` only for a hop whose destination it has resolved, pinned
 * and proven internal, so the token is minted after the destination is known
 * and only for one of our own backends (invariant 7).
 *
 * The header names it owns are deleted from EVERY hop first (invariant 1, and
 * any `X-Umbrella-User-Id` a server row or a previous hop carried), and set
 * again only when invariants 2 and 5 hold for the request this hop sends.
 */
export function createM365Credentials(
  mintService: M365MintService = m365MintService,
): InternalOnlyCredentials {
  return {
    headerNames: ["authorization", USER_ID_HEADER.toLowerCase()],
    forInternalHop: async ({ method, body }) => {
      const context = getM365UserContext();
      if (!context?.userId || !requestNeedsUserToken({ method, body })) {
        // Invariant 3: no context, no credential. Invariants 5 and 6: a
        // token-free request or a reply to the backend carries none either.
        return undefined;
      }
      // Invariant 2: token minted for exactly the request's user. Mint
      // failures throw typed M365BrokerError, deliberately not caught here,
      // so they surface through the SDK client call into the proxy layer's
      // typed-error mapping. Only a request that can execute a tool gets
      // here (invariant 5), so that error is always the answer to a
      // tools/call, never to a connect or a listing.
      const accessToken = await mintService.getAccessToken(context.userId);
      return {
        authorization: `Bearer ${accessToken}`,
        [USER_ID_HEADER]: context.userId,
      };
    },
    onWithheld: ({ method, body }, reason) => {
      if (!getM365UserContext()?.userId) return;
      if (!requestNeedsUserToken({ method, body })) return;
      // Value-free: no token, no user id, no URL. The operator fixes the
      // server row (or its DNS); the request itself goes out without the
      // credential and the backend refuses it per its own contract.
      logger.warn(
        `M365 user token withheld from an m365-injected server: its destination is not an internal backend proven by resolved address (${reason}). The request was sent without it.`,
      );
    },
  };
}

/**
 * Build an injected fetch: the guarded, pinned fetch with the per-user Graph
 * credential (`createM365Credentials`). `guardOptions` is the posture the
 * guard runs under; production passes the pooled data plane's, and tests
 * pass their transport and resolver seams (`baseFetch`, `lookup`) with it.
 */
export function makeM365InjectedFetch(
  mintService: M365MintService,
  guardOptions: McpUrlGuardOptions,
): FetchLike {
  return createGuardedFetch({
    ...guardOptions,
    internalOnlyCredentials: createM365Credentials(mintService),
  });
}

/**
 * The `client.ts` wiring hook: returns the injected fetch when (and only when)
 * `serverName` is configured for M365 delegated injection, built over the
 * guard posture the caller passes. Env is read per call — cheap, and keeps
 * tests deterministic.
 */
export function getInjectedFetchForServer(
  serverName: string,
  guardOptions: McpUrlGuardOptions,
): FetchLike | undefined {
  if (!getInjectedServerNames().has(serverName)) {
    return undefined;
  }
  return makeM365InjectedFetch(m365MintService, guardOptions);
}
