import type { FetchLike } from "@modelcontextprotocol/sdk/shared/transport.js";

import logger from "@/utils/logger";

import { getInjectedServerNames } from "../m365/config";
import type { CallerContext } from "./caller-context-store";
import { getCallerContext } from "./caller-context-store";

/**
 * `X-Umbrella-User-Id` on the POOLED data plane: the caller's identity as THIS
 * GATEWAY verified it, for the backends that are allowed to act on it.
 *
 * WHAT IT IS. A backend named in `VERIFIED_CALLER_SERVER_NAMES` receives the
 * better-auth `users.id` of the person whose credential authenticated the
 * inbound request, on every request that can execute backend code. The first
 * consumer is a team server whose tools act for "the person asking" (one
 * teammate's agent asks, another's answers), so the backend must know who is
 * calling, and must never learn it from the caller. A wrong value here lets
 * one employee's agent act as another's.
 *
 * WHERE THE VALUE COMES FROM, AND NOWHERE ELSE. `actsAsUserId ?? userId` from
 * the request-scoped caller binding (`caller-context-store`), which every
 * public transport builds per request from the fields `authenticateApiKey`
 * stamps (`apiKeyUserId`, `apiKeyActsAsUserId`, `oauthUserId`), and which the
 * admin Inspector's namespace surface builds from the signed-in session user.
 * An api-key caller is the key owner unless an admin bound the key to act as
 * someone (`api_keys.acts_as_user_id`, migration 0024); an OAuth caller is the
 * OAuth subject. Disabled accounts never get this far: the auth middleware
 * refuses them before stamping anything. Nothing the caller sends is read.
 * In particular `X-MCP-Actor` (`asserted-actor.ts`) is caller-ASSERTED and is
 * never consulted here.
 *
 * STRIP, ALWAYS; SET, ONLY WHEN PROVEN. For a named backend, any
 * `x-umbrella-user-id` already on the outgoing request is deleted first,
 * whatever request it is: a value stored on the server row, or one some future
 * code path copied from the inbound request, must never arrive. The verified
 * id is then set only when the request can execute backend code AND the
 * binding resolved an identity. No identity means no header, and the backend
 * refuses; it never falls back to the key owner when an acts-as binding is
 * present but blank.
 *
 * WHY "CAN EXECUTE BACKEND CODE" IS DECIDED POSITIVELY. One pooled backend
 * connection serves many callers, and its control traffic does not belong to
 * any one of them: a cold connect runs inside whichever request triggered it,
 * and SDK reconnect timers and the standing GET stream keep that opening
 * scope (see `asserted-actor.ts`, CONNECTION CONTROL TRAFFIC). So the header
 * is set only on a POST whose body parses to a JSON-RPC request that is not
 * the handshake, a listing or a notification. Everything this cannot
 * classify (a response to a server-initiated request, which is sent from the
 * opening scope; an unparseable or non-string body; PUT and the rest) carries
 * NO identity. The m365 token gate (`requestNeedsUserToken`) answers the same
 * question but mints when unsure, because there a missing token only fails
 * the call; here an unsure answer could name the wrong person. The two agree
 * on every request-shaped message, which `verified-caller.test.ts` pins.
 *
 * WHY NOT THE M365 INJECTION. `lib/m365/injected-fetch.ts` sets the same
 * header name, but it also mints a Graph token, reads its own user context
 * (OAuth and acts-as only, never a plain key owner), and owns the backends in
 * `M365_INJECTED_SERVER_NAMES`. A server in both lists would get two writers
 * for one header, so the gateway refuses to start with an overlap
 * (`assertVerifiedCallerConfig`) and refuses to build that transport.
 *
 * INTERNAL DESTINATIONS ONLY. The pool's guarded fetch drops this header on
 * any hop whose destination is not internal (`internalOnlyHeaders` in
 * `client.ts`), so a user id never reaches a third-party server, and the
 * gateway trust header (`X-Gateway-Auth`, `url-guard.ts`) rides the same
 * internal hops. A backend must check that trust header before it believes
 * this one: the identity is only as good as the proof that the gateway sent
 * it.
 *
 * NO INJECTION BY DEFAULT. With `VERIFIED_CALLER_SERVER_NAMES` unset or empty
 * no backend is named and `getVerifiedCallerFetchForServer` returns the base
 * fetch itself. The Inspector still reserves this custom header, and the
 * pool still strips it on non-internal hops, even with an empty list.
 */
export const VERIFIED_CALLER_HEADER = "x-umbrella-user-id";

export const VERIFIED_CALLER_SERVER_NAMES_ENV = "VERIFIED_CALLER_SERVER_NAMES";

/**
 * The backends that receive the verified caller, by server name.
 *
 * Comma-separated, each name trimmed, empty entries dropped, duplicates
 * collapsed, matched exactly (the same parsing as `M365_INJECTED_SERVER_NAMES`
 * in `lib/m365/config.ts`). Read fresh on each call, as that list is, so tests
 * stay deterministic; the value is constant for the life of the process.
 */
export function getVerifiedCallerServerNames(): Set<string> {
  const raw = process.env[VERIFIED_CALLER_SERVER_NAMES_ENV] ?? "";
  return new Set(
    raw
      .split(",")
      .map((name) => name.trim())
      .filter(Boolean),
  );
}

function overlapError(names: readonly string[]): Error {
  return new Error(
    `${VERIFIED_CALLER_SERVER_NAMES_ENV} and M365_INJECTED_SERVER_NAMES (default "m365") ` +
      `both name: ${names.join(", ")}. Each backend may receive X-Umbrella-User-Id from ` +
      `one source only; remove the server from one of the two lists.`,
  );
}

/**
 * Boot check. Throws when a server is named in both
 * `VERIFIED_CALLER_SERVER_NAMES` and `M365_INJECTED_SERVER_NAMES`, and logs
 * which servers receive the verified caller, so the posture is in the boot
 * log. `index.ts` calls it at module scope, before any route is registered,
 * so a bad configuration stops the gateway instead of serving with two
 * writers for one identity header.
 */
export function assertVerifiedCallerConfig(): void {
  const names = getVerifiedCallerServerNames();
  const m365 = getInjectedServerNames();
  const overlap = [...names].filter((name) => m365.has(name)).sort();
  if (overlap.length > 0) throw overlapError(overlap);
  if (names.size > 0) {
    logger.info(
      `Verified caller identity: X-Umbrella-User-Id is set from the authenticated caller for: ${[...names].sort().join(", ")}`,
    );
  }
}

/**
 * JSON-RPC methods that never execute a tool or read a user's data: the
 * handshake and the registry listings, the same list as the m365 token gate
 * (`lib/m365/injected-fetch.ts`). `notifications/*` is matched by prefix.
 */
const NON_EXECUTING_RPC_METHODS: ReadonlySet<string> = new Set([
  "initialize",
  "ping",
  "tools/list",
  "prompts/list",
  "resources/list",
  "resources/templates/list",
]);
const NOTIFICATION_METHOD_PREFIX = "notifications/";

function isExecutingRpcRequest(message: unknown): boolean {
  if (typeof message !== "object" || message === null) return false;
  const method = (message as { method?: unknown }).method;
  return (
    typeof method === "string" &&
    !NON_EXECUTING_RPC_METHODS.has(method) &&
    !method.startsWith(NOTIFICATION_METHOD_PREFIX)
  );
}

/**
 * Whether this outgoing request can execute backend code and so carries the
 * verified caller. POSITIVE: true only for a POST whose string body parses to
 * a JSON-RPC message, or a batch, containing at least one request that is not
 * the handshake, a listing or a notification. Every other request is false.
 *
 * No body-size shortcut, unlike the m365 gate: that gate's unsure answer is
 * "mint", so it can skip parsing a large body; this one's unsure answer is
 * "no identity", which would refuse a legitimate long tool call. The body is
 * already in memory as a string, and only named backends pay for the parse.
 */
export function requestExecutesBackendCode(init?: RequestInit): boolean {
  if ((init?.method ?? "GET").toUpperCase() !== "POST") return false;
  const body = init?.body;
  if (typeof body !== "string") return false;
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    return false;
  }
  const messages: unknown[] = Array.isArray(parsed) ? parsed : [parsed];
  return messages.some(isExecutingRpcRequest);
}

/**
 * The verified user id for a caller binding: `actsAsUserId ?? userId`, or
 * undefined. Literally that expression: a blank acts-as binding yields no
 * identity rather than falling back to the key owner, because a broken
 * binding must not quietly act as the admin who issued the key.
 */
export function verifiedCallerUserId(
  caller: CallerContext | undefined,
): string | undefined {
  const id = caller?.actsAsUserId ?? caller?.userId;
  return typeof id === "string" && id !== "" ? id : undefined;
}

/**
 * Wrap a pooled transport's fetch so each outgoing request carries the
 * verified caller of the inbound request it serves, and no other value.
 * See the module comment for the strip and set rules.
 */
export function withVerifiedCaller(baseFetch: FetchLike): FetchLike {
  return async (url, init) => {
    const headers = new Headers(init?.headers);
    headers.delete(VERIFIED_CALLER_HEADER);
    if (requestExecutesBackendCode(init)) {
      const userId = verifiedCallerUserId(getCallerContext());
      if (userId) headers.set(VERIFIED_CALLER_HEADER, userId);
    }
    return baseFetch(url, { ...init, headers });
  };
}

/**
 * The `client.ts` wiring hook: the wrapped fetch for a named server, and
 * `baseFetch` itself (the same function, untouched) for every other server.
 * Throws for a server that is also in the m365 list; the boot check makes
 * that unreachable in a running gateway, and this keeps it unreachable for
 * any caller that bypasses the boot path.
 */
export function getVerifiedCallerFetchForServer(
  serverName: string,
  baseFetch: FetchLike,
): FetchLike {
  if (!getVerifiedCallerServerNames().has(serverName)) return baseFetch;
  if (getInjectedServerNames().has(serverName)) {
    throw overlapError([serverName]);
  }
  return withVerifiedCaller(baseFetch);
}

/**
 * Whether a header name is this one, in any casing and with surrounding
 * whitespace ignored. The admin Inspector uses it to refuse an
 * `x-custom-auth-header` that names it (`routers/mcp-proxy/server.ts`).
 */
export function isVerifiedCallerHeaderName(name: unknown): boolean {
  return (
    typeof name === "string" &&
    name.trim().toLowerCase() === VERIFIED_CALLER_HEADER
  );
}

/**
 * A copy of a stored-headers object with this header removed in every
 * casing. The Inspector's direct transports do not go through the pooled
 * fetch, so it applies this to a named backend's stored row headers itself.
 */
export function withoutVerifiedCallerHeader(
  headers: Record<string, string>,
): Record<string, string> {
  return Object.fromEntries(
    Object.entries(headers).filter(
      ([name]) => !isVerifiedCallerHeaderName(name),
    ),
  );
}
