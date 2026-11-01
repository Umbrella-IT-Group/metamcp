import type { FetchLike } from "@modelcontextprotocol/sdk/shared/transport.js";

import { getCallerContext } from "./caller-context-store";

/**
 * `X-MCP-Actor` on the POOLED data plane: the operator label a client asserts,
 * forwarded per request to the backend MCP servers.
 *
 * WHAT IT IS. Each operator's MCP client sends `X-MCP-Actor: <their email>` on
 * every request so the backend MCPs that keep an audit trail (shell-broker,
 * ninja, inventory, blackpoint, dropsuite, the network and CIPP grant doors)
 * can name the person an action was taken for instead of their generic
 * `mcp:<server>` default. It is ATTRIBUTION, NOT AUTHENTICATION: a caller can
 * send any value, so no backend may authorize on it. The authenticated record
 * of who called stays the endpoint credential and this gateway's own
 * `tool_call_audit` row.
 *
 * WHY THIS MODULE EXISTS. Fork #139 put the header on the passthrough list of
 * the admin Inspector proxy (`routers/mcp-proxy/server.ts`). Operator clients
 * do not use that route: they connect to the public endpoints
 * (`/metamcp/<endpoint>/mcp`), whose tool calls reach the backend through the
 * pooled client built in `client.ts`, and that path copied no inbound header.
 * A caller relying on that header could therefore receive the backend's
 * fallback attribution even when its client sent the header. The reported
 * live evidence is fallback attribution in inventory and disclosure audit
 * rows; effects on the other consumers follow from the shared code path.
 *
 * WHY PER REQUEST, NOT PER CONNECTION. One pooled backend connection serves
 * many callers (idle handoff, per-server cap reuse), so a header fixed at
 * connect time would name whoever connected first. The value rides the
 * request-scoped caller binding (`caller-context-store`), which every public
 * transport enters once per inbound request, and the pool's fetch reads it at
 * send time. That is the carrier and the choke point the M365 per-user
 * injection already uses (`lib/m365/injected-fetch.ts`).
 *
 * STRIP, THEN SET. Any `x-mcp-actor` already on the outgoing request (a server
 * row's stored headers) is removed first, and this request's value is set only
 * when the request carried one. A connection-level value would label every
 * caller's call with one name, and an audit row that names the wrong person is
 * worse than one that names nobody.
 *
 * CONNECTION CONTROL TRAFFIC. This wrapper also covers initialization, the
 * standalone stream GET and teardown. A cold connect inside a request carries
 * that request's label, and SDK reconnect timers retain their opening async
 * scope. Backends must read the actor on the CURRENT tool-call request, never
 * cache a handshake or stream's label as the pooled session's actor. Later
 * tool calls independently replace or clear the header; the real-SDK cold
 * connect/reconnect test in `client-actor-header.test.ts` pins that boundary.
 *
 * INTERNAL DESTINATIONS ONLY. The pool's guarded fetch drops this header on
 * any hop whose destination is not internal (`internalOnlyHeaders` in
 * `url-guard.ts`, the same classification that gates the gateway trust
 * header), so an operator's address never reaches a third-party MCP server
 * someone configured.
 */
export const ASSERTED_ACTOR_HEADER = "x-mcp-actor";

/**
 * Longest value forwarded. The backend readers cap at 256 (blackpoint, ninja,
 * inventory, shell-broker) or 200 (dropsuite, the grant doors), so 256 loses
 * nothing any of them keeps while bounding what one request can push upstream.
 */
export const ASSERTED_ACTOR_MAX_CHARS = 256;

/**
 * The value to forward for an inbound `x-mcp-actor` header, or undefined.
 *
 * Trimmed and capped; blank and non-string values (absent, or an array a
 * caller might construct by hand) forward nothing. No other filtering: Node's
 * HTTP parser already refused control characters in the inbound value, so
 * what remains is a valid outbound header value, and the backends store it as
 * a bound parameter, never interpolated.
 */
export function normalizeAssertedActor(raw: unknown): string | undefined {
  if (typeof raw !== "string") return undefined;
  const value = raw.trim().slice(0, ASSERTED_ACTOR_MAX_CHARS).trim();
  return value === "" ? undefined : value;
}

/**
 * Wrap a pooled transport's fetch so each outgoing request carries the
 * asserted actor of the inbound request it serves, and no other.
 *
 * Outside any request scope (idle warm-up, health probes, sweeps) there is no
 * caller binding and the request leaves with no `x-mcp-actor` at all.
 */
export function withAssertedActor(baseFetch: FetchLike): FetchLike {
  return (url, init) => {
    const headers = new Headers(init?.headers);
    headers.delete(ASSERTED_ACTOR_HEADER);
    const actor = getCallerContext()?.assertedActor;
    if (actor) headers.set(ASSERTED_ACTOR_HEADER, actor);
    return baseFetch(url, { ...init, headers });
  };
}
