/**
 * COLD-connect broker-failure fallback for the `tools/call` handler
 * (Track A5). The mint can fail on the backend `initialize` handshake
 * during a fresh connect — that throw is swallowed by the pool's connect
 * path (resolves `undefined`) and by the proxy's dynamic-find
 * catch-and-continue, so it reaches the outer `tools/call` catch as a
 * generic error rather than the typed `M365BrokerError` the WARM path
 * gets. `client.ts`'s connect catch latches the broker failure into the
 * request-scoped sink (`m365/request-context.ts`) for exactly this
 * reason; this module is the drain + ownership-gate glue that turns the
 * latch back into the same enrollment result the WARM path returns
 * (`buildM365BrokerErrorResult`).
 *
 * Kept as its own small module (mirrors `connect-error.ts`) so the
 * wiring itself — drain, parse, gate, build — has direct unit test
 * coverage without pulling in `metamcp-proxy.ts`'s full DB-backed
 * dependency graph (pool, config service, tools-sync cache) just to
 * exercise a few lines of glue.
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolResult } from "@modelcontextprotocol/sdk/types.js";

import { buildM365BrokerErrorResult } from "../m365/broker-error-result";
import { takeConnectBrokerFailure } from "../m365/request-context";
import { parseToolName } from "./tool-name-parser";
import { sanitizeName } from "./utils";

/**
 * Drain any cold-connect broker failure latched for this request and, if
 * it belongs to the server that owns `requestedToolName`, build the
 * enrollment result. Returns `undefined` when there's nothing latched OR
 * the latched failure belongs to a DIFFERENT server than the tool being
 * called — in both cases the caller should re-throw its original error.
 *
 * Gated on ownership: routing an unrelated tool can incidentally
 * probe-connect the m365 backend (dynamic-find walks every server in the
 * namespace) and latch a failure that must not hijack the real tool's
 * error. Only the injected m365 server can ever latch here today.
 *
 * ALWAYS drains via `takeConnectBrokerFailure` — even on a non-match —
 * so a stale failure from probing an unrelated server during dynamic
 * tool routing can't linger into a later request within the same
 * context.
 */
export function resolveColdConnectBrokerFallback(
  requestedToolName: string,
  server: Server,
): CallToolResult | undefined {
  const latched = takeConnectBrokerFailure();
  if (!latched) {
    return undefined;
  }

  const parsed = parseToolName(requestedToolName);
  if (!parsed || parsed.serverName !== sanitizeName(latched.serverName)) {
    return undefined;
  }

  return buildM365BrokerErrorResult(latched.error, server);
}
