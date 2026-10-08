import type { McpServer } from "@repo/zod-types";

import type { ConnectionStatus } from "./constants";

/**
 * The fields of a registered server that decide what an Inspector connection
 * talks to and how, and nothing else.
 *
 * The Inspector page connects through the gateway's proxy, and the proxy
 * rebuilds the connection from the stored `mcp_servers` row at connect time
 * (see `findRegisteredStdioServer` and `findAccessibleRemoteServer` in
 * `apps/backend/src/routers/mcp-proxy/server.ts`). So the settings that matter
 * are the ones the proxy reads, not only the ones the page passes to
 * `useConnection`:
 *
 *   uuid         which row the proxy resolves (STDIO), and which OAuth state the
 *                hook keys on.
 *   type         picks the transport (STDIO, SSE, STREAMABLE_HTTP).
 *   command,
 *   args, env    what a STDIO server spawns. `args` is kept as an array: the
 *                proxy spawns the stored array, so ["a b"] and ["a", "b"] are
 *                different servers even though the page joins them into the
 *                same string for the hook.
 *   url          the destination of a remote server.
 *   bearerToken  becomes the Authorization header the hook sends. This fork's
 *                list serializer always returns it as null (the token is never
 *                sent to the browser), so the field is inert here: a bearer-only
 *                edit cannot change the key and cannot change what the
 *                Inspector connects with either. It stays in the key because
 *                the page passes it to the hook, so the key follows the page if
 *                the serializer ever returns it.
 *   headers      stored request headers the proxy merges into every outbound
 *                remote request.
 *
 * Deliberately left out: `name` and `description` (labels), `created_at` and
 * `user_id` (bookkeeping), and `error_status`. `error_status` is the one that
 * matters: the pool's crash tracker writes it, independent of the Inspector's
 * own connection, and the proxy refuses a row that is in ERROR when it
 * connects, so a status flip is not a reason to reconnect.
 *
 * When `McpServerSchema` gains a field, `inspector-connection-key.test.ts`
 * fails until the field is classified as keyed or ignored there.
 */
export type InspectorConnectionFields = Pick<
  McpServer,
  | "uuid"
  | "type"
  | "command"
  | "args"
  | "env"
  | "url"
  | "bearerToken"
  | "headers"
>;

// Key order of a stored jsonb object is not part of its meaning. Sort by code
// unit (not locale) so the order is the same in every browser.
function sortedEntries(
  record: Record<string, string> | null | undefined,
): [string, string][] {
  return Object.entries(record ?? {}).sort(([a], [b]) =>
    a < b ? -1 : a > b ? 1 : 0,
  );
}

/**
 * A primitive that changes when the Inspector must open a new connection: a
 * different server, or different settings on the same server. It is not
 * per-transport, so a setting the selected server's transport ignores (a
 * headers or url edit on a STDIO server, say) also changes it; that costs one
 * reconnect and is harmless. Returns "" when no server is selected.
 *
 * The list query returns a new `servers` array whenever ANY row in the list
 * changes (the query cache keeps an unchanged row's object, so
 * `selectedServer` is new only when its own row changes). An effect that
 * depends on `servers` therefore reconnects on every unrelated update. React
 * compares a string dependency by value, which is what that effect needs.
 *
 * `null` and `""` are the same setting here because the page hands the hook
 * `|| ""` for `command` and `url` and the proxy tests `command` for
 * truthiness. The key holds the server's env and bearer token, so it stays in
 * memory as an effect dependency: never log or render it.
 */
export function buildInspectorConnectionKey(
  server: InspectorConnectionFields | null | undefined,
): string {
  if (!server) return "";
  return JSON.stringify([
    server.uuid,
    server.type,
    server.command ?? "",
    server.args ?? [],
    sortedEntries(server.env),
    server.url ?? "",
    server.bearerToken ?? "",
    sortedEntries(server.headers),
  ]);
}

/**
 * What the Inspector page does when its connection key changes (or the server
 * list finishes loading), given the hook's current status.
 *
 *   "reconnect"  connected to the previous server or settings: disconnect, then
 *                connect.
 *   "connect"    the hook holds no client, so connect. This includes the two
 *                error states: after a failed connect the failure belongs to
 *                the previous server or settings, so a changed key is a reason
 *                to try again. It cannot loop, because a failed connect does
 *                not change the key.
 *   "none"       a connect is reported as in flight; leave it alone.
 *
 * Kept as a pure function so the error branch has a regression test: the page
 * effect itself is not unit tested.
 */
export function inspectorConnectAction(
  status: ConnectionStatus,
): "reconnect" | "connect" | "none" {
  switch (status) {
    case "connected":
      return "reconnect";
    case "disconnected":
    case "error":
    case "error-connecting-to-proxy":
      return "connect";
    case "connecting":
      return "none";
  }
}
