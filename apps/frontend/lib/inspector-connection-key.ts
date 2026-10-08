import type { McpServer } from "@repo/zod-types";

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
 *   bearerToken  becomes the Authorization header the hook sends.
 *   headers      stored request headers the proxy merges into every outbound
 *                remote request.
 *
 * Deliberately left out: `name` and `description` (labels), `created_at` and
 * `user_id` (bookkeeping), and `error_status`. `error_status` is the one that
 * matters: the gateway's crash tracker flips it to ERROR and back to NONE, so
 * a key that read it would reconnect in response to the failure it follows.
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
 * A primitive that changes exactly when the Inspector must open a new
 * connection: a different server, or different settings on the same server.
 * Returns "" when no server is selected.
 *
 * The list query returns a new `servers` array and a new `selectedServer`
 * object whenever ANY row in the list changes, so an effect that depends on
 * those objects reconnects on every unrelated update. React compares a string
 * dependency by value, which is what that effect needs.
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
