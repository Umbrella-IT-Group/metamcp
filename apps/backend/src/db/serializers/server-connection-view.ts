import type { ServerDetailLevel } from "@repo/trpc";

/**
 * The connection fields of a stored server, as the two server serializers
 * (`McpServersSerializer` and the servers embedded by `NamespacesSerializer`)
 * emit them. One function for both, so the redaction set cannot drift between
 * the two routes a server object leaves by.
 *
 * `detail` is required and has no default. A value this function does not
 * recognise (a stale caller still passing a boolean, a typo) is read as
 * `redacted`, the least, so a new call site cannot inherit a connection by
 * omission.
 */
export interface StoredServerConnection {
  command: string | null;
  args: string[] | null | undefined;
  env: Record<string, string> | null | undefined;
  url: string | null;
  headers: Record<string, string> | null | undefined;
}

export interface ServerConnectionView {
  command: string | null;
  args: string[];
  env: Record<string, string>;
  url: string | null;
  headers: Record<string, string>;
}

/** Every value of the record replaced by the empty string, names kept. */
function withheldValues(
  record: Record<string, string> | null | undefined,
): Record<string, string> {
  const names: Record<string, string> = {};
  for (const name of Object.keys(record ?? {})) names[name] = "";
  return names;
}

export function serverConnectionView(
  server: StoredServerConnection,
  detail: ServerDetailLevel,
): ServerConnectionView {
  if (detail === "full") {
    return {
      command: server.command,
      args: server.args ?? [],
      env: server.env ?? {},
      url: server.url,
      headers: server.headers ?? {},
    };
  }
  if (detail === "names_only") {
    // The schema's own empty and null values, never a sentinel string: a
    // client parses the reply unchanged and renders nothing fake. The names
    // stay because they say what is configured. The URL goes whole: a path,
    // a query or a fragment can carry a credential as well as userinfo.
    return {
      command: null,
      args: [],
      env: withheldValues(server.env),
      url: null,
      headers: withheldValues(server.headers),
    };
  }
  return { command: null, args: [], env: {}, url: null, headers: {} };
}
