import type { ConnectionStatus } from "@/lib/constants";

/**
 * What the server page's tools panel shows.
 *
 *   server-error      the row is marked ERROR; the page does not connect.
 *   tools             connected; the tool list itself.
 *   connecting        a connect is under way; the loading placeholder.
 *   connection-error  the connect failed; an error, not the placeholder.
 *   idle              not connected yet; the placeholder and a prompt.
 *
 * A failed connect used to fall through to the loading placeholder, so a
 * server the proxy refused looked like one still loading, with no end.
 */
export type ToolsPanelView =
  | "server-error"
  | "tools"
  | "connecting"
  | "connection-error"
  | "idle";

export function toolsPanelView(
  serverInError: boolean,
  connectionStatus: ConnectionStatus,
): ToolsPanelView {
  if (serverInError) return "server-error";
  switch (connectionStatus) {
    case "connected":
      return "tools";
    case "connecting":
      return "connecting";
    case "error":
    case "error-connecting-to-proxy":
      return "connection-error";
    case "disconnected":
      return "idle";
  }
}
