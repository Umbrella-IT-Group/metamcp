import {
  type McpServer,
  type McpServerType,
  McpServerTypeEnum,
} from "@repo/zod-types";

import { buildInspectorConnectionKey } from "@/lib/inspector-connection-key";

import type { Translate } from "./translate";

/**
 * What the Inspector page is pointed at, and the one place the page's
 * connection settings come from.
 *
 * A target is a registered server (reached through the proxy's per-server
 * routes, as before), or, for administrators, a namespace or an endpoint
 * through the gateway's admin namespace route (`/mcp-proxy/metamcp/<uuid>/sse`).
 *
 * An endpoint target is a PREVIEW OF THAT ENDPOINT'S NAMESPACE. The admin route
 * has no endpoint concept: it serves a namespace to a signed-in administrator.
 * So nothing configured on the endpoint itself is applied (its presentation,
 * its authentication, its access groups, its rate limits). The labels, the
 * help text and the tests all say so; do not let a change here suggest
 * otherwise.
 */

export interface ResolvableNamespace {
  uuid: string;
  name: string;
}

export interface ResolvableEndpoint {
  uuid: string;
  name: string;
  namespace_uuid: string;
  namespace: { name: string };
}

export type InspectorTarget =
  | { kind: "none" }
  | { kind: "server"; server: McpServer }
  | { kind: "namespace"; namespaceUuid: string; label: string }
  | {
      kind: "endpoint";
      endpointUuid: string;
      endpointName: string;
      namespaceUuid: string;
      namespaceName: string;
    };

export type InspectorTargetKind = InspectorTarget["kind"];

export interface TargetParams {
  server?: string | null;
  namespace?: string | null;
  endpoint?: string | null;
}

export interface TargetLists {
  servers: readonly McpServer[];
  namespaces: readonly ResolvableNamespace[];
  endpoints: readonly ResolvableEndpoint[];
}

const NONE: InspectorTarget = { kind: "none" };

/**
 * Turns the URL parameters into a target by looking the uuid up, as an exact
 * string, in the lists the page loaded. A value that is not in a list (a stale
 * link, a path, anything a person typed) is `none`; no raw parameter is ever
 * used to build a URL.
 *
 * Only the first parameter that is present decides, in the order server,
 * namespace, endpoint: a present parameter that does not resolve gives `none`
 * and the next one is not tried, so a crafted URL cannot reach a gateway
 * target by also carrying a bad `server`.
 *
 * Namespace and endpoint are administrator-only (the whole `/mcp-proxy` route
 * is admin-gated, so a member would only get a 403): with `isAdmin` false they
 * resolve to `none` whatever the lists hold.
 */
export function resolveInspectorTarget(
  params: TargetParams,
  lists: TargetLists,
  opts: { isAdmin: boolean },
): InspectorTarget {
  if (params.server) {
    const server = lists.servers.find((entry) => entry.uuid === params.server);
    return server ? { kind: "server", server } : NONE;
  }
  if (!opts.isAdmin) return NONE;

  if (params.namespace) {
    const namespace = lists.namespaces.find(
      (entry) => entry.uuid === params.namespace,
    );
    return namespace
      ? {
          kind: "namespace",
          namespaceUuid: namespace.uuid,
          label: namespace.name,
        }
      : NONE;
  }
  if (params.endpoint) {
    const endpoint = lists.endpoints.find(
      (entry) => entry.uuid === params.endpoint,
    );
    return endpoint
      ? {
          kind: "endpoint",
          endpointUuid: endpoint.uuid,
          endpointName: endpoint.name,
          // The connection is made to the endpoint's namespace.
          namespaceUuid: endpoint.namespace_uuid,
          namespaceName: endpoint.namespace.name,
        }
      : NONE;
  }
  return NONE;
}

export interface InspectorConnectionOptions {
  mcpServerUuid: string;
  transportType: McpServerType;
  command: string;
  args: string;
  url: string;
  bearerToken?: string;
  isMetaMCP?: true;
  includeInactiveServers?: boolean;
  /** False for `none`; the page also waits for its lists to load. */
  targetEnabled: boolean;
}

/**
 * The connection settings for a target.
 *
 * A server keeps exactly the mapping the page always used. A gateway target
 * connects to the namespace's admin route; the endpoint's uuid and name never
 * appear in the URL (the route takes a namespace). `includeInactive` applies
 * to gateway targets only: clients never see inactive mounts, so it starts
 * off.
 */
export function inspectorConnectionOptions(
  target: InspectorTarget,
  includeInactive = false,
): InspectorConnectionOptions {
  switch (target.kind) {
    case "server": {
      const { server } = target;
      return {
        mcpServerUuid: server.uuid,
        transportType: server.type || McpServerTypeEnum.enum.STDIO,
        command: server.command || "",
        args: server.args?.join(" ") || "",
        url: server.url || "",
        bearerToken: server.bearerToken || undefined,
        targetEnabled: true,
      };
    }
    case "namespace":
    case "endpoint":
      return {
        mcpServerUuid: target.namespaceUuid,
        transportType: McpServerTypeEnum.enum.SSE,
        command: "",
        args: "",
        url: `/mcp-proxy/metamcp/${encodeURIComponent(target.namespaceUuid)}/sse`,
        isMetaMCP: true,
        includeInactiveServers: includeInactive,
        targetEnabled: true,
      };
    case "none":
      return {
        mcpServerUuid: "",
        transportType: McpServerTypeEnum.enum.STDIO,
        command: "",
        args: "",
        url: "",
        targetEnabled: false,
      };
  }
}

/**
 * A primitive that changes when the page must open a new connection. A server
 * keeps its existing key byte for byte (see inspector-connection-key.ts). A
 * gateway target is the namespace and the inactive flag: an endpoint and its
 * own namespace are the same connection, so moving between them reconnects
 * nothing.
 */
export function buildInspectorTargetKey(
  target: InspectorTarget,
  includeInactive = false,
): string {
  switch (target.kind) {
    case "server":
      return buildInspectorConnectionKey(target.server);
    case "namespace":
    case "endpoint":
      return JSON.stringify(["gateway", target.namespaceUuid, includeInactive]);
    case "none":
      return "none";
  }
}

export type InspectorTabId =
  | "tools"
  | "resources"
  | "prompts"
  | "ping"
  | "roots"
  | "sampling"
  | "serverInfo";

/**
 * The tabs a target shows, in order. A server shows the six it always did and
 * Server info. A gateway target serves tools only (prompts and resources
 * answer empty lists locally) and roots and sampling are features of the
 * Inspector as a client that the gateway does not use, so it shows Tools,
 * Ping and Server info.
 */
export function visibleTabs(kind: InspectorTargetKind): InspectorTabId[] {
  switch (kind) {
    case "server":
    case "none":
      return [
        "tools",
        "resources",
        "prompts",
        "ping",
        "roots",
        "sampling",
        "serverInfo",
      ];
    case "namespace":
    case "endpoint":
      return ["tools", "ping", "serverInfo"];
  }
}

/** The name a log or file is labelled with. */
export function targetName(target: InspectorTarget): string {
  switch (target.kind) {
    case "server":
      return target.server.name;
    case "namespace":
      return target.label;
    case "endpoint":
      return target.endpointName;
    case "none":
      return "";
  }
}

/**
 * The label shown for the selected target. An endpoint reads as a preview of
 * its namespace, because that is what it is.
 */
export function describeTarget(target: InspectorTarget, t: Translate): string {
  switch (target.kind) {
    case "server":
      return target.server.name;
    case "namespace":
      return t("inspector:inspectorTarget.namespaceLabel", {
        namespace: target.label,
      });
    case "endpoint":
      return t("inspector:inspectorTarget.endpointLabel", {
        endpoint: target.endpointName,
        namespace: target.namespaceName,
      });
    case "none":
      return "";
  }
}
