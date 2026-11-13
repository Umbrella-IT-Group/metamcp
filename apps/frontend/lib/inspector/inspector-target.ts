import type { McpServer, McpServerType } from "@repo/zod-types";

import type { Translate } from "./translate";

/**
 * Skeleton: the final exported API with inert bodies. The tests are written
 * against the real behaviour and fail here by assertion.
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

export function resolveInspectorTarget(
  _params: TargetParams,
  _lists: TargetLists,
  _opts: { isAdmin: boolean },
): InspectorTarget {
  return { kind: "none" };
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
  targetEnabled: boolean;
}

export function inspectorConnectionOptions(
  _target: InspectorTarget,
  _includeInactive = false,
): InspectorConnectionOptions {
  return {
    mcpServerUuid: "",
    transportType: "STDIO",
    command: "",
    args: "",
    url: "",
    targetEnabled: false,
  };
}

export function buildInspectorTargetKey(
  _target: InspectorTarget,
  _includeInactive = false,
): string {
  return "";
}

export type InspectorTabId =
  | "tools"
  | "resources"
  | "prompts"
  | "ping"
  | "roots"
  | "sampling"
  | "serverInfo";

export function visibleTabs(_kind: InspectorTargetKind): InspectorTabId[] {
  return [];
}

export function targetName(_target: InspectorTarget): string {
  return "";
}

export function describeTarget(
  _target: InspectorTarget,
  _t: Translate,
): string {
  return "";
}
