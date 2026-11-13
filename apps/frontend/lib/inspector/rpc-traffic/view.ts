import type { RpcResponseLabel } from "./correlation";
import type { RpcTrafficEntry } from "./types";

// Skeleton: the final exported API with inert bodies.

export const DEFAULT_OMIT_BODIES = false;

export function entrySearchText(_entry: RpcTrafficEntry): string {
  return "";
}

export function filterEntries(
  entries: readonly RpcTrafficEntry[],
  _query: string,
): readonly RpcTrafficEntry[] {
  return entries;
}

export interface TrafficExportMeta {
  target: { kind: string; name: string };
  exportedAtMs: number;
}

export interface TrafficExportEntry {
  id: string;
  direction: RpcTrafficEntry["direction"];
  timestamp: string;
  repeatCount?: number;
  latencyMs?: number;
  message: unknown;
}

export interface TrafficExport {
  format: "metamcp-inspector-rpc-log";
  version: 1;
  exportedAt: string;
  target: { kind: string; name: string };
  bodiesOmitted: boolean;
  entries: TrafficExportEntry[];
}

export function buildTrafficExport(
  _entries: readonly RpcTrafficEntry[],
  _responseLabels: ReadonlyMap<string, RpcResponseLabel>,
  meta: TrafficExportMeta,
  _options: { omitBodies: boolean },
): TrafficExport {
  return {
    format: "metamcp-inspector-rpc-log",
    version: 1,
    exportedAt: "",
    target: meta.target,
    bodiesOmitted: false,
    entries: [],
  };
}

export function trafficExportFilename(
  _targetName: string,
  _nowMs: number,
): string {
  return "";
}

export function extractInitializeResult(
  _entries: readonly RpcTrafficEntry[],
): Record<string, unknown> | null {
  return null;
}
