import type { RpcResponseLabel } from "./correlation";
import { asRecord, isRpcId, type RpcTrafficEntry } from "./types";

/**
 * What the traffic panel searches and what its Download writes.
 */

/**
 * Whether the download leaves out `params` and `result` bodies unless the
 * user turns that off. On, because a log is usually shared or attached to a
 * report and holds tool arguments and results exactly as exchanged (password
 * lookups, mailbox content); the structure alone (methods, ids, timing,
 * error codes) is what most debugging needs. It is an option, not a gate:
 * one checkbox, no confirmation.
 */
export const DEFAULT_OMIT_BODIES = true;

// Searching reads this much of a message body, so one huge result does not
// make every keystroke scan megabytes.
const SEARCH_BODY_LIMIT = 65_536;

// A transport error's text is kept in an export that leaves bodies out (it is
// the diagnosis of a failed connect) but bounded.
const OMITTED_TRANSPORT_TEXT_LIMIT = 500;

const searchTextCache = new WeakMap<RpcTrafficEntry, string>();

export function entrySearchText(entry: RpcTrafficEntry): string {
  const cached = searchTextCache.get(entry);
  if (cached !== undefined) return cached;
  const record = asRecord(entry.message);
  const method = typeof record?.method === "string" ? record.method : "";
  const text = `${method} ${JSON.stringify(entry.message).slice(0, SEARCH_BODY_LIMIT)}`;
  const lowered = text.toLowerCase();
  searchTextCache.set(entry, lowered);
  return lowered;
}

export function filterEntries(
  entries: readonly RpcTrafficEntry[],
  query: string,
): readonly RpcTrafficEntry[] {
  const needle = query.trim().toLowerCase();
  if (needle === "") return entries;
  return entries.filter((entry) => entrySearchText(entry).includes(needle));
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
  /** True when `params`, `result` and `error.data` were left out. */
  bodiesOmitted: boolean;
  entries: TrafficExportEntry[];
}

/**
 * The message with its bodies removed: `jsonrpc`, `id`, `method` and an error
 * code stay; `params`, `result` and `error.data` (and an error's free text)
 * go. A transport event keeps its kind and a bounded error text.
 */
function omitBodies(message: unknown): unknown {
  const record = asRecord(message);
  if (!record) return message;

  if (typeof record.transportEvent === "string") {
    const kept: Record<string, unknown> = {
      transportEvent: record.transportEvent,
    };
    if (typeof record.error === "string") {
      kept.error =
        record.error.length > OMITTED_TRANSPORT_TEXT_LIMIT
          ? `${record.error.slice(0, OMITTED_TRANSPORT_TEXT_LIMIT)}...`
          : record.error;
    }
    return kept;
  }

  const kept: Record<string, unknown> = {};
  if (typeof record.jsonrpc === "string") kept.jsonrpc = record.jsonrpc;
  if (isRpcId(record.id) || record.id === null) kept.id = record.id;
  if (typeof record.method === "string") kept.method = record.method;
  const error = asRecord(record.error);
  if (error) kept.error = { code: error.code };
  return kept;
}

export function buildTrafficExport(
  entries: readonly RpcTrafficEntry[],
  responseLabels: ReadonlyMap<string, RpcResponseLabel>,
  meta: TrafficExportMeta,
  options: { omitBodies: boolean },
): TrafficExport {
  return {
    format: "metamcp-inspector-rpc-log",
    version: 1,
    exportedAt: new Date(meta.exportedAtMs).toISOString(),
    target: { kind: meta.target.kind, name: meta.target.name },
    bodiesOmitted: options.omitBodies,
    entries: entries.map((entry) => {
      const label = responseLabels.get(entry.id);
      const exported: TrafficExportEntry = {
        id: entry.id,
        direction: entry.direction,
        timestamp: entry.timestamp,
        message: options.omitBodies ? omitBodies(entry.message) : entry.message,
      };
      if (entry.repeatCount !== undefined) {
        exported.repeatCount = entry.repeatCount;
      }
      if (label) exported.latencyMs = label.latencyMs;
      return exported;
    }),
  };
}

/**
 * `metamcp-inspector-traffic-<target>-<UTC time>.json`. The target name is
 * reduced to letters, digits, underscore and hyphen, so it can never carry a
 * path separator or a character a file system treats specially.
 */
export function trafficExportFilename(
  targetName: string,
  nowMs: number,
): string {
  const safe =
    targetName.replace(/[^A-Za-z0-9_-]/g, "_").slice(0, 48) || "target";
  const stamp = new Date(nowMs)
    .toISOString()
    .replace(/[-:]/g, "")
    .replace(/\.\d+Z$/, "Z");
  return `metamcp-inspector-traffic-${safe}-${stamp}.json`;
}

/**
 * The `result` of the initialize response: the first request sent with method
 * `initialize`, then the response received with the same id. Null when either
 * is missing (or the log no longer holds them).
 */
export function extractInitializeResult(
  entries: readonly RpcTrafficEntry[],
): Record<string, unknown> | null {
  let requestId: string | number | undefined;
  for (const entry of entries) {
    const record = asRecord(entry.message);
    if (!record) continue;
    if (requestId === undefined) {
      if (
        entry.direction === "send" &&
        record.method === "initialize" &&
        isRpcId(record.id)
      ) {
        requestId = record.id;
      }
      continue;
    }
    if (
      entry.direction === "receive" &&
      record.method === undefined &&
      record.id === requestId
    ) {
      return asRecord(record.result);
    }
  }
  return null;
}
