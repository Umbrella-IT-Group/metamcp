import type { RpcTrafficEntry } from "./types";

// Skeleton: the final exported API with inert bodies.

type RpcOutcome = "result" | "error";

export interface RpcResponseLabel {
  requestEntryId: string;
  method: string;
  latencyMs: number;
  outcome: RpcOutcome;
}

export interface RpcRequestPair {
  responseEntryId: string;
  latencyMs: number;
  outcome: RpcOutcome;
}

export interface RpcTrafficPairs {
  responseLabels: ReadonlyMap<string, RpcResponseLabel>;
  requestPairs: ReadonlyMap<string, RpcRequestPair>;
}

export function buildRpcTrafficPairs(
  _entries: readonly RpcTrafficEntry[],
): RpcTrafficPairs {
  return { responseLabels: new Map(), requestPairs: new Map() };
}
