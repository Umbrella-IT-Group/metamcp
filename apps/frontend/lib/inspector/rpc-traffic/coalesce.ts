import type { RpcTrafficEntry, RpcTrafficInput } from "./types";

// Skeleton: the final exported API with inert bodies.

export const RPC_COALESCE_WINDOW_MS = 300;

export function getRpcTrafficMethod(_message: unknown): string | null {
  return null;
}

export function getRpcCoalesceKey(_input: RpcTrafficInput): string | null {
  return null;
}

export function shouldCoalesceWithLast(
  _last: RpcTrafficEntry,
  _next: RpcTrafficInput,
  _nextMs: number,
  _windowMs: number = RPC_COALESCE_WINDOW_MS,
): boolean {
  return false;
}

export function mergeRpcTrafficEntry(
  last: RpcTrafficEntry,
  _next: Pick<RpcTrafficEntry, "timestamp" | "message" | "bytes" | "truncated">,
): RpcTrafficEntry {
  return last;
}
