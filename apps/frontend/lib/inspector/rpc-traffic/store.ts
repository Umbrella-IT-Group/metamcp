import type { RpcTrafficEntry, RpcTrafficInput, TrafficSink } from "./types";

// Skeleton: the final exported API with inert bodies. The store records
// nothing and reuseOrCreateStore always creates.

export const DEFAULT_MAX_ENTRIES = 1000;
export const DEFAULT_MAX_BYTES = 16 * 1024 * 1024;
export const DEFAULT_MAX_MESSAGE_BYTES = 4 * 1024 * 1024;

export interface RpcTrafficStoreOptions {
  maxEntries?: number;
  maxBytes?: number;
  maxMessageBytes?: number;
  windowMs?: number;
  now?: () => number;
  schedule?: (run: () => void) => void;
}

const EMPTY_SNAPSHOT: readonly RpcTrafficEntry[] = Object.freeze([]);

export class RpcTrafficStore {
  constructor(_options: RpcTrafficStoreOptions = {}) {}

  readonly sink: TrafficSink = {
    message: () => {},
    transport: () => {},
  };

  publish(_input: RpcTrafficInput): void {}
  publishTransportError(_error: unknown): void {}
  publishTransportClosed(): void {}
  getSnapshot = (): readonly RpcTrafficEntry[] => EMPTY_SNAPSHOT;
  getServerSnapshot = (): readonly RpcTrafficEntry[] => EMPTY_SNAPSHOT;
  subscribe = (_listener: () => void): (() => void) => () => {};
  clear(): void {}
  size(): number {
    return 0;
  }
  exportEntries(): RpcTrafficEntry[] {
    return [];
  }
  initializeResult(): Record<string, unknown> | null {
    return null;
  }
}

export function reuseOrCreateStore<S>(options: {
  capture: boolean;
  previous: S | null;
  retryCount: number;
  create: () => S;
}): S | null {
  return options.create();
}
