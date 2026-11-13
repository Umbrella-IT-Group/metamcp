import type { JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";

/**
 * Shared shapes of the Inspector's JSON-RPC traffic log. One log belongs to
 * one connection, so an entry carries no server or widget identity.
 */

export type RpcTrafficDirection = "send" | "receive";

export interface RpcTrafficEntry {
  id: string;
  direction: RpcTrafficDirection;
  /** ISO 8601, from the store's injected clock. */
  timestamp: string;
  /**
   * The JSON-RPC message as exchanged, or a transport event
   * (`{ transportEvent: "error", error }` or `{ transportEvent: "closed" }`).
   * Replaced by an envelope with a truncation marker when it was too large to
   * keep (see `truncated`).
   */
  message: unknown;
  /** Length of the message's JSON text as exchanged (before any truncation). */
  bytes: number;
  /** How many bursts of one notification were merged into this row. */
  repeatCount?: number;
  /** The body was over the per-message limit and was not kept. */
  truncated?: true;
}

export type RpcTrafficInput = {
  direction: RpcTrafficDirection;
  message: unknown;
};

/**
 * Where the transport tap reports. The tap only observes: a sink must never
 * be able to change what the transport sends or delivers.
 */
export interface TrafficSink {
  message(direction: RpcTrafficDirection, message: JSONRPCMessage): void;
  transport(event: "error" | "closed", error?: unknown): void;
}

export function asRecord(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

export function isRpcId(value: unknown): value is string | number {
  return typeof value === "string" || typeof value === "number";
}
