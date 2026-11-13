/**
 * Merging of bursty notifications in the Inspector's JSON-RPC traffic log.
 *
 * Adapted from mcp-use, libraries/typescript/packages/inspector/
 * src/client/rpc-traffic-coalesce.ts at commit 546081e
 * (https://github.com/mcp-use/mcp-use), which is distributed under the MIT
 * License below.
 *
 * MIT License
 *
 * Copyright (c) 2025 pietrozullo
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * Changes from the original:
 *   - The key is an allowlist. The original merged every method that matched
 *     `notifications/`, which folded `notifications/message` (each one is a
 *     different log line) and `notifications/cancelled` (a different
 *     `requestId` each time) into the last one and lost the rest. Only a burst
 *     that carries no new information is merged: progress notifications of one
 *     progress token (only the latest value matters) and the three
 *     `list_changed` notifications (each one means "ask again").
 *   - A progress notification with no token is never merged.
 *   - The window and the clock are parameters, and a clock that went backwards
 *     does not merge.
 *   - The entry types are this log's own (one log per connection, no server or
 *     widget identity).
 */

import { asRecord, type RpcTrafficEntry, type RpcTrafficInput } from "./types";

/** A burst this close to the previous row of the same kind is merged into it. */
export const RPC_COALESCE_WINDOW_MS = 300;

const LIST_CHANGED_METHODS = new Set([
  "notifications/tools/list_changed",
  "notifications/resources/list_changed",
  "notifications/prompts/list_changed",
]);

export function getRpcTrafficMethod(message: unknown): string | null {
  const method = asRecord(message)?.method;
  return typeof method === "string" ? method : null;
}

/**
 * A stable merge key for a notification that may fold into the row before it,
 * or null when the message must always get its own row (every request and
 * response, and every notification that is not on the allowlist).
 */
export function getRpcCoalesceKey(input: RpcTrafficInput): string | null {
  const record = asRecord(input.message);
  if (!record) return null;
  // A request has an id; a response has a result or an error. Neither merges.
  if (record.id !== undefined && record.id !== null) return null;
  if (record.result !== undefined || record.error !== undefined) return null;

  const method = getRpcTrafficMethod(input.message);
  if (method === null) return null;

  if (method === "notifications/progress") {
    const token = asRecord(record.params)?.progressToken;
    if (typeof token !== "string" && typeof token !== "number") return null;
    // typeof keeps token 0 and token "0" apart (JSON-RPC ids and progress
    // tokens are string or number, and the two are different values).
    return JSON.stringify([input.direction, method, typeof token, token]);
  }
  if (LIST_CHANGED_METHODS.has(method)) {
    return JSON.stringify([input.direction, method]);
  }
  return null;
}

export function shouldCoalesceWithLast(
  last: RpcTrafficEntry,
  next: RpcTrafficInput,
  nextMs: number,
  windowMs: number = RPC_COALESCE_WINDOW_MS,
): boolean {
  const lastKey = getRpcCoalesceKey(last);
  if (lastKey === null || lastKey !== getRpcCoalesceKey(next)) return false;

  const lastMs = Date.parse(last.timestamp);
  if (Number.isNaN(lastMs)) return false;
  const elapsed = nextMs - lastMs;
  return elapsed >= 0 && elapsed <= windowMs;
}

export function mergeRpcTrafficEntry(
  last: RpcTrafficEntry,
  next: Pick<RpcTrafficEntry, "timestamp" | "message" | "bytes" | "truncated">,
): RpcTrafficEntry {
  // The row shows the latest burst, so it takes the latest message and its
  // size and truncation (not the earlier row's) and counts the merge.
  const merged: RpcTrafficEntry = {
    id: last.id,
    direction: last.direction,
    timestamp: next.timestamp,
    message: next.message,
    bytes: next.bytes,
    repeatCount: (last.repeatCount ?? 1) + 1,
  };
  if (next.truncated) merged.truncated = true;
  return merged;
}
