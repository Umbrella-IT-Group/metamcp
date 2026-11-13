/**
 * Pairing of requests with their responses in the Inspector's JSON-RPC
 * traffic log.
 *
 * Adapted from mcp-use, libraries/typescript/packages/inspector/
 * src/client/rpc-traffic-correlation.ts at commit 546081e
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
 *   - One log serves one connection, so the key is the direction and the id
 *     alone (no server or widget identity). `typeof` stays in it: JSON-RPC
 *     ids are strings or numbers, and 0 and "0" are different ids.
 *   - Each label names the request's entry, and a second map goes the other
 *     way (request entry to its response), so the panel can badge both rows.
 *   - Both maps come from one pass over the entries.
 *   - The entry types are this log's own.
 */

import { getRpcTrafficMethod } from "./coalesce";
import {
  asRecord,
  isRpcId,
  type RpcTrafficDirection,
  type RpcTrafficEntry,
} from "./types";

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
  /** Response entry id to the request it answers. */
  responseLabels: ReadonlyMap<string, RpcResponseLabel>;
  /** Request entry id to the response that answered it. */
  requestPairs: ReadonlyMap<string, RpcRequestPair>;
}

interface PendingRequest {
  entryId: string;
  method: string;
  timestampMs: number;
}

function correlationKey(
  direction: RpcTrafficDirection,
  id: string | number,
): string {
  return JSON.stringify([direction, typeof id, id]);
}

function responseOutcome(message: Record<string, unknown>): RpcOutcome | null {
  if (message.error !== undefined) return "error";
  if (message.result !== undefined) return "result";
  return null;
}

export function buildRpcTrafficPairs(
  entries: readonly RpcTrafficEntry[],
): RpcTrafficPairs {
  const pending = new Map<string, PendingRequest>();
  const responseLabels = new Map<string, RpcResponseLabel>();
  const requestPairs = new Map<string, RpcRequestPair>();

  for (const entry of entries) {
    const message = asRecord(entry.message);
    // A transport event, a notification and anything else with no id is not
    // part of a pair.
    if (!message || !isRpcId(message.id)) continue;
    const id = message.id;
    const timestampMs = Date.parse(entry.timestamp);

    const method = getRpcTrafficMethod(message);
    if (method !== null) {
      // A request, from either side (the server can ask the client too).
      if (Number.isNaN(timestampMs)) continue;
      pending.set(correlationKey(entry.direction, id), {
        entryId: entry.id,
        method,
        timestampMs,
      });
      continue;
    }

    const outcome = responseOutcome(message);
    if (outcome === null) continue;

    // A response answers a request that went the other way.
    const requestDirection = entry.direction === "send" ? "receive" : "send";
    const requestKey = correlationKey(requestDirection, id);
    const request = pending.get(requestKey);
    if (!request) continue;
    pending.delete(requestKey);

    const latencyMs = timestampMs - request.timestampMs;
    if (Number.isNaN(latencyMs) || latencyMs < 0) continue;

    responseLabels.set(entry.id, {
      requestEntryId: request.entryId,
      method: request.method,
      latencyMs,
      outcome,
    });
    requestPairs.set(request.entryId, {
      responseEntryId: entry.id,
      latencyMs,
      outcome,
    });
  }

  return { responseLabels, requestPairs };
}
