/**
 * The Inspector's in-memory JSON-RPC traffic log: one store per connection.
 *
 * Adapted from mcp-use, libraries/typescript/packages/inspector/
 * src/client/rpc-traffic-store.ts at commit 546081e
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
 *   - It is a class instance per connection, not a process singleton, so one
 *     log never carries another target's traffic and a new connection starts
 *     an empty log (see reuseOrCreateStore).
 *   - `getSnapshot` returns a cached array that is rebuilt once per emit and
 *     never mutated afterwards. The original returned the array `publish`
 *     mutates in place, so a `useSyncExternalStore` subscriber saw the same
 *     reference after every change and never re-rendered.
 *   - Two caps instead of one: a number of entries and the total JSON text
 *     held, and a per-message cap above which a message is kept only as its
 *     envelope (id and method) with a truncation marker.
 *   - The initialize result is captured the moment it is published, so the
 *     page can read it right after `connect()`, before the snapshot (which is
 *     deferred to the next frame) catches up.
 *   - Transport errors and closes are entries too, and one error object that
 *     reaches the log by two routes is recorded once.
 *   - The clock, the scheduler and every limit are injectable.
 *   - Coalescing is allowlisted (see coalesce.ts).
 */

import { mergeRpcTrafficEntry, shouldCoalesceWithLast } from "./coalesce";
import {
  asRecord,
  isRpcId,
  type RpcTrafficEntry,
  type RpcTrafficInput,
  type TrafficSink,
} from "./types";

export const DEFAULT_MAX_ENTRIES = 1000;
/** Total JSON text held; a truncated message counts as its envelope. */
export const DEFAULT_MAX_BYTES = 16 * 1024 * 1024;
/** Over this a message is kept as its envelope only. */
export const DEFAULT_MAX_MESSAGE_BYTES = 4 * 1024 * 1024;

// A transport error can carry a response body ("Error POSTing to endpoint:
// <text>"), so its text is cut before it enters the log.
const MAX_TRANSPORT_TEXT = 2000;
// An id or a method name a server controls is cut for the same reason when a
// message is kept as its envelope.
const MAX_ENVELOPE_TEXT = 256;

export interface RpcTrafficStoreOptions {
  maxEntries?: number;
  maxBytes?: number;
  maxMessageBytes?: number;
  windowMs?: number;
  now?: () => number;
  /**
   * Runs `run` later (the default is the next animation frame) or at once
   * when there is no animation frame (a test, a server render). Only the
   * cached snapshot and the subscriber notification wait for it.
   */
  schedule?: (run: () => void) => void;
}

const EMPTY_SNAPSHOT: readonly RpcTrafficEntry[] = Object.freeze([]);

function defaultSchedule(run: () => void): void {
  if (typeof requestAnimationFrame === "function") {
    requestAnimationFrame(run);
  } else {
    run();
  }
}

function cut(text: string, limit: number): string {
  return text.length > limit ? `${text.slice(0, limit)}...` : text;
}

function envelopeScalar(value: unknown): unknown {
  return typeof value === "string" ? cut(value, MAX_ENVELOPE_TEXT) : value;
}

/**
 * A message too large to keep, reduced to what correlation needs: `jsonrpc`,
 * `id` and `method`, with `params`, `result` and `error.data` replaced by a
 * marker. The error's code and (cut) message stay, since they are the
 * answer to "did it fail".
 */
function truncatedEnvelope(message: unknown, bytes: number): unknown {
  const marker = { truncated: true, bytes };
  const record = asRecord(message);
  if (!record) return marker;

  const envelope: Record<string, unknown> = {};
  for (const key of ["jsonrpc", "id", "method"]) {
    if (key in record) envelope[key] = envelopeScalar(record[key]);
  }
  if (record.params !== undefined) envelope.params = marker;
  if (record.result !== undefined) envelope.result = marker;
  if (record.error !== undefined) {
    const error = asRecord(record.error);
    envelope.error = {
      code: error?.code,
      message: envelopeScalar(error?.message),
      data: marker,
    };
  }
  return envelope;
}

interface HeldEntry {
  entry: RpcTrafficEntry;
  /** Characters this row counts against `maxBytes`. */
  held: number;
}

export class RpcTrafficStore {
  private records: HeldEntry[] = [];
  private heldTotal = 0;
  private snapshot: readonly RpcTrafficEntry[] = EMPTY_SNAPSHOT;
  private readonly listeners = new Set<() => void>();
  private nextId = 0;
  private emitPending = false;
  private initializeRequestId: string | number | undefined;
  private initializeResultValue: Record<string, unknown> | null = null;
  // A WeakSet, not a list: the log must not keep a failed request's error
  // (and whatever it references) alive.
  private readonly seenErrors = new WeakSet<object>();

  private readonly maxEntries: number;
  private readonly maxBytes: number;
  private readonly maxMessageBytes: number;
  private readonly windowMs: number | undefined;
  private readonly now: () => number;
  private readonly schedule: (run: () => void) => void;

  constructor(options: RpcTrafficStoreOptions = {}) {
    this.maxEntries = options.maxEntries ?? DEFAULT_MAX_ENTRIES;
    this.maxBytes = options.maxBytes ?? DEFAULT_MAX_BYTES;
    this.maxMessageBytes = options.maxMessageBytes ?? DEFAULT_MAX_MESSAGE_BYTES;
    this.windowMs = options.windowMs;
    this.now = options.now ?? Date.now;
    this.schedule = options.schedule ?? defaultSchedule;
  }

  /** What the transport tap reports to. */
  readonly sink: TrafficSink = {
    message: (direction, message) => this.publish({ direction, message }),
    transport: (event, error) => {
      if (event === "error") this.publishTransportError(error);
      else this.publishTransportClosed();
    },
  };

  publish(input: RpcTrafficInput): void {
    this.captureInitialize(input);

    // JSON.stringify throws for a value JSON cannot hold. A message that came
    // off the wire (or goes onto it) always can; if one ever cannot, the
    // exception reaches the tap, which reports it with console.error, and
    // nothing here has changed yet.
    const text = JSON.stringify(input.message);
    const bytes = text.length;
    const truncated = bytes > this.maxMessageBytes;
    const message = truncated
      ? truncatedEnvelope(input.message, bytes)
      : input.message;
    const held = truncated ? JSON.stringify(message).length : bytes;

    const timestampMs = this.now();
    const timestamp = new Date(timestampMs).toISOString();

    const last = this.records[this.records.length - 1];
    if (
      last &&
      shouldCoalesceWithLast(
        last.entry,
        { direction: input.direction, message },
        timestampMs,
        this.windowMs,
      )
    ) {
      const merged = mergeRpcTrafficEntry(last.entry, {
        timestamp,
        message,
        bytes,
        truncated: truncated ? true : undefined,
      });
      this.heldTotal += held - last.held;
      this.records[this.records.length - 1] = { entry: merged, held };
    } else {
      const entry: RpcTrafficEntry = {
        id: `rpc-${++this.nextId}`,
        direction: input.direction,
        timestamp,
        message,
        bytes,
      };
      if (truncated) entry.truncated = true;
      this.records.push({ entry, held });
      this.heldTotal += held;
    }

    this.evict();
    this.scheduleEmit();
  }

  /**
   * Records a transport failure. One failure can reach the log twice (the
   * transport calls `onerror` and also rejects the call that hit it, and the
   * hook reports the rejection), so an error object is recorded once.
   */
  publishTransportError(error: unknown): void {
    if (typeof error === "object" && error !== null) {
      if (this.seenErrors.has(error)) return;
      this.seenErrors.add(error);
    }
    const text = error instanceof Error ? error.message : String(error);
    this.publish({
      direction: "receive",
      message: {
        transportEvent: "error",
        error: cut(text, MAX_TRANSPORT_TEXT),
      },
    });
  }

  publishTransportClosed(): void {
    this.publish({
      direction: "receive",
      message: { transportEvent: "closed" },
    });
  }

  /**
   * The cached snapshot: the same array until the next emit, never mutated
   * (the `useSyncExternalStore` contract).
   */
  getSnapshot = (): readonly RpcTrafficEntry[] => this.snapshot;

  getServerSnapshot = (): readonly RpcTrafficEntry[] => EMPTY_SNAPSHOT;

  subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  };

  /**
   * Empties the log. The initialize result stays: it describes the
   * connection, not the log.
   */
  clear(): void {
    this.records = [];
    this.heldTotal = 0;
    this.scheduleEmit();
  }

  /** Rows held right now (not the deferred snapshot's length). */
  size(): number {
    return this.records.length;
  }

  /**
   * A fresh copy of every row held, read from the live list rather than the
   * snapshot, so a download is complete even when the tab is in the
   * background and animation frames are not running.
   */
  exportEntries(): RpcTrafficEntry[] {
    return this.records.map((record) => record.entry);
  }

  /**
   * The `result` of the initialize response, available the moment that
   * response was published (before the snapshot catches up).
   */
  initializeResult(): Record<string, unknown> | null {
    return this.initializeResultValue;
  }

  private captureInitialize(input: RpcTrafficInput): void {
    const record = asRecord(input.message);
    if (!record) return;
    if (
      input.direction === "send" &&
      record.method === "initialize" &&
      isRpcId(record.id)
    ) {
      this.initializeRequestId = record.id;
      return;
    }
    if (
      input.direction === "receive" &&
      this.initializeRequestId !== undefined &&
      // Strict equality: id 0 and id "0" are different ids.
      record.id === this.initializeRequestId &&
      record.method === undefined
    ) {
      const result = asRecord(record.result);
      if (result) {
        this.initializeResultValue = result;
        this.initializeRequestId = undefined;
      }
    }
  }

  private evict(): void {
    // Always keep the newest row, even when it alone is over a limit.
    while (
      this.records.length > 1 &&
      (this.records.length > this.maxEntries || this.heldTotal > this.maxBytes)
    ) {
      const oldest = this.records.shift();
      if (oldest) this.heldTotal -= oldest.held;
    }
  }

  private scheduleEmit(): void {
    if (this.emitPending) return;
    this.emitPending = true;
    this.schedule(() => {
      this.emitPending = false;
      this.snapshot = this.records.map((record) => record.entry);
      for (const listener of this.listeners) listener();
    });
  }
}

/**
 * Which log a connect attempt writes to.
 *
 *   capture off              no log (the pages that do not show one).
 *   a retry inside a connect the same `connect()` call is still working on
 *                            (retryCount > 0): keep the log, so the attempt
 *                            that failed and led to the retry stays visible.
 *   a new connect            a new, empty log, so a log never outlives the
 *                            target it was recorded against.
 */
export function reuseOrCreateStore<S>(options: {
  capture: boolean;
  previous: S | null;
  retryCount: number;
  create: () => S;
}): S | null {
  if (!options.capture) return null;
  if (options.retryCount > 0 && options.previous) return options.previous;
  return options.create();
}
