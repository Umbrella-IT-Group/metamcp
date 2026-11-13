/**
 * Relays a backend's progress notifications for ONE tools/call to the consumer
 * that sent the call, under the consumer's own progress token.
 *
 * Progress is per call and travels on the call's POST stream (MCP spec,
 * basic/utilities/progress: a notification carries the token of the request it
 * belongs to, and notifications stop once the request completes). The relay is
 * therefore a closure over one call. It is never stored on the pooled handler
 * context, which is shared by every request on a session.
 *
 * `onprogress` is called by the SDK client for each backend notification and
 * must never throw or block, or it would fault the backend's response path.
 * It only enqueues. One sequential drain sends in arrival order, so the
 * consumer never sees progress reordered. The queue is bounded (a backend
 * that floods cannot grow memory) and the drain stops for good after the
 * first failed send or once the consumer is gone.
 *
 * `flush` is awaited by the proxy before the call's result is returned. The
 * ordering guarantee is bounded, and this is the whole of it: progress is
 * flushed before the result for up to five seconds (PROGRESS_FLUSH_MAX_MS);
 * after that, queued progress is dropped and at most one send already in
 * flight can arrive after the result, which clients ignore for a completed
 * request. `flush` closes the relay either way, so nothing queued or arriving
 * later is written.
 *
 * Why one send can still land after the result: a send is not abortable. The
 * SDK's `sendNotification` takes no signal (NotificationOptions carries only a
 * related request id), so a send that is in flight when the deadline passes
 * cannot be cancelled and settles on its own. Making sends abortable would
 * need a transport-level change; the bounded hold was chosen instead of
 * holding a result for a stuck consumer link.
 */

/** The consumer-chosen token echoed back (never the backend-facing one). */
export type ProgressToken = string | number;

export interface ProgressUpdate {
  progress: number;
  total?: number;
  message?: string;
}

export interface ProgressNotification {
  method: "notifications/progress";
  params: {
    progressToken: ProgressToken;
    progress: number;
    total?: number;
    message?: string;
  };
}

export interface ProgressRelay {
  onprogress: (update: ProgressUpdate) => void;
  flush: () => Promise<void>;
}

/** Notifications waiting to be sent. Beyond this the oldest is dropped. */
export const PROGRESS_QUEUE_MAX = 256;

/** The longest `flush` holds a call's result for a slow consumer. */
export const PROGRESS_FLUSH_MAX_MS = 5_000;

export interface ProgressRelayOptions {
  progressToken: ProgressToken;
  send: (notification: ProgressNotification) => Promise<void>;
  /** True once the consumer's request is aborted; nothing more is written. */
  consumerGone: () => boolean;
  /** One line, no consumer data; the caller adds the call's name. */
  warn: (message: string) => void;
}

export function createProgressRelay(
  options: ProgressRelayOptions,
): ProgressRelay {
  const { progressToken, send, consumerGone, warn } = options;
  let queue: ProgressUpdate[] = [];
  let closed = false;
  let stopped = false;
  let draining: Promise<void> | undefined;
  let dropped = 0;
  let warnedFailure = false;
  let warnedDrop = false;
  let warnedFlush = false;

  const stop = (): void => {
    stopped = true;
    queue = [];
  };

  const drain = async (): Promise<void> => {
    while (queue.length > 0) {
      if (closed || stopped || consumerGone()) {
        stop();
        return;
      }
      const update = queue.shift() as ProgressUpdate;
      try {
        await send({
          method: "notifications/progress",
          params: { progressToken, ...update },
        });
      } catch {
        // The failure text can carry transport detail; the call itself is
        // untouched and keeps running without a progress channel.
        stop();
        if (!warnedFailure) {
          warnedFailure = true;
          warn(
            "progress relay stopped after a send failed; the call continues",
          );
        }
        return;
      }
    }
  };

  const kick = (): void => {
    if (draining) return;
    draining = drain().finally(() => {
      draining = undefined;
      if (queue.length > 0 && !closed && !stopped) kick();
    });
  };

  return {
    onprogress(update) {
      try {
        if (closed || stopped) return;
        // Defined fields only: an `undefined` property would still be a key on
        // the wire object and a strict consumer schema can refuse it.
        const item: ProgressUpdate = { progress: update.progress };
        if (update.total !== undefined) item.total = update.total;
        if (update.message !== undefined) item.message = update.message;
        queue.push(item);
        if (queue.length > PROGRESS_QUEUE_MAX) {
          queue.shift();
          dropped += 1;
        }
        kick();
      } catch {
        // Never reaches the SDK's response path.
      }
    },

    async flush() {
      try {
        const pending = draining;
        if (pending) {
          let timer: ReturnType<typeof setTimeout> | undefined;
          const timedOut = new Promise<"timeout">((resolve) => {
            timer = setTimeout(() => resolve("timeout"), PROGRESS_FLUSH_MAX_MS);
            timer.unref?.();
          });
          const outcome = await Promise.race([
            pending.then(() => "drained" as const),
            timedOut,
          ]);
          if (timer) clearTimeout(timer);
          if (outcome === "timeout" && !warnedFlush) {
            warnedFlush = true;
            warn(
              "progress relay did not drain in time; the result was not held any longer",
            );
          }
        }
      } finally {
        // Closed with or without a timeout, so a late or queued item is
        // dropped. A send already in flight can still finish after the result.
        closed = true;
        queue = [];
      }
      if (dropped > 0 && !warnedDrop) {
        warnedDrop = true;
        warn(`progress relay dropped ${dropped} notification(s) under load`);
      }
    },
  };
}
