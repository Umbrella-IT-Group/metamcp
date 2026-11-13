/**
 * The per-call progress relay. Oracle: the MCP spec's
 * basic/utilities/progress page (a notification carries the token of its
 * request and none is sent after the request completes) plus the relay's own
 * contract: ordered, bounded, never throws into the SDK's response path, and
 * never holds a result longer than PROGRESS_FLUSH_MAX_MS.
 */
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  createProgressRelay,
  PROGRESS_FLUSH_MAX_MS,
  PROGRESS_QUEUE_MAX,
  type ProgressNotification,
} from "./tool-progress-relay";

afterEach(() => {
  vi.useRealTimers();
});

const turns = async (n = 30) => {
  for (let i = 0; i < n; i += 1) await Promise.resolve();
};

function setup(
  send: (n: ProgressNotification) => Promise<void> = async () => undefined,
  consumerGone: () => boolean = () => false,
) {
  const warn = vi.fn();
  const sent: ProgressNotification[] = [];
  const relay = createProgressRelay({
    progressToken: "tok",
    send: async (n) => {
      sent.push(n);
      await send(n);
    },
    consumerGone,
    warn,
  });
  return { relay, sent, warn };
}

describe("createProgressRelay", () => {
  it("sends in arrival order under the consumer's token, with defined fields only", async () => {
    const { relay, sent } = setup();

    relay.onprogress({ progress: 1 });
    relay.onprogress({ progress: 2, total: 10 });
    relay.onprogress({ progress: 3, total: 10, message: "step" });
    await relay.flush();

    expect(sent).toEqual([
      {
        method: "notifications/progress",
        params: { progressToken: "tok", progress: 1 },
      },
      {
        method: "notifications/progress",
        params: { progressToken: "tok", progress: 2, total: 10 },
      },
      {
        method: "notifications/progress",
        params: {
          progressToken: "tok",
          progress: 3,
          total: 10,
          message: "step",
        },
      },
    ]);
    expect(Object.keys(sent[0].params)).toEqual(["progressToken", "progress"]);
  });

  it("flush waits for a send that is in flight", async () => {
    let finish: () => void = () => undefined;
    const { relay, sent } = setup(
      () =>
        new Promise<void>((resolve) => {
          finish = resolve;
        }),
    );
    relay.onprogress({ progress: 1 });
    await turns();

    let flushed = false;
    const done = relay.flush().then(() => {
      flushed = true;
    });
    await turns();
    expect(sent).toHaveLength(1);
    expect(flushed).toBe(false);

    finish();
    await done;
    expect(flushed).toBe(true);
  });

  it("drops the oldest queued item beyond the cap and warns once", async () => {
    let finish: () => void = () => undefined;
    const { relay, sent, warn } = setup((n) =>
      n.params.progress === 0
        ? new Promise<void>((resolve) => {
            finish = resolve;
          })
        : Promise.resolve(),
    );
    // Item 0 is in flight and blocks the drain; the rest queue behind it.
    relay.onprogress({ progress: 0 });
    await turns();
    for (let i = 1; i <= PROGRESS_QUEUE_MAX + 2; i += 1) {
      relay.onprogress({ progress: i });
    }

    finish();
    await relay.flush();

    const progress = sent.map((n) => n.params.progress);
    expect(progress[0]).toBe(0);
    expect(progress).toHaveLength(1 + PROGRESS_QUEUE_MAX);
    // The two oldest queued items (1 and 2) were dropped.
    expect(progress[1]).toBe(3);
    expect(progress[progress.length - 1]).toBe(PROGRESS_QUEUE_MAX + 2);
    expect(warn).toHaveBeenCalledTimes(1);
  });

  it("stops after the first failed send, warns once, and never throws", async () => {
    const { relay, sent, warn } = setup(async () => {
      throw new Error("consumer link is gone: detail that must not be logged");
    });

    relay.onprogress({ progress: 1 });
    relay.onprogress({ progress: 2 });
    await expect(relay.flush()).resolves.toBeUndefined();
    relay.onprogress({ progress: 3 });
    await relay.flush();

    expect(sent).toHaveLength(1);
    expect(warn).toHaveBeenCalledTimes(1);
    expect(String(warn.mock.calls[0][0])).not.toContain("detail that must");
  });

  it("stops draining once the consumer is gone", async () => {
    let gone = false;
    const { relay, sent } = setup(
      async () => {
        gone = true;
      },
      () => gone,
    );

    relay.onprogress({ progress: 1 });
    relay.onprogress({ progress: 2 });
    relay.onprogress({ progress: 3 });
    await relay.flush();

    expect(sent.map((n) => n.params.progress)).toEqual([1]);
  });

  it("flush resolves after the bound when a send never settles", async () => {
    vi.useFakeTimers();
    const { relay, warn } = setup(() => new Promise<void>(() => undefined));
    relay.onprogress({ progress: 1 });
    await turns();

    let flushed = false;
    const done = relay.flush().then(() => {
      flushed = true;
    });
    await vi.advanceTimersByTimeAsync(PROGRESS_FLUSH_MAX_MS - 1);
    expect(flushed).toBe(false);
    await vi.advanceTimersByTimeAsync(1);
    await done;

    expect(flushed).toBe(true);
    expect(warn).toHaveBeenCalledTimes(1);
  });

  it("drops a late or queued item once flush has run, so nothing follows the result", async () => {
    vi.useFakeTimers();
    let finish: () => void = () => undefined;
    const { relay, sent } = setup((n) =>
      n.params.progress === 1
        ? new Promise<void>((resolve) => {
            finish = resolve;
          })
        : Promise.resolve(),
    );
    relay.onprogress({ progress: 1 });
    await turns();
    relay.onprogress({ progress: 2 }); // queued behind the stuck send

    const done = relay.flush();
    await vi.advanceTimersByTimeAsync(PROGRESS_FLUSH_MAX_MS);
    await done;

    // The stuck send finally completes after the flush gave up; the queued
    // item must not be written, nor a notification that arrives afterwards.
    finish();
    relay.onprogress({ progress: 3 });
    await turns();
    await vi.advanceTimersByTimeAsync(0);

    expect(sent.map((n) => n.params.progress)).toEqual([1]);
  });
});
