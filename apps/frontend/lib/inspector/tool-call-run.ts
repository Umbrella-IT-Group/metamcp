// Skeleton: the final exported API with the lifecycle this change must NOT
// have: no button that cancels, and an unmount that aborts the request. It
// exists so the tests can be run red first.

export const STOP_REASON = "Cancelled from the inspector";

export interface ToolCallRun<T> {
  readonly result: Promise<T>;
  stop(): void;
  detach(): void;
  readonly stoppedByUser: boolean;
  readonly detached: boolean;
}

export function startToolCall<T>(
  send: (signal: AbortSignal) => Promise<T>,
): ToolCallRun<T> {
  const controller = new AbortController();
  let detached = false;
  return {
    result: send(controller.signal),
    stop() {},
    detach() {
      detached = true;
      controller.abort(STOP_REASON);
    },
    get stoppedByUser() {
      return false;
    },
    get detached() {
      return detached;
    },
  };
}
