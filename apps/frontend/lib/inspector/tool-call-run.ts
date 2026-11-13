/**
 * The lifecycle of one Inspector tool call, kept apart from React so its rules
 * can be tested against a real SDK client.
 *
 * The rule: exactly one thing may cancel a call, and that is the person
 * pressing "Stop waiting" (stop). Everything else the page does (leaving it,
 * switching to another target, the connection closing) only detaches the UI
 * from the call (detach): the request is left alone, so the connection closes
 * the ordinary way and no cancellation is sent.
 *
 * Why this matters: aborting the SDK request emits an explicit
 * `notifications/cancelled` (SDK shared/protocol.js, request()), and the
 * gateway can pass a cancellation on to the backend. A write tool that was
 * halfway through should not be cancelled because someone navigated away from
 * a page. A closed connection, by contrast, is a transport event, not a
 * cancellation, and the gateway deliberately lets the backend finish.
 *
 * Note the converse for the button: it requests cancellation and stops the
 * page waiting, but the backend may still finish, so a stopped call is an
 * unknown outcome (see classifyCallFailure).
 */

export const STOP_REASON = "Cancelled from the inspector";

export interface ToolCallRun<T> {
  /** The request's own outcome. Rejects when stopped or when the call fails. */
  readonly result: Promise<T>;
  /** The explicit button: abort the request, which sends notifications/cancelled. */
  stop(): void;
  /** The page is going away: stop updating the UI, but do not touch the request. */
  detach(): void;
  readonly stoppedByUser: boolean;
  readonly detached: boolean;
}

export function startToolCall<T>(
  send: (signal: AbortSignal) => Promise<T>,
): ToolCallRun<T> {
  const controller = new AbortController();
  let stoppedByUser = false;
  let detached = false;
  let settled = false;

  const result = send(controller.signal);
  // A bare `finally` would re-reject this branch with no handler; the caller
  // owns the rejection through `result`.
  result.then(
    () => {
      settled = true;
    },
    () => {
      settled = true;
    },
  );

  return {
    result,
    stop() {
      // After the call has an outcome there is nothing to cancel, and the
      // record must not later read as "stopped by the user".
      if (settled || stoppedByUser) return;
      stoppedByUser = true;
      controller.abort(STOP_REASON);
    },
    detach() {
      detached = true;
    },
    get stoppedByUser() {
      return stoppedByUser;
    },
    get detached() {
      return detached;
    },
  };
}
