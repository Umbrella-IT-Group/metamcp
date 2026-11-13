import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import type { JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";

import type { TrafficSink } from "./types";

export type { TrafficSink } from "./types";

/**
 * Observes a transport for the Inspector's traffic log. The pattern (see every
 * message in both directions without changing any of them) follows mcp-use's
 * `logging-transport.ts` (MIT, https://github.com/mcp-use/mcp-use); this is a
 * new implementation, not a copy.
 *
 * Why it decorates the transport in place instead of wrapping it:
 *
 * - `Protocol.connect` (SDK `shared/protocol.js`) reads the transport's
 *   existing `onclose`, `onerror` and `onmessage`, then installs handlers that
 *   call those first. Handlers assigned before `connect` are therefore
 *   chained, which gives exactly one sink call per delivered message with no
 *   cooperation from the SDK.
 * - A property accessor on `onmessage` (what a wrapper object needs, to hand
 *   `Protocol` a different object's handler) loops: the accessor's getter
 *   returns the wrapper, `Protocol` calls it as "the previous handler", and the
 *   wrapper calls `Protocol`'s handler, which calls the wrapper again.
 * - A new wrapper object would lose members the app reaches through the real
 *   transport (`terminateSession`, `sessionId`, `setProtocolVersion`).
 * - The abort path sends `notifications/cancelled` with
 *   `{ relatedRequestId, resumptionToken, onresumptiontoken }` as the second
 *   argument, so the decorated `send` forwards every argument it is given.
 *
 * The tap must therefore be installed BEFORE `Client.connect`, which is why
 * the connection hook goes through `connectWithTraffic` and nowhere else.
 */

function safely(what: string, report: () => void): void {
  // The log is an observer. A defect in it must never break a message that
  // is on its way, so it is reported (console.error) and the message goes on.
  try {
    report();
  } catch (error) {
    console.error(`Inspector traffic log: ${what} failed`, error);
  }
}

/**
 * Decorates `transport` and returns the same object. A message is logged
 * before it is handed to the real `send` (a fast reply must not appear in the
 * log ahead of its request); a failed send is reported as a transport error
 * and thrown again unchanged.
 */
export function tapTransport<T extends Transport>(
  transport: T,
  sink: TrafficSink,
): T {
  const target: Transport = transport;
  const originalSend = target.send;
  const previousOnMessage = target.onmessage;
  const previousOnError = target.onerror;
  const previousOnClose = target.onclose;

  target.send = async (...args: Parameters<Transport["send"]>) => {
    const [message] = args;
    // A transport may be handed a batch; each element is one message.
    const messages: JSONRPCMessage[] = Array.isArray(message)
      ? (message as JSONRPCMessage[])
      : [message];
    for (const item of messages) {
      safely("recording a sent message", () => sink.message("send", item));
    }
    try {
      await Reflect.apply(originalSend, target, args);
    } catch (error) {
      safely("recording a send failure", () => sink.transport("error", error));
      throw error;
    }
  };

  target.onmessage = (message, extra) => {
    safely("recording a received message", () =>
      sink.message("receive", message),
    );
    previousOnMessage?.(message, extra);
  };

  target.onerror = (error) => {
    safely("recording a transport error", () => sink.transport("error", error));
    previousOnError?.(error);
  };

  target.onclose = () => {
    safely("recording a close", () => sink.transport("closed"));
    previousOnClose?.();
  };

  return transport;
}

/**
 * The one place the Inspector's connection hook connects. With a sink the
 * transport is tapped first; with none this is `client.connect(transport)`
 * and nothing else.
 */
export async function connectWithTraffic(
  client: { connect(transport: Transport): Promise<void> },
  transport: Transport,
  sink: TrafficSink | null,
): Promise<void> {
  if (sink) tapTransport(transport, sink);
  await client.connect(transport);
}
