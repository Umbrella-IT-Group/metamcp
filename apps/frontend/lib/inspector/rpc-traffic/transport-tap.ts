import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";

import type { TrafficSink } from "./types";

export type { TrafficSink } from "./types";

// Skeleton: the final exported API with inert bodies. The tap returns the
// transport untouched.

export function tapTransport<T extends Transport>(
  transport: T,
  _sink: TrafficSink,
): T {
  return transport;
}

export async function connectWithTraffic(
  client: { connect(transport: Transport): Promise<void> },
  transport: Transport,
  _sink: TrafficSink | null,
): Promise<void> {
  await client.connect(transport);
}
