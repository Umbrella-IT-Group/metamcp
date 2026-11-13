"use client";

import type { InspectorTarget } from "@/lib/inspector/inspector-target";
import type { RpcTrafficStore } from "@/lib/inspector/rpc-traffic/store";
import type { RpcTrafficEntry } from "@/lib/inspector/rpc-traffic/types";
import type { Translate } from "@/lib/inspector/translate";

// Skeleton: the final component API, rendering nothing.

interface RpcTrafficPanelViewProps {
  entries: readonly RpcTrafficEntry[];
  onClear: () => void;
  onDownload: (omitBodies: boolean) => void;
  onCopyMessage: (entry: RpcTrafficEntry) => void;
  t: Translate;
}

export function MessageBody(_props: { entry: RpcTrafficEntry; t: Translate }) {
  return null;
}

export function RpcTrafficPanelView(_props: RpcTrafficPanelViewProps) {
  return null;
}

interface RpcTrafficPanelProps {
  store: RpcTrafficStore | null;
  target: InspectorTarget;
  t: Translate;
}

export function RpcTrafficPanel(_props: RpcTrafficPanelProps) {
  return null;
}
