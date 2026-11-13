"use client";

import type { InspectorTargetKind } from "@/lib/inspector/inspector-target";
import type { InspectorServerInfo as ServerInfo } from "@/lib/inspector/server-info";
import type { Translate } from "@/lib/inspector/translate";

// Skeleton: the final component API, rendering nothing.

interface InspectorServerInfoProps {
  serverInfo: ServerInfo | null;
  targetKind: InspectorTargetKind;
  t: Translate;
}

export function InspectorServerInfo(_props: InspectorServerInfoProps) {
  return null;
}
