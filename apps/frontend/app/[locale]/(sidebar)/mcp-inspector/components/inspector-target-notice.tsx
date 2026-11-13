"use client";

import type { InspectorTarget } from "@/lib/inspector/inspector-target";
import type { Translate } from "@/lib/inspector/translate";

// Skeleton: the final component API, rendering nothing.

interface InspectorTargetNoticeProps {
  target: InspectorTarget;
  includeInactive: boolean;
  onIncludeInactiveChange: (value: boolean) => void;
  t: Translate;
}

export function InspectorTargetNotice(_props: InspectorTargetNoticeProps) {
  return null;
}
