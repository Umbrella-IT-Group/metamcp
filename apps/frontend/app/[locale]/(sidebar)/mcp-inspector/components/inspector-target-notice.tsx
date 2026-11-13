"use client";

import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
import type { InspectorTarget } from "@/lib/inspector/inspector-target";
import type { Translate } from "@/lib/inspector/translate";

interface InspectorTargetNoticeProps {
  target: InspectorTarget;
  includeInactive: boolean;
  onIncludeInactiveChange: (value: boolean) => void;
  t: Translate;
}

/**
 * What a namespace or endpoint target is, said plainly, with the one switch
 * that applies to it. Nothing for a server or no target.
 *
 * An endpoint target previews the endpoint's namespace through the admin
 * route, so the note says which endpoint was picked, which namespace is
 * connected, and that nothing configured on the endpoint is applied.
 *
 * Presentational (takes `t`) so a test can render it.
 */
export function InspectorTargetNotice({
  target,
  includeInactive,
  onIncludeInactiveChange,
  t,
}: InspectorTargetNoticeProps) {
  if (target.kind !== "namespace" && target.kind !== "endpoint") return null;

  return (
    <div
      role="note"
      className="space-y-2 rounded-md border bg-muted/40 p-3 text-xs text-muted-foreground"
    >
      {target.kind === "endpoint" && (
        <p className="font-medium text-foreground">
          {t("inspector:inspectorTarget.endpointNote", {
            endpoint: target.endpointName,
            namespace: target.namespaceName,
          })}
        </p>
      )}
      <p>{t("inspector:inspectorTarget.gatewayNote")}</p>
      <div className="flex flex-wrap items-center gap-2">
        <Checkbox
          id="inspector-include-inactive"
          checked={includeInactive}
          onCheckedChange={(checked) =>
            onIncludeInactiveChange(checked === true)
          }
        />
        <Label
          htmlFor="inspector-include-inactive"
          className="text-xs font-normal"
        >
          {t("inspector:inspectorTarget.includeInactive")}
        </Label>
        <span>{t("inspector:inspectorTarget.includeInactiveHelp")}</span>
      </div>
    </div>
  );
}
