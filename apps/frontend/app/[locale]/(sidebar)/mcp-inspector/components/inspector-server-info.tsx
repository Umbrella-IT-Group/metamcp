"use client";

import { CodeBlock } from "@/components/ui/code-block";
import type { InspectorTargetKind } from "@/lib/inspector/inspector-target";
import type { InspectorServerInfo as ServerInfo } from "@/lib/inspector/server-info";
import type { Translate } from "@/lib/inspector/translate";

/**
 * What the connected server announced when the connection was made.
 *
 * Presentational, and it takes `t` as a prop so a test can render it.
 *
 * Every value is the server's own text and is shown as a text node: the
 * website and the icon addresses are plain text, never a link or an image
 * (a `javascript:` address in a link would run on click, and an icon is
 * fetched from wherever the server says).
 */

// An icon address can be a data URI of any size.
const ICON_SRC_DISPLAY_LIMIT = 200;

function shorten(text: string): string {
  return text.length > ICON_SRC_DISPLAY_LIMIT
    ? `${text.slice(0, ICON_SRC_DISPLAY_LIMIT)}...`
    : text;
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="grid grid-cols-[10rem_1fr] gap-2 text-sm">
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="break-words font-mono text-xs">{value}</dd>
    </div>
  );
}

interface InspectorServerInfoProps {
  serverInfo: ServerInfo | null;
  targetKind: InspectorTargetKind;
  t: Translate;
}

export function InspectorServerInfo({
  serverInfo,
  targetKind,
  t,
}: InspectorServerInfoProps) {
  const isGateway = targetKind === "namespace" || targetKind === "endpoint";
  const unknown = t("inspector:inspectorServerInfo.unknown");
  const implementation = serverInfo?.implementation;
  const icons = implementation?.icons ?? [];

  return (
    <div className="space-y-4">
      {isGateway && (
        // The Server info tab reads the initialize result of the connection it
        // is on. Through the admin route that is the namespace server's, so it
        // cannot show what an endpoint announces (its own title or
        // instructions): say so rather than imply it does.
        <p
          role="note"
          className="rounded-md border bg-muted/40 p-3 text-xs text-muted-foreground"
        >
          {t("inspector:inspectorServerInfo.gatewayNote")}
        </p>
      )}

      <dl className="space-y-2">
        <Row
          label={t("inspector:inspectorServerInfo.name")}
          value={implementation?.name ?? unknown}
        />
        <Row
          label={t("inspector:inspectorServerInfo.title")}
          value={
            implementation?.title ?? t("inspector:inspectorServerInfo.none")
          }
        />
        <Row
          label={t("inspector:inspectorServerInfo.version")}
          value={implementation?.version ?? unknown}
        />
        <Row
          label={t("inspector:inspectorServerInfo.protocol")}
          value={serverInfo?.protocolVersion ?? unknown}
        />
        {implementation?.description !== undefined && (
          <Row
            label={t("inspector:inspectorServerInfo.description")}
            value={implementation.description}
          />
        )}
        {implementation?.websiteUrl !== undefined && (
          <Row
            label={t("inspector:inspectorServerInfo.website")}
            value={implementation.websiteUrl}
          />
        )}
        {icons.length > 0 && (
          <div className="grid grid-cols-[10rem_1fr] gap-2 text-sm">
            <dt className="text-muted-foreground">
              {t("inspector:inspectorServerInfo.icons")}
            </dt>
            <dd className="space-y-1 break-all font-mono text-xs">
              {icons.map((icon, index) => (
                <div key={`${index}:${icon.src.slice(0, 40)}`}>
                  {shorten(icon.src)}
                </div>
              ))}
            </dd>
          </div>
        )}
      </dl>

      <div className="space-y-1">
        <h6 className="text-sm font-medium">
          {t("inspector:inspectorServerInfo.instructions")}
        </h6>
        {serverInfo?.instructions ? (
          <pre className="max-h-96 overflow-auto whitespace-pre-wrap break-words rounded-md border bg-muted/30 p-3 text-xs">
            {serverInfo.instructions}
          </pre>
        ) : (
          <p className="text-sm text-muted-foreground">
            {t("inspector:inspectorServerInfo.none")}
          </p>
        )}
      </div>

      <div className="space-y-1">
        <h6 className="text-sm font-medium">
          {t("inspector:inspectorServerInfo.capabilities")}
        </h6>
        <CodeBlock language="json" maxHeight="320px" className="text-xs">
          {JSON.stringify(serverInfo?.capabilities ?? {}, null, 2)}
        </CodeBlock>
      </div>
    </div>
  );
}
