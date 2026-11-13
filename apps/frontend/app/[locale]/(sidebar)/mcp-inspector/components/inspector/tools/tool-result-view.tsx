"use client";

import {
  AlertTriangle,
  CheckCircle,
  Copy,
  Loader2,
  OctagonX,
  XCircle,
} from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { CodeBlock } from "@/components/ui/code-block";
import { copyToClipboard } from "@/lib/inspector/clipboard";
import {
  type ClassifiedFailure,
  type ClassifiedResult,
  classifyCallResult,
  type ContentBlock,
  HIGHLIGHT_LIMIT,
  stringifyForDisplay,
  type ToolExecutionRecord,
} from "@/lib/inspector/tool-result";
import type { Translate } from "@/lib/inspector/translate";

/**
 * One tool call as the Inspector shows it: status, timing, the arguments that
 * were sent, and the outcome.
 *
 * Presentational, and it takes `t` as a prop so a test can render it.
 *
 * Everything from the server is rendered as a React text node. There is no
 * markup built from a result, no link built from server data (a resource link
 * is shown as plain text), audio is described and never played, and an image
 * becomes a picture only through imageDataUrl's raster allowlist.
 */

const PLAIN_BLOCK =
  "max-h-96 overflow-auto whitespace-pre-wrap break-words rounded-md border bg-muted/30 p-2 font-mono text-xs";

/** Highlighted JSON, or a plain block when the text is too large to highlight. */
function JsonText({ text, t }: { text: string; t: Translate }) {
  if (text.length > HIGHLIGHT_LIMIT) {
    return (
      <div className="space-y-1">
        <p className="text-xs text-muted-foreground">
          {t("inspector:inspectorResult.plainLarge")}
        </p>
        <pre className={PLAIN_BLOCK}>{text}</pre>
      </div>
    );
  }
  return (
    <CodeBlock language="json" maxHeight="320px" className="text-xs">
      {text}
    </CodeBlock>
  );
}

function TextBlockView({
  block,
  t,
}: {
  block: Extract<ContentBlock, { kind: "text" }>;
  t: Translate;
}) {
  const [asJson, setAsJson] = useState(false);
  const pretty = block.prettyJson;
  return (
    <div className="space-y-1">
      {pretty !== undefined && (
        <Button
          variant="ghost"
          size="sm"
          className="h-6 px-2 text-xs"
          onClick={() => setAsJson((value) => !value)}
        >
          {asJson
            ? t("inspector:inspectorResult.showAsText")
            : t("inspector:inspectorResult.formatJson")}
        </Button>
      )}
      {asJson && pretty !== undefined ? (
        <JsonText text={pretty} t={t} />
      ) : (
        <pre className={PLAIN_BLOCK}>{block.text}</pre>
      )}
    </div>
  );
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div className="text-xs">
      <span className="text-muted-foreground">{label}: </span>
      <span className="break-all font-mono">{value}</span>
    </div>
  );
}

function BlockView({ block, t }: { block: ContentBlock; t: Translate }) {
  switch (block.kind) {
    case "text":
      return <TextBlockView block={block} t={t} />;
    case "image":
      return (
        <div className="space-y-1">
          <p className="text-xs text-muted-foreground">
            {block.dataUrl !== null
              ? t("inspector:inspectorResult.imageBlock", {
                  mimeType: block.mimeType,
                  bytes: block.bytes,
                })
              : t("inspector:inspectorResult.imageNotShown", {
                  mimeType: block.mimeType || "unknown",
                })}
          </p>
          {block.dataUrl !== null && (
            // The URL only ever comes from imageDataUrl: a raster type from
            // a fixed list and plain base64 text.
            // eslint-disable-next-line @next/next/no-img-element
            <img
              src={block.dataUrl}
              alt=""
              className="max-h-64 max-w-full rounded-md border"
            />
          )}
        </div>
      );
    case "audio":
      return (
        <p className="text-xs text-muted-foreground">
          {t("inspector:inspectorResult.audioBlock", {
            mimeType: block.mimeType || "unknown",
            bytes: block.bytes,
          })}
        </p>
      );
    case "resource_link":
      return (
        <div className="space-y-1 rounded-md border p-2">
          <p className="text-xs font-medium">
            {t("inspector:inspectorResult.resourceLink")}
          </p>
          <Field
            label={t("inspector:inspectorResult.uriLabel")}
            value={block.uri}
          />
          {block.name !== undefined && (
            <Field
              label={t("inspector:inspectorResult.nameLabel")}
              value={block.name}
            />
          )}
          {block.mimeType !== undefined && (
            <Field
              label={t("inspector:inspectorResult.typeLabel")}
              value={block.mimeType}
            />
          )}
          {block.description !== undefined && (
            <Field
              label={t("inspector:inspectorResult.descriptionLabel")}
              value={block.description}
            />
          )}
        </div>
      );
    case "resource":
      return (
        <div className="space-y-1 rounded-md border p-2">
          <p className="text-xs font-medium">
            {t("inspector:inspectorResult.resource")}
          </p>
          <Field
            label={t("inspector:inspectorResult.uriLabel")}
            value={block.uri}
          />
          {block.mimeType !== undefined && (
            <Field
              label={t("inspector:inspectorResult.typeLabel")}
              value={block.mimeType}
            />
          )}
          {block.bytes !== undefined && (
            <Field
              label={t("inspector:inspectorResult.bytesLabel")}
              value={String(block.bytes)}
            />
          )}
          {block.text !== undefined && (
            <pre className={PLAIN_BLOCK}>{block.text}</pre>
          )}
        </div>
      );
    case "unknown":
      return (
        <div className="space-y-1">
          <p className="text-xs text-muted-foreground">
            {t("inspector:inspectorResult.unknownBlock", { type: block.type })}
          </p>
          <pre className={PLAIN_BLOCK}>{block.raw}</pre>
        </div>
      );
  }
}

function ResultBody({
  classified,
  t,
}: {
  classified: ClassifiedResult;
  t: Translate;
}) {
  const empty =
    classified.blocks.length === 0 && classified.structured === null;
  return (
    <div className="space-y-3">
      {classified.status === "tool_error" && (
        <div
          role="alert"
          className="rounded-md bg-red-50 p-2 text-xs text-red-700 dark:bg-red-950/20 dark:text-red-400"
        >
          <div className="mb-1 font-medium">
            {t("inspector:toolsComponent.error")}:
          </div>
          <pre className="whitespace-pre-wrap break-words font-mono">
            {classified.errorText}
          </pre>
        </div>
      )}
      {classified.structured !== null && (
        <div className="space-y-1">
          <p className="text-xs font-medium text-muted-foreground">
            {t("inspector:inspectorResult.structured")}:
          </p>
          <JsonText text={stringifyForDisplay(classified.structured)} t={t} />
        </div>
      )}
      {classified.blocks.length > 0 && (
        <div className="space-y-2">
          <p className="text-xs font-medium text-muted-foreground">
            {t("inspector:inspectorResult.content")}:
          </p>
          {classified.blocks.map((block, index) => (
            <BlockView key={index} block={block} t={t} />
          ))}
        </div>
      )}
      {empty && classified.status === "success" && (
        <p className="text-xs text-muted-foreground">
          {t("inspector:inspectorResult.noContent")}
        </p>
      )}
    </div>
  );
}

function FailureBody({
  failure,
  durationMs,
  t,
}: {
  failure: ClassifiedFailure;
  durationMs: number | undefined;
  t: Translate;
}) {
  const stopped = failure.status === "stopped";
  return (
    <div
      role="alert"
      className="space-y-1 rounded-md bg-red-50 p-2 text-xs text-red-700 dark:bg-red-950/20 dark:text-red-400"
    >
      {stopped ? (
        <p>
          {t("inspector:inspectorResult.stoppedNote", {
            ms: durationMs ?? 0,
          })}
        </p>
      ) : (
        <>
          {failure.code !== undefined && (
            <p className="font-medium">
              {t("inspector:inspectorResult.errorCode", {
                code: failure.code,
              })}
            </p>
          )}
          <pre className="whitespace-pre-wrap break-words font-mono">
            {failure.message}
          </pre>
          {failure.data !== undefined && (
            <JsonText text={stringifyForDisplay(failure.data)} t={t} />
          )}
        </>
      )}
      {failure.outcomeUnknown && (
        <p className="pt-1">{t("inspector:inspectorResult.outcomeUnknown")}</p>
      )}
    </div>
  );
}

const STATUS_LABEL_KEY = {
  running: "inspector:toolsComponent.running",
  success: "inspector:inspectorResult.statusSuccess",
  tool_error: "inspector:inspectorResult.statusToolError",
  protocol_error: "inspector:inspectorResult.statusError",
  stopped: "inspector:inspectorResult.statusStopped",
} as const;

const STATUS_VARIANT = {
  running: "info",
  success: "success",
  tool_error: "danger",
  protocol_error: "danger",
  stopped: "warning",
} as const;

function StatusIcon({ status }: { status: ToolExecutionRecord["status"] }) {
  switch (status) {
    case "running":
      return (
        <Loader2 className="h-4 w-4 animate-spin text-blue-600 dark:text-blue-400" />
      );
    case "success":
      return (
        <CheckCircle className="h-4 w-4 text-green-600 dark:text-green-400" />
      );
    case "tool_error":
      return (
        <AlertTriangle className="h-4 w-4 text-red-600 dark:text-red-400" />
      );
    case "protocol_error":
      return <XCircle className="h-4 w-4 text-red-600 dark:text-red-400" />;
    case "stopped":
      return (
        <OctagonX className="h-4 w-4 text-yellow-600 dark:text-yellow-400" />
      );
  }
}

function formatDuration(durationMs: number, t: Translate) {
  if (durationMs < 1000) {
    return t("inspector:toolsComponent.formatDuration.milliseconds", {
      duration: durationMs,
    });
  }
  return t("inspector:toolsComponent.formatDuration.seconds", {
    duration: (durationMs / 1000).toFixed(2),
  });
}

export function ToolResultView({
  execution,
  t,
}: {
  execution: ToolExecutionRecord;
  t: Translate;
}) {
  const [view, setView] = useState<"formatted" | "raw">("formatted");
  const hasResult = execution.result !== undefined;
  const classified = hasResult ? classifyCallResult(execution.result) : null;
  const rawText = hasResult ? stringifyForDisplay(execution.result) : "";

  const copyRaw = async () => {
    const copied = await copyToClipboard(rawText);
    if (copied) toast.success(t("inspector:inspectorResult.resultCopied"));
    else toast.error(t("inspector:inspectorResult.copyFailed"));
  };

  return (
    <div
      className="rounded-lg border p-3"
      data-status={execution.status}
      data-testid="tool-execution"
    >
      <div className="mb-2 flex items-center justify-between gap-2">
        <div className="flex min-w-0 items-center gap-2">
          <StatusIcon status={execution.status} />
          <span className="truncate font-mono text-sm">
            {execution.toolName}
          </span>
          <Badge variant={STATUS_VARIANT[execution.status]}>
            {t(STATUS_LABEL_KEY[execution.status])}
          </Badge>
        </div>
        <div className="shrink-0 text-xs text-muted-foreground">
          {new Date(execution.startedAt).toLocaleTimeString()}
          {execution.durationMs !== undefined &&
            ` • ${formatDuration(execution.durationMs, t)}`}
        </div>
      </div>

      {Object.keys(execution.args).length > 0 && (
        <div className="mb-2">
          <div className="mb-1 text-xs font-medium text-muted-foreground">
            {t("inspector:toolsComponent.arguments")}:
          </div>
          <CodeBlock language="json" maxHeight="200px" className="text-xs">
            {stringifyForDisplay(execution.args)}
          </CodeBlock>
        </div>
      )}

      {execution.failure !== undefined && (
        <FailureBody
          failure={execution.failure}
          durationMs={execution.durationMs}
          t={t}
        />
      )}

      {classified !== null && (
        <div className="space-y-2">
          <div className="flex items-center justify-between gap-2">
            <div className="flex gap-1">
              {(["formatted", "raw"] as const).map((mode) => (
                <Button
                  key={mode}
                  variant={view === mode ? "secondary" : "ghost"}
                  size="sm"
                  className="h-6 px-2 text-xs"
                  aria-pressed={view === mode}
                  onClick={() => setView(mode)}
                >
                  {mode === "formatted"
                    ? t("inspector:inspectorResult.viewFormatted")
                    : t("inspector:inspectorResult.viewRaw")}
                </Button>
              ))}
            </div>
            <Button
              variant="ghost"
              size="sm"
              className="h-6 gap-1 px-2 text-xs"
              onClick={copyRaw}
            >
              <Copy className="h-3 w-3" />
              {t("inspector:inspectorResult.copyResult")}
            </Button>
          </div>
          {view === "formatted" ? (
            <ResultBody classified={classified} t={t} />
          ) : (
            <JsonText text={rawText} t={t} />
          )}
        </div>
      )}
    </div>
  );
}
