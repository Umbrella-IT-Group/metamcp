"use client";

import {
  ArrowDown,
  ArrowUp,
  ChevronDown,
  ChevronUp,
  Copy,
  Download,
  Trash2,
} from "lucide-react";
import { useMemo, useState, useSyncExternalStore } from "react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { CodeBlock } from "@/components/ui/code-block";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { copyToClipboard } from "@/lib/inspector/clipboard";
import {
  type InspectorTarget,
  targetName,
} from "@/lib/inspector/inspector-target";
import { buildRpcTrafficPairs } from "@/lib/inspector/rpc-traffic/correlation";
import {
  DEFAULT_MAX_MESSAGE_BYTES,
  type RpcTrafficStore,
} from "@/lib/inspector/rpc-traffic/store";
import {
  asRecord,
  type RpcTrafficEntry,
} from "@/lib/inspector/rpc-traffic/types";
import {
  buildTrafficExport,
  DEFAULT_OMIT_BODIES,
  filterEntries,
  trafficExportFilename,
} from "@/lib/inspector/rpc-traffic/view";
import { HIGHLIGHT_LIMIT } from "@/lib/inspector/tool-result";
import type { Translate } from "@/lib/inspector/translate";

/**
 * The JSON-RPC traffic log: every message sent and received on the current
 * connection, newest first, kept in this browser tab's memory only.
 *
 * Nothing here is saved anywhere: no storage, no network. The server keeps no
 * copy of this log (it does record tool calls in its own audit log, which is
 * a different record, and the note on the panel says both).
 *
 * Every value in a message is rendered as a text node: a message body is
 * server-controlled text.
 */

const PLAIN_BLOCK =
  "max-h-96 overflow-auto whitespace-pre-wrap break-words rounded-md border bg-muted/30 p-2 font-mono text-xs";

// A server-controlled id is shortened for the one-line summary.
const ID_DISPLAY_LIMIT = 40;

function formatTime(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  const pad = (value: number, width = 2) => String(value).padStart(width, "0");
  return `${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}.${pad(date.getMilliseconds(), 3)}`;
}

function shortId(id: unknown): string | null {
  if (typeof id === "number") return String(id);
  if (typeof id === "string") {
    return id.length > ID_DISPLAY_LIMIT
      ? `${id.slice(0, ID_DISPLAY_LIMIT)}...`
      : id;
  }
  return null;
}

interface RpcTrafficPanelViewProps {
  entries: readonly RpcTrafficEntry[];
  onClear: () => void;
  onDownload: (omitBodies: boolean) => void;
  onCopyMessage: (entry: RpcTrafficEntry) => void;
  t: Translate;
}

export function MessageBody({
  entry,
  t,
}: {
  entry: RpcTrafficEntry;
  t: Translate;
}) {
  const text = JSON.stringify(entry.message, null, 2);
  return (
    <div className="space-y-1">
      {entry.truncated && (
        <p className="text-xs text-muted-foreground">
          {t("inspector:inspectorTraffic.truncated", {
            limit: DEFAULT_MAX_MESSAGE_BYTES,
            bytes: entry.bytes,
          })}
        </p>
      )}
      {text.length > HIGHLIGHT_LIMIT ? (
        <pre className={PLAIN_BLOCK}>{text}</pre>
      ) : (
        <CodeBlock language="json" maxHeight="320px" className="text-xs">
          {text}
        </CodeBlock>
      )}
    </div>
  );
}

/** Presentational (takes `t`, and the entries it shows). */
export function RpcTrafficPanelView({
  entries,
  onClear,
  onDownload,
  onCopyMessage,
  t,
}: RpcTrafficPanelViewProps) {
  const [open, setOpen] = useState(true);
  const [query, setQuery] = useState("");
  // On by default: see DEFAULT_OMIT_BODIES.
  const [omitBodies, setOmitBodies] = useState(DEFAULT_OMIT_BODIES);
  const [expanded, setExpanded] = useState<ReadonlySet<string>>(new Set());

  const { responseLabels, requestPairs } = useMemo(
    () => buildRpcTrafficPairs(entries),
    [entries],
  );
  const shown = useMemo(
    () => filterEntries(entries, query).slice().reverse(),
    [entries, query],
  );

  const toggle = (id: string) =>
    setExpanded((previous) => {
      const next = new Set(previous);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  const summarize = (entry: RpcTrafficEntry) => {
    const record = asRecord(entry.message);
    if (typeof record?.transportEvent === "string") {
      const isError = record.transportEvent === "error";
      return {
        label: isError
          ? t("inspector:inspectorTraffic.transportError")
          : t("inspector:inspectorTraffic.transportClosed"),
        detail: isError && typeof record.error === "string" ? record.error : "",
        id: null,
        transport: true,
      };
    }
    const method = typeof record?.method === "string" ? record.method : null;
    const responseLabel = responseLabels.get(entry.id);
    const isResponse =
      method === null &&
      (record?.result !== undefined || record?.error !== undefined);
    return {
      label:
        method ??
        (isResponse
          ? `${t("inspector:inspectorTraffic.response")}${
              responseLabel ? `: ${responseLabel.method}` : ""
            }`
          : t("inspector:inspectorTraffic.message")),
      detail: "",
      id: shortId(record?.id),
      transport: false,
    };
  };

  return (
    <Card className="w-full shadow-none">
      <CardHeader className="py-1 pb-1">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-1.5">
            <CardTitle className="text-sm">
              {t("inspector:inspectorTraffic.title")}
            </CardTitle>
            <Badge variant="outline" className="h-4 px-1 text-xs">
              {entries.length}
            </Badge>
          </div>
          <Button
            variant="ghost"
            size="sm"
            className="h-6 w-6 p-0"
            aria-expanded={open}
            onClick={() => setOpen((value) => !value)}
          >
            {open ? (
              <ChevronUp className="h-3 w-3" />
            ) : (
              <ChevronDown className="h-3 w-3" />
            )}
          </Button>
        </div>
        <p className="text-xs text-muted-foreground">
          {t("inspector:inspectorTraffic.subtitle")}
        </p>
      </CardHeader>

      {open && (
        <CardContent className="space-y-2 px-2 pb-2 pt-0">
          <div className="flex flex-wrap items-center gap-2">
            <Input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder={t("inspector:inspectorTraffic.searchPlaceholder")}
              aria-label={t("inspector:inspectorTraffic.searchPlaceholder")}
              className="h-8 max-w-xs text-xs"
            />
            <span className="text-xs text-muted-foreground">
              {t("inspector:inspectorTraffic.count", {
                shown: shown.length,
                total: entries.length,
              })}
            </span>
            <div className="ml-auto flex flex-wrap items-center gap-2">
              <div className="flex items-center gap-1.5">
                <Checkbox
                  id="traffic-omit-bodies"
                  checked={omitBodies}
                  onCheckedChange={(checked) => setOmitBodies(checked === true)}
                />
                <Label
                  htmlFor="traffic-omit-bodies"
                  className="text-xs font-normal"
                  title={t("inspector:inspectorTraffic.omitBodiesHelp")}
                >
                  {t("inspector:inspectorTraffic.omitBodies")}
                </Label>
              </div>
              <Button
                variant="outline"
                size="sm"
                className="h-7 px-2 text-xs"
                disabled={entries.length === 0}
                onClick={() => onDownload(omitBodies)}
              >
                <Download className="mr-1 h-3 w-3" />
                {t("inspector:inspectorTraffic.download")}
              </Button>
              <Button
                variant="outline"
                size="sm"
                className="h-7 px-2 text-xs"
                disabled={entries.length === 0}
                onClick={onClear}
              >
                <Trash2 className="mr-1 h-3 w-3" />
                {t("inspector:inspectorTraffic.clear")}
              </Button>
            </div>
          </div>

          <p className="text-xs text-muted-foreground">
            {t("inspector:inspectorTraffic.privacyNote")}
          </p>

          {shown.length === 0 ? (
            <p className="rounded-md border border-dashed p-4 text-center text-xs text-muted-foreground">
              {entries.length === 0
                ? t("inspector:inspectorTraffic.empty")
                : t("inspector:inspectorTraffic.noMatches")}
            </p>
          ) : (
            <div className="max-h-[480px] space-y-1 overflow-y-auto">
              {shown.map((entry) => {
                const summary = summarize(entry);
                const isOpen = expanded.has(entry.id);
                const response = responseLabels.get(entry.id);
                const pair = requestPairs.get(entry.id);
                const outcome = response ?? pair;
                return (
                  <div
                    key={entry.id}
                    className="rounded-md border text-xs"
                    data-direction={entry.direction}
                  >
                    <button
                      type="button"
                      className="flex w-full flex-wrap items-center gap-2 px-2 py-1 text-left hover:bg-muted/50"
                      aria-expanded={isOpen}
                      aria-label={
                        isOpen
                          ? t("inspector:inspectorTraffic.hideMessage")
                          : t("inspector:inspectorTraffic.showMessage")
                      }
                      onClick={() => toggle(entry.id)}
                    >
                      <span className="font-mono text-muted-foreground">
                        {formatTime(entry.timestamp)}
                      </span>
                      {entry.direction === "send" ? (
                        <ArrowUp
                          className="h-3 w-3 text-blue-600 dark:text-blue-400"
                          aria-label={t("inspector:inspectorTraffic.sent")}
                        />
                      ) : (
                        <ArrowDown
                          className="h-3 w-3 text-green-600 dark:text-green-400"
                          aria-label={t("inspector:inspectorTraffic.received")}
                        />
                      )}
                      <span
                        className={`break-all font-mono font-medium ${
                          summary.transport
                            ? "text-red-600 dark:text-red-400"
                            : ""
                        }`}
                      >
                        {summary.label}
                      </span>
                      {summary.id !== null && (
                        <span className="font-mono text-muted-foreground">
                          #{summary.id}
                        </span>
                      )}
                      {summary.detail !== "" && (
                        <span className="break-all text-muted-foreground">
                          {summary.detail}
                        </span>
                      )}
                      {entry.repeatCount !== undefined && (
                        <Badge variant="secondary" className="h-4 px-1">
                          {t("inspector:inspectorTraffic.repeat", {
                            count: entry.repeatCount,
                          })}
                        </Badge>
                      )}
                      {outcome && (
                        <Badge
                          variant={
                            outcome.outcome === "error"
                              ? "destructive"
                              : "outline"
                          }
                          className="h-4 px-1"
                        >
                          {t("inspector:inspectorTraffic.latency", {
                            ms: outcome.latencyMs,
                          })}{" "}
                          {outcome.outcome === "error"
                            ? t("inspector:inspectorTraffic.pairError")
                            : t("inspector:inspectorTraffic.pairOk")}
                        </Badge>
                      )}
                      <span className="ml-auto font-mono text-muted-foreground">
                        {entry.bytes}B
                      </span>
                    </button>
                    {isOpen && (
                      <div className="space-y-1 border-t p-2">
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-6 px-2 text-xs"
                          onClick={() => onCopyMessage(entry)}
                        >
                          <Copy className="mr-1 h-3 w-3" />
                          {t("inspector:inspectorTraffic.copyMessage")}
                        </Button>
                        <MessageBody entry={entry} t={t} />
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </CardContent>
      )}
    </Card>
  );
}

const noSubscribe = () => () => {};
const emptySnapshot: readonly RpcTrafficEntry[] = Object.freeze([]);
const getEmptySnapshot = () => emptySnapshot;

interface RpcTrafficPanelProps {
  store: RpcTrafficStore | null;
  target: InspectorTarget;
  t: Translate;
}

/** The panel for a connection's store (or an empty one before the first connect). */
export function RpcTrafficPanel({ store, target, t }: RpcTrafficPanelProps) {
  const entries = useSyncExternalStore(
    store ? store.subscribe : noSubscribe,
    store ? store.getSnapshot : getEmptySnapshot,
    store ? store.getServerSnapshot : getEmptySnapshot,
  );

  const download = (omitBodies: boolean) => {
    if (!store) return;
    // Read from the live list, not the snapshot: the snapshot waits for an
    // animation frame, which a background tab does not run.
    const held = store.exportEntries();
    const nowMs = Date.now();
    const payload = buildTrafficExport(
      held,
      buildRpcTrafficPairs(held).responseLabels,
      {
        target: { kind: target.kind, name: targetName(target) },
        exportedAtMs: nowMs,
      },
      { omitBodies },
    );
    const blob = new Blob([JSON.stringify(payload, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = trafficExportFilename(targetName(target), nowMs);
    document.body.appendChild(anchor);
    anchor.click();
    document.body.removeChild(anchor);
    URL.revokeObjectURL(url);
    toast.success(t("inspector:inspectorTraffic.downloaded"));
  };

  const copyMessage = async (entry: RpcTrafficEntry) => {
    const copied = await copyToClipboard(
      JSON.stringify(entry.message, null, 2),
    );
    if (copied) toast.success(t("inspector:inspectorTraffic.messageCopied"));
    else toast.error(t("inspector:inspectorResult.copyFailed"));
  };

  return (
    <RpcTrafficPanelView
      entries={entries}
      onClear={() => store?.clear()}
      onDownload={download}
      onCopyMessage={copyMessage}
      t={t}
    />
  );
}
