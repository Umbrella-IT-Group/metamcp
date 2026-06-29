"use client";

import { FileTerminal, RefreshCw, Trash2 } from "lucide-react";
import { useMemo, useState } from "react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { useTranslations } from "@/hooks/useTranslations";
import { useLogsStore } from "@/lib/stores/logs-store";

// Event categories for the activity view. Short tag + filter label + color.
// Strings are intentionally literal (not i18n): this is an internal admin
// surface and the operator works in English.
// Literal Tailwind classes (text-*/bg-*) — never build these by string
// concatenation or the JIT purge drops them from the bundle.
const CATEGORIES = [
  {
    key: "tool_call",
    tag: "TOOL",
    label: "Tool calls",
    text: "text-emerald-400",
    dot: "bg-emerald-400",
  },
  {
    key: "connection",
    tag: "CONN",
    label: "Connections",
    text: "text-sky-400",
    dot: "bg-sky-400",
  },
  {
    key: "server",
    tag: "SRV",
    label: "Server",
    text: "text-amber-400",
    dot: "bg-amber-400",
  },
  {
    key: "system",
    tag: "SYS",
    label: "System",
    text: "text-violet-400",
    dot: "bg-violet-400",
  },
] as const;

const categoryMeta = (category: string) =>
  CATEGORIES.find((c) => c.key === category) ?? {
    tag: "LOG",
    label: category,
    text: "text-gray-400",
  };

const messageColor = (level: string) =>
  level === "error"
    ? "text-red-300"
    : level === "warn"
      ? "text-amber-300"
      : "text-gray-300";

export default function LiveLogsPage() {
  const { t } = useTranslations();
  const [showClearDialog, setShowClearDialog] = useState(false);
  const {
    logs,
    isLoading,
    isAutoRefreshing,
    totalCount,
    lastFetch,
    fetchLogs,
    clearLogs,
    setAutoRefresh,
  } = useLogsStore();

  const handleClearLogs = async () => {
    try {
      await clearLogs();
      toast.success(t("logs:logsClearSuccess"));
      setShowClearDialog(false);
    } catch (_error) {
      toast.error(t("logs:logsClearError"));
    }
  };

  const handleRefresh = async () => {
    try {
      await fetchLogs();
      toast.success(t("logs:refreshSuccess"));
    } catch (_error) {
      toast.error(t("logs:refreshError"));
    }
  };

  const handleToggleAutoRefresh = () => {
    setAutoRefresh(!isAutoRefreshing);
    if (!isAutoRefreshing) {
      toast.success(t("logs:autoRefreshEnabled"));
    } else {
      toast.info(t("logs:autoRefreshDisabled"));
    }
  };

  const [enabledCategories, setEnabledCategories] = useState<Set<string>>(
    () => new Set(CATEGORIES.map((c) => c.key)),
  );
  const [problemsOnly, setProblemsOnly] = useState(false);

  const toggleCategory = (key: string) => {
    setEnabledCategories((prev) => {
      const next = new Set(prev);
      if (next.has(key)) {
        next.delete(key);
      } else {
        next.add(key);
      }
      return next;
    });
  };

  const filteredLogs = useMemo(
    () =>
      logs.filter(
        (log) =>
          enabledCategories.has(log.category ?? "system") &&
          (!problemsOnly || log.level === "error" || log.level === "warn"),
      ),
    [logs, enabledCategories, problemsOnly],
  );

  const formatTimestamp = (timestamp: Date) => {
    return new Date(timestamp).toLocaleString();
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <FileTerminal className="h-6 w-6 text-muted-foreground" />
          <div>
            <h1 className="text-2xl font-semibold">{t("logs:title")}</h1>
            <p className="text-sm text-muted-foreground">
              {t("logs:subtitle")}
              {lastFetch && (
                <span className="ml-2">
                  (
                  {t("logs:lastUpdated", {
                    timestamp: formatTimestamp(lastFetch),
                  })}
                  )
                </span>
              )}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Badge variant="outline">
            {t("logs:totalLogs", { count: totalCount })}
          </Badge>
          <Button variant="outline" size="sm" onClick={handleToggleAutoRefresh}>
            {isAutoRefreshing
              ? t("logs:stopAutoRefresh")
              : t("logs:startAutoRefresh")}
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={handleRefresh}
            disabled={isLoading}
          >
            <RefreshCw
              className={`h-4 w-4 ${isLoading ? "animate-spin" : ""}`}
            />
            {t("logs:refresh")}
          </Button>
          <Button
            variant="destructive"
            size="sm"
            onClick={() => setShowClearDialog(true)}
            disabled={isLoading || logs.length === 0}
          >
            <Trash2 className="h-4 w-4" />
            {t("logs:clearLogs")}
          </Button>
        </div>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <span>{t("logs:consoleOutput")}</span>
            {isAutoRefreshing && (
              <Badge variant="secondary" className="text-xs">
                {t("logs:live")}
              </Badge>
            )}
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          {/* Category + severity filters (client-side over the fetched window) */}
          <div className="flex flex-wrap items-center gap-2">
            {CATEGORIES.map((cat) => {
              const on = enabledCategories.has(cat.key);
              return (
                <Button
                  key={cat.key}
                  variant={on ? "secondary" : "outline"}
                  size="sm"
                  className="h-7 px-2 text-xs"
                  onClick={() => toggleCategory(cat.key)}
                >
                  <span
                    className={`mr-1.5 inline-block h-2 w-2 rounded-full ${on ? cat.dot : "bg-gray-600"}`}
                  />
                  {cat.label}
                </Button>
              );
            })}
            <span className="mx-1 h-4 w-px bg-border" />
            <Button
              variant={problemsOnly ? "secondary" : "outline"}
              size="sm"
              className="h-7 px-2 text-xs"
              onClick={() => setProblemsOnly((v) => !v)}
            >
              Errors &amp; warnings only
            </Button>
          </div>

          <div className="bg-black rounded-lg p-4 font-mono text-sm max-h-[600px] overflow-y-auto">
            {filteredLogs.length === 0 ? (
              <div className="text-gray-400 text-center py-8">
                {isLoading ? t("logs:loadingLogs") : t("logs:noLogsDisplay")}
              </div>
            ) : (
              <div className="space-y-1">
                {filteredLogs.map((log) => {
                  const meta = categoryMeta(log.category ?? "system");
                  return (
                    <div
                      key={log.id}
                      className="flex items-start gap-2 hover:bg-gray-800 px-2 py-1 rounded"
                    >
                      <span className="text-gray-500 text-xs whitespace-nowrap">
                        {formatTimestamp(new Date(log.timestamp))}
                      </span>
                      <span
                        className={`text-xs font-semibold tracking-wide whitespace-nowrap ${meta.text}`}
                        title={meta.label}
                      >
                        {meta.tag}
                      </span>
                      <span className="text-blue-400 font-medium whitespace-nowrap">
                        [{log.serverName}]
                      </span>
                      <span className="flex-1 break-all">
                        <span className={messageColor(log.level)}>
                          {log.message}
                        </span>
                        {log.error && (
                          <span className="text-red-400 ml-2">
                            — {log.error}
                          </span>
                        )}
                      </span>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </CardContent>
      </Card>

      {logs.length > 0 && (
        <div className="text-sm text-muted-foreground text-center">
          {t("logs:showingLogs", {
            count: filteredLogs.length,
            total: totalCount,
          })}
        </div>
      )}

      <Dialog open={showClearDialog} onOpenChange={setShowClearDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t("logs:clearAllLogs")}</DialogTitle>
            <DialogDescription>{t("logs:clearLogsConfirm")}</DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowClearDialog(false)}>
              {t("common:cancel")}
            </Button>
            <Button
              variant="destructive"
              onClick={handleClearLogs}
              disabled={isLoading}
            >
              <Trash2 className="h-4 w-4 mr-2" />
              {t("logs:clearLogs")}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
