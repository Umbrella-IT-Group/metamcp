"use client";

import { FileTerminal, RefreshCw } from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import { toast } from "sonner";

import { GatewayEventHistory } from "@/components/gateway-event-history";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { useTranslations } from "@/hooks/useTranslations";
import { authClient } from "@/lib/auth-client";
import { CATEGORIES, categoryMeta, messageColor } from "@/lib/log-categories";
import { useLogsStore } from "@/lib/stores/logs-store";

// The two things this page can show. LIVE is the in-memory ring buffer tailed
// every 2s — fast, and gone on restart. HISTORY is `gateway_events` (migration
// 0031), the durable record of the same events, immutable for 30 days.
//
// A mode toggle rather than a second page: an operator troubleshooting moves
// between "what is happening now" and "was this happening yesterday too" in one
// investigation, and splitting them across two navigation items makes that a
// context switch instead of a click. Live stays the default so the page opens
// on the cheap view.
type LogView = "live" | "history";

// The history controls are literal English rather than i18n keys, matching
// this page's pre-existing category-filter buttons. See the note at the top of
// components/gateway-event-history.tsx for why half a namespace is worse than
// none.

// Read-only view. The "Clear logs" button and its confirm dialog were removed
// with migration 0028's audit_log: they were the one admin gesture that
// erased the live security view mid-investigation. See
// packages/trpc/src/routers/frontend/logs.ts — the procedure behind them no
// longer exists. The history view is read-only for the same reason, one layer
// deeper: its table refuses UPDATE and TRUNCATE at any age.
export default function LiveLogsPage() {
  const { t } = useTranslations();
  const [view, setView] = useState<LogView>("live");
  const {
    logs,
    isLoading,
    isAutoRefreshing,
    totalCount,
    lastFetch,
    fetchLogs,
    setAutoRefresh,
  } = useLogsStore();

  // Resolved for the HISTORY view only. `logs.history` is an adminProcedure,
  // and `enabled: isAdmin` keeps a member from firing a query that could only
  // ever return FORBIDDEN. The live view above is untouched: it fetches through
  // the logs store, which already stops its own poll on a 401/403.
  //
  // roleLoaded matters for the same reason it does on the OAuth-clients page:
  // isAdmin starts false, so without it an admin would see a flash of the false
  // "administrators only" claim while the session request is in flight. A
  // failed fetch surfaces a retry rather than pinning the neutral state
  // forever. Fail-closed throughout.
  const [isAdmin, setIsAdmin] = useState(false);
  const [roleLoaded, setRoleLoaded] = useState(false);
  const [roleError, setRoleError] = useState(false);
  const loadRole = useCallback(() => {
    setRoleError(false);
    authClient
      .getSession()
      .then((session) => {
        const role = (session?.data?.user as { role?: string } | undefined)
          ?.role;
        setIsAdmin(role === "admin");
        setRoleLoaded(true);
      })
      .catch(() => {
        setRoleError(true);
      });
  }, []);
  useEffect(() => {
    loadRole();
  }, [loadRole]);

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
          {/* Mode toggle. The live controls beside it stay mounted but hidden in
              history mode — the tail keeps running underneath, so switching back
              shows a current buffer rather than an empty one. */}
          <div className="flex items-center rounded-md border p-0.5">
            <Button
              variant={view === "live" ? "secondary" : "ghost"}
              size="sm"
              className="h-7 px-3 text-xs"
              onClick={() => setView("live")}
            >
              Live
            </Button>
            <Button
              variant={view === "history" ? "secondary" : "ghost"}
              size="sm"
              className="h-7 px-3 text-xs"
              onClick={() => setView("history")}
            >
              History
            </Button>
          </div>
          {view === "live" && (
            <>
              <Badge variant="outline">
                {t("logs:totalLogs", { count: totalCount })}
              </Badge>
              <Button
                variant="outline"
                size="sm"
                onClick={handleToggleAutoRefresh}
              >
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
            </>
          )}
          {view === "history" && roleError && (
            <Button variant="outline" size="sm" onClick={loadRole}>
              <RefreshCw className="h-4 w-4" />
              {t("logs:refresh")}
            </Button>
          )}
        </div>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <span>
              {view === "live" ? t("logs:consoleOutput") : "Recorded activity"}
            </span>
            {view === "live" && isAutoRefreshing && (
              <Badge variant="secondary" className="text-xs">
                {t("logs:live")}
              </Badge>
            )}
          </CardTitle>
        </CardHeader>
        {view === "history" ? (
          <CardContent className="space-y-3">
            {/* Four states, not two, and the two extra ones both exist because
                `isAdmin` starts false. A FAILED session lookup and a session
                lookup still IN FLIGHT are each indistinguishable from "not an
                admin" by that flag alone, and mounting the history in either
                case renders the disabled query as an empty result — which reads
                as "nothing was recorded". On an investigation surface that is
                the one wrong answer that looks like a right one. */}
            {roleError ? (
              <p className="text-sm text-destructive">
                Could not confirm your role, so recorded activity was not
                loaded. Use Refresh above to retry.
              </p>
            ) : !roleLoaded ? (
              <p className="text-sm text-muted-foreground">
                Checking access...
              </p>
            ) : !isAdmin ? (
              <p className="text-sm text-muted-foreground">
                Recorded activity is available to administrators only.
              </p>
            ) : (
              <GatewayEventHistory isAdmin={isAdmin} />
            )}
          </CardContent>
        ) : (
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
                          {log.clientName && (
                            <span className="text-cyan-300 ml-2">
                              ← {log.clientName}
                            </span>
                          )}
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
        )}
      </Card>

      {view === "live" && logs.length > 0 && (
        <div className="text-sm text-muted-foreground text-center">
          {t("logs:showingLogs", {
            count: filteredLogs.length,
            total: totalCount,
          })}
        </div>
      )}
    </div>
  );
}
