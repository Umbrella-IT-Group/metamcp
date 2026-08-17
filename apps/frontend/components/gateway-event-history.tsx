"use client";

import type { GatewayEvent, GatewayEventCursor } from "@repo/zod-types";
import { Loader2, Search } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  activeCursor,
  isFetchStillCurrent,
  joinPages,
} from "@/lib/gateway-event-paging";
import {
  categoryMeta,
  HISTORY_CATEGORIES,
  messageColor,
} from "@/lib/log-categories";
import { trpc } from "@/lib/trpc";

/**
 * The durable half of the Live Logs page: `gateway_events` (migration 0031),
 * browsable rather than tailed.
 *
 * The live view above it is a 2s poll of an in-memory ring buffer that dies
 * with the process. This one answers the questions that buffer cannot — "was
 * this failing yesterday too?", "who was connected when it broke?" — over a
 * table that is immutable for 30 days.
 *
 * Rows are rendered with the SAME tag, colour and layout as the live tail
 * (`lib/log-categories`), because they are the same events. A history that
 * looked different from the tail would make an operator second-guess whether
 * they were reading the same thing.
 *
 * EVERY user-visible string here is a literal, deliberately, and it is a
 * deviation from the rest of the page worth naming rather than leaving to be
 * discovered. The page's headings and buttons resolve through `t("logs:…")`
 * against `public/locales/{en,ko,zh}/logs.json`, but its category filter
 * buttons have always been literal English on the same reasoning the live view
 * states: this is an internal admin surface and the operator works in English.
 * Adding half a namespace — English keys with no zh/ko translations, silently
 * falling back — would look translated without being translated. If this
 * surface is ever localised, all three files get the keys in one pass.
 */

const RANGES = [
  { key: "1h", label: "Last hour", hours: 1 },
  { key: "24h", label: "Last 24 hours", hours: 24 },
  { key: "7d", label: "Last 7 days", hours: 24 * 7 },
  { key: "30d", label: "Last 30 days", hours: 24 * 30 },
  { key: "90d", label: "Last 90 days", hours: 24 * 90 },
] as const;

const LEVELS = [
  { key: "error", label: "Errors" },
  { key: "warn", label: "Warnings" },
  { key: "info", label: "Info" },
] as const;

const PAGE_SIZE = 100;

/** Sentinel for "no filter". A Select item cannot carry an empty value. */
const ANY = "__any";

export function GatewayEventHistory({ isAdmin }: { isAdmin: boolean }) {
  const [rangeKey, setRangeKey] = useState<string>("24h");
  const [category, setCategory] = useState<string>(ANY);
  const [level, setLevel] = useState<string>(ANY);
  const [serverName, setServerName] = useState<string>(ANY);
  // Two pieces of state for one box: `searchDraft` is what the operator is
  // typing, `search` is what has been submitted. Without the split every
  // keystroke would be a query against a table that only grows.
  const [searchDraft, setSearchDraft] = useState("");
  const [search, setSearch] = useState("");

  const range = RANGES.find((r) => r.key === rangeKey) ?? RANGES[1];

  // Pinned when the filters change rather than recomputed per render: a `from`
  // that slides forward on every render would make the first page's cursor
  // point into a window the next page no longer covers.
  const from = useMemo(
    () => new Date(Date.now() - range.hours * 60 * 60 * 1000).toISOString(),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [range.hours, category, level, serverName, search],
  );

  const filters = useMemo(
    () => ({
      from,
      category: category === ANY ? undefined : (category as never),
      level: level === ANY ? undefined : (level as never),
      serverName: serverName === ANY ? undefined : serverName,
      search: search === "" ? undefined : search,
      limit: PAGE_SIZE,
    }),
    [from, category, level, serverName, search],
  );

  const { data, error, isError, isLoading, isFetching, refetch } =
    trpc.frontend.logs.history.useQuery(filters, { enabled: isAdmin });

  const utils = trpc.useUtils();
  const [extraPages, setExtraPages] = useState<GatewayEvent[][]>([]);
  const [pagedCursor, setPagedCursor] = useState<GatewayEventCursor | null>(
    null,
  );
  const [isLoadingMore, setIsLoadingMore] = useState(false);

  // Reset on the FILTERS, not on `data`.
  //
  // Keying this on the query result would discard every page the operator had
  // loaded whenever the first page merely REFETCHED — a background revalidation
  // is a new `data` identity with the same filters, so pressing "Load older"
  // three times and then losing all of it to an invisible refetch was reachable
  // without touching a control. The filter object is the thing that actually
  // invalidates a cursor, because a cursor points into one ordered result set.
  //
  // The epoch counter rides along so an in-flight "load older" can tell that
  // the world moved under it — see loadMore. Bumped HERE, in the same effect
  // that discards the pages, so the two can never disagree about whether a
  // filter change happened.
  const filterEpoch = useRef(0);
  useEffect(() => {
    filterEpoch.current += 1;
    setExtraPages([]);
    setPagedCursor(null);
  }, [filters]);

  // Pure, and tested in lib/gateway-event-paging.test.ts: the frontend harness
  // has no DOM, so the decisions worth pinning live outside the component.
  const cursor = activeCursor(data?.nextCursor, pagedCursor, extraPages.length);

  const loadMore = useCallback(async () => {
    if (!cursor) return;
    // Captured BEFORE the await. A filter changed while this request is in
    // flight makes its rows belong to a result set that is no longer on screen,
    // and appending them would interleave old-filter events under the new first
    // page while paging continued from a cursor into the old ordering.
    const dispatchedAt = filterEpoch.current;
    setIsLoadingMore(true);
    try {
      const next = await utils.frontend.logs.history.fetch({
        ...filters,
        cursor,
      });
      if (!isFetchStillCurrent(dispatchedAt, filterEpoch.current)) return;
      setExtraPages((pages) => [...pages, next.data]);
      // Null here ends the run — the button disappears rather than fetching an
      // empty page forever.
      setPagedCursor(next.nextCursor ?? null);
    } catch (error) {
      // A failure from a superseded request is not worth a toast either: the
      // operator has already moved on, and the filters they are looking at now
      // loaded fine.
      if (!isFetchStillCurrent(dispatchedAt, filterEpoch.current)) return;
      toast.error(
        error instanceof Error ? error.message : "Failed to load more events",
      );
    } finally {
      setIsLoadingMore(false);
    }
  }, [cursor, filters, utils]);

  const events = useMemo(
    () => joinPages(data?.data, extraPages),
    [data, extraPages],
  );

  const serverNames = data?.serverNames ?? [];

  const submitSearch = () => setSearch(searchDraft.trim());

  const resetFilters = () => {
    setRangeKey("24h");
    setCategory(ANY);
    setLevel(ANY);
    setServerName(ANY);
    setSearchDraft("");
    setSearch("");
  };

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <Select value={rangeKey} onValueChange={setRangeKey}>
          <SelectTrigger className="h-8 w-[160px] text-xs">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {RANGES.map((r) => (
              <SelectItem key={r.key} value={r.key}>
                {r.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>

        <Select value={category} onValueChange={setCategory}>
          <SelectTrigger className="h-8 w-[160px] text-xs">
            <SelectValue placeholder="All categories" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value={ANY}>All categories</SelectItem>
            {HISTORY_CATEGORIES.map((c) => (
              <SelectItem key={c.key} value={c.key}>
                {c.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>

        <Select value={level} onValueChange={setLevel}>
          <SelectTrigger className="h-8 w-[140px] text-xs">
            <SelectValue placeholder="All levels" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value={ANY}>All levels</SelectItem>
            {LEVELS.map((l) => (
              <SelectItem key={l.key} value={l.key}>
                {l.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>

        <Select value={serverName} onValueChange={setServerName}>
          <SelectTrigger className="h-8 w-[190px] text-xs">
            <SelectValue placeholder="All servers" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value={ANY}>All servers</SelectItem>
            {serverNames.map((name) => (
              <SelectItem key={name} value={name}>
                {name}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>

        <div className="flex items-center gap-1">
          <Input
            value={searchDraft}
            onChange={(event) => setSearchDraft(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === "Enter") submitSearch();
            }}
            placeholder="Search messages"
            className="h-8 w-[220px] text-xs"
          />
          <Button
            variant="outline"
            size="sm"
            className="h-8 px-2"
            onClick={submitSearch}
          >
            <Search className="h-3.5 w-3.5" />
          </Button>
        </div>

        <Button
          variant="outline"
          size="sm"
          className="h-8 px-2 text-xs"
          onClick={resetFilters}
        >
          Reset
        </Button>

        <Button
          variant="outline"
          size="sm"
          className="h-8 px-2 text-xs"
          onClick={() => refetch()}
          disabled={isFetching}
        >
          {isFetching ? (
            <Loader2 className="h-3.5 w-3.5 animate-spin" />
          ) : (
            "Reload"
          )}
        </Button>
      </div>

      {/* A failed query must NOT render as an empty result. On an investigation
          surface "no recorded events match these filters" and "the query did
          not run" lead to opposite conclusions, and the first one is the
          reassuring one. */}
      {isError && (
        <div className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive">
          Could not load recorded activity:{" "}
          {error instanceof Error ? error.message : "unknown error"}
        </div>
      )}

      <div className="bg-black rounded-lg p-4 font-mono text-sm max-h-[600px] overflow-y-auto">
        {events.length === 0 ? (
          <div className="text-gray-400 text-center py-8">
            {isLoading
              ? "Loading history..."
              : isError
                ? "History unavailable"
                : "No recorded events match these filters"}
          </div>
        ) : (
          <div className="space-y-1">
            {events.map((event) => {
              const meta = categoryMeta(event.category);
              const detail =
                event.metadata &&
                typeof event.metadata.error === "string" &&
                event.metadata.error !== ""
                  ? event.metadata.error
                  : null;
              return (
                <div
                  key={event.uuid}
                  className="flex items-start gap-2 hover:bg-gray-800 px-2 py-1 rounded"
                >
                  <span className="text-gray-500 text-xs whitespace-nowrap">
                    {new Date(event.occurredAt).toLocaleString()}
                  </span>
                  <span
                    className={`text-xs font-semibold tracking-wide whitespace-nowrap ${meta.text}`}
                    title={meta.label}
                  >
                    {meta.tag}
                  </span>
                  <span className="text-blue-400 font-medium whitespace-nowrap">
                    [{event.serverName ?? "gateway"}]
                  </span>
                  <span className="flex-1 break-all">
                    <span className={messageColor(event.level)}>
                      {event.message}
                    </span>
                    {event.clientName && (
                      <span className="text-cyan-300 ml-2">
                        ← {event.clientName}
                      </span>
                    )}
                    {detail && (
                      <span className="text-red-400 ml-2">— {detail}</span>
                    )}
                  </span>
                </div>
              );
            })}
          </div>
        )}
      </div>

      <div className="flex items-center justify-between">
        <span className="text-sm text-muted-foreground">
          {events.length > 0
            ? `Showing ${events.length} recorded event${events.length === 1 ? "" : "s"} (newest first)`
            : ""}
        </span>
        <div className="flex items-center gap-2">
          <Badge variant="outline" className="text-xs">
            Immutable for 30 days
          </Badge>
          {cursor && (
            <Button
              variant="outline"
              size="sm"
              onClick={loadMore}
              disabled={isLoadingMore}
            >
              {isLoadingMore ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                "Load older"
              )}
            </Button>
          )}
        </div>
      </div>
    </div>
  );
}
