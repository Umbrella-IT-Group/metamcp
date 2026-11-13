"use client";

import { Code, Search, Wrench, X } from "lucide-react";
import { useMemo, useState } from "react";

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
  type FilterableTool,
  filterToolEntries,
  toolPrefixCounts,
} from "@/lib/inspector/tool-filter";
import type { Translate } from "@/lib/inspector/translate";

// A prefix can never start with "__" (the first "__" of a tool name is where
// the prefix ends), so these two values cannot collide with a real prefix.
const ALL_PREFIXES = "__all__";
const NO_PREFIX = "__none__";

interface ToolListProps<T extends FilterableTool> {
  tools: T[];
  selectedTool: T | null;
  onSelect: (tool: T) => void;
  loading: boolean;
  t: Translate;
}

/**
 * The tool list with a search box and, when the tools come from more than one
 * server, a server filter with counts. The list is the full set of tools the
 * connection returned; the filter only changes what is shown.
 */
export function ToolList<T extends FilterableTool>({
  tools,
  selectedTool,
  onSelect,
  loading,
  t,
}: ToolListProps<T>) {
  const [query, setQuery] = useState("");
  const [prefixChoice, setPrefixChoice] = useState(ALL_PREFIXES);

  const prefixCounts = useMemo(() => toolPrefixCounts(tools), [tools]);
  // A single bucket gives nothing to choose between (one server, directly).
  const showPrefixSelect = prefixCounts.length >= 2;
  // A choice that no longer exists (the list was cleared and reloaded from
  // another target) falls back to "all" instead of hiding every tool.
  const prefix = useMemo(() => {
    if (!showPrefixSelect || prefixChoice === ALL_PREFIXES) return undefined;
    if (prefixChoice === NO_PREFIX) {
      return prefixCounts.some((entry) => entry.prefix === null)
        ? null
        : undefined;
    }
    return prefixCounts.some((entry) => entry.prefix === prefixChoice)
      ? prefixChoice
      : undefined;
  }, [showPrefixSelect, prefixChoice, prefixCounts]);

  const entries = useMemo(
    () => filterToolEntries(tools, { query, prefix }),
    [tools, query, prefix],
  );
  const filtering = query.trim() !== "" || prefix !== undefined;

  if (tools.length === 0) {
    return loading ? null : (
      <div className="rounded-lg border border-dashed p-6 text-center">
        <Wrench className="mx-auto mb-2 h-6 w-6 text-muted-foreground" />
        <p className="text-sm text-muted-foreground">
          {t("inspector:toolsComponent.clickListTools")}
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2">
        <div className="relative flex-1">
          <Search className="pointer-events-none absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
          <Input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder={t("inspector:inspectorFilter.searchPlaceholder")}
            aria-label={t("inspector:inspectorFilter.searchPlaceholder")}
            className="pl-8"
          />
        </div>
        {filtering && (
          <Button
            variant="ghost"
            size="icon"
            aria-label={t("inspector:inspectorFilter.clear")}
            title={t("inspector:inspectorFilter.clear")}
            onClick={() => {
              setQuery("");
              setPrefixChoice(ALL_PREFIXES);
            }}
          >
            <X className="h-4 w-4" />
          </Button>
        )}
      </div>

      {showPrefixSelect && (
        <Select value={prefixChoice} onValueChange={setPrefixChoice}>
          <SelectTrigger className="w-full" size="sm">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value={ALL_PREFIXES}>
              {t("inspector:inspectorFilter.allServers")} ({tools.length})
            </SelectItem>
            {prefixCounts.map((entry) => (
              <SelectItem
                key={entry.prefix ?? NO_PREFIX}
                value={entry.prefix ?? NO_PREFIX}
              >
                {entry.prefix ?? t("inspector:inspectorFilter.noPrefix")} (
                {entry.count})
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      )}

      <p className="text-xs text-muted-foreground">
        {t("inspector:inspectorFilter.showing", {
          shown: entries.length,
          total: tools.length,
        })}
      </p>

      {entries.length === 0 ? (
        <p className="rounded-lg border border-dashed p-4 text-center text-sm text-muted-foreground">
          {t("inspector:inspectorFilter.noMatches")}
        </p>
      ) : (
        <div className="space-y-2">
          {entries.map(({ tool, index }) => (
            <div
              // Load-more can append a page that repeats a name, so the name
              // alone is not a safe key.
              key={`${tool.name}:${index}`}
              className={`cursor-pointer rounded-lg border p-3 transition-colors ${
                selectedTool === tool
                  ? "border-blue-500 bg-blue-50 dark:border-blue-400 dark:bg-blue-950/20"
                  : "hover:bg-muted/50"
              }`}
              onClick={() => onSelect(tool)}
            >
              <div className="flex items-center gap-2">
                <Code className="h-4 w-4 text-blue-500 dark:text-blue-400" />
                <span className="font-mono text-sm">{tool.name}</span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
