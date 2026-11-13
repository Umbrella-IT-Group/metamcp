import { parseToolName } from "@/lib/tool-name-parser";

/**
 * Search and server-prefix filtering for the Inspector's tool list.
 *
 * A gateway tool name is `{server prefix}__{tool}` (see lib/tool-name-parser.ts:
 * the first "__" is the separator, and anything after it belongs to the tool
 * name), so the prefix is the part before the first "__". A tool with no "__"
 * has no prefix, which is the normal case when the Inspector is connected to
 * one server directly.
 */

export interface FilterableTool {
  name: string;
  description?: string | undefined;
}

export interface ToolFilter {
  query: string;
  /**
   * undefined: do not filter by prefix. null: only tools with no prefix. A
   * string: only tools with exactly that prefix.
   */
  prefix?: string | null;
}

export interface PrefixCount {
  prefix: string | null;
  count: number;
}

export function toolPrefix(name: string): string | null {
  const parsed = parseToolName(name);
  return parsed && parsed.serverName !== "" ? parsed.serverName : null;
}

/** Tools per prefix, sorted by code unit (not locale), no-prefix last. */
export function toolPrefixCounts(tools: FilterableTool[]): PrefixCount[] {
  const counts = new Map<string | null, number>();
  for (const tool of tools) {
    const prefix = toolPrefix(tool.name);
    counts.set(prefix, (counts.get(prefix) ?? 0) + 1);
  }
  const named = [...counts.entries()]
    .filter((entry): entry is [string, number] => entry[0] !== null)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([prefix, count]) => ({ prefix, count }));
  const unprefixed = counts.get(null);
  return unprefixed === undefined
    ? named
    : [...named, { prefix: null, count: unprefixed }];
}

/**
 * The tools that match, each with its position in the full list (the list uses
 * the position for a stable row key, since load-more can append a page that
 * repeats a name).
 */
export function filterToolEntries<T extends FilterableTool>(
  tools: T[],
  filter: ToolFilter,
): { tool: T; index: number }[] {
  const query = filter.query.trim().toLowerCase();
  const entries: { tool: T; index: number }[] = [];
  tools.forEach((tool, index) => {
    if (
      filter.prefix !== undefined &&
      toolPrefix(tool.name) !== filter.prefix
    ) {
      return;
    }
    if (query !== "") {
      const inName = tool.name.toLowerCase().includes(query);
      const inDescription = (tool.description ?? "")
        .toLowerCase()
        .includes(query);
      if (!inName && !inDescription) return;
    }
    entries.push({ tool, index });
  });
  return entries;
}

export function filterTools<T extends FilterableTool>(
  tools: T[],
  filter: ToolFilter,
): T[] {
  return filterToolEntries(tools, filter).map((entry) => entry.tool);
}
