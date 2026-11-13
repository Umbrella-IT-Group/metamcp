// Skeleton: the final exported API, inert until the implementation commit.

export interface FilterableTool {
  name: string;
  description?: string | undefined;
}

export interface ToolFilter {
  query: string;
  prefix?: string | null;
}

export interface PrefixCount {
  prefix: string | null;
  count: number;
}

export function toolPrefix(_name: string): string | null {
  return null;
}

export function toolPrefixCounts(_tools: FilterableTool[]): PrefixCount[] {
  return [];
}

export function filterToolEntries<T extends FilterableTool>(
  tools: T[],
  _filter: ToolFilter,
): { tool: T; index: number }[] {
  return tools.map((tool, index) => ({ tool, index }));
}

export function filterTools<T extends FilterableTool>(
  tools: T[],
  filter: ToolFilter,
): T[] {
  return filterToolEntries(tools, filter).map((entry) => entry.tool);
}
