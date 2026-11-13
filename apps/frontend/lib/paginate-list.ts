// Skeleton: the final exported API with the loop as it was before this change,
// which follows nextCursor for as long as the server returns one.

export const MAX_LIST_PAGES = 50;

export type Truncation = "repeated_cursor" | "page_cap";

export interface Page<T> {
  items: T[];
  nextCursor?: string | null;
}

export interface CollectedPages<T> {
  items: T[];
  pages: number;
  truncated: Truncation | null;
}

export async function collectAllPages<T>(
  fetchPage: (cursor: string | undefined) => Promise<Page<T>>,
  _options?: { maxPages?: number },
): Promise<CollectedPages<T>> {
  const items: T[] = [];
  let cursor: string | undefined;
  let pages = 0;
  let hasMore = true;
  while (hasMore) {
    pages += 1;
    const page = await fetchPage(cursor);
    items.push(...page.items);
    cursor = page.nextCursor ?? undefined;
    hasMore = !!page.nextCursor;
  }
  return { items, pages, truncated: null };
}
