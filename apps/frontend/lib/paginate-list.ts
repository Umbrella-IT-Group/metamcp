/**
 * Collects every page of an MCP list (tools/list and the like) without being
 * able to loop forever.
 *
 * MCP pagination (server/utilities/pagination): the cursor is an opaque token
 * and a response without `nextCursor` ends the list. A server that returns a
 * cursor it has already returned (a bug, or a hostile or confused backend)
 * would hold a plain `while (nextCursor)` loop open indefinitely, flooding the
 * server with requests and growing the result without bound. So the walk also
 * stops on a repeated cursor and on a page cap, and says that it stopped.
 *
 * The cap and the rule match the gateway's own backend pagination helper.
 */

export const MAX_LIST_PAGES = 50;

export type Truncation = "repeated_cursor" | "page_cap";

export interface Page<T> {
  items: T[];
  nextCursor?: string | null;
}

export interface CollectedPages<T> {
  items: T[];
  pages: number;
  /**
   * Null when the list ended on its own. Otherwise why the walk was cut short:
   * the items are then an incomplete list and must not be treated as the whole
   * of it (for example, never used to delete what is not in them).
   */
  truncated: Truncation | null;
}

export async function collectAllPages<T>(
  fetchPage: (cursor: string | undefined) => Promise<Page<T>>,
  options: { maxPages?: number } = {},
): Promise<CollectedPages<T>> {
  const maxPages = options.maxPages ?? MAX_LIST_PAGES;
  const items: T[] = [];
  const requested = new Set<string>();
  let cursor: string | undefined;
  let pages = 0;

  for (;;) {
    pages += 1;
    const page = await fetchPage(cursor);
    items.push(...page.items);

    const next = page.nextCursor;
    // An absent, null or empty cursor ends the list.
    if (!next) return { items, pages, truncated: null };

    // The cursor this very page was fetched with counts as seen, so a server
    // that answers every request with the cursor it was just given is caught
    // on the second page.
    if (cursor !== undefined) requested.add(cursor);
    if (requested.has(next)) {
      return { items, pages, truncated: "repeated_cursor" };
    }
    if (pages >= maxPages) return { items, pages, truncated: "page_cap" };
    cursor = next;
  }
}
