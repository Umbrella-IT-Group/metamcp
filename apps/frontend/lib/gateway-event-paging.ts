import type { GatewayEvent, GatewayEventCursor } from "@repo/zod-types";

/**
 * The pure half of the history view's pagination.
 *
 * Extracted from `components/gateway-event-history.tsx` so it can be TESTED.
 * The frontend harness is `environment: "node"` with no DOM and no
 * component-testing library (see `vitest.config.ts`), and this is the part of
 * that component where being wrong is silent: a cursor taken from the wrong
 * page, or rows joined in the wrong order, produces a list that looks fine and
 * is missing entries. The React that remains around these functions is state
 * plumbing.
 */

/**
 * Which cursor drives "load older".
 *
 * Until an extra page has been loaded, the live first page is the authority on
 * whether more exists. After that, the last page fetched is. Deriving it from
 * both instead of storing one is what keeps a background refetch of page one
 * from stranding or resurrecting the button: the two sources are never both
 * consulted, so they cannot disagree.
 */
export function activeCursor(
  firstPageCursor: GatewayEventCursor | null | undefined,
  pagedCursor: GatewayEventCursor | null,
  loadedPageCount: number,
): GatewayEventCursor | null {
  if (loadedPageCount > 0) return pagedCursor;
  return firstPageCursor ?? null;
}

/**
 * Flatten the first page and every page loaded after it, newest first.
 *
 * Order is positional rather than re-sorted: each page already arrives
 * newest-first from a keyset query that resumes exactly where the previous one
 * stopped, so re-sorting here would only be able to hide a paging bug, never
 * fix one.
 */
export function joinPages(
  firstPage: GatewayEvent[] | undefined,
  extraPages: GatewayEvent[][],
): GatewayEvent[] {
  return [...(firstPage ?? []), ...extraPages.flat()];
}
