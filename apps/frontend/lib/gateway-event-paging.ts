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

/**
 * Should a resolved "load older" fetch still be applied?
 *
 * A fetch is issued against one filter set and resolves some time later. If the
 * operator changed a filter while it was in flight, the rows that come back
 * belong to the PREVIOUS result set — appending them puts old-filter events
 * underneath the new first page, and the cursor that arrives with them points
 * into the old ordering, so every subsequent page compounds the mix. On an
 * investigation surface that is worse than an error: the list looks like one
 * coherent answer to the filters currently on screen.
 *
 * The epoch is bumped by the same effect that clears the loaded pages, so
 * "the filters changed" and "the accumulated pages were discarded" are the same
 * event by construction rather than by two conditions agreeing.
 */
export function isFetchStillCurrent(
  epochAtDispatch: number,
  epochNow: number,
): boolean {
  return epochAtDispatch === epochNow;
}
