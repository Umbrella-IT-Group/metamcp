import logger from "@/utils/logger";

import { metamcpLogStore } from "./log-store";

/**
 * One guarded loop for every `tools/list` the gateway runs against a backend.
 *
 * MCP pagination (spec, server/utilities/pagination) is opaque cursors, and a
 * missing `nextCursor` ends the listing. A backend that never ends it (a
 * cursor it hands out again, or endless fresh cursors) used to hang the
 * request-path listing, the dynamic tool lookup and the OpenAPI listing, and
 * only the periodic sweep had a guard. A repeated cursor or the page cap now
 * stops the loop with the pages gathered so far. The stop is reported to the
 * caller so it can refuse to treat a partial list as the whole one.
 */

/** The page cap the periodic sweep already used. */
export const TOOLS_LIST_MAX_PAGES = 50;

export type ToolsListStop = "cursor_repeat" | "page_cap";

export interface CollectedToolPages<T> {
  pages: T[];
  /** Set when the loop stopped early; the listing is then incomplete. */
  stopped?: ToolsListStop;
}

/**
 * Fetches pages until the backend ends the listing or a guard fires.
 *
 * A guard fires only when the backend offers ANOTHER page: a listing of
 * exactly `maxPages` pages that ends on its own is complete and is not
 * reported. The page that carried a repeated cursor is kept.
 */
export async function collectToolsListPages<T extends { nextCursor?: string }>(
  fetchPage: (cursor: string | undefined) => Promise<T>,
  maxPages: number = TOOLS_LIST_MAX_PAGES,
): Promise<CollectedToolPages<T>> {
  const pages: T[] = [];
  const requested = new Set<string>();
  let cursor: string | undefined;

  for (;;) {
    const page = await fetchPage(cursor);
    pages.push(page);

    const next = page.nextCursor;
    // Cursors are opaque strings: even "" can identify another page. Only
    // an absent cursor proves the listing is complete and safe to sync.
    if (next === undefined) return { pages };
    if (requested.has(next) || next === cursor) {
      return { pages, stopped: "cursor_repeat" };
    }
    if (pages.length >= maxPages) {
      return { pages, stopped: "page_cap" };
    }
    requested.add(next);
    cursor = next;
  }
}

/**
 * The tools of every gathered page. A listing that ended on its own is a plain
 * flatten, byte-identical to what each loop produced before. A stopped listing
 * is de-duplicated by name (first occurrence wins): a backend that ignores the
 * cursor repeats its first page, and a tool name served twice would register
 * one route twice and be written to the catalog twice.
 */
export function flattenToolPages<T extends { name: string }>(
  collected: CollectedToolPages<{ tools?: T[] }>,
): T[] {
  const tools = collected.pages.flatMap((page) => page.tools ?? []);
  if (!collected.stopped) return tools;
  const seen = new Set<string>();
  return tools.filter((tool) => {
    if (seen.has(tool.name)) return false;
    seen.add(tool.name);
    return true;
  });
}

/** One report per server and reason in this window; later ones are debug. */
export const TRUNCATION_REPORT_WINDOW_MS = 10 * 60 * 1000;

const lastReported = new Map<string, number>();

/** Test seam: forget every recorded report. */
export function resetToolsListTruncationReportsForTesting(): void {
  lastReported.clear();
}

const REASON_TEXT: Record<ToolsListStop, string> = {
  cursor_repeat: "the backend returned a cursor it had already been asked for",
  page_cap: `the ${TOOLS_LIST_MAX_PAGES}-page limit was reached`,
};

/**
 * Says that a listing was cut short. The first report per server and reason
 * in the window is a persisted gateway event (category `server`; the log
 * store also mirrors it to stdout as a WARN), so "was this truncated
 * yesterday too" is answerable. Later ones in the window are DEBUG, so a
 * backend that does this on every listing cannot flood the log.
 *
 * The text avoids the words the log-based dashboards count as failures: a
 * truncation is a handled outcome, not a gateway fault.
 */
export function reportToolsListTruncation(report: {
  serverName: string;
  serverUuid?: string;
  stopped: ToolsListStop;
  pages: number;
  /** Where the listing ran, for example "tool lookup". */
  scope: string;
}): void {
  const message = `Tool listing for server ${JSON.stringify(report.serverName)} (${report.scope}) stopped after ${report.pages} page(s): ${REASON_TEXT[report.stopped]}. Tools past that point are not listed.`;
  const key = `${report.serverUuid ?? report.serverName}|${report.stopped}`;
  const now = Date.now();
  const last = lastReported.get(key);
  if (last !== undefined && now - last < TRUNCATION_REPORT_WINDOW_MS) {
    logger.debug(message);
    return;
  }
  lastReported.set(key, now);
  metamcpLogStore.record({
    category: "server",
    serverName: report.serverName,
    serverUuid: report.serverUuid,
    level: "warn",
    message,
  });
}
