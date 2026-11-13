/**
 * The shared tools/list pagination guard. Oracle: the MCP spec's
 * server/utilities/pagination page (cursors are opaque, a missing nextCursor
 * ends the listing) and, for the stop rules, the periodic sweep's existing
 * tests in mcp-server-pool.test.ts: two requests for a constant cursor, fifty
 * for an endless run of fresh cursors.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  collectToolsListPages,
  flattenToolPages,
  reportToolsListTruncation,
  resetToolsListTruncationReportsForTesting,
  TOOLS_LIST_MAX_PAGES,
  TRUNCATION_REPORT_WINDOW_MS,
} from "./paginate-tools-list";

const { record, debug } = vi.hoisted(() => ({
  record: vi.fn(),
  debug: vi.fn(),
}));

vi.mock("@/utils/logger", () => ({
  default: { error: vi.fn(), warn: vi.fn(), info: vi.fn(), debug },
}));
vi.mock("./log-store", () => ({ metamcpLogStore: { record } }));

type Page = { tools?: Array<{ name: string }>; nextCursor?: string };

/** A backend that serves `script[cursor ?? ""]`, counting requests. */
function backend(script: Record<string, Page>) {
  const requested: Array<string | undefined> = [];
  const fetchPage = async (cursor: string | undefined) => {
    requested.push(cursor);
    // Tripwire: after 200 requests the listing simply ends, so an unguarded
    // loop finishes and fails the request-count assertions instead of hanging.
    if (requested.length > 200) return { tools: [] };
    return script[cursor ?? ""];
  };
  return { fetchPage, requested };
}

describe("collectToolsListPages", () => {
  it("follows cursors across pages until nextCursor is absent", async () => {
    const { fetchPage, requested } = backend({
      "": { tools: [{ name: "a" }], nextCursor: "p2" },
      p2: { tools: [{ name: "b" }], nextCursor: "p3" },
      p3: { tools: [{ name: "c" }] },
    });

    const result = await collectToolsListPages(fetchPage);

    expect(requested).toEqual([undefined, "p2", "p3"]);
    expect(result.stopped).toBeUndefined();
    expect(flattenToolPages(result).map((t) => t.name)).toEqual([
      "a",
      "b",
      "c",
    ]);
  });

  it("stops on a cycle, keeps the page that repeated the cursor, and says why", async () => {
    const { fetchPage, requested } = backend({
      "": { tools: [{ name: "a" }], nextCursor: "A" },
      A: { tools: [{ name: "b" }], nextCursor: "B" },
      B: { tools: [{ name: "c" }], nextCursor: "A" },
    });

    const result = await collectToolsListPages(fetchPage);

    expect(requested).toEqual([undefined, "A", "B"]);
    expect(result.stopped).toBe("cursor_repeat");
    expect(result.pages).toHaveLength(3);
  });

  it("stops after two requests when the backend returns a constant cursor", async () => {
    const { fetchPage, requested } = backend({
      "": { tools: [{ name: "a" }], nextCursor: "same" },
      same: { tools: [{ name: "a" }], nextCursor: "same" },
    });

    const result = await collectToolsListPages(fetchPage);

    expect(requested).toHaveLength(2);
    expect(result.stopped).toBe("cursor_repeat");
  });

  it("caps an endless run of fresh cursors at the page limit", async () => {
    let n = 0;
    const requested: Array<string | undefined> = [];
    const result = await collectToolsListPages(async (cursor) => {
      requested.push(cursor);
      n += 1;
      // Tripwire: an unguarded loop ends here and fails the count assertion.
      if (n > 200) return { tools: [] };
      return { tools: [], nextCursor: `page-${n}` };
    });

    expect(requested).toHaveLength(TOOLS_LIST_MAX_PAGES);
    expect(result.stopped).toBe("page_cap");
  });

  it("reports no truncation for a listing of exactly the cap that ends on its own", async () => {
    let n = 0;
    const result = await collectToolsListPages(async () => {
      n += 1;
      return n < TOOLS_LIST_MAX_PAGES
        ? { tools: [], nextCursor: `page-${n}` }
        : { tools: [] };
    });

    expect(result.pages).toHaveLength(TOOLS_LIST_MAX_PAGES);
    expect(result.stopped).toBeUndefined();
  });

  it("follows an empty-string cursor because cursors are opaque", async () => {
    const requested: Array<string | undefined> = [];
    const result = await collectToolsListPages(async (cursor) => {
      requested.push(cursor);
      return cursor === undefined
        ? { tools: [{ name: "a" }], nextCursor: "" }
        : { tools: [{ name: "b" }] };
    });

    expect(requested).toEqual([undefined, ""]);
    expect(flattenToolPages(result).map((tool) => tool.name)).toEqual([
      "a",
      "b",
    ]);
    expect(result.stopped).toBeUndefined();
  });

  it("reports a repeated empty-string cursor as truncation", async () => {
    const { fetchPage, requested } = backend({
      "": { tools: [{ name: "a" }], nextCursor: "" },
    });

    const result = await collectToolsListPages(fetchPage);

    expect(requested).toEqual([undefined, ""]);
    expect(result.stopped).toBe("cursor_repeat");
  });
});

describe("flattenToolPages", () => {
  it("de-duplicates by name only when the listing was stopped (first wins)", () => {
    const pages: Page[] = [
      { tools: [{ name: "a" }, { name: "b" }] },
      { tools: [{ name: "a" }, { name: "c" }] },
    ];

    expect(
      flattenToolPages({ pages, stopped: "cursor_repeat" }).map((t) => t.name),
    ).toEqual(["a", "b", "c"]);
    // A listing that ended on its own is a plain flatten, untouched.
    expect(flattenToolPages({ pages }).map((t) => t.name)).toEqual([
      "a",
      "b",
      "a",
      "c",
    ]);
  });
});

describe("reportToolsListTruncation", () => {
  const report = {
    serverName: "ninja",
    serverUuid: "uuid-1",
    stopped: "cursor_repeat" as const,
    pages: 3,
    scope: "tool lookup",
  };

  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-01-01T00:00:00Z"));
    record.mockClear();
    debug.mockClear();
    resetToolsListTruncationReportsForTesting();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it("records one persisted server event, then only debug inside the window, then again after it", () => {
    reportToolsListTruncation(report);
    reportToolsListTruncation(report);
    reportToolsListTruncation({ ...report, pages: 4 });

    expect(record).toHaveBeenCalledTimes(1);
    expect(debug).toHaveBeenCalledTimes(2);
    const event = record.mock.calls[0][0];
    expect(event).toMatchObject({
      category: "server",
      level: "warn",
      serverName: "ninja",
      serverUuid: "uuid-1",
    });
    expect(event.message).toContain("3 page(s)");
    expect(event.message).not.toMatch(/\b(error|fatal|panic|exception)\b/i);

    vi.setSystemTime(Date.now() + TRUNCATION_REPORT_WINDOW_MS + 1);
    reportToolsListTruncation(report);
    expect(record).toHaveBeenCalledTimes(2);
  });

  it("dedupes per server and per reason", () => {
    reportToolsListTruncation(report);
    reportToolsListTruncation({ ...report, serverUuid: "uuid-2" });
    reportToolsListTruncation({ ...report, stopped: "page_cap" });

    expect(record).toHaveBeenCalledTimes(3);
  });
});
