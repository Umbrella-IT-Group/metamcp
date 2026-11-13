import { describe, expect, it } from "vitest";

import { collectAllPages, MAX_LIST_PAGES, type Page } from "./paginate-list";

// MCP specification, server/utilities/pagination: the cursor is an opaque
// token, a response without nextCursor ends the list, and a client "MUST NOT"
// assume anything about its form. A server that keeps returning a cursor it
// already returned would otherwise hold the caller in a loop forever, so the
// walk stops on a repeated cursor and on a page cap.

// A fake list endpoint. It records the cursor of every request and throws once
// a runaway walk has made far more requests than any test below needs, so a
// loop with no guard fails here instead of hanging the run.
function fakeList(
  next: (cursor: string | undefined, call: number) => Page<number>,
) {
  const requested: (string | undefined)[] = [];
  const fetchPage = async (cursor: string | undefined) => {
    requested.push(cursor);
    if (requested.length > 200) {
      throw new Error("runaway pagination: more than 200 requests");
    }
    return next(cursor, requested.length);
  };
  return { fetchPage, requested };
}

describe("collectAllPages", () => {
  it("follows cursors to the end and keeps the order", async () => {
    const pages: Record<string, Page<number>> = {
      start: { items: [1, 2], nextCursor: "a" },
      a: { items: [3], nextCursor: "b" },
      b: { items: [4, 5] },
    };
    const list = fakeList((cursor) => pages[cursor ?? "start"]!);
    const result = await collectAllPages(list.fetchPage);
    expect(result).toEqual({
      items: [1, 2, 3, 4, 5],
      pages: 3,
      truncated: null,
    });
    expect(list.requested).toEqual([undefined, "a", "b"]);
  });

  it("returns one page when there is no cursor", async () => {
    const list = fakeList(() => ({ items: [9] }));
    expect(await collectAllPages(list.fetchPage)).toEqual({
      items: [9],
      pages: 1,
      truncated: null,
    });
  });

  it("ends the list on a null or empty cursor", async () => {
    for (const nextCursor of [null, ""]) {
      const list = fakeList(() => ({ items: [1], nextCursor }));
      const result = await collectAllPages(list.fetchPage);
      expect(result.pages).toBe(1);
      expect(result.truncated).toBeNull();
    }
  });

  it("stops when the server returns the cursor it was just asked with", async () => {
    const list = fakeList((cursor) => ({
      items: [cursor === undefined ? 1 : 2],
      nextCursor: "x",
    }));
    const result = await collectAllPages(list.fetchPage);
    expect(result).toEqual({
      items: [1, 2],
      pages: 2,
      truncated: "repeated_cursor",
    });
    expect(list.requested).toEqual([undefined, "x"]);
  });

  it("stops when a cursor comes round again", async () => {
    const ring: Record<string, string> = { start: "a", a: "b", b: "a" };
    const list = fakeList((cursor) => ({
      items: [list.requested.length],
      nextCursor: ring[cursor ?? "start"],
    }));
    const result = await collectAllPages(list.fetchPage);
    expect(result.truncated).toBe("repeated_cursor");
    expect(result.pages).toBe(3);
    expect(list.requested).toEqual([undefined, "a", "b"]);
  });

  it("stops at the page cap when every cursor is new", async () => {
    const list = fakeList((_cursor, call) => ({
      items: [call],
      nextCursor: `c${call}`,
    }));
    const result = await collectAllPages(list.fetchPage);
    expect(result.truncated).toBe("page_cap");
    expect(result.pages).toBe(MAX_LIST_PAGES);
    expect(list.requested).toHaveLength(MAX_LIST_PAGES);
    expect(result.items).toHaveLength(MAX_LIST_PAGES);
  });

  it("honours a smaller cap", async () => {
    const list = fakeList((_cursor, call) => ({
      items: [call],
      nextCursor: `c${call}`,
    }));
    const result = await collectAllPages(list.fetchPage, { maxPages: 3 });
    expect(result).toEqual({
      items: [1, 2, 3],
      pages: 3,
      truncated: "page_cap",
    });
  });

  it("does not call a list that ends on the last allowed page truncated", async () => {
    const list = fakeList((_cursor, call) =>
      call < MAX_LIST_PAGES
        ? { items: [call], nextCursor: `c${call}` }
        : { items: [call] },
    );
    const result = await collectAllPages(list.fetchPage);
    expect(result.truncated).toBeNull();
    expect(result.pages).toBe(MAX_LIST_PAGES);
  });

  it("lets a failed page fail the whole walk", async () => {
    const list = fakeList((_cursor, call) => {
      if (call === 2) throw new Error("backend unavailable");
      return { items: [call], nextCursor: "next" };
    });
    await expect(collectAllPages(list.fetchPage)).rejects.toThrow(
      "backend unavailable",
    );
  });
});
