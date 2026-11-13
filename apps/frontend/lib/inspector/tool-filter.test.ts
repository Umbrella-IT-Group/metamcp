import { describe, expect, it } from "vitest";

import {
  filterToolEntries,
  filterTools,
  toolPrefix,
  toolPrefixCounts,
} from "./tool-filter";

// The prefix rule is the one in lib/tool-name-parser.ts: the first "__"
// separates the top-level server prefix from the forwarded tool name, and
// anything after it (including more "__") belongs to the tool name.
describe("toolPrefix", () => {
  it("is the text before the first double underscore", () => {
    expect(toolPrefix("Hacker-News__get_stories")).toBe("Hacker-News");
    expect(toolPrefix("Parent__Child__tool")).toBe("Parent");
    expect(toolPrefix("a_b__c")).toBe("a_b");
  });

  it("is null when there is no prefix", () => {
    expect(toolPrefix("plain_tool")).toBeNull();
    expect(toolPrefix("single_underscore")).toBeNull();
    expect(toolPrefix("__leading")).toBeNull();
    expect(toolPrefix("")).toBeNull();
  });
});

const tools = [
  { name: "Alpha__list_items", description: "List every item" },
  { name: "Alpha__delete_item", description: "Remove one item" },
  { name: "Beta__send_message", description: "Send a Message to a room" },
  { name: "Parent__Child__tool", description: undefined },
  { name: "plain_tool" },
  { name: "dotted.name", description: "has a dot" },
];

describe("toolPrefixCounts", () => {
  it("counts tools per prefix, sorted, with no-prefix last", () => {
    expect(toolPrefixCounts(tools)).toEqual([
      { prefix: "Alpha", count: 2 },
      { prefix: "Beta", count: 1 },
      { prefix: "Parent", count: 1 },
      { prefix: null, count: 2 },
    ]);
  });

  it("returns nothing for an empty list", () => {
    expect(toolPrefixCounts([])).toEqual([]);
  });

  it("sorts by code unit, not locale", () => {
    expect(
      toolPrefixCounts([
        { name: "b__x" },
        { name: "B__x" },
        { name: "a__x" },
      ]).map((entry) => entry.prefix),
    ).toEqual(["B", "a", "b"]);
  });
});

describe("filterTools", () => {
  const names = (list: { name: string }[]) => list.map((tool) => tool.name);

  it("returns every tool for an empty or blank query", () => {
    expect(filterTools(tools, { query: "" })).toHaveLength(tools.length);
    expect(filterTools(tools, { query: "   " })).toHaveLength(tools.length);
  });

  it("matches the name case-insensitively", () => {
    expect(names(filterTools(tools, { query: "SEND_MESSAGE" }))).toEqual([
      "Beta__send_message",
    ]);
  });

  it("matches the description case-insensitively", () => {
    expect(names(filterTools(tools, { query: "a message" }))).toEqual([
      "Beta__send_message",
    ]);
    expect(names(filterTools(tools, { query: "ITEM" }))).toEqual([
      "Alpha__list_items",
      "Alpha__delete_item",
    ]);
  });

  it("treats the query as plain text, not a pattern", () => {
    expect(names(filterTools(tools, { query: "." }))).toEqual(["dotted.name"]);
    expect(filterTools(tools, { query: ".*" })).toEqual([]);
  });

  it("copes with a tool that has no description", () => {
    expect(names(filterTools(tools, { query: "plain" }))).toEqual([
      "plain_tool",
    ]);
  });

  it("filters by prefix, and by no prefix", () => {
    expect(names(filterTools(tools, { query: "", prefix: "Alpha" }))).toEqual([
      "Alpha__list_items",
      "Alpha__delete_item",
    ]);
    expect(names(filterTools(tools, { query: "", prefix: null }))).toEqual([
      "plain_tool",
      "dotted.name",
    ]);
    expect(filterTools(tools, { query: "", prefix: undefined })).toHaveLength(
      tools.length,
    );
    expect(filterTools(tools, { query: "", prefix: "alpha" })).toEqual([]);
  });

  it("combines the prefix and the query", () => {
    expect(
      names(filterTools(tools, { query: "delete", prefix: "Alpha" })),
    ).toEqual(["Alpha__delete_item"]);
    expect(filterTools(tools, { query: "delete", prefix: "Beta" })).toEqual([]);
  });
});

describe("filterToolEntries", () => {
  it("keeps each tool's position in the full list", () => {
    expect(
      filterToolEntries(tools, { query: "item" }).map((entry) => entry.index),
    ).toEqual([0, 1]);
    expect(
      filterToolEntries(tools, { query: "send" }).map((entry) => entry.index),
    ).toEqual([2]);
  });
});
