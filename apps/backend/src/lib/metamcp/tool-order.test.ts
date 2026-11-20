/**
 * The shared tool-listing order (issue #278). Oracle: UTF-16 code unit order,
 * which the language's default `sort()` implements, and literals.
 */
import { describe, expect, it } from "vitest";

import { compareToolNames, sortToolsByName } from "./tool-order";

const named = (...names: string[]) => names.map((name) => ({ name }));

describe("sortToolsByName", () => {
  it("orders by code unit, not by locale", () => {
    const sorted = sortToolsByName(named("s__é", "s__a", "s___x", "s__B"));
    expect(sorted.map((t) => t.name)).toEqual([
      "s__B",
      "s___x",
      "s__a",
      "s__é",
    ]);
  });

  it("returns a copy and leaves its input alone", () => {
    const input = named("b", "a");
    const sorted = sortToolsByName(input);
    expect(sorted).not.toBe(input);
    expect(input.map((t) => t.name)).toEqual(["b", "a"]);
  });

  it("keeps equal names in the order given (stable)", () => {
    const first = { name: "dup", tag: 1 };
    const second = { name: "dup", tag: 2 };
    const sorted = sortToolsByName([second, { name: "a" }, first].reverse());
    expect(sorted.filter((t) => t.name === "dup")).toEqual([first, second]);
  });

  it("compares equal names as 0", () => {
    expect(compareToolNames({ name: "a" }, { name: "a" })).toBe(0);
    expect(compareToolNames({ name: "a" }, { name: "b" })).toBeLessThan(0);
    expect(compareToolNames({ name: "b" }, { name: "a" })).toBeGreaterThan(0);
  });
});
