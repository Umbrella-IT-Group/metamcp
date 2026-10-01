import { describe, expect, it } from "vitest";

import {
  getRetiredToolInfo,
  isRetiredToolResult,
  markRetiredToolResult,
} from "./retired-tool-marker";

describe("retired-tool marker", () => {
  it("recognizes only the object that was registered", () => {
    const result = { isError: true, content: [] };
    expect(isRetiredToolResult(result)).toBe(false);

    const marked = markRetiredToolResult(result, { replacement: "a__b" });
    expect(marked).toBe(result);
    expect(isRetiredToolResult(result)).toBe(true);
    expect(getRetiredToolInfo(result)).toEqual({ replacement: "a__b" });
  });

  it("does not recognize a structurally identical copy", () => {
    const marked = markRetiredToolResult(
      { isError: true, content: [] },
      { replacement: null },
    );
    const copy = { ...marked };
    expect(isRetiredToolResult(copy)).toBe(false);
    expect(getRetiredToolInfo(copy)).toBeUndefined();
  });

  it("tolerates any non-object input", () => {
    for (const value of [undefined, null, "x", 5, true]) {
      expect(isRetiredToolResult(value)).toBe(false);
      expect(getRetiredToolInfo(value)).toBeUndefined();
    }
  });
});
