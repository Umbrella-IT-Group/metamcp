import { describe, expect, it } from "vitest";

import { pluralize } from "./pluralize";

describe("pluralize", () => {
  it("returns the singular form for a count of one", () => {
    expect(pluralize(1, "session", "sessions")).toBe("session");
  });

  it("returns the plural form for zero", () => {
    // Zero takes the plural in English ("0 sessions"), which is the whole
    // reason the bug read "1 sessions" but "0 sessions" looked fine.
    expect(pluralize(0, "session", "sessions")).toBe("sessions");
  });

  it("returns the plural form for counts above one", () => {
    expect(pluralize(2, "session", "sessions")).toBe("sessions");
    expect(pluralize(11, "key", "keys")).toBe("keys");
  });

  it("derives a regular +s plural when none is given", () => {
    expect(pluralize(3, "server")).toBe("servers");
    expect(pluralize(1, "server")).toBe("server");
  });

  it("uses the explicit plural even when it is irregular", () => {
    expect(pluralize(2, "entry", "entries")).toBe("entries");
  });

  it("returns the provided word unchanged for non-inflecting locales", () => {
    // zh/ko carry the same string for both forms; the helper must not append
    // anything, so both branches return that word as-is.
    expect(pluralize(1, "会话", "会话")).toBe("会话");
    expect(pluralize(5, "会话", "会话")).toBe("会话");
  });
});
