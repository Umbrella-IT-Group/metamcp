/**
 * The shared category metadata behind both halves of the Live Logs page.
 *
 * The frontend test harness is `environment: "node"` with no DOM and no
 * component-testing library (see vitest.config.ts), so this covers the pure
 * module rather than the components — which is where the invariant that
 * matters lives anyway: the history filter must not offer a category the
 * history table can never contain.
 */

import { describe, expect, it } from "vitest";

import {
  CATEGORIES,
  categoryMeta,
  HISTORY_CATEGORIES,
  messageColor,
} from "./log-categories";

describe("HISTORY_CATEGORIES", () => {
  it("omits tool_call — those rows live in tool_call_audit, not gateway_events", () => {
    // Offering the filter would produce an always-empty page that reads as
    // "no tool calls happened".
    expect(HISTORY_CATEGORIES.map((c) => c.key)).not.toContain("tool_call");
  });

  it("keeps every other live category, so the two views stay in step", () => {
    expect(HISTORY_CATEGORIES.map((c) => c.key).sort()).toEqual([
      "client",
      "connection",
      "server",
      "system",
    ]);
    expect(HISTORY_CATEGORIES).toHaveLength(CATEGORIES.length - 1);
  });
});

describe("categoryMeta", () => {
  it("resolves a known category to its tag", () => {
    expect(categoryMeta("connection").tag).toBe("CONN");
  });

  it("degrades an unknown category to a neutral tag instead of throwing", () => {
    // The category column is text on purpose (a new event class must never make
    // an INSERT fail), so the renderer has to survive a value it predates.
    expect(categoryMeta("something_new")).toMatchObject({
      tag: "LOG",
      label: "something_new",
    });
  });
});

describe("messageColor", () => {
  it("colours by severity", () => {
    expect(messageColor("error")).toBe("text-red-300");
    expect(messageColor("warn")).toBe("text-amber-300");
    expect(messageColor("info")).toBe("text-gray-300");
  });

  it("treats a missing level as info", () => {
    // `gateway_events.level` is nullable, unlike the live entry's required
    // level, so the history view can hand this function null.
    expect(messageColor(null)).toBe("text-gray-300");
    expect(messageColor(undefined)).toBe("text-gray-300");
  });
});
