import { describe, expect, it } from "vitest";

import { toolsPanelView } from "./tools-panel-view";

// Defect: a failed connect left the tools panel on its loading placeholder.
describe("the server page's tools panel", () => {
  it.each(["error", "error-connecting-to-proxy"] as const)(
    "leaves the loading placeholder for an error when the connect ends in %s",
    (status) => {
      expect(toolsPanelView(false, status)).toBe("connection-error");
    },
  );

  it("keeps the loading placeholder while a connect is under way or not started", () => {
    expect(toolsPanelView(false, "connecting")).toBe("connecting");
    expect(toolsPanelView(false, "disconnected")).toBe("idle");
  });
});
