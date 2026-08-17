/**
 * The bounds that keep one event from costing the archive more than it is
 * worth, and one filter from costing the database more than it is worth.
 *
 * `escapeLikePattern` is the one with a correctness consequence rather than
 * only a cost one: an unescaped `%` silently turns a substring filter into a
 * prefix match, so the history view answers a question the operator did not
 * ask. On an investigation surface a wrong answer beats no answer only in the
 * sense that it is worse.
 */

import { describe, expect, it } from "vitest";

import {
  clampGatewayMetadata,
  clampGatewayText,
  clampSearchText,
  escapeLikePattern,
  GATEWAY_EVENT_METADATA_MAX_CHARS,
  GATEWAY_EVENT_SEARCH_MAX,
  GATEWAY_EVENT_TEXT_MAX,
} from "./bounds";

describe("clampGatewayText", () => {
  it("keeps a normal value whole", () => {
    expect(clampGatewayText("example-backend")).toBe("example-backend");
  });

  it("truncates past the bound", () => {
    expect(clampGatewayText("x".repeat(1000))).toHaveLength(
      GATEWAY_EVENT_TEXT_MAX,
    );
  });

  it("degrades absent and empty values to null", () => {
    expect(clampGatewayText(undefined)).toBeNull();
    expect(clampGatewayText(null)).toBeNull();
    // An empty string in a nullable column reads as "we recorded an empty
    // name", which is a different (and false) claim from "there was no name".
    expect(clampGatewayText("")).toBeNull();
  });
});

describe("clampGatewayMetadata", () => {
  it("returns null for absent metadata", () => {
    expect(clampGatewayMetadata(undefined)).toBeNull();
    expect(clampGatewayMetadata(null)).toBeNull();
  });

  it("keeps a small object", () => {
    expect(clampGatewayMetadata({ error: "socket hang up" })).toEqual({
      error: "socket hang up",
    });
  });

  it("drops an oversized object entirely rather than truncating it", () => {
    const oversized = {
      error: "x".repeat(GATEWAY_EVENT_METADATA_MAX_CHARS + 1),
    };
    // Half a JSON document is not a JSON document, and a row whose metadata
    // cannot be parsed is worse than a row with none.
    expect(clampGatewayMetadata(oversized)).toBeNull();
  });

  it("drops an unserializable object rather than throwing", () => {
    const circular: Record<string, unknown> = {};
    circular.self = circular;
    expect(clampGatewayMetadata(circular)).toBeNull();
  });
});

describe("escapeLikePattern", () => {
  it("neutralises the wildcards so a substring stays a substring", () => {
    expect(escapeLikePattern("100%")).toBe("100\\%");
    expect(escapeLikePattern("a_b")).toBe("a\\_b");
  });

  it("escapes the escape character first, so it cannot double-escape", () => {
    // `\%` must become `\\\%` — a literal backslash followed by a literal
    // percent. Escaping `%` first would produce `\\%`, which is a literal
    // backslash followed by a WILDCARD.
    expect(escapeLikePattern("\\%")).toBe("\\\\\\%");
  });

  it("leaves ordinary text untouched", () => {
    expect(escapeLikePattern("Transport closed unexpectedly")).toBe(
      "Transport closed unexpectedly",
    );
  });
});

describe("clampSearchText", () => {
  it("bounds a pasted filter instead of rejecting it", () => {
    expect(clampSearchText("q".repeat(1000))).toHaveLength(
      GATEWAY_EVENT_SEARCH_MAX,
    );
  });
});
