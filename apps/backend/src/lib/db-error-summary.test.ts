import { DrizzleQueryError } from "drizzle-orm/errors";
import { describe, expect, it } from "vitest";

import { describeDbError } from "./db-error-summary";

const SECRET = "Private administrator prose";

describe("database error summary", () => {
  it("does not trust a wrapper message that copies a query error", () => {
    const cause = Object.assign(new Error(SECRET), {
      code: "23514",
      constraint: "presentation_check",
    });
    const queryError = new DrizzleQueryError(
      "insert into endpoint_presentation (instructions) values ($1)",
      [SECRET],
      cause,
    );
    const wrapped = new Error(`write failed: ${queryError.message}`, {
      cause: queryError,
    });

    const summary = describeDbError(wrapped);
    expect(summary).not.toContain(SECRET);
    expect(summary).not.toContain("insert into");
    expect(summary).toContain("DrizzleQueryError");
    expect(summary).toContain("code=23514");
    expect(summary).toContain("constraint=presentation_check");
  });

  it("drops unknown messages even when no query marker is present", () => {
    expect(describeDbError(new Error(SECRET))).not.toContain(SECRET);
  });

  it.each([
    "timeout exceeded when trying to connect",
    "Connection terminated unexpectedly",
    "Query read timeout",
  ])("preserves the fixed driver diagnostic %s", (message) => {
    expect(describeDbError(new Error(message))).toContain(message);
    expect(describeDbError(new Error(`${message}: ${SECRET}`))).not.toContain(
      SECRET,
    );
  });

  it.each(["cause", "message", "constructor", "code"])(
    "does not let a throwing %s getter break failure reporting",
    (key) => {
      const error = Object.defineProperty(new Error(), key, {
        get() {
          throw new Error(SECRET);
        },
      });
      expect(() => describeDbError(error)).not.toThrow();
      expect(describeDbError(error)).not.toContain(SECRET);
      expect(describeDbError(error)).toContain("summary unavailable");
    },
  );
});
