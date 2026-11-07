import { McpError } from "@modelcontextprotocol/sdk/types.js";
import { describe, expect, it } from "vitest";

import { describeListingFailure } from "./audit-listing-log";

// The words the log panels count as failures (whole word, any case).
const PANEL_WORDS = /\b(error|fatal|panic|exception)\b/i;

describe("describeListingFailure", () => {
  it("names the class and the message", () => {
    class PoolRefused extends Error {
      constructor(message: string) {
        super(message);
        this.name = "PoolRefused";
      }
    }
    expect(describeListingFailure(new PoolRefused("connection cap hit"))).toBe(
      "PoolRefused: connection cap hit",
    );
    expect(describeListingFailure(new TypeError("fetch refused"))).toBe(
      "TypeError: fetch refused",
    );
  });

  it("describes a rejection that is not an Error without reading its fields", () => {
    expect(describeListingFailure("plain string reason")).toBe(
      "string: plain string reason",
    );
    expect(describeListingFailure({ token: "hunter2", args: { q: 1 } })).toBe(
      "object",
    );
    expect(describeListingFailure(undefined)).toBe("undefined");
  });

  it("keeps the line clear of the words the panels count, whatever the text says", () => {
    const samples = [
      new Error("Error POSTing to endpoint (HTTP 404): Session not found"),
      new McpError(-32600, 'Fatal: {"error":{"code":-32600}} panic exception'),
      new Error("an EXCEPTION was thrown"),
    ];
    for (const sample of samples) {
      const text = describeListingFailure(sample);
      expect(text).not.toMatch(PANEL_WORDS);
    }
    // The cut is visible and keeps the rest of the message readable.
    expect(describeListingFailure(new Error("Error POSTing to endpoint"))).toBe(
      "Err*: Err* POSTing to endpoint",
    );
    // A name that merely contains one is not cut; the SDK's own prefix is.
    expect(
      describeListingFailure(new McpError(-32000, "Connection closed")),
    ).toBe("McpError: MCP err* -32000: Connection closed");
  });

  it("stays on one line, so a message cannot forge a log line", () => {
    const text = describeListingFailure(
      new Error("first\n[ERROR] 2026/11/07 - 07:00:00 | forged\r\nline"),
    );
    expect(text).not.toMatch(/[\r\n]/);
    expect(text).toContain("first [ERR*]");
  });

  it("holds the text to a bound and never leaves part of a credential behind the cut", () => {
    const long = describeListingFailure(new Error("x".repeat(5_000)));
    expect(long.length).toBeLessThanOrEqual(240 + "...".length);
    expect(long.endsWith("...")).toBe(true);

    // The cut would fall right after the password and before the "@" that
    // the userinfo scrub needs. Cutting first would leave the password in the
    // line; scrubbing first leaves none of it. ("Error: " is 7 characters.)
    const padded = `${"p".repeat(214)} http://svc:hunter2@backend.internal/mcp`;
    expect(`Error: ${padded}`.slice(0, 240).endsWith("hunter2")).toBe(true);
    const cut = describeListingFailure(new Error(padded));
    expect(cut).not.toContain("hunter2");
    expect(cut).toContain("[redacted]@");
  });

  it.each([
    [
      "userinfo in a URL",
      "connect to http://svc:hunter2@backend.internal:3000/mcp refused",
      ["hunter2", "svc:"],
    ],
    [
      "a key in a URL query string",
      "GET https://backend.internal/mcp?api_key=abc123key&x=1 timed out",
      ["abc123key", "x=1"],
    ],
    [
      "a bearer token",
      "upstream said Authorization: Bearer eyJhbGciOi.payload.sig",
      ["eyJhbGciOi"],
    ],
    [
      "a key=value pair",
      "retry with token=abc123def and password=hunter2",
      ["abc123def", "hunter2"],
    ],
    [
      "a JSON field",
      'body {"x-api-key": "k-9f8e7d", "secret":"s3cr3t"}',
      ["k-9f8e7d", "s3cr3t"],
    ],
  ])("scrubs %s", (_label, message, secrets) => {
    const text = describeListingFailure(new Error(message));
    for (const secret of secrets) expect(text).not.toContain(secret);
    expect(text).toContain("[redacted]");
  });

  it("returns a fixed string when reading the reason throws", () => {
    const hostile = new Error("fine");
    Object.defineProperty(hostile, "message", {
      get() {
        throw new Error("getter exploded");
      },
    });
    expect(() => describeListingFailure(hostile)).not.toThrow();
    expect(describeListingFailure(hostile)).toBe(
      "the reason could not be read",
    );
  });
});
