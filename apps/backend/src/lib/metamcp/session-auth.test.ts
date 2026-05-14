import { createHash, randomBytes } from "node:crypto";

import { describe, expect, it } from "vitest";

import { hashAuthPrincipal, principalMatches } from "./session-auth";

describe("hashAuthPrincipal", () => {
  it("returns a 64-char hex SHA-256 digest", () => {
    const out = hashAuthPrincipal("alpha-token", "api_key");
    expect(out).toMatch(/^[0-9a-f]{64}$/);
  });

  it("includes the method in the hash so same-token-different-method produces distinct principals", () => {
    const apiHash = hashAuthPrincipal("identical-token-value", "api_key");
    const oauthHash = hashAuthPrincipal("identical-token-value", "oauth");
    expect(apiHash).not.toEqual(oauthHash);
  });

  it("is deterministic — same inputs produce the same digest", () => {
    const a = hashAuthPrincipal("repeat-token", "api_key");
    const b = hashAuthPrincipal("repeat-token", "api_key");
    expect(a).toEqual(b);
  });

  it("matches a manual SHA-256(method + ':' + token) reference", () => {
    const token = "sample-token";
    const method = "oauth" as const;
    const reference = createHash("sha256")
      .update(`${method}:${token}`, "utf8")
      .digest("hex");
    expect(hashAuthPrincipal(token, method)).toEqual(reference);
  });
});

describe("principalMatches", () => {
  it("returns true for equal hex digests", () => {
    const hash = hashAuthPrincipal("match-token", "api_key");
    expect(principalMatches(hash, hash)).toBe(true);
  });

  it("returns false for distinct digests", () => {
    const a = hashAuthPrincipal("token-a", "api_key");
    const b = hashAuthPrincipal("token-b", "api_key");
    expect(principalMatches(a, b)).toBe(false);
  });

  it("returns false for empty inputs", () => {
    expect(principalMatches("", "")).toBe(false);
    expect(principalMatches("abc", "")).toBe(false);
    expect(principalMatches("", "abc")).toBe(false);
  });

  it("returns false when lengths differ even if prefix matches", () => {
    const hash = hashAuthPrincipal("token", "api_key");
    expect(principalMatches(hash, hash + "00")).toBe(false);
    expect(principalMatches(hash + "00", hash)).toBe(false);
  });

  it("returns false for non-hex garbage", () => {
    const hash = hashAuthPrincipal("token", "api_key");
    // Same length as the hash but contains 'g' (non-hex char). Buffer.from(..., 'hex')
    // silently truncates at the first non-hex char; the resulting buffer is
    // a different length, so the compare bails.
    const garbage = "g".repeat(hash.length);
    expect(principalMatches(garbage, hash)).toBe(false);
  });

  it("does not throw on long random non-matching inputs", () => {
    const a = randomBytes(32).toString("hex");
    const b = randomBytes(32).toString("hex");
    // Astronomically unlikely to collide, but the assertion is "doesn't throw"
    // and "returns a boolean".
    const result = principalMatches(a, b);
    expect(typeof result).toBe("boolean");
  });
});
