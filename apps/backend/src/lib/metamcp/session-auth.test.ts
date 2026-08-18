import { createHash, randomBytes } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  hashAuthPrincipal,
  identityMatches,
  principalMatches,
  resolveSessionIdentity,
} from "./session-auth";

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

describe("resolveSessionIdentity", () => {
  it("resolves an api-key request to its KEY uuid, not its owner", () => {
    expect(
      resolveSessionIdentity({
        authMethod: "api_key",
        apiKeyUuid: "key-uuid-1",
        oauthUserId: undefined,
      }),
    ).toEqual({ method: "api_key", credentialId: "key-uuid-1" });
  });

  it("resolves an OAuth request to its USER id, so a token refresh keeps the identity", () => {
    expect(
      resolveSessionIdentity({
        authMethod: "oauth",
        oauthUserId: "user-1",
      }),
    ).toEqual({ method: "oauth", credentialId: "user-1" });
  });

  it("resolves a request with no auth method to anonymous", () => {
    expect(resolveSessionIdentity({})).toEqual({
      method: "anonymous",
      credentialId: null,
    });
  });

  it("keeps the method but nulls the id when an authenticated request carries none", () => {
    expect(resolveSessionIdentity({ authMethod: "api_key" })).toEqual({
      method: "api_key",
      credentialId: null,
    });
  });
});

describe("identityMatches", () => {
  const keyA = { method: "api_key" as const, credentialId: "key-A" };

  it("matches the same api key", () => {
    expect(identityMatches(keyA, { ...keyA })).toBe(true);
  });

  it("rejects a different api key", () => {
    expect(
      identityMatches(keyA, { method: "api_key", credentialId: "key-B" }),
    ).toBe(false);
  });

  it("rejects a different auth method even when the ids are equal", () => {
    expect(
      identityMatches(keyA, { method: "oauth", credentialId: "key-A" }),
    ).toBe(false);
  });

  it("matches the same OAuth user across two different access tokens", () => {
    // The identity is the user id precisely so a 24h token refresh does not
    // force the connector to re-initialize its MCP session.
    const stored = { method: "oauth" as const, credentialId: "user-1" };
    expect(identityMatches(stored, { ...stored })).toBe(true);
  });

  it("rejects a different OAuth user", () => {
    expect(
      identityMatches(
        { method: "oauth", credentialId: "user-1" },
        { method: "oauth", credentialId: "user-2" },
      ),
    ).toBe(false);
  });

  it("treats a missing stored identity as belonging to nobody", () => {
    expect(identityMatches(undefined, keyA)).toBe(false);
  });

  it("never matches an authenticated identity with no id, in either direction", () => {
    const unnameable = { method: "api_key" as const, credentialId: null };
    expect(identityMatches(unnameable, unnameable)).toBe(false);
    expect(identityMatches(unnameable, keyA)).toBe(false);
    expect(identityMatches(keyA, unnameable)).toBe(false);
  });

  it("matches anonymous to anonymous — an endpoint published without auth has no credential to bind to", () => {
    const anon = { method: "anonymous" as const, credentialId: null };
    expect(identityMatches(anon, anon)).toBe(true);
  });

  it("never matches anonymous against an authenticated identity", () => {
    const anon = { method: "anonymous" as const, credentialId: null };
    expect(identityMatches(anon, keyA)).toBe(false);
    expect(identityMatches(keyA, anon)).toBe(false);
  });
});
