/**
 * Tests for the OAuth helper rules that are security-relevant on their own.
 *
 * `resolveGrantedScope` is the whole scope decision `/oauth/authorize` makes.
 * It used to be the inline expression `scope ? scope : "admin"`, which meant a
 * request that named no scope was recorded as an admin grant — on the very
 * path a self-registered client reaches once its user logs in. The rule lives
 * here, outside the express handler, so it can be driven without a server, a
 * database, or a better-auth session.
 */

import { describe, expect, it } from "vitest";

import { resolveGrantedScope } from "./utils";

describe("resolveGrantedScope", () => {
  it("NEVER invents the admin scope for a request that names none", () => {
    // The regression this file exists for.
    expect(resolveGrantedScope(undefined, null)).not.toBe("admin");
    expect(resolveGrantedScope(undefined, null)).toBe("");
  });

  it("honours an explicitly requested scope", () => {
    expect(resolveGrantedScope("mcp:read", null)).toBe("mcp:read");
  });

  it("prefers the requested scope over the registered one", () => {
    expect(resolveGrantedScope("mcp:read", "mcp:write")).toBe("mcp:read");
  });

  it("falls back to the scope registered for the client (RFC 6749 §3.3)", () => {
    expect(resolveGrantedScope(undefined, "mcp:read")).toBe("mcp:read");
  });

  it("treats a blank requested scope as absent", () => {
    expect(resolveGrantedScope("   ", "mcp:read")).toBe("mcp:read");
    expect(resolveGrantedScope("", null)).toBe("");
  });

  it("ignores a non-string requested scope rather than coercing it", () => {
    // req.query values are `unknown` — a repeated ?scope= gives an array, and
    // a crafted query can give an object. Neither may become a scope string.
    expect(resolveGrantedScope(["admin"], null)).toBe("");
    expect(resolveGrantedScope({ admin: true }, "mcp:read")).toBe("mcp:read");
  });

  it("returns a string for a client whose registered scope is NULL", () => {
    // oauth_authorization_codes.scope / oauth_access_tokens.scope are NOT
    // NULL, so a null registered scope must land as "" and not as null.
    expect(resolveGrantedScope(undefined, undefined)).toBe("");
  });
});
