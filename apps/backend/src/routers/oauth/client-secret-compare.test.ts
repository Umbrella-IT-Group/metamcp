/**
 * `timingSafeEqualSecret` — the constant-time client-secret comparison the
 * token endpoint uses.
 *
 * The load-bearing property is that hashing both sides with SHA-256 first makes
 * every comparison a fixed 32-byte-vs-32-byte check, so `timingSafeEqual` never
 * sees buffers of unequal length (which would throw) and the compare time does
 * not depend on how many leading characters two secrets share. The equality
 * behaviour is asserted too, since a constant-time compare that got the answer
 * wrong would be worse than a fast one.
 */

import { describe, expect, it } from "vitest";

const { timingSafeEqualSecret } = await import("./utils");

describe("timingSafeEqualSecret", () => {
  it("returns true for identical secrets", () => {
    expect(
      timingSafeEqualSecret("mcp_secret_abc123", "mcp_secret_abc123"),
    ).toBe(true);
  });

  it("returns false for different secrets of the same length", () => {
    expect(
      timingSafeEqualSecret("mcp_secret_abc123", "mcp_secret_abc124"),
    ).toBe(false);
  });

  it("returns false (never throws) for different-length inputs", () => {
    // The reason for the SHA-256 step: a raw timingSafeEqual on these would
    // throw on the length mismatch.
    expect(timingSafeEqualSecret("short", "a-much-longer-secret")).toBe(false);
    expect(timingSafeEqualSecret("", "nonempty")).toBe(false);
  });

  it("returns false for a missing presented or stored value", () => {
    expect(timingSafeEqualSecret(undefined, "mcp_secret_abc123")).toBe(false);
    expect(timingSafeEqualSecret("mcp_secret_abc123", null)).toBe(false);
    expect(timingSafeEqualSecret(undefined, undefined)).toBe(false);
  });
});
