import { randomBytes } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  constantTimeEquals,
  decryptRefreshToken,
  encryptRefreshToken,
  envelopeKekId,
} from "./crypto";

const KEK = randomBytes(32);

describe("m365 refresh-token envelope crypto", () => {
  it("round-trips a refresh token", () => {
    const rt = "0.AXEAtoken-value_with.dots-and~chars";
    const envelope = encryptRefreshToken(rt, KEK, "k1");
    expect(envelope.startsWith("v1.k1.")).toBe(true);
    expect(envelope).not.toContain(rt);
    expect(decryptRefreshToken(envelope, KEK)).toBe(rt);
  });

  it("produces a unique envelope per encryption (fresh IV)", () => {
    const a = encryptRefreshToken("same-token", KEK, "k1");
    const b = encryptRefreshToken("same-token", KEK, "k1");
    expect(a).not.toBe(b);
    expect(decryptRefreshToken(a, KEK)).toBe("same-token");
    expect(decryptRefreshToken(b, KEK)).toBe("same-token");
  });

  it("rejects decryption under the wrong KEK", () => {
    const envelope = encryptRefreshToken("secret", KEK, "k1");
    expect(() => decryptRefreshToken(envelope, randomBytes(32))).toThrow();
  });

  it("rejects a tampered ciphertext segment", () => {
    const envelope = encryptRefreshToken("secret", KEK, "k1");
    const parts = envelope.split(".");
    const ct = Buffer.from(parts[4], "base64url");
    ct[0] ^= 0xff;
    parts[4] = ct.toString("base64url");
    expect(() => decryptRefreshToken(parts.join("."), KEK)).toThrow();
  });

  it("rejects a tampered kek_id header (AAD-bound)", () => {
    const envelope = encryptRefreshToken("secret", KEK, "k1");
    const parts = envelope.split(".");
    parts[1] = "k2";
    expect(() => decryptRefreshToken(parts.join("."), KEK)).toThrow();
  });

  it("rejects malformed envelopes", () => {
    expect(() => decryptRefreshToken("not-an-envelope", KEK)).toThrow();
    expect(() => decryptRefreshToken("v2.k1.a.b.c", KEK)).toThrow();
  });

  it("requires a 32-byte KEK and a dot-free kek_id", () => {
    expect(() => encryptRefreshToken("x", randomBytes(16), "k1")).toThrow();
    expect(() => encryptRefreshToken("x", KEK, "k.1")).toThrow();
  });

  it("exposes the envelope kek_id for rotation-aware lookup", () => {
    const envelope = encryptRefreshToken("x", KEK, "rotation-2027");
    expect(envelopeKekId(envelope)).toBe("rotation-2027");
  });

  it("compares strings in constant time semantics (equality + length)", () => {
    expect(constantTimeEquals("abc", "abc")).toBe(true);
    expect(constantTimeEquals("abc", "abd")).toBe(false);
    expect(constantTimeEquals("abc", "abcd")).toBe(false);
    expect(constantTimeEquals("", "")).toBe(true);
  });
});
