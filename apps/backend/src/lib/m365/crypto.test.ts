import { randomBytes } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  boundEnvelopeAad,
  constantTimeEquals,
  decryptRefreshToken,
  encryptRefreshToken,
  envelopeKekId,
  envelopeVersion,
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

/**
 * Envelope v2: the associated data binds the owning row's identity.
 *
 * Oracle for every "refused" case below: NIST SP 800-38D section 5.2.2
 * (authenticated decryption returns FAIL when the tag does not verify over the
 * ciphertext AND the associated data). A v2 envelope is authenticated against
 * its context, so any other context is a different associated data and must
 * fail.
 */
describe("m365 refresh-token envelope crypto, v2 (bound context)", () => {
  const CTX_A = "m365-refresh-token:user-A";
  const CTX_B = "m365-refresh-token:user-B";

  it("round-trips under its own context and carries the v2 label", () => {
    const envelope = encryptRefreshToken("rt-for-A", KEK, "k1", CTX_A);
    expect(envelope.startsWith("v2.k1.")).toBe(true);
    expect(envelope).not.toContain("rt-for-A");
    expect(decryptRefreshToken(envelope, KEK, CTX_A)).toBe("rt-for-A");
  });

  it("refuses an envelope presented under another user's context (a moved ciphertext)", () => {
    const envelope = encryptRefreshToken("rt-for-A", KEK, "k1", CTX_A);
    expect(() => decryptRefreshToken(envelope, KEK, CTX_B)).toThrow();
  });

  it("refuses a v2 envelope presented with no context, never falling back to the v1 associated data", () => {
    const envelope = encryptRefreshToken("rt-for-A", KEK, "k1", CTX_A);
    expect(() => decryptRefreshToken(envelope, KEK)).toThrow(/context/);
  });

  it("refuses a v2 envelope whose header is relabelled v1 (downgrade control)", () => {
    const envelope = encryptRefreshToken("rt-for-A", KEK, "k1", CTX_A);
    const parts = envelope.split(".");
    parts[0] = "v1";
    expect(() => decryptRefreshToken(parts.join("."), KEK)).toThrow();
    expect(() => decryptRefreshToken(parts.join("."), KEK, CTX_A)).toThrow();
  });

  it("refuses a v1 envelope whose header is relabelled v2", () => {
    const envelope = encryptRefreshToken("rt", KEK, "k1");
    const parts = envelope.split(".");
    parts[0] = "v2";
    expect(() => decryptRefreshToken(parts.join("."), KEK, CTX_A)).toThrow();
  });

  it("refuses a tampered kek_id on a v2 envelope (still AAD-bound)", () => {
    const envelope = encryptRefreshToken("rt", KEK, "k1", CTX_A);
    const parts = envelope.split(".");
    parts[1] = "k2";
    expect(() => decryptRefreshToken(parts.join("."), KEK, CTX_A)).toThrow();
  });

  it("never lets an invalid context fall back to v1 when encrypting", () => {
    expect(() => encryptRefreshToken("rt", KEK, "k1", "")).toThrow(/context/);
    expect(() => encryptRefreshToken("rt", KEK, "k1", "x".repeat(513))).toThrow(
      /context/,
    );
    // 512 UTF-8 bytes is the boundary, counted in bytes rather than characters.
    const edge = "x".repeat(512);
    expect(
      decryptRefreshToken(
        encryptRefreshToken("rt", KEK, "k1", edge),
        KEK,
        edge,
      ),
    ).toBe("rt");
    expect(() => encryptRefreshToken("rt", KEK, "k1", "é".repeat(257))).toThrow(
      /context/,
    );
  });

  it("refuses a v2 decrypt with an empty context", () => {
    const envelope = encryptRefreshToken("rt", KEK, "k1", CTX_A);
    expect(() => decryptRefreshToken(envelope, KEK, "")).toThrow(/context/);
  });

  it("ignores the context on a v1 envelope (dual-read)", () => {
    const envelope = encryptRefreshToken("legacy", KEK, "k1");
    expect(decryptRefreshToken(envelope, KEK, CTX_A)).toBe("legacy");
    expect(decryptRefreshToken(envelope, KEK)).toBe("legacy");
  });

  it("keeps refusing malformed envelopes of either version", () => {
    // `v2.k1.a.b.c` (existing test above) is refused because a v2 envelope
    // needs a context; these cases keep the "malformed is refused" intent.
    expect(() => decryptRefreshToken("v3.k1.a.b.c", KEK, CTX_A)).toThrow(
      /Unrecognized/,
    );
    expect(() => decryptRefreshToken("v2.k1.a.b.c", KEK, CTX_A)).toThrow(
      /iv\/tag length/,
    );
    expect(() => decryptRefreshToken("v2.k1.a.b", KEK, CTX_A)).toThrow(
      /Unrecognized/,
    );
  });

  it("freezes the v2 associated-data layout (4-byte big-endian length, then UTF-8, three fields)", () => {
    // Computed by hand from the layout, not by calling the code under test:
    //   00000002 7632                        "v2"
    //   00000002 6b31                        "k1"
    //   00000019 6d3336352d72656672657368... "m365-refresh-token:user-1" (25 bytes)
    expect(
      boundEnvelopeAad("k1", "m365-refresh-token:user-1").toString("hex"),
    ).toBe(
      "000000027632000000026b31000000196d3336352d726566726573682d746f6b656e3a757365722d31",
    );
  });

  it("makes the associated data injective across (kekId, context) pairs", () => {
    expect(
      boundEnvelopeAad("k1", "23").equals(boundEnvelopeAad("k12", "3")),
    ).toBe(false);
    expect(boundEnvelopeAad("k", "").equals(boundEnvelopeAad("", "k"))).toBe(
      false,
    );
  });

  it("reads the version and kek_id from both envelope versions and rejects others", () => {
    const v1 = encryptRefreshToken("x", KEK, "ka");
    const v2 = encryptRefreshToken("x", KEK, "kb", CTX_A);
    expect(envelopeVersion(v1)).toBe("v1");
    expect(envelopeVersion(v2)).toBe("v2");
    expect(envelopeKekId(v1)).toBe("ka");
    expect(envelopeKekId(v2)).toBe("kb");
    expect(() => envelopeVersion("v3.k1.a.b.c")).toThrow();
    expect(() => envelopeKekId("v3.k1.a.b.c")).toThrow();
    expect(() => envelopeVersion("v1.k1.a.b")).toThrow();
  });

  /**
   * Golden vectors. The v1 literal was written by the PRODUCTION code before
   * this change (commit d4c9fec: KEK = 32 bytes of 0x07, kek_id "k1", plaintext
   * "golden-rt-v1"), so it is bytes the deployed gateway has actually stored,
   * not output of the code under test: it proves dual-read keeps opening what
   * is already in the table. The v2 literal was written once by this change
   * (same KEK, plaintext "golden-rt-v2", context "m365-refresh-token:user-1")
   * and protects the on-disk contract for bound rows from here on.
   */
  const GOLDEN_KEK = Buffer.alloc(32, 0x07);
  const GOLDEN_V1 =
    "v1.k1.7Bw3pX9eYvhNBlyW.0zd0gfk7KXczFt0Ow6La_w.tpX97BDct2VMXh8M";
  const GOLDEN_V2 =
    "v2.k1.31dtWRG-HGxX4D6a.c5jIEIgwpsZd-jR_kNiM2A.VhlnO7VGtqsHtlPo";

  it("opens the golden v1 envelope with and without a context (dual-read)", () => {
    expect(decryptRefreshToken(GOLDEN_V1, GOLDEN_KEK)).toBe("golden-rt-v1");
    expect(decryptRefreshToken(GOLDEN_V1, GOLDEN_KEK, CTX_A)).toBe(
      "golden-rt-v1",
    );
  });

  it("opens the golden v2 envelope under its context only", () => {
    expect(
      decryptRefreshToken(GOLDEN_V2, GOLDEN_KEK, "m365-refresh-token:user-1"),
    ).toBe("golden-rt-v2");
    expect(() =>
      decryptRefreshToken(GOLDEN_V2, GOLDEN_KEK, "m365-refresh-token:user-2"),
    ).toThrow();
  });

  it("keeps secrets out of its error text", () => {
    const envelope = encryptRefreshToken("super-secret-rt", KEK, "k1", CTX_A);
    let message = "";
    try {
      decryptRefreshToken(envelope, KEK, CTX_B);
    } catch (error) {
      message = String((error as Error).message);
    }
    expect(message).not.toBe("");
    expect(message).not.toContain("super-secret-rt");
    expect(message).not.toContain(KEK.toString("hex"));
    expect(message).not.toContain(KEK.toString("base64"));
    expect(message).not.toContain(envelope);
    expect(message).not.toContain(CTX_A);
  });
});
