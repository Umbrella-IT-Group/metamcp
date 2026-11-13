/**
 * The M365 envelope policy: which version is written, whether v1 is still
 * accepted, and the row-bound seal/open/rewrap helpers. Real crypto throughout,
 * so a moved ciphertext is refused by AES-GCM itself, not by a stub.
 *
 * Oracle for the policy table: the operator rule that ONLY an explicit
 * `M365_ENVELOPE_WRITE_VERSION=1` ever lowers a row's version (a typo or a
 * dropped variable must never strip a binding), and that an unrecognised
 * `M365_ENVELOPE_STRICT` value fails CLOSED (strict, with an ERROR line) rather
 * than quietly leaving the downgrade path open.
 */
import { randomBytes } from "node:crypto";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const loggerMock = vi.hoisted(() => ({
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
  debug: vi.fn(),
}));
vi.mock("@/utils/logger", () => ({ default: loggerMock }));

// A switch that makes the crypto primitive write a BAD seal, to prove the
// rewrap's round-trip check is what stands between a bad seal and a write:
//  - tamper: a flipped ciphertext byte (fails authentication);
//  - unbound: a valid envelope at the wrong version (the context is dropped);
//  - other-plaintext: a valid envelope that holds a different token.
const corrupt = vi.hoisted(() => ({
  mode: "off" as "off" | "tamper" | "unbound" | "other-plaintext",
}));
vi.mock("./crypto", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./crypto")>();
  return {
    ...actual,
    encryptRefreshToken: (
      plaintext: string,
      kek: Buffer,
      kekId: string,
      context?: string,
    ) => {
      if (corrupt.mode === "unbound") {
        return actual.encryptRefreshToken(plaintext, kek, kekId);
      }
      if (corrupt.mode === "other-plaintext") {
        return actual.encryptRefreshToken("not-the-token", kek, kekId, context);
      }
      const envelope = actual.encryptRefreshToken(
        plaintext,
        kek,
        kekId,
        context,
      );
      if (corrupt.mode !== "tamper") return envelope;
      const parts = envelope.split(".");
      const ct = Buffer.from(parts[4], "base64url");
      ct[0] ^= 0xff;
      parts[4] = ct.toString("base64url");
      return parts.join(".");
    },
  };
});

import { decryptRefreshToken, encryptRefreshToken } from "./crypto";
import {
  __resetEnvelopePolicyLogsForTesting,
  describeEnvelopePolicy,
  effectiveWriteVersion,
  openUserRefreshToken,
  peekEnvelopeVersion,
  refreshTokenContext,
  resolveEnvelopePolicy,
  rewrapUserEnvelope,
  sealUserRefreshToken,
  sealUserRefreshTokenAt,
} from "./envelope";

const KEK = randomBytes(32);

function policyFrom(env: Record<string, string | undefined>) {
  return resolveEnvelopePolicy(env as NodeJS.ProcessEnv);
}

beforeEach(() => {
  __resetEnvelopePolicyLogsForTesting();
  corrupt.mode = "off";
});
afterEach(() => {
  vi.unstubAllEnvs();
  vi.clearAllMocks();
});

describe("resolveEnvelopePolicy", () => {
  it.each([
    ["unset", undefined],
    ["empty", ""],
  ])("keeps each row's version when the write version is %s", (_l, value) => {
    expect(policyFrom({ M365_ENVELOPE_WRITE_VERSION: value })).toEqual({
      mode: "keep",
      strict: false,
    });
    expect(loggerMock.warn).not.toHaveBeenCalled();
  });

  it("writes v1 only for an explicit 1 and v2 only for an explicit 2", () => {
    expect(policyFrom({ M365_ENVELOPE_WRITE_VERSION: "1" }).mode).toBe("v1");
    expect(policyFrom({ M365_ENVELOPE_WRITE_VERSION: "2" }).mode).toBe("v2");
  });

  it.each(["v2", "2 ", "3", "true", "0", "02"])(
    "keeps (never lowers) and warns for the unrecognised write version %j",
    (value) => {
      expect(policyFrom({ M365_ENVELOPE_WRITE_VERSION: value }).mode).toBe(
        "keep",
      );
      expect(loggerMock.warn).toHaveBeenCalledTimes(1);
      expect(String(loggerMock.warn.mock.calls[0][0])).toContain(
        "M365_ENVELOPE_WRITE_VERSION",
      );
    },
  );

  it("logs each distinct warning once per process", () => {
    policyFrom({ M365_ENVELOPE_WRITE_VERSION: "v2" });
    policyFrom({ M365_ENVELOPE_WRITE_VERSION: "v2" });
    expect(loggerMock.warn).toHaveBeenCalledTimes(1);
  });

  it.each([
    ["unset", undefined],
    ["empty", ""],
    ["0", "0"],
  ])("strict is off when the flag is %s", (_l, value) => {
    expect(policyFrom({ M365_ENVELOPE_STRICT: value }).strict).toBe(false);
    expect(loggerMock.error).not.toHaveBeenCalled();
  });

  it("strict is on for 1, and forces v2 writes", () => {
    expect(policyFrom({ M365_ENVELOPE_STRICT: "1" })).toEqual({
      mode: "v2",
      strict: true,
    });
    expect(loggerMock.error).not.toHaveBeenCalled();
  });

  it.each(["true", "yes", "on", "2", " 1", "TRUE", "enabled"])(
    "resolves the unrecognised strict value %j to STRICT with an ERROR line (fails closed)",
    (value) => {
      const policy = policyFrom({ M365_ENVELOPE_STRICT: value });
      expect(policy).toEqual({ mode: "v2", strict: true });
      expect(loggerMock.error).toHaveBeenCalledTimes(1);
      expect(String(loggerMock.error.mock.calls[0][0])).toContain(
        "M365_ENVELOPE_STRICT",
      );
      expect(String(loggerMock.error.mock.calls[0][0])).toContain("STRICT");
    },
  );

  it("quotes and bounds an operator-supplied value in its log line", () => {
    policyFrom({ M365_ENVELOPE_STRICT: `${"x".repeat(100)}\nforged` });
    const line = String(loggerMock.error.mock.calls[0][0]);
    expect(line).not.toContain("\n");
    expect(line).not.toContain("forged");
  });

  it("strict wins over an explicit write version of 1, with a warning", () => {
    expect(
      policyFrom({
        M365_ENVELOPE_STRICT: "1",
        M365_ENVELOPE_WRITE_VERSION: "1",
      }),
    ).toEqual({ mode: "v2", strict: true });
    expect(loggerMock.warn).toHaveBeenCalledTimes(1);
  });

  it("prints strict=on|off and the effective write version", () => {
    expect(describeEnvelopePolicy(policyFrom({}))).toBe(
      "mode=keep strict=off write_version=v1",
    );
    expect(
      describeEnvelopePolicy(policyFrom({ M365_ENVELOPE_WRITE_VERSION: "2" })),
    ).toBe("mode=v2 strict=off write_version=v2");
    expect(
      describeEnvelopePolicy(policyFrom({ M365_ENVELOPE_STRICT: "1" })),
    ).toBe("mode=v2 strict=on write_version=v2");
    expect(effectiveWriteVersion({ mode: "v1", strict: false })).toBe("v1");
  });

  it("reads process.env per call by default", () => {
    vi.stubEnv("M365_ENVELOPE_WRITE_VERSION", "2");
    expect(resolveEnvelopePolicy().mode).toBe("v2");
    vi.stubEnv("M365_ENVELOPE_WRITE_VERSION", "");
    expect(resolveEnvelopePolicy().mode).toBe("keep");
  });
});

describe("peekEnvelopeVersion", () => {
  it("reads both versions and never throws on garbage", () => {
    expect(peekEnvelopeVersion(encryptRefreshToken("x", KEK, "k1"))).toBe("v1");
    expect(peekEnvelopeVersion(encryptRefreshToken("x", KEK, "k1", "c"))).toBe(
      "v2",
    );
    for (const garbage of [
      "",
      "nope",
      "v3.a.b.c.d",
      "v1.a.b.c",
      null,
      undefined,
    ]) {
      expect(peekEnvelopeVersion(garbage)).toBeNull();
    }
  });
});

describe("sealUserRefreshToken", () => {
  it("in keep mode preserves the current version (v2 stays v2, v1 or none gives v1)", () => {
    vi.stubEnv("M365_ENVELOPE_WRITE_VERSION", "");
    const kept2 = sealUserRefreshToken("rt", KEK, "k1", "user-1", "v2");
    const kept1 = sealUserRefreshToken("rt", KEK, "k1", "user-1", "v1");
    const none = sealUserRefreshToken("rt", KEK, "k1", "user-1", null);
    const omitted = sealUserRefreshToken("rt", KEK, "k1", "user-1");
    expect(peekEnvelopeVersion(kept2)).toBe("v2");
    expect(peekEnvelopeVersion(kept1)).toBe("v1");
    expect(peekEnvelopeVersion(none)).toBe("v1");
    expect(peekEnvelopeVersion(omitted)).toBe("v1");
  });

  it("binds a v2 seal to the owning user only", () => {
    vi.stubEnv("M365_ENVELOPE_WRITE_VERSION", "2");
    const envelope = sealUserRefreshToken("rt", KEK, "k1", "user-1", "v1");
    expect(peekEnvelopeVersion(envelope)).toBe("v2");
    expect(
      decryptRefreshToken(envelope, KEK, refreshTokenContext("user-1")),
    ).toBe("rt");
    expect(() =>
      decryptRefreshToken(envelope, KEK, refreshTokenContext("user-2")),
    ).toThrow();
  });

  it("writes v1 for an explicit 1 even over a v2 row", () => {
    vi.stubEnv("M365_ENVELOPE_WRITE_VERSION", "1");
    expect(
      peekEnvelopeVersion(sealUserRefreshToken("rt", KEK, "k1", "u", "v2")),
    ).toBe("v1");
  });

  it("writes v2 under strict whatever the row held", () => {
    vi.stubEnv("M365_ENVELOPE_STRICT", "1");
    expect(
      peekEnvelopeVersion(sealUserRefreshToken("rt", KEK, "k1", "u", "v1")),
    ).toBe("v2");
  });
});

describe("openUserRefreshToken", () => {
  const v1 = encryptRefreshToken("rt-1", KEK, "k1");
  const v2 = encryptRefreshToken("rt-2", KEK, "k1", refreshTokenContext("u-1"));

  it("accepts both versions when strict is off", () => {
    expect(openUserRefreshToken(v1, KEK, "u-1")).toEqual({
      plaintext: "rt-1",
      version: "v1",
    });
    expect(openUserRefreshToken(v2, KEK, "u-1")).toEqual({
      plaintext: "rt-2",
      version: "v2",
    });
  });

  it("refuses another user's v2 envelope", () => {
    expect(() => openUserRefreshToken(v2, KEK, "u-2")).toThrow();
  });

  it("strict refuses v1 before decrypting and accepts v2", () => {
    vi.stubEnv("M365_ENVELOPE_STRICT", "1");
    expect(() => openUserRefreshToken(v1, KEK, "u-1")).toThrow(/STRICT/);
    expect(openUserRefreshToken(v2, KEK, "u-1").plaintext).toBe("rt-2");
    // The refusal does not depend on the KEK being right: it precedes decrypt.
    expect(() => openUserRefreshToken(v1, randomBytes(32), "u-1")).toThrow(
      /STRICT/,
    );
  });

  it("allowV1: true overrides strict (the converge must read v1 to rewrap it)", () => {
    vi.stubEnv("M365_ENVELOPE_STRICT", "1");
    expect(
      openUserRefreshToken(v1, KEK, "u-1", { allowV1: true }).plaintext,
    ).toBe("rt-1");
  });

  it("allowV1: false refuses v1 even when strict is off", () => {
    expect(() =>
      openUserRefreshToken(v1, KEK, "u-1", { allowV1: false }),
    ).toThrow(/STRICT/);
  });
});

describe("rewrapUserEnvelope", () => {
  it("rewraps v1 to v2 bound to the user, keeping the plaintext", () => {
    const v1 = encryptRefreshToken("the-rt", KEK, "k1");
    const next = rewrapUserEnvelope(v1, KEK, "k1", "u-1", "v2");
    expect(peekEnvelopeVersion(next)).toBe("v2");
    expect(openUserRefreshToken(next, KEK, "u-1").plaintext).toBe("the-rt");
    expect(() => openUserRefreshToken(next, KEK, "u-2")).toThrow();
  });

  it("rewraps v2 back to v1 (the explicit rollback)", () => {
    const v2 = sealUserRefreshTokenAt("v2", "the-rt", KEK, "k1", "u-1");
    const next = rewrapUserEnvelope(v2, KEK, "k1", "u-1", "v1");
    expect(peekEnvelopeVersion(next)).toBe("v1");
    expect(decryptRefreshToken(next, KEK)).toBe("the-rt");
  });

  it("throws for an envelope bound to a different user", () => {
    const foreign = sealUserRefreshTokenAt("v2", "rt", KEK, "k1", "u-other");
    expect(() => rewrapUserEnvelope(foreign, KEK, "k1", "u-1", "v2")).toThrow();
  });

  it.each([
    ["a tampered ciphertext", "tamper"],
    ["a valid envelope at the wrong version", "unbound"],
    ["a valid envelope holding a different token", "other-plaintext"],
  ] as const)(
    "throws instead of returning %s (round-trip verify)",
    (_label, mode) => {
      const v1 = encryptRefreshToken("the-rt", KEK, "k1");
      corrupt.mode = mode;
      expect(() => rewrapUserEnvelope(v1, KEK, "k1", "u-1", "v2")).toThrow();
    },
  );
});
