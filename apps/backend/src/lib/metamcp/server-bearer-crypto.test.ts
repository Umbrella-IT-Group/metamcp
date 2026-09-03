/**
 * At-rest encryption for `mcp_servers.bearer_token`.
 *
 * Three properties are load-bearing, and each is a live-outage or a
 * plaintext-at-rest bug if it is wrong:
 *
 * 1. A stored bearer round-trips. The value must stay recoverable, client.ts
 *    reads it back to build the upstream Authorization header, so it is
 *    encrypted, not hashed, and decryption at the point of use must return the
 *    exact bytes that were stored.
 * 2. The write path fails CLOSED. A gateway credential must never be written in
 *    the clear, so encryption with no KEK configured throws rather than degrade
 *    to plaintext.
 * 3. The read path fails CLOSED after converge. A legacy plaintext row is
 *    tolerated only until the boot converge has run; once it has, an untagged
 *    value is a fault to surface, not a credential to trust. A row that cannot
 *    be decrypted yields no header rather than a broken one.
 */
import { randomBytes } from "node:crypto";

import { beforeEach, describe, expect, it, vi } from "vitest";

const loggerMock = vi.hoisted(() => ({
  debug: vi.fn(),
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
}));

vi.mock("@/utils/logger", () => ({ default: loggerMock }));

import {
  __resetServerBearerConvergeForTests,
  BEARER_ENVELOPE_PREFIX,
  encryptServerBearerToken,
  isEncryptedBearerToken,
  markServerBearerConvergeComplete,
  resolveServerBearerToken,
} from "./server-bearer-crypto";

// A valid 32-byte (AES-256) KEK, base64, the shape getTokenKek() validates.
const VALID_KEK = randomBytes(32).toString("base64");

beforeEach(() => {
  vi.clearAllMocks();
  __resetServerBearerConvergeForTests();
  process.env.M365_TOKEN_KEK = VALID_KEK;
  delete process.env.M365_KEK_ID;
});

describe("encryptServerBearerToken / resolveServerBearerToken round trip", () => {
  it("round-trips a bearer token through an enc:v1: envelope", () => {
    const plaintext = "mcp_endpoint_key_abc123";
    const stored = encryptServerBearerToken(plaintext);

    expect(stored.startsWith(BEARER_ENVELOPE_PREFIX)).toBe(true);
    expect(stored).not.toContain(plaintext);
    expect(isEncryptedBearerToken(stored)).toBe(true);
    expect(resolveServerBearerToken(stored)).toBe(plaintext);
  });

  it("produces a unique envelope per encryption but decrypts to the same value", () => {
    const a = encryptServerBearerToken("same-bearer");
    const b = encryptServerBearerToken("same-bearer");
    expect(a).not.toBe(b);
    expect(resolveServerBearerToken(a)).toBe("same-bearer");
    expect(resolveServerBearerToken(b)).toBe("same-bearer");
  });

  it("does not treat a plaintext value as an envelope", () => {
    expect(isEncryptedBearerToken("mcp_endpoint_key_abc123")).toBe(false);
  });
});

describe("encryptServerBearerToken fails closed without a KEK", () => {
  it("throws rather than storing plaintext when no KEK is configured", () => {
    delete process.env.M365_TOKEN_KEK;
    expect(() => encryptServerBearerToken("mcp_endpoint_key_abc123")).toThrow(
      /M365_TOKEN_KEK is not configured/,
    );
  });
});

describe("resolveServerBearerToken", () => {
  it("returns null for an empty stored value", () => {
    expect(resolveServerBearerToken(null)).toBeNull();
    expect(resolveServerBearerToken(undefined)).toBeNull();
    expect(resolveServerBearerToken("")).toBeNull();
  });

  it("honours a legacy plaintext value BEFORE the converge has run", () => {
    // The rollout window: an untagged row is still presented so nothing breaks
    // between the migration landing and the boot converge encrypting it.
    expect(resolveServerBearerToken("mcp_legacy_plaintext")).toBe(
      "mcp_legacy_plaintext",
    );
  });

  it("refuses a legacy plaintext value AFTER the converge has run", () => {
    // Post-converge an untagged value is a fault: the converge should have
    // encrypted it. Fail closed (no credential) and log, rather than present a
    // value that was supposed to be encrypted.
    markServerBearerConvergeComplete();
    expect(resolveServerBearerToken("mcp_legacy_plaintext")).toBeNull();
    expect(loggerMock.error).toHaveBeenCalled();
  });

  it("returns null (not the ciphertext) when an envelope cannot be decrypted", () => {
    // A tampered or wrong-key envelope must not crash the connection machinery
    // and must never present the raw ciphertext as a credential.
    const stored = encryptServerBearerToken("mcp_endpoint_key_abc123");
    process.env.M365_TOKEN_KEK = randomBytes(32).toString("base64");
    expect(resolveServerBearerToken(stored)).toBeNull();
    expect(loggerMock.error).toHaveBeenCalled();
  });

  it("returns null when an envelope is present but no KEK is configured", () => {
    const stored = encryptServerBearerToken("mcp_endpoint_key_abc123");
    delete process.env.M365_TOKEN_KEK;
    expect(resolveServerBearerToken(stored)).toBeNull();
    expect(loggerMock.error).toHaveBeenCalled();
  });
});
