/**
 * The rule for when a shipped placeholder must be fatal.
 *
 * The two guards this backs are asymmetric on purpose (see the module header):
 * a placeholder signing key is refused at boot in production because it makes
 * the whole auth plane forgeable, while a placeholder or too-short bootstrap
 * password is refused so the insecure administrator account is never created.
 * Both are warn-only outside production so a throwaway local stack still boots.
 *
 * These pin the DECISION in every mode. The throwing wiring is a thin call on
 * top: `auth.ts` for the secret, `validateConfig` in `bootstrap.service` for
 * the password.
 */

import { describe, expect, it } from "vitest";

import {
  isPlaceholderOrShortBootstrapPassword,
  MIN_BOOTSTRAP_PASSWORD_LENGTH,
  SHIPPED_PLACEHOLDER_AUTH_SECRET,
  SHIPPED_PLACEHOLDER_PASSWORDS,
  shouldRefuseAuthSecretInProduction,
  shouldRefuseBootstrapPasswordInProduction,
} from "./shipped-placeholders";

const REAL_SECRET = "a".repeat(64);
const REAL_PASSWORD = "a-real-long-enough-secret";

describe("shouldRefuseAuthSecretInProduction", () => {
  it("refuses the shipped placeholder in production", () => {
    expect(
      shouldRefuseAuthSecretInProduction(
        SHIPPED_PLACEHOLDER_AUTH_SECRET,
        "production",
      ),
    ).toBe(true);
  });

  it("allows the placeholder outside production so a local stack boots", () => {
    for (const env of ["development", "test", undefined]) {
      expect(
        shouldRefuseAuthSecretInProduction(
          SHIPPED_PLACEHOLDER_AUTH_SECRET,
          env,
        ),
      ).toBe(false);
    }
  });

  it("allows a real secret in production", () => {
    expect(shouldRefuseAuthSecretInProduction(REAL_SECRET, "production")).toBe(
      false,
    );
  });
});

describe("isPlaceholderOrShortBootstrapPassword", () => {
  it("flags every published placeholder", () => {
    for (const password of SHIPPED_PLACEHOLDER_PASSWORDS) {
      expect(isPlaceholderOrShortBootstrapPassword(password)).toBe(true);
    }
  });

  it("flags a password shorter than the floor", () => {
    expect(
      isPlaceholderOrShortBootstrapPassword(
        "x".repeat(MIN_BOOTSTRAP_PASSWORD_LENGTH - 1),
      ),
    ).toBe(true);
    // The floor length itself is allowed.
    expect(
      isPlaceholderOrShortBootstrapPassword(
        "x".repeat(MIN_BOOTSTRAP_PASSWORD_LENGTH),
      ),
    ).toBe(false);
  });

  it("passes a real password and treats undefined as not-its-concern", () => {
    expect(isPlaceholderOrShortBootstrapPassword(REAL_PASSWORD)).toBe(false);
    expect(isPlaceholderOrShortBootstrapPassword(undefined)).toBe(false);
  });

  // Interim credential-hardening step for the CI-login rework: the bootstrap
  // password floor was raised from 8 to 14. Pinned as a literal (not the
  // symbol) so a regression that lowers it fails here rather than silently
  // tracking the change.
  it("enforces a floor of 14 characters", () => {
    expect(MIN_BOOTSTRAP_PASSWORD_LENGTH).toBe(14);
    expect(isPlaceholderOrShortBootstrapPassword("x".repeat(13))).toBe(true);
    expect(isPlaceholderOrShortBootstrapPassword("x".repeat(14))).toBe(false);
    // A password that cleared the OLD 8-char floor but not the new one.
    expect(isPlaceholderOrShortBootstrapPassword("abcdefghijk")).toBe(true);
  });
});

describe("shouldRefuseBootstrapPasswordInProduction", () => {
  it("refuses a placeholder or short password in production", () => {
    expect(
      shouldRefuseBootstrapPasswordInProduction("changeme", "production"),
    ).toBe(true);
    expect(
      shouldRefuseBootstrapPasswordInProduction("short", "production"),
    ).toBe(true);
  });

  it("allows a placeholder outside production so a local stack boots", () => {
    for (const env of ["development", "test", undefined]) {
      expect(shouldRefuseBootstrapPasswordInProduction("changeme", env)).toBe(
        false,
      );
    }
  });

  it("allows a real password in production", () => {
    expect(
      shouldRefuseBootstrapPasswordInProduction(REAL_PASSWORD, "production"),
    ).toBe(false);
  });
});
