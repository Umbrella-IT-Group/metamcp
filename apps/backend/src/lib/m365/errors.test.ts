import { describe, expect, it } from "vitest";

import {
  isM365BrokerError,
  isPerUserBrokerError,
  M365BrokerError,
  type M365BrokerErrorCode,
} from "./errors";

describe("isPerUserBrokerError", () => {
  it.each([
    "credential_missing",
    "credential_expired",
    "credential_revoked",
    "mfa_required",
  ] as const)("is true for %s: the user's own enrollment state", (code) => {
    const error = new M365BrokerError(code, "state", "https://x/enroll");
    expect(isPerUserBrokerError(error)).toBe(true);
    expect(isM365BrokerError(error)).toBe(true);
  });

  it.each(["not_configured", "mint_failed"] as const)(
    "is false for %s: an operator-actionable fault, not the user's state",
    (code) => {
      const error = new M365BrokerError(code, "fault");
      expect(isPerUserBrokerError(error)).toBe(false);
      expect(isM365BrokerError(error)).toBe(true);
    },
  );

  it("is false for anything that is not a broker error", () => {
    expect(isPerUserBrokerError(new Error("terminated"))).toBe(false);
    expect(isPerUserBrokerError("credential_missing")).toBe(false);
    expect(isPerUserBrokerError(undefined)).toBe(false);
    expect(isPerUserBrokerError({ code: "credential_missing" })).toBe(false);
  });

  it("matches a broker error that crossed a module boundary (name check)", () => {
    const foreign = Object.assign(new Error("dual-instantiated"), {
      name: "M365BrokerError",
      code: "credential_missing" as M365BrokerErrorCode,
    });
    expect(isPerUserBrokerError(foreign)).toBe(true);
  });

  it("is false for a name-matched error that carries no known code", () => {
    const foreign = Object.assign(new Error("no code"), {
      name: "M365BrokerError",
    });
    expect(isPerUserBrokerError(foreign)).toBe(false);
  });
});
