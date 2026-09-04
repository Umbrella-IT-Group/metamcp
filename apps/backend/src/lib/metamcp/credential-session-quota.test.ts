/**
 * Per-credential concurrent-session ceiling.
 *
 * The count is DERIVED by summing across registered session counters (not a
 * maintained tally), the ceiling is env-configurable, anonymous callers are
 * exempt, and the decision WARNs at 80% so an operator sees a credential
 * approaching the limit before anything is refused.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { loggerMock } = vi.hoisted(() => ({
  loggerMock: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

vi.mock("@/utils/logger", () => ({ default: loggerMock }));

import {
  checkConcurrentSessionCeiling,
  countLiveSessionsForIdentity,
  DEFAULT_MAX_SESSIONS_PER_CREDENTIAL,
  registerSessionCounter,
  resetSessionCountersForTests,
  resolveSessionCeiling,
} from "./credential-session-quota";
import { SessionIdentity } from "./session-auth";

const API_KEY_IDENTITY: SessionIdentity = {
  method: "api_key",
  credentialId: "key-1",
};

const ORIGINAL_ENV = process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL;

function counterReturning(count: number) {
  return { countSessionsForIdentity: vi.fn().mockReturnValue(count) };
}

beforeEach(() => {
  vi.clearAllMocks();
  resetSessionCountersForTests();
  delete process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL;
});

afterEach(() => {
  if (ORIGINAL_ENV === undefined) {
    delete process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL;
  } else {
    process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL = ORIGINAL_ENV;
  }
});

describe("resolveSessionCeiling", () => {
  it("uses the default when unset", () => {
    expect(resolveSessionCeiling()).toBe(DEFAULT_MAX_SESSIONS_PER_CREDENTIAL);
  });

  it("parses a configured value, including 0 (disabled)", () => {
    process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL = "5";
    expect(resolveSessionCeiling()).toBe(5);
    process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL = "0";
    expect(resolveSessionCeiling()).toBe(0);
  });

  it("falls back to the default with a WARN on a malformed value", () => {
    process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL = "not-a-number";
    expect(resolveSessionCeiling()).toBe(DEFAULT_MAX_SESSIONS_PER_CREDENTIAL);
    expect(loggerMock.warn).toHaveBeenCalledTimes(1);
  });
});

describe("countLiveSessionsForIdentity", () => {
  it("sums across every registered counter", () => {
    registerSessionCounter(counterReturning(2));
    registerSessionCounter(counterReturning(3));
    expect(countLiveSessionsForIdentity(API_KEY_IDENTITY)).toBe(5);
  });

  it("does not double-count the same counter registered twice", () => {
    const counter = counterReturning(4);
    registerSessionCounter(counter);
    registerSessionCounter(counter);
    expect(countLiveSessionsForIdentity(API_KEY_IDENTITY)).toBe(4);
  });
});

describe("checkConcurrentSessionCeiling", () => {
  it("allows a credential below the ceiling", () => {
    process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL = "10";
    registerSessionCounter(counterReturning(3));

    const decision = checkConcurrentSessionCeiling(API_KEY_IDENTITY);

    expect(decision.allowed).toBe(true);
    expect(decision.current).toBe(3);
    expect(decision.ceiling).toBe(10);
  });

  it("refuses a credential at the ceiling", () => {
    process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL = "3";
    registerSessionCounter(counterReturning(3));

    const decision = checkConcurrentSessionCeiling(API_KEY_IDENTITY);

    expect(decision.allowed).toBe(false);
    expect(loggerMock.warn).toHaveBeenCalledTimes(1);
  });

  it("WARNs at 80% of the ceiling while still allowing", () => {
    process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL = "10";
    registerSessionCounter(counterReturning(8));

    const decision = checkConcurrentSessionCeiling(API_KEY_IDENTITY);

    expect(decision.allowed).toBe(true);
    expect(loggerMock.warn).toHaveBeenCalledTimes(1);
  });

  it("exempts anonymous callers (no per-caller identity to key on)", () => {
    process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL = "1";
    registerSessionCounter(counterReturning(99));

    const decision = checkConcurrentSessionCeiling({
      method: "anonymous",
      credentialId: null,
    });

    expect(decision.allowed).toBe(true);
  });

  it("is disabled entirely when the ceiling is 0", () => {
    process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL = "0";
    registerSessionCounter(counterReturning(1000));

    const decision = checkConcurrentSessionCeiling(API_KEY_IDENTITY);

    expect(decision.allowed).toBe(true);
  });
});

describe("checkConcurrentSessionCeiling — credential label in the WARN text", () => {
  // The label names WHICH credential is at the ceiling so a leak is
  // identifiable from the logs. It is a display name (api-key name or user
  // email), never a token or key value.
  it("names the credential in the refusal WARN when a label is given", () => {
    process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL = "3";
    registerSessionCounter(counterReturning(3));

    checkConcurrentSessionCeiling(API_KEY_IDENTITY, {
      label: "Autotask connector",
    });

    expect(loggerMock.warn).toHaveBeenCalledTimes(1);
    expect(loggerMock.warn.mock.calls[0][0]).toContain(
      'api_key credential "Autotask connector":',
    );
  });

  it("omits the label cleanly in the refusal WARN when none is given", () => {
    process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL = "3";
    registerSessionCounter(counterReturning(3));

    checkConcurrentSessionCeiling(API_KEY_IDENTITY);

    const message = loggerMock.warn.mock.calls[0][0];
    expect(message).toContain("api_key credential:");
    expect(message).not.toContain('"');
  });

  it("names the credential in the 80% WARN when a label is given", () => {
    process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL = "10";
    registerSessionCounter(counterReturning(8));

    const decision = checkConcurrentSessionCeiling(API_KEY_IDENTITY, {
      label: "user@example.test",
    });

    expect(decision.approaching).toBe(true);
    expect(loggerMock.warn).toHaveBeenCalledTimes(1);
    expect(loggerMock.warn.mock.calls[0][0]).toContain(
      'api_key credential "user@example.test":',
    );
  });

  it("omits the label cleanly in the 80% WARN when none is given", () => {
    process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL = "10";
    registerSessionCounter(counterReturning(8));

    checkConcurrentSessionCeiling(API_KEY_IDENTITY);

    const message = loggerMock.warn.mock.calls[0][0];
    expect(message).toContain("api_key credential:");
    expect(message).not.toContain('"');
  });

  it("reports approaching=false and does not WARN below the 80% threshold", () => {
    process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL = "10";
    registerSessionCounter(counterReturning(3));

    const decision = checkConcurrentSessionCeiling(API_KEY_IDENTITY, {
      label: "Autotask connector",
    });

    expect(decision.approaching).toBe(false);
    expect(loggerMock.warn).not.toHaveBeenCalled();
  });
});
