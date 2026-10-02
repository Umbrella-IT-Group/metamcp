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
  formatCredentialSessionSummary,
  registerSessionActivityProbe,
  registerSessionCounter,
  resetSessionCountersForTests,
  resolveSessionCeiling,
  summarizeCredentialSessions,
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

describe("summarizeCredentialSessions — what is filling a credential", () => {
  const OTHER_IDENTITY: SessionIdentity = {
    method: "api_key",
    credentialId: "key-2",
  };

  /** A counter that lists sessions per identity, like the real managers. */
  function listingCounter(
    byIdentity: Record<
      string,
      Array<{ sessionId: string; endpointName: string }>
    >,
  ) {
    return {
      countSessionsForIdentity: (identity: SessionIdentity) =>
        (byIdentity[identity.credentialId ?? ""] ?? []).length,
      listSessionsForIdentity: (identity: SessionIdentity) =>
        byIdentity[identity.credentialId ?? ""] ?? [],
    };
  }

  const sessions = (
    prefix: string,
    endpointName: string,
    count: number,
  ): Array<{ sessionId: string; endpointName: string }> =>
    Array.from({ length: count }, (_, i) => ({
      sessionId: `${prefix}-${endpointName}-${i}`,
      endpointName,
    }));

  /** Probe table: session id -> activity; unlisted ids are untracked. */
  const probeFor =
    (table: Record<string, { idleMs: number; inFlight: boolean }>) =>
    (sessionId: string) =>
      table[sessionId];

  it("counts per endpoint, splits in-flight from idle, and finds the oldest idle", () => {
    registerSessionCounter(
      listingCounter({
        "key-1": [
          ...sessions("s", "autotask", 3),
          ...sessions("s", "itglue", 2),
          ...sessions("s", "ninja", 1),
        ],
      }),
    );
    registerSessionActivityProbe(
      probeFor({
        "s-autotask-0": { idleMs: 0, inFlight: true },
        "s-autotask-1": { idleMs: 60_000, inFlight: false },
        "s-autotask-2": { idleMs: 1_710_900, inFlight: false },
        "s-itglue-0": { idleMs: 5_000, inFlight: false },
        "s-itglue-1": { idleMs: 0, inFlight: true },
        // s-ninja-0 is untracked.
      }),
    );

    const summary = summarizeCredentialSessions(API_KEY_IDENTITY);

    expect(summary).toEqual({
      total: 6,
      byEndpoint: [
        ["autotask", 3],
        ["itglue", 2],
        ["ninja", 1],
      ],
      endpoints: 3,
      inFlight: 2,
      idle: 3,
      oldestIdleSeconds: 1710,
      untracked: 1,
    });
  });

  it("does not count another credential's sessions", () => {
    registerSessionCounter(
      listingCounter({
        "key-1": sessions("a", "autotask", 2),
        "key-2": sessions("b", "ninja", 9),
      }),
    );
    registerSessionActivityProbe(() => ({ idleMs: 0, inFlight: false }));

    expect(summarizeCredentialSessions(API_KEY_IDENTITY).total).toBe(2);
    expect(summarizeCredentialSessions(OTHER_IDENTITY).total).toBe(9);
  });

  it("keeps the top five endpoints and says how many there are in all", () => {
    const listed = [];
    for (let i = 0; i < 8; i += 1) {
      listed.push(...sessions("s", `ep${i}`, 8 - i));
    }
    registerSessionCounter(listingCounter({ "key-1": listed }));

    const summary = summarizeCredentialSessions(API_KEY_IDENTITY);

    expect(summary.endpoints).toBe(8);
    expect(summary.byEndpoint).toHaveLength(5);
    expect(summary.byEndpoint[0]).toEqual(["ep0", 8]);
    expect(summary.byEndpoint[4]).toEqual(["ep4", 4]);
  });

  it("breaks ties by endpoint name so the output is stable", () => {
    registerSessionCounter(
      listingCounter({
        "key-1": [
          ...sessions("s", "zeta", 2),
          ...sessions("s", "alpha", 2),
          ...sessions("s", "mid", 2),
        ],
      }),
    );
    expect(
      summarizeCredentialSessions(API_KEY_IDENTITY).byEndpoint.map(([n]) => n),
    ).toEqual(["alpha", "mid", "zeta"]);
  });

  it("with no probe, every session is untracked and nothing is guessed", () => {
    registerSessionCounter(
      listingCounter({ "key-1": sessions("s", "autotask", 4) }),
    );
    const summary = summarizeCredentialSessions(API_KEY_IDENTITY);
    expect(summary).toMatchObject({
      total: 4,
      inFlight: 0,
      idle: 0,
      oldestIdleSeconds: null,
      untracked: 4,
    });
  });

  it("a counter that cannot list contributes nothing, and a listing that throws is skipped", () => {
    registerSessionCounter(counterReturning(7));
    registerSessionCounter({
      countSessionsForIdentity: () => 1,
      listSessionsForIdentity: () => {
        throw new Error("boom");
      },
    });
    registerSessionCounter(
      listingCounter({ "key-1": sessions("s", "autotask", 2) }),
    );

    expect(summarizeCredentialSessions(API_KEY_IDENTITY).total).toBe(2);
  });

  it("a probe that throws counts that session as untracked and does not stop the summary", () => {
    registerSessionCounter(
      listingCounter({ "key-1": sessions("s", "autotask", 3) }),
    );
    registerSessionActivityProbe((sessionId) => {
      if (sessionId.endsWith("-1")) throw new Error("probe fault");
      return { idleMs: 1000, inFlight: false };
    });

    const summary = summarizeCredentialSessions(API_KEY_IDENTITY);
    expect(summary).toMatchObject({ total: 3, idle: 2, untracked: 1 });
  });

  it("asks a later probe when an earlier one does not track the session", () => {
    registerSessionCounter(
      listingCounter({ "key-1": sessions("s", "autotask", 2) }),
    );
    registerSessionActivityProbe((sessionId) =>
      sessionId.endsWith("-0") ? { idleMs: 0, inFlight: true } : undefined,
    );
    registerSessionActivityProbe(() => ({ idleMs: 2_000, inFlight: false }));

    expect(summarizeCredentialSessions(API_KEY_IDENTITY)).toMatchObject({
      inFlight: 1,
      idle: 1,
      untracked: 0,
      oldestIdleSeconds: 2,
    });
  });
});

describe("formatCredentialSessionSummary", () => {
  const summary = (
    overrides: Partial<
      Parameters<typeof formatCredentialSessionSummary>[0]
    > = {},
  ): Parameters<typeof formatCredentialSessionSummary>[0] => ({
    total: 63,
    byEndpoint: [
      ["autotask", 21],
      ["itglue", 21],
      ["ninja", 21],
    ],
    endpoints: 14,
    inFlight: 187,
    idle: 113,
    oldestIdleSeconds: 1710,
    untracked: 0,
    ...overrides,
  });

  it("renders the one-line clause", () => {
    expect(formatCredentialSessionSummary(summary())).toBe(
      "live: autotask=21, itglue=21, ninja=21 (top 3 of 14 endpoints); in-flight 187, idle 113, oldest idle 1710s",
    );
  });

  it("drops the 'top N of M' scope when every endpoint is shown", () => {
    expect(formatCredentialSessionSummary(summary({ endpoints: 3 }))).toBe(
      "live: autotask=21, itglue=21, ninja=21; in-flight 187, idle 113, oldest idle 1710s",
    );
  });

  it("mentions untracked sessions and omits the oldest idle when there is none", () => {
    expect(
      formatCredentialSessionSummary(
        summary({
          inFlight: 4,
          idle: 0,
          oldestIdleSeconds: null,
          untracked: 2,
          endpoints: 3,
        }),
      ),
    ).toBe(
      "live: autotask=21, itglue=21, ninja=21; in-flight 4, idle 0, untracked 2",
    );
  });

  it("says nothing when there are no sessions to describe", () => {
    expect(
      formatCredentialSessionSummary(
        summary({ total: 0, byEndpoint: [], endpoints: 0 }),
      ),
    ).toBe("");
  });

  it("stays short: long endpoint names are truncated and trailing endpoints dropped", () => {
    const long = "x".repeat(60);
    const text = formatCredentialSessionSummary(
      summary({
        byEndpoint: [
          [`${long}-1`, 9],
          [`${long}-2`, 8],
          [`${long}-3`, 7],
          [`${long}-4`, 6],
          [`${long}-5`, 5],
        ],
        endpoints: 14,
      }),
    );
    expect(text.length).toBeLessThanOrEqual(180);
    expect(text).toContain("endpoints)");
    expect(text).toContain("in-flight 187");
  });

  it("neutralizes characters that could forge a log line", () => {
    const text = formatCredentialSessionSummary(
      summary({
        byEndpoint: [['bad\nname with spaces\r"q"', 3]],
        endpoints: 1,
      }),
    );
    expect(text).not.toMatch(/[\r\n" ]{1}name/);
    expect(text).not.toContain("\n");
    expect(text).not.toContain("\r");
    expect(text).toContain("bad?name?with?spaces??q?=3");
  });
});

describe("checkConcurrentSessionCeiling — the live summary", () => {
  const UUID_PATTERN =
    /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i;

  function registerBusyCredential(count: number) {
    const sessions = Array.from({ length: count }, (_, i) => ({
      // Real session ids are UUIDs; none may ever reach a log line.
      sessionId: `0b3f6c1e-aaaa-4bbb-8ccc-${String(i).padStart(12, "0")}`,
      endpointName: i % 2 === 0 ? "autotask" : "itglue",
    }));
    registerSessionCounter({
      countSessionsForIdentity: () => sessions.length,
      listSessionsForIdentity: () => sessions,
    });
    registerSessionActivityProbe(() => ({ idleMs: 90_000, inFlight: false }));
  }

  it("appends the summary to the refusal WARN, after the original text", () => {
    process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL = "4";
    registerBusyCredential(4);

    const decision = checkConcurrentSessionCeiling(API_KEY_IDENTITY, {
      label: "Example connector",
    });

    const message = loggerMock.warn.mock.calls[0][0] as string;
    expect(message).toMatch(
      /^Concurrent-session ceiling reached for api_key credential "Example connector": 4\/4 live sessions; refusing a new session\. Raise MCP_MAX_SESSIONS_PER_CREDENTIAL if this is a legitimate consumer\. live: autotask=2, itglue=2; in-flight 0, idle 4, oldest idle 90s$/,
    );
    expect(decision.liveSummary).toBe(
      "live: autotask=2, itglue=2; in-flight 0, idle 4, oldest idle 90s",
    );
  });

  it("appends it to the approaching WARN too", () => {
    process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL = "5";
    registerBusyCredential(4);

    const decision = checkConcurrentSessionCeiling(API_KEY_IDENTITY);

    expect(decision.approaching).toBe(true);
    const message = loggerMock.warn.mock.calls[0][0] as string;
    expect(message).toMatch(
      /^Concurrent-session usage high for api_key credential: /,
    );
    expect(message).toContain(" live: autotask=2, itglue=2;");
  });

  it("never puts a session id (or anything UUID-shaped) in the line or the decision", () => {
    process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL = "4";
    registerBusyCredential(4);

    const decision = checkConcurrentSessionCeiling(API_KEY_IDENTITY);

    expect(String(loggerMock.warn.mock.calls[0][0])).not.toMatch(UUID_PATTERN);
    expect(JSON.stringify(decision)).not.toMatch(UUID_PATTERN);
  });

  it("keeps the whole WARN under 400 characters even with long names and a long label", () => {
    process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL = "4";
    const sessions = Array.from({ length: 12 }, (_, i) => ({
      sessionId: `s${i}`,
      endpointName: `${"endpoint".repeat(10)}${i}`,
    }));
    registerSessionCounter({
      countSessionsForIdentity: () => 12,
      listSessionsForIdentity: () => sessions,
    });

    checkConcurrentSessionCeiling(API_KEY_IDENTITY, { label: "Example" });

    const message = loggerMock.warn.mock.calls[0][0] as string;
    const summary = message.slice(message.indexOf(" live: "));
    expect(summary.length).toBeLessThanOrEqual(181);
  });

  it("does not compute or log a summary for a healthy credential", () => {
    process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL = "100";
    const list = vi.fn().mockReturnValue([]);
    registerSessionCounter({
      countSessionsForIdentity: () => 10,
      listSessionsForIdentity: list,
    });

    const decision = checkConcurrentSessionCeiling(API_KEY_IDENTITY);

    expect(list).not.toHaveBeenCalled();
    expect(decision).toEqual({
      allowed: true,
      current: 10,
      ceiling: 100,
      approaching: false,
    });
    expect(loggerMock.warn).not.toHaveBeenCalled();
  });

  it("the admission decision is identical with and without the summary", () => {
    process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL = "4";

    registerSessionCounter(counterReturning(4));
    const without = checkConcurrentSessionCeiling(API_KEY_IDENTITY);
    resetSessionCountersForTests();

    registerBusyCredential(4);
    const withSummary = checkConcurrentSessionCeiling(API_KEY_IDENTITY);

    const { liveSummary, ...rest } = withSummary;
    expect(liveSummary).toBeDefined();
    expect(rest).toEqual(without);
  });

  it("a throwing lister or probe still returns the decision and never fails the check", () => {
    process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL = "4";
    registerSessionCounter({
      countSessionsForIdentity: () => 4,
      listSessionsForIdentity: () => {
        throw new Error("lister fault");
      },
    });
    registerSessionActivityProbe(() => {
      throw new Error("probe fault");
    });

    const decision = checkConcurrentSessionCeiling(API_KEY_IDENTITY);

    expect(decision).toEqual({
      allowed: false,
      current: 4,
      ceiling: 4,
      approaching: true,
    });
    // The original WARN is still written, just without a summary.
    expect(loggerMock.warn).toHaveBeenCalledTimes(1);
    expect(String(loggerMock.warn.mock.calls[0][0])).not.toContain(" live: ");
  });

  it("keeps the exact WARN text when no counter can list (today's behavior)", () => {
    process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL = "3";
    registerSessionCounter(counterReturning(3));

    checkConcurrentSessionCeiling(API_KEY_IDENTITY, { label: "Example" });

    expect(loggerMock.warn.mock.calls[0][0]).toBe(
      'Concurrent-session ceiling reached for api_key credential "Example": 3/3 live sessions; refusing a new session. Raise MCP_MAX_SESSIONS_PER_CREDENTIAL if this is a legitimate consumer.',
    );
  });
});
