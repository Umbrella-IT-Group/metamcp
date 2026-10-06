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
  DEFAULT_CEILING_EVICT_MIN_IDLE_SECONDS,
  DEFAULT_MAX_SESSIONS_PER_CREDENTIAL,
  EVICTION_ADMISSION_WAIT_MS,
  formatCredentialSessionSummary,
  type IdentitySessionCounter,
  MIN_CEILING_EVICT_MIN_IDLE_SECONDS,
  registerSessionActivityProbe,
  registerSessionCounter,
  resetSessionCountersForTests,
  resolveEvictionConfig,
  resolveSessionCeiling,
  selectEvictionCandidate,
  summarizeCredentialSessions,
} from "./credential-session-quota";
import { SessionIdentity } from "./session-auth";

const API_KEY_IDENTITY: SessionIdentity = {
  method: "api_key",
  credentialId: "key-1",
};

const ORIGINAL_ENV = process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL;
const ORIGINAL_EVICT_ENV = process.env.MCP_SESSION_CEILING_EVICT_IDLE;
const ORIGINAL_EVICT_IDLE_ENV =
  process.env.MCP_SESSION_CEILING_EVICT_MIN_IDLE_SECONDS;

function restoreEnv(name: string, value: string | undefined): void {
  if (value === undefined) {
    delete process.env[name];
  } else {
    process.env[name] = value;
  }
}

function counterReturning(count: number) {
  return { countSessionsForIdentity: vi.fn().mockReturnValue(count) };
}

beforeEach(() => {
  vi.clearAllMocks();
  resetSessionCountersForTests();
  delete process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL;
  delete process.env.MCP_SESSION_CEILING_EVICT_IDLE;
  delete process.env.MCP_SESSION_CEILING_EVICT_MIN_IDLE_SECONDS;
});

afterEach(() => {
  restoreEnv("MCP_MAX_SESSIONS_PER_CREDENTIAL", ORIGINAL_ENV);
  restoreEnv("MCP_SESSION_CEILING_EVICT_IDLE", ORIGINAL_EVICT_ENV);
  restoreEnv(
    "MCP_SESSION_CEILING_EVICT_MIN_IDLE_SECONDS",
    ORIGINAL_EVICT_IDLE_ENV,
  );
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

describe("admissions starting below the ceiling", () => {
  it("reserves a free slot before a concurrent admission checks it", () => {
    process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL = "1";
    registerSessionCounter(counterReturning(0));
    const first = checkConcurrentSessionCeiling(API_KEY_IDENTITY, {
      evictIdle: true,
    });
    const second = checkConcurrentSessionCeiling(API_KEY_IDENTITY, {
      evictIdle: true,
    });
    expect(first.allowed).toBe(true);
    expect(second.allowed).toBe(false);
    expect(countLiveSessionsForIdentity(API_KEY_IDENTITY)).toBe(1);
  });

  it("with the kill switch off, free-slot decisions stay identical to the old path", () => {
    process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL = "1";
    registerSessionCounter(counterReturning(0));
    const oldDecision = checkConcurrentSessionCeiling(API_KEY_IDENTITY);
    const oldLogs = [...loggerMock.warn.mock.calls];
    loggerMock.warn.mockClear();
    process.env.MCP_SESSION_CEILING_EVICT_IDLE = "false";
    const decision = checkConcurrentSessionCeiling(API_KEY_IDENTITY, {
      evictIdle: true,
    });
    expect(decision).toEqual(oldDecision);
    expect(loggerMock.warn.mock.calls).toEqual(oldLogs);
    expect(countLiveSessionsForIdentity(API_KEY_IDENTITY)).toBe(0);
  });

  it.each([
    "120junk",
    "1.5",
    "1e2",
    "Infinity",
    "9007199254740992",
    "9".repeat(400),
  ])("rejects a malformed or unsafe idle floor %s", (value) => {
    process.env.MCP_SESSION_CEILING_EVICT_MIN_IDLE_SECONDS = value;
    expect(resolveEvictionConfig().minIdleMs).toBe(120_000);
    expect(loggerMock.warn).toHaveBeenCalledTimes(1);
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

    const summary = summarizeCredentialSessions(API_KEY_IDENTITY);
    expect(summary.total).toBe(2);
    expect(summary.incomplete).toBe(true);
    // A skipped manager must not make the remaining sessions look complete.
    expect(formatCredentialSessionSummary(summary)).toBe("");
    expect(loggerMock.warn).toHaveBeenCalledTimes(1);
    expect(String(loggerMock.warn.mock.calls[0][0])).not.toContain("boom");
  });

  it("a probe that throws counts that session as untracked and does not stop the summary", () => {
    registerSessionCounter(
      listingCounter({ "key-1": sessions("s", "autotask", 3) }),
    );
    registerSessionActivityProbe((sessionId) => {
      if (sessionId.endsWith("-1")) throw new Error("private-probe-data");
      return { idleMs: 1000, inFlight: false };
    });

    const summary = summarizeCredentialSessions(API_KEY_IDENTITY);
    expect(summary).toMatchObject({ total: 3, idle: 2, untracked: 1 });
    expect(loggerMock.warn).toHaveBeenCalledTimes(1);
    expect(String(loggerMock.warn.mock.calls[0][0])).not.toContain(
      "private-probe-data",
    );
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
        throw new Error("private-lister-data");
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
    // The summary fault is visible, and the original refusal WARN still runs.
    expect(loggerMock.warn).toHaveBeenCalledTimes(2);
    expect(String(loggerMock.warn.mock.calls[0][0])).not.toContain(
      "private-lister-data",
    );
    expect(String(loggerMock.warn.mock.calls[1][0])).toMatch(
      /^Concurrent-session ceiling reached/,
    );
    expect(String(loggerMock.warn.mock.calls[1][0])).not.toContain(" live: ");
  });

  it("does not publish a partial breakdown when one of two listers fails", () => {
    process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL = "4";
    registerBusyCredential(2);
    registerSessionCounter({
      countSessionsForIdentity: () => 2,
      listSessionsForIdentity: () => {
        throw new Error("private session id");
      },
    });
    expect(checkConcurrentSessionCeiling(API_KEY_IDENTITY)).toEqual({
      allowed: false,
      current: 4,
      ceiling: 4,
      approaching: true,
    });
    expect(loggerMock.warn).toHaveBeenCalledTimes(2);
    expect(JSON.stringify(loggerMock.warn.mock.calls)).not.toContain(
      "private session id",
    );
  });

  it("reports a rendering fault without changing admission or leaking the fault object", () => {
    process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL = "1";
    registerSessionCounter({
      countSessionsForIdentity: () => 1,
      listSessionsForIdentity: () => [
        {
          sessionId: "private-session-id",
          endpointName: null as unknown as string,
        },
      ],
    });
    expect(checkConcurrentSessionCeiling(API_KEY_IDENTITY)).toEqual({
      allowed: false,
      current: 1,
      ceiling: 1,
      approaching: true,
    });
    expect(loggerMock.warn).toHaveBeenCalledTimes(2);
    expect(loggerMock.warn.mock.calls[0][0]).toBe(
      "Session ceiling summary could not be rendered; continuing admission check.",
    );
    expect(JSON.stringify(loggerMock.warn.mock.calls)).not.toContain(
      "private-session-id",
    );
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

describe("resolveEvictionConfig", () => {
  it("is on with a 120s idle floor by default", () => {
    expect(resolveEvictionConfig()).toEqual({
      enabled: true,
      minIdleMs: DEFAULT_CEILING_EVICT_MIN_IDLE_SECONDS * 1000,
    });
    expect(DEFAULT_CEILING_EVICT_MIN_IDLE_SECONDS).toBe(120);
    expect(loggerMock.warn).not.toHaveBeenCalled();
  });

  it("turns off for every recognised off value, in any case and padding", () => {
    for (const value of [
      "false",
      "0",
      "off",
      "no",
      "disable",
      "disabled",
      " FALSE ",
      "Off",
      "Disabled",
    ]) {
      process.env.MCP_SESSION_CEILING_EVICT_IDLE = value;
      expect(resolveEvictionConfig().enabled).toBe(false);
    }
    expect(loggerMock.warn).not.toHaveBeenCalled();
  });

  it("stays on for every recognised on value and for an empty value", () => {
    for (const value of [
      "true",
      "1",
      "on",
      "yes",
      "enable",
      "enabled",
      "TRUE",
      "",
    ]) {
      process.env.MCP_SESSION_CEILING_EVICT_IDLE = value;
      expect(resolveEvictionConfig().enabled).toBe(true);
    }
    expect(loggerMock.warn).not.toHaveBeenCalled();
  });

  it("falls back to on with a WARN for a malformed kill-switch value", () => {
    process.env.MCP_SESSION_CEILING_EVICT_IDLE = "fasle";
    expect(resolveEvictionConfig().enabled).toBe(true);
    expect(loggerMock.warn).toHaveBeenCalledTimes(1);
    expect(loggerMock.warn.mock.calls[0][0]).toBe(
      "MCP_SESSION_CEILING_EVICT_IDLE=fasle invalid; falling back to default true.",
    );
  });

  it("parses a configured idle floor in seconds", () => {
    process.env.MCP_SESSION_CEILING_EVICT_MIN_IDLE_SECONDS = "300";
    expect(resolveEvictionConfig().minIdleMs).toBe(300_000);
  });

  it("falls back to the default floor with a WARN on a malformed or negative value", () => {
    for (const value of ["soon", "-5"]) {
      vi.clearAllMocks();
      process.env.MCP_SESSION_CEILING_EVICT_MIN_IDLE_SECONDS = value;
      expect(resolveEvictionConfig().minIdleMs).toBe(120_000);
      expect(loggerMock.warn).toHaveBeenCalledTimes(1);
      expect(loggerMock.warn.mock.calls[0][0]).toContain(
        "falling back to default 120",
      );
    }
  });

  it("raises a floor below the minimum (including 0) to the minimum, with a WARN", () => {
    for (const value of ["0", "9"]) {
      vi.clearAllMocks();
      process.env.MCP_SESSION_CEILING_EVICT_MIN_IDLE_SECONDS = value;
      expect(resolveEvictionConfig().minIdleMs).toBe(
        MIN_CEILING_EVICT_MIN_IDLE_SECONDS * 1000,
      );
      expect(loggerMock.warn).toHaveBeenCalledTimes(1);
      expect(loggerMock.warn.mock.calls[0][0]).toContain(
        "is below the minimum; using 10.",
      );
    }
    vi.clearAllMocks();
    process.env.MCP_SESSION_CEILING_EVICT_MIN_IDLE_SECONDS = "10";
    expect(resolveEvictionConfig().minIdleMs).toBe(10_000);
    expect(loggerMock.warn).not.toHaveBeenCalled();
  });
});

/**
 * A counter that behaves like the StreamableHTTP manager behind its adapter:
 * lists per identity, and its evictor removes the session synchronously (the
 * contract the reservation logic depends on) and returns a teardown promise.
 */
function evictableCounter(
  byIdentity: Record<
    string,
    Array<{ sessionId: string; endpointName: string }>
  >,
  options: { evictReturns?: "promise" | "undefined" | "throw" } = {},
) {
  const evicted: string[] = [];
  const counter: IdentitySessionCounter & {
    evictSessionForAdmission: ReturnType<typeof vi.fn>;
  } = {
    countSessionsForIdentity: (identity: SessionIdentity) =>
      (byIdentity[identity.credentialId ?? ""] ?? []).length,
    listSessionsForIdentity: (identity: SessionIdentity) => [
      ...(byIdentity[identity.credentialId ?? ""] ?? []),
    ],
    evictSessionForAdmission: vi.fn((sessionId: string) => {
      if (options.evictReturns === "throw") {
        throw new Error("private-evictor-fault");
      }
      if (options.evictReturns === "undefined") {
        return undefined;
      }
      for (const list of Object.values(byIdentity)) {
        const index = list.findIndex((s) => s.sessionId === sessionId);
        if (index >= 0) list.splice(index, 1);
      }
      evicted.push(sessionId);
      return Promise.resolve();
    }),
  };
  return { counter, evicted };
}

/** Probe table: session id -> activity; unlisted ids are untracked. */
const activityTable =
  (table: Record<string, { idleMs: number; inFlight: boolean }>) =>
  (sessionId: string) =>
    table[sessionId];

const idle = (seconds: number) => ({ idleMs: seconds * 1000, inFlight: false });

describe("selectEvictionCandidate — which session the ceiling may evict", () => {
  const OTHER: SessionIdentity = { method: "api_key", credentialId: "key-2" };
  const MIN_IDLE = { minIdleMs: 120_000 };

  it("picks the credential's session that has been idle longest", () => {
    const { counter } = evictableCounter({
      "key-1": [
        { sessionId: "s-a", endpointName: "autotask" },
        { sessionId: "s-b", endpointName: "ninja" },
        { sessionId: "s-c", endpointName: "itglue" },
      ],
    });
    registerSessionCounter(counter);
    registerSessionActivityProbe(
      activityTable({ "s-a": idle(200), "s-b": idle(1700), "s-c": idle(600) }),
    );

    const candidate = selectEvictionCandidate(API_KEY_IDENTITY, MIN_IDLE);

    expect(candidate).toMatchObject({
      sessionId: "s-b",
      endpointName: "ninja",
      idleMs: 1_700_000,
    });
    expect(candidate?.counter).toBe(counter);
  });

  it("never picks a session with a request or an open stream in flight, however old", () => {
    const { counter } = evictableCounter({
      "key-1": [
        { sessionId: "s-stream", endpointName: "autotask" },
        { sessionId: "s-idle", endpointName: "autotask" },
      ],
    });
    registerSessionCounter(counter);
    registerSessionActivityProbe(
      activityTable({
        "s-stream": { idleMs: 9_000_000, inFlight: true },
        "s-idle": idle(130),
      }),
    );

    expect(selectEvictionCandidate(API_KEY_IDENTITY, MIN_IDLE)?.sessionId).toBe(
      "s-idle",
    );
  });

  it("never picks a session idle for less than the floor", () => {
    const { counter } = evictableCounter({
      "key-1": [{ sessionId: "s-recent", endpointName: "autotask" }],
    });
    registerSessionCounter(counter);
    registerSessionActivityProbe(activityTable({ "s-recent": idle(119) }));

    expect(selectEvictionCandidate(API_KEY_IDENTITY, MIN_IDLE)).toBeUndefined();
  });

  it("counts exactly the floor as eligible", () => {
    const { counter } = evictableCounter({
      "key-1": [{ sessionId: "s-edge", endpointName: "autotask" }],
    });
    registerSessionCounter(counter);
    registerSessionActivityProbe(activityTable({ "s-edge": idle(120) }));

    expect(selectEvictionCandidate(API_KEY_IDENTITY, MIN_IDLE)?.sessionId).toBe(
      "s-edge",
    );
  });

  it("never picks a session no probe tracks", () => {
    const { counter } = evictableCounter({
      "key-1": [{ sessionId: "s-untracked", endpointName: "autotask" }],
    });
    registerSessionCounter(counter);
    registerSessionActivityProbe(activityTable({}));

    expect(selectEvictionCandidate(API_KEY_IDENTITY, MIN_IDLE)).toBeUndefined();
  });

  it("never picks a session from a counter without an evictor (the SSE manager)", () => {
    // Listed and reported idle, but its counter cannot evict: an SSE session
    // is one open stream, never an idle orphan.
    registerSessionCounter({
      countSessionsForIdentity: () => 1,
      listSessionsForIdentity: () => [
        { sessionId: "s-sse", endpointName: "autotask" },
      ],
    });
    registerSessionActivityProbe(activityTable({ "s-sse": idle(5000) }));

    expect(selectEvictionCandidate(API_KEY_IDENTITY, MIN_IDLE)).toBeUndefined();
  });

  it("never picks another credential's session", () => {
    const { counter } = evictableCounter({
      "key-1": [{ sessionId: "s-mine", endpointName: "autotask" }],
      "key-2": [{ sessionId: "s-theirs", endpointName: "autotask" }],
    });
    registerSessionCounter(counter);
    registerSessionActivityProbe(
      activityTable({ "s-mine": idle(10), "s-theirs": idle(9000) }),
    );

    // key-1's only session is under the floor; key-2's idle one is NOT a
    // fallback, however much older it is.
    expect(selectEvictionCandidate(API_KEY_IDENTITY, MIN_IDLE)).toBeUndefined();
    expect(selectEvictionCandidate(OTHER, MIN_IDLE)?.sessionId).toBe(
      "s-theirs",
    );
  });

  it("breaks an idle-time tie by session id, so the choice is deterministic", () => {
    const { counter } = evictableCounter({
      "key-1": [
        { sessionId: "s-z", endpointName: "autotask" },
        { sessionId: "s-a", endpointName: "autotask" },
      ],
    });
    registerSessionCounter(counter);
    registerSessionActivityProbe(
      activityTable({ "s-z": idle(500), "s-a": idle(500) }),
    );

    expect(selectEvictionCandidate(API_KEY_IDENTITY, MIN_IDLE)?.sessionId).toBe(
      "s-a",
    );
  });

  it("never evicts for an anonymous identity", () => {
    const { counter } = evictableCounter({
      "": [{ sessionId: "s-anon", endpointName: "public" }],
    });
    registerSessionCounter(counter);
    registerSessionActivityProbe(activityTable({ "s-anon": idle(5000) }));

    expect(
      selectEvictionCandidate(
        { method: "anonymous", credentialId: null },
        MIN_IDLE,
      ),
    ).toBeUndefined();
  });

  it("skips a faulting lister or probe, reports counts only, and still chooses from the rest", () => {
    registerSessionCounter({
      countSessionsForIdentity: () => 1,
      listSessionsForIdentity: () => {
        throw new Error("private-lister-data");
      },
      evictSessionForAdmission: () => Promise.resolve(),
    });
    const { counter } = evictableCounter({
      "key-1": [
        { sessionId: "s-faulty", endpointName: "autotask" },
        { sessionId: "s-ok", endpointName: "autotask" },
      ],
    });
    registerSessionCounter(counter);
    registerSessionActivityProbe((sessionId) => {
      if (sessionId === "s-faulty") throw new Error("private-probe-data");
      return idle(300);
    });

    expect(selectEvictionCandidate(API_KEY_IDENTITY, MIN_IDLE)?.sessionId).toBe(
      "s-ok",
    );
    expect(loggerMock.warn).toHaveBeenCalledTimes(1);
    const message = String(loggerMock.warn.mock.calls[0][0]);
    expect(message).toBe(
      "Session ceiling eviction scan degraded: 1 lister faults, 1 activity probe faults.",
    );
  });
});

describe("checkConcurrentSessionCeiling — evicting an idle session at the ceiling", () => {
  function atCeilingWithIdleSessions(
    sessions: Array<{ sessionId: string; endpointName: string; idleS: number }>,
  ) {
    process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL = String(sessions.length);
    const listed = sessions.map(({ sessionId, endpointName }) => ({
      sessionId,
      endpointName,
    }));
    const harness = evictableCounter({ "key-1": listed });
    registerSessionCounter(harness.counter);
    registerSessionActivityProbe(
      activityTable(
        Object.fromEntries(sessions.map((s) => [s.sessionId, idle(s.idleS)])),
      ),
    );
    return harness;
  }

  const REFUSAL_WARN =
    'Concurrent-session ceiling reached for api_key credential "Example": 2/2 live sessions; refusing a new session. Raise MCP_MAX_SESSIONS_PER_CREDENTIAL if this is a legitimate consumer.';

  it("evicts the longest-idle session and admits, logging one INFO line and no refusal WARN", async () => {
    const { counter, evicted } = atCeilingWithIdleSessions([
      { sessionId: "s-1", endpointName: "autotask", idleS: 300 },
      { sessionId: "s-2", endpointName: "ninja", idleS: 1710 },
    ]);

    const decision = checkConcurrentSessionCeiling(API_KEY_IDENTITY, {
      label: "Example",
      evictIdle: true,
    });

    expect(decision.allowed).toBe(true);
    expect(decision.current).toBe(2);
    expect(decision.ceiling).toBe(2);
    expect(decision.approaching).toBe(true);
    expect(decision.eviction).toMatchObject({
      endpointName: "ninja",
      idleSeconds: 1710,
    });
    expect(counter.evictSessionForAdmission).toHaveBeenCalledTimes(1);
    expect(counter.evictSessionForAdmission).toHaveBeenCalledWith("s-2");
    expect(evicted).toEqual(["s-2"]);
    await expect(decision.eviction?.teardownWait).resolves.toBeUndefined();

    expect(loggerMock.warn).not.toHaveBeenCalled();
    expect(loggerMock.info).toHaveBeenCalledTimes(1);
    expect(loggerMock.info.mock.calls[0][0]).toBe(
      'Concurrent-session ceiling: evicted idle session on ninja (idle 1710s) for api_key credential "Example" to admit a new session (2/2) live: autotask=1, ninja=1; in-flight 0, idle 2, oldest idle 1710s',
    );
  });

  it("holds the freed slot until release, so the count stays at the ceiling", () => {
    atCeilingWithIdleSessions([
      { sessionId: "s-1", endpointName: "autotask", idleS: 300 },
      { sessionId: "s-2", endpointName: "autotask", idleS: 400 },
    ]);

    const decision = checkConcurrentSessionCeiling(API_KEY_IDENTITY, {
      evictIdle: true,
    });

    // One session left the manager; the reservation takes its place.
    expect(countLiveSessionsForIdentity(API_KEY_IDENTITY)).toBe(2);
    decision.eviction?.release();
    expect(countLiveSessionsForIdentity(API_KEY_IDENTITY)).toBe(1);
    // Idempotent: a second release (the router's `finally`) changes nothing.
    decision.eviction?.release();
    expect(countLiveSessionsForIdentity(API_KEY_IDENTITY)).toBe(1);
  });

  it("concurrent admissions evict DISTINCT victims, then refuse once none is left", () => {
    const { evicted } = atCeilingWithIdleSessions([
      { sessionId: "s-1", endpointName: "autotask", idleS: 300 },
      { sessionId: "s-2", endpointName: "autotask", idleS: 900 },
      { sessionId: "s-3", endpointName: "autotask", idleS: 600 },
    ]);

    // Three admissions arrive before any of them registers its session.
    const decisions = [1, 2, 3, 4].map(() =>
      checkConcurrentSessionCeiling(API_KEY_IDENTITY, { evictIdle: true }),
    );

    expect(decisions.slice(0, 3).every((d) => d.allowed)).toBe(true);
    expect(evicted).toEqual(["s-2", "s-3", "s-1"]);
    // The fourth found nothing left to evict and is refused exactly as today.
    expect(decisions[3]).toEqual({
      allowed: false,
      current: 3,
      ceiling: 3,
      approaching: true,
    });
    expect(countLiveSessionsForIdentity(API_KEY_IDENTITY)).toBe(3);
  });

  it("refuses with today's exact WARN and decision when nothing is eligible", () => {
    const { counter } = atCeilingWithIdleSessions([
      { sessionId: "s-1", endpointName: "autotask", idleS: 30 },
      { sessionId: "s-2", endpointName: "autotask", idleS: 60 },
    ]);
    const without = checkConcurrentSessionCeiling(API_KEY_IDENTITY, {
      label: "Example",
    });
    vi.clearAllMocks();

    const withEvict = checkConcurrentSessionCeiling(API_KEY_IDENTITY, {
      label: "Example",
      evictIdle: true,
    });

    expect(withEvict).toEqual(without);
    expect(withEvict.allowed).toBe(false);
    expect(counter.evictSessionForAdmission).not.toHaveBeenCalled();
    expect(loggerMock.warn).toHaveBeenCalledTimes(1);
    expect(
      String(loggerMock.warn.mock.calls[0][0]).startsWith(REFUSAL_WARN),
    ).toBe(true);
    expect(loggerMock.info).not.toHaveBeenCalled();
  });

  it("kill switch off: refuses exactly as today and never calls the evictor", () => {
    process.env.MCP_SESSION_CEILING_EVICT_IDLE = "false";
    const { counter } = atCeilingWithIdleSessions([
      { sessionId: "s-1", endpointName: "autotask", idleS: 5000 },
      { sessionId: "s-2", endpointName: "autotask", idleS: 6000 },
    ]);

    const decision = checkConcurrentSessionCeiling(API_KEY_IDENTITY, {
      label: "Example",
      evictIdle: true,
    });

    expect(decision.allowed).toBe(false);
    expect(decision.eviction).toBeUndefined();
    expect(counter.evictSessionForAdmission).not.toHaveBeenCalled();
    expect(loggerMock.warn).toHaveBeenCalledTimes(1);
    expect(
      String(loggerMock.warn.mock.calls[0][0]).startsWith(REFUSAL_WARN),
    ).toBe(true);
    expect(countLiveSessionsForIdentity(API_KEY_IDENTITY)).toBe(2);
  });

  it("never evicts without the caller opting in", () => {
    const { counter } = atCeilingWithIdleSessions([
      { sessionId: "s-1", endpointName: "autotask", idleS: 5000 },
    ]);

    const decision = checkConcurrentSessionCeiling(API_KEY_IDENTITY);

    expect(decision.allowed).toBe(false);
    expect(counter.evictSessionForAdmission).not.toHaveBeenCalled();
  });

  it("never evicts below the ceiling", () => {
    process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL = "3";
    const { counter } = evictableCounter({
      "key-1": [
        { sessionId: "s-1", endpointName: "autotask" },
        { sessionId: "s-2", endpointName: "autotask" },
      ],
    });
    registerSessionCounter(counter);
    registerSessionActivityProbe(() => idle(5000));

    const decision = checkConcurrentSessionCeiling(API_KEY_IDENTITY, {
      evictIdle: true,
    });

    expect(decision.allowed).toBe(true);
    expect(decision.eviction).toBeUndefined();
    expect(counter.evictSessionForAdmission).not.toHaveBeenCalled();
  });

  it("refuses as before when the evictor declines (session busy or gone after all)", () => {
    process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL = "1";
    const { counter } = evictableCounter(
      { "key-1": [{ sessionId: "s-1", endpointName: "autotask" }] },
      { evictReturns: "undefined" },
    );
    registerSessionCounter(counter);
    registerSessionActivityProbe(() => idle(5000));

    const decision = checkConcurrentSessionCeiling(API_KEY_IDENTITY, {
      evictIdle: true,
    });

    expect(decision.allowed).toBe(false);
    expect(counter.evictSessionForAdmission).toHaveBeenCalledWith("s-1");
    // Nothing reserved: the count is just the session that is still there.
    expect(countLiveSessionsForIdentity(API_KEY_IDENTITY)).toBe(1);
    expect(String(loggerMock.warn.mock.calls[0][0])).toMatch(
      /^Concurrent-session ceiling reached for api_key credential: 1\/1/,
    );
  });

  it("a throwing evictor falls back to the refusal and never leaks the fault", () => {
    process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL = "1";
    const { counter } = evictableCounter(
      { "key-1": [{ sessionId: "s-1", endpointName: "autotask" }] },
      { evictReturns: "throw" },
    );
    registerSessionCounter(counter);
    registerSessionActivityProbe(() => idle(5000));

    const decision = checkConcurrentSessionCeiling(API_KEY_IDENTITY, {
      evictIdle: true,
    });

    expect(decision.allowed).toBe(false);
    expect(loggerMock.warn).toHaveBeenCalledTimes(2);
    expect(loggerMock.warn.mock.calls[0][0]).toBe(
      "Session ceiling eviction faulted; refusing the new session as before.",
    );
    expect(String(loggerMock.warn.mock.calls[1][0])).toMatch(
      /^Concurrent-session ceiling reached/,
    );
    expect(JSON.stringify(loggerMock.warn.mock.calls)).not.toContain(
      "private-evictor-fault",
    );
  });

  it("a teardown that rejects despite the contract is reported and never rejects the admission", async () => {
    process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL = "1";
    registerSessionCounter({
      countSessionsForIdentity: () => 1,
      listSessionsForIdentity: () => [
        { sessionId: "s-1", endpointName: "autotask" },
      ],
      evictSessionForAdmission: () =>
        Promise.reject(new Error("private-teardown-fault")),
    });
    registerSessionActivityProbe(() => idle(5000));

    const decision = checkConcurrentSessionCeiling(API_KEY_IDENTITY, {
      evictIdle: true,
    });

    expect(decision.allowed).toBe(true);
    await expect(decision.eviction?.teardownWait).resolves.toBeUndefined();
    expect(loggerMock.warn).toHaveBeenCalledWith(
      "Session ceiling eviction: the evicted session's teardown rejected; admitting the new session anyway.",
    );
    expect(JSON.stringify(loggerMock.warn.mock.calls)).not.toContain(
      "private-teardown-fault",
    );
    decision.eviction?.release();
  });

  it("never puts a session id in the INFO line or the decision", () => {
    process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL = "1";
    const uuid = "0b3f6c1e-aaaa-4bbb-8ccc-000000000001";
    const { counter } = evictableCounter({
      "key-1": [{ sessionId: uuid, endpointName: 'bad\nname"x' }],
    });
    registerSessionCounter(counter);
    registerSessionActivityProbe(() => idle(5000));

    const decision = checkConcurrentSessionCeiling(API_KEY_IDENTITY, {
      evictIdle: true,
    });

    const line = String(loggerMock.info.mock.calls[0][0]);
    expect(line).not.toContain(uuid);
    expect(JSON.stringify(decision)).not.toContain(uuid);
    // The victim's endpoint name goes through the same log-safe reduction as
    // the summary, so it cannot forge a second line.
    expect(decision.eviction?.endpointName).toBe("bad?name?x");
    expect(line).not.toContain("\n");
    decision.eviction?.release();
  });

  it("releases the reserved slot itself when the INFO line throws, since the caller never gets the eviction", () => {
    const { evicted } = atCeilingWithIdleSessions([
      { sessionId: "s-1", endpointName: "autotask", idleS: 300 },
      { sessionId: "s-2", endpointName: "autotask", idleS: 900 },
    ]);
    loggerMock.info.mockImplementationOnce(() => {
      throw new Error("log sink down");
    });

    expect(() =>
      checkConcurrentSessionCeiling(API_KEY_IDENTITY, { evictIdle: true }),
    ).toThrow("log sink down");

    // The victim is gone and nothing holds its slot: one session left.
    expect(evicted).toEqual(["s-2"]);
    expect(countLiveSessionsForIdentity(API_KEY_IDENTITY)).toBe(1);
  });

  it("a listing that cannot be rendered faults BEFORE anything is evicted, so nothing is reserved", () => {
    process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL = "1";
    const { counter } = evictableCounter({
      // Not a string: the log-safe reduction of the name throws.
      "key-1": [{ sessionId: "s-1", endpointName: 42 as unknown as string }],
    });
    registerSessionCounter(counter);
    registerSessionActivityProbe(() => idle(5000));

    const decision = checkConcurrentSessionCeiling(API_KEY_IDENTITY, {
      evictIdle: true,
    });

    expect(decision.allowed).toBe(false);
    expect(counter.evictSessionForAdmission).not.toHaveBeenCalled();
    expect(countLiveSessionsForIdentity(API_KEY_IDENTITY)).toBe(1);
    expect(loggerMock.warn).toHaveBeenCalledWith(
      "Session ceiling eviction faulted; refusing the new session as before.",
    );
  });
});

describe("checkConcurrentSessionCeiling: the admission's wait on the victim's teardown is bounded", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  /** One idle session at a ceiling of one, evicted with the given teardown. */
  function atCeilingWithTeardown(teardown: Promise<void>) {
    process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL = "1";
    let resident = true;
    registerSessionCounter({
      countSessionsForIdentity: () => (resident ? 1 : 0),
      listSessionsForIdentity: () =>
        resident ? [{ sessionId: "s-1", endpointName: "autotask" }] : [],
      evictSessionForAdmission: () => {
        resident = false;
        return teardown;
      },
    });
    registerSessionActivityProbe(() => idle(5000));
  }

  it("is 5 seconds", () => {
    expect(EVICTION_ADMISSION_WAIT_MS).toBe(5_000);
  });

  it("settles after the bound, with one WARN, when the teardown hangs; the slot stays reserved until release", async () => {
    vi.useFakeTimers();
    atCeilingWithTeardown(new Promise<void>(() => {}));
    const decision = checkConcurrentSessionCeiling(API_KEY_IDENTITY, {
      evictIdle: true,
    });
    expect(decision.allowed).toBe(true);
    let settled = false;
    void decision.eviction?.teardownWait.then(() => {
      settled = true;
    });

    await vi.advanceTimersByTimeAsync(EVICTION_ADMISSION_WAIT_MS - 1);
    expect(settled).toBe(false);
    expect(loggerMock.warn).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(1);
    expect(settled).toBe(true);
    expect(loggerMock.warn).toHaveBeenCalledTimes(1);
    expect(loggerMock.warn.mock.calls[0][0]).toBe(
      "Session ceiling eviction: the evicted session's teardown on autotask has not finished after 5000 ms; admitting the new session without waiting for it. The teardown continues in the background.",
    );
    // Timing out the wait hands nothing back by itself; the caller still owns
    // the reservation until its session is registered.
    expect(countLiveSessionsForIdentity(API_KEY_IDENTITY)).toBe(1);
    decision.eviction?.release();
    expect(countLiveSessionsForIdentity(API_KEY_IDENTITY)).toBe(0);
  });

  it("settles with the teardown when it finishes first, clears its timer and logs nothing", async () => {
    vi.useFakeTimers();
    let finish!: () => void;
    atCeilingWithTeardown(
      new Promise<void>((resolve) => {
        finish = resolve;
      }),
    );
    const decision = checkConcurrentSessionCeiling(API_KEY_IDENTITY, {
      evictIdle: true,
    });
    let settled = false;
    void decision.eviction?.teardownWait.then(() => {
      settled = true;
    });

    await vi.advanceTimersByTimeAsync(1_000);
    expect(settled).toBe(false);
    finish();
    await vi.advanceTimersByTimeAsync(0);

    expect(settled).toBe(true);
    expect(vi.getTimerCount()).toBe(0);
    await vi.advanceTimersByTimeAsync(EVICTION_ADMISSION_WAIT_MS);
    expect(loggerMock.warn).not.toHaveBeenCalled();
    decision.eviction?.release();
  });
});
