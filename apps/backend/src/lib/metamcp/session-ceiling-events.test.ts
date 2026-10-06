/**
 * Throttled, durable observability for the per-credential session ceiling.
 *
 * The helper records a `client`-category gateway event when a credential is
 * refused by the ceiling and when one first crosses the 80% mark, naming the
 * credential by its display name. It is throttled PER (credential, endpoint,
 * kind) to one event per interval, folds the suppressed count into the next
 * emitted message, and must never throw into the session-creation path.
 *
 * `log-store` is mocked at the module seam: it reaches the durable gateway sink
 * and therefore `db/index`, which throws without DATABASE_URL. Only the
 * envelope this helper builds is under test here.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";

const { recordMock } = vi.hoisted(() => ({ recordMock: vi.fn() }));

vi.mock("./log-store", () => ({
  metamcpLogStore: { record: recordMock },
}));

import type { CeilingDecision } from "./credential-session-quota";
import type { SessionIdentity } from "./session-auth";
import {
  __resetSessionCeilingThrottleForTesting,
  recordSessionCeilingEvent,
  SESSION_CEILING_EVENT_INTERVAL_MS,
} from "./session-ceiling-events";

const identityA: SessionIdentity = { method: "api_key", credentialId: "key-A" };
const identityB: SessionIdentity = { method: "api_key", credentialId: "key-B" };

const refused = (): CeilingDecision => ({
  allowed: false,
  current: 101,
  ceiling: 100,
  approaching: true,
});

const approaching = (): CeilingDecision => ({
  allowed: true,
  current: 81,
  ceiling: 100,
  approaching: true,
});

const evicted = (): CeilingDecision => ({
  allowed: true,
  current: 300,
  ceiling: 300,
  approaching: true,
  eviction: {
    endpointName: "ninja",
    idleSeconds: 1710,
    teardownWait: Promise.resolve(),
    release: () => {},
  },
});

const belowThreshold = (): CeilingDecision => ({
  allowed: true,
  current: 40,
  ceiling: 100,
  approaching: false,
});

beforeEach(() => {
  vi.clearAllMocks();
  __resetSessionCeilingThrottleForTesting();
});

describe("recordSessionCeilingEvent — what it emits", () => {
  it("emits a refused event on the first refusal, naming the credential", () => {
    recordSessionCeilingEvent({
      identity: identityA,
      endpointName: "ep-1",
      label: "Autotask connector",
      decision: refused(),
    });

    expect(recordMock).toHaveBeenCalledTimes(1);
    const entry = recordMock.mock.calls[0][0];
    expect(entry.category).toBe("client");
    expect(entry.serverName).toBe("ep-1");
    expect(entry.level).toBe("warn");
    expect(entry.clientName).toBe("Autotask connector");
    expect(entry.message).toBe(
      "session refused: concurrent-session ceiling reached (101/100)",
    );
  });

  it("emits an approaching event when allowed but at the 80% threshold", () => {
    recordSessionCeilingEvent({
      identity: identityA,
      endpointName: "ep-1",
      label: "user@example.test",
      decision: approaching(),
    });

    expect(recordMock).toHaveBeenCalledTimes(1);
    const entry = recordMock.mock.calls[0][0];
    expect(entry.clientName).toBe("user@example.test");
    expect(entry.message).toBe(
      "concurrent sessions at 81/100, approaching the ceiling",
    );
  });

  it("emits nothing when the decision allowed and the credential is below the threshold", () => {
    recordSessionCeilingEvent({
      identity: identityA,
      endpointName: "ep-1",
      decision: belowThreshold(),
    });

    expect(recordMock).not.toHaveBeenCalled();
  });

  it("passes the label through as-is and emits without one when absent", () => {
    recordSessionCeilingEvent({
      identity: identityA,
      endpointName: "ep-1",
      decision: refused(),
    });

    expect(recordMock).toHaveBeenCalledTimes(1);
    expect(recordMock.mock.calls[0][0].clientName).toBeUndefined();
  });
});

describe("recordSessionCeilingEvent — the throttle", () => {
  it("emits the first refusal and suppresses the rest of the window", () => {
    for (let i = 0; i < 6; i += 1) {
      recordSessionCeilingEvent({
        identity: identityA,
        endpointName: "ep-1",
        label: "x",
        decision: refused(),
      });
    }

    expect(recordMock).toHaveBeenCalledTimes(1);
  });

  it("emits again after the interval, folding the suppressed count into the message", () => {
    // A pinned credential refuses hundreds of times an hour; the volume is the
    // question an operator asks, so it must survive the throttle even though
    // per-attempt events do not.
    recordSessionCeilingEvent({
      identity: identityA,
      endpointName: "ep-1",
      label: "x",
      decision: refused(),
    });
    for (let i = 0; i < 318; i += 1) {
      recordSessionCeilingEvent({
        identity: identityA,
        endpointName: "ep-1",
        label: "x",
        decision: refused(),
      });
    }

    expect(recordMock).toHaveBeenCalledTimes(1);

    vi.useFakeTimers();
    try {
      vi.setSystemTime(Date.now() + SESSION_CEILING_EVENT_INTERVAL_MS + 1);
      recordSessionCeilingEvent({
        identity: identityA,
        endpointName: "ep-1",
        label: "x",
        decision: refused(),
      });
    } finally {
      vi.useRealTimers();
    }

    expect(recordMock).toHaveBeenCalledTimes(2);
    expect(recordMock.mock.calls[1][0].message).toBe(
      "session refused: concurrent-session ceiling reached (101/100) " +
        "(318 more refusals suppressed in the last 60s)",
    );
  });

  it("keys per credential — a noisy credential never hides another's first refusal", () => {
    recordSessionCeilingEvent({
      identity: identityA,
      endpointName: "ep-1",
      decision: refused(),
    });
    recordSessionCeilingEvent({
      identity: identityA,
      endpointName: "ep-1",
      decision: refused(),
    });
    recordSessionCeilingEvent({
      identity: identityB,
      endpointName: "ep-1",
      decision: refused(),
    });

    expect(recordMock).toHaveBeenCalledTimes(2);
  });

  it("keys per endpoint — the same credential on a different endpoint emits its own first event", () => {
    recordSessionCeilingEvent({
      identity: identityA,
      endpointName: "ep-1",
      decision: refused(),
    });
    recordSessionCeilingEvent({
      identity: identityA,
      endpointName: "ep-2",
      decision: refused(),
    });

    expect(recordMock).toHaveBeenCalledTimes(2);
  });

  it("keys per kind — a refusal and an approaching from the same credential and endpoint both emit", () => {
    recordSessionCeilingEvent({
      identity: identityA,
      endpointName: "ep-1",
      decision: approaching(),
    });
    recordSessionCeilingEvent({
      identity: identityA,
      endpointName: "ep-1",
      decision: refused(),
    });
    // ...while a repeat of either kind is still collapsed.
    recordSessionCeilingEvent({
      identity: identityA,
      endpointName: "ep-1",
      decision: approaching(),
    });

    expect(recordMock).toHaveBeenCalledTimes(2);
    expect(recordMock.mock.calls.map((call) => call[0].message)).toEqual([
      "concurrent sessions at 81/100, approaching the ceiling",
      "session refused: concurrent-session ceiling reached (101/100)",
    ]);
  });
});

describe("recordSessionCeilingEvent — it never throws into the request path", () => {
  it("swallows a throwing store rather than failing the session-creation path", () => {
    recordMock.mockImplementationOnce(() => {
      throw new Error("log store down");
    });

    expect(() =>
      recordSessionCeilingEvent({
        identity: identityA,
        endpointName: "ep-1",
        label: "x",
        decision: refused(),
      }),
    ).not.toThrow();
  });
});

describe("recordSessionCeilingEvent — the live summary", () => {
  const SUMMARY =
    "live: autotask=21, itglue=21, ninja=21 (top 3 of 14 endpoints); in-flight 187, idle 113, oldest idle 1710s";

  it("appends the summary to a refused event, after the existing text", () => {
    recordSessionCeilingEvent({
      identity: identityA,
      endpointName: "ep-1",
      label: "Autotask connector",
      decision: { ...refused(), liveSummary: SUMMARY },
    });

    const entry = recordMock.mock.calls[0][0];
    expect(entry.message).toBe(
      `session refused: concurrent-session ceiling reached (101/100); ${SUMMARY}`,
    );
    expect(entry.message.length).toBeLessThan(300);
  });

  it("appends it to an approaching event", () => {
    recordSessionCeilingEvent({
      identity: identityA,
      endpointName: "ep-1",
      decision: { ...approaching(), liveSummary: SUMMARY },
    });
    expect(recordMock.mock.calls[0][0].message).toBe(
      `concurrent sessions at 81/100, approaching the ceiling; ${SUMMARY}`,
    );
  });

  it("keeps the suppressed count and still stays under 300 characters", () => {
    const decision = { ...refused(), liveSummary: SUMMARY };
    recordSessionCeilingEvent({
      identity: identityA,
      endpointName: "ep-1",
      decision,
    });
    recordSessionCeilingEvent({
      identity: identityA,
      endpointName: "ep-1",
      decision,
    });
    vi.useFakeTimers();
    try {
      vi.setSystemTime(Date.now() + SESSION_CEILING_EVENT_INTERVAL_MS + 1);
      recordSessionCeilingEvent({
        identity: identityA,
        endpointName: "ep-1",
        decision,
      });
    } finally {
      vi.useRealTimers();
    }

    expect(recordMock).toHaveBeenCalledTimes(2);
    const second = recordMock.mock.calls[1][0].message as string;
    expect(second).toContain("(1 more refusals suppressed in the last 60s)");
    expect(second.endsWith(SUMMARY)).toBe(true);
    expect(second.length).toBeLessThan(300);
  });

  it("is unchanged when the decision carries no summary", () => {
    recordSessionCeilingEvent({
      identity: identityA,
      endpointName: "ep-1",
      decision: refused(),
    });
    expect(recordMock.mock.calls[0][0].message).toBe(
      "session refused: concurrent-session ceiling reached (101/100)",
    );
  });
});

describe("recordSessionCeilingEvent — evictions", () => {
  it("emits an info-level evicted event naming the victim's endpoint and idle time", () => {
    recordSessionCeilingEvent({
      identity: identityA,
      endpointName: "ep-1",
      label: "cowork workspace",
      decision: evicted(),
    });

    expect(recordMock).toHaveBeenCalledTimes(1);
    const entry = recordMock.mock.calls[0][0];
    expect(entry.category).toBe("client");
    expect(entry.serverName).toBe("ep-1");
    // Nothing was turned away, so a refusal stays the only warn-level outcome.
    expect(entry.level).toBe("info");
    expect(entry.clientName).toBe("cowork workspace");
    expect(entry.message).toBe(
      "idle session evicted to admit a new session at the concurrent-session ceiling (300/300): ninja, idle 1710s",
    );
  });

  it("is an eviction, not an approaching warning, even though the credential is past 80%", () => {
    recordSessionCeilingEvent({
      identity: identityA,
      endpointName: "ep-1",
      decision: evicted(),
    });
    expect(recordMock.mock.calls[0][0].message).not.toContain("approaching");
  });

  it("collapses a burst of evictions into one event and folds the count into the next", () => {
    for (let i = 0; i < 16; i += 1) {
      recordSessionCeilingEvent({
        identity: identityA,
        endpointName: "ep-1",
        decision: evicted(),
      });
    }
    expect(recordMock).toHaveBeenCalledTimes(1);

    vi.useFakeTimers();
    try {
      vi.setSystemTime(Date.now() + SESSION_CEILING_EVENT_INTERVAL_MS + 1);
      recordSessionCeilingEvent({
        identity: identityA,
        endpointName: "ep-1",
        decision: { ...evicted(), liveSummary: "live: ninja=300; idle 300" },
      });
    } finally {
      vi.useRealTimers();
    }

    expect(recordMock).toHaveBeenCalledTimes(2);
    expect(recordMock.mock.calls[1][0].message).toBe(
      "idle session evicted to admit a new session at the concurrent-session ceiling (300/300): ninja, idle 1710s " +
        "(15 more evictions suppressed in the last 60s); live: ninja=300; idle 300",
    );
  });

  it("throttles evictions separately from refusals and approaching warnings", () => {
    recordSessionCeilingEvent({
      identity: identityA,
      endpointName: "ep-1",
      decision: refused(),
    });
    recordSessionCeilingEvent({
      identity: identityA,
      endpointName: "ep-1",
      decision: approaching(),
    });
    recordSessionCeilingEvent({
      identity: identityA,
      endpointName: "ep-1",
      decision: evicted(),
    });
    // A repeat of the eviction inside the window is collapsed...
    recordSessionCeilingEvent({
      identity: identityA,
      endpointName: "ep-1",
      decision: evicted(),
    });
    // ...but another credential's first eviction is not hidden by it.
    recordSessionCeilingEvent({
      identity: identityB,
      endpointName: "ep-1",
      decision: evicted(),
    });

    expect(recordMock).toHaveBeenCalledTimes(4);
    expect(recordMock.mock.calls.map((call) => call[0].level)).toEqual([
      "warn",
      "warn",
      "info",
      "info",
    ]);
  });
});
