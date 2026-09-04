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
