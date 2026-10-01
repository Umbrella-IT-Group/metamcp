/**
 * Unit tests for the session-binding mechanism. A public session is keyed in
 * memory by `Mcp-Session-Id` alone; the binding records the endpoint it was
 * created against AND the credential that created it, so a lookup can reject
 * an id presented on a DIFFERENT endpoint (the original cross-endpoint replay
 * hole, PR #84 review round) or under a DIFFERENT credential on the same
 * endpoint.
 *
 * `bindingMatches` is the endpoint-only predicate the persisted-row guards
 * use; `boundSessionMatches` is the endpoint + identity predicate every
 * in-memory lookup funnels through.
 */
import { describe, expect, it, vi } from "vitest";

vi.mock("@/utils/logger", () => ({
  default: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

// config.service reaches @/db transitively; the binding tests never call the
// TTL path, but the import graph still resolves it.
vi.mock("@/db", () => ({ db: {}, pool: { on: vi.fn() } }));

import { PublicSessionSweeper } from "../routers/public-metamcp/public-session-sweeper";
import {
  checkConcurrentSessionCeiling,
  registerSessionActivityProbe,
  registerSessionCounter,
  resetSessionCountersForTests,
} from "./metamcp/credential-session-quota";
import type { SessionIdentity } from "./metamcp/session-auth";
import {
  bindingMatches,
  boundSessionMatches,
  classifyBindingDenial,
  SessionLifetimeManagerImpl,
} from "./session-lifetime-manager";

const KEY_A: SessionIdentity = { method: "api_key", credentialId: "key-A" };
const KEY_B: SessionIdentity = { method: "api_key", credentialId: "key-B" };

describe("bindingMatches — the endpoint-only predicate", () => {
  const target = { namespaceUuid: "ns-A", endpointName: "ep-A" };

  it("matches only when BOTH namespace uuid and endpoint name agree", () => {
    expect(bindingMatches({ ...target }, target)).toBe(true);
  });

  it("rejects a namespace mismatch", () => {
    expect(
      bindingMatches({ namespaceUuid: "ns-B", endpointName: "ep-A" }, target),
    ).toBe(false);
  });

  it("rejects an endpoint-name mismatch (same namespace)", () => {
    expect(
      bindingMatches({ namespaceUuid: "ns-A", endpointName: "ep-B" }, target),
    ).toBe(false);
  });

  it("treats a missing binding as a non-match (session with no recorded binding is never served)", () => {
    expect(bindingMatches(undefined, target)).toBe(false);
  });
});

describe("boundSessionMatches — endpoint AND creating credential", () => {
  const target = {
    namespaceUuid: "ns-A",
    endpointName: "ep-A",
    identity: KEY_A,
  };

  it("matches when the endpoint and the identity both agree", () => {
    expect(boundSessionMatches({ ...target }, target)).toBe(true);
  });

  it("rejects the SAME endpoint under a different credential", () => {
    expect(boundSessionMatches({ ...target, identity: KEY_B }, target)).toBe(
      false,
    );
  });

  it("still rejects a cross-endpoint presentation by the SAME credential", () => {
    expect(
      boundSessionMatches({ ...target, endpointName: "ep-B" }, target),
    ).toBe(false);
  });

  it("rejects a missing binding entirely", () => {
    expect(boundSessionMatches(undefined, target)).toBe(false);
  });

  it("still shares a session between anonymous callers on an endpoint published without auth", () => {
    // ALLOW_UNAUTHENTICATED_ENDPOINTS puts every caller on the same identity
    // because there is no credential to tell them apart. Refusing here would
    // break that escape hatch outright rather than narrowing it.
    const anon = {
      namespaceUuid: "ns-A",
      endpointName: "ep-A",
      identity: { method: "anonymous" as const, credentialId: null },
    };
    expect(boundSessionMatches({ ...anon }, anon)).toBe(true);
    // It is still a distinct identity from any authenticated one.
    expect(boundSessionMatches({ ...anon }, target)).toBe(false);
    expect(boundSessionMatches({ ...target }, anon)).toBe(false);
  });
});

describe("classifyBindingDenial — which half of the binding failed", () => {
  const target = {
    namespaceUuid: "ns-A",
    endpointName: "ep-A",
    identity: KEY_A,
  };

  it("names a cross-endpoint replay as an ENDPOINT mismatch, not a credential one", () => {
    // The defect this classifier closes: a single hardcoded reason wrote
    // `session_credential_mismatch` for a same-credential, wrong-endpoint
    // replay — asserting an event that did not happen, in an append-only
    // table, in the exact field an operator queries to tell them apart.
    expect(
      classifyBindingDenial({ ...target, endpointName: "ep-B" }, target),
    ).toBe("session_endpoint_mismatch");
    expect(
      classifyBindingDenial({ ...target, namespaceUuid: "ns-B" }, target),
    ).toBe("session_endpoint_mismatch");
  });

  it("names a same-endpoint foreign credential as a CREDENTIAL mismatch", () => {
    expect(classifyBindingDenial({ ...target, identity: KEY_B }, target)).toBe(
      "session_credential_mismatch",
    );
  });

  it("names an anonymous caller on an authenticated session as a credential mismatch", () => {
    const anon = { method: "anonymous" as const, credentialId: null };
    expect(classifyBindingDenial({ ...target, identity: anon }, target)).toBe(
      "session_credential_mismatch",
    );
  });

  it("gives a resident session with NO binding its own reason", () => {
    expect(classifyBindingDenial(undefined, target)).toBe(
      "session_binding_absent",
    );
  });

  it("classifies exactly the cases boundSessionMatches rejects, in the same order", () => {
    // The classifier and the predicate must not drift: every input the
    // predicate refuses gets a reason, and the endpoint half is decided
    // first in both.
    const refused = [
      undefined,
      { ...target, endpointName: "ep-B" },
      { ...target, identity: KEY_B },
      // Both halves wrong — the endpoint half is reported, matching the
      // order boundSessionMatches evaluates them in.
      { ...target, endpointName: "ep-B", identity: KEY_B },
    ];
    for (const binding of refused) {
      expect(boundSessionMatches(binding, target)).toBe(false);
      expect(classifyBindingDenial(binding, target)).toBeTruthy();
    }
    expect(
      classifyBindingDenial(
        { ...target, endpointName: "ep-B", identity: KEY_B },
        target,
      ),
    ).toBe("session_endpoint_mismatch");
  });
});

describe("SessionLifetimeManagerImpl — binding storage", () => {
  it("stores and returns a session's binding, and clears it on removeSession", () => {
    const mgr = new SessionLifetimeManagerImpl<{ id: string }>("test");
    const binding = {
      namespaceUuid: "ns-A",
      endpointName: "ep-A",
      identity: KEY_A,
    };

    mgr.addSession("s1", { id: "s1" }, binding);
    expect(mgr.getSession("s1")).toEqual({ id: "s1" });
    expect(mgr.getSessionBinding("s1")).toEqual(binding);

    mgr.removeSession("s1");
    expect(mgr.getSession("s1")).toBeUndefined();
    expect(mgr.getSessionBinding("s1")).toBeUndefined();
  });

  it("a session added without a binding has an undefined binding (legacy/defensive path)", () => {
    const mgr = new SessionLifetimeManagerImpl<{ id: string }>("test");
    mgr.addSession("s2", { id: "s2" });
    expect(mgr.getSession("s2")).toBeDefined();
    expect(mgr.getSessionBinding("s2")).toBeUndefined();
  });
});

describe("countSessionsForIdentity feeds the per-credential ceiling", () => {
  const ep = { namespaceUuid: "ns-A", endpointName: "ep-A" };

  it("counts only the live sessions bound to the given identity", () => {
    const mgr = new SessionLifetimeManagerImpl<{ id: string }>("test");
    mgr.addSession("a1", { id: "a1" }, { ...ep, identity: KEY_A });
    mgr.addSession("a2", { id: "a2" }, { ...ep, identity: KEY_A });
    mgr.addSession("b1", { id: "b1" }, { ...ep, identity: KEY_B });

    expect(mgr.countSessionsForIdentity(KEY_A)).toBe(2);
    expect(mgr.countSessionsForIdentity(KEY_B)).toBe(1);
  });

  it("falls as sessions are removed, so the count is self-healing", () => {
    const mgr = new SessionLifetimeManagerImpl<{ id: string }>("test");
    mgr.addSession("a1", { id: "a1" }, { ...ep, identity: KEY_A });
    mgr.addSession("a2", { id: "a2" }, { ...ep, identity: KEY_A });
    expect(mgr.countSessionsForIdentity(KEY_A)).toBe(2);

    mgr.removeSession("a1");
    expect(mgr.countSessionsForIdentity(KEY_A)).toBe(1);
  });

  it("does not count a session added without a binding", () => {
    const mgr = new SessionLifetimeManagerImpl<{ id: string }>("test");
    mgr.addSession("nobind", { id: "nobind" });
    expect(mgr.countSessionsForIdentity(KEY_A)).toBe(0);
  });
});

describe("listSessionsForIdentity feeds the ceiling summary", () => {
  const ep = (endpointName: string) => ({
    namespaceUuid: "ns-A",
    endpointName,
  });

  it("lists only the sessions bound to the given identity, with their endpoints", () => {
    const mgr = new SessionLifetimeManagerImpl<{ id: string }>("test");
    mgr.addSession("a1", { id: "a1" }, { ...ep("ep-1"), identity: KEY_A });
    mgr.addSession("a2", { id: "a2" }, { ...ep("ep-2"), identity: KEY_A });
    mgr.addSession("b1", { id: "b1" }, { ...ep("ep-1"), identity: KEY_B });

    expect(mgr.listSessionsForIdentity(KEY_A)).toEqual([
      { sessionId: "a1", endpointName: "ep-1" },
      { sessionId: "a2", endpointName: "ep-2" },
    ]);
    expect(mgr.listSessionsForIdentity(KEY_B)).toEqual([
      { sessionId: "b1", endpointName: "ep-1" },
    ]);
  });

  it("always agrees with countSessionsForIdentity", () => {
    const mgr = new SessionLifetimeManagerImpl<{ id: string }>("test");
    for (let i = 0; i < 5; i += 1) {
      mgr.addSession(
        `a${i}`,
        { id: `a${i}` },
        { ...ep("ep"), identity: KEY_A },
      );
    }
    mgr.removeSession("a2");
    mgr.addSession("nobind", { id: "nobind" });

    expect(mgr.listSessionsForIdentity(KEY_A)).toHaveLength(
      mgr.countSessionsForIdentity(KEY_A),
    );
    expect(mgr.listSessionsForIdentity(KEY_A)).toHaveLength(4);
  });

  it("returns an empty list for an identity with no sessions and skips unbound sessions", () => {
    const mgr = new SessionLifetimeManagerImpl<{ id: string }>("test");
    mgr.addSession("nobind", { id: "nobind" });
    expect(mgr.listSessionsForIdentity(KEY_A)).toEqual([]);
  });
});

describe("ceiling summary, end to end with the real manager and sweeper", () => {
  it("names the endpoints, splits in-flight from idle, and counts SSE-style sessions as untracked", () => {
    resetSessionCountersForTests();
    const streamable = new SessionLifetimeManagerImpl<{ id: string }>("http");
    const sse = new SessionLifetimeManagerImpl<{ id: string }>("sse");
    registerSessionCounter(streamable);
    registerSessionCounter(sse);

    let clock = 1_000_000;
    const sweeper = new PublicSessionSweeper(
      "http",
      { ttlMs: 60_000, intervalMs: 5_000 },
      { reapSession: async () => undefined, now: () => clock },
    );
    registerSessionActivityProbe((id) => sweeper.getActivity(id));

    const bind = (endpointName: string) => ({
      namespaceUuid: "ns-A",
      endpointName,
      identity: KEY_A,
    });
    // Three Streamable HTTP sessions: two idle (one for 40 s), one in flight.
    streamable.addSession("h1", { id: "h1" }, bind("autotask"));
    streamable.addSession("h2", { id: "h2" }, bind("autotask"));
    streamable.addSession("h3", { id: "h3" }, bind("ninja"));
    sweeper.beginTracking("h1");
    sweeper.beginTracking("h2");
    sweeper.beginTracking("h3");
    clock += 40_000;
    sweeper.touch("h1");
    sweeper.markInFlight("h3");
    clock += 5_000;
    // One SSE session the sweeper does not track.
    sse.addSession("s1", { id: "s1" }, bind("ninja"));
    // Another credential's session must not appear.
    streamable.addSession(
      "x1",
      { id: "x1" },
      { ...bind("itglue"), identity: KEY_B },
    );

    process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL = "4";
    const decision = checkConcurrentSessionCeiling(KEY_A, { label: "Example" });
    delete process.env.MCP_MAX_SESSIONS_PER_CREDENTIAL;
    resetSessionCountersForTests();

    expect(decision.allowed).toBe(false);
    expect(decision.current).toBe(4);
    expect(decision.liveSummary).toBe(
      "live: autotask=2, ninja=2; in-flight 1, idle 2, oldest idle 45s, untracked 1",
    );
    // h1 was touched 5 s ago, h2 has been idle 45 s: the oldest is h2's.
    expect(decision.liveSummary).not.toMatch(/\bh\d\b|\bs1\b|\bx1\b/);
  });
});
