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
