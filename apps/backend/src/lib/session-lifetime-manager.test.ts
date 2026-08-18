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
