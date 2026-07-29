/**
 * Unit tests for the endpoint-binding mechanism added to close the
 * cross-endpoint session-replay hole (PR #84 review round). A public
 * session is keyed in memory by `Mcp-Session-Id` alone; the binding records
 * the endpoint it was created against so a lookup can reject an id presented
 * on a DIFFERENT endpoint. `bindingMatches` is the single predicate both
 * public-endpoint legs and the DELETE guard funnel through.
 */
import { describe, expect, it, vi } from "vitest";

vi.mock("@/utils/logger", () => ({
  default: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

// config.service reaches @/db transitively; the binding tests never call the
// TTL path, but the import graph still resolves it.
vi.mock("@/db", () => ({ db: {}, pool: { on: vi.fn() } }));

import {
  bindingMatches,
  SessionLifetimeManagerImpl,
} from "./session-lifetime-manager";

describe("bindingMatches — the endpoint-binding predicate", () => {
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

describe("SessionLifetimeManagerImpl — binding storage", () => {
  it("stores and returns a session's binding, and clears it on removeSession", () => {
    const mgr = new SessionLifetimeManagerImpl<{ id: string }>("test");
    const binding = { namespaceUuid: "ns-A", endpointName: "ep-A" };

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
