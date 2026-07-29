/**
 * Unit tests for the SSE `/message` endpoint-binding guard
 * (`resolveSseMessageSession`) — PR #84 review round 2: the guard shipped
 * in round 1 with zero tests, leaving one of the two least-reviewed new
 * security branches unpinned. The resolver is pure over an injected
 * manager, so these run with no express harness and no postgres.
 *
 * Mocking mirrors `streamable-http.test.ts`: DB-touching boundaries only
 * (`@/db` transitively via session-lifetime-manager -> config.service),
 * plus the express middlewares the router module pulls in at import time.
 */
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import { describe, expect, it, vi } from "vitest";

vi.mock("@/utils/logger", () => ({
  default: {
    error: vi.fn(),
    warn: vi.fn(),
    info: vi.fn(),
    debug: vi.fn(),
  },
}));

vi.mock("@/db", () => ({
  db: {},
  pool: { on: vi.fn() },
}));

vi.mock("@/middleware/api-key-oauth.middleware", () => ({
  authenticateApiKey: vi.fn(),
}));
vi.mock("@/middleware/lookup-endpoint-middleware", () => ({
  lookupEndpoint: vi.fn(),
}));
vi.mock("@/middleware/rate-limit.middleware", () => ({
  rateLimitMiddleware: vi.fn(),
}));

vi.mock("../../lib/metamcp/metamcp-server-pool", () => ({
  metaMcpServerPool: {
    getServer: vi.fn(),
    cleanupSession: vi.fn().mockResolvedValue(undefined),
  },
}));

import { SessionLifetimeManagerImpl } from "../../lib/session-lifetime-manager";
import { resolveSseMessageSession } from "./sse";

function seededManager(): {
  manager: SessionLifetimeManagerImpl<Transport>;
  transport: Transport;
} {
  const manager = new SessionLifetimeManagerImpl<Transport>("SSE-test");
  const transport = { handlePostMessage: vi.fn() } as unknown as Transport;
  manager.addSession("sess-1", transport, {
    namespaceUuid: "ns-A",
    endpointName: "ep-A",
  });
  return { manager, transport };
}

describe("resolveSseMessageSession — endpoint-binding guard on the /message leg", () => {
  it("resolves the transport when the message targets the SAME endpoint the stream was opened on", () => {
    const { manager, transport } = seededManager();

    const resolution = resolveSseMessageSession(manager, "sess-1", {
      namespaceUuid: "ns-A",
      endpointName: "ep-A",
    });

    expect(resolution).toEqual({ outcome: "ok", transport });
  });

  it("resolves not_found when a caller for a DIFFERENT endpoint presents the session id (replay)", () => {
    const { manager } = seededManager();

    const crossEndpoint = resolveSseMessageSession(manager, "sess-1", {
      namespaceUuid: "ns-B",
      endpointName: "ep-B",
    });
    expect(crossEndpoint.outcome).toBe("not_found");

    // Partial match (same namespace, different endpoint name) is still a miss.
    const wrongName = resolveSseMessageSession(manager, "sess-1", {
      namespaceUuid: "ns-A",
      endpointName: "ep-B",
    });
    expect(wrongName.outcome).toBe("not_found");
  });

  it("resolves not_found for a session id that does not exist", () => {
    const { manager } = seededManager();

    const resolution = resolveSseMessageSession(manager, "sess-never-seen", {
      namespaceUuid: "ns-A",
      endpointName: "ep-A",
    });
    expect(resolution.outcome).toBe("not_found");
  });

  it("resolves not_found for a session stored WITHOUT a binding (fail-closed, never blindly served)", () => {
    const manager = new SessionLifetimeManagerImpl<Transport>("SSE-test");
    manager.addSession("sess-unbound", {
      handlePostMessage: vi.fn(),
    } as unknown as Transport);

    const resolution = resolveSseMessageSession(manager, "sess-unbound", {
      namespaceUuid: "ns-A",
      endpointName: "ep-A",
    });
    expect(resolution.outcome).toBe("not_found");
  });

  it("shapes absent and cross-endpoint identically for the response: same outcome, crossEndpoint drives ONLY the warn log", () => {
    const { manager } = seededManager();

    const absent = resolveSseMessageSession(manager, "sess-never-seen", {
      namespaceUuid: "ns-A",
      endpointName: "ep-A",
    });
    const cross = resolveSseMessageSession(manager, "sess-1", {
      namespaceUuid: "ns-B",
      endpointName: "ep-B",
    });

    // Both feed the route's single 404 branch — the response never learns
    // WHICH not_found it was; only the log-only flag differs.
    expect(absent.outcome).toBe("not_found");
    expect(cross.outcome).toBe("not_found");
    if (absent.outcome === "not_found" && cross.outcome === "not_found") {
      expect(absent.crossEndpoint).toBe(false);
      expect(cross.crossEndpoint).toBe(true);
    }
  });
});
