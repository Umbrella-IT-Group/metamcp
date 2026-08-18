/**
 * Unit tests for the SSE `/message` ownership guard
 * (`resolveSseMessageSession`) — PR #84 review round 2: the guard shipped
 * in round 1 with zero tests, leaving one of the two least-reviewed new
 * security branches unpinned. It now checks the creating CREDENTIAL as well
 * as the endpoint, so the same-endpoint cases below matter as much as the
 * cross-endpoint ones. The resolver is pure over an injected manager, so
 * these run with no express harness and no postgres.
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

import type { SessionIdentity } from "../../lib/metamcp/session-auth";
import { SessionLifetimeManagerImpl } from "../../lib/session-lifetime-manager";
import { resolveSseMessageSession } from "./sse";

const KEY_A: SessionIdentity = { method: "api_key", credentialId: "key-A" };
const KEY_B: SessionIdentity = { method: "api_key", credentialId: "key-B" };

/** The binding the stream-open leg records for the seeded session. */
const OWNER = {
  namespaceUuid: "ns-A",
  endpointName: "ep-A",
  identity: KEY_A,
};

function seededManager(): {
  manager: SessionLifetimeManagerImpl<Transport>;
  transport: Transport;
} {
  const manager = new SessionLifetimeManagerImpl<Transport>("SSE-test");
  const transport = { handlePostMessage: vi.fn() } as unknown as Transport;
  manager.addSession("sess-1", transport, OWNER);
  return { manager, transport };
}

describe("resolveSseMessageSession — ownership guard on the /message leg", () => {
  it("resolves the transport when the message targets the SAME endpoint under the SAME credential", () => {
    const { manager, transport } = seededManager();

    const resolution = resolveSseMessageSession(manager, "sess-1", {
      ...OWNER,
    });

    expect(resolution).toEqual({ outcome: "ok", transport });
  });

  it("resolves not_found when a caller for a DIFFERENT endpoint presents the session id (replay)", () => {
    const { manager } = seededManager();

    const crossEndpoint = resolveSseMessageSession(manager, "sess-1", {
      namespaceUuid: "ns-B",
      endpointName: "ep-B",
      identity: KEY_A,
    });
    expect(crossEndpoint.outcome).toBe("not_found");

    // Partial match (same namespace, different endpoint name) is still a miss.
    const wrongName = resolveSseMessageSession(manager, "sess-1", {
      namespaceUuid: "ns-A",
      endpointName: "ep-B",
      identity: KEY_A,
    });
    expect(wrongName.outcome).toBe("not_found");
  });

  it("resolves not_found when a DIFFERENT credential on the SAME endpoint presents the session id", () => {
    const { manager } = seededManager();

    const foreign = resolveSseMessageSession(manager, "sess-1", {
      ...OWNER,
      identity: KEY_B,
    });
    expect(foreign.outcome).toBe("not_found");
  });

  it("resolves not_found for a session id that does not exist", () => {
    const { manager } = seededManager();

    const resolution = resolveSseMessageSession(manager, "sess-never-seen", {
      ...OWNER,
    });
    expect(resolution.outcome).toBe("not_found");
  });

  it("resolves not_found for a session stored WITHOUT a binding (fail-closed, never blindly served)", () => {
    const manager = new SessionLifetimeManagerImpl<Transport>("SSE-test");
    manager.addSession("sess-unbound", {
      handlePostMessage: vi.fn(),
    } as unknown as Transport);

    const resolution = resolveSseMessageSession(manager, "sess-unbound", {
      ...OWNER,
    });
    expect(resolution.outcome).toBe("not_found");
  });

  it("shapes absent, cross-endpoint and foreign-credential identically for the response: same outcome, residentRefused drives ONLY the warn log", () => {
    const { manager } = seededManager();

    const absent = resolveSseMessageSession(manager, "sess-never-seen", {
      ...OWNER,
    });
    const cross = resolveSseMessageSession(manager, "sess-1", {
      namespaceUuid: "ns-B",
      endpointName: "ep-B",
      identity: KEY_A,
    });
    const foreign = resolveSseMessageSession(manager, "sess-1", {
      ...OWNER,
      identity: KEY_B,
    });

    // All three feed the route's single 404 branch — the response never
    // learns WHICH not_found it was; only the log-only flag differs.
    expect(absent.outcome).toBe("not_found");
    expect(cross.outcome).toBe("not_found");
    expect(foreign.outcome).toBe("not_found");
    if (
      absent.outcome === "not_found" &&
      cross.outcome === "not_found" &&
      foreign.outcome === "not_found"
    ) {
      expect(absent.residentRefused).toBe(false);
      expect(cross.residentRefused).toBe(true);
      expect(foreign.residentRefused).toBe(true);
    }
  });
});
