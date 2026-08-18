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
import { beforeEach, describe, expect, it, vi } from "vitest";

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

import type { ApiKeyAuthenticatedRequest } from "@/middleware/api-key-oauth.middleware";

import type { AuditEvent } from "../../lib/audit/audit-emitter";
import { setAuditSinkForTesting } from "../../lib/audit/audit-emitter";
import type { SessionIdentity } from "../../lib/metamcp/session-auth";
import { __resetSessionDenialThrottleForTesting } from "../../lib/metamcp/session-binding-denial";
import { SessionLifetimeManagerImpl } from "../../lib/session-lifetime-manager";
import { refuseSseMessage, resolveSseMessageSession } from "./sse";

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

  it("shapes absent, cross-endpoint and foreign-credential identically for the response: same outcome, refusedReason drives ONLY the warn log and audit row", () => {
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
    // learns WHICH not_found it was; only the log-only reason differs.
    expect(absent.outcome).toBe("not_found");
    expect(cross.outcome).toBe("not_found");
    expect(foreign.outcome).toBe("not_found");
    if (
      absent.outcome === "not_found" &&
      cross.outcome === "not_found" &&
      foreign.outcome === "not_found"
    ) {
      // Null means "genuine miss": nothing to record, nothing to warn about.
      expect(absent.refusedReason).toBeNull();
      // A cross-endpoint replay must NOT be recorded as a credential
      // mismatch — the audit row is the operator's only way to separate the
      // two classes after the fact.
      expect(cross.refusedReason).toBe("session_endpoint_mismatch");
      expect(foreign.refusedReason).toBe("session_credential_mismatch");
    }
  });

  it("reports a resident session with NO binding as its own reason, not as an endpoint mismatch", () => {
    // Fail-closed and unreachable in production (every addSession call site
    // passes a binding), but if it ever fires the row must say what actually
    // happened rather than assert a mismatch that never occurred.
    const manager = new SessionLifetimeManagerImpl<Transport>("SSE-test");
    manager.addSession("sess-unbound", {
      handlePostMessage: vi.fn(),
    } as unknown as Transport);

    const resolution = resolveSseMessageSession(manager, "sess-unbound", {
      ...OWNER,
    });
    expect(resolution.outcome).toBe("not_found");
    if (resolution.outcome === "not_found") {
      expect(resolution.refusedReason).toBe("session_binding_absent");
    }
  });
});

describe("refuseSseMessage — the /message leg's durable record", () => {
  const foreignReq = () =>
    ({
      headers: { "x-api-key": "sibling-key-value" },
      query: {},
      endpoint: { uuid: "ep-A-uuid" },
      endpointName: "ep-A",
      namespaceUuid: "ns-A",
      authMethod: "api_key",
      apiKeyUuid: "key-B-uuid",
    }) as unknown as ApiKeyAuthenticatedRequest;

  beforeEach(() => {
    __resetSessionDenialThrottleForTesting();
  });

  it("writes an mcp.auth.denied row — an SSE hijack attempt is not log-only", async () => {
    // Before this, the /message refusal emitted a warn and nothing else, so a
    // cross-credential stream hijack attempt left nothing queryable in the one
    // table this fork treats as the stolen-key detector.
    const events: AuditEvent[] = [];
    setAuditSinkForTesting(async (event) => {
      events.push(event);
    });
    try {
      refuseSseMessage(foreignReq(), "sess-1", "session_credential_mismatch");
      await Promise.resolve();
      await Promise.resolve();
    } finally {
      setAuditSinkForTesting(undefined);
    }

    expect(events).toHaveLength(1);
    expect(events[0].action).toBe("mcp.auth.denied");
    // Same 404 the response gives, so the row and the answer agree.
    expect(events[0].http_status).toBe(404);
    expect(events[0].detail?.reason).toBe("session_credential_mismatch");
    expect(events[0].detail?.session_id).toBe("sess-1");
    expect(events[0].actor_id).toBe("key-B-uuid");
    expect(JSON.stringify(events[0])).not.toContain("sibling-key-value");
  });

  it("carries the endpoint-mismatch reason through unchanged", async () => {
    const events: AuditEvent[] = [];
    setAuditSinkForTesting(async (event) => {
      events.push(event);
    });
    try {
      refuseSseMessage(foreignReq(), "sess-1", "session_endpoint_mismatch");
      await Promise.resolve();
      await Promise.resolve();
    } finally {
      setAuditSinkForTesting(undefined);
    }

    expect(events).toHaveLength(1);
    expect(events[0].detail?.reason).toBe("session_endpoint_mismatch");
  });

  it("collapses a burst from one credential into ONE row", async () => {
    const events: AuditEvent[] = [];
    setAuditSinkForTesting(async (event) => {
      events.push(event);
    });
    try {
      for (let i = 0; i < 20; i += 1) {
        refuseSseMessage(
          foreignReq(),
          `sess-${i}`,
          "session_credential_mismatch",
        );
      }
      await Promise.resolve();
      await Promise.resolve();
    } finally {
      setAuditSinkForTesting(undefined);
    }

    expect(events).toHaveLength(1);
  });
});
