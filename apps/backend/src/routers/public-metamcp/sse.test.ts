/**
 * Tests for the SSE `/message` ownership guard — PR #84 review round 2: the
 * guard shipped in round 1 with zero tests, leaving one of the two
 * least-reviewed new security branches unpinned. It now checks the creating
 * CREDENTIAL as well as the endpoint, so the same-endpoint cases below matter
 * as much as the cross-endpoint ones.
 *
 * Three layers, narrowest first: `resolveSseMessageSession` is pure over an
 * injected manager and needs no harness; `refuseSseMessage` is driven straight
 * against the audit sink; and the last block drives the REAL router over a real
 * socket. That last layer is not redundant — the first two both stay green
 * while the route's call joining them is deleted, which is exactly how this leg
 * could revert to log-only unnoticed.
 *
 * Mocking mirrors `streamable-http.test.ts`: DB-touching boundaries only
 * (`@/db` transitively via session-lifetime-manager -> config.service),
 * plus the express middlewares the router module pulls in at import time.
 */
import type { Server } from "node:http";

import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import express from "express";
import {
  afterAll,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";

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
import { authenticateApiKey } from "@/middleware/api-key-oauth.middleware";
import { lookupEndpoint } from "@/middleware/lookup-endpoint-middleware";
import { rateLimitMiddleware } from "@/middleware/rate-limit.middleware";

import type { AuditEvent } from "../../lib/audit/audit-emitter";
import { setAuditSinkForTesting } from "../../lib/audit/audit-emitter";
import type { SessionIdentity } from "../../lib/metamcp/session-auth";
import { __resetSessionDenialThrottleForTesting } from "../../lib/metamcp/session-binding-denial";
import { SessionLifetimeManagerImpl } from "../../lib/session-lifetime-manager";
import sseRouter, {
  __removeSseSessionForTesting,
  __seedSseSessionForTesting,
  refuseSseMessage,
  resolveSseMessageSession,
} from "./sse";

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

/**
 * The two blocks above test the guard and the emitter in isolation, which
 * leaves the thing that connects them — the route — unpinned: with only those,
 * deleting the route's `refuseSseMessage` call keeps the suite green while the
 * SSE leg silently reverts to log-only. These drive the real router over a real
 * socket so that call is load-bearing.
 */
describe("POST /:endpoint_name/message — the route wires the guard to the record", () => {
  const SEEDED_SESSION = "sess-route-1";
  let server: Server;
  let baseUrl = "";
  let currentKeyUuid = "key-A";
  let currentEndpointName = "ep-A";
  let currentNamespaceUuid = "ns-A";

  const transport = () =>
    ({
      // The real SSEServerTransport answers 202 and forwards the body onto the
      // open stream. A stub that never responds would hang the request rather
      // than fail it, so it answers too.
      handlePostMessage: vi.fn(
        async (_req: express.Request, res: express.Response) => {
          res.status(202).end("Accepted");
        },
      ),
    }) as unknown as Transport;
  let seededTransport: Transport;

  /** The stub's spy, past the `Transport` cast the seam takes. */
  const postMessageSpy = () =>
    (
      seededTransport as unknown as {
        handlePostMessage: ReturnType<typeof vi.fn>;
      }
    ).handlePostMessage;

  beforeAll(async () => {
    // The guard is what is under test, so the three middlewares in front of it
    // become pass-throughs that stamp what `lookupEndpoint` /
    // `authenticateApiKey` would have resolved. Same harness shape as the
    // route-level block in `streamable-http.test.ts`.
    vi.mocked(lookupEndpoint).mockImplementation(((
      req: express.Request,
      _res: express.Response,
      next: () => void,
    ) => {
      const authReq = req as ApiKeyAuthenticatedRequest;
      authReq.namespaceUuid = currentNamespaceUuid;
      authReq.endpointName = currentEndpointName;
      authReq.endpoint = {
        uuid: "ep-A-uuid",
        name: currentEndpointName,
        enable_api_key_auth: true,
        use_query_param_auth: false,
      } as unknown as ApiKeyAuthenticatedRequest["endpoint"];
      next();
    }) as never);
    vi.mocked(authenticateApiKey).mockImplementation(((
      req: express.Request,
      _res: express.Response,
      next: () => void,
    ) => {
      const authReq = req as ApiKeyAuthenticatedRequest;
      authReq.authMethod = "api_key";
      authReq.apiKeyUuid = currentKeyUuid;
      next();
    }) as never);
    vi.mocked(rateLimitMiddleware).mockImplementation(((
      _req: express.Request,
      _res: express.Response,
      next: () => void,
    ) => next()) as never);

    const app = express();
    app.use("/metamcp", sseRouter);
    await new Promise<void>((resolve) => {
      server = app.listen(0, "127.0.0.1", resolve);
    });
    const address = server.address();
    if (typeof address === "object" && address) {
      baseUrl = `http://127.0.0.1:${address.port}`;
    }
  });

  afterAll(async () => {
    __removeSseSessionForTesting(SEEDED_SESSION);
    vi.mocked(lookupEndpoint).mockImplementation((() => undefined) as never);
    vi.mocked(authenticateApiKey).mockImplementation(
      (() => undefined) as never,
    );
    vi.mocked(rateLimitMiddleware).mockImplementation(
      (() => undefined) as never,
    );
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  beforeEach(() => {
    __resetSessionDenialThrottleForTesting();
    __removeSseSessionForTesting(SEEDED_SESSION);
    seededTransport = transport();
    // The session the owning credential opened on ep-A.
    __seedSseSessionForTesting(SEEDED_SESSION, seededTransport, {
      namespaceUuid: "ns-A",
      endpointName: "ep-A",
      identity: KEY_A,
    });
    currentKeyUuid = "key-A";
    currentEndpointName = "ep-A";
    currentNamespaceUuid = "ns-A";
  });

  const post = async (
    sessionId: string,
  ): Promise<{ status: number; events: AuditEvent[] }> => {
    const events: AuditEvent[] = [];
    setAuditSinkForTesting(async (event) => {
      events.push(event);
    });
    try {
      const response = await fetch(
        `${baseUrl}/metamcp/${currentEndpointName}/message?sessionId=${sessionId}`,
        {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-api-key": "presented-key-value",
          },
          body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
        },
      );
      // `emit` is fire-and-forget through a promise chain; let it settle.
      await Promise.resolve();
      await Promise.resolve();
      return { status: response.status, events };
    } finally {
      setAuditSinkForTesting(undefined);
    }
  };

  it("writes the audit row when a FOREIGN credential presents a live session id", async () => {
    currentKeyUuid = "key-B";

    const { status, events } = await post(SEEDED_SESSION);

    expect(status).toBe(404);
    expect(events).toHaveLength(1);
    expect(events[0].action).toBe("mcp.auth.denied");
    expect(events[0].http_status).toBe(404);
    expect(events[0].detail?.reason).toBe("session_credential_mismatch");
    expect(events[0].detail?.session_id).toBe(SEEDED_SESSION);
    expect(events[0].actor_id).toBe("key-B");
    // The refused caller never reaches the owner's transport.
    expect(postMessageSpy()).not.toHaveBeenCalled();
  });

  it("carries the endpoint-mismatch class through the route for a cross-endpoint replay", async () => {
    // Same credential, replaying the id against a different endpoint. The row
    // must not call this a credential mismatch.
    currentEndpointName = "ep-B";
    currentNamespaceUuid = "ns-B";

    const { status, events } = await post(SEEDED_SESSION);

    expect(status).toBe(404);
    expect(events).toHaveLength(1);
    expect(events[0].detail?.reason).toBe("session_endpoint_mismatch");
  });

  it("writes NOTHING for a genuine miss — an unknown id is not an incident", async () => {
    const { status, events } = await post("sess-never-existed");

    expect(status).toBe(404);
    expect(events).toHaveLength(0);
  });

  it("serves the owner: same endpoint, same credential is not refused", async () => {
    const { status, events } = await post(SEEDED_SESSION);

    // No refusal row, and the guard handed the request to the bound transport.
    expect(status).toBe(202);
    expect(events).toHaveLength(0);
    expect(postMessageSpy()).toHaveBeenCalled();
  });
});
