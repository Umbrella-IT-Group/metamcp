import { describe, expect, it } from "vitest";

import {
  CallerContextSource,
  resolveCallerContext,
  stampCallerContext,
} from "./caller-context";
import { MetaMCPHandlerContext } from "./metamcp-middleware/functional-middleware";

const apiKeyRequest: CallerContextSource = {
  headers: { "cf-connecting-ip": "203.0.113.7" },
  apiKeyUuid: "3f7f8a1e-0000-4000-8000-000000000001",
  apiKeyUserId: "user-owner-1",
  authMethod: "api_key",
  auditRequestId: "req-aaaa",
};

describe("resolveCallerContext — field sources", () => {
  it("takes the credential, method, owner, address and request id off the request", () => {
    expect(resolveCallerContext(apiKeyRequest)).toEqual({
      apiKeyUuid: "3f7f8a1e-0000-4000-8000-000000000001",
      authMethod: "api_key",
      userId: "user-owner-1",
      callerIp: "203.0.113.7",
      requestId: "req-aaaa",
    });
  });

  it("uses the OAuth subject as user_id when the caller authenticated with a bearer token", () => {
    const caller = resolveCallerContext({
      headers: {},
      oauthUserId: "user-oauth-9",
      authMethod: "oauth",
      auditRequestId: "req-bbbb",
    });

    expect(caller.userId).toBe("user-oauth-9");
    expect(caller.authMethod).toBe("oauth");
    expect(caller.apiKeyUuid).toBeUndefined();
  });

  it("reads the address from CF-Connecting-IP and ignores every other address header", () => {
    const caller = resolveCallerContext({
      headers: {
        "cf-connecting-ip": "198.51.100.4",
        "x-forwarded-for": "10.0.0.1, 192.0.2.9",
        "x-real-ip": "172.16.0.2",
      },
    });

    // X-Forwarded-For is APPENDED to rather than overwritten, so it is
    // caller-controlled; only the edge-overwritten header is evidence.
    expect(caller.callerIp).toBe("198.51.100.4");
  });

  it("bounds the address at 64 characters (AUDIT_IP_MAX) so one request cannot bloat the row", () => {
    const caller = resolveCallerContext({
      headers: { "cf-connecting-ip": "9".repeat(500) },
    });

    expect(caller.callerIp).toHaveLength(64);
  });

  it("leaves the address unknown rather than fabricating one when the header is absent", () => {
    expect(resolveCallerContext({ headers: {} }).callerIp).toBeUndefined();
  });

  it("mints no synthetic request id when the audit-context middleware did not run", () => {
    // A fabricated id would be a join key that matches no audit_log row while
    // looking exactly like a real one.
    expect(resolveCallerContext({ headers: {} }).requestId).toBeUndefined();
  });
});

describe("stampCallerContext — pooled contexts are reused across consumers", () => {
  it("clears the previous caller's binding instead of leaving it in place", () => {
    const context: MetaMCPHandlerContext = {
      namespaceUuid: "ns-1",
      sessionId: "sess-1",
    };
    stampCallerContext(context, apiKeyRequest);
    expect(context.apiKeyUuid).toBe("3f7f8a1e-0000-4000-8000-000000000001");

    // Second consumer on the same pooled instance resolves no identity at all.
    stampCallerContext(context, { headers: {} });

    expect(context.apiKeyUuid).toBeUndefined();
    expect(context.authMethod).toBeUndefined();
    expect(context.userId).toBeUndefined();
    expect(context.callerIp).toBeUndefined();
    expect(context.requestId).toBeUndefined();
  });

  it("overwrites the per-request fields on a re-stamp so a session's later calls are not frozen at initialize", () => {
    const context: MetaMCPHandlerContext = {
      namespaceUuid: "ns-1",
      sessionId: "sess-1",
    };
    stampCallerContext(context, apiKeyRequest);
    stampCallerContext(context, {
      ...apiKeyRequest,
      headers: { "cf-connecting-ip": "203.0.113.99" },
      auditRequestId: "req-cccc",
    });

    expect(context.requestId).toBe("req-cccc");
    expect(context.callerIp).toBe("203.0.113.99");
    // The identity half is pinned for the life of the session and unchanged.
    expect(context.apiKeyUuid).toBe("3f7f8a1e-0000-4000-8000-000000000001");
  });
});
