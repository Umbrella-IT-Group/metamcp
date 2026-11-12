import { describe, expect, it } from "vitest";

import {
  callerBinding,
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

describe("resolveCallerContext — delegated identity and address provenance", () => {
  it("records an admin key's acts-as target separately from the key owner", () => {
    const caller = resolveCallerContext({
      headers: {},
      authMethod: "api_key",
      apiKeyUuid: "3f7f8a1e-0000-4000-8000-000000000002",
      apiKeyUserId: "key-owner-1",
      apiKeyActsAsUserId: "acted-as-user-1",
    });

    // One column answers "whose credential", the other "whose identity was
    // exercised". Folded together, a delegated call reads as a direct one.
    expect(caller.userId).toBe("key-owner-1");
    expect(caller.actsAsUserId).toBe("acted-as-user-1");
  });

  it("leaves the acts-as target unset for an unbound key", () => {
    const caller = resolveCallerContext({
      headers: {},
      authMethod: "api_key",
      apiKeyUserId: "key-owner-1",
    });

    expect(caller.actsAsUserId).toBeUndefined();
  });

  it("prefers the address the audit-context middleware already stamped", () => {
    // Reading the same value `audit_log.actor_ip` records keeps the two tables
    // from silently disagreeing about where one request came from.
    const caller = resolveCallerContext({
      headers: { "cf-connecting-ip": "198.51.100.4" },
      auditClientIp: "203.0.113.7",
    });

    expect(caller.callerIp).toBe("203.0.113.7");
  });

  it("falls back to the header for a route that runs outside that middleware", () => {
    const caller = resolveCallerContext({
      headers: { "cf-connecting-ip": "198.51.100.4" },
    });

    expect(caller.callerIp).toBe("198.51.100.4");
  });
});

describe("resolveCallerContext: the caller-asserted X-MCP-Actor", () => {
  it("carries the header, trimmed, so the pooled client can forward it", () => {
    const caller = resolveCallerContext({
      ...apiKeyRequest,
      headers: { "x-mcp-actor": "  tech.one@example.com " },
    });

    expect(caller.assertedActor).toBe("tech.one@example.com");
    // Asserted, not identity: the credential fields are untouched by it.
    expect(caller.userId).toBe("user-owner-1");
  });

  it("caps the header so one request cannot push an unbounded value upstream", () => {
    const caller = resolveCallerContext({
      headers: { "x-mcp-actor": "a".repeat(1000) },
    });

    expect(caller.assertedActor).toHaveLength(256);
  });

  it.each([
    ["absent", {}],
    ["blank", { "x-mcp-actor": "   " }],
  ])("leaves it unset when the header is %s", (_label, headers) => {
    expect(resolveCallerContext({ headers }).assertedActor).toBeUndefined();
  });
});

describe("stampCallerContext — the consumer label travels with the binding", () => {
  it("stamps the label and clears it for a caller that resolved none", () => {
    const context: MetaMCPHandlerContext = {
      namespaceUuid: "ns-1",
      sessionId: "sess-1",
    };
    stampCallerContext(context, apiKeyRequest, { name: "example connector" });
    expect(context.clientName).toBe("example connector");

    // A pooled instance handed to a caller with no resolvable identity must
    // not keep advertising the previous consumer's name.
    stampCallerContext(context, { headers: {} });
    expect(context.clientName).toBeUndefined();
  });
});

describe("resolveCallerContext: the OAuth client", () => {
  it("carries the OAuth client the token was issued to", () => {
    const caller = resolveCallerContext({
      headers: {},
      authMethod: "oauth",
      oauthUserId: "user-oauth-9",
      oauthClientId: "mcp_client_example",
    });

    expect(caller.oauthClientId).toBe("mcp_client_example");
  });

  it("leaves it unset for an API-key caller", () => {
    expect(resolveCallerContext(apiKeyRequest).oauthClientId).toBeUndefined();
  });
});

describe("callerBinding: the label and the account email", () => {
  const actsAsRequest: CallerContextSource = {
    ...apiKeyRequest,
    apiKeyActsAsUserId: "acted-as-user-1",
  };

  it("adds the consumer label and the effective account's email to the request's binding", () => {
    expect(
      callerBinding(apiKeyRequest, {
        name: "example connector",
        account: { userId: "user-owner-1", email: "owner@example.com" },
      }),
    ).toEqual({
      ...resolveCallerContext(apiKeyRequest),
      clientName: "example connector",
      email: "owner@example.com",
    });
  });

  it("takes the acts-as user's email for a bound key", () => {
    const caller = callerBinding(actsAsRequest, {
      account: { userId: "acted-as-user-1", email: "bound@example.com" },
    });

    expect(caller.email).toBe("bound@example.com");
  });

  it("never takes an email looked up for a different user than the binding names", () => {
    // A lookup for the key owner must not describe a call made as the
    // acts-as user: that would put one person's address beside another's id.
    const caller = callerBinding(actsAsRequest, {
      account: { userId: "user-owner-1", email: "owner@example.com" },
    });

    expect(caller.email).toBeUndefined();
    expect(caller.actsAsUserId).toBe("acted-as-user-1");
  });

  it.each([
    ["the email could not be read", { userId: "user-owner-1", email: null }],
    ["no account was resolved", undefined],
  ])(
    "leaves the email unset when %s, with no fallback to the label",
    (_l, account) => {
      const caller = callerBinding(apiKeyRequest, {
        name: "owner@example.com",
        account: account as
          | { userId: string; email: string | null }
          | undefined,
      });

      expect(caller.email).toBeUndefined();
      expect(caller.clientName).toBe("owner@example.com");
    },
  );

  it("leaves the email unset when the binding names no user", () => {
    const caller = callerBinding(
      { headers: {}, authMethod: "api_key", apiKeyUuid: "k-1" },
      { account: { userId: "", email: "someone@example.com" } },
    );

    expect(caller.email).toBeUndefined();
  });

  it("is the request's own binding with no consumer", () => {
    expect(callerBinding(apiKeyRequest)).toEqual(
      resolveCallerContext(apiKeyRequest),
    );
  });
});

describe("stampCallerContext: the credential and email fields", () => {
  it("stamps the OAuth client and the email, and clears both for the next caller", () => {
    const context: MetaMCPHandlerContext = {
      namespaceUuid: "ns-1",
      sessionId: "sess-1",
    };
    stampCallerContext(
      context,
      {
        headers: {},
        authMethod: "oauth",
        oauthUserId: "user-oauth-9",
        oauthClientId: "mcp_client_example",
      },
      { account: { userId: "user-oauth-9", email: "oauth@example.com" } },
    );
    expect(context.oauthClientId).toBe("mcp_client_example");
    expect(context.email).toBe("oauth@example.com");

    stampCallerContext(context, apiKeyRequest);

    expect(context.oauthClientId).toBeUndefined();
    expect(context.email).toBeUndefined();
  });
});
