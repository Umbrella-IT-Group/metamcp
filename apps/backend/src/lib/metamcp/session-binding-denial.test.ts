/**
 * Unit tests for the shared session-refusal surface: the credential extractor
 * every guard path names a caller with, and the throttle that keeps a refused
 * caller from pacing writes into an append-only table.
 *
 * `audit-emitter` is mocked at the module seam — it reaches `audit-log.repo`
 * and therefore `db/index`, which throws without DATABASE_URL. Only the
 * envelope this module builds is under test here; that it lands on the right
 * legs is pinned at the route level in `streamable-http.test.ts` / `sse.test.ts`.
 */

import type { DatabaseEndpoint } from "@repo/zod-types";
import express from "express";
import { beforeEach, describe, expect, it, vi } from "vitest";

const { emitMock } = vi.hoisted(() => ({ emitMock: vi.fn() }));

vi.mock("../audit/audit-emitter", () => ({
  emit: emitMock,
  auditRequestContext: () => ({
    actor_ip: "203.0.113.9",
    actor_user_agent: "test-agent",
    request_id: "req-1",
  }),
  credentialFingerprint: (token?: string) => ({
    sha256: token ? "hashed" : null,
    last4: token ? token.slice(-4) : null,
  }),
}));

import {
  __resetSessionDenialThrottleForTesting,
  emitSessionBindingDenial,
  extractPresentedCredential,
  recordSessionBindingDenial,
  SESSION_DENIAL_REPORT_INTERVAL_MS,
} from "./session-binding-denial";

const makeEndpoint = (
  overrides: Partial<DatabaseEndpoint> = {},
): DatabaseEndpoint =>
  ({
    uuid: "ep-uuid",
    name: "autotask",
    enable_api_key_auth: true,
    enable_oauth: false,
    use_query_param_auth: false,
    ...overrides,
  }) as unknown as DatabaseEndpoint;

const makeReq = (overrides: Partial<express.Request> = {}): express.Request =>
  ({ headers: {}, query: {}, ...overrides }) as unknown as express.Request;

beforeEach(() => {
  vi.clearAllMocks();
  __resetSessionDenialThrottleForTesting();
});

describe("extractPresentedCredential — one gated definition of the presented credential", () => {
  it("reads the x-api-key header", () => {
    expect(
      extractPresentedCredential(
        makeReq({ headers: { "x-api-key": "sk_live_key" } }),
        makeEndpoint(),
      ),
    ).toBe("sk_live_key");
  });

  it("reads a Bearer authorization header", () => {
    expect(
      extractPresentedCredential(
        makeReq({ headers: { authorization: "Bearer mcp_token_abc" } }),
        makeEndpoint(),
      ),
    ).toBe("mcp_token_abc");
  });

  it("headers win over the query parameter, so an appended ?api_key= cannot override one", () => {
    expect(
      extractPresentedCredential(
        makeReq({
          headers: { "x-api-key": "header-key" },
          query: { api_key: "query-key" },
        } as Partial<express.Request>),
        makeEndpoint({ use_query_param_auth: true }),
      ),
    ).toBe("header-key");
  });

  it("reads ?api_key= ONLY when the endpoint enables api-key auth AND query-param auth", () => {
    const req = makeReq({
      query: { api_key: "query-key" },
    } as Partial<express.Request>);
    expect(
      extractPresentedCredential(
        req,
        makeEndpoint({ enable_api_key_auth: true, use_query_param_auth: true }),
      ),
    ).toBe("query-key");
    expect(
      extractPresentedCredential(
        req,
        makeEndpoint({
          enable_api_key_auth: true,
          use_query_param_auth: false,
        }),
      ),
    ).toBeNull();
    expect(
      extractPresentedCredential(
        req,
        makeEndpoint({
          enable_api_key_auth: false,
          use_query_param_auth: true,
        }),
      ),
    ).toBeNull();
  });

  it("ignores ?api_key= on an endpoint published WITHOUT auth — the persisted-principal bypass", () => {
    // A CONDITION-1 endpoint (both auth toggles off, published through
    // ALLOW_UNAUTHENTICATED_ENDPOINTS) never accepts a query-param token at
    // the middleware. Honouring one here would let an anonymous caller who
    // holds a raw key satisfy a persisted-row credential check the middleware
    // itself would have refused, and drop another consumer's recovery row.
    expect(
      extractPresentedCredential(
        makeReq({
          query: { apikey: "someone-elses-key" },
        } as Partial<express.Request>),
        makeEndpoint({ enable_api_key_auth: false, enable_oauth: false }),
      ),
    ).toBeNull();
  });

  it("returns null with no endpoint and no header, rather than trusting the query", () => {
    expect(
      extractPresentedCredential(
        makeReq({ query: { api_key: "k" } } as Partial<express.Request>),
        undefined,
      ),
    ).toBeNull();
  });

  it("returns null when nothing recognizable is presented", () => {
    expect(extractPresentedCredential(makeReq(), makeEndpoint())).toBeNull();
    // A bare "Bearer " carries no token.
    expect(
      extractPresentedCredential(
        makeReq({ headers: { authorization: "Bearer " } }),
        makeEndpoint(),
      ),
    ).toBeNull();
  });
});

describe("recordSessionBindingDenial — the write throttle", () => {
  const MISMATCH = "session_credential_mismatch";

  it("writes the first refusal for a key and swallows the rest of the window", () => {
    expect(recordSessionBindingDenial("key-A", "ep-1", MISMATCH)).toEqual({
      emit: true,
      suppressed: 0,
    });
    expect(recordSessionBindingDenial("key-A", "ep-1", MISMATCH)).toEqual({
      emit: false,
      suppressed: 1,
    });
    expect(recordSessionBindingDenial("key-A", "ep-1", MISMATCH)).toEqual({
      emit: false,
      suppressed: 2,
    });
  });

  it("carries the swallowed count onto the next row that IS written", () => {
    // Volume is the question a responder asks of this event — "denied once"
    // and "denied 4,000 times in a minute" must stay distinguishable even
    // though per-attempt timestamps do not survive.
    recordSessionBindingDenial("key-A", "ep-1", MISMATCH);
    for (let i = 0; i < 40; i += 1)
      recordSessionBindingDenial("key-A", "ep-1", MISMATCH);

    vi.useFakeTimers();
    try {
      vi.setSystemTime(Date.now() + SESSION_DENIAL_REPORT_INTERVAL_MS + 1);
      expect(recordSessionBindingDenial("key-A", "ep-1", MISMATCH)).toEqual({
        emit: true,
        suppressed: 40,
      });
    } finally {
      vi.useRealTimers();
    }
  });

  it("throttles PER (actor, endpoint, reason) — one noisy caller never hides another's first refusal", () => {
    expect(recordSessionBindingDenial("key-A", "ep-1", MISMATCH).emit).toBe(
      true,
    );
    expect(recordSessionBindingDenial("key-A", "ep-1", MISMATCH).emit).toBe(
      false,
    );
    // Same caller, different endpoint.
    expect(recordSessionBindingDenial("key-A", "ep-2", MISMATCH).emit).toBe(
      true,
    );
    // Different caller, same endpoint.
    expect(recordSessionBindingDenial("key-B", "ep-1", MISMATCH).emit).toBe(
      true,
    );
  });

  it("keys on the REASON too — a second class from the same caller and endpoint is not swallowed", () => {
    // The whole point of `detail.reason` is letting an operator separate a
    // cross-endpoint replay from a stolen credential. Keying without it means
    // whichever class arrives first in a window hides every other class behind
    // a bare count, so the distinguishing field never reaches the table.
    expect(
      recordSessionBindingDenial("key-A", "ep-1", "session_endpoint_mismatch")
        .emit,
    ).toBe(true);
    expect(
      recordSessionBindingDenial("key-A", "ep-1", "session_endpoint_mismatch")
        .emit,
    ).toBe(false);

    // Same credential, same endpoint, DIFFERENT class — its own first row.
    expect(recordSessionBindingDenial("key-A", "ep-1", MISMATCH).emit).toBe(
      true,
    );
    expect(
      recordSessionBindingDenial("key-A", "ep-1", "session_binding_absent")
        .emit,
    ).toBe(true);
    expect(
      recordSessionBindingDenial(
        "key-A",
        "ep-1",
        "session_persisted_credential_mismatch",
      ).emit,
    ).toBe(true);
  });

  it("stays bounded: the four reasons are the ceiling for one (actor, endpoint) window", () => {
    // Per-reason keying must not become an amplifier. The reason is assigned by
    // the server from a closed four-member union, so a caller cannot vary it to
    // buy extra permanent rows — a burst of every class still writes 4, and
    // everything after that is swallowed.
    const reasons = [
      "session_binding_absent",
      "session_endpoint_mismatch",
      "session_credential_mismatch",
      "session_persisted_credential_mismatch",
    ] as const;

    let written = 0;
    for (let i = 0; i < 200; i += 1) {
      for (const reason of reasons) {
        if (recordSessionBindingDenial("key-A", "ep-1", reason).emit) {
          written += 1;
        }
      }
    }

    expect(written).toBe(reasons.length);
  });
});

describe("emitSessionBindingDenial — the mcp.auth.denied envelope", () => {
  const authReq = () =>
    makeReq({
      headers: { "x-api-key": "the-other-key-value" },
      endpoint: makeEndpoint(),
      endpointName: "autotask",
      authMethod: "api_key",
      apiKeyUuid: "key-B-uuid",
    } as unknown as Partial<express.Request>);

  it("records the reason it was given, never a fixed one", () => {
    emitSessionBindingDenial(authReq(), {
      sessionId: "sess-1",
      reason: "session_endpoint_mismatch",
    });

    expect(emitMock).toHaveBeenCalledTimes(1);
    const event = emitMock.mock.calls[0][0];
    expect(event.action).toBe("mcp.auth.denied");
    expect(event.outcome).toBe("denied");
    expect(event.http_status).toBe(404);
    expect(event.detail.reason).toBe("session_endpoint_mismatch");
    expect(event.detail.session_id).toBe("sess-1");
  });

  it("names the caller who tried, fingerprinted — never the raw secret", () => {
    emitSessionBindingDenial(authReq(), {
      sessionId: "sess-1",
      reason: "session_credential_mismatch",
    });

    const event = emitMock.mock.calls[0][0];
    expect(event.actor_type).toBe("api_key");
    expect(event.actor_id).toBe("key-B-uuid");
    expect(event.target_id).toBe("ep-uuid");
    expect(event.detail.credential.last4).toBe("alue");
    expect(JSON.stringify(event)).not.toContain("the-other-key-value");
  });

  it("writes ONE row for a burst from the same caller, carrying the suppressed count", () => {
    const first = emitSessionBindingDenial(authReq(), {
      sessionId: "sess-1",
      reason: "session_credential_mismatch",
    });
    // An id-enumeration sweep: same credential, same endpoint, many ids.
    for (let i = 0; i < 25; i += 1) {
      emitSessionBindingDenial(authReq(), {
        sessionId: `sess-${i}`,
        reason: "session_credential_mismatch",
      });
    }

    expect(first).toEqual({ emitted: true, suppressed: 0 });
    expect(emitMock).toHaveBeenCalledTimes(1);
    expect(emitMock.mock.calls[0][0].detail.suppressed_since_last).toBe(0);

    vi.useFakeTimers();
    try {
      vi.setSystemTime(Date.now() + SESSION_DENIAL_REPORT_INTERVAL_MS + 1);
      const next = emitSessionBindingDenial(authReq(), {
        sessionId: "sess-99",
        reason: "session_credential_mismatch",
      });
      expect(next).toEqual({ emitted: true, suppressed: 25 });
      expect(emitMock).toHaveBeenCalledTimes(2);
      expect(emitMock.mock.calls[1][0].detail.suppressed_since_last).toBe(25);
    } finally {
      vi.useRealTimers();
    }
  });

  it("writes a SECOND row when the same caller trips a different class in one window", () => {
    // A cross-endpoint replay and a credential mismatch from the same key are
    // different incidents. If the throttle collapsed them, the operator would
    // see only the class that happened to arrive first and the other would
    // survive as an unattributed number — exactly the read `detail.reason`
    // exists to prevent.
    emitSessionBindingDenial(authReq(), {
      sessionId: "sess-1",
      reason: "session_endpoint_mismatch",
    });
    emitSessionBindingDenial(authReq(), {
      sessionId: "sess-2",
      reason: "session_credential_mismatch",
    });
    // ...while a repeat of either class is still collapsed.
    emitSessionBindingDenial(authReq(), {
      sessionId: "sess-3",
      reason: "session_endpoint_mismatch",
    });

    expect(emitMock).toHaveBeenCalledTimes(2);
    expect(emitMock.mock.calls.map((call) => call[0].detail.reason)).toEqual([
      "session_endpoint_mismatch",
      "session_credential_mismatch",
    ]);
  });

  it("attributes an OAuth refusal to the user, not to an api key", () => {
    emitSessionBindingDenial(
      makeReq({
        headers: { authorization: "Bearer mcp_token_value" },
        endpoint: makeEndpoint(),
        endpointName: "autotask",
        authMethod: "oauth",
        oauthUserId: "user-7",
      } as unknown as Partial<express.Request>),
      { sessionId: "sess-1", reason: "session_credential_mismatch" },
    );

    const event = emitMock.mock.calls[0][0];
    expect(event.actor_type).toBe("user");
    expect(event.actor_id).toBe("user-7");
    expect(event.detail.auth_method).toBe("oauth");
  });

  it("never throws, and reports not-emitted, when the sink itself fails", () => {
    // A refusal must be answered whether or not it can be recorded.
    emitMock.mockImplementationOnce(() => {
      throw new Error("audit sink down");
    });

    let result: ReturnType<typeof emitSessionBindingDenial> | undefined;
    expect(() => {
      result = emitSessionBindingDenial(authReq(), {
        sessionId: "sess-1",
        reason: "session_credential_mismatch",
      });
    }).not.toThrow();

    // Not just "did not throw": the caller shapes its warn log off this, so a
    // failed sink must report the row as NOT written rather than claim one.
    expect(result).toEqual({ emitted: false, suppressed: 0 });
  });
});
