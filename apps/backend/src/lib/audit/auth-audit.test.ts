/**
 * The authentication plane's audit rows.
 *
 * Two emitters, one contract. `auth-relay-audit.ts` reads the `/api/auth`
 * relay's HTTP verdict; `auth-hook-audit.ts` reads better-auth's database
 * hooks. Between them they cover the events the 2026-08-13 incident review
 * had to infer: who tried to sign in and failed, who registered an account,
 * who was refused registration, and which sessions existed.
 *
 * What is pinned here, in priority order:
 *  1. a FAILED sign-in writes a row at all — until Phase 1B it wrote nothing
 *     anywhere, so credential stuffing against this gateway was invisible;
 *  2. no row ever carries a secret. The sign-in success body contains the
 *     SESSION TOKEN and the request body contains the PASSWORD; a session row
 *     carries the session token. None of the three may reach the table, which
 *     is append-only and cannot be pruned;
 *  3. the outcome, not the attempt, decides the row — a 401 must not produce
 *     `auth.login.success`;
 *  4. a failing sink cannot break authentication.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { loggerMock } = vi.hoisted(() => ({
  loggerMock: {
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  },
}));

vi.mock("@/utils/logger", () => ({ default: loggerMock }));

const {
  AUDIT_CLIENT_IP_HEADER,
  AUDIT_REQUEST_ID_HEADER,
  setAuditSinkForTesting,
  stampAuditHeaders,
} = await import("./audit-emitter");
const { emitAuthRelayEvent } = await import("./auth-relay-audit");
const {
  emitSessionCreated,
  emitSessionRevoked,
  emitSignupCreated,
  emitSignupDenied,
} = await import("./auth-hook-audit");

type AuditRow = {
  action: string;
  outcome: string;
  actor_type: string;
  actor_id?: string | null;
  actor_label?: string | null;
  actor_ip?: string | null;
  actor_user_agent?: string | null;
  request_id?: string | null;
  http_status?: number | null;
  target_type?: string | null;
  target_id?: string | null;
  detail?: Record<string, unknown>;
};

const AUDIT = {
  actor_ip: "203.0.113.7",
  actor_user_agent: "Mozilla/5.0",
  request_id: "req-under-test",
};

const SESSION_TOKEN = "st_super_secret_session_token_value";
const PASSWORD = "hunter2-do-not-log-me";

/** What better-auth answers a successful `sign-in/email` with. */
const SIGN_IN_OK_BODY = JSON.stringify({
  redirect: false,
  token: SESSION_TOKEN,
  user: { id: "user-42", email: "person@example.invalid", role: "member" },
});

/** A better-auth hook context, as the relay's header stamping leaves it. */
const hookContext = {
  headers: new Headers({
    [AUDIT_REQUEST_ID_HEADER]: AUDIT.request_id,
    [AUDIT_CLIENT_IP_HEADER]: AUDIT.actor_ip,
    "user-agent": AUDIT.actor_user_agent,
  }),
};

let rows: AuditRow[];

/** Flush the detached promise chain `emit()` schedules. */
const flush = () => new Promise((resolve) => setTimeout(resolve, 0));

/** Every string that lands in the table, for the no-secrets assertions. */
const serialized = () => JSON.stringify(rows);

beforeEach(() => {
  vi.clearAllMocks();
  rows = [];
  setAuditSinkForTesting(async (event) => {
    rows.push(event as AuditRow);
  });
});

afterEach(() => {
  setAuditSinkForTesting(undefined);
});

describe("auth.login.failure — the signal that did not exist before", () => {
  it("writes one anonymous row naming the ATTEMPTED address, never the password", async () => {
    emitAuthRelayEvent({
      path: "/api/auth/sign-in/email",
      status: 401,
      requestBody: { email: "victim@example.invalid", password: PASSWORD },
      responseBody: JSON.stringify({ message: "Invalid email or password" }),
      audit: AUDIT,
    });
    await flush();

    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      action: "auth.login.failure",
      outcome: "failure",
      // Anonymous, because the claimed identity was NOT proven.
      actor_type: "anonymous",
      actor_id: null,
      actor_label: "victim@example.invalid",
      actor_ip: "203.0.113.7",
      actor_user_agent: "Mozilla/5.0",
      request_id: "req-under-test",
      http_status: 401,
      target_type: "user",
    });
    expect(serialized()).not.toContain(PASSWORD);
  });

  it("clamps the attempted address — the row COUNT is bounded, the SIZE is not", async () => {
    // `email` is attacker-controlled body text on a route whose JSON limit is
    // 50mb, and it lands in a table with no prune path. Without a clamp, a
    // bounded number of failed sign-ins is still an unbounded number of
    // BYTES.
    emitAuthRelayEvent({
      path: "/api/auth/sign-in/email",
      status: 401,
      requestBody: { email: "a".repeat(100_000), password: PASSWORD },
      responseBody: "{}",
      audit: AUDIT,
    });
    await flush();

    expect(rows).toHaveLength(1);
    // RFC 5321's maximum address length.
    expect(rows[0].actor_label).toHaveLength(320);
  });

  it("treats the disabled-account 403 as a failure too", async () => {
    // `auth.ts`'s session.create.before throws APIError FORBIDDEN for a
    // locked account, which reaches the relay as a 403. A status-range check
    // that only recognised 401 would file a locked-out attacker's attempts as
    // successes.
    emitAuthRelayEvent({
      path: "/api/auth/sign-in/email",
      status: 403,
      requestBody: { email: "locked@example.invalid", password: PASSWORD },
      responseBody: JSON.stringify({
        message: "This account has been disabled.",
      }),
      audit: AUDIT,
    });
    await flush();

    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      action: "auth.login.failure",
      outcome: "failure",
      http_status: 403,
      actor_label: "locked@example.invalid",
    });
  });
});

describe("auth.login.success — the outcome decides the row", () => {
  it("names the authenticated user and does NOT carry the session token", async () => {
    emitAuthRelayEvent({
      path: "/api/auth/sign-in/email",
      status: 200,
      requestBody: { email: "person@example.invalid", password: PASSWORD },
      responseBody: SIGN_IN_OK_BODY,
      audit: AUDIT,
    });
    await flush();

    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      action: "auth.login.success",
      outcome: "success",
      actor_type: "user",
      actor_id: "user-42",
      actor_label: "person@example.invalid",
      target_type: "user",
      target_id: "user-42",
      http_status: 200,
    });
    // The response body this row was built from contains the session token.
    expect(serialized()).not.toContain(SESSION_TOKEN);
    expect(serialized()).not.toContain(PASSWORD);
  });

  it("writes NOTHING for sign-in/social, whose 200 is a redirect URL not a login", async () => {
    // A 200 here means "here is where to send the browser". Filing it as a
    // successful login would put a login row in the table for a flow that has
    // not authenticated anybody. SSO logins are covered by session.create.
    emitAuthRelayEvent({
      path: "/api/auth/sign-in/social",
      status: 200,
      requestBody: { provider: "oidc" },
      responseBody: JSON.stringify({ url: "https://idp.example.invalid/auth" }),
      audit: AUDIT,
    });
    await flush();

    expect(rows).toEqual([]);
  });

  it("writes NOTHING for an unrelated /api/auth path", async () => {
    emitAuthRelayEvent({
      path: "/api/auth/get-session",
      status: 200,
      requestBody: {},
      responseBody: SIGN_IN_OK_BODY,
      audit: AUDIT,
    });
    await flush();

    expect(rows).toEqual([]);
  });
});

describe("auth.logout", () => {
  it("writes one row on a successful sign-out", async () => {
    emitAuthRelayEvent({
      path: "/api/auth/sign-out",
      status: 200,
      requestBody: {},
      responseBody: JSON.stringify({ success: true }),
      audit: AUDIT,
    });
    await flush();

    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      action: "auth.logout",
      outcome: "success",
      target_type: "session",
      request_id: "req-under-test",
    });
  });
});

describe("stampAuditHeaders — a caller cannot forge its own attribution", () => {
  it("overwrites values the caller invented under the internal header names", async () => {
    const headers = new Headers({
      [AUDIT_REQUEST_ID_HEADER]: "attacker-chosen-id",
      [AUDIT_CLIENT_IP_HEADER]: "10.0.0.1",
    });

    stampAuditHeaders(headers, AUDIT);

    expect(headers.get(AUDIT_REQUEST_ID_HEADER)).toBe("req-under-test");
    expect(headers.get(AUDIT_CLIENT_IP_HEADER)).toBe("203.0.113.7");
  });

  it("DELETES them when we have no value — the case a forgery would survive", async () => {
    // No `CF-Connecting-IP` means the request did not come through the
    // Cloudflare tunnel, which is precisely when a caller-supplied IP is
    // worthless. Skipping the write instead of deleting would leave the
    // attacker's value standing and it would be read back as evidence.
    const headers = new Headers({
      [AUDIT_REQUEST_ID_HEADER]: "attacker-chosen-id",
      [AUDIT_CLIENT_IP_HEADER]: "10.0.0.1",
    });

    stampAuditHeaders(headers, {
      actor_ip: null,
      actor_user_agent: null,
      request_id: null,
    });

    expect(headers.get(AUDIT_REQUEST_ID_HEADER)).toBeNull();
    expect(headers.get(AUDIT_CLIENT_IP_HEADER)).toBeNull();
  });
});

describe("auth.signup.denied — registration refused because signup is closed", () => {
  it("writes a denied row carrying the attempted email and the method", async () => {
    emitSignupDenied(
      { id: "should-not-be-used", email: "walkin@example.invalid" },
      hookContext,
      "basic",
    );
    await flush();

    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      action: "auth.signup.denied",
      outcome: "denied",
      actor_type: "user",
      // No account was created, so there is no id to name.
      actor_id: null,
      actor_label: "walkin@example.invalid",
      target_type: "user",
      target_id: null,
    });
    expect(rows[0].detail).toMatchObject({ method: "basic" });
  });

  it("recovers the request id and caller IP the relay stamped as headers", async () => {
    // The hook never sees the express request. Without the two internal
    // headers index.ts sets, every hook-emitted row would be unattributable
    // and unjoinable to the auth.login.* row from the same HTTP call.
    emitSignupDenied({ email: "walkin@example.invalid" }, hookContext, "sso");
    await flush();

    expect(rows[0]).toMatchObject({
      actor_ip: "203.0.113.7",
      actor_user_agent: "Mozilla/5.0",
      request_id: "req-under-test",
    });
    expect(rows[0].detail).toMatchObject({ method: "sso" });
  });

  it("falls through to context.request.headers when context.headers cannot answer", async () => {
    // better-auth types the hook context's `headers` as the loose
    // `HeadersInit`, satisfied by a plain object with no `.get`. Giving up on
    // that bag instead of falling through would produce an unattributed row
    // while a real `Headers` sat on `context.request`.
    emitSignupDenied(
      { email: "walkin@example.invalid" },
      {
        headers: { "user-agent": "not-a-Headers-instance" },
        request: {
          headers: new Headers({
            [AUDIT_REQUEST_ID_HEADER]: AUDIT.request_id,
            [AUDIT_CLIENT_IP_HEADER]: AUDIT.actor_ip,
          }),
        },
      },
      "basic",
    );
    await flush();

    expect(rows[0]).toMatchObject({
      actor_ip: "203.0.113.7",
      request_id: "req-under-test",
    });
  });

  it("degrades to nulls rather than throwing when there is no hook context", async () => {
    // better-auth types the context `GenericEndpointContext | null`. A throw
    // here would break sign-up to record it.
    expect(() =>
      emitSignupDenied({ email: "x@y.invalid" }, null, "basic"),
    ).not.toThrow();
    await flush();

    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      action: "auth.signup.denied",
      actor_ip: null,
      request_id: null,
    });
  });
});

describe("auth.signup / session lifecycle", () => {
  it("auth.signup names the account that now exists", async () => {
    emitSignupCreated(
      { id: "user-99", email: "new@example.invalid" },
      hookContext,
    );
    await flush();

    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      action: "auth.signup",
      outcome: "success",
      actor_id: "user-99",
      actor_label: "new@example.invalid",
      target_type: "user",
      target_id: "user-99",
    });
  });

  it("session.create records the session ID and never the session token", async () => {
    emitSessionCreated(
      { id: "sess-7", userId: "user-99", token: SESSION_TOKEN },
      hookContext,
    );
    await flush();

    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      action: "session.create",
      outcome: "success",
      actor_id: "user-99",
      target_type: "session",
      target_id: "sess-7",
    });
    expect(serialized()).not.toContain(SESSION_TOKEN);
  });

  it("session.revoke records the deleted session, token still absent", async () => {
    emitSessionRevoked(
      { id: "sess-7", userId: "user-99", token: SESSION_TOKEN },
      hookContext,
    );
    await flush();

    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      action: "session.revoke",
      outcome: "success",
      actor_id: "user-99",
      target_id: "sess-7",
    });
    expect(serialized()).not.toContain(SESSION_TOKEN);
  });

  it("session.revoke separates a swept expiry from a deliberate kill", async () => {
    // One verb covers sign-out, expiry sweeping and bulk revocation. Without
    // this field "which sessions were killed on purpose" — the question asked
    // during an incident — is unanswerable from the row.
    emitSessionRevoked(
      {
        id: "sess-old",
        userId: "user-99",
        expiresAt: new Date(Date.now() - 1000),
      },
      hookContext,
    );
    emitSessionRevoked(
      {
        id: "sess-live",
        userId: "user-99",
        expiresAt: new Date(Date.now() + 60_000),
      },
      hookContext,
    );
    emitSessionRevoked({ id: "sess-unknown", userId: "user-99" }, hookContext);
    await flush();

    expect(rows).toHaveLength(3);
    expect(rows[0].detail).toMatchObject({ already_expired: true });
    expect(rows[1].detail).toMatchObject({ already_expired: false });
    // Honest null rather than a guess when better-auth gave us no expiry.
    expect(rows[2].detail).toMatchObject({ already_expired: null });
  });
});

describe("a broken audit sink cannot break authentication", () => {
  it("survives a sink that throws synchronously", async () => {
    setAuditSinkForTesting(() => {
      throw new Error("audit table is on fire");
    });

    expect(() =>
      emitAuthRelayEvent({
        path: "/api/auth/sign-in/email",
        status: 401,
        requestBody: { email: "a@b.invalid", password: PASSWORD },
        responseBody: "{}",
        audit: AUDIT,
      }),
    ).not.toThrow();
    expect(() =>
      emitSignupDenied({ email: "a@b.invalid" }, hookContext, "basic"),
    ).not.toThrow();
    expect(() =>
      emitSessionCreated({ id: "s", userId: "u" }, hookContext),
    ).not.toThrow();
    await flush();
  });

  it("survives a sink that REJECTS — an unhandled rejection kills the process", async () => {
    setAuditSinkForTesting(async () => {
      throw new Error("connection pool exhausted");
    });

    expect(() =>
      emitAuthRelayEvent({
        path: "/api/auth/sign-in/email",
        status: 200,
        requestBody: {},
        responseBody: SIGN_IN_OK_BODY,
        audit: AUDIT,
      }),
    ).not.toThrow();
    expect(() =>
      emitSessionRevoked({ id: "s", userId: "u" }, hookContext),
    ).not.toThrow();
    await flush();
  });

  it("survives a malformed response body without losing the row", async () => {
    emitAuthRelayEvent({
      path: "/api/auth/sign-in/email",
      status: 200,
      requestBody: {},
      responseBody: "<html>gateway timeout</html>",
      audit: AUDIT,
    });
    await flush();

    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      action: "auth.login.success",
      actor_id: null,
      actor_label: null,
    });
  });
});
